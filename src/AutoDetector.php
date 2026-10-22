<?php

/**
 * This file is part of accountdesk/mail-autodetect.
 *
 * @license MIT
 * @copyright 2026 accountdesk
 * @see https://github.com/accountdesk/mail-autodetect
 */

declare(strict_types=1);

namespace MailAutodetect;

class AutoDetector
{
  private int $timeout_http = 10;
  private int $timeout_tcp = 3;

  /** @var bool Verify SSL certificates (disable only for testing!) */
  private bool $verify_ssl = true;

  /** @var bool Allow connections to private/internal IP ranges */
  private bool $allow_private_ips = false;

  /** @var list<string> Non-public addresses that are allowed anyway (tests only) */
  private array $trusted_ips = [];

  /** @var object|null PSR-3 Logger */
  private ?object $logger = null;

  /** @var array<string, mixed> In-memory cache */
  private array $cache = [];

  /** HTTP client with SSRF guard (public addresses only, pinned, max 3 redirects) */
  private SafeHttp $http;

  public function __construct(array $options = [])
  {
    if (isset($options['timeout_http'])) {
      $this->timeout_http = (int) $options['timeout_http'];
    }
    if (isset($options['timeout_tcp'])) {
      $this->timeout_tcp = (int) $options['timeout_tcp'];
    }
    if (isset($options['verify_ssl'])) {
      $this->verify_ssl = (bool) $options['verify_ssl'];
    }
    if (isset($options['allow_private_ips'])) {
      $this->allow_private_ips = (bool) $options['allow_private_ips'];
    }
    if (isset($options['logger']) && is_object($options['logger'])) {
      $this->logger = $options['logger'];
    }
    if (isset($options['trusted_ips']) && is_array($options['trusted_ips'])) {
      $this->trusted_ips = array_values(array_map(strval(...), $options['trusted_ips']));
    }

    $this->http = new SafeHttp([
      'timeout' => $this->timeout_http,
      'connect_timeout' => min($this->timeout_http, 5),
      'verify_ssl' => $this->verify_ssl,
      'allow_private_ips' => $this->allow_private_ips,
      'max_redirects' => 3,
      'trusted_ips' => $this->trusted_ips,
      'resolver' => $options['resolver'] ?? null,
      'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      'logger' => $this->logger,
    ]);
  }

  /**
   * PSR-3 compatible logging
   */
  private function log(string $level, string $message, array $context = []): void
  {
    if ($this->logger === null) {
      return;
    }
    $this->logger->$level($message, $context);
  }

  /**
   * Main function: collects candidates from all sources
   * @param string $email_or_domain Email address or domain
   * @param int $threshold Score threshold - stop early when IMAP+SMTP with score > threshold found
   * @return array ['imap' => [[...], [...]], 'smtp' => [[...], [...]]]
   */
  public function autoDetect($email_or_domain, $threshold = 90)
  {
    // Email or domain?
    if (str_contains($email_or_domain, '@')) {
      $email = $email_or_domain;
      $domain = explode('@', $email, 2)[1];
    } else {
      $email = null;
      $domain = $email_or_domain;
    }

    $this->log('info', 'AutoDetect started', [
      'domain' => $domain,
      'email' => $email,
      'threshold' => $threshold,
    ]);

    $imap = [];
    $smtp = [];

    $getters = [
      'get_from_mozilla_ispdb',
      'get_from_known_mx',
      'get_from_microsoft_autodiscover',
      'get_from_dns_srv',
      'get_from_domain_autoconfig',
      'get_from_mx_heuristic',
      'get_from_standard_hosts',
    ];

    foreach ($getters as $getter) {
      $this->log('debug', "Strategy: {$getter}", ['domain' => $domain]);

      if ($getter === 'get_from_microsoft_autodiscover') {
        if (!$email) {
          continue;
        }
        $result = $this->get_from_microsoft_autodiscover($email);
      } else {
        $result = $this->$getter($domain);
      }

      $imap_count = count($result['imap']);
      $smtp_count = count($result['smtp']);

      if ($imap_count > 0 || $smtp_count > 0) {
        $this->log('debug', "Found via {$getter}", [
          'imap' => $imap_count,
          'smtp' => $smtp_count,
        ]);
      }

      $imap = array_merge($imap, $result['imap']);
      $smtp = array_merge($smtp, $result['smtp']);

      // Check if good candidate found (both with score > threshold)
      $best_imap = $result['imap'] !== [] ? max(array_column($result['imap'], 'score')) : 0;
      $best_smtp = $result['smtp'] !== [] ? max(array_column($result['smtp'], 'score')) : 0;

      if ($best_imap >= $threshold && $best_smtp >= $threshold) {
        $this->log('info', 'Threshold reached, stopping early', [
          'getter' => $getter,
          'best_imap' => $best_imap,
          'best_smtp' => $best_smtp,
        ]);
        break;
      }
    }

    // Deduplicate (same host+port, highest score wins)
    $imap = $this->deduplicate($imap);
    $smtp = $this->deduplicate($smtp);

    // Sort by score (highest first)
    usort($imap, static fn($a, $b) => $b['score'] <=> $a['score']);
    usort($smtp, static fn($a, $b) => $b['score'] <=> $a['score']);

    $this->log('info', 'AutoDetect completed', [
      'domain' => $domain,
      'imap_count' => count($imap),
      'smtp_count' => count($smtp),
    ]);

    return [
      'imap' => $imap,
      'smtp' => $smtp,
    ];
  }

  // ============================================================
  // CANDIDATE GETTERS (each returns array of candidates with score)
  // ============================================================

  /**
   * 1. Mozilla ISPDB - Thunderbird autoconfig database
   * Score: 95 (very reliable for known providers)
   * @return array ['imap' => [...], 'smtp' => [...]]
   */
  private function get_from_mozilla_ispdb($domain)
  {
    $result = ['imap' => [], 'smtp' => []];
    $source = 'mozilla_ispdb';
    $score = 95;

    $url = "https://autoconfig.thunderbird.net/v1.1/{$domain}";
    $xml = $this->http_get($url);

    if (!$xml) {
      return $result;
    }

    $config = @simplexml_load_string($xml);
    if (!$config) {
      return $result;
    }

    // Parse IMAP servers
    if (isset($config->emailProvider->incomingServer)) {
      foreach ($config->emailProvider->incomingServer as $server) {
        if ((string) $server['type'] !== 'imap') {
          continue;
        }
        $result['imap'][] = [
          'host' => (string) $server->hostname,
          'port' => (int) $server->port,
          'ssl' => $this->parse_socket_type((string) $server->socketType),
          'auth' => (string) $server->authentication,
          'source' => $source,
          'score' => $score,
        ];
      }
    }

    // Parse SMTP servers
    if (isset($config->emailProvider->outgoingServer)) {
      foreach ($config->emailProvider->outgoingServer as $server) {
        if ((string) $server['type'] !== 'smtp') {
          continue;
        }
        $result['smtp'][] = [
          'host' => (string) $server->hostname,
          'port' => (int) $server->port,
          'ssl' => $this->parse_socket_type((string) $server->socketType),
          'auth' => (string) $server->authentication,
          'source' => $source,
          'score' => $score,
        ];
      }
    }

    return $result;
  }

  /**
   * 2. Known MX Patterns - Detect known providers by MX record
   * Score: 92 (very reliable, no HTTP needed)
   * @return array ['imap' => [...], 'smtp' => [...]]
   */
  private function get_from_known_mx($domain)
  {
    $source = 'known_mx';

    // Known providers: MX pattern => direct output format
    $known_providers = [
      // Google / Gmail
      'google.com' => [
        'imap' => ['host' => 'imap.gmail.com', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'OAuth2'],
        'smtp' => ['host' => 'smtp.gmail.com', 'port' => 465, 'ssl' => 'ssl', 'auth' => 'OAuth2'],
      ],
      'googlemail.com' => [
        'imap' => ['host' => 'imap.gmail.com', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'OAuth2'],
        'smtp' => ['host' => 'smtp.gmail.com', 'port' => 465, 'ssl' => 'ssl', 'auth' => 'OAuth2'],
      ],
      // Microsoft / Outlook / Office 365
      'outlook.com' => [
        'imap' => ['host' => 'outlook.office365.com', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'OAuth2'],
        'smtp' => ['host' => 'smtp.office365.com', 'port' => 587, 'ssl' => 'starttls', 'auth' => 'OAuth2'],
      ],
      'protection.outlook.com' => [
        'imap' => ['host' => 'outlook.office365.com', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'OAuth2'],
        'smtp' => ['host' => 'smtp.office365.com', 'port' => 587, 'ssl' => 'starttls', 'auth' => 'OAuth2'],
      ],
      // Yahoo
      'yahoodns.net' => [
        'imap' => ['host' => 'imap.mail.yahoo.com', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'smtp.mail.yahoo.com', 'port' => 465, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
      ],
      // GMX
      'gmx.net' => [
        'imap' => ['host' => 'imap.gmx.net', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'mail.gmx.net', 'port' => 587, 'ssl' => 'starttls', 'auth' => 'password-cleartext'],
      ],
      // Web.de
      'web.de' => [
        'imap' => ['host' => 'imap.web.de', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'smtp.web.de', 'port' => 587, 'ssl' => 'starttls', 'auth' => 'password-cleartext'],
      ],
      // IONOS / 1&1
      'ionos.com' => [
        'imap' => ['host' => 'imap.ionos.de', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'smtp.ionos.de', 'port' => 587, 'ssl' => 'starttls', 'auth' => 'password-cleartext'],
      ],
      'mx00.ionos.de' => [
        'imap' => ['host' => 'imap.ionos.de', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'smtp.ionos.de', 'port' => 587, 'ssl' => 'starttls', 'auth' => 'password-cleartext'],
      ],
      'mx01.ionos.de' => [
        'imap' => ['host' => 'imap.ionos.de', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'smtp.ionos.de', 'port' => 587, 'ssl' => 'starttls', 'auth' => 'password-cleartext'],
      ],
      'mx00.udag.de' => [
        'imap' => ['host' => 'imaps.udag.de', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'smtps.udag.de', 'port' => 465, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
      ],
      'mx01.udag.de' => [
        'imap' => ['host' => 'imaps.udag.de', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'smtps.udag.de', 'port' => 465, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
      ],
      'perfora.net' => [
        'imap' => ['host' => 'imap.ionos.de', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'smtp.ionos.de', 'port' => 587, 'ssl' => 'starttls', 'auth' => 'password-cleartext'],
      ],
      // Strato
      'strato.de' => [
        'imap' => ['host' => 'imap.strato.de', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'smtp.strato.de', 'port' => 465, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
      ],
      'smtpin.rzone.de' => [
        'imap' => ['host' => 'imap.strato.de', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'smtp.strato.de', 'port' => 465, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
      ],
      // iCloud
      'icloud.com' => [
        'imap' => ['host' => 'imap.mail.me.com', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'smtp.mail.me.com', 'port' => 587, 'ssl' => 'starttls', 'auth' => 'password-cleartext'],
      ],
      // Zoho
      'zoho.com' => [
        'imap' => ['host' => 'imap.zoho.com', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'smtp.zoho.com', 'port' => 465, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
      ],
      // ProtonMail (requires Bridge)
      'protonmail.ch' => [
        'imap' => ['host' => '127.0.0.1', 'port' => 1143, 'ssl' => 'starttls', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => '127.0.0.1', 'port' => 1025, 'ssl' => 'starttls', 'auth' => 'password-cleartext'],
      ],
      // Fastmail
      'fastmail.com' => [
        'imap' => ['host' => 'imap.fastmail.com', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'smtp.fastmail.com', 'port' => 465, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
      ],
      // mailbox.org
      'mailbox.org' => [
        'imap' => ['host' => 'imap.mailbox.org', 'port' => 993, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
        'smtp' => ['host' => 'smtp.mailbox.org', 'port' => 465, 'ssl' => 'ssl', 'auth' => 'password-cleartext'],
      ],
    ];

    $mx_records = $this->get_dns($domain, 'MX');
    if (!$mx_records) {
      return ['imap' => [], 'smtp' => []];
    }

    // Get MX host (lowest priority)
    usort($mx_records, static fn($a, $b) => $a['pri'] <=> $b['pri']);
    foreach ($mx_records as $mx) {
      $mx_host = strtolower(rtrim($mx['target'], '.'));

      // Match known providers
      foreach ($known_providers as $pattern => $config) {
        if (str_contains($mx_host, $pattern)) {
          $this->log('debug', 'Known MX match', ['mx' => $mx_host, 'pattern' => $pattern]);

          return [
            'imap' => [array_merge($config['imap'], ['source' => $source, 'score' => 92])],
            'smtp' => [array_merge($config['smtp'], ['source' => $source, 'score' => 92])],
          ];
        }
      }
    }

    return ['imap' => [], 'smtp' => []];
  }

  /**
   * 3. Microsoft Autodiscover (Exchange/Office 365)
   * Score: 92 (very reliable for Exchange)
   * @param string $email The email address
   * @return array ['imap' => [...], 'smtp' => [...]]
   */
  private function get_from_microsoft_autodiscover($email)
  {
    $result = ['imap' => [], 'smtp' => []];
    $source = 'microsoft_autodiscover';
    $score = 92;

    $domain = explode('@', $email, 2)[1];

    // Try autodiscover URLs
    $urls = [
      "https://autodiscover.{$domain}/autodiscover/autodiscover.xml",
      "https://{$domain}/autodiscover/autodiscover.xml",
    ];

    // DNS SRV record as fallback
    $srv = $this->get_dns("_autodiscover._tcp.{$domain}", 'SRV');
    if ($srv) {
      $autodiscover_host = rtrim($srv[0]['target'], '.');
      $urls[] = "https://{$autodiscover_host}/autodiscover/autodiscover.xml";
    }

    // Autodiscover request XML
    $request_xml = '<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
  <Request>
    <EMailAddress>' . htmlspecialchars($email) . '</EMailAddress>
    <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
  </Request>
</Autodiscover>';

    foreach ($urls as $url) {
      $response = $this->http_post($url, $request_xml, 'text/xml');

      if ($response === false || $response === '') {
        continue;
      }

      $config = @simplexml_load_string($response);
      if ($config === false) {
        continue;
      }

      // Register namespace for XPath
      $config->registerXPathNamespace(
        'a',
        'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a',
      );

      // Search for protocol entries
      $protocols = $config->xpath('//a:Protocol');
      if (!is_array($protocols) || $protocols === []) {
        $protocols = $config->xpath('//Protocol');
      }
      if (!is_array($protocols) || $protocols === []) {
        continue;
      }

      foreach ($protocols as $protocol) {
        $type = strtoupper((string) ($protocol->Type ?? ''));
        $server = (string) ($protocol->Server ?? '');
        $port = (int) ($protocol->Port ?? 0);
        $ssl = strtolower((string) ($protocol->SSL ?? '')) === 'on';

        if ($server === '' || $port === 0) {
          continue;
        }

        if ($type === 'IMAP') {
          $result['imap'][] = [
            'host' => $server,
            'port' => $port,
            'ssl' => $ssl ? 'ssl' : 'starttls',
            'auth' => null,
            'source' => $source,
            'score' => $score,
          ];
        } elseif ($type === 'SMTP') {
          $result['smtp'][] = [
            'host' => $server,
            'port' => $port,
            'ssl' => $ssl ? 'ssl' : 'starttls',
            'auth' => null,
            'source' => $source,
            'score' => $score,
          ];
        }
      }

      // If found, don't try more URLs
      if ($result['imap'] !== [] || $result['smtp'] !== []) {
        break;
      }
    }

    return $result;
  }

  /**
   * 4. DNS SRV Records (RFC 6186)
   * Score: 90 (official standard, but rarely used)
   * @return array ['imap' => [...], 'smtp' => [...]]
   */
  private function get_from_dns_srv($domain)
  {
    $result = ['imap' => [], 'smtp' => []];
    $source = 'dns_srv';
    $score = 90;

    // IMAP SSL
    $imap_srv = $this->get_dns("_imaps._tcp.{$domain}", 'SRV');
    if ($imap_srv) {
      $result['imap'][] = [
        'host' => rtrim($imap_srv[0]['target'], '.'),
        'port' => (int) $imap_srv[0]['port'],
        'ssl' => 'ssl',
        'auth' => null,
        'source' => $source,
        'score' => $score,
      ];
    }

    // IMAP STARTTLS
    $imap_srv = $this->get_dns("_imap._tcp.{$domain}", 'SRV');
    if ($imap_srv) {
      $result['imap'][] = [
        'host' => rtrim($imap_srv[0]['target'], '.'),
        'port' => (int) $imap_srv[0]['port'],
        'ssl' => 'starttls',
        'auth' => null,
        'source' => $source,
        'score' => $score - 5,
      ];
    }

    // SMTP SSL
    $smtp_srv = $this->get_dns("_submissions._tcp.{$domain}", 'SRV');
    if ($smtp_srv) {
      $result['smtp'][] = [
        'host' => rtrim($smtp_srv[0]['target'], '.'),
        'port' => (int) $smtp_srv[0]['port'],
        'ssl' => 'ssl',
        'auth' => null,
        'source' => $source,
        'score' => $score,
      ];
    }

    // SMTP STARTTLS
    $smtp_srv = $this->get_dns("_submission._tcp.{$domain}", 'SRV');
    if ($smtp_srv) {
      $result['smtp'][] = [
        'host' => rtrim($smtp_srv[0]['target'], '.'),
        'port' => (int) $smtp_srv[0]['port'],
        'ssl' => 'starttls',
        'auth' => null,
        'source' => $source,
        'score' => $score - 5,
      ];
    }

    return $result;
  }

  /**
   * 5. Autoconfig on the domain itself
   * Score: 90 (configured by domain owner)
   * @return array ['imap' => [...], 'smtp' => [...]]
   */
  private function get_from_domain_autoconfig($domain)
  {
    $result = ['imap' => [], 'smtp' => []];
    $source = 'domain_autoconfig';
    $score = 90;

    $urls = [
      "https://autoconfig.{$domain}/mail/config-v1.1.xml",
      "https://{$domain}/.well-known/autoconfig/mail/config-v1.1.xml",
      "http://autoconfig.{$domain}/mail/config-v1.1.xml",
    ];

    foreach ($urls as $url) {
      $xml = $this->http_get($url);

      if ($xml === false || $xml === '') {
        continue;
      }

      $config = @simplexml_load_string($xml);
      if ($config === false) {
        continue;
      }

      // Parse IMAP servers
      if (isset($config->emailProvider->incomingServer)) {
        foreach ($config->emailProvider->incomingServer as $server) {
          if ((string) $server['type'] !== 'imap') {
            continue;
          }
          $result['imap'][] = [
            'host' => (string) $server->hostname,
            'port' => (int) $server->port,
            'ssl' => $this->parse_socket_type((string) $server->socketType),
            'auth' => (string) $server->authentication,
            'source' => $source,
            'score' => $score,
          ];
        }
      }

      // Parse SMTP servers
      if (isset($config->emailProvider->outgoingServer)) {
        foreach ($config->emailProvider->outgoingServer as $server) {
          if ((string) $server['type'] !== 'smtp') {
            continue;
          }
          $result['smtp'][] = [
            'host' => (string) $server->hostname,
            'port' => (int) $server->port,
            'ssl' => $this->parse_socket_type((string) $server->socketType),
            'auth' => (string) $server->authentication,
            'source' => $source,
            'score' => $score,
          ];
        }
      }

      // If found, don't try more URLs
      if ($result['imap'] !== [] || $result['smtp'] !== []) {
        break;
      }
    }

    return $result;
  }

  /**
   * 6. MX record heuristic
   * Score: 80 (heuristic based on MX)
   * @return array ['imap' => [...], 'smtp' => [...]]
   */
  private function get_from_mx_heuristic($domain)
  {
    $result = ['imap' => [], 'smtp' => []];
    $source = 'mx_heuristic';

    // Collect all checks to run in parallel
    $checks = [];
    /** @var array<string, array{type: string, ssl_type: string, source: string, score: int}> */
    $check_meta = [];

    // Get MX record
    $mx_records = $this->get_dns($domain, 'MX');
    $mx_host = null;

    if ($mx_records) {
      usort($mx_records, static fn($a, $b) => $a['pri'] <=> $b['pri']);
      foreach ($mx_records as $mx) {
        $mx_host = rtrim($mx['target'], '.');

        // Add MX host checks for IMAP
        foreach ([
          [993, true,  'ssl'],
          [143, false, 'starttls'],
        ] as [$port, $ssl, $type]) {
          $key = "{$mx_host}:{$port}";
          $checks[] = ['host' => $mx_host, 'port' => $port, 'ssl' => $ssl];
          $check_meta[$key] = ['type' => 'imap', 'ssl_type' => $type, 'source' => $source, 'score' => 80];
        }

        // Add MX host checks for SMTP
        foreach ([
          [465, true,  'ssl'],
          [587, false, 'starttls'],
        ] as [$port, $ssl, $type]) {
          $key = "{$mx_host}:{$port}";
          $checks[] = ['host' => $mx_host, 'port' => $port, 'ssl' => $ssl];
          $check_meta[$key] = ['type' => 'smtp', 'ssl_type' => $type, 'source' => $source, 'score' => 80];
        }
      }
    }

    // Add SPF hosts checks for SMTP
    $spf_hosts = $this->extract_spf_hosts($domain);
    foreach ($spf_hosts as $spf_host) {
      foreach ([
        [465, true,  'ssl'],
        [587, false, 'starttls'],
      ] as [$port, $ssl, $type]) {
        $key = "{$spf_host}:{$port}";
        if (!isset($check_meta[$key])) { // Avoid duplicates
          $checks[] = ['host' => $spf_host, 'port' => $port, 'ssl' => $ssl];
          $check_meta[$key] = ['type' => 'smtp', 'ssl_type' => $type, 'source' => $source . '_spf', 'score' => 75];
        }
      }
    }

    if ($checks === []) {
      return $result;
    }

    // Run all checks in parallel
    $tcp_results = $this->get_tcp_info_batch($checks);

    // Process results
    foreach ($tcp_results as $key => $info) {
      $key = (string) $key;
      if (!$info['success'] || !isset($check_meta[$key])) {
        continue;
      }

      $meta = $check_meta[$key];
      $expected_service = $meta['type'];

      if ($info['service'] === $expected_service) {
        $result[$expected_service][] = [
          'host' => $info['host'],
          'port' => $info['port'],
          'ssl' => $meta['ssl_type'],
          'auth' => null,
          'source' => $meta['source'],
          'score' => $meta['score'],
        ];
      }
    }

    return $result;
  }

  /**
   * Extracts hostnames from SPF record (recursive)
   */
  private function extract_spf_hosts($domain, $depth = 0)
  {
    if ($depth > 3) {
      return [];
    }

    $hosts = [];
    $txt_records = $this->get_dns($domain, 'TXT');

    if (!$txt_records) {
      return $hosts;
    }

    foreach ($txt_records as $record) {
      $txt = $record['txt'] ?? '';
      if (!str_starts_with(strtolower($txt), 'v=spf1')) {
        continue;
      }

      // "a" mechanism -> domain itself
      if (preg_match('/\ba\b/', $txt)) {
        $hosts[] = $domain;
      }

      // "mx" mechanism -> MX hosts of the domain
      if (preg_match('/\bmx\b/', $txt)) {
        $mx_records = $this->get_dns($domain, 'MX');
        if ($mx_records) {
          foreach ($mx_records as $mx) {
            $hosts[] = rtrim($mx['target'], '.');
          }
        }
      }

      // "a:hostname" mechanism
      $matches = [];
      if (preg_match_all('/a:([^\s]+)/', $txt, $matches)) {
        $hosts = array_merge($hosts, $matches[1]);
      }

      // "mx:domain" mechanism
      if (preg_match_all('/mx:([^\s]+)/', $txt, $matches)) {
        foreach ($matches[1] as $mx_domain) {
          $mx_records = $this->get_dns($mx_domain, 'MX');
          if ($mx_records) {
            foreach ($mx_records as $mx) {
              $hosts[] = rtrim($mx['target'], '.');
            }
          }
        }
      }

      // "include:domain" -> resolve recursively
      if (preg_match_all('/include:([^\s]+)/', $txt, $matches)) {
        foreach ($matches[1] as $inc_domain) {
          $hosts = array_merge($hosts, $this->extract_spf_hosts($inc_domain, $depth + 1));
        }
      }
    }

    return array_unique($hosts);
  }

  /**
   * 7. Standard hostnames guessing + TCP check
   * Score: 50-70 (guessed but verified)
   * @return array ['imap' => [...], 'smtp' => [...]]
   */
  private function get_from_standard_hosts($domain)
  {
    $result = ['imap' => [], 'smtp' => []];
    $source = 'standard_hosts';

    $imap_hosts = [
      "imap.{$domain}",
      "mail.{$domain}",
      $domain,
    ];

    $smtp_hosts = [
      "smtp.{$domain}",
      "mail.{$domain}",
      $domain,
    ];

    $imap_ports = [
      ['port' => 993, 'ssl' => true, 'type' => 'ssl'],
      ['port' => 143, 'ssl' => false, 'type' => 'starttls'],
    ];

    $smtp_ports = [
      ['port' => 465, 'ssl' => true, 'type' => 'ssl'],
      ['port' => 587, 'ssl' => false, 'type' => 'starttls'],
      ['port' => 25, 'ssl' => false, 'type' => 'plain'],
    ];

    // Collect all checks to run in parallel
    $checks = [];
    /** @var array<string, array{type: string, ssl_type: string}> */
    $check_meta = [];

    // Add IMAP checks
    foreach ($imap_hosts as $host) {
      foreach ($imap_ports as $port_config) {
        $key = "{$host}:{$port_config['port']}";
        if (!isset($check_meta[$key])) {
          $checks[] = ['host' => $host, 'port' => $port_config['port'], 'ssl' => $port_config['ssl']];
          $check_meta[$key] = ['type' => 'imap', 'ssl_type' => $port_config['type']];
        }
      }
    }

    // Add SMTP checks
    foreach ($smtp_hosts as $host) {
      foreach ($smtp_ports as $port_config) {
        $key = "{$host}:{$port_config['port']}";
        if (!isset($check_meta[$key])) {
          $checks[] = ['host' => $host, 'port' => $port_config['port'], 'ssl' => $port_config['ssl']];
          $check_meta[$key] = ['type' => 'smtp', 'ssl_type' => $port_config['type']];
        }
      }
    }

    // Run all checks in parallel
    $tcp_results = $this->get_tcp_info_batch($checks);

    // Process results
    foreach ($tcp_results as $key => $info) {
      $key = (string) $key;
      if (!$info['success'] || !isset($check_meta[$key])) {
        continue;
      }

      $meta = $check_meta[$key];
      $expected_service = $meta['type'];

      if ($info['service'] === $expected_service) {
        $score = 70;
        // Check reverse DNS (only for successful connections)
        if (!$this->reverse_dns_matches($info['host'], $domain)) {
          $score -= 15;
        }

        $result[$expected_service][] = [
          'host' => $info['host'],
          'port' => $info['port'],
          'ssl' => $meta['ssl_type'],
          'auth' => null,
          'source' => $source,
          'score' => $score,
        ];
      }
    }

    return $result;
  }

  // ============================================================
  // HELPER FUNCTIONS
  // ============================================================

  /**
   * Cache access
   */
  private function cache_get(string $key): mixed
  {
    if (!isset($this->cache[$key])) {
      return null;
    }

    $this->log('debug', 'Cache hit', ['key' => $key]);
    return $this->cache[$key];
  }

  private function cache_set(string $key, mixed $value): void
  {
    $this->cache[$key] = $value;
  }

  /**
   * HTTP GET request (cached). SSRF guard, pinning and redirects: SafeHttp.
   */
  private function http_get($url)
  {
    $cache_key = 'http:' . $url;
    $cached = $this->cache_get($cache_key);
    if ($cached !== null) {
      return $cached;
    }

    $this->log('debug', 'HTTP GET', ['url' => $url]);
    $response = $this->http->get((string) $url);
    $this->cache_set($cache_key, $response);
    return $response;
  }

  /**
   * HTTP POST request (cached). SSRF guard, pinning and redirects: SafeHttp.
   */
  private function http_post($url, $body, $content_type = 'application/x-www-form-urlencoded')
  {
    $cache_key = 'http_post:' . md5($url . $body);
    $cached = $this->cache_get($cache_key);
    if ($cached !== null) {
      return $cached;
    }

    $this->log('debug', 'HTTP POST', ['url' => $url]);
    $response = $this->http->post((string) $url, (string) $body, (string) $content_type);
    $this->cache_set($cache_key, $response);
    return $response;
  }

  /**
   * Deduplicates candidates by host+port, combines scores
   * Entries found multiple times get a bonus
   */
  private function deduplicate(array $candidates): array
  {
    $unique = [];

    foreach ($candidates as $c) {
      $key = strtolower($c['host']) . ':' . $c['port'];

      if (!isset($unique[$key])) {
        $c['sources'] = [$c['source']];
        $c['match_count'] = 1;
        $unique[$key] = $c;
        continue;
      }

      // Found multiple times - combine scores
      $existing = $unique[$key];
      $existing['sources'][] = $c['source'];
      $existing['match_count'] = (int) $existing['match_count'] + 1;

      // Take highest base score + bonus for multiple matches
      $base_score = max($existing['score'], $c['score']);
      $bonus = ($existing['match_count'] - 1) * 5; // +5 per additional source
      $existing['score'] = min(100, $base_score + $bonus); // Max 100

      $unique[$key] = $existing;
    }

    return array_values($unique);
  }

  /**
   * Parses socketType from autoconfig XML
   */
  private function parse_socket_type($type)
  {
    $type = strtoupper($type);
    if ($type === 'SSL') {
      return 'ssl';
    }
    if ($type === 'STARTTLS') {
      return 'starttls';
    }
    return 'plain';
  }

  /**
   * Reads a specific DNS record (cached)
   * @param string $domain The domain
   * @param string $type The DNS record type (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, etc.)
   * @return array|false Array with DNS records or false on error
   */
  private function get_dns($domain, $type = 'A')
  {
    $type = strtoupper($type);

    $cache_key = "dns:{$domain}:{$type}";
    $cached = $this->cache_get($cache_key);
    if ($cached !== null) {
      /** @var array|false $cached */
      return $cached;
    }

    $type_map = [
      'A' => DNS_A,
      'AAAA' => DNS_AAAA,
      'MX' => DNS_MX,
      'TXT' => DNS_TXT,
      'CNAME' => DNS_CNAME,
      'NS' => DNS_NS,
      'SOA' => DNS_SOA,
      'SRV' => DNS_SRV,
      'PTR' => DNS_PTR,
      'ANY' => DNS_ANY,
    ];

    if (!isset($type_map[$type])) {
      return false;
    }

    $this->log('debug', 'DNS lookup', ['domain' => $domain, 'type' => $type]);

    $records = @dns_get_record($domain, $type_map[$type]);

    if ($records === false || $records === []) {
      $this->cache_set($cache_key, false);
      return false;
    }

    $this->cache_set($cache_key, $records);
    return $records;
  }

  /**
   * Reverse DNS lookup - returns hostname for an IP
   * @param string $domain_or_ip Domain or IP address
   * @return string|false Hostname or false on error
   */
  private function get_reverse_dns($domain_or_ip)
  {
    // Check if it's an IP
    $ip = $domain_or_ip;
    if (!filter_var($domain_or_ip, FILTER_VALIDATE_IP)) {
      // Domain -> resolve IP first
      $ip = @gethostbyname($domain_or_ip);
      if ($ip === $domain_or_ip) {
        return false; // Could not resolve
      }
    }

    $hostname = @gethostbyaddr($ip);

    // gethostbyaddr returns the IP if no PTR exists
    if ($hostname === $ip) {
      return false;
    }

    return $hostname;
  }

  /**
   * Checks if reverse DNS of host matches the domain
   * @param string $host The host
   * @param string $domain The expected domain
   * @return bool True if reverse DNS matches the domain
   */
  private function reverse_dns_matches($host, $domain)
  {
    $reverse = $this->get_reverse_dns($host);

    if ($reverse === false) {
      return false;
    }

    // Check if domain is contained in reverse DNS
    // e.g. "mail.example.com" contains "example.com"
    $reverse = strtolower($reverse);
    $domain = strtolower($domain);

    // Exact match or ends with .domain
    if ($reverse === $domain || str_ends_with($reverse, ".{$domain}")) {
      return true;
    }

    return false;
  }

  /**
   * Batch TCP check - tests multiple host/port combinations in parallel
   *
   * Fully non-blocking state machine (connect -> optional TLS handshake ->
   * banner read) with hard deadlines. The connect MUST use the tcp://
   * transport: the ssl:// wrapper does not support STREAM_CLIENT_ASYNC_CONNECT
   * and silently falls back to a synchronous connect + handshake that ignores
   * the timeout argument (observed: 20s+ per check against firewalled hosts,
   * hanging PHP-FPM workers indefinitely). TLS is therefore negotiated after
   * the async connect via non-blocking stream_socket_enable_crypto().
   *
   * @param array $checks Array of ['host' => ..., 'port' => ..., 'ssl' => bool]
   * @return array Results indexed by "host:port"
   */
  private function get_tcp_info_batch(array $checks): array
  {
    $results = [];
    $sockets = [];
    $socket_meta = [];

    $now = microtime(true);
    $connect_deadline = $now + $this->timeout_tcp;
    // Extra window after connect for TLS handshake + banner (was previously
    // the 1s blocking banner read timeout).
    $banner_window = 1.0;
    $hard_deadline = $connect_deadline + $banner_window;

    // Initialize results and prepare connections
    foreach ($checks as $check) {
      $host = $check['host'];
      $port = $check['port'];
      $use_ssl = $check['ssl'] ?? false;
      $key = "{$host}:{$port}";

      $results[$key] = [
        'host' => $host,
        'port' => $port,
        'success' => false,
        'banner' => null,
        'service' => 'unknown',
        'ssl' => $use_ssl,
        'error' => null,
      ];

      // Resolve hostname first to avoid DNS blocking
      $ip = @gethostbyname($host);
      if ($ip === $host && !filter_var($host, FILTER_VALIDATE_IP)) {
        $results[$key]['error'] = 'DNS resolution failed';
        continue;
      }

      // SSRF protection: block private IPs
      if (!$this->allow_private_ips && $this->is_private_ip($ip)) {
        $results[$key]['error'] = 'Private IP blocked';
        $this->log('warning', 'Blocked TCP connection to private IP', ['host' => $host, 'ip' => $ip]);
        continue;
      }

      // peer_name: we connect to the IP, so SNI + certificate verification
      // need the original hostname.
      $context = stream_context_create([
        'ssl' => [
          'verify_peer' => $this->verify_ssl,
          'verify_peer_name' => $this->verify_ssl,
          'allow_self_signed' => !$this->verify_ssl,
          'peer_name' => $host,
        ],
      ]);

      $errno = null;
      $errstr = null;

      // Non-blocking connect (always tcp://, see docblock)
      $socket = @stream_socket_client(
        "tcp://{$ip}:{$port}",
        $errno,
        $errstr,
        0, // 0 timeout for non-blocking
        STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT,
        $context,
      );

      if ($socket === false) {
        $results[$key]['error'] = "{$errno}: {$errstr}";
        continue;
      }

      stream_set_blocking($socket, false);
      $sockets[$key] = $socket;
      $socket_meta[$key] = [
        'state' => 'connecting',
        'ssl' => $use_ssl,
        'deadline' => $connect_deadline,
      ];
    }

    while ($sockets !== [] && microtime(true) < $hard_deadline) {
      $read = [];
      $write = [];
      $except = null;

      foreach ($sockets as $key => $socket) {
        $state = $socket_meta[$key]['state'];
        if ($state === 'connecting') {
          $write[$key] = $socket;
        } elseif ($state === 'tls') {
          // Handshake progresses on both readable and writable events
          $read[$key] = $socket;
          $write[$key] = $socket;
        } else { // banner
          $read[$key] = $socket;
        }
      }

      // Short select slices so per-socket deadlines are enforced even when
      // nothing becomes ready.
      $select_result = @stream_select($read, $write, $except, 0, 200_000);

      if ($select_result === false) {
        break;
      }

      $now = microtime(true);
      $ready = $read + $write; // stream_select preserves keys

      foreach ($sockets as $key => $socket) {
        if (array_key_exists($key, $ready)) {
          if ($socket_meta[$key]['state'] === 'connecting') {
            // Async connect finished - distinguish success from refusal
            if (@stream_socket_get_name($socket, true) === false) {
              $results[$key]['error'] = 'Connection failed';
              fclose($socket);
              unset($sockets[$key]);
              continue;
            }
            $socket_meta[$key]['state'] = $socket_meta[$key]['ssl'] ? 'tls' : 'banner';
            $socket_meta[$key]['deadline'] = $now + $banner_window;
            if (!$socket_meta[$key]['ssl']) {
              $results[$key]['success'] = true;
            }
          }

          if ($socket_meta[$key]['state'] === 'tls') {
            $crypto = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
            if ($crypto === true) {
              $socket_meta[$key]['state'] = 'banner';
              $results[$key]['success'] = true;
            } elseif ($crypto === false) {
              $results[$key]['error'] = 'TLS handshake failed';
              fclose($socket);
              unset($sockets[$key]);
              continue;
            }

            // 0: handshake in progress, retry on next loop iteration
          }

          if ($socket_meta[$key]['state'] === 'banner' && array_key_exists($key, $read)) {
            $banner = @fread($socket, 4096);
            if (is_string($banner) && strlen($banner) > 0) {
              $results[$key]['banner'] = trim($banner);
              $results[$key]['service'] = $this->detect_service($banner, $results[$key]['port']);
              fclose($socket);
              unset($sockets[$key]);
              continue;
            }
            if (feof($socket)) {
              // Server closed without banner - connection itself succeeded
              fclose($socket);
              unset($sockets[$key]);
              continue;
            }
          }
        }

        // Per-socket deadline
        if ($now >= $socket_meta[$key]['deadline']) {
          if ($socket_meta[$key]['state'] === 'connecting') {
            $results[$key]['error'] = 'Connection timed out';
          } elseif ($socket_meta[$key]['state'] === 'tls') {
            $results[$key]['error'] = 'TLS handshake timed out';
          }
          // banner state: no banner received, but connect succeeded
          fclose($socket);
          unset($sockets[$key]);
        }
      }
    }

    // Close remaining sockets (hard deadline reached)
    foreach ($sockets as $key => $socket) {
      if (!$results[$key]['success']) {
        $results[$key]['error'] = 'Connection timed out';
      }
      @fclose($socket);
    }

    return $results;
  }

  /**
   * Checks if an IP address is private/internal (see SafeHttp::isBlockedIp)
   * @param string $ip The IP address to check
   * @return bool True if the IP must not be contacted
   */
  private function is_private_ip(string $ip): bool
  {
    return SafeHttp::isBlockedIp($ip) && !in_array($ip, $this->trusted_ips, true);
  }

  /**
   * Detects the service based on the banner
   */
  private function detect_service($banner, $port)
  {
    $banner_lower = strtolower($banner);

    // SSH
    if (str_starts_with($banner, 'SSH-')) {
      return 'ssh';
    }

    // SMTP
    if (
      preg_match('/^220\s/', $banner)
      && (
        str_contains($banner_lower, 'smtp')
        || str_contains($banner_lower, 'mail')
        || str_contains($banner_lower, 'esmtp')
        || in_array($port, [25, 465, 587], true)
      )
    ) {
      return 'smtp';
    }

    // IMAP
    if (
      preg_match('/^\*\s*OK/i', $banner)
      && (str_contains($banner_lower, 'imap') || in_array($port, [143, 993], true))
    ) {
      return 'imap';
    }

    // POP3
    if (preg_match('/^\+OK/i', $banner) && (str_contains($banner_lower, 'pop') || in_array($port, [110, 995], true))) {
      return 'pop3';
    }

    return 'unknown';
  }
}
