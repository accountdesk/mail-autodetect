<?php

declare(strict_types=1);

namespace MailAutodetect;

class AutoDetector
{
  private int $timeout_http = 10;
  private int $timeout_tcp = 3;

  /** @var object|null PSR-3 Logger */
  private ?object $logger = null;

  /** @var array<string, mixed> In-Memory Cache */
  private array $cache = [];

  public function __construct(array $options = [])
  {
    if (isset($options['timeout_http'])) {
      $this->timeout_http = (int) $options['timeout_http'];
    }
    if (isset($options['timeout_tcp'])) {
      $this->timeout_tcp = (int) $options['timeout_tcp'];
    }
    if (isset($options['logger']) && is_object($options['logger'])) {
      $this->logger = $options['logger'];
    }
  }

  /**
   * PSR-3 kompatibles Logging
   */
  private function log(string $level, string $message, array $context = []): void
  {
    if ($this->logger === null) {
      return;
    }
    $this->logger->$level($message, $context);
  }

  /**
   * Hauptfunktion: Sammelt Kandidaten aus allen Quellen
   * @param string $email_or_domain E-Mail-Adresse oder Domain
   * @param int $threshold Score-Schwellwert - wenn IMAP+SMTP mit Score > threshold gefunden, abbrechen
   * @return array ['imap' => [[...], [...]], 'smtp' => [[...], [...]]]
   */
  public function autoDetect($email_or_domain, $threshold = 90)
  {
    // E-Mail oder Domain?
    if (str_contains($email_or_domain, '@')) {
      $email = $email_or_domain;
      $domain = explode('@', $email, 2)[1];
    } else {
      $email = null;
      $domain = $email_or_domain;
    }

    $this->log('info', 'AutoDetect gestartet', [
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
      // Autodiscover braucht E-Mail, sonst überspringen
      if ($getter === 'get_from_microsoft_autodiscover' && $email === null) {
        continue;
      }

      $this->log('debug', "Strategie: {$getter}", ['domain' => $domain]);

      $result = $getter === 'get_from_microsoft_autodiscover' ? $this->$getter($email) : $this->$getter($domain);

      $imap_count = count($result['imap']);
      $smtp_count = count($result['smtp']);

      if ($imap_count > 0 || $smtp_count > 0) {
        $this->log('debug', "Gefunden via {$getter}", [
          'imap' => $imap_count,
          'smtp' => $smtp_count,
        ]);
      }

      $imap = array_merge($imap, $result['imap']);
      $smtp = array_merge($smtp, $result['smtp']);

      // Prüfen ob guter Kandidat gefunden (beide mit Score > threshold)
      $best_imap = $result['imap'] !== [] ? max(array_column($result['imap'], 'score')) : 0;
      $best_smtp = $result['smtp'] !== [] ? max(array_column($result['smtp'], 'score')) : 0;

      if ($best_imap > $threshold && $best_smtp > $threshold) {
        $this->log('info', 'Threshold erreicht, breche ab', [
          'getter' => $getter,
          'best_imap' => $best_imap,
          'best_smtp' => $best_smtp,
        ]);
        break;
      }
    }

    // Deduplizieren (gleiche host+port, höchster Score gewinnt)
    $imap = $this->deduplicate($imap);
    $smtp = $this->deduplicate($smtp);

    // Nach Score sortieren (höchster zuerst)
    usort($imap, static fn($a, $b) => $b['score'] <=> $a['score']);
    usort($smtp, static fn($a, $b) => $b['score'] <=> $a['score']);

    $this->log('info', 'AutoDetect abgeschlossen', [
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
  // KANDIDATEN-GETTER (jeder liefert Array von Kandidaten mit Score)
  // ============================================================

  /**
   * 1. Mozilla ISPDB - Thunderbird Autoconfig Datenbank
   * Score: 95 (sehr zuverlässig für bekannte Provider)
   * @return array ['imap' => [...], 'smtp' => [...]]
   */
  private function get_from_mozilla_ispdb($domain)
  {
    $result = ['imap' => [], 'smtp' => []];
    $source = 'mozilla_ispdb';
    $score = 95;

    $url = "https://autoconfig.thunderbird.net/v1.1/{$domain}";
    $xml = $this->http_get($url);

    if ($xml === false || $xml === '') {
      return $result;
    }

    $config = @simplexml_load_string($xml);
    if ($config === false) {
      return $result;
    }

    // IMAP Server parsen
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

    // SMTP Server parsen
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
   * 2. Known MX Patterns - Bekannte Provider anhand MX-Record erkennen
   * Score: 92 (sehr zuverlässig, kein HTTP nötig)
   * @return array ['imap' => [...], 'smtp' => [...]]
   */
  private function get_from_known_mx($domain)
  {
    $result = ['imap' => [], 'smtp' => []];
    $source = 'known_mx';
    $score = 92;

    // Bekannte Provider: MX-Pattern => [imap_host, imap_port, smtp_host, smtp_port]
    $known_providers = [
      // Google / Gmail
      'google.com' => ['imap.gmail.com', 993, 'smtp.gmail.com', 465],
      'googlemail.com' => ['imap.gmail.com', 993, 'smtp.gmail.com', 465],
      // Microsoft / Outlook / Office 365
      'outlook.com' => ['outlook.office365.com', 993, 'smtp.office365.com', 587],
      'protection.outlook.com' => ['outlook.office365.com', 993, 'smtp.office365.com', 587],
      // Yahoo
      'yahoodns.net' => ['imap.mail.yahoo.com', 993, 'smtp.mail.yahoo.com', 465],
      // GMX
      'gmx.net' => ['imap.gmx.net', 993, 'mail.gmx.net', 587],
      // Web.de
      'web.de' => ['imap.web.de', 993, 'smtp.web.de', 587],
      // IONOS / 1&1
      'ionos.com' => ['imap.ionos.de', 993, 'smtp.ionos.de', 587],
      'perfora.net' => ['imap.ionos.de', 993, 'smtp.ionos.de', 587],
      // Strato
      'strato.de' => ['imap.strato.de', 993, 'smtp.strato.de', 465],
      // iCloud
      'icloud.com' => ['imap.mail.me.com', 993, 'smtp.mail.me.com', 587],
      // Zoho
      'zoho.com' => ['imap.zoho.com', 993, 'smtp.zoho.com', 465],
      // ProtonMail (Bridge nötig)
      'protonmail.ch' => ['127.0.0.1', 1143, '127.0.0.1', 1025],
      // Fastmail
      'fastmail.com' => ['imap.fastmail.com', 993, 'smtp.fastmail.com', 465],
      // mailbox.org
      'mailbox.org' => ['imap.mailbox.org', 993, 'smtp.mailbox.org', 465],
    ];

    $mx_records = $this->get_dns($domain, 'MX');
    if (!$mx_records) {
      return $result;
    }

    // MX-Host holen (niedrigste Priorität)
    usort($mx_records, static fn($a, $b) => $a['pri'] <=> $b['pri']);
    $mx_host = strtolower(rtrim($mx_records[0]['target'], '.'));

    // Bekannte Provider matchen
    foreach ($known_providers as $pattern => $config) {
      if (str_contains($mx_host, $pattern)) {
        [$imap_host, $imap_port, $smtp_host, $smtp_port] = $config;

        $result['imap'][] = [
          'host' => $imap_host,
          'port' => $imap_port,
          'ssl' => 'ssl',
          'auth' => null,
          'source' => $source,
          'score' => $score,
        ];

        $result['smtp'][] = [
          'host' => $smtp_host,
          'port' => $smtp_port,
          'ssl' => $smtp_port === 465 ? 'ssl' : 'starttls',
          'auth' => null,
          'source' => $source,
          'score' => $score,
        ];

        $this->log('debug', 'Known MX match', ['mx' => $mx_host, 'pattern' => $pattern]);
        break;
      }
    }

    return $result;
  }

  /**
   * 3. Microsoft Autodiscover (Exchange/Office 365)
   * Score: 92 (sehr zuverlässig für Exchange)
   * @param string $email Die E-Mail-Adresse
   * @return array ['imap' => [...], 'smtp' => [...]]
   */
  private function get_from_microsoft_autodiscover($email)
  {
    $result = ['imap' => [], 'smtp' => []];
    $source = 'microsoft_autodiscover';
    $score = 92;

    $domain = explode('@', $email, 2)[1];

    // Autodiscover URLs probieren
    $urls = [
      "https://autodiscover.{$domain}/autodiscover/autodiscover.xml",
      "https://{$domain}/autodiscover/autodiscover.xml",
    ];

    // DNS SRV Record als Fallback
    $srv = $this->get_dns("_autodiscover._tcp.{$domain}", 'SRV');
    if ($srv) {
      $autodiscover_host = rtrim($srv[0]['target'], '.');
      $urls[] = "https://{$autodiscover_host}/autodiscover/autodiscover.xml";
    }

    // Autodiscover Request XML
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

      // Namespace registrieren für XPath
      $config->registerXPathNamespace(
        'a',
        'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a',
      );

      // Protocol-Einträge suchen
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

      // Wenn gefunden, nicht weitere URLs probieren
      if ($result['imap'] !== [] || $result['smtp'] !== []) {
        break;
      }
    }

    return $result;
  }

  /**
   * 3. DNS SRV Records (RFC 6186)
   * Score: 90 (offizieller Standard, aber selten genutzt)
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
   * 3. Autoconfig auf der Domain selbst
   * Score: 90 (vom Domain-Besitzer konfiguriert)
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

      // IMAP Server parsen
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

      // SMTP Server parsen
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

      // Wenn gefunden, nicht weitere URLs probieren
      if ($result['imap'] !== [] || $result['smtp'] !== []) {
        break;
      }
    }

    return $result;
  }

  /**
   * 4. MX-Record Heuristik (bekannte Provider erkennen)
   * Score: 80 (Heuristik basierend auf MX)
   * @return array ['imap' => [...], 'smtp' => [...]]
   */
  private function get_from_mx_heuristic($domain)
  {
    $result = ['imap' => [], 'smtp' => []];
    $source = 'mx_heuristic';

    // MX-Record auslesen für IMAP und SMTP
    $mx_records = $this->get_dns($domain, 'MX');
    if ($mx_records) {
      usort($mx_records, static fn($a, $b) => $a['pri'] <=> $b['pri']);
      $mx_host = rtrim($mx_records[0]['target'], '.');

      // IMAP auf MX-Host prüfen
      foreach ([
        [993, true,  'ssl'],
        [143, false, 'starttls'],
      ] as [$port, $ssl, $type]) {
        $info = $this->get_tcp_info($mx_host, $port, $ssl);
        if ($info['success'] && $info['service'] === 'imap') {
          $result['imap'][] = [
            'host' => $mx_host,
            'port' => $port,
            'ssl' => $type,
            'auth' => null,
            'source' => $source,
            'score' => 80,
          ];
        }
      }

      // SMTP auf MX-Host prüfen
      foreach ([
        [465, true,  'ssl'],
        [587, false, 'starttls'],
      ] as [$port, $ssl, $type]) {
        $info = $this->get_tcp_info($mx_host, $port, $ssl);
        if ($info['success'] && $info['service'] === 'smtp') {
          $result['smtp'][] = [
            'host' => $mx_host,
            'port' => $port,
            'ssl' => $type,
            'auth' => null,
            'source' => $source,
            'score' => 80,
          ];
        }
      }
    }

    // SPF-Record für zusätzliche SMTP-Hosts
    $spf_hosts = $this->extract_spf_hosts($domain);
    foreach ($spf_hosts as $spf_host) {
      foreach ([
        [465, true,  'ssl'],
        [587, false, 'starttls'],
      ] as [$port, $ssl, $type]) {
        $info = $this->get_tcp_info($spf_host, $port, $ssl);
        if ($info['success'] && $info['service'] === 'smtp') {
          $result['smtp'][] = [
            'host' => $spf_host,
            'port' => $port,
            'ssl' => $type,
            'auth' => null,
            'source' => $source . '_spf',
            'score' => 75,
          ];
        }
      }
    }

    return $result;
  }

  /**
   * Extrahiert Hostnamen aus SPF-Record (rekursiv)
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

      // "a" mechanism → Domain selbst
      if (preg_match('/\ba\b/', $txt)) {
        $hosts[] = $domain;
      }

      // "mx" mechanism → MX-Hosts der Domain
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

      // "include:domain" → rekursiv auflösen
      if (preg_match_all('/include:([^\s]+)/', $txt, $matches)) {
        foreach ($matches[1] as $inc_domain) {
          $hosts = array_merge($hosts, $this->extract_spf_hosts($inc_domain, $depth + 1));
        }
      }
    }

    return array_unique($hosts);
  }

  /**
   * 5. Standard-Hostnamen raten + TCP-Check
   * Score: 50-70 (geraten, aber verifiziert)
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

    // IMAP finden
    foreach ($imap_hosts as $host) {
      foreach ($imap_ports as $port_config) {
        $info = $this->get_tcp_info($host, $port_config['port'], $port_config['ssl']);
        if ($info['success'] && $info['service'] === 'imap') {
          $score = 70;
          // Reverse DNS prüfen
          if (!$this->reverse_dns_matches($host, $domain)) {
            $score -= 15;
          }
          $result['imap'][] = [
            'host' => $host,
            'port' => $port_config['port'],
            'ssl' => $port_config['type'],
            'auth' => null,
            'source' => $source,
            'score' => $score,
          ];
        }
      }
    }

    // SMTP finden
    foreach ($smtp_hosts as $host) {
      foreach ($smtp_ports as $port_config) {
        $info = $this->get_tcp_info($host, $port_config['port'], $port_config['ssl']);
        if ($info['success'] && $info['service'] === 'smtp') {
          $score = 70;
          // Reverse DNS prüfen
          if (!$this->reverse_dns_matches($host, $domain)) {
            $score -= 15;
          }
          $result['smtp'][] = [
            'host' => $host,
            'port' => $port_config['port'],
            'ssl' => $port_config['type'],
            'auth' => null,
            'source' => $source,
            'score' => $score,
          ];
        }
      }
    }

    return $result;
  }

  // ============================================================
  // HILFSFUNKTIONEN
  // ============================================================

  /**
   * Cache-Zugriff
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
   * HTTP GET Request mit cURL (cached)
   */
  private function http_get($url)
  {
    $cache_key = 'http:' . $url;
    $cached = $this->cache_get($cache_key);
    if ($cached !== null) {
      return $cached;
    }

    $this->log('debug', 'HTTP GET', ['url' => $url]);

    $ch = curl_init();
    if ($ch === false) {
      $this->log('warning', 'curl_init fehlgeschlagen');
      return false;
    }
    curl_setopt_array($ch, [
      CURLOPT_URL => $url,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_TIMEOUT => $this->timeout_http,
      CURLOPT_SSL_VERIFYPEER => false,
      CURLOPT_SSL_VERIFYHOST => false,
      CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if ($response === false || $httpCode >= 400) {
      $this->log('debug', 'HTTP Fehler', ['url' => $url, 'code' => $httpCode]);
      $this->cache_set($cache_key, false);
      return false;
    }

    $this->cache_set($cache_key, $response);
    return $response;
  }

  /**
   * HTTP POST Request mit cURL (cached)
   */
  private function http_post($url, $body, $content_type = 'application/x-www-form-urlencoded')
  {
    $cache_key = 'http_post:' . md5($url . $body);
    $cached = $this->cache_get($cache_key);
    if ($cached !== null) {
      return $cached;
    }

    $this->log('debug', 'HTTP POST', ['url' => $url]);

    $ch = curl_init();
    if ($ch === false) {
      $this->log('warning', 'curl_init fehlgeschlagen');
      return false;
    }
    curl_setopt_array($ch, [
      CURLOPT_URL => $url,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_FOLLOWLOCATION => true,
      CURLOPT_TIMEOUT => $this->timeout_http,
      CURLOPT_SSL_VERIFYPEER => false,
      CURLOPT_SSL_VERIFYHOST => false,
      CURLOPT_POST => true,
      CURLOPT_POSTFIELDS => $body,
      CURLOPT_HTTPHEADER => [
        'Content-Type: ' . $content_type,
        'Content-Length: ' . strlen($body),
      ],
      CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

    if ($response === false || $httpCode >= 400) {
      $this->log('debug', 'HTTP POST Fehler', ['url' => $url, 'code' => $httpCode]);
      $this->cache_set($cache_key, false);
      return false;
    }

    $this->cache_set($cache_key, $response);
    return $response;
  }

  /**
   * Dedupliziert Kandidaten nach host+port, kombiniert Scores
   * Mehrfach gefundene Einträge bekommen Bonus
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

      // Mehrfach gefunden - Score kombinieren
      $existing = $unique[$key];
      $existing['sources'][] = $c['source'];
      $existing['match_count'] = (int) $existing['match_count'] + 1;

      // Höchsten Basis-Score nehmen + Bonus für Mehrfachtreffer
      $base_score = max($existing['score'], $c['score']);
      $bonus = ($existing['match_count'] - 1) * 5; // +5 pro zusätzlicher Quelle
      $existing['score'] = min(100, $base_score + $bonus); // Max 100

      $unique[$key] = $existing;
    }

    return array_values($unique);
  }

  /**
   * Parst socketType aus Autoconfig XML
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
   * Liest einen spezifischen DNS-Eintrag aus (cached)
   * @param string $domain Die Domain
   * @param string $type Der DNS-Record-Typ (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, etc.)
   * @return array|false Array mit DNS-Einträgen oder false bei Fehler
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

    $this->log('debug', 'DNS Lookup', ['domain' => $domain, 'type' => $type]);

    $records = @dns_get_record($domain, $type_map[$type]);

    if ($records === false || $records === []) {
      $this->cache_set($cache_key, false);
      return false;
    }

    $this->cache_set($cache_key, $records);
    return $records;
  }

  /**
   * Reverse DNS Lookup - gibt den Hostnamen für eine IP zurück
   * @param string $domain_or_ip Domain oder IP-Adresse
   * @return string|false Hostname oder false bei Fehler
   */
  private function get_reverse_dns($domain_or_ip)
  {
    // Prüfen ob es eine IP ist
    $ip = $domain_or_ip;
    if (!filter_var($domain_or_ip, FILTER_VALIDATE_IP)) {
      // Domain → erst IP auflösen
      $ip = @gethostbyname($domain_or_ip);
      if ($ip === $domain_or_ip) {
        return false; // Konnte nicht aufgelöst werden
      }
    }

    $hostname = @gethostbyaddr($ip);

    // gethostbyaddr gibt die IP zurück wenn kein PTR existiert
    if ($hostname === $ip) {
      return false;
    }

    return $hostname;
  }

  /**
   * Prüft ob Reverse DNS des Hosts zur Domain passt
   * @param string $host Der Host
   * @param string $domain Die erwartete Domain
   * @return bool True wenn Reverse DNS zur Domain passt
   */
  private function reverse_dns_matches($host, $domain)
  {
    $reverse = $this->get_reverse_dns($host);

    if ($reverse === false) {
      return false;
    }

    // Prüfen ob Domain im Reverse DNS enthalten ist
    // z.B. "mail.example.com" enthält "example.com"
    $reverse = strtolower($reverse);
    $domain = strtolower($domain);

    // Exakter Match oder endet mit .domain
    if ($reverse === $domain || str_ends_with($reverse, ".{$domain}")) {
      return true;
    }

    return false;
  }

  /**
   * Öffnet eine TCP-Verbindung und liest das Server-Banner
   * @param string $domain_or_ip Domain oder IP-Adresse
   * @param int $port Der Port (z.B. 22=SSH, 25=SMTP, 143=IMAP, 993=IMAPS, 465=SMTPS, 587=Submission)
   * @param bool $use_ssl SSL verwenden
   * @return array Informationen über den Dienst
   */
  private function get_tcp_info($domain_or_ip, $port, $use_ssl = false)
  {
    $result = [
      'host' => $domain_or_ip,
      'port' => $port,
      'success' => false,
      'banner' => null,
      'service' => 'unknown',
      'ssl' => false,
      'error' => null,
    ];

    $address = $use_ssl ? "ssl://{$domain_or_ip}" : "tcp://{$domain_or_ip}";

    $context = stream_context_create([
      'ssl' => [
        'verify_peer' => false,
        'verify_peer_name' => false,
        'allow_self_signed' => true,
      ],
    ]);

    $errno = null;
    $errstr = null;
    $socket = @stream_socket_client(
      "{$address}:{$port}",
      $errno,
      $errstr,
      $this->timeout_tcp,
      STREAM_CLIENT_CONNECT,
      $context,
    );

    if (!$socket) {
      $result['error'] = "{$errno}: {$errstr}";
      return $result;
    }

    $result['success'] = true;
    $result['ssl'] = $use_ssl;

    stream_set_timeout($socket, $this->timeout_tcp);

    // Banner lesen (viele Dienste senden direkt nach Connect)
    $banner = @fread($socket, 4096);

    if ($banner !== false && strlen($banner) > 0) {
      $result['banner'] = trim($banner);
      $result['service'] = $this->detect_service($banner, $port);
    }

    fclose($socket);

    return $result;
  }

  /**
   * Erkennt den Dienst anhand des Banners
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
