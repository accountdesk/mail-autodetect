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

/**
 * Minimal HTTP client that refuses to talk to internal networks (SSRF guard).
 *
 * For every hop (the initial URL and each redirect target):
 * - only http/https, only the allowed ports (default 80/443), no userinfo
 * - the host is resolved (A + AAAA) and EVERY address must be public
 * - the connection is pinned to the checked addresses via CURLOPT_RESOLVE,
 *   so curl never resolves the name a second time (no DNS rebinding)
 * - redirects are followed manually (at most `max_redirects`)
 *
 * The response body is capped (`max_bytes`) and every request has a connect
 * and a total timeout.
 */
final class SafeHttp
{
  /** @var array{timeout: int, connect_timeout: int, max_redirects: int, max_bytes: int} */
  private array $limits = [
    'timeout' => 10,
    'connect_timeout' => 5,
    'max_redirects' => 3,
    'max_bytes' => 2_097_152,
  ];

  private bool $verify_ssl = true;
  private bool $allow_private_ips = false;
  private string $user_agent = 'Mozilla/5.0 (compatible; mail-autodetect)';

  /** @var list<int> */
  private array $allowed_ports = [80, 443];

  /** @var list<string> */
  private array $trusted_ips = [];

  /** Replaces the DNS lookup: fn(string $host): list<string> */
  private ?\Closure $resolver = null;

  /** @var object|null PSR-3 logger */
  private ?object $logger = null;

  /**
   * Options:
   * - timeout (int, seconds, total per hop), connect_timeout (int, seconds)
   * - verify_ssl (bool)
   * - allow_private_ips (bool) — disables the address check (tests/intranet only)
   * - max_redirects (int, default 3)
   * - max_bytes (int, response body cap, default 2 MiB)
   * - allowed_ports (list<int>, default [80, 443])
   * - trusted_ips (list<string>) — addresses that pass the check although
   *   they are not public (e.g. a local test server); use with care
   * - resolver (callable(string $host): list<string>) — replaces DNS lookup
   * - user_agent (string), logger (PSR-3 object)
   *
   * @param array<string, mixed> $options
   */
  public function __construct(array $options = [])
  {
    foreach (['timeout' => 1, 'connect_timeout' => 1, 'max_redirects' => 0, 'max_bytes' => 1] as $key => $min) {
      $value = $options[$key] ?? null;
      if (is_int($value) || is_numeric($value)) {
        $this->limits[$key] = max($min, (int) $value);
      }
    }
    $verify_ssl = $options['verify_ssl'] ?? null;
    if ($verify_ssl !== null) {
      $this->verify_ssl = (bool) $verify_ssl;
    }
    $allow_private_ips = $options['allow_private_ips'] ?? null;
    if ($allow_private_ips !== null) {
      $this->allow_private_ips = (bool) $allow_private_ips;
    }
    $allowed_ports = $options['allowed_ports'] ?? null;
    if (is_array($allowed_ports)) {
      $this->allowed_ports = array_values(array_map(intval(...), $allowed_ports));
    }
    $trusted_ips = $options['trusted_ips'] ?? null;
    if (is_array($trusted_ips)) {
      $this->trusted_ips = array_values(array_map(strval(...), $trusted_ips));
    }
    $resolver = $options['resolver'] ?? null;
    if (is_callable($resolver)) {
      $this->resolver = \Closure::fromCallable($resolver);
    }
    $user_agent = $options['user_agent'] ?? null;
    if (is_string($user_agent)) {
      $this->user_agent = $user_agent;
    }
    $logger = $options['logger'] ?? null;
    if (is_object($logger)) {
      $this->logger = $logger;
    }
  }

  /**
   * True if the address is not a public unicast address (or not an IP at all).
   */
  public static function isBlockedIp(string $ip): bool
  {
    $ip = trim($ip, '[]');
    $bin = @inet_pton($ip);
    if ($bin === false) {
      return true;
    }

    if (strlen($bin) === 16) {
      $prefix12 = substr($bin, 0, 12);
      $embedded = null;
      if ($prefix12 === "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff") {
        $embedded = substr($bin, 12); // IPv4-mapped ::ffff:a.b.c.d
      } elseif ($prefix12 === "\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00") {
        $embedded = substr($bin, 12); // NAT64 64:ff9b::/96
      } elseif (substr($bin, 0, 2) === "\x20\x02") {
        $embedded = substr($bin, 2, 4); // 6to4 2002::/16
      } elseif (
        $prefix12 === str_repeat("\x00", 12)
        && substr($bin, 12) !== "\x00\x00\x00\x00"
        && substr($bin, 12) !== "\x00\x00\x00\x01"
      ) {
        $embedded = substr($bin, 12); // IPv4-compatible ::a.b.c.d (deprecated)
      }
      if ($embedded !== null) {
        $bin = $embedded;
      }
    }

    foreach (self::blockedCidrs() as $cidr) {
      if (self::inCidr($bin, $cidr)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Checks a URL without fetching it.
   *
   * @return array{scheme: string, host: string, port: int, ips: list<string>}|string
   *   the checked target, or a short reason why it was rejected
   */
  public function check(string $url): array|string
  {
    $parts = parse_url($url);
    if ($parts === false) {
      return 'invalid url';
    }
    $scheme = strtolower($parts['scheme'] ?? '');
    $raw_host = $parts['host'] ?? '';
    if ($scheme === '' || $raw_host === '') {
      return 'invalid url';
    }
    if ($scheme !== 'http' && $scheme !== 'https') {
      return 'scheme not allowed';
    }
    if (($parts['user'] ?? null) !== null || ($parts['pass'] ?? null) !== null) {
      return 'credentials in url not allowed';
    }
    $default_port = $scheme === 'https' ? 443 : 80;
    $port = (int) ($parts['port'] ?? $default_port);
    if (!in_array($port, $this->allowed_ports, true)) {
      return 'port not allowed';
    }

    $host = strtolower(rtrim($raw_host, '.'));
    if ($host === '') {
      return 'invalid url';
    }

    $literal = trim($host, '[]');
    if (filter_var($literal, FILTER_VALIDATE_IP) !== false) {
      $ips = [$literal];
    } else {
      $ips = $this->resolve($host);
    }
    if ($ips === []) {
      return 'host not resolvable';
    }

    if (!$this->allow_private_ips) {
      foreach ($ips as $ip) {
        if (self::isBlockedIp($ip) && !in_array($ip, $this->trusted_ips, true)) {
          return 'address not allowed (' . $ip . ')';
        }
      }
    }

    return ['scheme' => $scheme, 'host' => $host, 'port' => $port, 'ips' => $ips];
  }

  /**
   * GET request. Returns the body, or false on error/blocked target/HTTP >= 400.
   */
  public function get(string $url): string|false
  {
    return $this->request('GET', $url, null, []);
  }

  /**
   * POST request. Returns the body, or false on error/blocked target/HTTP >= 400.
   */
  public function post(
    string $url,
    string $body,
    string $content_type = 'application/x-www-form-urlencoded',
  ): string|false {
    return $this->request('POST', $url, $body, ['Content-Type: ' . $content_type]);
  }

  /**
   * @param list<string> $headers
   */
  private function request(string $method, string $url, ?string $body, array $headers): string|false
  {
    for ($hop = 0; $hop <= $this->limits['max_redirects']; $hop++) {
      $target = $this->check($url);
      if (is_string($target)) {
        $this->log('warning', 'Blocked HTTP request', ['url' => $url, 'reason' => $target, 'hop' => $hop]);
        return false;
      }

      $result = $this->exec($method, $url, $body, $headers, $target);
      if ($result === null) {
        return false;
      }

      [$code, $response, $location] = $result;
      if ($code >= 300 && $code < 400 && $location !== '') {
        $this->log('debug', 'HTTP redirect', ['from' => $url, 'to' => $location, 'code' => $code]);
        $url = $location;
        // Same semantics as curl's FOLLOWLOCATION: 307/308 keep the method,
        // everything else continues as GET without body.
        if ($code !== 307 && $code !== 308) {
          $method = 'GET';
          $body = null;
          $headers = [];
        }
        continue;
      }

      if ($code >= 400 || $code === 0) {
        $this->log('debug', 'HTTP error', ['url' => $url, 'code' => $code]);
        return false;
      }

      return $response;
    }

    $this->log('warning', 'Too many redirects', ['url' => $url, 'max' => $this->limits['max_redirects']]);
    return false;
  }

  /**
   * One request without following redirects.
   *
   * @param list<string> $headers
   * @param array{scheme: string, host: string, port: int, ips: list<string>} $target
   * @return array{0: int, 1: string, 2: string}|null [status, body, absolute redirect target]
   */
  private function exec(string $method, string $url, ?string $body, array $headers, array $target): ?array
  {
    $ch = curl_init();
    if ($ch === false) {
      $this->log('warning', 'curl_init failed');
      return null;
    }

    $resolve = [];
    if (filter_var(trim($target['host'], '[]'), FILTER_VALIDATE_IP) === false) {
      $addresses = array_map(static fn(string $ip): string => str_contains($ip, ':')
        ? '[' . $ip . ']'
        : $ip, $target['ips']);
      $resolve[] = $target['host'] . ':' . $target['port'] . ':' . implode(',', $addresses);
    }

    $response = '';
    $too_big = false;
    $max_bytes = $this->limits['max_bytes'];

    $options = [
      CURLOPT_URL => $url,
      CURLOPT_RETURNTRANSFER => false,
      CURLOPT_FOLLOWLOCATION => false,
      CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
      CURLOPT_RESOLVE => $resolve,
      CURLOPT_CONNECTTIMEOUT => $this->limits['connect_timeout'],
      CURLOPT_TIMEOUT => $this->limits['timeout'],
      CURLOPT_SSL_VERIFYPEER => $this->verify_ssl,
      CURLOPT_SSL_VERIFYHOST => $this->verify_ssl ? 2 : 0,
      CURLOPT_USERAGENT => $this->user_agent,
      CURLOPT_NOPROXY => '*',
      CURLOPT_WRITEFUNCTION => static function ($_ch, string $chunk) use (&$response, &$too_big, $max_bytes): int {
        if ((strlen($response) + strlen($chunk)) > $max_bytes) {
          $too_big = true;
          return 0;
        }
        $response .= $chunk;
        return strlen($chunk);
      },
    ];
    if ($method === 'POST') {
      $options[CURLOPT_POST] = true;
      $options[CURLOPT_POSTFIELDS] = (string) $body;
    }
    if ($headers !== []) {
      $options[CURLOPT_HTTPHEADER] = $headers;
    }
    curl_setopt_array($ch, $options);

    $ok = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $location = (string) curl_getinfo($ch, CURLINFO_REDIRECT_URL);

    if ($too_big) {
      $this->log('warning', 'HTTP response too large', ['url' => $url, 'max_bytes' => $max_bytes]);
      return null;
    }
    if ($ok === false) {
      $this->log('debug', 'HTTP request failed', ['url' => $url, 'error' => curl_error($ch)]);
      return null;
    }

    return [$code, $response, $location];
  }

  /**
   * @return list<string>
   */
  private function resolve(string $host): array
  {
    if ($this->resolver !== null) {
      $ips = ($this->resolver)($host);
      return array_values(array_unique(array_map(strval(...), $ips)));
    }

    $ips = [];
    $records_a = @dns_get_record($host, DNS_A);
    if (is_array($records_a)) {
      foreach ($records_a as $record) {
        $ip = (string) ($record['ip'] ?? '');
        if ($ip !== '') {
          $ips[] = $ip;
        }
      }
    }
    $records_aaaa = @dns_get_record($host, DNS_AAAA);
    if (is_array($records_aaaa)) {
      foreach ($records_aaaa as $record) {
        $ip = (string) ($record['ipv6'] ?? '');
        if ($ip !== '') {
          $ips[] = $ip;
        }
      }
    }
    if ($ips === []) {
      // dns_get_record ignores /etc/hosts; fall back to the system resolver.
      $list = @gethostbynamel($host);
      if (is_array($list)) {
        $ips = $list;
      }
    }

    return array_values(array_unique($ips));
  }

  /**
   * Non-public address ranges (IPv4 and IPv6) in CIDR notation.
   * IPv6 transition forms that embed an IPv4 address (IPv4-mapped,
   * IPv4-compatible, NAT64, 6to4) are unwrapped and checked as IPv4.
   *
   * @return list<string>
   */
  private static function blockedCidrs(): array
  {
    return [
      '0.0.0.0/8', // "this network"
      '10.0.0.0/8', // RFC 1918
      '100.64.0.0/10', // carrier-grade NAT
      '127.0.0.0/8', // loopback
      '169.254.0.0/16', // link-local incl. cloud metadata (169.254.169.254)
      '172.16.0.0/12', // RFC 1918
      '192.0.0.0/24', // IETF protocol assignments
      '192.0.2.0/24', // TEST-NET-1
      '192.88.99.0/24', // 6to4 relay anycast
      '192.168.0.0/16', // RFC 1918
      '198.18.0.0/15', // benchmarking
      '198.51.100.0/24', // TEST-NET-2
      '203.0.113.0/24', // TEST-NET-3
      '224.0.0.0/4', // multicast
      '240.0.0.0/4', // reserved + broadcast
      '::/128', // unspecified
      '::1/128', // loopback
      '100::/64', // discard-only
      '2001::/32', // Teredo (embedded address cannot be checked reliably)
      '2001:db8::/32', // documentation
      'fc00::/7', // unique local
      'fe80::/10', // link-local
      'fec0::/10', // site-local (deprecated)
      'ff00::/8', // multicast
    ];
  }

  private static function inCidr(string $bin, string $cidr): bool
  {
    [$net, $bits] = explode('/', $cidr, 2);
    $net_bin = inet_pton($net);
    if ($net_bin === false || strlen($net_bin) !== strlen($bin)) {
      return false;
    }
    $bits = (int) $bits;
    $bytes = $bits >> 3;
    if (substr($bin, 0, $bytes) !== substr($net_bin, 0, $bytes)) {
      return false;
    }
    $rest = $bits % 8;
    if ($rest === 0) {
      return true;
    }
    $mask = (0xff << (8 - $rest)) & 0xff;
    return (ord($bin[$bytes]) & $mask) === (ord($net_bin[$bytes]) & $mask);
  }

  /**
   * @param array<string, mixed> $context
   */
  private function log(string $level, string $message, array $context = []): void
  {
    if ($this->logger === null) {
      return;
    }
    $this->logger->$level($message, $context);
  }
}
