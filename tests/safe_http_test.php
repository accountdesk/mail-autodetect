<?php

/**
 * Self-contained checks for the SSRF guard (no PHPUnit needed):
 *
 *   php tests/safe_http_test.php
 *
 * Starts a PHP built-in server on 127.0.0.1 for the redirect cases.
 */

declare(strict_types=1);

require __DIR__ . '/../src/SafeHttp.php';

use MailAutodetect\SafeHttp;

$failures = 0;
$checks = 0;

$assert = static function (mixed $condition, string $label) use (&$failures, &$checks): void {
  $checks++;
  if ($condition === true) {
    echo "ok   {$label}\n";
    return;
  }
  $failures++;
  echo "FAIL {$label}\n";
};

// --- address ranges --------------------------------------------------------
$blocked = [
  '127.0.0.1',
  '127.255.255.254',
  '10.0.0.1',
  '172.16.0.1',
  '172.31.255.255',
  '192.168.1.1',
  '169.254.169.254',
  '100.64.0.1',
  '0.0.0.0',
  '224.0.0.1',
  '255.255.255.255',
  '198.18.0.1',
  '::1',
  '::',
  'fd00::1',
  'fc00::1',
  'fe80::1',
  'ff02::1',
  'fec0::1',
  '::ffff:127.0.0.1',
  '::ffff:169.254.169.254',
  '64:ff9b::7f00:1',
  '2002:7f00:1::',
  '::127.0.0.1',
  '2001:0:4136:e378::1',
  'not-an-ip',
  '',
];
foreach ($blocked as $ip) {
  $assert(SafeHttp::isBlockedIp($ip), "blocked: {$ip}");
}
$public = [
  '8.8.8.8',
  '1.1.1.1',
  '172.32.0.1',
  '100.128.0.1',
  '2a00:1450:4001:80b::200e',
  '::ffff:8.8.8.8',
  '2002:0808:0808::1',
];
foreach ($public as $ip) {
  $assert(!SafeHttp::isBlockedIp($ip), "public: {$ip}");
}

// --- URL checks with a fake resolver ---------------------------------------
$dns = [
  'public.test' => ['93.184.216.34'],
  'mixed.test' => ['93.184.216.34', '10.0.0.5'],
  'v6.test' => ['2a00:1450:4001:80b::200e', 'fd12::1'],
  'meta.test' => ['169.254.169.254'],
];
$client = new SafeHttp(['resolver' => static fn(string $host): array => $dns[$host] ?? []]);
$assert(is_array($client->check('https://public.test/x')), 'public host passes');
$assert(is_string($client->check('https://mixed.test/x')), 'host with one private address is rejected');
$assert(is_string($client->check('https://v6.test/x')), 'host with private IPv6 address is rejected');
$assert(is_string($client->check('http://meta.test/latest/meta-data')), 'metadata address is rejected');
$assert(is_string($client->check('http://127.0.0.1/')), 'loopback literal is rejected');
$assert(is_string($client->check('http://[::1]/')), 'IPv6 loopback literal is rejected');
$assert(is_string($client->check('http://[::ffff:7f00:1]/')), 'IPv4-mapped loopback literal is rejected');
$assert(is_string($client->check('https://public.test:5054/')), 'non-standard port is rejected');
$assert(is_string($client->check('ftp://public.test/')), 'ftp is rejected');
$assert(is_string($client->check('file:///etc/passwd')), 'file is rejected');
$assert(is_string($client->check('gopher://public.test/')), 'gopher is rejected');
$assert(is_string($client->check('https://user:pw@public.test/')), 'userinfo is rejected');
$assert(is_string($client->check('https://unknown.test/')), 'unresolvable host is rejected');
$assert($client->get('http://127.0.0.1/') === false, 'GET to loopback returns false');

// --- live checks against a local server -------------------------------------
$port = 18_000 + random_int(0, 999);
$router = sys_get_temp_dir() . '/safe_http_router_' . (string) getmypid() . '.php';
file_put_contents($router, <<<'PHP'
  <?php
  $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
  if ($path === '/ok') { echo 'ok:' . $_SERVER['REQUEST_METHOD']; return; }
  if ($path === '/to-meta') { header('Location: http://169.254.169.254/latest/meta-data/', true, 302); return; }
  if ($path === '/to-ok') { header('Location: /ok', true, 302); return; }
  if ($path === '/to-ok-307') { header('Location: /ok', true, 307); return; }
  if ($path === '/loop') { header('Location: /loop', true, 302); return; }
  if ($path === '/to-port') { header('Location: http://127.0.0.1:5054/', true, 302); return; }
  if ($path === '/big') { echo str_repeat('x', 300_000); return; }
  http_response_code(404);
  PHP);
$pipes = [];
$proc = proc_open(
  [PHP_BINARY, '-S', "127.0.0.1:{$port}", $router],
  [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
  $pipes,
);
if ($proc === false) {
  echo "FAIL could not start the PHP built-in server\n";
  exit(1);
}
for ($i = 0; $i < 50; $i++) {
  $fp = @fsockopen('127.0.0.1', $port);
  if ($fp !== false) {
    fclose($fp);
    break;
  }
  usleep(100_000);
}

$resolver_calls = 0;
$rebinding = static function (string $_host) use (&$resolver_calls): array {
  $resolver_calls++;
  // First answer: the (trusted) test server; any later answer would be internal.
  return $resolver_calls === 1 ? ['127.0.0.1'] : ['10.0.0.1'];
};
$local = new SafeHttp([
  'trusted_ips' => ['127.0.0.1'],
  'allowed_ports' => [80, 443, $port],
  'resolver' => $rebinding,
  'max_bytes' => 100_000,
  'timeout' => 5,
]);
$assert(
  $local->get("http://rebind.test:{$port}/ok") === 'ok:GET',
  'connection is pinned to the checked address (no second lookup)',
);
$assert($resolver_calls === 1, 'resolver was asked exactly once');

$local = new SafeHttp(['trusted_ips' => ['127.0.0.1'], 'allowed_ports' => [80, 443, $port], 'max_bytes' => 100_000]);
$assert($local->get("http://127.0.0.1:{$port}/to-ok") === 'ok:GET', 'redirect to an allowed target is followed');
$assert($local->post("http://127.0.0.1:{$port}/to-ok", 'a=1') === 'ok:GET', '302 after POST continues as GET');
$assert($local->post("http://127.0.0.1:{$port}/to-ok-307", 'a=1') === 'ok:POST', '307 keeps POST');
$assert($local->get("http://127.0.0.1:{$port}/to-meta") === false, 'redirect to metadata address is blocked');
$assert($local->get("http://127.0.0.1:{$port}/to-port") === false, 'redirect to an internal service port is blocked');
$assert($local->get("http://127.0.0.1:{$port}/loop") === false, 'redirect loop stops');
$assert($local->get("http://127.0.0.1:{$port}/big") === false, 'oversized body is rejected');

$strict = new SafeHttp(['allowed_ports' => [80, 443, $port]]);
$assert($strict->get("http://127.0.0.1:{$port}/ok") === false, 'local server is blocked without trusted_ips');

proc_terminate($proc);
proc_close($proc);
@unlink($router);

echo "\n{$checks} checks, {$failures} failures\n";
exit($failures === 0 ? 0 : 1);
