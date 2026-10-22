# Mail-AutoDetect

[![Latest Version](https://img.shields.io/packagist/v/accountdesk/mail-autodetect)](https://packagist.org/packages/accountdesk/mail-autodetect)
[![Total Downloads](https://img.shields.io/packagist/dt/accountdesk/mail-autodetect)](https://packagist.org/packages/accountdesk/mail-autodetect)
[![License](https://img.shields.io/packagist/l/accountdesk/mail-autodetect)](https://packagist.org/packages/accountdesk/mail-autodetect)
[![PHP Version](https://img.shields.io/packagist/php-v/accountdesk/mail-autodetect)](https://packagist.org/packages/accountdesk/mail-autodetect)
[![CI](https://github.com/accountdesk/mail-autodetect/actions/workflows/ci.yml/badge.svg)](https://github.com/accountdesk/mail-autodetect/actions/workflows/ci.yml)

> *Mail server discovery on autopilot*

PHP library for automatic detection of IMAP and SMTP server settings for any domain.

## Installation

### Option 1: Composer

```bash
composer require accountdesk/mail-autodetect
```

### Option 2: Manual

Copy `src/AutoDetector.php` and `src/SafeHttp.php` into your project and include them:

```php
require_once 'path/to/SafeHttp.php';
require_once 'path/to/AutoDetector.php';
```

**Requirements:**
- PHP >= 8.1
- ext-curl
- ext-simplexml

## Usage

```php
use MailAutodetect\AutoDetector;

$detector = new AutoDetector();

// With email address (recommended - enables Microsoft Autodiscover)
$result = $detector->autoDetect('user@example.com');

// With domain only (without Autodiscover)
$result = $detector->autoDetect('gmail.com');

print_r($result);
```

**Output:**

```php
[
    'imap' => [
        [
            'host' => 'imap.gmail.com',
            'port' => 993,
            'ssl' => 'ssl',
            'auth' => 'OAuth2',
            'source' => 'mozilla_ispdb',
            'score' => 95,
            'sources' => ['mozilla_ispdb'],
            'match_count' => 1,
        ],
        // more candidates...
    ],
    'smtp' => [
        [
            'host' => 'smtp.gmail.com',
            'port' => 465,
            'ssl' => 'ssl',
            'auth' => 'OAuth2',
            'source' => 'mozilla_ispdb',
            'score' => 95,
            'sources' => ['mozilla_ispdb'],
            'match_count' => 1,
        ],
        // more candidates...
    ],
]
```

## Configuration

```php
$detector = new AutoDetector([
    'timeout_http' => 10,  // HTTP requests (default: 10s)
    'timeout_tcp'  => 3,   // TCP connections (default: 3s)
    'logger'       => $logger,  // PSR-3 logger (optional)
]);

// Threshold: stop early when IMAP+SMTP with score > threshold found
$result = $detector->autoDetect('example.com', threshold: 90);
```

### Logging (PSR-3)

```php
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$logger = new Logger('mail-autodetect');
$logger->pushHandler(new StreamHandler('php://stderr', Logger::DEBUG));

$detector = new AutoDetector(['logger' => $logger]);
```

Log levels:
- `info`: Start/end of detection, threshold reached
- `debug`: Individual strategies, DNS/HTTP requests, cache hits
- `warning`: HTTP/DNS errors

### Caching

DNS and HTTP results are automatically cached (in-memory per request).
Multiple queries for the same domain won't trigger duplicate requests.

## Detection Strategies

The library uses multiple strategies in descending reliability:

| # | Strategy | Score | Description |
|---|----------|-------|-------------|
| 1 | Mozilla ISPDB | 95 | Thunderbird autoconfig database |
| 2 | Known MX | 92 | Known providers (Gmail, Outlook, etc.) via MX pattern |
| 3 | Microsoft Autodiscover | 92 | Exchange/Office 365 (requires email) |
| 4 | DNS SRV | 90 | RFC 6186 service records |
| 5 | Domain Autoconfig | 90 | `autoconfig.domain/mail/config-v1.1.xml` |
| 6 | MX Heuristic | 75-80 | MX record + SPF parsing + TCP check |
| 7 | Standard Hosts | 55-70 | `imap.domain`, `smtp.domain` + TCP check |

**Score calculation:**
- Servers found by multiple sources get +5 bonus per additional source
- Reverse DNS mismatch on guessed hosts: -15 points
- Maximum: 100 points

## Response Format

Each candidate contains:

| Field | Type | Description |
|-------|------|-------------|
| `host` | string | Server hostname |
| `port` | int | Port (993, 465, 587, ...) |
| `ssl` | string | `ssl`, `starttls`, or `plain` |
| `auth` | string\|null | Auth method (if known) |
| `source` | string | Primary source |
| `sources` | array | All sources that found this server |
| `score` | int | Confidence score (0-100) |
| `match_count` | int | Number of sources |

## Security Considerations

> **Important:** This library detects mail server configurations but does NOT validate them.

Before using detected settings with real credentials:

1. **Always confirm with the user** - Show the detected hostname/port and ask for explicit confirmation
2. **Don't auto-connect** - Never automatically test connections with real passwords
3. **Validate the domain** - Ensure the detected hosts belong to the expected domain

Example secure implementation:

```php
$result = $detector->autoDetect($email);
$imap = $result['imap'][0] ?? null;

if ($imap) {
    // Show user the detected settings and ask for confirmation
    echo "Detected IMAP server: {$imap['host']}:{$imap['port']}\n";
    echo "Is this correct? (y/n): ";

    if (readline() !== 'y') {
        // Let user enter settings manually
    }
}
```

**Why this matters:** A malicious domain could configure autoconfig/autodiscover to point to an attacker-controlled server, potentially capturing credentials.

### SSRF protection

The domain is chosen by whoever types the email address, so every outgoing request is guarded
(`MailAutodetect\SafeHttp`, also usable on its own):

- only `http`/`https`, only ports 80 and 443, no credentials in the URL
- the host is resolved (A + AAAA) and **every** address must be public — loopback, RFC 1918,
  carrier-grade NAT, link-local incl. cloud metadata (`169.254.169.254`), multicast, reserved,
  `::1`, `fc00::/7`, `fe80::/10` and IPv4 addresses embedded in IPv6 (`::ffff:`, NAT64, 6to4) are refused
- the connection is pinned to the checked addresses (`CURLOPT_RESOLVE`), so a second DNS answer
  cannot redirect it (DNS rebinding)
- redirects are followed manually, at most 3, and each target is checked again
- connect timeout, total timeout and a cap on the response size (2 MiB)

TCP probes of the candidate servers connect to the checked IP address as well.

`allow_private_ips => true` switches the address check off (intranet setups only).

## License

MIT

## Testing

Static analysis (Mago) plus a self-contained check of the SSRF guard (starts a PHP built-in server for the redirect cases):

```bash
php tests/safe_http_test.php
```
