# Changelog

## [0.4.0] - 2026-10-23
- Security: HTTP requests (autoconfig, ISPDB, autodiscover) no longer follow
  redirects blindly. New `SafeHttp` client: only http/https on ports 80/443,
  every resolved address (A + AAAA) must be public, the connection is pinned
  to the checked addresses via `CURLOPT_RESOLVE` (no DNS rebinding), at most
  3 redirects with a fresh check per hop, connect/total timeout, 2 MiB body cap.
- Security: the private-address check now covers carrier-grade NAT,
  benchmarking/documentation ranges, multicast, `::`, site-local and IPv4
  addresses embedded in IPv6 (IPv4-mapped, NAT64, 6to4, Teredo) — previously
  only `filter_var` ranges and only the first IPv4 address of a host.
- Removed the unused `get_tcp_info()` (connected by hostname, unpinned).
- New option `trusted_ips` (tests only) and `resolver` (custom DNS lookup).

## [0.3.1] - 2026-07-07
- Fixed: TCP batch check no longer hangs indefinitely. The `ssl://` wrapper
  does not support `STREAM_CLIENT_ASYNC_CONNECT` and silently fell back to a
  synchronous connect + TLS handshake without timeout (20s+ per check against
  firewalled hosts, hanging PHP-FPM workers). Connects now always use `tcp://`
  with TLS negotiated afterwards via non-blocking `stream_socket_enable_crypto()`.
- Fixed: SSL candidates (IMAPS 993, SMTPS 465) were never detected because the
  broken `ssl://` async connect always failed with `EINPROGRESS`.
- Banner read is now non-blocking with a hard per-socket deadline (previously a
  blocking `fread()` that could stall the whole batch).
- SNI/certificate verification now uses the original hostname (`peer_name`)
  even though the connect goes to the resolved IP.

## [0.2.0] - 2025-01-23
- Optimized detection speed
- Improved autodetect algorithm

## [0.1.0] - Initial Release
- Multi-strategy mail server detection
- Support for Mozilla ISPDB, Microsoft Autodiscover, DNS SRV
- PSR-3 logging support
