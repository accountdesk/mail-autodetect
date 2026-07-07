# Changelog

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
