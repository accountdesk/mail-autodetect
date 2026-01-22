# Mail-Autodetect Todo

## Must Have

- [x] Code nach `src/` verschieben
- [x] Namespace + `composer.json` + PSR-4 Autoloading
- [x] Testcode in `demo.php` auslagern
- [x] `mago fmt` ausführen
- [x] `mago lint` ausführen
- [x] `mago analyze` ausführen

## Should Have

- [x] API Surface vereinfachen (nur `autoDetect()` public)
- [x] README.md mit Beispielen
- [x] .gitignore
- [x] Logging (Constructor Option, PSR-3 kompatibel)
- [x] Cache (DNS/HTTP Ergebnisse, In-Memory)
- [x] Microsoft Autodiscover (Exchange/Office 365)

## Nice to Have

- [x] CI/CD (GitHub Actions)
- [x] Known MX Entries (Gmail, Outlook, etc. direkt aus MX-Pattern erkennen)

---

## Erledigt

- [x] Mozilla ISPDB Integration
- [x] DNS SRV Records (RFC 6186)
- [x] Domain Autoconfig
- [x] MX-Record Heuristik
- [x] SPF-Record Parsing (rekursiv)
- [x] Standard-Hostnamen raten + TCP-Check
- [x] Reverse DNS Prüfung
- [x] Konfigurierbare Timeouts
- [x] Deduplizierung mit Score-Kombination
