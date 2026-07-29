# Security policy

Report security issues privately to the project maintainer before public disclosure.

## Credential boundaries

- Keep all Coinbase/exchange API keys on the bridge.
- Give each display a unique, revocable bridge bearer token.
- Allowlist the generated device UUID together with that token.
- Never publish provisioned firmware images, NVS partitions, flash dumps, or serial logs captured with local modifications.

## Production hardening

This reference firmware provides a protected local setup AP, CSRF values, physical OTA arming, dual-slot validation/rollback, bounded parsing, redirect refusal, and fail-closed `read_only` enforcement. A commercial deployment should additionally enable ESP32-S3 Secure Boot, flash encryption, signed OTA, a managed token-rotation/revocation service, and a bridge TLS certificate chain trusted by ESP-IDF.

The setup AP password and bearer token are stored in NVS. Without flash encryption, physical flash access can recover them; revoke the token after loss or factory reset.
