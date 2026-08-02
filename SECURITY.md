# Security Policy

## Supported versions

The project is pre-1.0. Security fixes are made only on the default branch until
the first supported release line is announced. Unreleased snapshots and old
firmware images may not receive fixes.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.
Submit a private vulnerability report through GitHub's reporting feature on the
repository **Security** tab. Include:

- the affected component and revision;
- a minimal reproduction or proof of concept;
- realistic impact and required attacker access;
- whether any real credential or account data may have been exposed; and
- a safe way to validate a proposed fix.

Do not include live credentials, feed tokens, account payloads, balances,
personal infrastructure, or unredacted logs. If private reporting is not enabled,
ask a maintainer in a public issue to enable it without disclosing details.

Maintainers will acknowledge a complete report when practical, assess severity,
coordinate a fix, and credit reporters who request credit. This project does not
currently operate a paid bug-bounty program or promise a fixed response time.

## Security invariants

Changes must preserve these boundaries:

1. **Coinbase credentials remain on the local bridge.** They must never be
   compiled into firmware, posted to the ESP setup portal, returned by an
   endpoint, written to URLs/browser storage/client logs, or placed in an image.
2. **The Coinbase credential is view-only.** Configure it without trade,
   transfer, withdrawal, or address-management permissions.
3. **The ESP receives only a scoped feed token.** A feed token authenticates one
   device to the minimal display feed. It is not a Coinbase credential.
4. **No trading surface exists.** The bridge must not implement order placement,
   cancellation, modification, transfer, or withdrawal routes.
5. **Network exposure stays private.** The standalone CLI binds to loopback. The
   two-step installer explicitly opens the authenticated feed on the host's
   trusted LAN so the display can pair; do not use that mode on an
   untrusted network or expose it through router forwarding. Use a private
   tailnet or an authenticated TLS reverse proxy for cross-network access.
6. **Logs and errors are minimized.** Never log authorization headers, setup
   submissions, raw Coinbase responses, credential files, Wi-Fi passwords, feed
   tokens, or full portfolio payloads.
7. **Local onboarding is one-time and loopback-only.** Expiring setup and CSRF
   values, strict Origin/CORS/PNA checks, bounded bodies, and rollback must remain
   mandatory. The browser never sends a Coinbase key to the ESP.

Any pull request that weakens one of these invariants requires explicit security
review and should normally be rejected.

## Operator hardening checklist

- Use a dedicated, least-privilege Coinbase credential.
- Store credentials in a local secret store or owner-readable file outside Git.
- Use a unique random feed token per display and rotate it after loss or resale.
- Keep the bridge and reverse proxy patched.
- Terminate TLS before traffic leaves the bridge host.
- Restrict inbound access by host firewall and private-network policy; allow
  installer port 8788 only from the trusted display LAN.
- Avoid displaying sensitive values where shoulder surfing is possible.
- Erase device NVS before transferring hardware to another person.
- Review dependency and CodeQL alerts before each release.
- Treat any CI-built firmware as non-production because CI uses placeholders.

## If a secret is exposed

1. Revoke or rotate the credential at its source immediately.
2. Rotate every affected device-feed token.
3. Remove the secret from the current tree and from Git history using an
   appropriate history-rewrite tool.
4. Invalidate cached artifacts, releases, container layers, and CI logs.
5. Audit account access and bridge logs without copying sensitive payloads into an
   issue.
6. Document the incident and preventive fix privately before publishing a
   sanitized advisory.

Deleting a secret in a later commit is not sufficient; Git history is durable.

## Known limitations

- A compromised bridge host can read everything available to its Coinbase
  credential and can falsify display data.
- A stolen feed token may reveal the minimized feed until it expires or is
  rotated.
- TLS protects transport, not a compromised endpoint.
- The display itself can expose portfolio data to anyone who can see or possess
  it.
- This project cannot guarantee Coinbase API availability or data freshness.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full analysis.
