# Security policy

## Hard boundaries

- The Coinbase client signs and sends only `GET` requests to a closed allowlist
  below `https://api.coinbase.com/api/v3/brokerage/`.
- No order, preview, transfer, convert, allocation, sweep, or other mutation
  endpoint is implemented.
- Startup calls `GET /key_permissions` and refuses to bind unless the key has
  `can_view=true`, `can_trade=false`, and `can_transfer=false`.
- The HTTP service exposes only `GET`/`HEAD` health routes and the authenticated
  device feed. There is no HTTP admin route.
- Raw Coinbase credentials never enter `config.json`. Device bearer tokens are
  stored there only as SHA-256 digests.

These are defense-in-depth controls, not permission to use a broadly privileged
Coinbase key. Create a dedicated ECDSA key with **view only**, portfolio and IP
restrictions, and no trade or transfer capability.

## Deployment expectations

1. Keep the bridge and its data directory patched and access-controlled.
2. Use HTTPS end to end. The default host bind is loopback. A non-loopback plain
   HTTP bind requires an explicit unsafe acknowledgement and is intended only
   behind a trusted TLS reverse proxy or inside a private container network.
3. Do not place bearer tokens in URLs, shell history, screenshots, tickets, or
   logs. The setup CLI writes them to mode-0600 files and never prints values.
4. Give every physical terminal a separate opaque device ID and token. Revoke or
   rotate that one device if it is lost.
5. Protect logs even though the JSON formatter redacts known credential forms.
6. Do not expose the config/data volume from a web server.

## If a secret may be exposed

1. Revoke the Coinbase API key in CDP immediately.
2. Stop the bridge and provision a new dedicated view-only ECDSA key.
3. Rotate affected device tokens with `device rotate`.
4. Review access logs and network exposure without pasting secrets into a report.

## Reporting a vulnerability

Do not include API keys, private keys, device tokens, account values, or private
URLs in a public issue. Contact the maintainer through a private channel and
provide a minimal reproduction using synthetic/sample data.

This project is unofficial and is not affiliated with or endorsed by Coinbase.
