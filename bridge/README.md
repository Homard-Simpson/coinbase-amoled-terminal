# Coinbase AMOLED Bridge

A small, consumer-facing Python bridge for an **unofficial** Coinbase AMOLED
terminal. It converts a Coinbase Advanced Trade account into one compact,
authenticated, read-only device feed.

This project is not affiliated with, endorsed by, or supported by Coinbase.
It never trades. It is not trading or investment advice.

## Security properties

- Coinbase access is limited in code to a closed allowlist of Advanced Trade
  **GET** endpoints.
- Startup checks `GET /api/v3/brokerage/key_permissions` and refuses to bind
  unless `can_view=true`, `can_trade=false`, and `can_transfer=false`.
- The upstream origin is fixed to `https://api.coinbase.com`; redirects are not
  followed and users cannot configure another upstream URL.
- There is no HTTP admin API. Setup, allowlist changes, and token rotation are
  local CLI operations only.
- Every terminal gets an opaque device ID and an independent 256-bit bearer
  token. Only the SHA-256 token digest is stored in `config.json`.
- Coinbase credentials and generated bearer tokens are never printed. Setup
  writes secrets to mode-0600 files.
- Public handlers accept only `GET` and `HEAD`; mutation methods return `405`.
- Per-IP and per-device token buckets, bounded concurrency, request/header/body
  limits, socket timeouts, no-cache/security headers, and redacted JSON logs are
  enabled by default.
- Versioned JSON config is locked, validated, atomically replaced, and backed up
  before migration. Unknown future schemas fail closed.

Read [SECURITY.md](SECURITY.md) before exposing the bridge to any network.

## Feed contents

`GET /v1/device-feed` returns a compact, numeric, privacy-minimized document
matched to the firmware parser:

- `schema_version: 1`, `read_only: true`, and `mode: live|sample`
- `prices`: a live price number per configured symbol
- `candles`: up to 30 recent one-minute `[timestamp, open, high, low, close,
  volume]` arrays per symbol, plus a short numeric `price_history`
- `positions`: open positions only, keyed by symbol, each with `side`, `entry`,
  `pnl`, and size
- `portfolio`: `positions_value`, `unrealized_pnl`, and `realized_pnl_today`

The device response contains **no cash balance, total account value, or
derivatives collateral** — only open-position values and market data. Internally
the bridge fetches richer Coinbase data (spot, CFM futures, and, where available,
INTX perpetuals) and projects it to this contract in
[device_feed.py](src/coinbase_amoled_bridge/device_feed.py).

The bridge requests up to 120 one-minute buckets and keeps the newest 30 valid
buckets. It never fabricates missing live candles; a thin or unavailable market
simply yields fewer. Sample mode always provides 30 synthetic candles.

The versioned schema is [docs/device-feed.schema.json](docs/device-feed.schema.json).
Account UUIDs, portfolio UUIDs, wallet names, API permissions, device IDs, cash
balances, and credentials are never included in device responses.

## Supported symbols

Defaults: **BTC, SOL, XLM, HYPE, ETH**. A safe generic mapping turns an uppercase
base symbol such as `DOGE` into `DOGE-USD`. Explicit `BASE-USD` input is accepted;
path separators, extra product segments, non-USD quotes, and unsafe characters
are rejected.

```sh
coinbase-amoled-bridge --data-dir ./data symbols set BTC,SOL,XLM,HYPE,ETH,DOGE
```

Restart after changing symbols. A Coinbase product that does not exist is marked
unavailable without taking down other markets.

## Requirements

- Python 3.11+
- `cryptography` (the only runtime dependency)
- A dedicated Coinbase CDP **ECDSA / ES256** API key with view permission only

Coinbase App Advanced Trade does not support Ed25519 keys. In CDP, select ECDSA,
turn off trade and transfer permissions, restrict the key to the intended
portfolio, and add an IP allowlist where practical.

## Install

```sh
cd bridge
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

## Secure one-prompt quickstart

The root `install.sh` invokes this automatically after installing its per-user
launchd/systemd service:

```sh
coinbase-amoled-bridge --data-dir ./data quickstart
```

At one hidden prompt, paste the downloaded Coinbase CDP ECDSA JSON or drag the
JSON file into the terminal. The parser accepts Coinbase's `name` and
`privateKey` fields, validates an unencrypted P-256/ES256 PEM, and rejects Legacy,
Ed25519, RSA, malformed, and oversized inputs. It checks `/key_permissions`
before saving, stores only the key name and private PEM in atomic mode-0600 files,
creates/reuses one display credential, starts the installed user service, and
runs `doctor`. Newly created state is rolled back if final validation fails.
Credential and device-token values are never printed.

The installer configures the authenticated feed on trusted-LAN port `8788` for a
preflashed package pairing screen. Use private HTTPS/tailnet ingress on any
untrusted network. Source-built firmware generates its own device ID; register it
with the advanced `device add --device-id` command.

## Offline/sample quick start

Sample mode does not read Coinbase credentials or make network requests, but it
still requires device authentication.

```sh
coinbase-amoled-bridge --data-dir ./data quickstart --sample
# Or use the lower-level commands:
coinbase-amoled-bridge --data-dir ./data setup --sample --non-interactive
coinbase-amoled-bridge --data-dir ./data doctor --sample
coinbase-amoled-bridge --data-dir ./data serve --sample
```

Setup prints the generated **device ID** and the path to its protected token
file. It deliberately does not print the token value. Configure the terminal to
send:

```text
X-Device-ID: <opaque device ID>
Authorization: Bearer <contents of that device's protected token file>
```

Never put the bearer token in a URL or query string.

## Live credential setup

Credential source priority is:

1. direct environment pair
2. paths supplied through environment
3. Docker secrets at conventional paths
4. private files created by interactive setup

### Interactive local setup (recommended)

```sh
coinbase-amoled-bridge --data-dir ./data setup
```

The key name prompt is hidden. The CLI then asks for the path to the downloaded
ECDSA private-key PEM, validates it, and copies both values into private files.
It also creates the first device unless `--no-device` is supplied.

For non-interactive local provisioning, put the key name and PEM in separate
protected files and pass only their paths:

```sh
coinbase-amoled-bridge --data-dir ./data setup --non-interactive \
  --key-name-file /secure/input/key-name \
  --private-key-file /secure/input/private-key.pem
```

No CLI option accepts a credential value, which keeps values out of command
history and process arguments.

### Environment or file secrets

Direct environment variables (supported, but file secrets are safer):

- `COINBASE_API_KEY_NAME`
- `COINBASE_API_PRIVATE_KEY` (literal newlines or escaped `\n`)

File-secret environment variables:

- `COINBASE_API_KEY_NAME_FILE`
- `COINBASE_API_PRIVATE_KEY_FILE`

Docker secrets are discovered automatically at:

- `/run/secrets/coinbase_api_key_name`
- `/run/secrets/coinbase_api_private_key`

Do not bake any secret into an image, Compose file, source tree, or firmware
repository.

### Verify and serve

```sh
coinbase-amoled-bridge --data-dir ./data doctor
coinbase-amoled-bridge --data-dir ./data serve
```

`doctor` and `serve` both verify the key's permissions. A trade-capable,
transfer-capable, malformed, inaccessible, or unverifiable key fails closed.
The server does not bind first and check later.

## Device administration (local CLI only)

```sh
coinbase-amoled-bridge --data-dir ./data device list
coinbase-amoled-bridge --data-dir ./data device add --label kitchen-terminal
coinbase-amoled-bridge --data-dir ./data device rotate <device-id>
coinbase-amoled-bridge --data-dir ./data device revoke <device-id>
coinbase-amoled-bridge --data-dir ./data device enable <device-id>
```

Use generated IDs, or supply your own 12-64 character opaque value with
`--device-id`. Do **not** use a MAC address, email, account ID, serial number, or
other identifying value. Allowlist changes hot-reload (normally within one
second). Rotation writes a new token file and immediately invalidates the old
token. Replacing an existing custom `--token-file` requires the explicit
`--replace-token-file` flag; protected config/credential paths are always
rejected.

## HTTP surface

| Method | Path | Authentication | Purpose |
|---|---|---|---|
| `GET`, `HEAD` | `/healthz` | none | process liveness only |
| `GET`, `HEAD` | `/readyz` | none | configured/ready state only |
| `GET`, `HEAD` | `/v1/device-feed` | device ID + bearer | device data |

No query parameters are accepted. There are no setup, admin, metrics, debug,
order, transfer, or proxy routes. Health responses do not reveal symbols,
devices, credentials, balances, or upstream errors.

## TLS and public deployment

The default bind is `127.0.0.1:8788`. Plain HTTP on a non-loopback interface is
refused unless it is explicitly acknowledged for use behind a trusted TLS
reverse proxy or inside a private container network.

Built-in TLS:

```sh
coinbase-amoled-bridge --data-dir ./data serve \
  --host 0.0.0.0 --tls-cert /secure/tls/fullchain.pem --tls-key /secure/tls/key.pem
```

Reverse-proxy deployment:

```sh
coinbase-amoled-bridge --data-dir ./data serve \
  --host 0.0.0.0 --allow-insecure-public-bind
```

That flag does not make HTTP safe. Restrict the listener to the private proxy
network, terminate modern TLS at the proxy, preserve client-rate protections at
the edge, and never publish the bridge's plain-HTTP port directly.

## Docker

The image runs as UID/GID `10001`, drops root after installation, and includes a
liveness health check. Prepare a writable mode-0700 `data/` directory for that
UID, a mode-0700 `secrets/` directory, and mode-0600 secret files; then review
`compose.example.yaml`.

```sh
docker build -t coinbase-amoled-bridge:local .
docker compose -f compose.example.yaml run --rm bridge setup --non-interactive
docker compose -f compose.example.yaml run --rm bridge device add
docker compose -f compose.example.yaml up -d
```

The example publishes only to host loopback. Put HTTPS in front before remote
access. Its container filesystem is read-only, capabilities are dropped,
`no-new-privileges` is set, PID count is bounded, and only `/data` is writable.

## Configuration and operations

Useful environment controls:

- `BRIDGE_DATA_DIR`
- `BRIDGE_HOST`, `BRIDGE_PORT`
- `BRIDGE_SAMPLE_MODE=true|false`
- `BRIDGE_TLS_CERT`, `BRIDGE_TLS_KEY`
- `BRIDGE_LOG_LEVEL=DEBUG|INFO|WARNING|ERROR|CRITICAL`
- `BRIDGE_ALLOW_INSECURE_PUBLIC_BIND=true|false`

Service tuning (refresh, staleness, rate limits, concurrency, derivatives) lives
in the validated `settings` object in `config.json`. Stop the service before a
manual edit; malformed, unknown, or secret-bearing fields are rejected.
Prefer the CLI for supported changes.

Logs are one-line JSON. Remote addresses are process-salted hashes; authorization
headers, token-like fields, CDP key names, bearer patterns, and PEM blocks are
redacted. The bridge never logs upstream response bodies or account payloads.
Still treat logs as sensitive operational data.

### Staleness behavior

A failed component refresh retains the last good value while it is within
`max_stale_seconds`, marks errors/degradation immediately, becomes stale after
`stale_after_seconds`, and is removed from the device payload after expiry.
This avoids silently presenting indefinitely old balances or prices.

### Derivatives note

CFM futures are queried through the current read-only Advanced Trade GET
endpoints. Legacy INTX perpetual GET endpoints are supported best-effort, but
Coinbase documents their retirement for September 9, 2026. Deployers using INTX
must follow Coinbase's derivatives migration guidance; an unavailable INTX
portfolio is isolated from spot/CFM data.

## Tests

The suite is offline and uses generated keys plus synthetic provider fixtures.
It never contacts Coinbase.

```sh
python -m unittest discover -s tests -t . -v
```

Coverage includes JWT signing/verification, GET allowlisting, view-only gates,
credential sources, token hashing/rotation/revocation, config migration and
rollback behavior, symbol validation, feed parsing/staleness/expiry, sample
candles, redaction, rate limiting, health/auth headers, no-admin behavior, and
HTTP mutation rejection.

## License

Original bridge software is licensed under GNU AGPL-3.0-or-later; see
[LICENSE](LICENSE). The AGPL network-source obligations matter when a modified
bridge is offered as a network service. AGPL-compliant commercial use and resale
remain allowed without royalty. Optional proprietary exceptions are described in
[commercial licensing](../COMMERCIAL-LICENSING.md).
