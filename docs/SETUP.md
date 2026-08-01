# Setup Overview

This guide describes a safe baseline. Component-specific flags may evolve before
1.0; check `bridge/README.md` and `firmware/README.md` for implementation details.

## Preflashed hardware: two steps

### Step 1

On macOS or mainstream Linux, run:

```bash
curl -fsSL https://raw.githubusercontent.com/Homard-Simpson/coinbase-amoled-terminal/main/install.sh | bash
```

Python 3.11+ and Git are required. The installer does not use Docker, modify shell
startup files, request administrator access, or invoke `sudo`. Application source
comes only from this exact repository's `main` branch; isolated pip installs the
declared runtime dependency from official PyPI. It then writes a per-user service
and opens the secure quickstart prompt.

### Step 2

Paste the complete Coinbase CDP ECDSA key JSON at the hidden prompt, or drag the
downloaded JSON file into the terminal, and press Enter. Minified one-line JSON
and file paths with spaces are accepted. The JSON must contain Coinbase's `name`
and `privateKey` fields. Legacy secrets, Ed25519 keys, and any curve other than
P-256/ES256 are rejected.

Before anything is stored, quickstart calls Coinbase's read-only
`/key_permissions` endpoint. It proceeds only when view access is enabled and
trade and transfer access are both disabled. The key name and private PEM are
then written atomically to owner-only files. A separate display ID/token is
created, the user service is started, and `doctor` repeats the live safety gate.
A failed safety check rolls back state created by that attempt when it is safe to
do so.

Quickstart prints the trusted-LAN feed URL, display ID, and protected token-file
path. It never prints the key or token itself. Enter those pairing values in the
preflashed display's setup screen. Do not use the trusted-LAN HTTP URL on a hotel,
guest, public, or otherwise untrusted network; use private HTTPS/tailnet ingress
instead.

The installer writes these per-user components:

- macOS application data under `~/Library/Application Support/`, plus a LaunchAgent
  under `~/Library/LaunchAgents/`;
- Linux application data under `${XDG_DATA_HOME:-~/.local/share}` and a systemd
  user unit under `${XDG_CONFIG_HOME:-~/.config}/systemd/user/`; and
- a convenience command at `~/.local/bin/coinbase-amoled-bridge` when that path is
  available without replacing an existing file.

If launchd or `systemd --user` is unavailable, setup still validates and stores
the configuration, then prints an exact foreground command. Resolve the user
service/session issue or keep that foreground process running while the display
is in use.

Offline sample install:

```bash
curl -fsSL https://raw.githubusercontent.com/Homard-Simpson/coinbase-amoled-terminal/main/install.sh | bash -s -- --sample
```

Idempotent update: rerun the Step 1 command. The installer fast-forwards a clean
checkout, refreshes the virtual environment and service template, revalidates an
existing setup, and never replaces a different command or a modified checkout.

Uninstall while retaining private state:

```bash
curl -fsSL https://raw.githubusercontent.com/Homard-Simpson/coinbase-amoled-terminal/main/install.sh | bash -s -- --uninstall
```

Append `--purge` to that command to explicitly delete credentials, configuration,
and device tokens too.

This flow is for the preflashed hardware package. **Source firmware builders:**
continue with the advanced deployment and build steps below; the source firmware
first-boot portal generates its own device ID, which must be registered with
`coinbase-amoled-bridge device add --device-id <displayed-id>`.

## 1. Choose a deployment

Recommended order:

1. **Same trusted LAN:** bridge host and display share an administered network;
   bridge stays behind a host firewall.
2. **Private tailnet:** use private HTTPS ingress and ACLs when the device must
   reach the bridge across networks.
3. **TLS reverse proxy on a restricted network:** acceptable when a tailnet is not
   available and firewall rules are tightly scoped.

An anonymous public URL is not a supported deployment. Do not use a public tunnel
or funnel for convenience.

## 2. Install development prerequisites

- Git
- Python 3.11 or newer
- Docker Engine/Desktop with Compose v2, if using containers
- ESP-IDF 5.5.x, including the `esp32s3` target, for firmware
- ShellCheck, markdownlint-cli2, and actionlint for complete local validation

Prepare Python tools:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

Run the repository preflight before provisioning secrets:

```bash
./scripts/preflight.sh
```

## 3. Create a least-privilege Coinbase credential

Coinbase changes its developer UI and credential formats over time. Follow the
current official Coinbase documentation, but preserve these constraints:

- create a dedicated credential for this bridge;
- grant only the minimum view/read permissions needed by the displayed fields;
- do not grant trade, transfer, withdrawal, address, or account-management
  permissions;
- restrict source addresses if Coinbase supports it and the bridge has stable
  egress; and
- set a reminder to review and rotate the credential.

If the permission set is unclear, stop. Do not assume that the absence of a trade
button means the key is read-only.

Store the downloaded credential material as `secrets/coinbase-credentials.json`
or the filename expected by the bridge implementation. Never retype it into a
tracked source file.

## 4. Create a separate device-feed token

The feed token is not a Coinbase key. Generate a unique token locally:

```bash
mkdir -m 700 -p secrets
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' \
  > secrets/device-feed-token
chmod 600 secrets/device-feed-token secrets/coinbase-credentials.json
```

Use one token per display when the bridge supports multiple devices. Rotation
should not require replacing the Coinbase credential.

## 5. Configure non-secret settings

```bash
cp .env.example .env
```

Review `.env`. It intentionally contains only ports, cache durations, log level,
public API base URL, and local secret-directory location. If a setting value would
grant access when disclosed, it belongs in a secret file instead.

## 6. Start the bridge

```bash
docker compose up --build
```

The Compose file:

- publishes only to `127.0.0.1`;
- mounts the secrets directory read-only;
- runs with a read-only root filesystem;
- drops Linux capabilities;
- enables `no-new-privileges`; and
- uses a small temporary filesystem for runtime scratch data.

Check health locally:

```bash
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
```

The health response must not include account data, upstream errors containing
payloads, or configuration values.

## 7. Provide private HTTPS ingress

The ESP should validate HTTPS whenever traffic leaves the bridge host.

### Private tailnet

Use your tailnet provider's HTTPS serving feature and ACL policy to expose only
the bridge's feed route. Keep public-sharing/funnel features disabled. Grant access
only to the display identity or its dedicated subnet, and verify the route from an
unauthorized tailnet client is denied.

### Caddy example

`terminal.example.invalid` is a reserved placeholder; replace it with a name you
control and can validate.

```caddyfile
terminal.example.invalid {
    @feed path /v1/device-feed
    handle @feed {
        reverse_proxy 127.0.0.1:8080
    }

    @health path /healthz
    handle @health {
        reverse_proxy 127.0.0.1:8080
    }

    respond 404
}
```

Add network restrictions or mutual TLS as appropriate. Configure access logs not
to capture authorization headers, query tokens, or response bodies.

### Nginx example

```nginx
server {
    listen 443 ssl;
    server_name terminal.example.invalid;

    ssl_certificate /etc/ssl/example/fullchain.pem;
    ssl_certificate_key /etc/ssl/example/private-key.pem;

    location = /v1/device-feed {
        limit_except GET { deny all; }
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header X-Forwarded-Proto https;
        access_log off;
    }

    location = /healthz {
        limit_except GET { deny all; }
        proxy_pass http://127.0.0.1:8080;
        access_log off;
    }

    location / {
        return 404;
    }
}
```

Use certificates and key paths appropriate to your host. Do not copy a private TLS
key into this repository or into a firmware image.

## 8. Build firmware

Export ESP-IDF in the current shell, identify the exact board revision, and provide
local provisioning through environment variables/files documented by the firmware:

```bash
./scripts/build-firmware.sh v1
# or
./scripts/build-firmware.sh v2
```

The wrapper refuses unknown variants. Keep the feed-token file outside the
firmware tree. Generated configuration must be deleted automatically after the
build and remains ignored by Git.

For a no-secret compilation check:

```bash
./scripts/build-firmware.sh v1 --ci-placeholder
./scripts/build-firmware.sh v2 --ci-placeholder
```

Placeholder artifacts use a reserved non-resolving URL and cannot authenticate to
a real bridge.

## 9. Provision and test

1. Flash the artifact labeled for the exact board revision.
2. Confirm the boot log reports the expected variant.
3. Provision Wi-Fi and the private HTTPS feed URL.
4. Provision only the scoped feed token, never the Coinbase credential.
5. Verify a valid feed, then an invalid token, stale cache, bridge outage, and
   malformed response.
6. Power-cycle and confirm reconnect behavior.
7. Crop or blur account values before retaining test screenshots.

## 10. Rotate and deprovision

Rotate the feed token when a board is lost, transferred, returned, or suspected of
extraction. Revoke the Coinbase credential separately if bridge-host compromise is
possible. Before transferring hardware, erase NVS and verify the device no longer
reaches the feed.

## Production checklist

- [ ] Bridge credential is view-only.
- [ ] Bridge listens on loopback.
- [ ] HTTPS or private-tailnet ingress is enforced.
- [ ] Only fixed GET health/feed routes are exposed.
- [ ] Unique feed token is stored outside Git and container layers.
- [ ] Logs exclude headers and account payloads.
- [ ] Correct V1/V2 artifact is selected.
- [ ] Stale/offline state has been tested.
- [ ] `./scripts/preflight.sh` passes.
