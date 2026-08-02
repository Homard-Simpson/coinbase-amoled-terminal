# Setup Overview

This guide describes a safe baseline. Component-specific flags may evolve before
1.0; check `bridge/README.md` and `firmware/README.md` for implementation details.

## Consumer setup: two steps

> **Current stable release:** `v2.0.0`, signed and hardware-verified for both
> Waveshare V1 and V2 revisions.

### Step 1

Plug in one display with a USB data cable and run:

```bash
curl -fsSL https://raw.githubusercontent.com/Homard-Simpson/coinbase-amoled-terminal/v2.0.0/install.sh | bash -s -- --version v2.0.0
```

The installer requires Python 3.11+ and Git. It finds exactly one likely USB
serial device, creates an isolated Python/esptool environment, verifies a
versioned release manifest and every SHA-256 artifact, installs the local bridge
without Docker or administrator access, flashes only declared firmware regions,
and writes a short-lived setup session to the dedicated onboarding partition.
It does not erase unrelated NVS.

If the existing device contains an official image whose exact flash hash appears
in the release manifest, that trusted hash identifies the model. Otherwise the
installer asks which **display controller** the unit has:

- **V1 / SH8601 display**, normally with FT5x06 or FT3168 touch; or
- **V2 / CO5300 display**, normally with CST820 or CST816S touch.

Check the listing, packaging, board marking, or Waveshare example folder for
`SH8601` or `CO5300`. Both versions use an ESP32-S3 and a 368 × 448 AMOLED, so USB
names, chip identity, flash size, and screen dimensions cannot identify the model.
The installer selects neither by default and fails closed instead of trying both.

### Step 2

Join the protected setup Wi-Fi shown on the display. Its captive portal asks for
home Wi-Fi and the downloaded Coinbase CDP ECDSA JSON. Press **Finish**.

Portal JavaScript sends that Coinbase JSON directly from the browser to an
authenticated localhost-only endpoint on this computer. It is never submitted
to `/save`, and the ESP cannot read it. The localhost bridge validates P-256
key material, calls `/key_permissions`, refuses trade or transfer capability,
then atomically stores the key name and private PEM in an owner-only credential
bundle. A failed validation stores nothing.

The browser sends the ESP only home Wi-Fi, the local feed URL, a UUIDv4 device
ID, and a random revocable `cbat_` token. The setup and CSRF tokens are
short-lived, single-use, and carried in request headers—not URLs. The local
service binds only to `127.0.0.1`, accepts only exact portal/localhost origins and
CORS/PNA preflights, and uses no cookies, external assets, analytics, autocomplete,
or browser storage. If a captive mini-browser blocks localhost, the portal opens
a same-computer localhost fallback page backed by the same session. See
[Secure two-step onboarding](SECURE_ONBOARDING.md) for the complete boundary.

The installer writes these per-user components:

- macOS application data under `~/Library/Application Support/`, plus a LaunchAgent
  under `~/Library/LaunchAgents/`;
- Linux application data under `${XDG_DATA_HOME:-~/.local/share}` and a systemd
  user unit under `${XDG_CONFIG_HOME:-~/.config}/systemd/user/`; and
- a convenience command at `~/.local/bin/coinbase-amoled-bridge` when that path is
  available without replacing an existing file.

If launchd or `systemd --user` cannot start, setup stops before provisioning the
display and rolls back new local state. Fix the user service/session, then run the
same install line again.

Offline sample install from a checked-out source tree:

```bash
./install.sh --sample
```

Idempotent update: rerun the Step 1 command with a newer approved version. The
installer refreshes its isolated environment and service template, validates the
manifest before flashing, and never replaces a different command or modified
checkout.

Uninstall while retaining private state:

```bash
./install.sh --uninstall
```

Append `--purge` to that command to explicitly delete credentials, configuration,
and device tokens too.

Reviewers may use `--manifest-url` only with the explicit
`--allow-unverified-test-artifacts` acknowledgement. **Source firmware builders:**
continue with the advanced steps below and choose the exact V1 or V2 revision.

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
