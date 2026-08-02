# Coinbase AMOLED Terminal

Your Coinbase account, on a tiny screen. Your key stays on your computer. This
display can't trade.

> [!IMPORTANT]
> This independent project is **not affiliated with, endorsed by, or sponsored by
> Coinbase**. Coinbase and related marks belong to their respective owners. This
> software is not financial advice and must not be used as a substitute for the
> official Coinbase interfaces.

> [!CAUTION]
> Use a dedicated Coinbase CDP **view-only P-256 ECDSA** key. The installer rejects
> keys with trade or transfer permission, but you should still verify permissions
> in Coinbase before setup.

## Step 1 — plug in and run one command

Connect the **Waveshare ESP32-S3 Touch AMOLED 1.8** with a USB data cable. The
release command installs the local read-only bridge, verifies the matching
firmware, flashes only approved regions, and places a one-time setup session on
the display. It runs as you. No `sudo`. No Docker.

Run the version-pinned one-line installer:

```bash
curl -fsSL https://raw.githubusercontent.com/Homard-Simpson/coinbase-amoled-terminal/v2.0.0/install.sh | bash -s -- --version v2.0.0
```

The tag and firmware manifest are immutable and signed; the installer verifies
release identity, board revision, every flashed region, and SHA-256 before writing.
Reviewers can instead supply an explicit test manifest. That path requires the
loud `--allow-unverified-test-artifacts` flag and is never presented as a
production install.

## Step 2 — join the display Wi-Fi

Join the setup Wi-Fi shown on the display. Its captive portal asks for two things:

1. your home Wi-Fi; and
2. the Coinbase CDP **ECDSA** API-key JSON you downloaded.

Press **Finish**. The page securely hands the Coinbase JSON straight to the
localhost bridge on this same computer. It sends the display only Wi-Fi, a local
feed address, a device ID, and a revocable read-only token.

If an operating system's small captive window blocks localhost, the portal gives
you one button to open the same setup on the computer. It is still the same two
steps. This is a same-computer flow, not phone-only setup.

Unsafe Coinbase keys are rejected. The key must be P-256 ECDSA and strictly
view-only. A key that can trade or transfer is never saved.

### What happens behind the scenes

- The installer accepts exactly one USB serial device. It never identifies a
  board from a port name, USB ID, chip model, flash size, or panel probing.
- An existing official image may identify V1 or V2 only when its exact firmware
  hash is present in the downloaded release manifest. Otherwise the installer
  asks once for V1 or V2, with a clear hardware-identification link. No choice is
  preselected; unattended ambiguity stops safely.
- Every release artifact and flash region is declared in a versioned manifest and
  verified with SHA-256 before writing. Unrelated NVS is preserved.
- The one-time localhost session is short-lived, single-use, and authenticated.
  It has no analytics, external assets, cookies, browser storage, or secret URLs.
- The read-only bridge runs as your normal user through launchd or systemd.

### Which display version do I have?

V1 and V2 refer to the **AMOLED display electronics**, not a different ESP32:

- **V1 — SH8601 display controller** with an FT5x06/FT3168-family touch controller.
  Choose **V1 / SH8601** in the installer.
- **V2 — CO5300 display controller** with a CST820/CST816S-family touch controller.
  Choose **V2 / CO5300** in the installer.

Check the product listing, packaging, board revision, or Waveshare example folder
for `SH8601` or `CO5300`. Both versions look similar and use the same 368 × 448
screen, so USB port names and the ESP32-S3 chip cannot identify the display model.
If it is still unclear, use Waveshare's
[Version Options guide](https://www.waveshare.com/wiki/ESP32-S3-Touch-AMOLED-1.8#Version_Options).
Do not guess or try both: V1 performs display power setup that must not run on the
V2/CO5300 model.

Safe local sample mode (no Coinbase account, credential, or flashing):

```bash
./install.sh --sample
```

Uninstall the app and service while keeping private setup data:

```bash
./install.sh --uninstall
```

Add `--purge` after `--uninstall` only when you also want to delete local
credentials, configuration, and device tokens.

### Updates, recovery, and reset

- **Update:** rerun Step 1 with a newer approved version. Board and checksum
  checks run again; saved NVS is preserved.
- **Automatic V2 update:** V2 checks the official release channel in the
  background and installs only a strictly newer stable V2 application whose
  board identity, version, size, and SHA-256 are authenticated by the pinned
  Ed25519 release key. V1 remains manual-update only.
- **Physical controls:** POWER short press enters/wakes standby. BOOT short press
  activates the blue bottom button, BOOT release after 0.8 to under 10 seconds
  toggles privacy mode, and an uninterrupted 10-second BOOT hold arms manual OTA.
- **Setup expired or interrupted:** reconnect USB and rerun the same command. New
  local state is rolled back unless the display confirms its final save.
- **Lost display:** revoke that display's token on the bridge. The Coinbase key
  does not need to be copied to or recovered from the hardware.
- **Factory reset:** hold BOOT for 10 seconds, join the protected display Wi-Fi,
  and type `RESET` in the portal. This clears Wi-Fi, device identity/token, and
  one-time setup metadata while leaving firmware installed. The USB recovery
  helper erases those same two data partitions only.

## Actual interface — v2.0.0

These are direct 368 × 448 framebuffer captures from the production firmware
renderer using current public market data. They are not concepts or hand-designed
mockups. Account fields are hidden by the renderer's privacy mode.

### Live prices

![Production prices page showing five public markets](docs/images/prices-page-v2.0.0.png)

Five public markets with live prices, short-window direction, a consolidated
battery/status/12-hour-time header, and tap targets for expanded charts.

### Positions in privacy mode

![Production positions page with account fields obfuscated](docs/images/positions-privacy-page-v2.0.0.png)

The actual account page with portfolio, position, quantity, entry, P&L, and
closed-position fields obfuscated before framebuffer output.

### BTC candles, BB20, and key levels

![Production BTC candle chart with Bollinger bands and support and resistance](docs/images/btc-chart-bb20-levels-v2.0.0.png)

Real hourly BTC-USD candles with volume-weighted body widths, BB20 upper/lower and
middle bands, live-price marker, muted left-axis prices, and public-data
support/resistance levels.

See [capture provenance](docs/INTERFACE_CAPTURE.md) for renderer source hashes,
raw framebuffer checksums, the immutable public-data snapshot, and reproduction
steps.

## Status

`v2.0.0` is the first stable public release. Interfaces and provisioning may
continue to evolve, but the security-first defaults, dual-board hardware guards,
and read-only trading boundary remain non-negotiable release requirements.

## Sustainable project model

The open-source licenses permit personal and commercial use, modification,
hosting, support, and resale when their terms are followed. Compliant commercial
resale owes the project no royalty. Buying hardware or support is not required to
use the source.

The maintainers may separately offer official preassembled or preflashed
hardware, integration, updates, and support. They may also offer a paid
proprietary exception for closed-source use. Those optional offerings fund
maintenance; they do not remove the open-source option or imply Coinbase
endorsement. See [commercial licensing](COMMERCIAL-LICENSING.md).

## What it does

- Shows selected public market prices, compact history, and read-only portfolio
  data on a 368 × 448 AMOLED display.
- Supports the Waveshare ESP32-S3 Touch AMOLED 1.8 V1 and V2 hardware revisions.
- Preserves the same POWER standby/wake and BOOT action/privacy/manual-OTA
  controls on both board revisions.
- Keeps Coinbase API credentials on a bridge you control.
- Gives the display only a separate, scoped device-feed token.
- Supports local-network or private-tailnet deployments by default.
- Builds both hardware variants in CI with non-production placeholder settings.

## What it deliberately does not do

- Place, edit, cancel, or simulate orders.
- Expose trading or order-management endpoints.
- Store Coinbase API credentials on the ESP32.
- Provide a hosted relay, telemetry service, analytics, or cloud account.
- Promise portfolio accuracy, uptime, execution safety, or investment outcomes.

## Security model in one minute

```mermaid
flowchart LR
    C[Coinbase read-only API] -->|authenticated read requests| B[Local bridge]
    K[(Local credential file or secret store)] --> B
    B -->|minimal cached feed| R[TLS reverse proxy or private tailnet]
    R -->|scoped feed token| E[ESP32 AMOLED]
    E -. no Coinbase credentials .-> E
    B -. no trading routes .-> B
```

The bridge is the only component that can read Coinbase credentials. The device
receives a minimized display payload through a read-only feed route. Bind the
bridge to loopback, expose it only through a private tailnet or an authenticated
TLS reverse proxy, and use a Coinbase key restricted to view-only permissions.

See [Architecture](docs/ARCHITECTURE.md) and
[Threat model](docs/THREAT_MODEL.md) for the full trust-boundary analysis.

## Hardware support

| Board | Display | Touch | Build variant | Status |
| --- | --- | --- | --- | --- |
| Waveshare ESP32-S3 Touch AMOLED 1.8 V1 | SH8601 | FT5x06 family | `v1` | Supported |
| Waveshare ESP32-S3 Touch AMOLED 1.8 V2 | CO5300 | CST816S/CST820 family | `v2` | Supported |

Board revisions are not electrically interchangeable. In particular, V2 must not
receive V1-specific PMU initialization writes. Confirm the revision before
flashing. Details: [Hardware compatibility](docs/HARDWARE_COMPATIBILITY.md).

## Repository layout

```text
install.sh  Two-step per-user installer entry point
installer/  Fixed launchd/systemd templates and safe renderer
bridge/     Local read-only feed service; owns Coinbase credentials
firmware/   ESP-IDF application for V1 and V2 boards
docs/       Architecture, setup, security, and release documentation
scripts/    Public-safety checks, CI helpers, and the one-command preflight
tests/      Repository, installer, and scanner tests
.github/    CI, dependency updates, and contribution templates
```

## Documentation

- [Setup overview](docs/SETUP.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Hardware compatibility](docs/HARDWARE_COMPATIBILITY.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Security policy](SECURITY.md) and [privacy notes](PRIVACY.md)
- [Release checklist](docs/RELEASE_CHECKLIST.md)
- [Public-release checklist](docs/PUBLIC_RELEASE_CHECKLIST.md)
- [Interface capture provenance](docs/INTERFACE_CAPTURE.md)
- [Branch protection status](docs/BRANCH_PROTECTION.md)
- [Licensing scope](LICENSING.md) and [commercial licensing](COMMERCIAL-LICENSING.md)
- [Contributor License Agreement](CONTRIBUTOR_LICENSE_AGREEMENT.md)
- [Trademark policy](TRADEMARKS.md)

## Advanced source/developer setup

Use this section when building firmware from source, developing the bridge, or
configuring private HTTPS/tailnet ingress manually.

### 1. Review the boundaries

Read [SECURITY.md](SECURITY.md), [PRIVACY.md](PRIVACY.md), and the
[setup overview](docs/SETUP.md). Create a Coinbase credential with read-only/view
permissions; never enable transfer or trading permissions for this project.

### 2. Prepare local development tools

Requirements:

- Python 3.11 or newer
- ESP-IDF 5.5.x for firmware builds
- Docker Compose v2 (optional, for the bridge)
- ShellCheck, markdownlint-cli2, and actionlint (recommended for full preflight)

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

### 3. Configure placeholders, then secrets

```bash
cp .env.example .env
mkdir -m 700 secrets
```

`.env` contains only non-secret runtime settings. Put credentials and the device
feed token in separate files under `secrets/`; that directory is ignored by Git.
The exact file formats and least-privilege guidance are in
[docs/SETUP.md](docs/SETUP.md). Do not paste secrets into Compose files, firmware
headers, issue reports, logs, or screenshots.

### 4. Run the local bridge

```bash
docker compose up --build
```

The provided Compose configuration publishes the bridge on loopback only. It is a
development baseline, not a public-internet deployment. Add a TLS reverse proxy
or private tailnet before connecting a remote display.

### 5. Build the correct firmware variant

With ESP-IDF exported in the current shell:

```bash
./scripts/build-firmware.sh v1
# or
./scripts/build-firmware.sh v2
```

No secrets are compiled in. During the installer flow, the captive portal accepts
home Wi-Fi and sends the Coinbase JSON directly to the authenticated localhost
endpoint. The ESP receives only Wi-Fi, the bridge feed URL, a UUIDv4 device ID,
and the per-device bearer token; those device-safe values are stored in NVS. CI
builds both variants as compile proofs only; do not flash CI artifacts as
configured releases.

### 6. Run the complete preflight

```bash
./scripts/preflight.sh
```

This scans publishable text for secrets and personal infrastructure, validates
shell and Python sources, runs lint/tests when installed, checks Compose when
available, and checks Git whitespace. Binary files and image pixels/metadata still
require manual review. Use `PREFLIGHT_STRICT_TOOLS=1` to require every optional
tool.

## Common commands

```bash
make help
make scan
make lint
make test
make markdown
make workflow-lint
make preflight
make firmware-v1
make firmware-v2
make compose-check
```

## Deployment defaults

1. Keep the bridge on the same trusted LAN as the display, or on a private
   tailnet.
2. Bind the bridge to loopback and publish it through a TLS reverse proxy when it
   crosses a host boundary.
3. Require a unique, rotatable feed token for every device.
4. Return only fields required by the UI; avoid raw account responses.
5. Disable request-body and authorization-header logging.
6. Keep all order and trading functionality out of the bridge.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), the
[Contributor License Agreement](CONTRIBUTOR_LICENSE_AGREEMENT.md), and the
[Code of Conduct](CODE_OF_CONDUCT.md). Security vulnerabilities belong in a
private GitHub security report, not a public issue; see [SECURITY.md](SECURITY.md).

Before opening a pull request, run:

```bash
./scripts/preflight.sh
```

## Licensing and trademarks

Original root and bridge software is available under
[GNU AGPL-3.0-or-later](LICENSE). Original firmware software is available under
[GNU GPL-3.0-or-later](firmware/LICENSE). Third-party components and assets retain
their upstream terms.

No original hardware/CAD/source-design files are currently included. Future
original hardware design files are intended to use CERN-OHL-S-2.0 unless a
file-level notice says otherwise; third-party Waveshare designs and documentation
will not be relicensed.

Paid proprietary exceptions may be available for closed-source use, but
AGPL/GPL-compliant commercial use and resale remain royalty-free. See
[licensing scope](LICENSING.md), [commercial licensing](COMMERCIAL-LICENSING.md),
[NOTICE](NOTICE), and the [trademark policy](TRADEMARKS.md). These license choices
and the contributor agreement should be reviewed by qualified counsel before
material commercial reliance.
