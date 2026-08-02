# Troubleshooting

Start with the smallest safe check. Do not paste credentials, feed tokens, account
payloads, unique device identifiers, private hostnames, network addresses, or
uncropped display photos into an issue.

## Two-step installer or captive portal fails

### Git or Python prerequisite is missing

Install Git and Python 3.11 or newer (including Python's `venv` support) through
your operating system's supported package manager, then rerun the approved Step 1
command. The installer intentionally does not request administrator access or
silently run privileged commands. Docker is not required.

### Firmware manifest or download fails

The installer treats HTTP, manifest, size, and SHA-256 failures as fatal and never
flashes a partial download. Confirm normal HTTPS access to the exact versioned
GitHub release and retry. Do not bypass a mismatch or substitute an artifact from
another board. The public default intentionally fails until approved production
assets exist.

### The installer cannot find the display

Use a USB data cable. Disconnect other USB serial boards, leave one display
connected, and run the same install command again. The installer deliberately
stops on zero or multiple candidates.

USB names and ESP chip details cannot safely distinguish V1 from V2. An existing
official firmware is auto-identified only when its exact application hash appears
in the accepted release manifest. Otherwise inspect the board with the linked
Waveshare guide and answer the single V1/V2 question. Never try both images.

### The setup Wi-Fi or captive page does not open

Check the display for its protected setup Wi-Fi name and password. Join it, then
open `http://192.168.4.1` if the captive page does not appear. The page has no
external assets, so it renders while the computer is off its normal Wi-Fi.

If it says the setup session expired, rerun the approved installer command over
USB. That creates fresh one-time setup and CSRF values without erasing unrelated
NVS.

### The setup page rejects the key file

- Choose the original JSON downloaded from Coinbase, or paste that JSON into the
  captive portal or localhost fallback page.
- Confirm it has text fields named `name` and `privateKey`.
- Create a Coinbase CDP **ECDSA / ES256 / P-256** key. Legacy API secrets,
  Ed25519, RSA, encrypted PEMs, and other curves are unsupported.
- Never paste the key into an issue, ESP endpoint, command, environment variable,
  or log.

### Permission validation refuses the key

This is the safety gate working. In Coinbase, remove trade and transfer access and
keep only view access, or create a new dedicated view-only key. Press Finish again
with the corrected JSON. Nothing is stored or sent to the display when this check
fails.

### The captive page says localhost is blocked

Some operating-system captive mini-browsers block access to localhost. Press
**Open setup on this computer**. Complete the same form in the full browser, then
return to the display portal and press its final save button. Do not move setup to
a phone: the authenticated endpoint is bound to the computer that ran Step 1.

If a full Chrome browser also fails, rerun Step 1 to replace an expired session.
Do not disable browser security or expose the localhost endpoint on the LAN.

### The user service cannot start

Setup stops before provisioning the display and rolls back new local state. Inspect
the user service without elevated access:

```bash
# Linux
systemctl --user status coinbase-amoled-bridge.service

# macOS
launchctl print "gui/$(id -u)/com.homardsimpson.coinbase-amoled-bridge"
```

Common causes are a headless Linux session without a user service bus, a disabled
user manager, or a stale service file. Fix that user-session issue, then rerun
Step 1. Never copy a Coinbase key into a unit file.

### The display cannot reach the feed after setup

- Keep the computer and display on the same trusted LAN.
- Confirm the computer firewall permits local port `8788`; never add router port
  forwarding.
- Rerun the same approved version. Existing private state is preserved unless a
  full replacement transaction succeeds.
- For guest/public or cross-network access, use private HTTPS/tailnet deployment.

### I only want to test the installer

Use sample mode. It creates no Coinbase credential and makes no Coinbase request:

```bash
./install.sh --sample
```

## Preflight fails

### Missing Ruff, pytest, ShellCheck, markdownlint-cli2, actionlint, or Docker

Install Python development tools:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

Install ShellCheck, markdownlint-cli2, actionlint, and Docker Compose using your
operating system's supported package path. By default, preflight warns when
optional tools are unavailable. To make missing tools fatal, run:

```bash
PREFLIGHT_STRICT_TOOLS=1 ./scripts/preflight.sh
```

### Public-safety scanner reports a finding

Assume the finding is real first. Replace the value with a reserved example,
rotate it if it was usable, and remove it from Git history if committed. Do not
silence a pattern simply to make CI green. If the content is a required synthetic
test, construct the value from fragments at test runtime so no secret-like literal
is published.

## Firmware will not build

### `idf.py` is missing

Install ESP-IDF 5.5.x and source its export script in the current shell. Confirm:

```bash
idf.py --version
```

Do not silently build with an unreviewed major ESP-IDF version; component APIs and
generated output can differ.

### Feed token or URL is missing

Production builds intentionally require explicit local provisioning. Supply the
files/settings described by `firmware/README.md`, or use `--ci-placeholder` only
for a compilation check. Never weaken the build to fall back to a real checked-in
token.

### Managed component resolution fails

- confirm internet access to the ESP component registry;
- review the component manifest and dependency lock diff;
- remove only generated build/component caches, not source manifests; and
- rebuild from clean state.

Do not commit `managed_components/` merely to bypass a transient registry issue.

## Display is blank or corrupted

1. Disconnect power.
2. Confirm V1 versus V2 from the board/vendor documentation.
3. Delete generated build state.
4. Build the exact matching variant.
5. Flash over a wired connection and capture only sanitized boot status.

A V1 hardware path can issue PMU initialization that is unsafe on V2. Do not probe
an unknown board by trying both images repeatedly. If the correct V2 build remains
blank, inspect panel power, QSPI setup, reset sequencing, and known-good vendor
examples before changing PMU registers.

## Touch is missing or intermittent

- Verify the correct controller path: FT5x06 family on V1, CST816S/CST820 family on
  V2.
- Confirm coordinate orientation and bounds against all four display corners.
- On V1, preserve interrupt-gated reads; idle controller reads may NACK.
- Ensure network fetches do not block the touch-polling task.
- Check for I2C contention without logging unique hardware identifiers.

## Bridge will not start

### Secret mount is empty or permission denied

Confirm the local `secrets/` directory exists, expected files are present, and the
files are owner-readable. Do not make them world-readable to fix a container
permission problem. Prefer matching the container runtime user or a narrow group
permission.

### Health check fails

Run the bridge in the foreground and inspect sanitized status logs. Confirm the
configured internal port matches Compose and that `/healthz` does not depend on a
successful Coinbase request. A health route should distinguish process health from
upstream readiness without returning sensitive details.

### Coinbase authentication fails

- Verify system time.
- Confirm the credential file has not been altered by newline or escaping changes.
- Verify the key is active and view-only in Coinbase.
- Check the configured public Coinbase API base URL.
- Rotate the credential if its storage or logs may have exposed it.

Never paste the credential into a command line or issue to test it.

## Device gets an authentication error

- Confirm the device uses the feed token, not the Coinbase credential.
- Check for extra whitespace when provisioning the token file.
- Verify the token belongs to that device and has not expired or been rotated.
- Ensure the reverse proxy forwards the authorization header.
- Keep authentication error bodies generic; inspect server-side reason codes only
  in sanitized local logs.

Repeated failures should trigger backoff, not rapid polling.

## Device is always stale or offline

- Compare bridge time, proxy time, and device time.
- Confirm TLS validation succeeds; do not downgrade to HTTP.
- Verify the feed's generation timestamp advances.
- Check that cache duration and advertised refresh interval are bounded.
- Confirm proxy/CDN caching is disabled for authenticated portfolio responses.
- Simulate bridge recovery and verify the last-known-good state is replaced
  atomically.

## TLS errors

- Use a hostname covered by the certificate.
- Install the correct trust chain in the firmware build.
- Confirm device time before certificate validation.
- Avoid private/self-signed CAs unless you have a deliberate provisioning and
  rotation process.
- Never set an "insecure skip verify" option as a permanent fix.

## Compose validation fails

Run:

```bash
docker compose --env-file .env.example config
```

The example expects a `bridge/Dockerfile`. If bridge implementation files have not
been added yet, Compose can parse but cannot build. Confirm variable expansion and
that the published address begins with loopback, not a wildcard.

## CI firmware artifact connects nowhere

That is intentional. CI builds use a reserved non-resolving hostname and a
placeholder feed token. They prove both variants compile but are not provisioned
release images. Build locally for an actual device.

## Preparing a safe bug report

Include:

- component and source revision;
- board revision without serial/MAC information;
- expected and actual behavior;
- shortest reproduction;
- sanitized error category and status code; and
- tests already attempted.

Before attaching a file:

```bash
python3 scripts/scan_public_safety.py path/to/sanitized-material
```

That scanner checks UTF-8 text only. Manually inspect image pixels/metadata,
binaries, archives, and history.

For vulnerabilities, stop and use the private process in `SECURITY.md`.
