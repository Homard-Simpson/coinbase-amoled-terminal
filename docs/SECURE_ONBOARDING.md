# Secure Two-Step Onboarding

This document defines the consumer onboarding boundary. The goal is a genuinely
simple flow without ever moving a Coinbase credential onto the display.

## Exact user flow

### Step 1: USB install and flash

The user connects one Waveshare ESP32-S3 Touch AMOLED 1.8 and runs one installer
command. The installer, without `sudo`:

1. creates or refreshes a private per-user application directory and isolated
   Python environment;
2. installs the local read-only bridge and its launchd or systemd user service;
3. creates a short-lived localhost setup session with independent random session,
   authorization, and CSRF values;
4. downloads one versioned firmware manifest and verifies every declared artifact
   with SHA-256 before use;
5. identifies V1/V2 only from an exact trusted existing-firmware hash, or asks the
   user once when a blank/DIY board cannot be identified safely;
6. flashes only manifest-approved firmware regions; and
7. writes the short-lived setup metadata to a dedicated onboarding partition over
   the physical USB connection.

Unrelated NVS is not erased. The setup partition contains no Coinbase key, Wi-Fi
password, feed token, account data, MAC address, or personal host information.

### Step 2: captive portal

The user joins the protected setup Wi-Fi shown on the display. The captive portal
asks for home Wi-Fi and the Coinbase CDP ECDSA API-key JSON. When the user presses
**Finish**:

1. portal JavaScript sends the API-key JSON directly to the authenticated
   localhost endpoint on the same computer;
2. the bridge parses only the official `name` and `privateKey` fields, verifies an
   unencrypted P-256 ECDSA key, calls Coinbase `/key_permissions`, and rejects any
   trade or transfer capability;
3. the bridge stores the key name and PEM in one atomic owner-only credential
   bundle, creates a UUIDv4 device identity plus revocable `cbat_` feed token, and
   starts the user service;
4. the localhost endpoint returns only the bridge feed URL, device ID, and raw
   one-time device token to that exact browser origin;
5. JavaScript builds a separate allowlisted `/save` form containing home Wi-Fi and
   those three device-safe values; and
6. after the ESP accepts that form, the browser acknowledges completion to
   localhost. The ESP clears the USB setup partition and restarts.

The Coinbase JSON, key name, and PEM are never posted to `/save`, returned by the
bridge, logged, or made readable by firmware.

## Same-computer fallback

Some operating-system captive mini-browsers block requests from the setup AP to
localhost even when a full browser permits them. The portal therefore includes a
button to open its short-lived localhost setup page on the same computer. That
page uses the same session and security checks. After key validation it asks the
user to return to the already-open display portal and press the final save button.

This preserves the perceived two-step process. It does **not** make a phone-only
claim: the localhost endpoint exists on the computer that ran the installer.

## Credential boundary

The Coinbase JSON is accepted only by the localhost bridge process. It must never
appear in any ESP request, firmware-generated HTML, URL, query string, browser
history, command argument, environment variable, service unit, log entry, error
body, analytics request, or persisted browser storage.

The ESP receives exactly these persistent provisioning values:

- home Wi-Fi name and password;
- complete local bridge feed URL;
- a UUIDv4 device ID; and
- one random, revocable `cbat_` device token.

The display token is not a Coinbase key. The bridge stores only its SHA-256 digest
in `config.json`; the raw token is kept in a mode-0600 device file and ESP NVS.

The temporary USB onboarding partition contains only:

- schema version and expiry;
- opaque session, setup-authorization, and CSRF values;
- the loopback onboarding and fallback URLs; and
- the non-secret bridge feed URL.

Its payload is length-bounded and SHA-256 protected against accidental corruption.
Firmware rejects malformed, duplicate, unknown, expired-shape, non-loopback, or
wrong-path metadata.

## Local setup-session controls

- Bind only to `127.0.0.1` on an operating-system-selected port.
- Generate independent cryptographically random session, setup-authorization,
  and CSRF values; compare them in constant time.
- Put authorization and CSRF values only in request headers, never in URLs,
  referrers, logs, cookies, or browser storage.
- Expire the session after a short bounded lifetime. Permit one credential
  submission at a time, consume it after the first success, and accept only one
  matching finish acknowledgement.
- Require the exact loopback `Host`, exact portal or same-session localhost
  `Origin`, fixed paths, restricted methods, exact content type, one bounded
  `Content-Length`, and an exact request-header allowlist.
- Answer CORS and Chrome Private Network Access preflights only for those exact
  origins, methods, paths, and headers. Never enable credentialed CORS.
- Return `Cache-Control: no-store`, restrictive CSP/referrer/frame/content-type
  headers, and generic non-echoing errors.
- Send no external assets and use no analytics, redirects, cookies, browser
  persistence, or autocomplete.
- Clear browser text/file inputs immediately after submission. The process and
  session disappear after completion, expiry, or installer failure.

The ESP `/save` path separately accepts an exact URL-encoded field allowlist,
rejects unknown or duplicate fields, bounds the body and every decoded value, and
rejects any API-key field name or private-key marker before touching NVS.

## Validation, persistence, and rollback

The localhost bridge uses the same closed read-only Coinbase client used at
runtime. Before credentials are committed it:

1. parses an object with exactly `name` and `privateKey` string fields;
2. rejects NULs, encrypted PEM, Legacy keys, RSA, Ed25519, and non-P-256 curves;
3. verifies `/key_permissions` returns `can_view=true`, `can_trade=false`, and
   `can_transfer=false`; and
4. performs a bounded read-only product request.

The credential bundle uses a versioned binary envelope with the key name and PEM,
is written through a fresh mode-0600 temporary file, `fsync`, atomic replace, and
parent-directory sync. Legacy two-file credentials remain readable for existing
installations, but new onboarding writes only the bundle.

Coordinator changes are transactional. Before mutation it snapshots credential,
configuration, token-file, and service state. Permission failure writes nothing.
Any later device, config, or service failure restores the snapshot and removes new
files. Existing state is preserved rather than partially overwritten.

## Board revision and flashing safety

V1 and V2 are electrically different. The V1 image includes AXP2101 power setup;
the V2 path must not issue those writes. The installer therefore does not infer a
revision from USB VID/PID, serial-port names, ESP chip identity, flash size, MAC
address, panel probing, or a failed attempt to boot one image.

For an existing official installation, automatic selection is allowed only when
the exact bytes read from the current application region hash to a firmware digest
listed for one board in the accepted release manifest. Any missing, ambiguous, or
mismatched hash falls back to explicit choice.

For a blank or DIY board, the installer presents one friendly V1/V2 question and
links to Waveshare's Version Options guide. No option is preselected. Invalid or
non-interactive ambiguity fails before erase or write.

The manifest must declare:

- one board (`v1` or `v2`) per board record;
- ESP-IDF `5.5.2`;
- the exact chip and flash mode/frequency/size;
- every artifact URL, offset, byte size, and SHA-256 digest;
- the dedicated onboarding offset and size; and
- production readiness, controls verification, and hardware-attestation flags.

Production mode accepts only HTTPS assets below the official versioned GitHub
release prefix and requires all three readiness controls. A separate explicit
review mode accepts other manifests only with
`--allow-unverified-test-artifacts`. It is intentionally unsuitable for public
installation.

The flasher verifies downloads before connecting, rejects overlaps, oversized or
undeclared regions, partition-table inconsistencies, wrong onboarding geometry,
and board-mismatched app descriptions. It writes only listed regions plus the
fresh setup partition. It never runs `erase_flash` and never writes the unrelated
NVS region.

## Recovery, updates, and factory reset

- **Retry setup:** rerun the same approved installer command. A fresh setup session
  replaces expired onboarding metadata; existing private bridge state is kept
  unless a transaction succeeds.
- **Firmware update:** use a newer approved version. The same manifest, board, and
  checksum gates apply. Reflashing does not erase NVS.
- **Lost display:** revoke or rotate that device's feed token on the bridge.
- **Factory reset from the portal:** type the explicit reset confirmation. Firmware
  erases its NVS and dedicated onboarding partition, then restarts.
- **Factory reset over USB:** the helper erases exactly those two data partitions,
  not the complete flash.
- **Uninstall:** removes the user service and application. Private data is retained
  unless `--purge` is explicitly supplied.

The physical BOOT contract is unchanged: a short press toggles the view, a
0.75–10 second hold toggles the display, and a 10 second hold wakes the display and
arms local OTA for five minutes.

## Verification boundary and current release status

Automated tests use generated P-256 keys, fake Coinbase transports, fake release
artifacts, fake esptool runners, temporary files, and a local fake ESP portal.
They cover token expiry/single use, CORS/PNA, request bounds, API-key exclusion from
ESP payloads, permission refusal, rollback, service installation, manifest and
checksum enforcement, serial ambiguity, and V1/V2 fail-closed behavior. Google
Chrome automation exercises the real cross-origin browser flow on macOS without a
Coinbase account.

Compile proof is not hardware proof. The public installer remains disabled until
both board images have been built with ESP-IDF 5.5.2, tested on real V1 and V2
hardware, and published in an approved versioned release with completed control
and attestation fields.
