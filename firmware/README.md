# Unofficial Coinbase AMOLED terminal firmware

Public-ready ESP-IDF firmware for the **Waveshare ESP32-S3 Touch AMOLED 1.8**. It is an unofficial, read-only market and positions display; it is not made, endorsed, or supported by Coinbase.

The ESP never connects to Coinbase or stores exchange API keys. It performs one authenticated `GET` against a consumer-operated local/tailnet bridge. The bridge owns all exchange integration and emits the bounded read-only JSON contract in [`docs/bridge-feed.schema.json`](docs/bridge-feed.schema.json).

## Supported boards

| Build | Display | Touch | Power / reset |
|---|---|---|---|
| `v1` | SH8601 | FT5x06 / FT3168 | TCA9554 + AXP2101 |
| `v2` | CO5300 | CST820 (CST816-compatible protocol) | TCA9554 reset; no AXP register writes |

Choose the revision before flashing. The images are not interchangeable. OTA checks the project name and `-v1`/`-v2` version suffix to prevent accidental cross-flashing.

## User experience

- Live BTC, SOL, XLM, HYPE, and ETH prices.
- Positions-only summary: open-position value, unrealized P/L, and today's realized P/L. The firmware does not request or display cash or unrelated account balances.
- Open positions are taller, color-accented, and show an emphasized live price.
- Tap an asset for an expanded OHLCV chart. Candle body width scales with volume; no separate volume histogram is used.
- Entry and live-price guide lines, subtle light-blue left-side chart levels, list sparklines, and closed-today rows.
- A single top row with battery/charge state at left and bridge-local current time at right in 12-hour AM/PM format.
- Dedicated 10 ms touch task so network requests and frame transfers do not drop taps.
- **Short BOOT press:** toggle Prices / Positions (or leave a chart).
- **BOOT hold 0.8-10 seconds:** display off/on (privacy/standby).
- **BOOT hold continuously for 10 seconds:** wake the display and arm local OTA for five minutes.

## Security model

- No URL, Wi-Fi network, token, hardware MAC, or personal device ID is compiled in.
- A UUIDv4 device ID, setup-AP password, bridge URL, and per-device bearer token are generated/stored in NVS at runtime.
- The setup AP uses WPA2-PMF and a random 12-character password shown on the AMOLED.
- Setup, reset, and OTA handlers accept only clients on the device AP subnet. Setup/reset forms also use a random per-portal CSRF value.
- The bearer token is never rendered back into the portal, included in logs, or followed across redirects. HTTP redirects are disabled.
- HTTPS uses the ESP-IDF certificate bundle. Plain HTTP is accepted only for RFC1918, link-local, loopback, CGNAT/tailnet, `.local`, `.lan`, `.home.arpa`, `.internal`, or single-label LAN hosts.
- Feed bodies are capped at 192 KiB. Candle storage is capped at 36 per symbol; closed-today storage is capped at 20 rows.
- The entire response is rejected unless `read_only` is the JSON boolean `true`. Missing, `false`, string, or numeric values fail closed and do not replace the last trusted state.
- Manual OTA requires physical presence plus a six-digit one-time code. V2 also checks the official latest-release endpoint in the background and accepts only a strictly newer stable V2 application whose SHA-256 is bound to a production-ready Ed25519-signed manifest. Both paths use dual slots and ESP-IDF rollback. This protects network updates, but it is not a substitute for hardware Secure Boot against a physical attacker.

The NVS token is a revocable **bridge credential**, not a Coinbase credential. Never paste Coinbase API keys, API secrets, private keys, or session cookies into the portal.

## Build prerequisites

- ESP-IDF **5.5.2**
- Python environment installed by ESP-IDF
- USB data cable for initial flashing

Managed display, touch, expander, and cJSON dependencies are declared in [`main/idf_component.yml`](main/idf_component.yml). Do not vendor `managed_components/`, `dependencies.lock`, `sdkconfig`, or `build/`; all are ignored.

### Build V1

```sh
./scripts/build-v1.sh
```

### Build V2

```sh
./scripts/build-v2.sh
```

### Build both

```sh
./scripts/build-all.sh
```

The scripts refuse ESP-IDF versions other than 5.5.2 and use isolated `build/v1` and `build/v2` directories. Set `IDF_EXPORT=/path/to/esp-idf/export.sh` if ESP-IDF is installed elsewhere.

## Initial USB flash

Build the exact board revision, then:

```sh
./scripts/flash-v1.sh /dev/cu.usbmodemXXXX
# or
./scripts/flash-v2.sh /dev/cu.usbmodemXXXX
```

The helper writes bootloader, partition table, initial OTA metadata, and the application. It deliberately does **not** erase NVS. Do not distribute built binaries after provisioning: flash/NVS dumps can contain Wi-Fi and bridge credentials.

## First-boot onboarding

The consumer installer writes a short-lived setup session to the dedicated
`onboarding` data partition over USB. That partition contains only loopback setup
URLs, opaque session/authorization/CSRF values, the non-secret bridge feed URL,
and an expiry. It never contains Coinbase JSON, a Coinbase key name or PEM, Wi-Fi,
a device token, a MAC address, or personal infrastructure.

1. Flash the exact V1 or V2 image and USB onboarding partition, then reboot.
2. The AMOLED shows `FIRST-BOOT SETUP`, a unique `AMOLED-Terminal-xxxx` SSID, and
   its random WPA2 password.
3. Join that Wi-Fi and open `http://192.168.4.1` if the captive page does not
   appear automatically.
4. Enter home Wi-Fi and choose or paste the Coinbase CDP ECDSA JSON. Portal
   JavaScript sends the JSON directly to the authenticated localhost bridge; it
   never posts it to the ESP `/save` handler.
5. The bridge returns only a local feed URL, UUIDv4 device ID, and revocable
   `cbat_` feed token. The browser posts those safe values plus Wi-Fi to `/save`.
6. Firmware commits only those allowlisted fields to NVS, erases the one-time
   onboarding partition, restarts, joins Wi-Fi, and begins polling.

The `/save` parser rejects unknown and duplicate fields, malformed percent
encoding, oversized bodies and values, credential-like field names, and private
key markers before changing NVS. If a captive mini-browser cannot contact
localhost, it offers a same-computer fallback URL. The fallback does not make
phone-only onboarding possible.

If saved Wi-Fi cannot connect for 45 seconds, the protected setup AP returns while
station retries continue. A source-built image without valid USB onboarding
metadata retains the advanced manual portal: leave SSID or token blank only when
intentionally keeping an existing value, and never enter Coinbase credentials in
manual bridge fields.

The logical persistent fields are documented in
[`config/runtime-config.schema.json`](config/runtime-config.schema.json). The
firmware accepts them through the portal and does not read a JSON config file.

## Local bridge contract

The configured URL must return HTTP 200 JSON matching [`docs/bridge-feed.schema.json`](docs/bridge-feed.schema.json). Requests contain:

```text
Authorization: Bearer <per-device bridge token>
X-Device-ID: <generated UUIDv4>
Accept: application/json
```

The bridge should:

- authenticate both token and device ID;
- expose a GET-only, read-only projection;
- return `read_only: true` as a JSON boolean;
- return only open positions in `positions`;
- return `portfolio.positions_value`, not a total account/cash balance;
- keep Coinbase/API private keys server-side;
- avoid redirects; and
- revoke a device token independently when a device is lost or reset.

Compact candles use `[timestamp, open, high, low, close, volume]`. Object candles with long keys and `t/o/h/l/c/v` aliases are also accepted. Epoch seconds and milliseconds are normalized; malformed candles are skipped, timestamps are sorted/de-duplicated, and only the newest 36 remain.

## OTA

### Automatic V2 updates

After a randomized startup delay, V2 checks the official GitHub latest-release endpoint every six hours. It installs only when the release manifest and detached Ed25519 signature authenticate under the pinned release key, all production/control/V2-hardware readiness flags are true, the release is a strictly newer stable semantic version, and the downloaded V2 application matches the signed size, SHA-256, project, board suffix, and app version. Redirects are permitted only in this signed-download path; an altered payload cannot pass the pinned signature and digest checks. Failed checks or transfers leave the current slot selected, and ESP-IDF rollback remains enabled.

V1 does not compile or run the automatic updater. Prereleases and same/older versions are never installed automatically.

### Manual recovery/update

1. Build the image for the device revision.
2. Hold BOOT continuously for 10 seconds. The display wakes and shows a six-digit code for five minutes.
3. Join the displayed setup AP, open `http://192.168.4.1`, choose `coinbase_amoled_terminal.bin`, and enter the code.
4. The firmware verifies project identity, board suffix, size, and complete ESP-IDF image before selecting the inactive slot and restarting.

A failed or interrupted upload leaves the running slot selected. Manual OTA remains available independently of automatic update checks.

## Factory reset

### From the protected portal

Hold BOOT for 10 seconds, join the setup AP, open the portal, type `RESET` in
the Factory reset section, and submit. This clears Wi-Fi, bridge URL/token,
device UUID, setup password, and the dedicated one-time onboarding partition,
then restarts. Firmware and OTA slots remain intact.

### From USB

```sh
./scripts/factory-reset.sh /dev/cu.usbmodemXXXX --confirm=RESET
```

This erases only NVS at `0x9000` (size `0x6000`) and the onboarding partition at
`0xE20000` (size `0x2000`). Reflashing without those explicit erases is not a
factory reset.

## Host tests

```sh
./tests/run.sh
```

The test gate compiles the same URL/token/Wi-Fi validation code used by firmware, checks safe/unsafe feed fixtures, verifies the fail-closed parser hooks, validates the documentation schemas as JSON, and scans the source tree for private literals or publishable build artifacts.

## Repository hygiene

This directory intentionally contains source, scripts, schemas, tests, and documentation only. It contains no build output, managed components, reference dumps, firmware binaries, flash dumps, logs, credentials, private URLs, device MACs, personal identifiers, or git history.

## License and trademarks

Original firmware source is licensed under GNU GPL-3.0-or-later; see
[`LICENSE`](LICENSE). Third-party managed components retain their upstream
licenses, and the bitmap font notice is in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). GPL-compliant commercial
hardware resale remains permitted without royalty; distributors must satisfy the
applicable source, notice, and installation-information requirements.

Coinbase is a trademark of Coinbase, Inc. All product names and trademarks belong to their respective owners.
