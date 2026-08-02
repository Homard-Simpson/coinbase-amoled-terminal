# Hardware Compatibility

## Supported board family

The firmware targets the **Waveshare ESP32-S3 Touch AMOLED 1.8** family with a
368 × 448 AMOLED panel. Two revisions are supported, but they use different
display and touch-controller paths.

Do not treat V1 and V2 as interchangeable firmware targets.

## Compatibility matrix

| Characteristic | V1 | V2 |
| --- | --- | --- |
| Build selector | `v1` | `v2` |
| Display controller | SH8601 | CO5300 |
| Touch controller path | FT5x06/FT3168 family | CST816S-compatible path; often identified as CST820 |
| Resolution | 368 × 448 | 368 × 448 |
| ESP target | ESP32-S3 | ESP32-S3 |
| Expected flash configuration | 16 MB | 16 MB |
| Expected external RAM | Octal PSRAM | Octal PSRAM |
| Display/IO sequencing | TCA9554 and V1-specific AXP2101 rail sequencing | TCA9554 reset; no V1 PMU rail writes |
| Shared runtime power control | AXP2101 PWRKEY IRQ registers `0x41`/`0x49` only | AXP2101 PWRKEY IRQ registers `0x41`/`0x49` only |
| Touch polling note | Interrupt-gated reads avoid idle NACK behavior | Event-oriented controller can be polled by the compatible driver path |
| Project status | Supported; hardware smoke test required per release | Supported; hardware smoke test required per release |

Component substitutions can occur within a vendor product family. Confirm the
actual board documentation and markings rather than relying only on a listing
title.

## Critical V1/V2 safety rule

V1-specific PMU initialization writes must not run on V2. They can blank or
destabilize the CO5300 display path. The shared source therefore uses an explicit
compile-time board selector rather than probing both controller families at boot.
The only cross-variant runtime PMU writes are the proven PWRKEY short-press IRQ
enable/consume operations; the write allowlist cannot address rail registers
`0x80` through `0x99`.

If the display goes blank immediately after initialization:

1. disconnect power;
2. confirm the exact board revision;
3. remove generated build state;
4. rebuild the matching variant; and
5. flash only the newly labeled artifact.

Do not keep experimenting with PMU register writes on an unidentified board.

## Identifying the revision

Use, in order:

1. the revision printed on the board or packaging;
2. the controller names in the vendor documentation supplied with that unit;
3. a known-good factory example for that exact revision; and
4. non-destructive boot diagnostics from a previously validated image.

Do not identify a board in public documentation by a MAC address, serial number,
or another globally unique device value. Do not make runtime safety decisions from
those identifiers.

## Build commands

With a production local configuration:

```bash
./scripts/build-firmware.sh v1
./scripts/build-firmware.sh v2
```

For compilation-only checks with synthetic configuration:

```bash
./scripts/build-firmware.sh v1 --ci-placeholder
./scripts/build-firmware.sh v2 --ci-placeholder
```

Placeholder artifacts cannot reach a real feed and must not be distributed as
ready-to-flash releases.

## Required release smoke tests

Run these on both revisions before marking a release supported:

- boot log identifies the intended variant;
- panel initializes without reset loops, corruption, or unexpected blanking;
- brightness and screen on/off behavior work;
- POWER short press enters/wakes standby with panel, Wi-Fi, feed, and touch
  paused/resumed;
- BOOT short activates the blue bottom action, 0.8–<10 seconds toggles privacy,
  and uninterrupted 10 seconds arms manual OTA without a privacy toggle;
- touch coordinates reach every intended control region;
- Wi-Fi provisioning and reconnect work after power cycle;
- HTTPS feed authentication succeeds with a test feed;
- malformed and stale feeds show safe error states;
- background refresh does not starve touch input;
- OTA rollback or wired recovery is available; and
- V2 signed automatic OTA does not race POWER standby; V1 has no automatic
  updater; and
- no credential, token, or unique hardware identifier appears in logs/artifacts.

Record only generic pass/fail results in public release notes. Keep serial numbers,
network details, tokens, and portfolio screenshots out of evidence.

## Unsupported or unverified hardware

- Other Waveshare AMOLED sizes and resolutions.
- Boards that resemble this model but use undocumented controller substitutions.
- Generic ESP32-S3 boards connected to an external AMOLED without a maintained
  board definition.
- Any revision built with a guessed selector.

Contributions for new hardware should add a separate explicit board definition,
vendor-source citations, clean build coverage, and a documented hardware smoke
test. Do not weaken V1/V2 safeguards to make an unknown board appear to work.

## Flashing precautions

- Back up only non-sensitive factory firmware where licensing permits.
- Never publish a full flash dump; it may contain Wi-Fi or token material in NVS.
- Prefer application images and documented partition artifacts over raw flash
  copies.
- Verify artifact checksums before flashing.
- Keep wired recovery available during OTA testing.
- Erase NVS before selling, gifting, or returning a board.
