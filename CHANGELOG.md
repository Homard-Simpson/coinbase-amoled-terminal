# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/) once
public releases begin.

## [Unreleased]

### Changed

- Reduced the token-chart price-axis gutter and widened the plot area on both V1
  and V2 without moving its right edge.

## [2.0.0] - 2026-08-02

### Added

- Public-ready project documentation and governance policies.
- V1 and V2 ESP-IDF build paths for Waveshare ESP32-S3 Touch AMOLED 1.8 boards.
- Local read-only bridge boundary with device-feed token separation.
- CI for Python quality, dual-variant firmware builds, CodeQL, dependency updates,
  and secret/privacy scanning.
- A README gallery of lossless production-renderer framebuffer captures for live
  prices, privacy-mode positions, and BTC candles with BB20 and key levels.
- Reproducible host capture tooling, public market-data input, renderer/frame
  checksums, and explicit branch-protection plan constraints.
- Public open-source release licensing: AGPL-3.0-or-later for root/bridge software
  and GPL-3.0-or-later for firmware, with future original hardware designs
  intended for CERN-OHL-S-2.0.
- Commercial-licensing, contributor-agreement, and trademark policies supporting
  optional proprietary exceptions while preserving royalty-free copyleft resale.
- A two-step macOS/Linux installer with isolated Python environment, per-user
  launchd/systemd service, idempotent updates, safe uninstall, and offline sample
  mode.
- A secure captive-portal flow backed by a short-lived localhost endpoint. The
  browser sends Coinbase JSON directly to the computer, while a separate ESP
  request contains only Wi-Fi and revocable device credentials.
- Real USB flashing and one-time onboarding-partition provisioning with isolated
  esptool, versioned SHA-256 manifests, exact-hash board detection, and an
  explicit fail-closed V1/V2 choice for blank or DIY boards.
- A production release gate: public installation remains disabled until signed
  artifacts, controls, and both hardware checklists are verified.
- V2-only forward automatic OTA using the pinned Ed25519 release-manifest key,
  signed SHA-256/board/version checks, dual slots, and rollback.
- A consolidated battery/time header and subtle left-side price levels on token
  charts for both board variants, with bridge-local time rendered in fixed-width
  12-hour AM/PM format.
- The production physical-control contract on both variants: POWER-only
  standby/wake; BOOT short blue action; BOOT 0.8–<10 second privacy toggle; and
  uninterrupted 10-second manual OTA arming.
- Standby coordination that pauses feed/touch/Wi-Fi and prevents POWER from
  interrupting an active signed V2 automatic update.

### Security

- Documented a local-bridge credential boundary and no-trading invariant.
- Added repository preflight checks for common secrets and personal
  infrastructure.
- Local onboarding rejects Legacy, Ed25519, non-P-256, malformed, and oversized
  keys; enforces the live view-only permission gate before storage; uses expiring
  single-use setup/CSRF tokens with strict Origin/CORS/PNA; and rolls back failed
  provisioning.
- Installer scripts and service templates are included in shell, lint, test, and
  public-safety CI gates.
