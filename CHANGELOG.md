# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/) once
public releases begin.

## [Unreleased]

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
- A secure one-prompt `quickstart` command for Coinbase CDP JSON or dragged-file
  input, display credential creation, service startup, and doctor checks.

### Security

- Documented a local-bridge credential boundary and no-trading invariant.
- Added repository preflight checks for common secrets and personal
  infrastructure.
- Quickstart rejects Legacy, Ed25519, non-P-256, malformed, and oversized keys;
  enforces the live view-only permission gate before storage; and rolls back new
  state after failed final validation.
- Installer scripts and service templates are included in shell, lint, test, and
  public-safety CI gates.

No stable version has been released.
