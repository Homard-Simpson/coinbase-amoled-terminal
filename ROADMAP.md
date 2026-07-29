# Roadmap

The roadmap is directional, not a delivery promise. Security and reliable
read-only behavior take priority over feature count.

## Phase 0 — Private hardening

- [ ] Remove all environment-specific values and generated firmware artifacts.
- [ ] Validate V1 and V2 builds from clean ESP-IDF environments.
- [ ] Exercise credential rotation and device deprovisioning.
- [ ] Verify bridge responses are minimized and logs are payload-free.
- [ ] Complete threat-model and dependency-license reviews.
- [ ] Run the public-release checklist from a fresh clone.

## Phase 1 — Public preview

- [ ] Publish signed source tags and checksums for release artifacts.
- [ ] Document reproducible local bridge and firmware provisioning.
- [ ] Collect sanitized hardware compatibility reports.
- [ ] Stabilize the feed schema and publish compatibility guarantees.
- [ ] Add automated stale-data, token-expiry, and rollback tests.

## Phase 2 — Reliability

- [ ] Improve offline and stale-state UX.
- [ ] Add schema-version negotiation between bridge and firmware.
- [ ] Add deterministic mock-feed fixtures for UI development.
- [ ] Expand recovery documentation for interrupted OTA updates.
- [ ] Publish a software bill of materials with releases.

## Possible later work

- Additional display themes with OLED burn-in-aware motion.
- More explicit on-device privacy controls.
- Hardware-in-the-loop smoke tests for both board revisions.
- Optional local-only metrics that never contain account payloads.

## Permanent non-goals

- Trading, order management, transfers, withdrawals, or autonomous decisions.
- Hosted credential custody or a project-operated cloud relay.
- Advertising, analytics, tracking, or sale of operator data.
- Support for configurations that place Coinbase credentials on the ESP32.
