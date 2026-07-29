# Release Checklist

Use this checklist for every tagged release. A release is not complete until both
board variants, the bridge, documentation, and publication artifacts pass review.

## 1. Scope and version

- [ ] Define the release scope and defer unrelated changes.
- [ ] Select a Semantic Versioning-compatible version.
- [ ] Move user-visible entries from `Unreleased` in `CHANGELOG.md`.
- [ ] Confirm feed-schema and firmware compatibility notes are explicit.
- [ ] Confirm no stable-support claim exceeds tested behavior.

## 2. Source hygiene

- [ ] Work from a clean clone of the intended commit.
- [ ] Run `git diff --check`.
- [ ] Run `./scripts/preflight.sh` with strict tool checks.
- [ ] Run a full-history Gitleaks scan, not only a working-tree scan.
- [ ] Confirm generated firmware, NVS dumps, logs, screenshots, and caches are
  absent.
- [ ] Review every new binary; avoid source-release binaries unless required.
- [ ] Verify `.env.example` and Compose contain placeholders only.
- [ ] Confirm no personal paths, private hosts, device identifiers, phone numbers,
  account values, or production URLs are present.

## 3. Security and privacy

- [ ] Review `SECURITY.md`, `PRIVACY.md`, and `docs/THREAT_MODEL.md` against the
  actual implementation.
- [ ] Inventory bridge routes and verify there are no trade/order/transfer routes
  or generic upstream proxy behavior.
- [ ] Verify Coinbase credentials are loaded only on the bridge.
- [ ] Verify firmware receives only the scoped feed token.
- [ ] Confirm authorization headers and account payloads are absent from logs.
- [ ] Review CodeQL, dependency, secret-scanning, and `pip-audit` results.
- [ ] Triage or explicitly document every remaining security alert.
- [ ] Rotate any credential used during testing if its handling is uncertain.

## 4. Dependency and license review

- [ ] Review Python, ESP-IDF component, container, and GitHub Action changes.
- [ ] Confirm lockfiles/manifests are updated intentionally.
- [ ] Check dependency licenses are compatible with Apache-2.0 distribution.
- [ ] Preserve all required third-party notices.
- [ ] Generate an SBOM for release components when tooling is available.

## 5. Bridge verification

- [ ] Build the container without mounting secrets during the image build.
- [ ] Inspect image history for copied files and sensitive build arguments.
- [ ] Start with synthetic/mock data and verify loopback-only publication.
- [ ] Verify a non-root runtime user, read-only filesystem, dropped capabilities,
  and no-new-privileges.
- [ ] Test valid token, invalid token, missing token, expired token, and rate limit.
- [ ] Test malformed/oversized upstream responses and timeouts.
- [ ] Verify `/healthz` reveals no account/configuration detail.
- [ ] Audit feed fields against the minimal-data contract.

## 6. Firmware verification

- [ ] Build V1 from clean state.
- [ ] Build V2 from clean state.
- [ ] Ensure artifact names contain the board variant and version.
- [ ] Verify production provisioning was injected locally and generated headers
  were removed after each build.
- [ ] Scan strings and symbols for credential material and private infrastructure.
- [ ] Verify no NVS/full-flash dump is included.
- [ ] Record SHA-256 checksums.

## 7. Hardware smoke test — V1

- [ ] Correct V1 variant appears in sanitized boot output.
- [ ] SH8601 panel initializes and remains stable.
- [ ] FT5x06-family touch works across the screen.
- [ ] Wi-Fi, HTTPS feed, stale/offline state, and reconnect pass.
- [ ] Wired recovery and OTA rollback path are available.

## 8. Hardware smoke test — V2

- [ ] Correct V2 variant appears in sanitized boot output.
- [ ] CO5300 panel initializes without V1-specific PMU writes.
- [ ] CST816S/CST820-family touch works across the screen.
- [ ] Wi-Fi, HTTPS feed, stale/offline state, and reconnect pass.
- [ ] Wired recovery and OTA rollback path are available.

## 9. Documentation and UX

- [ ] Follow `docs/SETUP.md` from a fresh environment.
- [ ] Verify all relative Markdown links.
- [ ] Confirm commands do not contain user-specific paths or live endpoints.
- [ ] Confirm screenshots are synthetic/cropped and metadata-stripped.
- [ ] Update hardware matrix and troubleshooting notes.
- [ ] Recheck trademark disclaimer and unofficial-project wording.

## 10. Artifacts and provenance

- [ ] Produce source archive from the reviewed tag.
- [ ] Publish separate, unmistakably labeled V1 and V2 artifacts if binaries are
  included.
- [ ] Include checksums and an artifact manifest.
- [ ] Sign the tag and artifacts when release infrastructure supports it.
- [ ] State whether binaries are placeholder, unprovisioned, or locally
  provisioned; never imply CI placeholders are ready to flash.
- [ ] Verify downloaded artifacts against published checksums.

## 11. Publish and monitor

- [ ] Obtain final maintainer approval.
- [ ] Create the tag from the reviewed commit.
- [ ] Publish release notes with security/privacy-relevant changes.
- [ ] Verify links and artifacts from a logged-out browser session.
- [ ] Monitor private vulnerability reports and issue regressions.
- [ ] Preserve a documented rollback or release-withdrawal path.

## Sign-off

Record sign-off in the release pull request, not in this reusable template:

- Source commit reviewed: [ ]
- Security review complete: [ ]
- V1 hardware verified: [ ]
- V2 hardware verified: [ ]
- Artifacts/checksums verified: [ ]
- Release approved: [ ]
