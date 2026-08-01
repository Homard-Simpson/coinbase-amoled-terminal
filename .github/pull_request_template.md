# Pull request

## Summary

<!-- What changed, and why is this the smallest safe solution? -->

## Security and privacy impact

<!-- Describe credential, network, logging, payload, storage, and display effects. -->

- [ ] Coinbase credentials remain on the local bridge.
- [ ] The ESP receives only a scoped device-feed token.
- [ ] No trading, order, transfer, withdrawal, or generic proxy surface was added.
- [ ] Logs, fixtures, screenshots, and artifacts contain only public/synthetic/sanitized data.

## Validation

<!-- List exact tests and hardware revisions exercised. -->

- [ ] `./scripts/preflight.sh`
- [ ] Python tests/lint, if affected
- [ ] V1 clean build, if firmware affected
- [ ] V2 clean build, if firmware affected
- [ ] Hardware smoke test, or a clear reason it was not possible

## Documentation and compatibility

- [ ] User-facing documentation is updated.
- [ ] `CHANGELOG.md` is updated for observable behavior.
- [ ] Feed-schema compatibility is documented.
- [ ] V1/V2 behavior remains explicit and safe.

## Evidence

<!-- Use actual-renderer captures with public/sanitized data and sanitized logs only. Never attach real account data. -->
