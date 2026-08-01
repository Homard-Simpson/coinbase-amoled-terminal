# Contributing

Thanks for helping improve Coinbase AMOLED Terminal. Contributions should keep the
project small, read-only, deployment-private-by-default, and safe to publish.

## Before starting

- Search existing issues and pull requests.
- For large changes, open a design issue before investing substantial work.
- Report vulnerabilities privately under [SECURITY.md](SECURITY.md).
- Do not propose trading, order, transfer, withdrawal, or hosted credential
  features; those are intentional non-goals.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
./scripts/preflight.sh
```

Firmware development additionally requires ESP-IDF 5.5.x with the `esp32s3`
target. Docker Compose v2 is optional for bridge development.

## Branches and commits

- Branch from the current default branch.
- Keep commits focused and explain why the change is needed.
- Do not commit generated firmware, local configuration, secrets, dependency
  caches, logs, or hardware identifiers.
- Use clear, imperative commit subjects.

## Code expectations

- Preserve the security invariants in [SECURITY.md](SECURITY.md).
- Keep Python compatible with the versions tested in CI.
- Format and lint Python with Ruff.
- Use strict shell settings (`set -euo pipefail`) in Bash scripts.
- Keep V1 and V2 hardware paths explicit; never infer a board revision from a
  sensitive or globally unique identifier.
- Add tests for security boundaries, parsing, and error behavior.
- Update user-facing docs and `CHANGELOG.md` for observable changes.

## Tests

Run the complete preflight:

```bash
./scripts/preflight.sh
```

For firmware changes, also build both variants:

```bash
./scripts/build-firmware.sh v1 --ci-placeholder
./scripts/build-firmware.sh v2 --ci-placeholder
```

Placeholder builds prove compilation only. Test release candidates on the exact
board revision, using locally provisioned values, before release.

## Pull requests

A good pull request:

- states the problem and chosen approach;
- identifies security and privacy effects;
- lists tests and hardware revisions exercised;
- includes sanitized UI evidence when visual behavior changes;
- avoids unrelated reformatting; and
- passes required CI checks.

Every copyright-significant contribution requires acceptance of the
[Contributor License Agreement](CONTRIBUTOR_LICENSE_AGREEMENT.md). Put this exact
statement in the pull-request description and check the CLA box in the template:

```text
I have read and agree to the Contributor License Agreement.
```

The CLA leaves your copyright with you while granting rights needed for the
Project's AGPL/GPL distribution and optional proprietary dual licensing. A
maintainer must not merge a contribution without explicit acceptance. If you
submit on behalf of an employer or another entity, you must have authority to
make the CLA grants.

## Handling test data

Use synthetic fixtures for authenticated/account behavior. Public market-data
snapshots may be used when their source and capture time are documented. Never
copy an authenticated Coinbase response, account value, credential, token,
device identifier, private hostname, network address, or unsanitized serial log
into the repository. Interface evidence must come from the actual renderer using
only public or synthetic data, with privacy mode enabled for account pages.
Construct secret-like values dynamically inside scanner tests so the test source
itself remains safe to publish.

## Code of Conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
