# Branch Protection Status

The repository is private and must remain private. On 2026-08-01, authenticated
GitHub API requests using the `Homard-Simpson` account returned HTTP 403 for both
classic protection and repository rulesets on `main`:

```text
Upgrade to GitHub Pro or make this repository public to enable this feature.
```

GitHub therefore does not expose server-enforced branch protection for this
private repository on its current plan. The project will not be made public and
no plan purchase or upgrade is assumed.

GitHub Actions remain useful checks, but they do **not** prevent an authorized
user from force-pushing or bypassing review. No workflow in this repository is
represented as a substitute for branch protection.

Until the account plan changes, maintainers must treat this as an explicit
platform constraint: avoid force pushes, review changes before pushing `main`,
and keep recoverable local clones/backups. Recheck the API before claiming that
server-side protection is active.
