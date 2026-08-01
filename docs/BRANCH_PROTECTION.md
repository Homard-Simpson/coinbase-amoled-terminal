# Branch Protection Status

Before the 2026-08-01 public release, authenticated GitHub API requests using the
repository owner's account returned HTTP 403 for both classic protection and
repository rulesets on `main`:

```text
Upgrade to GitHub Pro or make this repository public to enable this feature.
```

No workflow was represented as a substitute for protection, and the project did
not purchase a plan upgrade. After authorized public release, `main` is protected
with these server-enforced settings:

- pull requests are required;
- at least one approving review is required;
- stale approvals are dismissed when new commits are pushed;
- conversation resolution is required;
- administrators are subject to the rule;
- force pushes and branch deletion are blocked; and
- only stable, currently passing CI contexts are required.

GitHub Actions are evidence for a change, but they do not independently prevent
an authorized bypass. Maintainers should recheck the branch protection API after
repository setting changes and before claiming these controls remain active.
