# Public-Release Checklist

Use this once when converting the repository from private development to public,
and again after any history rewrite. Complete the normal release checklist too.

## Gate 0 — Stop if uncertain

- [ ] A maintainer is explicitly authorized to make the repository public.
- [ ] The chosen license and ownership of all source/assets are understood.
- [ ] There is no unresolved suspicion that a secret or personal data entered Git
  history.
- [ ] The bridge remains read-only and no trade/order/transfer surface exists.

If any answer is uncertain, keep the repository private.

## Gate 1 — Inventory every object

- [ ] Enumerate tracked files, Git LFS objects, tags, branches, stashes, releases,
  Actions artifacts, packages, wiki pages, issue attachments, and Pages content.
- [ ] Remove full flash dumps, NVS images, firmware backups, logs, crash dumps,
  screenshots with account data, and local databases.
- [ ] Confirm submodules and vendored code point only to publishable sources.
- [ ] Confirm deleted files are not still reachable from Git history.

## Gate 2 — Secret and privacy review

- [ ] Run `./scripts/preflight.sh` with strict tool checks.
- [ ] Run Gitleaks over all refs and history.
- [ ] Search history for credential headers, authorization values, token files,
  environment files, unique device identifiers, private network values, personal
  paths, contact details, and account values.
- [ ] Review CI logs and artifacts separately; source scans do not cover them.
- [ ] Rotate every secret that ever entered the repository, even if later removed.
- [ ] Rewrite history when needed, then rescan the rewritten clone.
- [ ] Have a second reviewer independently inspect the final file list and scan
  results.

## Gate 3 — Legal and brand review

- [ ] `LICENSE` contains the complete Apache License 2.0 text.
- [ ] `NOTICE` preserves required attributions and the Coinbase trademark
  disclaimer.
- [ ] README prominently says the project is unofficial and not affiliated with
  Coinbase.
- [ ] No Coinbase logo, trade dress, or copied proprietary asset is included.
- [ ] Third-party license/NOTICE obligations are satisfied.
- [ ] Every contributor has the right to license their contribution.

## Gate 4 — Documentation truth check

- [ ] README status, support claims, and commands match the code.
- [ ] Security docs state that credentials stay on the local bridge and the ESP
  receives only a scoped feed token.
- [ ] Local/private-tailnet deployment is the default everywhere.
- [ ] TLS reverse-proxy guidance does not suggest disabling verification.
- [ ] Privacy docs enumerate display/account data and physical-observation risk.
- [ ] V1/V2 matrix and PMU warning match current firmware.
- [ ] No document contains a real host, address, account value, device ID, or
  user-specific path.

## Gate 5 — Repository settings before visibility change

- [ ] Enable private vulnerability reporting.
- [ ] Enable GitHub secret scanning and push protection where available.
- [ ] Enable Dependabot alerts, security updates, and grouped version updates.
- [ ] Enable CodeQL/code scanning and review initial findings. While private, the
  workflow requires GitHub Code Security plus `ENABLE_PRIVATE_CODEQL=true`; it
  runs automatically after the repository becomes public.
- [ ] Restrict workflow token permissions to read-only by default.
- [ ] Require approval for workflows from first-time external contributors.
- [ ] Protect the default branch with pull requests and required status checks.
- [ ] Require conversation resolution and block force pushes/deletions.
- [ ] Configure merge and tag rules appropriate to the maintainer model.
- [ ] Remove stale deploy keys, webhooks, collaborators, environments, and Actions
  secrets.
- [ ] Disable unused repository features and public Pages deployments.

## Gate 6 — CI and supply chain

- [ ] Python lint/tests pass on supported versions.
- [ ] V1 and V2 ESP-IDF builds pass from clean state.
- [ ] CodeQL and public-safety scans pass.
- [ ] Workflow actions are first-party or reviewed and version-pinned.
- [ ] Dependabot is configured for Python, GitHub Actions, and container inputs.
- [ ] No workflow prints environment variables or secret-file contents.
- [ ] Pull-request workflows from forks cannot access production secrets.
- [ ] CI firmware uses only reserved placeholder values and is clearly labeled
  non-production.

## Gate 7 — Public collaboration readiness

- [ ] `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, and issue/PR templates
  are present.
- [ ] Security templates direct reporters away from public issues.
- [ ] Bug templates warn against logs/screenshots with financial data.
- [ ] Maintainers can receive private conduct and vulnerability reports.
- [ ] Roadmap and changelog make pre-1.0 status clear.
- [ ] Support expectations and non-goals are explicit.

## Gate 8 — Dry run

- [ ] Clone into a new directory with no local environment files.
- [ ] Run strict preflight.
- [ ] Validate Compose configuration with `.env.example`.
- [ ] Build both placeholder firmware variants.
- [ ] Follow setup docs with synthetic/mock data.
- [ ] Inspect the repository and rendered README while logged out.
- [ ] Download a candidate source archive and scan it independently.

## Gate 9 — Visibility change

- [ ] Capture final private-repository settings for rollback/reference.
- [ ] Change visibility only after all prior gates have sign-off.
- [ ] Immediately verify the public file tree, branches, tags, releases, packages,
  Actions, security policy, and issue forms.
- [ ] Confirm search engines/users cannot access any unintended deployment or
  artifact linked from documentation.
- [ ] Re-run public scanners against the public clone.

## Gate 10 — First 72 hours

- [ ] Monitor security reports, Actions runs, dependency alerts, and issue uploads.
- [ ] Remove any accidental artifact immediately and rotate affected values before
  discussing it publicly.
- [ ] Correct misleading support or affiliation language quickly.
- [ ] Triage build failures on both hardware variants.
- [ ] Publish a sanitized advisory if a material pre-publication exposure is found.

## Final sign-off

Keep evidence in a private release record until it has been reviewed and sanitized:

- Repository/history scan: [ ]
- Credential rotation review: [ ]
- Legal/trademark review: [ ]
- Documentation review: [ ]
- CI and GitHub settings review: [ ]
- Independent second review: [ ]
- Authorized visibility change: [ ]
