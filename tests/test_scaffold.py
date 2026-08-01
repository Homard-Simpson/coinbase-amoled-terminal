from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    "README.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "PRIVACY.md",
    "CONTRIBUTING.md",
    "LICENSING.md",
    "CONTRIBUTOR_LICENSE_AGREEMENT.md",
    "COMMERCIAL-LICENSING.md",
    "TRADEMARKS.md",
    "CODE_OF_CONDUCT.md",
    "CHANGELOG.md",
    "ROADMAP.md",
    "docker-compose.yml",
    ".env.example",
    ".gitignore",
    ".gitattributes",
    "Makefile",
    "docs/ARCHITECTURE.md",
    "docs/THREAT_MODEL.md",
    "docs/HARDWARE_COMPATIBILITY.md",
    "docs/SETUP.md",
    "docs/TROUBLESHOOTING.md",
    "docs/RELEASE_CHECKLIST.md",
    "docs/PUBLIC_RELEASE_CHECKLIST.md",
    "scripts/scan_public_safety.py",
    "scripts/preflight.sh",
    ".github/dependabot.yml",
    ".github/pull_request_template.md",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/workflows/python.yml",
    ".github/workflows/security.yml",
    ".github/workflows/codeql.yml",
    ".github/workflows/firmware.yml",
)

MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


class RepositoryScaffoldTests(unittest.TestCase):
    def test_required_public_files_exist(self) -> None:
        missing = [relative for relative in REQUIRED_FILES if not (ROOT / relative).is_file()]
        self.assertEqual(missing, [], f"missing required files: {missing}")

    def test_readme_has_unofficial_and_read_only_boundaries(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("not affiliated", readme)
        self.assertIn("read-only", readme)
        self.assertIn("no trading", readme)
        self.assertIn("scoped device-feed token", readme)

    def test_security_policy_preserves_credential_boundary(self) -> None:
        policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8").lower()
        self.assertIn("credentials remain on the local bridge", policy)
        self.assertIn("no trading surface", policy)
        self.assertIn("private vulnerability", policy)

    def test_license_boundaries_and_cla_acceptance_are_explicit(self) -> None:
        root_license = (ROOT / "LICENSE").read_text(encoding="utf-8")
        bridge_license = (ROOT / "bridge" / "LICENSE").read_text(encoding="utf-8")
        firmware_license = (ROOT / "firmware" / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("GNU AFFERO GENERAL PUBLIC LICENSE", root_license)
        self.assertEqual(root_license, bridge_license)
        self.assertIn("GNU GENERAL PUBLIC LICENSE", firmware_license)
        self.assertNotIn("AFFERO", firmware_license)
        scope = (ROOT / "LICENSING.md").read_text(encoding="utf-8")
        for identifier in ("AGPL-3.0-or-later", "GPL-3.0-or-later", "CERN-OHL-S-2.0"):
            self.assertIn(identifier, scope)

        acceptance = "I have read and agree to the Contributor License Agreement."
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        template = (ROOT / ".github" / "pull_request_template.md").read_text(encoding="utf-8")
        self.assertIn(acceptance, contributing)
        self.assertIn(acceptance, template)

    def test_hardware_matrix_names_both_controller_paths(self) -> None:
        matrix = (ROOT / "docs" / "HARDWARE_COMPATIBILITY.md").read_text(encoding="utf-8")
        for expected in ("V1", "V2", "SH8601", "CO5300", "FT5x06", "CST816S"):
            self.assertIn(expected, matrix)

    def test_compose_publishes_bridge_on_loopback_and_hardens_container(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("127.0.0.1:${BRIDGE_PORT:-8788}:8788", compose)
        self.assertIn("read_only: true", compose)
        self.assertIn("no-new-privileges:true", compose)
        self.assertNotIn("0.0.0.0:${BRIDGE_PORT", compose)

    def test_external_github_actions_are_pinned_to_commit_sha(self) -> None:
        failures: list[str] = []
        pattern = re.compile(r"^\s*uses:\s*([^@\s]+)@([^\s#]+)", re.MULTILINE)
        for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            text = workflow.read_text(encoding="utf-8")
            for action, revision in pattern.findall(text):
                if not re.fullmatch(r"[0-9a-f]{40}", revision):
                    failures.append(f"{workflow.name}: {action}@{revision}")
        self.assertEqual(failures, [], "unpinned actions:\n" + "\n".join(failures))

    def test_relative_markdown_links_resolve(self) -> None:
        failures: list[str] = []
        markdown_files = sorted(ROOT.glob("*.md")) + sorted((ROOT / "docs").glob("*.md"))
        for document in markdown_files:
            text = document.read_text(encoding="utf-8")
            for raw_target in MARKDOWN_LINK.findall(text):
                target = raw_target.strip().split()[0].strip("<>")
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                relative = target.split("#", 1)[0]
                if relative and not (document.parent / relative).resolve().exists():
                    failures.append(f"{document.relative_to(ROOT)} -> {relative}")
        self.assertEqual(failures, [], "broken relative links:\n" + "\n".join(failures))

    def test_text_files_have_lf_final_newline_and_no_trailing_space(self) -> None:
        failures: list[str] = []
        suffixes = {".md", ".py", ".sh", ".toml", ".txt", ".yml", ".yaml"}
        named_files = {"LICENSE", "NOTICE", "Makefile", ".env.example", ".gitignore"}
        excluded_parts = {"build", "managed_components", ".git", ".venv"}
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file() or any(part in excluded_parts for part in path.parts):
                continue
            if path.suffix not in suffixes and path.name not in named_files:
                continue
            raw = path.read_bytes()
            relative = path.relative_to(ROOT)
            if b"\r\n" in raw:
                failures.append(f"{relative}: CRLF line ending")
            if raw and not raw.endswith(b"\n"):
                failures.append(f"{relative}: missing final newline")
            for line_number, line in enumerate(raw.splitlines(), start=1):
                if line.endswith((b" ", b"\t")):
                    failures.append(f"{relative}:{line_number}: trailing whitespace")
        self.assertEqual(failures, [], "text hygiene failures:\n" + "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
