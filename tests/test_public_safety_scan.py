from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER_PATH = ROOT / "scripts" / "scan_public_safety.py"
SPEC = importlib.util.spec_from_file_location("public_safety_scanner", SCANNER_PATH)
assert SPEC is not None and SPEC.loader is not None
SCANNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SCANNER
SPEC.loader.exec_module(SCANNER)


class PublicSafetyScannerTests(unittest.TestCase):
    def scan_content(self, content: str, filename: str = "sample.txt") -> tuple[str, ...]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / filename
            path.write_text(content, encoding="utf-8")
            report = SCANNER.scan_paths([path])
        return tuple(finding.category for finding in report.findings)

    def test_reserved_placeholders_are_allowed(self) -> None:
        content = "\n".join(
            (
                "SERVICE_URL=https://service.example.invalid/feed",
                "API_KEY=<replace-me>",
                "DEVICE_FEED_TOKEN_FILE=/run/secrets/device-feed-token",
                "contact=security@example.com",
                "loopback=127.0.0.1",
            )
        )
        self.assertEqual(self.scan_content(content, ".env"), ())

    def test_known_token_signatures_are_detected_without_echoing_values(self) -> None:
        github_like = "gh" + "p_" + ("A" * 32)
        aws_like = "AK" + "IA" + ("7" * 16)
        categories = self.scan_content(f"first={github_like}\nsecond={aws_like}\n")
        self.assertIn("github-token", categories)
        self.assertIn("aws-key", categories)

    def test_private_key_header_is_detected(self) -> None:
        header = "-----BEGIN " + "PRIVATE KEY-----"
        self.assertIn("private-key", self.scan_content(header))

    def test_private_infrastructure_and_personal_values_are_detected(self) -> None:
        private_ip = ".".join(("192", "168", "40", "12"))
        hardware_address = ":".join(("ab", "cd", "ef", "01", "23", "45"))
        personal_path = "/" + "/".join(("Users", "specific-person", "project"))
        phone_number = "555" + "-" + "234" + "-" + "6789"
        content = "\n".join((private_ip, hardware_address, personal_path, phone_number))
        categories = self.scan_content(content)
        self.assertIn("private-ip", categories)
        self.assertIn("mac-address", categories)
        self.assertIn("personal-path", categories)
        self.assertIn("phone-number", categories)

    def test_non_example_email_is_detected(self) -> None:
        address = "person" + "@" + "somewhere.testdomain"
        self.assertIn("email-address", self.scan_content(address))

    def test_prefixed_literal_secret_assignment_is_detected(self) -> None:
        key_name = "_".join(("COINBASE", "API", "KEY"))
        value = "Correct" + "Horse" + "7" + "!" + "Battery"
        categories = self.scan_content(json.dumps({key_name: value}), "settings.json")
        self.assertIn("secret-assignment", categories)

    def test_excluded_build_directory_is_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            build = root / "build"
            build.mkdir()
            token_like = "gh" + "p_" + ("B" * 32)
            (build / "generated.txt").write_text(token_like, encoding="utf-8")
            (root / "safe.txt").write_text("placeholder only", encoding="utf-8")
            report = SCANNER.scan_paths([root])
        self.assertEqual(report.findings, ())
        self.assertEqual(report.files_scanned, 1)

    def test_git_worktree_pointer_is_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            personal_path = "/" + "/".join(("Users", "specific-person", "worktree"))
            (root / ".git").write_text(f"gitdir: {personal_path}\n", encoding="utf-8")
            (root / "safe.txt").write_text("placeholder only", encoding="utf-8")
            report = SCANNER.scan_paths([root])
        self.assertEqual(report.findings, ())
        self.assertEqual(report.files_scanned, 1)

    def test_external_directory_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "repository"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "external").symlink_to(outside, target_is_directory=True)
            report = SCANNER.scan_paths([root])
        self.assertIn("external-symlink", {finding.category for finding in report.findings})

    def test_oversized_text_requires_manual_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "large.txt"
            path.write_text("safe but too large", encoding="utf-8")
            report = SCANNER.scan_paths([path], max_bytes=4)
        self.assertIn("oversized-text", {finding.category for finding in report.findings})

    def test_repository_tree_scans_clean(self) -> None:
        report = SCANNER.scan_paths([ROOT])
        details = "\n".join(
            f"{finding.path}:{finding.line} [{finding.category}]" for finding in report.findings
        )
        self.assertEqual(report.findings, (), details)


if __name__ == "__main__":
    unittest.main()
