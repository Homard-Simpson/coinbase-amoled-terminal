#!/usr/bin/env python3
"""Scan publishable text for likely secrets and personal infrastructure.

This intentionally favors high-confidence, explainable findings. It complements a
full-history scanner such as Gitleaks; it does not replace credential rotation or
human review.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

DEFAULT_MAX_BYTES = 5 * 1024 * 1024

EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "artifacts",
        "build",
        "coverage",
        "dist",
        "htmlcov",
        "managed_components",
        "node_modules",
        "out",
        "secrets",
        "venv",
    }
)

ALLOWED_EXAMPLE_DOMAINS = frozenset(
    {
        "example.com",
        "example.invalid",
        "example.net",
        "example.org",
        "users.noreply.github.com",
    }
)

PLACEHOLDER_MARKERS = (
    "${",
    "<",
    "example",
    "fake",
    "not-a-real",
    "not_real",
    "placeholder",
    "redacted",
    "replace-me",
    "replace_me",
    "synthetic",
    "test-only",
    "test_only",
)

RFC1918_NETWORKS = (
    ipaddress.ip_network(".".join(("10", "0", "0", "0")) + "/8"),
    ipaddress.ip_network(".".join(("172", "16", "0", "0")) + "/12"),
    ipaddress.ip_network(".".join(("192", "168", "0", "0")) + "/16"),
)

# The ESP32 SoftAP captive portal always serves onboarding at this fixed gateway
# address. It is a universal, non-personal constant, so it is not treated as
# leaked private infrastructure. Real LAN addresses are still reported.
ALLOWED_PRIVATE_IPS = frozenset({".".join(("192", "168", "4", "1"))})


@dataclass(frozen=True, order=True)
class Finding:
    """A redacted scanner finding."""

    path: str
    line: int
    category: str
    message: str


@dataclass(frozen=True)
class ScanReport:
    """Scanner result and non-sensitive counters."""

    findings: tuple[Finding, ...]
    files_scanned: int
    binary_files_skipped: int
    oversized_files_skipped: int


@dataclass(frozen=True)
class RegexRule:
    category: str
    message: str
    pattern: re.Pattern[str]


def _joined(*parts: str) -> str:
    """Keep scanner signatures out of the scanner's own publishable source."""

    return "".join(parts)


REGEX_RULES = (
    RegexRule(
        "private-key",
        "private-key material",
        re.compile(_joined(r"-{5}BEGIN ", r"(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-{5}")),
    ),
    RegexRule(
        "github-token",
        "GitHub token-like value",
        re.compile(_joined(r"\bgh", r"[pousr]_[A-Za-z0-9]{30,}\b")),
    ),
    RegexRule(
        "github-token",
        "GitHub fine-grained token-like value",
        re.compile(_joined(r"\bgithub_pat_", r"[A-Za-z0-9_]{40,}\b")),
    ),
    RegexRule(
        "aws-key",
        "AWS access-key-like value",
        re.compile(_joined(r"\bAK", r"IA[0-9A-Z]{16}\b")),
    ),
    RegexRule(
        "slack-token",
        "Slack token-like value",
        re.compile(_joined(r"\bxox", r"[aboprs]-[A-Za-z0-9-]{10,}\b")),
    ),
    RegexRule(
        "stripe-key",
        "Stripe key-like value",
        re.compile(_joined(r"\b(?:sk|rk)_live_", r"[A-Za-z0-9]{16,}\b")),
    ),
    RegexRule(
        "jwt",
        "JWT-like bearer value",
        re.compile(_joined(r"\beyJ[A-Za-z0-9_-]{8,}\.", r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ),
    RegexRule(
        "tailnet-host",
        "private tailnet hostname",
        re.compile(r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9-]+\.ts\.net\b", re.I),
    ),
    RegexRule(
        "mac-address",
        "hardware MAC address",
        re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I),
    ),
    RegexRule(
        "personal-path",
        "user-specific absolute path",
        re.compile(
            r"/(?:Users|home)/(?!example(?:/|$)|user(?:name)?(?:/|$))[A-Za-z0-9._-]+(?:/|$)"
        ),
    ),
    RegexRule(
        "personal-path",
        "user-specific Windows path",
        re.compile(
            r"\b[A-Za-z]:\\Users\\(?!Public\\|Default\\|example\\|user(?:name)?\\)"
            r"[A-Za-z0-9._ -]+\\",
            re.I,
        ),
    ),
    RegexRule(
        "phone-number",
        "phone-number-like value",
        re.compile(r"(?<!\d)(?:\(\d{3}\)\s*|\d{3}[-. ])\d{3}[-. ]\d{4}(?!\d)"),
    ),
    RegexRule(
        "phone-number",
        "international phone-number-like value",
        re.compile(r"(?<!\w)\+\d{1,3}(?:[-. ]?\d){8,14}(?!\d)"),
    ),
    RegexRule(
        "account-value",
        "currency amount adjacent to an account/result label",
        re.compile(
            r"\b(?:balance|equity|portfolio\s+value|pnl|profit|loss)\b[^\n]{0,24}"
            r"(?:USD\s*[-+]?\d|\$\s*[-+]?\d)",
            re.I,
        ),
    ),
)

EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.I)
IPV4_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(?:^|[\s{,])[\"']?"
    r"(?P<name>(?:[a-z0-9]+[_-])*(?:api[_-]?(?:key|secret)|access[_-]?token|"
    r"client[_-]?secret|feed[_-]?token|password|private[_-]?key))"
    r"[\"']?\s*[:=]\s*(?P<value>[^\s,;#]+)"
)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("\"'").lower()
    if not normalized:
        return True
    return normalized in {"none", "null", "unset"} or any(
        marker in normalized for marker in PLACEHOLDER_MARKERS
    )


def _looks_like_literal_secret(value: str, source_path: Path) -> bool:
    cleaned = value.strip().strip("\"'")
    if _is_placeholder(cleaned):
        return False
    if cleaned.startswith(("$", "/run/secrets/", "env(", "getenv(", "os.", "pathlib.")):
        return False
    if cleaned.endswith(")") and "(" in cleaned:
        # Code expressions such as Path("/run/secrets/...") or client.get_token()
        # are function/constructor calls, not literal secret values.
        return False
    if len(cleaned) < 8:
        return False

    configuration_suffixes = {".env", ".ini", ".json", ".toml", ".yaml", ".yml"}
    if source_path.suffix.lower() in configuration_suffixes:
        return True

    was_quoted = value[:1] in {'"', "'"}
    if was_quoted:
        return True

    character_classes = sum(
        (
            any(char.islower() for char in cleaned),
            any(char.isupper() for char in cleaned),
            any(char.isdigit() for char in cleaned),
            any(not char.isalnum() and char != "_" for char in cleaned),
        )
    )
    return len(cleaned) >= 16 and character_classes >= 3


def scan_text(text: str, display_path: str, source_path: Path | None = None) -> list[Finding]:
    """Return redacted findings for one decoded text file."""

    path_for_rules = source_path or Path(display_path)
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()

    def add(offset: int, category: str, message: str) -> None:
        line = _line_number(text, offset)
        key = (line, category)
        if key not in seen:
            seen.add(key)
            findings.append(Finding(display_path, line, category, message))

    for rule in REGEX_RULES:
        for match in rule.pattern.finditer(text):
            add(match.start(), rule.category, rule.message)

    for match in EMAIL_PATTERN.finditer(text):
        domain = match.group(1).lower()
        if domain not in ALLOWED_EXAMPLE_DOMAINS and not domain.endswith(".example.invalid"):
            add(match.start(), "email-address", "non-example email address")

    for match in IPV4_PATTERN.finditer(text):
        if match.group(0) in ALLOWED_PRIVATE_IPS:
            continue
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if any(address in network for network in RFC1918_NETWORKS):
            add(match.start(), "private-ip", "RFC 1918 private network address")

    for match in SECRET_ASSIGNMENT_PATTERN.finditer(text):
        if _looks_like_literal_secret(match.group("value"), path_for_rules):
            add(match.start(), "secret-assignment", "literal assigned to a secret-like field")

    return findings


def _display_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _iter_files(inputs: Sequence[Path]) -> Iterator[tuple[Path, Path]]:
    """Yield (file, display-root) without following directory symlinks."""

    for raw_path in inputs:
        path = Path(os.path.abspath(raw_path.expanduser()))
        if path.is_symlink() or path.is_file():
            yield path, path.parent
            continue
        if not path.exists():
            raise FileNotFoundError(path)
        if not path.is_dir():
            continue

        root = path.resolve()
        for current, directories, filenames in os.walk(path, followlinks=False):
            for directory in sorted(directories):
                candidate = Path(current) / directory
                if candidate.is_symlink():
                    yield candidate, root
            directories[:] = sorted(
                directory
                for directory in directories
                if directory not in EXCLUDED_DIRECTORIES
                and not (Path(current) / directory).is_symlink()
            )
            for filename in sorted(filenames):
                candidate = Path(current) / filename
                yield candidate, root


def scan_paths(inputs: Sequence[Path], max_bytes: int = DEFAULT_MAX_BYTES) -> ScanReport:
    """Scan paths and return findings without printing matched secret values."""

    findings: list[Finding] = []
    files_scanned = 0
    binary_skipped = 0
    oversized_skipped = 0

    for path, root in _iter_files(inputs):
        display_path = _display_path(path, root)
        if path.is_symlink():
            target = path.resolve(strict=False)
            try:
                target.relative_to(root.resolve())
            except ValueError:
                findings.append(
                    Finding(
                        display_path,
                        1,
                        "external-symlink",
                        "symlink resolves outside scan root",
                    )
                )
            continue

        try:
            size = path.stat().st_size
        except OSError:
            findings.append(
                Finding(display_path, 1, "unreadable", "file metadata could not be read")
            )
            continue

        if size > max_bytes:
            try:
                with path.open("rb") as handle:
                    prefix = handle.read(8192)
                prefix.decode("utf-8")
            except (OSError, UnicodeDecodeError):
                binary_skipped += 1
            else:
                if b"\0" in prefix:
                    binary_skipped += 1
                else:
                    oversized_skipped += 1
                    findings.append(
                        Finding(
                            display_path,
                            1,
                            "oversized-text",
                            "text file exceeds scan-size limit and requires manual review",
                        )
                    )
            continue

        try:
            raw = path.read_bytes()
        except OSError:
            findings.append(
                Finding(display_path, 1, "unreadable", "file contents could not be read")
            )
            continue

        if b"\0" in raw[:8192]:
            binary_skipped += 1
            continue

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            binary_skipped += 1
            continue

        files_scanned += 1
        findings.extend(scan_text(text, display_path, path))

    return ScanReport(
        findings=tuple(sorted(set(findings))),
        files_scanned=files_scanned,
        binary_files_skipped=binary_skipped,
        oversized_files_skipped=oversized_skipped,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan text for likely secrets, personal data, and private infrastructure."
    )
    parser.add_argument("paths", nargs="+", type=Path, help="File or directory to scan")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help=f"maximum decoded file size (default: {DEFAULT_MAX_BYTES})",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def _render_text(report: ScanReport) -> None:
    for finding in report.findings:
        print(
            f"{finding.path}:{finding.line}: "
            f"[{finding.category}] {finding.message} (value redacted)"
        )
    summary = (
        f"scanned={report.files_scanned} "
        f"binary_skipped={report.binary_files_skipped} "
        f"oversized_skipped={report.oversized_files_skipped} "
        f"findings={len(report.findings)}"
    )
    print(summary)


def main(argv: Iterable[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.max_bytes < 1:
        parser.error("--max-bytes must be positive")

    try:
        report = scan_paths(args.paths, max_bytes=args.max_bytes)
    except FileNotFoundError as exc:
        parser.error(f"path does not exist: {exc}")

    if args.json:
        payload = {
            "findings": [asdict(finding) for finding in report.findings],
            "files_scanned": report.files_scanned,
            "binary_files_skipped": report.binary_files_skipped,
            "oversized_files_skipped": report.oversized_files_skipped,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _render_text(report)
    return 1 if report.findings else 0


if __name__ == "__main__":
    sys.exit(main())
