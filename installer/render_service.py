#!/usr/bin/env python3
"""Render fixed per-user service templates with strict path escaping."""

from __future__ import annotations

import argparse
import html
import os
import tempfile
from pathlib import Path

PLACEHOLDERS = {
    "@EXECUTABLE_XML@",
    "@DATA_DIR_XML@",
    "@SAMPLE_ARG_XML@",
    "@EXECUTABLE_SYSTEMD@",
    "@DATA_DIR_SYSTEMD@",
    "@SAMPLE_ARG_SYSTEMD@",
}


def _validate_path(value: str, label: str) -> str:
    if not value or not os.path.isabs(value):
        raise ValueError(f"{label} must be an absolute path")
    if any(ord(character) < 0x20 for character in value):
        raise ValueError(f"{label} contains a control character")
    return value


def _systemd_quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    return f'"{escaped}"'


def render_launchd(template: str, *, executable: str, data_dir: str, sample: bool) -> str:
    executable = _validate_path(executable, "executable")
    data_dir = _validate_path(data_dir, "data directory")
    rendered = template.replace("@EXECUTABLE_XML@", html.escape(executable, quote=False))
    rendered = rendered.replace("@DATA_DIR_XML@", html.escape(data_dir, quote=False))
    rendered = rendered.replace(
        "@SAMPLE_ARG_XML@", "        <string>--sample</string>\n" if sample else ""
    )
    return _finish(rendered)


def render_systemd(template: str, *, executable: str, data_dir: str, sample: bool) -> str:
    executable = _validate_path(executable, "executable")
    data_dir = _validate_path(data_dir, "data directory")
    rendered = template.replace("@EXECUTABLE_SYSTEMD@", _systemd_quote(executable))
    rendered = rendered.replace("@DATA_DIR_SYSTEMD@", _systemd_quote(data_dir))
    rendered = rendered.replace("@SAMPLE_ARG_SYSTEMD@", " --sample" if sample else "")
    return _finish(rendered)


def _finish(rendered: str) -> str:
    remaining = sorted(placeholder for placeholder in PLACEHOLDERS if placeholder in rendered)
    if remaining:
        raise ValueError("service template contains unresolved placeholders")
    return rendered.rstrip() + "\n"


def _write_atomic(path: Path, payload: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}-", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("launchd", "systemd"), required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--executable", required=True)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--sample", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    template = args.template.read_text(encoding="utf-8")
    if args.platform == "launchd":
        rendered = render_launchd(
            template,
            executable=args.executable,
            data_dir=args.data_dir,
            sample=args.sample,
        )
    else:
        rendered = render_systemd(
            template,
            executable=args.executable,
            data_dir=args.data_dir,
            sample=args.sample,
        )
    _write_atomic(args.output, rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
