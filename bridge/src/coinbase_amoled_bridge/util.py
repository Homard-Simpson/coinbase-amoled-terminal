"""Small, dependency-free helpers used across the bridge."""

from __future__ import annotations

import math
import os
import re
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso_z(value: datetime | None = None) -> str:
    value = value or utc_now()
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_bool(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError("expected a boolean value")


def safe_text(value: Any, *, max_length: int = 80, allow_empty: bool = True) -> str:
    text = str(value)
    if CONTROL_RE.search(text):
        raise ValueError("control characters are not allowed")
    if len(text) > max_length:
        raise ValueError(f"value exceeds {max_length} characters")
    if not allow_empty and not text:
        raise ValueError("value must not be empty")
    return text


def decimal_string(value: Any, *, default: str | None = None) -> str | None:
    """Return a finite JSON-safe decimal string without exponent notation."""

    try:
        decimal_value = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return default
    if not decimal_value.is_finite():
        return default
    if decimal_value == 0:
        return "0"
    rendered = format(decimal_value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def decimal_value(value: Any, *, default: Decimal = Decimal("0")) -> Decimal:
    rendered = decimal_string(value)
    return Decimal(rendered) if rendered is not None else default


def finite_float(value: Any, *, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if math.isfinite(parsed) else default


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path, 0o700)
    except OSError:
        # Some mounted filesystems do not implement POSIX modes. Individual
        # secret writes still use mode 0600 and never log contents.
        pass


def is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower().strip("[]")
    return normalized in {"127.0.0.1", "::1", "localhost"}
