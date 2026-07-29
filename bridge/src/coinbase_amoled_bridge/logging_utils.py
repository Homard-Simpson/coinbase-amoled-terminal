"""One-line JSON logging with aggressive secret redaction."""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Any

SENSITIVE_KEY_RE = re.compile(
    r"(?:authorization|bearer|credential|private.?key|api.?key|secret|token|cookie)",
    re.IGNORECASE,
)
TEXT_PATTERNS = (
    re.compile(r"Bearer\s+[A-Za-z0-9._~+\-/]+=*", re.IGNORECASE),
    re.compile(r"cbat_[A-Za-z0-9_-]{20,}"),
    re.compile(r"organizations/[^\s/]+/apiKeys/[^\s]+", re.IGNORECASE),
    re.compile(
        r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
        re.IGNORECASE | re.DOTALL,
    ),
)


def redact_text(value: str) -> str:
    result = value
    for pattern in TEXT_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


def redact(value: Any, *, key: str = "") -> Any:
    if SENSITIVE_KEY_RE.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(child_key): redact(child, key=str(child_key))
            for child_key, child in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(child) for child in value]
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return redact_text(str(value))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        timestamp = (
            datetime.fromtimestamp(record.created, UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        payload: dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": redact_text(record.getMessage()),
        }
        fields = getattr(record, "bridge_fields", None)
        if isinstance(fields, dict):
            payload.update(redact(fields))
        if record.exc_info:
            # Exception messages can include URLs or provider data. Log only the
            # type; callers provide a sanitized error code as a normal field.
            payload["exception_type"] = record.exc_info[0].__name__
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True)


def configure_logging(level: str = "INFO") -> None:
    normalized = level.upper()
    if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValueError("invalid log level")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(normalized)


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.INFO,
    exc_info: bool = False,
    **fields: Any,
) -> None:
    logger.log(level, event, extra={"bridge_fields": fields}, exc_info=exc_info)
