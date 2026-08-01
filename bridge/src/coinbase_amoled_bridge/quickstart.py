"""Secure parsing for the one-prompt Coinbase CDP quickstart."""

from __future__ import annotations

import getpass
import json
import shlex
from pathlib import Path
from typing import Any

from .auth import MAX_KEY_NAME_BYTES, MAX_PRIVATE_KEY_BYTES, Credentials
from .errors import CredentialError

MAX_CDP_JSON_BYTES = 131_072
MAX_INPUT_LINE_BYTES = MAX_CDP_JSON_BYTES
MAX_PATH_INPUT_BYTES = 4_096
QUICKSTART_PROMPT = (
    "Paste the Coinbase CDP ECDSA API key JSON downloaded from Coinbase, "
    "or drag the JSON file into the terminal, then press Enter: "
)


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CredentialError("Coinbase key JSON contains duplicate fields")
        result[key] = value
    return result


def _read_json_file(path: Path) -> bytes:
    try:
        if not path.is_file():
            raise CredentialError("Coinbase key input is not a regular JSON file")
        size = path.stat().st_size
        if size <= 0 or size > MAX_CDP_JSON_BYTES:
            raise CredentialError("Coinbase key JSON file has an invalid size")
        payload = path.read_bytes()
    except CredentialError:
        raise
    except OSError as exc:
        raise CredentialError("Unable to read the Coinbase key JSON file") from exc
    if len(payload) > MAX_CDP_JSON_BYTES or b"\x00" in payload:
        raise CredentialError("Coinbase key JSON file has an invalid size or content")
    return payload


def _dragged_path(value: str) -> Path:
    if len(value.encode("utf-8")) > MAX_PATH_INPUT_BYTES:
        raise CredentialError("Coinbase key file path is too long")
    try:
        parts = shlex.split(value, comments=False, posix=True)
    except ValueError as exc:
        raise CredentialError("Coinbase key file path is malformed") from exc
    if len(parts) != 1 or not parts[0]:
        raise CredentialError("Enter one JSON object or one JSON file path")
    return Path(parts[0]).expanduser()


def parse_cdp_key_input(value: str) -> Credentials:
    """Parse one hidden prompt value without ever rendering it in an error."""

    if not isinstance(value, str):
        raise CredentialError("Coinbase key input must be text")
    stripped = value.strip()
    if not stripped:
        raise CredentialError("Coinbase key JSON or file path is required")
    try:
        encoded = stripped.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CredentialError("Coinbase key input must be UTF-8") from exc
    if b"\x00" in encoded:
        raise CredentialError("Coinbase key input contains an invalid character")

    if stripped.startswith("{"):
        if len(encoded) > MAX_INPUT_LINE_BYTES:
            raise CredentialError("Coinbase key JSON is too large")
        raw = encoded
    else:
        raw = _read_json_file(_dragged_path(stripped))

    try:
        parsed = json.loads(
            raw.decode("utf-8-sig"), object_pairs_hook=_reject_duplicate_fields
        )
    except CredentialError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CredentialError("Coinbase key input is not valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise CredentialError("Coinbase key JSON must be an object")

    if any(field in parsed for field in ("apiKey", "apiSecret", "secret")):
        raise CredentialError(
            "Legacy Coinbase keys are not supported; download a CDP ECDSA key JSON"
        )
    key_name = parsed.get("name")
    private_key = parsed.get("privateKey")
    if not isinstance(key_name, str) or not isinstance(private_key, str):
        raise CredentialError(
            "Coinbase key JSON must contain text fields named name and privateKey"
        )
    if len(key_name.encode("utf-8")) > MAX_KEY_NAME_BYTES:
        raise CredentialError("Coinbase API key name is too long")
    if len(private_key.encode("utf-8")) > MAX_PRIVATE_KEY_BYTES:
        raise CredentialError("Coinbase private key is too large")

    return Credentials.from_values(
        key_name=key_name,
        private_key_pem=private_key.encode("utf-8"),
        source="quickstart",
    )


def prompt_for_cdp_key() -> Credentials:
    """Read the downloaded JSON or path with terminal echo disabled when possible."""

    try:
        value = getpass.getpass(QUICKSTART_PROMPT)
    except EOFError as exc:
        raise CredentialError(
            "No terminal input was available; rerun the quickstart in a terminal"
        ) from exc
    return parse_cdp_key_input(value)
