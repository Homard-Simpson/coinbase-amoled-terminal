"""Bridge-specific exceptions with deliberately non-secret messages."""

from __future__ import annotations


class BridgeError(Exception):
    """Base class for expected, safely reportable bridge failures."""


class ConfigError(BridgeError):
    """Configuration is missing, unsupported, or unsafe."""


class CredentialError(BridgeError):
    """Credential material is missing or invalid."""


class UnsafeCredentialError(CredentialError):
    """The Coinbase key is not strictly view-only."""


class ReadOnlyViolation(BridgeError):
    """A request fell outside the hard-coded GET allowlist."""


class CoinbaseAPIError(BridgeError):
    """Sanitized upstream error.

    The response body is intentionally not retained: upstream bodies can
    contain account context and should not find their way into logs.
    """

    def __init__(
        self,
        code: str,
        *,
        status: int | None = None,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
        self.retry_after = retry_after
