"""Narrow Coinbase Advanced Trade GET client.

There is intentionally no generic method argument and no mutation endpoint in
this module. Every path and query field is selected from a closed allowlist.
"""

from __future__ import annotations

import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from . import __version__
from .auth import JWTSigner
from .errors import CoinbaseAPIError, ReadOnlyViolation, UnsafeCredentialError
from .symbols import PRODUCT_RE

API_ORIGIN = "https://api.coinbase.com"
API_PREFIX = "/api/v3/brokerage"
MAX_RESPONSE_BYTES = 2_000_000
MAX_ACCOUNT_PAGES = 4


@dataclass(frozen=True, slots=True)
class TransportResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


Transport = Callable[[str, Mapping[str, str], float], TransportResponse]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(  # type: ignore[override]
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


class CoinbaseClient:
    """Authenticated read-only client for a small Advanced Trade subset."""

    def __init__(
        self,
        signer: JWTSigner,
        *,
        timeout: float = 8.0,
        transport: Transport | None = None,
    ) -> None:
        if not 1.0 <= timeout <= 30.0:
            raise ValueError("timeout must be between 1 and 30 seconds")
        self.signer = signer
        self.timeout = float(timeout)
        self._transport = transport or self._default_transport

    def _default_transport(
        self, url: str, headers: Mapping[str, str], timeout: float
    ) -> TransportResponse:
        context = ssl.create_default_context()
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), _NoRedirectHandler()
        )
        # URL origin and path are closed allowlists; urllib is not a general
        # fetcher here.
        request = urllib.request.Request(  # noqa: S310
            url=url, headers=dict(headers), method="GET"
        )
        try:
            with opener.open(request, timeout=timeout) as response:
                final = urllib.parse.urlsplit(response.geturl())
                if final.scheme != "https" or final.hostname != "api.coinbase.com":
                    raise CoinbaseAPIError("unsafe_upstream_redirect")
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                if len(payload) > MAX_RESPONSE_BYTES:
                    raise CoinbaseAPIError("upstream_response_too_large")
                return TransportResponse(
                    status=int(response.status),
                    headers={
                        key.lower(): value for key, value in response.headers.items()
                    },
                    body=payload,
                )
        except urllib.error.HTTPError as exc:
            # Do not read or retain the body: it may contain account context.
            try:
                retry_after = _parse_retry_after(exc.headers.get("Retry-After"))
                return TransportResponse(
                    status=int(exc.code),
                    headers={"retry-after": str(retry_after)} if retry_after else {},
                    body=b"",
                )
            finally:
                exc.close()
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
            raise CoinbaseAPIError("upstream_unreachable") from exc

    def _get(
        self, path: str, params: Mapping[str, str | int] | None = None
    ) -> dict[str, Any]:
        allowed_query = self._validate_path(path)
        supplied = dict(params or {})
        unknown_query = set(supplied) - allowed_query
        if unknown_query:
            raise ReadOnlyViolation("query fields are outside the endpoint allowlist")
        for key, value in supplied.items():
            rendered = str(value)
            if len(rendered) > 512 or any(ord(ch) < 0x20 for ch in rendered):
                raise ReadOnlyViolation(f"unsafe query value for {key}")
        query = urllib.parse.urlencode(supplied, doseq=False, safe="")
        url = API_ORIGIN + path + ("?" + query if query else "")
        token = self.signer.sign("GET", path)
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Cache-Control": "no-cache",
            "User-Agent": f"coinbase-amoled-bridge/{__version__}",
        }
        response = self._transport(url, headers, self.timeout)
        if response.status != 200:
            raise _http_error(response)
        if len(response.body) > MAX_RESPONSE_BYTES:
            raise CoinbaseAPIError("upstream_response_too_large")
        try:
            parsed = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CoinbaseAPIError("invalid_upstream_json") from exc
        if not isinstance(parsed, dict):
            raise CoinbaseAPIError("invalid_upstream_shape")
        return parsed

    @staticmethod
    def _validate_path(path: str) -> set[str]:
        exact: dict[str, set[str]] = {
            f"{API_PREFIX}/accounts": {"limit", "cursor"},
            f"{API_PREFIX}/key_permissions": set(),
            f"{API_PREFIX}/cfm/positions": set(),
            f"{API_PREFIX}/cfm/balance_summary": set(),
            f"{API_PREFIX}/portfolios": {"portfolio_type"},
        }
        if path in exact:
            return exact[path]
        product_prefix = f"{API_PREFIX}/products/"
        if path.startswith(product_prefix):
            suffix = path[len(product_prefix) :]
            if suffix.endswith("/candles"):
                product_id = suffix[: -len("/candles")]
                if PRODUCT_RE.fullmatch(product_id):
                    return {"start", "end", "granularity", "limit"}
            elif PRODUCT_RE.fullmatch(suffix):
                return set()
        intx_position_prefix = f"{API_PREFIX}/intx/positions/"
        intx_portfolio_prefix = f"{API_PREFIX}/intx/portfolio/"
        for prefix in (intx_position_prefix, intx_portfolio_prefix):
            if path.startswith(prefix) and _valid_uuid(path[len(prefix) :]):
                return set()
        raise ReadOnlyViolation("Coinbase path is outside the read-only GET allowlist")

    def key_permissions(self) -> dict[str, bool]:
        payload = self._get(f"{API_PREFIX}/key_permissions")
        return {
            "can_view": payload.get("can_view") is True,
            "can_trade": payload.get("can_trade") is True,
            "can_transfer": payload.get("can_transfer") is True,
        }

    def assert_view_only(self) -> None:
        permissions = self.key_permissions()
        if (
            not permissions["can_view"]
            or permissions["can_trade"]
            or permissions["can_transfer"]
        ):
            raise UnsafeCredentialError(
                "Coinbase key must have view permission and no trade or transfer "
                "permission"
            )

    def list_accounts(self) -> list[dict[str, Any]]:
        accounts: list[dict[str, Any]] = []
        cursor = ""
        seen_cursors: set[str] = set()
        for _ in range(MAX_ACCOUNT_PAGES):
            params: dict[str, str | int] = {"limit": 250}
            if cursor:
                params["cursor"] = cursor
            payload = self._get(f"{API_PREFIX}/accounts", params)
            page = payload.get("accounts", [])
            if not isinstance(page, list):
                raise CoinbaseAPIError("invalid_accounts_shape")
            accounts.extend(item for item in page if isinstance(item, dict))
            if not payload.get("has_next"):
                return accounts
            next_cursor = payload.get("cursor")
            if (
                not isinstance(next_cursor, str)
                or not next_cursor
                or next_cursor in seen_cursors
            ):
                raise CoinbaseAPIError("invalid_accounts_cursor")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise CoinbaseAPIError("accounts_page_limit_exceeded")

    def get_product(self, product_id: str) -> dict[str, Any]:
        if not PRODUCT_RE.fullmatch(product_id):
            raise ReadOnlyViolation("invalid product ID")
        return self._get(f"{API_PREFIX}/products/{product_id}")

    def get_candles(
        self,
        product_id: str,
        *,
        end_epoch: int | None = None,
        lookback_minutes: int = 120,
    ) -> list[dict[str, Any]]:
        if not PRODUCT_RE.fullmatch(product_id):
            raise ReadOnlyViolation("invalid product ID")
        if not 30 <= lookback_minutes <= 350:
            raise ValueError("lookback_minutes must be between 30 and 350")
        end_value = int(time.time() if end_epoch is None else end_epoch)
        end_value -= end_value % 60
        start_value = end_value - lookback_minutes * 60
        payload = self._get(
            f"{API_PREFIX}/products/{product_id}/candles",
            {
                "start": start_value,
                "end": end_value,
                "granularity": "ONE_MINUTE",
                "limit": lookback_minutes,
            },
        )
        candles = payload.get("candles", [])
        if not isinstance(candles, list):
            raise CoinbaseAPIError("invalid_candles_shape")
        return [item for item in candles if isinstance(item, dict)]

    def get_cfm_positions(self) -> list[dict[str, Any]]:
        payload = self._get(f"{API_PREFIX}/cfm/positions")
        positions = payload.get("positions", [])
        if not isinstance(positions, list):
            raise CoinbaseAPIError("invalid_cfm_positions_shape")
        return [item for item in positions if isinstance(item, dict)]

    def get_cfm_balance_summary(self) -> dict[str, Any]:
        payload = self._get(f"{API_PREFIX}/cfm/balance_summary")
        summary = payload.get("balance_summary", {})
        if not isinstance(summary, dict):
            raise CoinbaseAPIError("invalid_cfm_balance_shape")
        return summary

    def list_intx_portfolios(self) -> list[dict[str, Any]]:
        payload = self._get(f"{API_PREFIX}/portfolios", {"portfolio_type": "INTX"})
        portfolios = payload.get("portfolios", [])
        if not isinstance(portfolios, list):
            raise CoinbaseAPIError("invalid_portfolios_shape")
        return [
            item
            for item in portfolios
            if isinstance(item, dict)
            and item.get("type") == "INTX"
            and not item.get("deleted")
            and _valid_uuid(str(item.get("uuid", "")))
        ]

    def get_intx_positions(self, portfolio_uuid: str) -> list[dict[str, Any]]:
        if not _valid_uuid(portfolio_uuid):
            raise ReadOnlyViolation("invalid portfolio UUID")
        payload = self._get(f"{API_PREFIX}/intx/positions/{portfolio_uuid}")
        positions = payload.get("positions", [])
        if not isinstance(positions, list):
            raise CoinbaseAPIError("invalid_intx_positions_shape")
        return [item for item in positions if isinstance(item, dict)]

    def get_intx_portfolio_summary(self, portfolio_uuid: str) -> dict[str, Any]:
        if not _valid_uuid(portfolio_uuid):
            raise ReadOnlyViolation("invalid portfolio UUID")
        payload = self._get(f"{API_PREFIX}/intx/portfolio/{portfolio_uuid}")
        summary = payload.get("summary", {})
        return summary if isinstance(summary, dict) else {}


def _valid_uuid(value: str) -> bool:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return str(parsed) == value.lower()


def _parse_retry_after(value: str | None) -> int | None:
    try:
        parsed = int(value or "")
    except ValueError:
        return None
    return min(max(parsed, 1), 3600)


def _http_error(response: TransportResponse) -> CoinbaseAPIError:
    retry_after = _parse_retry_after(response.headers.get("retry-after"))
    if response.status == 401:
        code = "upstream_auth_failed"
    elif response.status == 403:
        code = "upstream_forbidden"
    elif response.status == 404:
        code = "upstream_not_found"
    elif response.status == 429:
        code = "upstream_rate_limited"
    elif 500 <= response.status <= 599:
        code = "upstream_server_error"
    else:
        code = "upstream_http_error"
    return CoinbaseAPIError(code, status=response.status, retry_after=retry_after)
