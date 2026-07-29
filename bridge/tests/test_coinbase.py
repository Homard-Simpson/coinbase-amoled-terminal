from __future__ import annotations

import json
import unittest
from urllib.parse import parse_qs, urlsplit

from coinbase_amoled_bridge.coinbase import (
    API_PREFIX,
    CoinbaseClient,
    TransportResponse,
)
from coinbase_amoled_bridge.errors import (
    CoinbaseAPIError,
    ReadOnlyViolation,
    UnsafeCredentialError,
)

from .helpers import candles, make_signer


class RecordingTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str], float]] = []
        self.responses: list[TransportResponse] = []

    def queue(self, value: dict, *, status: int = 200) -> None:
        self.responses.append(
            TransportResponse(
                status=status, headers={}, body=json.dumps(value).encode()
            )
        )

    def __call__(
        self, url: str, headers: dict[str, str], timeout: float
    ) -> TransportResponse:
        self.calls.append((url, dict(headers), timeout))
        return self.responses.pop(0)


class CoinbaseClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = RecordingTransport()
        self.client = CoinbaseClient(make_signer(), timeout=4, transport=self.transport)

    def test_view_only_permission_gate(self) -> None:
        self.transport.queue(
            {"can_view": True, "can_trade": False, "can_transfer": False}
        )
        self.client.assert_view_only()
        url, headers, timeout = self.transport.calls[0]
        self.assertEqual(url, f"https://api.coinbase.com{API_PREFIX}/key_permissions")
        self.assertTrue(headers["Authorization"].startswith("Bearer "))
        self.assertEqual(headers["Cache-Control"], "no-cache")
        self.assertEqual(timeout, 4)

    def test_trade_or_transfer_permissions_are_rejected(self) -> None:
        for permissions in (
            {"can_view": True, "can_trade": True, "can_transfer": False},
            {"can_view": True, "can_trade": False, "can_transfer": True},
            {"can_view": False, "can_trade": False, "can_transfer": False},
        ):
            self.transport.queue(permissions)
            with self.assertRaises(UnsafeCredentialError):
                self.client.assert_view_only()

    def test_mutation_and_arbitrary_paths_never_reach_transport(self) -> None:
        with self.assertRaises(ReadOnlyViolation):
            self.client._get(f"{API_PREFIX}/orders")
        with self.assertRaises(ReadOnlyViolation):
            self.client._get(f"{API_PREFIX}/accounts", {"evil": "1"})
        self.assertEqual(self.transport.calls, [])

    def test_account_pagination_is_bounded_and_combined(self) -> None:
        self.transport.queue(
            {"accounts": [{"currency": "BTC"}], "has_next": True, "cursor": "next"}
        )
        self.transport.queue({"accounts": [{"currency": "USD"}], "has_next": False})
        result = self.client.list_accounts()
        self.assertEqual([item["currency"] for item in result], ["BTC", "USD"])
        second_query = parse_qs(urlsplit(self.transport.calls[1][0]).query)
        self.assertEqual(second_query["cursor"], ["next"])
        self.assertEqual(second_query["limit"], ["250"])

    def test_product_and_candle_queries_are_strict(self) -> None:
        self.transport.queue({"product_id": "BTC-USD", "price": "100"})
        product = self.client.get_product("BTC-USD")
        self.assertEqual(product["price"], "100")
        self.transport.queue({"candles": candles(40)})
        result = self.client.get_candles(
            "BTC-USD", end_epoch=1_700_010_005, lookback_minutes=120
        )
        self.assertEqual(len(result), 40)
        parsed = urlsplit(self.transport.calls[-1][0])
        query = parse_qs(parsed.query)
        self.assertEqual(query["granularity"], ["ONE_MINUTE"])
        self.assertEqual(query["limit"], ["120"])
        self.assertEqual(int(query["end"][0]) % 60, 0)
        with self.assertRaises(ReadOnlyViolation):
            self.client.get_product("../../orders")

    def test_http_error_is_sanitized(self) -> None:
        self.transport.responses.append(
            TransportResponse(
                status=403,
                headers={},
                body=b'{"message":"account-specific secret detail"}',
            )
        )
        with self.assertRaises(CoinbaseAPIError) as raised:
            self.client.list_accounts()
        self.assertEqual(raised.exception.code, "upstream_forbidden")
        self.assertNotIn("secret detail", str(raised.exception))

    def test_intx_uuid_is_validated_locally(self) -> None:
        with self.assertRaises(ReadOnlyViolation):
            self.client.get_intx_positions("not-a-uuid")
        self.assertEqual(self.transport.calls, [])


if __name__ == "__main__":
    unittest.main()
