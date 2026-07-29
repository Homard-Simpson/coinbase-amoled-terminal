from __future__ import annotations

import copy
import json
import unittest
from typing import Any

from coinbase_amoled_bridge.config import default_config
from coinbase_amoled_bridge.device_feed import to_device_feed
from coinbase_amoled_bridge.feed import SampleFeedService

# Fields that would disclose cash or whole-account value and must never reach the
# device projection.
FORBIDDEN_DEVICE_KEYS = {
    "account_summary",
    "markets",
    "spot_cash_value",
    "estimated_total_value",
    "futures_total_usd_balance",
    "intx_total_balance",
}


def _rich_with_positions(positions: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "read_only": True,
        "mode": "live",
        "generated_at": "2023-11-14T22:16:40Z",
        "refresh_seconds": 15,
        "symbols": ["BTC"],
        "prices": {"BTC": "65000"},
        "markets": {
            "BTC": {
                "symbol": "BTC",
                "price": "65000",
                "candles": [
                    {
                        "start": 1_700_004_940,
                        "open": "64990",
                        "high": "65010",
                        "low": "64980",
                        "close": "65000",
                        "volume": "12.5",
                    }
                ],
            }
        },
        "positions": positions,
        "account_summary": {"spot_cash_value": "2500", "estimated_total_value": "9999"},
        "staleness": {"stale": False},
    }


class DeviceFeedProjectionTests(unittest.TestCase):
    def test_sample_feed_projects_to_numeric_compact_contract(self) -> None:
        settings = copy.deepcopy(default_config()["settings"])
        rich = SampleFeedService(settings, clock=lambda: 1_700_005_000).get_feed()
        device = to_device_feed(rich)

        self.assertEqual(device["schema_version"], 1)
        self.assertIs(device["read_only"], True)
        self.assertEqual(device["candle_interval_seconds"], 60)

        self.assertIsInstance(device["prices"]["BTC"], float)
        self.assertGreater(device["prices"]["BTC"], 0)

        self.assertIsInstance(device["positions"], dict)
        for symbol, position in device["positions"].items():
            self.assertIsInstance(symbol, str)
            self.assertIs(position["open"], True)
            self.assertIsInstance(position["entry"], float)
            self.assertIsInstance(position["pnl"], float)

        candles = device["candles"]["BTC"]
        self.assertEqual(len(candles[0]), 6)
        for value in candles[0]:
            self.assertIsInstance(value, (int, float))

        self.assertEqual(
            set(device["portfolio"]),
            {"positions_value", "unrealized_pnl", "realized_pnl_today"},
        )

    def test_projection_drops_cash_and_account_totals(self) -> None:
        rich = _rich_with_positions([])
        device = to_device_feed(rich)
        serialized = json.dumps(device)
        for forbidden in FORBIDDEN_DEVICE_KEYS:
            self.assertNotIn(forbidden, device)
            self.assertNotIn(forbidden, serialized)
        # The privacy-sensitive cash values themselves must be absent.
        self.assertNotIn("2500", serialized)
        self.assertNotIn("9999", serialized)

    def test_derivative_position_wins_symbol_collision(self) -> None:
        rich = _rich_with_positions(
            [
                {
                    "symbol": "BTC",
                    "position_type": "spot",
                    "side": "LONG",
                    "quantity": "0.11",
                    "entry_price": None,
                    "market_value": "7150",
                    "unrealized_pnl": None,
                },
                {
                    "symbol": "BTC",
                    "position_type": "cfm_futures",
                    "side": "SHORT",
                    "contracts": "2",
                    "entry_price": "64000",
                    "market_value": None,
                    "unrealized_pnl": "-2000",
                    "daily_realized_pnl": "0",
                },
            ]
        )
        device = to_device_feed(rich)
        btc = device["positions"]["BTC"]
        self.assertEqual(btc["side"], "SHORT")
        self.assertEqual(btc["entry"], 64000.0)
        self.assertEqual(btc["pnl"], -2000.0)
        self.assertEqual(btc["contracts"], 2.0)
        # Aggregate value still includes the spot market value.
        self.assertEqual(device["portfolio"]["positions_value"], 7150.0)
        self.assertEqual(device["portfolio"]["unrealized_pnl"], -2000.0)

    def test_non_finite_and_negative_prices_are_dropped(self) -> None:
        rich = _rich_with_positions([])
        rich["markets"]["BTC"]["price"] = "-5"
        device = to_device_feed(rich)
        self.assertNotIn("BTC", device["prices"])


if __name__ == "__main__":
    unittest.main()
