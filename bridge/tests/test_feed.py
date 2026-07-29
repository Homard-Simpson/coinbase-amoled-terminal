from __future__ import annotations

import copy
import unittest
from typing import Any, ClassVar

from coinbase_amoled_bridge.config import default_config
from coinbase_amoled_bridge.errors import CoinbaseAPIError
from coinbase_amoled_bridge.feed import FeedService, SampleFeedService

from .helpers import candles


class MutableClock:
    def __init__(self, value: float) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class FakeClient:
    PRICES: ClassVar[dict[str, str]] = {
        "BTC-USD": "65000",
        "SOL-USD": "160",
        "XLM-USD": "0.42",
        "HYPE-USD": "42",
        "ETH-USD": "3500",
    }

    def __init__(self) -> None:
        self.fail = False
        self.candle_count = 40

    def _check(self) -> None:
        if self.fail:
            raise CoinbaseAPIError("upstream_unreachable")

    def get_product(self, product_id: str) -> dict[str, Any]:
        self._check()
        return {
            "product_id": product_id,
            "price": self.PRICES.get(product_id, "12.5"),
            "price_percentage_change_24h": "1.25",
            "volume_24h": "12345",
        }

    def get_candles(self, product_id: str, *, end_epoch: int) -> list[dict[str, str]]:
        self._check()
        return list(reversed(candles(self.candle_count)))

    def list_accounts(self) -> list[dict[str, Any]]:
        self._check()
        return [
            {
                "uuid": "private-account-uuid",
                "name": "Private Wallet Name",
                "currency": "BTC",
                "active": True,
                "platform": "ACCOUNT_PLATFORM_CONSUMER",
                "available_balance": {"value": "0.1"},
                "hold": {"value": "0.01"},
            },
            {
                "currency": "USD",
                "active": True,
                "platform": "ACCOUNT_PLATFORM_CONSUMER",
                "available_balance": {"value": "1000"},
                "hold": {"value": "0"},
            },
        ]

    def get_cfm_positions(self) -> list[dict[str, Any]]:
        self._check()
        return [
            {
                "product_id": "BTC-PERP",
                "side": "SHORT",
                "number_of_contracts": "2",
                "current_price": "65000",
                "avg_entry_price": "64000",
                "unrealized_pnl": "-2000",
                "daily_realized_pnl": "0",
            }
        ]

    def get_cfm_balance_summary(self) -> dict[str, Any]:
        self._check()
        return {
            "total_usd_balance": {"value": "1500"},
            "unrealized_pnl": {"value": "-2000"},
            "available_margin": {"value": "1200"},
            "liquidation_buffer_amount": {"value": "1000"},
        }

    def list_intx_portfolios(self) -> list[dict[str, Any]]:
        self._check()
        return []

    def get_intx_positions(self, portfolio_uuid: str) -> list[dict[str, Any]]:
        self._check()
        return []

    def get_intx_portfolio_summary(self, portfolio_uuid: str) -> dict[str, Any]:
        self._check()
        return {}


class FeedTests(unittest.TestCase):
    def settings(self) -> dict[str, Any]:
        return copy.deepcopy(default_config()["settings"])

    def test_live_feed_has_prices_positions_summary_and_30_sorted_candles(self) -> None:
        clock = MutableClock(1_700_005_000)
        feed = FeedService(FakeClient(), self.settings(), clock=clock).get_feed()
        self.assertTrue(feed["read_only"])
        self.assertEqual(feed["mode"], "live")
        self.assertEqual(feed["symbols"], ["BTC", "SOL", "XLM", "HYPE", "ETH"])
        self.assertEqual(feed["prices"]["BTC"], "65000")
        for market in feed["markets"].values():
            self.assertEqual(market["candle_count"], 30)
            self.assertTrue(market["candles_complete"])
            starts = [item["start"] for item in market["candles"]]
            self.assertEqual(starts, sorted(starts))
        types = {position["position_type"] for position in feed["positions"]}
        self.assertEqual(types, {"spot", "cfm_futures"})
        self.assertEqual(feed["account_summary"]["futures_unrealized_pnl"], "-2000")
        # BTC spot value 0.11 * 65000 plus CFM total USD 1500.
        self.assertEqual(feed["account_summary"]["estimated_total_value"], "8650")
        self.assertFalse(feed["staleness"]["stale"])
        self.assertFalse(feed["staleness"]["degraded"])
        serialized = str(feed)
        self.assertNotIn("private-account-uuid", serialized)
        self.assertNotIn("Private Wallet Name", serialized)

    def test_failed_refresh_retains_then_expires_stale_data(self) -> None:
        clock = MutableClock(1_700_005_000)
        client = FakeClient()
        service = FeedService(client, self.settings(), clock=clock)
        initial = service.get_feed()
        self.assertEqual(initial["prices"]["BTC"], "65000")
        client.fail = True
        clock.value += 16
        degraded = service.get_feed()
        self.assertEqual(degraded["prices"]["BTC"], "65000")
        self.assertTrue(degraded["staleness"]["degraded"])
        self.assertFalse(degraded["staleness"]["stale"])
        clock.value += 90
        stale = service.get_feed()
        self.assertTrue(stale["staleness"]["stale"])
        self.assertTrue(stale["markets"]["BTC"]["stale"])
        clock.value += 600
        expired = service.get_feed()
        self.assertIsNone(expired["prices"]["BTC"])
        self.assertFalse(expired["markets"]["BTC"]["available"])
        self.assertEqual(expired["positions"], [])
        self.assertFalse(expired["account_summary"]["available"])

    def test_insufficient_provider_candles_are_disclosed_not_invented(self) -> None:
        client = FakeClient()
        client.candle_count = 12
        feed = FeedService(
            client, self.settings(), clock=MutableClock(1_700_005_000)
        ).get_feed()
        self.assertEqual(feed["markets"]["BTC"]["candle_count"], 12)
        self.assertFalse(feed["markets"]["BTC"]["candles_complete"])
        self.assertIn(
            {"scope": "markets.BTC", "code": "insufficient_candles"},
            feed["staleness"]["errors"],
        )

    def test_disabled_derivative_sources_are_explicit_and_not_errors(self) -> None:
        settings = self.settings()
        settings["include_cfm_positions"] = False
        settings["include_intx_positions"] = False
        feed = FeedService(
            FakeClient(), settings, clock=MutableClock(1_700_005_000)
        ).get_feed()
        self.assertEqual(feed["staleness"]["components"]["cfm"]["status"], "disabled")
        self.assertEqual(feed["staleness"]["components"]["intx"]["status"], "disabled")
        self.assertFalse(feed["staleness"]["degraded"])

    def test_sample_mode_has_exactly_30_candles_for_defaults_and_generic_symbol(
        self,
    ) -> None:
        settings = self.settings()
        settings["symbols"] = ["BTC", "SOL", "XLM", "HYPE", "ETH", "DOGE"]
        feed = SampleFeedService(settings, clock=MutableClock(1_700_005_000)).get_feed()
        self.assertEqual(feed["source"], "synthetic_offline")
        self.assertTrue(feed["read_only"])
        self.assertIn("DOGE", feed["markets"])
        self.assertFalse(feed["staleness"]["stale"])
        for market in feed["markets"].values():
            self.assertEqual(len(market["candles"]), 30)


if __name__ == "__main__":
    unittest.main()
