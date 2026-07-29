"""Build the privacy-minimized, device-facing read-only feed."""

from __future__ import annotations

import copy
import hashlib
import logging
import math
import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, ClassVar

from .coinbase import CoinbaseClient
from .errors import CoinbaseAPIError
from .logging_utils import log_event
from .symbols import SymbolSpec, normalize_symbols
from .util import decimal_string, decimal_value, iso_z, safe_text

EXPECTED_CANDLES = 30
FIAT_CURRENCIES = {"USD", "USDC"}
CURRENCY_RE = re.compile(r"^[A-Z0-9_]{1,16}$")
MARKET_IDENTIFIER_RE = re.compile(r"^[A-Z0-9_-]{1,64}$")
LOGGER = logging.getLogger("coinbase_amoled_bridge.feed")
LOGGER.addHandler(logging.NullHandler())


@dataclass(slots=True)
class _Component:
    value: Any = None
    as_of: float | None = None
    error_code: str | None = None
    warning_code: str | None = None


class FeedService:
    """Refresh and retain independently stale-safe feed components."""

    def __init__(
        self,
        client: CoinbaseClient,
        settings: dict[str, Any],
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.client = client
        self.settings = copy.deepcopy(settings)
        self.clock = clock
        self.symbols = normalize_symbols(
            self.settings["symbols"], quote_currency=self.settings["quote_currency"]
        )
        self.refresh_seconds = int(self.settings["refresh_seconds"])
        self.stale_after_seconds = int(self.settings["stale_after_seconds"])
        self.max_stale_seconds = int(self.settings["max_stale_seconds"])
        self._lock = threading.RLock()
        self._next_refresh = 0.0
        self._last_attempt: float | None = None
        self._markets = {spec.symbol: _Component() for spec in self.symbols}
        self._spot = _Component()
        self._cfm = _Component(
            error_code=None
            if self.settings.get("include_cfm_positions", True)
            else "disabled"
        )
        self._intx = _Component(
            error_code=None
            if self.settings.get("include_intx_positions", True)
            else "disabled"
        )

    def get_feed(self) -> dict[str, Any]:
        now = float(self.clock())
        with self._lock:
            if now >= self._next_refresh:
                self._refresh(now)
            return self._assemble(float(self.clock()))

    def _refresh(self, now: float) -> None:
        self._last_attempt = now
        self._next_refresh = now + self.refresh_seconds

        worker_count = min(5, max(1, len(self.symbols)))
        with ThreadPoolExecutor(
            max_workers=worker_count, thread_name_prefix="market"
        ) as pool:
            futures = {
                pool.submit(self._fetch_market, spec, now): spec
                for spec in self.symbols
            }
            for future in as_completed(futures):
                spec = futures[future]
                component = self._markets[spec.symbol]
                try:
                    market, warning = future.result()
                except Exception as exc:  # sanitized before it reaches the feed
                    component.error_code = _error_code(exc)
                    log_event(
                        LOGGER,
                        "feed_component_refresh_failed",
                        level=logging.WARNING,
                        component="market",
                        symbol=spec.symbol,
                        error_code=component.error_code,
                    )
                else:
                    component.value = market
                    component.as_of = now
                    component.error_code = None
                    component.warning_code = warning

        prices = {
            symbol: component.value.get("price")
            for symbol, component in self._markets.items()
            if isinstance(component.value, dict)
            and component.value.get("price") is not None
        }
        try:
            accounts = self.client.list_accounts()
            self._spot.value = _parse_spot_accounts(accounts, prices)
            self._spot.as_of = now
            self._spot.error_code = None
        except Exception as exc:
            self._spot.error_code = _error_code(exc)
            log_event(
                LOGGER,
                "feed_component_refresh_failed",
                level=logging.WARNING,
                component="accounts",
                error_code=self._spot.error_code,
            )

        if self.settings.get("include_cfm_positions", True):
            try:
                cfm_positions = self.client.get_cfm_positions()
                cfm_summary = self.client.get_cfm_balance_summary()
                self._cfm.value = {
                    "positions": _parse_cfm_positions(cfm_positions),
                    "summary": _parse_cfm_summary(cfm_summary),
                }
                self._cfm.as_of = now
                self._cfm.error_code = None
            except Exception as exc:
                self._cfm.error_code = _optional_error_code(exc)
                if self._cfm.error_code == "not_applicable":
                    self._cfm.value = None
                    self._cfm.as_of = None
                else:
                    log_event(
                        LOGGER,
                        "feed_component_refresh_failed",
                        level=logging.WARNING,
                        component="cfm",
                        error_code=self._cfm.error_code,
                    )

        if self.settings.get("include_intx_positions", True):
            try:
                portfolios = self.client.list_intx_portfolios()
                intx_positions: list[dict[str, Any]] = []
                intx_summaries: list[dict[str, Any]] = []
                for portfolio in portfolios[:10]:
                    portfolio_uuid = str(portfolio["uuid"])
                    intx_positions.extend(
                        self.client.get_intx_positions(portfolio_uuid)
                    )
                    intx_summaries.append(
                        self.client.get_intx_portfolio_summary(portfolio_uuid)
                    )
                self._intx.value = {
                    "positions": _parse_intx_positions(intx_positions),
                    "summary": _parse_intx_summaries(intx_summaries),
                }
                self._intx.as_of = now
                self._intx.error_code = None
            except Exception as exc:
                self._intx.error_code = _optional_error_code(exc)
                if self._intx.error_code == "not_applicable":
                    self._intx.value = None
                    self._intx.as_of = None
                else:
                    log_event(
                        LOGGER,
                        "feed_component_refresh_failed",
                        level=logging.WARNING,
                        component="intx",
                        error_code=self._intx.error_code,
                    )

    def _fetch_market(
        self, spec: SymbolSpec, now: float
    ) -> tuple[dict[str, Any], str | None]:
        product = self.client.get_product(spec.product_id)
        candles_raw = self.client.get_candles(spec.product_id, end_epoch=int(now))
        price = decimal_string(product.get("price"))
        if price is None or Decimal(price) <= 0:
            raise CoinbaseAPIError("invalid_product_price")
        candles = _normalize_candles(candles_raw)
        warning = None if len(candles) == EXPECTED_CANDLES else "insufficient_candles"
        return (
            {
                "available": True,
                "symbol": spec.symbol,
                "product_id": spec.product_id,
                "quote_currency": spec.quote_currency,
                "price": price,
                "price_change_24h": decimal_string(
                    product.get("price_percentage_change_24h")
                ),
                "volume_24h": decimal_string(product.get("volume_24h")),
                "candle_granularity": "ONE_MINUTE",
                "expected_candle_count": EXPECTED_CANDLES,
                "candle_count": len(candles),
                "candles_complete": len(candles) == EXPECTED_CANDLES,
                "candles": candles,
            },
            warning,
        )

    def _assemble(self, now: float) -> dict[str, Any]:
        components_meta: dict[str, dict[str, Any]] = {}
        errors: list[dict[str, Any]] = []
        markets: dict[str, dict[str, Any]] = {}
        prices: dict[str, str | None] = {}
        required_stale = False
        required_ages: list[int] = []

        for spec in self.symbols:
            component = self._markets[spec.symbol]
            meta = self._component_meta(component, now, optional=False)
            components_meta[f"markets.{spec.symbol}"] = meta
            if component.error_code:
                errors.append(
                    {"scope": f"markets.{spec.symbol}", "code": component.error_code}
                )
            if component.warning_code:
                errors.append(
                    {"scope": f"markets.{spec.symbol}", "code": component.warning_code}
                )
            if meta["stale"] or not meta["available"]:
                required_stale = True
            if meta["age_seconds"] is not None:
                required_ages.append(meta["age_seconds"])

            if meta["available"] and isinstance(component.value, dict):
                market = copy.deepcopy(component.value)
                market["as_of"] = meta["as_of"]
                market["age_seconds"] = meta["age_seconds"]
                market["stale"] = meta["stale"]
            else:
                market = {
                    "available": False,
                    "symbol": spec.symbol,
                    "product_id": spec.product_id,
                    "quote_currency": spec.quote_currency,
                    "price": None,
                    "price_change_24h": None,
                    "volume_24h": None,
                    "candle_granularity": "ONE_MINUTE",
                    "expected_candle_count": EXPECTED_CANDLES,
                    "candle_count": 0,
                    "candles_complete": False,
                    "candles": [],
                    "as_of": meta["as_of"],
                    "age_seconds": meta["age_seconds"],
                    "stale": True,
                }
            markets[spec.symbol] = market
            prices[spec.symbol] = market["price"]

        spot_meta = self._component_meta(self._spot, now, optional=False)
        components_meta["accounts"] = spot_meta
        if self._spot.error_code:
            errors.append({"scope": "accounts", "code": self._spot.error_code})
        if spot_meta["stale"] or not spot_meta["available"]:
            required_stale = True
        if spot_meta["age_seconds"] is not None:
            required_ages.append(spot_meta["age_seconds"])

        cfm_meta = self._component_meta(self._cfm, now, optional=True)
        intx_meta = self._component_meta(self._intx, now, optional=True)
        components_meta["cfm"] = cfm_meta
        components_meta["intx"] = intx_meta
        for scope, component in (("cfm", self._cfm), ("intx", self._intx)):
            if component.error_code and component.error_code not in {
                "not_applicable",
                "disabled",
            }:
                errors.append({"scope": scope, "code": component.error_code})

        spot_value = self._spot.value if spot_meta["available"] else None
        cfm_value = self._cfm.value if cfm_meta["available"] else None
        intx_value = self._intx.value if intx_meta["available"] else None
        positions: list[dict[str, Any]] = []
        if isinstance(spot_value, dict):
            positions.extend(copy.deepcopy(spot_value.get("positions", [])))
        if isinstance(cfm_value, dict):
            positions.extend(copy.deepcopy(cfm_value.get("positions", [])))
        if isinstance(intx_value, dict):
            positions.extend(copy.deepcopy(intx_value.get("positions", [])))
        positions.sort(
            key=lambda item: (
                item.get("position_type") == "spot",
                item.get("symbol", ""),
            )
        )

        summary = _merge_account_summary(spot_value, cfm_value, intx_value)
        summary["available"] = bool(spot_meta["available"])
        summary["as_of"] = spot_meta["as_of"]
        summary["age_seconds"] = spot_meta["age_seconds"]
        summary["stale"] = spot_meta["stale"]

        return {
            "schema_version": "1.0",
            "read_only": True,
            "mode": "live",
            "source": "coinbase_advanced_trade",
            "generated_at": iso_z_from_epoch(now),
            "refresh_seconds": self.refresh_seconds,
            "symbols": [spec.symbol for spec in self.symbols],
            "prices": prices,
            "markets": markets,
            "positions": positions,
            "account_summary": summary,
            "staleness": {
                "stale": required_stale,
                "degraded": bool(errors),
                "age_seconds": max(required_ages, default=None),
                "stale_after_seconds": self.stale_after_seconds,
                "max_stale_seconds": self.max_stale_seconds,
                "last_refresh_attempt_at": (
                    iso_z_from_epoch(self._last_attempt)
                    if self._last_attempt is not None
                    else None
                ),
                "components": components_meta,
                "errors": errors,
            },
        }

    def _component_meta(
        self, component: _Component, now: float, *, optional: bool
    ) -> dict[str, Any]:
        age = None if component.as_of is None else max(0, int(now - component.as_of))
        expired = age is not None and age > self.max_stale_seconds
        available = component.value is not None and not expired
        stale = not available or (age is not None and age > self.stale_after_seconds)
        return {
            "available": available,
            "optional": optional,
            "as_of": iso_z_from_epoch(component.as_of)
            if component.as_of is not None
            else None,
            "age_seconds": age,
            "stale": stale,
            "expired": expired,
            "status": (
                "disabled"
                if optional and component.error_code == "disabled"
                else "not_applicable"
                if optional and component.error_code == "not_applicable"
                else "expired"
                if expired
                else "degraded"
                if available and (component.error_code or component.warning_code)
                else "error"
                if component.error_code and not available
                else "stale"
                if stale
                else "ok"
            ),
        }


class SampleFeedService:
    """Offline deterministic-ish data with no Coinbase credentials or network."""

    BASE_PRICES: ClassVar[dict[str, Decimal]] = {
        "BTC": Decimal("65000"),
        "SOL": Decimal("160"),
        "XLM": Decimal("0.42"),
        "HYPE": Decimal("42"),
        "ETH": Decimal("3500"),
    }

    def __init__(
        self,
        settings: dict[str, Any],
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = copy.deepcopy(settings)
        self.clock = clock
        self.symbols = normalize_symbols(
            self.settings["symbols"], quote_currency=self.settings["quote_currency"]
        )
        self.refresh_seconds = int(self.settings["refresh_seconds"])

    def get_feed(self) -> dict[str, Any]:
        now = float(self.clock())
        minute = int(now) - int(now) % 60
        markets: dict[str, dict[str, Any]] = {}
        prices: dict[str, str] = {}
        components: dict[str, dict[str, Any]] = {}
        for index, spec in enumerate(self.symbols):
            base = self.BASE_PRICES.get(spec.symbol, _generic_sample_price(spec.symbol))
            phase = minute / 300.0 + index * 0.91
            current = base * Decimal(str(1 + math.sin(phase) * 0.006))
            candles: list[dict[str, Any]] = []
            for offset in range(EXPECTED_CANDLES):
                start = minute - (EXPECTED_CANDLES - 1 - offset) * 60
                wave = math.sin(start / 360.0 + index) * 0.008
                open_value = base * Decimal(str(1 + wave))
                close_value = base * Decimal(
                    str(1 + wave + math.sin(start / 91.0) * 0.0015)
                )
                high = max(open_value, close_value) * Decimal("1.0012")
                low = min(open_value, close_value) * Decimal("0.9988")
                candles.append(
                    {
                        "start": start,
                        "open": decimal_string(open_value),
                        "high": decimal_string(high),
                        "low": decimal_string(low),
                        "close": decimal_string(close_value),
                        "volume": decimal_string(Decimal("10") + Decimal(offset) / 10),
                    }
                )
            price = decimal_string(current) or "0"
            prices[spec.symbol] = price
            markets[spec.symbol] = {
                "available": True,
                "symbol": spec.symbol,
                "product_id": spec.product_id,
                "quote_currency": spec.quote_currency,
                "price": price,
                "price_change_24h": decimal_string(Decimal(str(math.sin(phase) * 2.5))),
                "volume_24h": decimal_string(Decimal("1000000") + index * 250000),
                "candle_granularity": "ONE_MINUTE",
                "expected_candle_count": EXPECTED_CANDLES,
                "candle_count": EXPECTED_CANDLES,
                "candles_complete": True,
                "candles": candles,
                "as_of": iso_z_from_epoch(now),
                "age_seconds": 0,
                "stale": False,
            }
            components[f"markets.{spec.symbol}"] = _healthy_component(
                now, optional=False
            )

        positions: list[dict[str, Any]] = []
        for spec, quantity in zip(
            self.symbols[:2], (Decimal("0.05"), Decimal("10")), strict=False
        ):
            price = Decimal(prices[spec.symbol])
            positions.append(
                {
                    "symbol": spec.symbol,
                    "product_id": spec.product_id,
                    "position_type": "spot",
                    "side": "LONG",
                    "quantity": decimal_string(quantity),
                    "available": decimal_string(quantity),
                    "hold": "0",
                    "entry_price": None,
                    "current_price": decimal_string(price),
                    "market_value": decimal_string(quantity * price),
                    "unrealized_pnl": None,
                }
            )
        asset_value = sum(
            (Decimal(item["market_value"]) for item in positions), Decimal("0")
        )
        cash = Decimal("2500")
        summary = {
            "available": True,
            "currency": "USD",
            "estimated_total_value": decimal_string(asset_value + cash),
            "spot_cash_value": decimal_string(cash),
            "spot_asset_value": decimal_string(asset_value),
            "futures_total_usd_balance": None,
            "futures_unrealized_pnl": None,
            "futures_available_margin": None,
            "liquidation_buffer_amount": None,
            "intx_total_balance": None,
            "intx_unrealized_pnl": None,
            "position_count": len(positions),
            "account_count": len(positions) + 1,
            "unpriced_asset_count": 0,
            "as_of": iso_z_from_epoch(now),
            "age_seconds": 0,
            "stale": False,
        }
        components["accounts"] = _healthy_component(now, optional=False)
        components["cfm"] = _healthy_component(now, optional=True)
        components["intx"] = _healthy_component(now, optional=True)
        return {
            "schema_version": "1.0",
            "read_only": True,
            "mode": "sample",
            "source": "synthetic_offline",
            "generated_at": iso_z_from_epoch(now),
            "refresh_seconds": self.refresh_seconds,
            "symbols": [spec.symbol for spec in self.symbols],
            "prices": prices,
            "markets": markets,
            "positions": positions,
            "account_summary": summary,
            "staleness": {
                "stale": False,
                "degraded": False,
                "age_seconds": 0,
                "stale_after_seconds": int(self.settings["stale_after_seconds"]),
                "max_stale_seconds": int(self.settings["max_stale_seconds"]),
                "last_refresh_attempt_at": iso_z_from_epoch(now),
                "components": components,
                "errors": [],
            },
        }


def _normalize_candles(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_start: dict[int, dict[str, Any]] = {}
    for item in raw:
        try:
            start = int(str(item.get("start", "")))
        except ValueError:
            continue
        if start <= 0:
            continue
        normalized = {
            "start": start,
            "open": decimal_string(item.get("open")),
            "high": decimal_string(item.get("high")),
            "low": decimal_string(item.get("low")),
            "close": decimal_string(item.get("close")),
            "volume": decimal_string(item.get("volume")),
        }
        if any(
            normalized[key] is None
            for key in ("open", "high", "low", "close", "volume")
        ):
            continue
        open_value = Decimal(normalized["open"])
        high_value = Decimal(normalized["high"])
        low_value = Decimal(normalized["low"])
        close_value = Decimal(normalized["close"])
        volume_value = Decimal(normalized["volume"])
        if (
            min(open_value, high_value, low_value, close_value) < 0
            or volume_value < 0
            or high_value < max(open_value, close_value, low_value)
            or low_value > min(open_value, close_value, high_value)
        ):
            continue
        by_start[start] = normalized
    ordered = [by_start[key] for key in sorted(by_start)]
    return ordered[-EXPECTED_CANDLES:]


def _parse_spot_accounts(
    accounts: list[dict[str, Any]], prices: dict[str, str | None]
) -> dict[str, Any]:
    aggregate: dict[str, dict[str, Decimal]] = {}
    account_count = 0
    for account in accounts:
        if account.get("active") is False or account.get("deleted_at"):
            continue
        platform = str(account.get("platform", "ACCOUNT_PLATFORM_CONSUMER"))
        if platform not in {
            "ACCOUNT_PLATFORM_CONSUMER",
            "ACCOUNT_PLATFORM_UNSPECIFIED",
            "",
        }:
            continue
        currency = str(account.get("currency", "")).strip().upper()
        if not CURRENCY_RE.fullmatch(currency):
            continue
        available_obj = account.get("available_balance", {})
        hold_obj = account.get("hold", {})
        available = decimal_value(
            available_obj.get("value") if isinstance(available_obj, dict) else None
        )
        hold = decimal_value(
            hold_obj.get("value") if isinstance(hold_obj, dict) else None
        )
        if available < 0 or hold < 0:
            continue
        account_count += 1
        bucket = aggregate.setdefault(
            currency, {"available": Decimal("0"), "hold": Decimal("0")}
        )
        bucket["available"] += available
        bucket["hold"] += hold

    cash_value = Decimal("0")
    asset_value = Decimal("0")
    unpriced = 0
    positions: list[dict[str, Any]] = []
    for currency, amounts in sorted(aggregate.items()):
        quantity = amounts["available"] + amounts["hold"]
        if quantity <= 0:
            continue
        if currency in FIAT_CURRENCIES:
            cash_value += quantity
            continue
        price_text = prices.get(currency)
        price = Decimal(price_text) if price_text is not None else None
        market_value = quantity * price if price is not None else None
        if market_value is None:
            unpriced += 1
        else:
            asset_value += market_value
        positions.append(
            {
                "symbol": currency,
                "product_id": f"{currency}-USD",
                "position_type": "spot",
                "side": "LONG",
                "quantity": decimal_string(quantity),
                "available": decimal_string(amounts["available"]),
                "hold": decimal_string(amounts["hold"]),
                "entry_price": None,
                "current_price": price_text,
                "market_value": decimal_string(market_value)
                if market_value is not None
                else None,
                "unrealized_pnl": None,
            }
        )
    return {
        "positions": positions[:100],
        "cash_value": cash_value,
        "asset_value": asset_value,
        "account_count": account_count,
        "unpriced_asset_count": unpriced,
    }


def _parse_cfm_positions(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    positions: list[dict[str, Any]] = []
    for item in raw[:100]:
        product_id = _safe_market_identifier(item.get("product_id"))
        contracts = decimal_string(item.get("number_of_contracts"))
        if not product_id or contracts is None or decimal_value(contracts) == 0:
            continue
        side = str(item.get("side", "UNKNOWN")).upper()
        if side not in {"LONG", "SHORT"}:
            side = "UNKNOWN"
        positions.append(
            {
                "symbol": _base_from_product(product_id),
                "product_id": product_id,
                "position_type": "cfm_futures",
                "side": side,
                "quantity": contracts,
                "contracts": contracts,
                "available": None,
                "hold": None,
                "entry_price": decimal_string(item.get("avg_entry_price")),
                "current_price": decimal_string(item.get("current_price")),
                "market_value": None,
                "unrealized_pnl": decimal_string(item.get("unrealized_pnl")),
                "daily_realized_pnl": decimal_string(item.get("daily_realized_pnl")),
                "expiration_time": _safe_timestamp(item.get("expiration_time")),
            }
        )
    return positions


def _parse_cfm_summary(raw: dict[str, Any]) -> dict[str, str | None]:
    return {
        "total_usd_balance": _amount_value(raw.get("total_usd_balance")),
        "unrealized_pnl": _amount_value(raw.get("unrealized_pnl")),
        "available_margin": _amount_value(raw.get("available_margin")),
        "liquidation_buffer_amount": _amount_value(
            raw.get("liquidation_buffer_amount")
        ),
    }


def _parse_intx_positions(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    positions: list[dict[str, Any]] = []
    for item in raw[:100]:
        product_id = _safe_market_identifier(
            item.get("symbol") or item.get("product_id")
        )
        size = decimal_string(item.get("net_size"))
        if not product_id or size is None or decimal_value(size) == 0:
            continue
        side_raw = str(item.get("position_side", "")).upper()
        if side_raw.endswith("LONG"):
            side = "LONG"
        elif side_raw.endswith("SHORT"):
            side = "SHORT"
        else:
            side = "LONG" if decimal_value(size) > 0 else "SHORT"
        positions.append(
            {
                "symbol": _base_from_product(product_id),
                "product_id": product_id,
                "position_type": "intx_perpetual",
                "side": side,
                "quantity": size,
                "available": None,
                "hold": None,
                "entry_price": _amount_value(item.get("entry_vwap")),
                "current_price": _amount_value(item.get("mark_price")),
                "market_value": _amount_value(item.get("position_notional")),
                "unrealized_pnl": _amount_value(item.get("unrealized_pnl")),
                "liquidation_price": _amount_value(item.get("liquidation_price")),
                "leverage": decimal_string(item.get("leverage")),
            }
        )
    return positions


def _parse_intx_summaries(raw: list[dict[str, Any]]) -> dict[str, str | None]:
    total = Decimal("0")
    pnl = Decimal("0")
    found_total = False
    found_pnl = False
    for summary in raw:
        total_text = _amount_value(summary.get("total_balance"))
        pnl_text = _amount_value(summary.get("unrealized_pnl"))
        if total_text is not None:
            total += Decimal(total_text)
            found_total = True
        if pnl_text is not None:
            pnl += Decimal(pnl_text)
            found_pnl = True
    return {
        "total_balance": decimal_string(total) if found_total else None,
        "unrealized_pnl": decimal_string(pnl) if found_pnl else None,
    }


def _merge_account_summary(spot: Any, cfm: Any, intx: Any) -> dict[str, Any]:
    spot = spot if isinstance(spot, dict) else {}
    cfm_summary = cfm.get("summary", {}) if isinstance(cfm, dict) else {}
    intx_summary = intx.get("summary", {}) if isinstance(intx, dict) else {}
    cash = spot.get("cash_value", Decimal("0"))
    assets = spot.get("asset_value", Decimal("0"))
    if not isinstance(cash, Decimal):
        cash = decimal_value(cash)
    if not isinstance(assets, Decimal):
        assets = decimal_value(assets)
    futures_total_text = cfm_summary.get("total_usd_balance")
    intx_total_text = intx_summary.get("total_balance")
    # CFM total USD includes CBI spot USD, so it replaces (rather than adds to)
    # spot cash. INTX collateral is a separate portfolio and is additive.
    liquid_total = (
        Decimal(futures_total_text) if futures_total_text is not None else cash
    )
    intx_total = (
        Decimal(intx_total_text) if intx_total_text is not None else Decimal("0")
    )
    estimated = assets + liquid_total + intx_total
    position_count = sum(
        len(value.get("positions", [])) if isinstance(value, dict) else 0
        for value in (spot, cfm, intx)
    )
    return {
        "currency": "USD",
        "estimated_total_value": decimal_string(estimated),
        "spot_cash_value": decimal_string(cash),
        "spot_asset_value": decimal_string(assets),
        "futures_total_usd_balance": futures_total_text,
        "futures_unrealized_pnl": cfm_summary.get("unrealized_pnl"),
        "futures_available_margin": cfm_summary.get("available_margin"),
        "liquidation_buffer_amount": cfm_summary.get("liquidation_buffer_amount"),
        "intx_total_balance": intx_total_text,
        "intx_unrealized_pnl": intx_summary.get("unrealized_pnl"),
        "position_count": position_count,
        "account_count": int(spot.get("account_count", 0)),
        "unpriced_asset_count": int(spot.get("unpriced_asset_count", 0)),
    }


def _amount_value(value: Any) -> str | None:
    if isinstance(value, dict):
        return decimal_string(value.get("value"))
    return decimal_string(value)


def _safe_market_identifier(value: Any) -> str | None:
    try:
        rendered = safe_text(value or "", max_length=64, allow_empty=False).upper()
    except ValueError:
        return None
    if not MARKET_IDENTIFIER_RE.fullmatch(rendered):
        return None
    return rendered


def _base_from_product(product_id: str) -> str:
    base = product_id.split("-", 1)[0]
    aliases = {"BIT": "BTC", "ET": "ETH"}
    return aliases.get(base, base)[:16]


def _safe_timestamp(value: Any) -> str | None:
    try:
        return safe_text(value or "", max_length=40) or None
    except ValueError:
        return None


def _error_code(exc: Exception) -> str:
    return exc.code if isinstance(exc, CoinbaseAPIError) else "component_refresh_failed"


def _optional_error_code(exc: Exception) -> str:
    if isinstance(exc, CoinbaseAPIError) and exc.status in {403, 404}:
        return "not_applicable"
    return _error_code(exc)


def iso_z_from_epoch(value: float | None) -> str | None:
    if value is None:
        return None
    from datetime import UTC, datetime

    return iso_z(datetime.fromtimestamp(value, UTC))


def _healthy_component(now: float, *, optional: bool) -> dict[str, Any]:
    return {
        "available": True,
        "optional": optional,
        "as_of": iso_z_from_epoch(now),
        "age_seconds": 0,
        "stale": False,
        "expired": False,
        "status": "ok",
    }


def _generic_sample_price(symbol: str) -> Decimal:
    digest = hashlib.sha256(symbol.encode("ascii")).digest()
    cents = int.from_bytes(digest[:4], "big") % 990_000 + 1_000
    return Decimal(cents) / Decimal("100")
