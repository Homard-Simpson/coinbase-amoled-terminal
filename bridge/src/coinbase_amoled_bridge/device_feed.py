"""Project the rich internal feed into the compact device-facing contract.

The firmware is a constrained consumer: it parses a small, numeric, privacy-
minimized JSON document (see ``docs/device-feed.schema.json``). This module maps
the bridge's rich internal feed to that document. It deliberately drops every
account/cash/total-balance field so the device only ever receives open-position
values and market data, never a full account statement.
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any

from .util import finite_float

# The firmware only renders these five assets, but any configured symbol is
# projected; unknown symbols are simply ignored by the device.
DEVICE_SCHEMA_VERSION = 1
CANDLE_INTERVAL_SECONDS = 60
PRICE_HISTORY_SECONDS = 60
MAX_PRICE_HISTORY = 60
# Firmware rejects any numeric magnitude above 1e15; keep values well inside it.
MAX_DEVICE_NUMBER = 1e15


def _number(value: Any) -> float | None:
    """Return a finite float within the firmware's accepted range, else None."""

    if value is None:
        return None
    parsed = finite_float(value, default=math.nan)
    if not math.isfinite(parsed) or abs(parsed) > MAX_DEVICE_NUMBER:
        return None
    return parsed


def _positive(value: Any) -> float | None:
    parsed = _number(value)
    if parsed is None or parsed <= 0:
        return None
    return parsed


def _project_candles(raw_candles: Any) -> tuple[list[list[float]], list[float]]:
    compact: list[list[float]] = []
    closes: list[float] = []
    if not isinstance(raw_candles, list):
        return compact, closes
    for candle in raw_candles:
        if not isinstance(candle, dict):
            continue
        start = candle.get("start")
        if not isinstance(start, int) or start <= 0:
            continue
        open_ = _positive(candle.get("open"))
        high = _positive(candle.get("high"))
        low = _positive(candle.get("low"))
        close = _positive(candle.get("close"))
        volume = _number(candle.get("volume"))
        if None in (open_, high, low, close) or volume is None or volume < 0:
            continue
        # Preserve the OHLC invariants the firmware also enforces.
        if high < max(open_, close, low) or low > min(open_, close, high):
            continue
        compact.append([start, open_, high, low, close, volume])
        closes.append(close)
    return compact, closes


def _spot_rank(position: dict[str, Any]) -> int:
    # Prefer derivative positions over spot holdings when a symbol collides:
    # they carry entry price and P/L, which is what the position row displays.
    return 0 if position.get("position_type") == "spot" else 1


def _display_time() -> str:
    """Return bridge-local wall time in a locale-independent 12-hour format."""

    now = datetime.now().astimezone()
    hour = now.hour % 12 or 12
    suffix = "AM" if now.hour < 12 else "PM"
    return f"{hour:02d}:{now.minute:02d} {suffix}"


def to_device_feed(rich: dict[str, Any]) -> dict[str, Any]:
    """Map the rich internal feed to the compact firmware contract."""

    symbols = rich.get("symbols") or []
    markets = rich.get("markets") or {}

    prices: dict[str, float] = {}
    candles: dict[str, list[list[float]]] = {}
    price_history: dict[str, list[float]] = {}
    for symbol in symbols:
        market = markets.get(symbol)
        if not isinstance(market, dict):
            continue
        price = _positive(market.get("price"))
        if price is not None:
            prices[symbol] = price
        compact_candles, closes = _project_candles(market.get("candles"))
        if compact_candles:
            candles[symbol] = compact_candles
        if closes:
            price_history[symbol] = closes[-MAX_PRICE_HISTORY:]

    positions: dict[str, dict[str, Any]] = {}
    ranked: dict[str, int] = {}
    positions_value = 0.0
    unrealized_total = 0.0
    realized_total = 0.0
    for position in rich.get("positions") or []:
        if not isinstance(position, dict):
            continue
        symbol = position.get("symbol")
        if not isinstance(symbol, str) or not symbol:
            continue
        market_value = _number(position.get("market_value"))
        if market_value is not None:
            positions_value += market_value
        unrealized = _number(position.get("unrealized_pnl"))
        if unrealized is not None:
            unrealized_total += unrealized
        realized = _number(position.get("daily_realized_pnl"))
        if realized is not None:
            realized_total += realized

        contracts = _number(position.get("contracts"))
        quantity = _number(position.get("quantity"))
        size = contracts if contracts is not None else quantity
        record: dict[str, Any] = {
            "open": True,
            "side": str(position.get("side") or "").upper()[:10],
            "entry": _number(position.get("entry_price")) or 0.0,
            "pnl": unrealized or 0.0,
            "size": size or 0.0,
        }
        if contracts is not None:
            record["contracts"] = contracts
        rank = _spot_rank(position)
        if symbol not in positions or rank >= ranked[symbol]:
            positions[symbol] = record
            ranked[symbol] = rank

    refresh_seconds = rich.get("refresh_seconds")
    if not isinstance(refresh_seconds, int) or not 2 <= refresh_seconds <= 3600:
        refresh_seconds = 15

    return {
        "schema_version": DEVICE_SCHEMA_VERSION,
        "read_only": True,
        "mode": rich.get("mode", "live"),
        "generated_at": rich.get("generated_at"),
        "display_time": _display_time(),
        "refresh_seconds": refresh_seconds,
        "price_history_seconds": PRICE_HISTORY_SECONDS,
        "candle_interval_seconds": CANDLE_INTERVAL_SECONDS,
        "prices": prices,
        "price_history": price_history,
        "candles": candles,
        "positions": positions,
        "portfolio": {
            "positions_value": positions_value,
            "unrealized_pnl": unrealized_total,
            "realized_pnl_today": realized_total,
        },
        "closed_today": [],
    }
