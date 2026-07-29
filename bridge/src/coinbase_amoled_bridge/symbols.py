"""Strict symbol-to-product mapping with no user-controlled URL paths."""

from __future__ import annotations

import re
from dataclasses import dataclass

BASE_RE = re.compile(r"^[A-Z0-9]{2,12}$")
PRODUCT_RE = re.compile(r"^[A-Z0-9]{2,12}-[A-Z0-9]{2,8}$")
ALIASES = {"XBT": "BTC"}
DEFAULT_SYMBOLS = ("BTC", "SOL", "XLM", "HYPE", "ETH")


@dataclass(frozen=True, slots=True)
class SymbolSpec:
    symbol: str
    product_id: str
    quote_currency: str


def normalize_symbol(value: str, *, quote_currency: str = "USD") -> SymbolSpec:
    raw = str(value).strip().upper().replace("/", "-")
    quote = quote_currency.strip().upper()
    if not BASE_RE.fullmatch(quote):
        raise ValueError("invalid quote currency")

    if "-" in raw:
        if not PRODUCT_RE.fullmatch(raw):
            raise ValueError(f"invalid product mapping: {value!r}")
        base, supplied_quote = raw.split("-", 1)
        if supplied_quote != quote:
            raise ValueError(
                f"product {raw!r} does not use configured quote currency {quote!r}"
            )
    else:
        base = raw
        if not BASE_RE.fullmatch(base):
            raise ValueError(f"invalid symbol: {value!r}")

    base = ALIASES.get(base, base)
    if not BASE_RE.fullmatch(base):
        raise ValueError(f"invalid symbol: {value!r}")
    return SymbolSpec(symbol=base, product_id=f"{base}-{quote}", quote_currency=quote)


def normalize_symbols(
    values: list[str] | tuple[str, ...], *, quote_currency: str = "USD"
) -> list[SymbolSpec]:
    if not values:
        raise ValueError("at least one symbol is required")
    if len(values) > 20:
        raise ValueError("at most 20 symbols are supported")
    result: list[SymbolSpec] = []
    seen: set[str] = set()
    for value in values:
        spec = normalize_symbol(value, quote_currency=quote_currency)
        if spec.symbol in seen:
            continue
        seen.add(spec.symbol)
        result.append(spec)
    if not result:
        raise ValueError("at least one unique symbol is required")
    return result
