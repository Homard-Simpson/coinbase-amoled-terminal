#!/usr/bin/env python3
"""Build the production renderer harness and emit metadata-free PNG frames."""

from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import shutil
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path

WIDTH = 368
HEIGHT = 448
SYMBOLS = ("BTC", "SOL", "XLM", "HYPE", "ETH")
PAGES = {
    "prices": "prices-page.png",
    "positions": "positions-privacy-page.png",
    "chart": "btc-chart-bb20-levels.png",
}


def cpp_number(value: float | int) -> str:
    return format(value, ".17g")


def make_data_header(data: dict) -> str:
    lines = ["#pragma once", "static void load_capture_data(){"]
    for index, symbol in enumerate(SYMBOLS):
        product = data["products"][symbol]
        candles = product["hourly_candles"][-36:]
        lines.append(f"  assets[{index}].price={cpp_number(product['ticker_price'])};")
        lines.append(f"  assets[{index}].history_count={len(candles)};")
        lines.append(f"  assets[{index}].history_head={len(candles)};")
        for candle_index, candle in enumerate(candles):
            timestamp, opened, high, low, close, volume = candle
            lines.append(f"  assets[{index}].history[{candle_index}]={cpp_number(close)};")
            fields = ",".join(cpp_number(value) for value in candle)
            lines.append(f"  assets[{index}].candles[{candle_index}]={{{fields}}};")
        lines.append(f"  assets[{index}].candle_count={len(candles)};")
        for level in product["daily_extrema_key_levels"]:
            lines.append(f"  add_key_level(assets[{index}].key_levels,{cpp_number(level)});")
    lines.append("}")
    return "\n".join(lines) + "\n"


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)
    )


def rgb565_to_png(raw_path: Path, png_path: Path) -> None:
    raw = raw_path.read_bytes()
    expected = WIDTH * HEIGHT * 2
    if len(raw) != expected:
        raise ValueError(f"{raw_path}: expected {expected} bytes, got {len(raw)}")
    rows = bytearray()
    offset = 0
    for _ in range(HEIGHT):
        rows.append(0)  # PNG filter: None
        for _ in range(WIDTH):
            value = struct.unpack_from(">H", raw, offset)[0]
            offset += 2
            red = (value >> 11) & 0x1F
            green = (value >> 5) & 0x3F
            blue = value & 0x1F
            rows.extend(
                (
                    (red << 3) | (red >> 2),
                    (green << 2) | (green >> 4),
                    (blue << 3) | (blue >> 2),
                )
            )
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", WIDTH, HEIGHT, 8, 2, 0, 0, 0)
    png_path.write_bytes(
        signature
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", zlib.compress(bytes(rows), 9))
        + png_chunk(b"IEND", b"")
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    data = json.loads(args.data.read_text())
    args.output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="amoled-framebuffer-") as temp_name:
        temp = Path(temp_name)
        (temp / "capture_data.h").write_text(make_data_header(data))
        binary = temp / "renderer_capture"
        compiler = shutil.which("c++")
        if compiler is None:
            raise RuntimeError("C++17 compiler not found")
        subprocess.run(
            [
                compiler,
                "-std=c++17",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(temp),
                "-I",
                str(root),
                str(root / "renderer_capture.cc"),
                "-o",
                str(binary),
            ],
            check=True,
        )
        for page, filename in PAGES.items():
            raw = temp / f"{page}.rgb565"
            subprocess.run([str(binary), page, str(raw)], check=True)
            raw_digest = sha256(raw)
            output = args.output_dir / filename
            rgb565_to_png(raw, output)
            print(
                f"{output}: {WIDTH}x{HEIGHT} rgb565_sha256={raw_digest} png_sha256={sha256(output)}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
