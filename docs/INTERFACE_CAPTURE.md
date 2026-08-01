# Interface Capture Provenance

The gallery images are **not mockups**. They are lossless conversions of raw
368 × 448 RGB565 frames emitted by the current production firmware renderer on
2026-08-01.

## Capture method

1. The production renderer's `draw()` function was extracted without edits into
   `tools/framebuffer_capture/production_draw.inc`.
2. Its RGB565 palette, pixel, line, rectangle, bitmap-font, BB20, key-level, and
   page-layout code run in the host harness in
   `tools/framebuffer_capture/renderer_capture.cc`.
3. Only hardware boundaries are replaced: the setup portal reports inactive,
   feed health reports current, and `flush_frame()` writes the framebuffer to a
   raw file instead of transmitting it to the AMOLED panel.
4. `tools/framebuffer_capture/capture.py` converts those raw RGB565 bytes to RGB
   PNG without scaling, interpolation, overlays, or retouching.

The captured production `main.cc` had SHA-256
`06e1691e47b46b36a81e1f76688e3f849a6bbee1c4e2b4776a89db8faa9919fd`.
The exact extracted `draw()` include has SHA-256
`d4ed7d000374b392bedefc93f516a95f9d82b740c915769666b559d2abff38a7`.
The production font, BB20, and key-level headers are preserved beside the harness
and have SHA-256 values recorded below.

| Capture input | SHA-256 |
| --- | --- |
| `glcdfont.h` | `bd6d60ecb9cc350a83f209d7c62de2fe5f6ce3402d5598cde2988b5b44e83e02` |
| `bollinger_bands.h` | `43732fa011093af0ba34256133798c199d69e4b533d49a610ddd18d07603eb55` |
| `key_levels.h` | `aceb891059eb3d38be3fafc76b77d165e4dce40c9c4bc527c6b8d1ffd1ec8de5` |
| Public market snapshot | `e0ff0f441ce90b8fdea4d489ccced353e72ac298ef52fee334c2b1610aaa72ff` |

## Data and privacy

The market snapshot was captured at `2026-08-01T18:18:38Z` from Coinbase
Exchange's unauthenticated public ticker and candle endpoints. It contains 36
hourly OHLCV candles for BTC-USD, SOL-USD, XLM-USD, HYPE-USD, and ETH-USD. The
support and resistance candidates are daily high/low extrema from the same
public API. The immutable input is
[`capture-market-data.json`](images/capture-market-data.json).

No authenticated API response, credential, account balance, position, order,
device identifier, host, or network address entered the harness. Privacy mode is
active in all three frames. The positions page therefore exercises the
production renderer's own account-value obfuscation path (`********`) rather
than applying a redaction after capture.

## Frame checksums

| PNG | Raw RGB565 SHA-256 | PNG SHA-256 |
| --- | --- | --- |
| `prices-page.png` | `c8080cbda06bdb3f4686b1757842f2d6da92644bbfb21675b5c7581c63fcefd0` | `9799cd887d8061c20258fd3236de3282349f807d5cb6f23343ae717ce6214c02` |
| `positions-privacy-page.png` | `a0278b89ab494a91733ce5564b885f5770e4e74f9b56f3e287768d30f4b9932e` | `c744f95f8d12d53d88de4803b63ad0a93cc369bddabc8a8dd8d49615ed50304b` |
| `btc-chart-bb20-levels.png` | `d516f410d50a12e5e0640de3615570741f21510d92ad87c8a35632370abf89c9` | `ec55c7c7a66dd69776b4ffd9d80afa12dfbd1b76e54a1b1cb1c85b8ff16d0ae9` |

Each PNG is exactly 368 × 448, uses truecolor RGB at 8 bits per channel, and
contains only the required `IHDR`, `IDAT`, and `IEND` chunks. There are no text,
time, EXIF, ICC, or other metadata chunks.

## Reproduce

A C++17 compiler and Python 3.11 or newer are sufficient:

```bash
python3 tools/framebuffer_capture/capture.py \
  --data docs/images/capture-market-data.json \
  --output-dir docs/images
```

The renderer snapshot is intentionally isolated as documentation capture tooling.
It does not alter production controls or device hardware.
