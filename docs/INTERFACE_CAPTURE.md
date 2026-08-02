# Interface Capture Provenance

The gallery images are **not mockups**. They are lossless conversions of raw
368 × 448 RGB565 frames emitted by the current production firmware renderer on
2026-08-02.

## Capture method

1. The production renderer's gallery-page `draw()` paths are mirrored in
   `tools/framebuffer_capture/production_draw.inc`. The setup-only path is
   inactive and is not part of this gallery evidence.
2. Its RGB565 palette, pixel, line, rectangle, bitmap-font, BB20, key-level, and
   page-layout code run in the host harness in
   `tools/framebuffer_capture/renderer_capture.cc`.
3. Only hardware boundaries are replaced: the setup portal reports inactive,
   feed health reports current, bridge-local display time is fixed to the
   synthetic value `09:41 PM`, and `flush_frame()` writes the framebuffer to a
   raw file instead of transmitting it to the AMOLED panel.
4. `tools/framebuffer_capture/capture.py` converts those raw RGB565 bytes to RGB
   PNG without scaling, interpolation, overlays, or retouching.

The captured production `main.cc` has SHA-256
`290171f2dd94ff71eed190efa5e74de4977a39d63e860ef4b9d2b45de712cf16`.
The mirrored `draw()` include has SHA-256
`2836da3f7aa036d3b799030e0fe079537edb57b90f10f158eaa69ee4b6a33e32`.
The production font, BB20, and key-level headers are preserved beside the harness
and have SHA-256 values recorded below.

| Capture input | SHA-256 |
| --- | --- |
| `renderer_capture.cc` | `5bf6c1f21e10a71e6c52d0c31d80ee09bfe81492920bf959b348eda50ef84923` |
| `capture.py` | `a04097d0b0548b1450c060fe99eded91cd364c98386b59977a74621f87dcc085` |
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
device identifier, host, network address, or host clock entered the harness.
Privacy mode is active in all three frames. The positions page therefore
exercises the production renderer's own account-value obfuscation path
(`********`) rather than applying a redaction after capture. The immutable public
snapshot and fixed synthetic display time make every frame deterministic.

## Frame checksums

| PNG | Raw RGB565 SHA-256 | PNG SHA-256 |
| --- | --- | --- |
| `prices-page.png` | `13cbe2461cf449f785a41c18a2e648b39f5f0a36290d4d87d5fa4cd0b98d4f55` | `ce56c40c3c8e231f513e8a4206dc4cf14603e02e3bb0adfa449cf9ce655fd92d` |
| `positions-privacy-page.png` | `d5c2468c2d99ecc72acc741a38381617b394c6df82414e34e9037838a224a489` | `466ef924068f61fdfb2714dd097f3efee2d0eb83f2d4e7251376321b72511322` |
| `btc-chart-bb20-levels.png` | `2e47b3a27ff190b3d7813dce5a227a44d4e4e9823756bb0769162eca86e5df11` | `fc5efcbbf3c704c16ad4d2e1486fcd97fdf87fb069f8259255a50d70d9eed592` |

The versioned `*-v2.0.0.png` files used by the README are byte-identical copies
of the corresponding generated files above, and the reproduction check verifies
both sets. Each PNG is exactly 368 × 448, uses truecolor RGB at 8 bits per
channel, and contains only the required `IHDR`, `IDAT`, and `IEND` chunks. There
are no text, time, EXIF, ICC, or other metadata chunks.

## Reproduce

A C++17 compiler and Python 3.11 or newer are sufficient:

```bash
python3 tools/framebuffer_capture/capture.py \
  --data docs/images/capture-market-data.json \
  --output-dir docs/images
```

The renderer snapshot is intentionally isolated as documentation capture tooling.
It does not alter production controls or device hardware.
