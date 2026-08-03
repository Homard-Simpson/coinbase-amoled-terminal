# Interface Capture Provenance

The gallery images are **not mockups**. They are lossless conversions of raw
368 × 448 RGB565 frames emitted by the current production firmware renderer on
2026-08-03.

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
`08dc92ac17a97c8dd1862ad6367e136d2df69653202122c5db043280b0dd30ba`.
The mirrored `draw()` include has SHA-256
`f160866b0eb06059025c412cda25a3ae45340c48bc463260fc007cb6400ddbaa`.
The production UI helper is imported directly by the harness; its font, BB20,
and key-level mirrors are retained with the capture source. Their SHA-256 values
are recorded below.

| Capture input | SHA-256 |
| --- | --- |
| `renderer_capture.cc` | `5bf6c1f21e10a71e6c52d0c31d80ee09bfe81492920bf959b348eda50ef84923` |
| `capture.py` | `a04097d0b0548b1450c060fe99eded91cd364c98386b59977a74621f87dcc085` |
| `ui_helpers.h` | `353cc81a399ba4a6151917f5d1a5a85d751c2b90232c8da85fee844c59e7cf8f` |
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
| `prices-page.png` | `7808a75a581dfccd0c025f28278f9f1b77544bcc1134b586d9379dc3650fb86b` | `cd99d4d58dd2752c26c75a0295d7648ae3896fb6d1d7ad082406ffee539c56a4` |
| `positions-privacy-page.png` | `3069827e4a86148a37ad81caa4a016c6b7eef0c0e5b43bb65cbef17869428e35` | `4ba610fad706c4338a33463554d14a3cb436c39377e32b72b11854b91e849ec8` |
| `btc-chart-bb20-levels.png` | `3bf6a4c7392097242ffa9ac8907b99aac0611cc1c7f9d21a2ab1a4d9e289ff0c` | `ac0794f7d239cf2d4479707dc64efed67c3992b1719ff61beaee9a542a4d72d7` |

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
