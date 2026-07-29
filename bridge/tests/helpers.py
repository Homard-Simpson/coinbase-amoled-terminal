from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from coinbase_amoled_bridge.auth import Credentials, JWTSigner


def make_credentials() -> tuple[Credentials, ec.EllipticCurvePrivateKey]:
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    credentials = Credentials(
        key_name="organizations/example/apiKeys/test-key",
        private_key_pem=pem,
        source="test",
    )
    return credentials, key


def make_signer() -> JWTSigner:
    credentials, _ = make_credentials()
    return JWTSigner(credentials)


def decode_segment(value: str) -> dict[str, Any]:
    padded = value + "=" * (-len(value) % 4)
    return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))


def candles(count: int = 40, *, start: int = 1_700_000_000) -> list[dict[str, str]]:
    return [
        {
            "start": str(start + index * 60),
            "open": str(100 + index),
            "high": str(102 + index),
            "low": str(99 + index),
            "close": str(101 + index),
            "volume": str(10 + index),
        }
        for index in range(count)
    ]
