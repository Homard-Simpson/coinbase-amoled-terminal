#!/usr/bin/env python3
"""Local end-to-end smoke test; uses only synthetic data and temporary secrets."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def request(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    method: str = "GET",
) -> tuple[int, bytes]:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        raise ValueError("smoke requests are restricted to local HTTP")
    value = urllib.request.Request(  # noqa: S310 - validated loopback URL above
        url, headers=headers or {}, method=method
    )
    try:
        with urllib.request.urlopen(  # noqa: S310 - validated loopback URL above
            value, timeout=2
        ) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, exc.read()
        finally:
            exc.close()


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def main() -> int:
    smoke_parent = ROOT / "data"
    smoke_parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    smoke_root = Path(tempfile.mkdtemp(prefix=".smoke-", dir=smoke_parent))
    command = [
        sys.executable,
        "-m",
        "coinbase_amoled_bridge",
        "--data-dir",
        str(smoke_root),
    ]
    process: subprocess.Popen[str] | None = None
    try:
        setup = subprocess.run(  # noqa: S603 - fixed interpreter and arguments
            [*command, "setup", "--sample", "--non-interactive"],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
            timeout=15,
        )
        config = json.loads((smoke_root / "config.json").read_text())
        device_id = next(iter(config["devices"]))
        token_path = smoke_root / "secrets" / "devices" / f"{device_id}.token"
        token = token_path.read_text().strip()
        if token in setup.stdout or token in (smoke_root / "config.json").read_text():
            raise RuntimeError("setup exposed a raw device token")

        port = free_port()
        process = subprocess.Popen(  # noqa: S603 - fixed interpreter and arguments
            [*command, "serve", "--sample", "--host", "127.0.0.1", "--port", str(port)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        base = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 10
        health_status = 0
        while time.monotonic() < deadline:
            if process.poll() is not None:
                _, stderr = process.communicate(timeout=1)
                raise RuntimeError(f"service exited during startup: {stderr[-500:]}")
            try:
                health_status, _ = request(base + "/healthz")
                if health_status == 200:
                    break
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.1)
        if health_status != 200:
            raise RuntimeError("health endpoint did not become ready")

        headers = {
            "X-Device-ID": device_id,
            "Authorization": f"Bearer {token}",
        }
        feed_status, raw_feed = request(base + "/v1/device-feed", headers=headers)
        feed = json.loads(raw_feed)
        if feed_status != 200 or feed.get("read_only") is not True:
            raise RuntimeError("authenticated feed failed")
        if feed.get("mode") != "sample" or len(feed.get("symbols", [])) != 5:
            raise RuntimeError("sample feed shape failed")
        if any(
            len(market.get("candles", [])) != 30 for market in feed["markets"].values()
        ):
            raise RuntimeError("sample candles failed")
        serialized = json.dumps(feed)
        if token in serialized or device_id in serialized:
            raise RuntimeError("feed exposed device credentials")
        mutation_status, _ = request(base + "/v1/device-feed", method="POST")
        if mutation_status != 405:
            raise RuntimeError("mutation method was not rejected")

        print(
            "SMOKE_OK health=200 feed=200 mutation=405 "
            "symbols=5 candles_per_symbol=30 read_only=true"
        )
        return 0
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        shutil.rmtree(smoke_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
