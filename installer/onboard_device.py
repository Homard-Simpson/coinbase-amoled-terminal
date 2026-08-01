#!/usr/bin/env python3
"""Flash one display and keep its one-time localhost setup endpoint alive."""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

from coinbase_amoled_bridge.errors import ProvisioningError
from coinbase_amoled_bridge.onboarding import (
    OnboardingCoordinator,
    create_onboarding_server,
)
from firmware_installer import (
    EsptoolRunner,
    FirmwareInstallError,
    SetupMetadata,
    build_setup_partition,
    detect_serial_port,
    download_variant,
    load_manifest,
    official_manifest_url,
    require_release_readiness,
    select_board,
)

DEFAULT_FEED_PORT = 8788


def _private_lan_address() -> str:
    override = os.environ.get("CBAT_INSTALLER_LAN_IP", "").strip()
    if override:
        candidates = [override]
    else:
        candidates: list[str] = []
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                connection.connect(("192.0.2.1", 9))
                candidates.append(str(connection.getsockname()[0]))
        except OSError:
            pass
        try:
            candidates.extend(socket.gethostbyname_ex(socket.gethostname())[2])
        except OSError:
            pass
    for value in candidates:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        in_tailnet = address in ipaddress.ip_network("100.64.0.0/10")
        if (
            isinstance(address, ipaddress.IPv4Address)
            and not address.is_loopback
            and not address.is_unspecified
            and not address.is_link_local
            and (address.is_private or in_tailnet)
        ):
            return str(address)
    raise FirmwareInstallError("a private LAN address could not be determined; pass --bridge-url")


def _validate_bridge_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path != "/v1/device-feed"
    ):
        raise FirmwareInstallError("bridge URL must end at /v1/device-feed")
    if parsed.scheme == "http":
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            local_name = "." not in parsed.hostname or parsed.hostname.endswith(
                (".local", ".lan", ".home.arpa", ".internal")
            )
            if not local_name:
                raise FirmwareInstallError("plain HTTP bridge URL must be local") from None
        else:
            in_tailnet = address in ipaddress.ip_network("100.64.0.0/10")
            if not (address.is_private or address.is_loopback or in_tailnet):
                raise FirmwareInstallError("plain HTTP bridge URL must be private")
    return value


def _write_private(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--version")
    source.add_argument("--manifest-url")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--port")
    parser.add_argument("--board", choices=("v1", "v2"))
    parser.add_argument("--bridge-url")
    parser.add_argument("--allow-unverified-test-artifacts", action="store_true")
    parser.add_argument("--no-open", action="store_true")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--session-seconds", type=int, default=900)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    manifest_url = args.manifest_url if args.manifest_url else official_manifest_url(args.version)
    manifest = load_manifest(
        manifest_url,
        allow_test_url=args.allow_unverified_test_artifacts,
    )
    port = args.port or detect_serial_port()
    runner = EsptoolRunner(python=sys.executable, port=port)

    print("Checking the connected display without probing its panel hardware…")
    board = select_board(
        manifest,
        runner.read_flash,
        requested=args.board,
        interactive=not args.non_interactive,
    )
    require_release_readiness(
        manifest,
        board=board,
        allow_unverified_test_artifacts=args.allow_unverified_test_artifacts,
    )
    print(f"Using the verified {board.upper()} firmware path.")

    bridge_url = _validate_bridge_url(
        args.bridge_url or f"http://{_private_lan_address()}:{DEFAULT_FEED_PORT}/v1/device-feed"
    )
    coordinator = OnboardingCoordinator(args.data_dir, bridge_url=bridge_url)
    server = create_onboarding_server(
        coordinator,
        ttl_seconds=args.session_seconds,
    )
    session = server.app.session
    server_thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.1},
        name="localhost-onboarding",
        daemon=True,
    )
    server_thread.start()
    finalized = False

    try:
        with tempfile.TemporaryDirectory(prefix="cbat-firmware-") as temporary_name:
            temporary = Path(temporary_name)
            artifacts = download_variant(
                manifest,
                board,
                temporary / "artifacts",
                allow_test_url=args.allow_unverified_test_artifacts,
            )
            metadata = SetupMetadata(
                session_id=session.session_id,
                setup_token=session.setup_token,
                completion_token=session.completion_token,
                csrf_token=session.csrf_token,
                endpoint_url=session.endpoint_url,
                local_page_url=session.local_page_url,
                bridge_url=bridge_url,
                expires_at=session.expires_at,
            )
            setup_path = temporary / "onboarding.bin"
            _write_private(setup_path, build_setup_partition(metadata))
            print("Checksums passed. Flashing firmware and one-time setup metadata…")
            runner.flash(artifacts, setup_path)

        print("Firmware installed. NVS and any unrelated device data were not erased.")
        print("Join the Wi-Fi name shown on the display, then press Finish in its portal.")
        print("If the captive window blocks localhost, use its same-computer fallback link.")

        timeout = max(0.0, session.monotonic_deadline - time.monotonic())
        session.terminal_event.wait(timeout=timeout)
        if session.finished_event.is_set():
            finalized = True
            print("Setup complete. The key stayed on this computer; the display is restarting.")
            return 0
        if session.failed_event.is_set():
            raise FirmwareInstallError(
                "the display saved setup, but the local transaction failed closed"
            )
        if session.provisioned_event.is_set():
            raise FirmwareInstallError(
                "the bridge is ready, but the display did not confirm its final save"
            )
        raise FirmwareInstallError("the one-time setup session expired; rerun the installer")
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2.0)
        if not finalized:
            try:
                coordinator.rollback_pending()
            except ProvisioningError as exc:
                raise FirmwareInstallError(
                    "incomplete local setup could not be rolled back"
                ) from exc
            finally:
                coordinator.close()
        else:
            coordinator.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FirmwareInstallError as exc:
        print(f"install error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
