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
    PENDING_REJECTION_GRACE_SECONDS,
    OnboardingCoordinator,
    create_onboarding_server,
    create_pending_claim_server,
)
from firmware_installer import (
    EsptoolRunner,
    FirmwareInstallError,
    SetupMetadata,
    build_setup_partition,
    detect_serial_port,
    download_variant,
    installed_source_commit,
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
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path != "/v1/device-feed"
    ):
        raise FirmwareInstallError(
            "automated onboarding needs this computer's local HTTP /v1/device-feed URL"
        )
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
    bridge_url = _validate_bridge_url(
        args.bridge_url or f"http://{_private_lan_address()}:{DEFAULT_FEED_PORT}/v1/device-feed"
    )
    coordinator = OnboardingCoordinator(
        args.data_dir,
        bridge_url=bridge_url,
        pending_ttl_seconds=args.session_seconds,
    )
    recovered = coordinator.pending_provisioning()
    claim_bridge_url = recovered.bridge_url if recovered is not None else bridge_url
    pending_server = create_pending_claim_server(
        coordinator,
        bridge_url=claim_bridge_url,
    )
    pending_thread = threading.Thread(
        target=pending_server.serve_forever,
        kwargs={"poll_interval": 0.1},
        name="esp-pending-claim",
        daemon=True,
    )
    pending_thread.start()
    pending_running = True
    server = None
    server_thread = None
    session = None
    finalized = False

    def stop_pending_listener() -> None:
        nonlocal pending_running
        if not pending_running:
            return
        pending_server.shutdown()
        pending_server.server_close()
        pending_thread.join(timeout=3.0)
        if pending_thread.is_alive():
            raise ProvisioningError("pending claim listener did not stop")
        pending_running = False

    try:
        provisioning = recovered
        if provisioning is None:
            manifest_url = (
                args.manifest_url if args.manifest_url else official_manifest_url(args.version)
            )
            manifest = load_manifest(
                manifest_url,
                expected_release_version=args.version,
                expected_source_commit=(
                    None
                    if args.allow_unverified_test_artifacts
                    else installed_source_commit(Path(__file__).resolve().parents[1])
                ),
                allow_test_url=args.allow_unverified_test_artifacts,
            )
            board = select_board(
                manifest,
                requested=args.board,
                interactive=not args.non_interactive,
            )
            port = args.port or detect_serial_port()
            runner = EsptoolRunner(python=sys.executable, port=port)
            require_release_readiness(
                manifest,
                board=board,
                allow_unverified_test_artifacts=args.allow_unverified_test_artifacts,
            )
            print(f"Using the explicit {board.upper()} physical-board selection.")
            server = create_onboarding_server(
                coordinator,
                ttl_seconds=args.session_seconds,
                on_staged=pending_server.app.set_pending,
            )
            session = server.app.session
            server_thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.1},
                name="localhost-onboarding",
                daemon=True,
            )
            server_thread.start()
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

            print("Firmware installed. NVS and unrelated device data were not erased.")
            print("Join the Wi-Fi name shown on the display and press Finish once.")
            timeout = max(0.0, session.monotonic_deadline - time.monotonic())
            if not session.provisioned_event.wait(timeout=timeout):
                raise FirmwareInstallError(
                    "the one-time localhost credential staging session expired"
                )
            provisioning = session.safe_provisioning()
            if provisioning is None:
                raise FirmwareInstallError("local credential staging was unavailable")
        else:
            pending_server.app.set_pending(provisioning)
            print("Recovered the display's inactive pending setup; waiting for its claim.")

        claim_timeout = max(0.0, provisioning.expires_at - time.time())
        if not pending_server.app.claimed_event.wait(timeout=claim_timeout):
            pending_server.app.set_status("rejected")
            coordinator.rollback_pending()
            raise FirmwareInstallError("pending display setup expired before it was claimed")

        try:
            coordinator.finish_pending(
                provisioning,
                status_callback=pending_server.app.set_status,
                before_service_start=stop_pending_listener,
            )
        except Exception as exc:
            if pending_running:
                pending_server.app.set_status("rejected")
                pending_server.app.terminal_event.wait(timeout=PENDING_REJECTION_GRACE_SECONDS)
            raise FirmwareInstallError(
                "the claimed setup was rejected or could not activate safely"
            ) from exc
        if session is not None:
            session.mark_finished()
        finalized = True
        print("Setup complete. The key stayed on this computer; the display is ready.")
        return 0
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if server_thread is not None:
            server_thread.join(timeout=2.0)
        if pending_running:
            stop_pending_listener()
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
