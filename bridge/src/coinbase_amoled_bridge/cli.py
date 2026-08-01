"""Local setup/admin CLI and service entry point."""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import shlex
import signal
import socket
import sys
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__
from .auth import (
    Credentials,
    DeviceManager,
    DeviceProvision,
    DeviceRegistry,
    JWTSigner,
    prompt_key_name,
    save_local_credentials,
)
from .coinbase import CoinbaseClient
from .config import ConfigStore
from .errors import BridgeError, ConfigError, CredentialError
from .feed import FeedService, SampleFeedService
from .logging_utils import configure_logging, log_event
from .quickstart import prompt_for_cdp_key
from .server import BridgeApplication, create_server
from .symbols import normalize_symbols
from .user_service import (
    ServiceStartResult,
    rollback_user_service,
    start_user_service,
)
from .util import is_loopback_host, parse_bool

DEFAULT_DATA_DIR = "~/.config/coinbase-amoled-bridge"
DEFAULT_BRIDGE_PORT = 8788


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="coinbase-amoled-bridge",
        description=(
            "Read-only device bridge for an unofficial Coinbase AMOLED terminal"
        ),
    )
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("BRIDGE_DATA_DIR", DEFAULT_DATA_DIR),
        help="configuration/state directory (default: %(default)s)",
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    setup = commands.add_parser("setup", help="initialize config and local secrets")
    setup.add_argument(
        "--sample", action="store_true", help="skip Coinbase credentials"
    )
    setup.add_argument("--non-interactive", action="store_true")
    setup.add_argument("--key-name-file")
    setup.add_argument("--private-key-file")
    setup.add_argument("--replace-credentials", action="store_true")
    setup.add_argument("--device-id")
    setup.add_argument("--label", default="")
    setup.add_argument("--token-file")
    setup.add_argument("--no-device", action="store_true")
    setup.add_argument(
        "--symbols",
        default=",".join(("BTC", "SOL", "XLM", "HYPE", "ETH")),
        help="comma-separated base symbols or USD products",
    )

    quickstart = commands.add_parser(
        "quickstart",
        help="secure one-prompt setup, safety check, and service start",
    )
    quickstart.add_argument(
        "--sample",
        action="store_true",
        help="use offline sample data without Coinbase credentials",
    )

    serve = commands.add_parser("serve", help="run the HTTP bridge")
    serve.add_argument("--sample", action="store_true")
    serve.add_argument("--host", default=os.environ.get("BRIDGE_HOST", "127.0.0.1"))
    serve.add_argument(
        "--port", type=int, default=int(os.environ.get("BRIDGE_PORT", "8788"))
    )
    serve.add_argument("--tls-cert", default=os.environ.get("BRIDGE_TLS_CERT"))
    serve.add_argument("--tls-key", default=os.environ.get("BRIDGE_TLS_KEY"))
    serve.add_argument(
        "--allow-insecure-public-bind",
        action="store_true",
        default=_environment_bool("BRIDGE_ALLOW_INSECURE_PUBLIC_BIND", False),
        help="explicitly allow plain HTTP on a non-loopback interface",
    )
    serve.add_argument(
        "--log-level", default=os.environ.get("BRIDGE_LOG_LEVEL", "INFO")
    )

    doctor = commands.add_parser(
        "doctor", help="validate local config and live key safety"
    )
    doctor.add_argument("--sample", action="store_true")

    device = commands.add_parser("device", help="manage the device allowlist")
    device_commands = device.add_subparsers(dest="device_command", required=True)
    device_add = device_commands.add_parser("add")
    device_add.add_argument("--device-id")
    device_add.add_argument("--label", default="")
    device_add.add_argument("--token-file")
    device_commands.add_parser("list")
    device_revoke = device_commands.add_parser("revoke")
    device_revoke.add_argument("device_id")
    device_enable = device_commands.add_parser("enable")
    device_enable.add_argument("device_id")
    device_rotate = device_commands.add_parser("rotate")
    device_rotate.add_argument("device_id")
    device_rotate.add_argument("--token-file")
    device_rotate.add_argument(
        "--replace-token-file",
        action="store_true",
        help="allow replacing an existing custom token-file path",
    )

    symbols = commands.add_parser("symbols", help="show or change market symbols")
    symbol_commands = symbols.add_subparsers(dest="symbols_command", required=True)
    symbol_commands.add_parser("list")
    symbol_set = symbol_commands.add_parser("set")
    symbol_set.add_argument(
        "values", help="comma-separated base symbols or USD products"
    )
    return parser


def _environment_bool(name: str, default: bool) -> bool:
    try:
        return parse_bool(os.environ.get(name), default=default)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a boolean") from exc


def _sample_requested(flag: bool) -> bool:
    try:
        return flag or parse_bool(os.environ.get("BRIDGE_SAMPLE_MODE"), default=False)
    except ValueError as exc:
        raise ConfigError("BRIDGE_SAMPLE_MODE must be a boolean") from exc


def _read_bounded(path_value: str, maximum: int) -> bytes:
    path = Path(path_value).expanduser()
    try:
        if (
            not path.is_file()
            or path.stat().st_size <= 0
            or path.stat().st_size > maximum
        ):
            raise CredentialError("credential input file has an invalid size or type")
        return path.read_bytes()
    except CredentialError:
        raise
    except OSError as exc:
        raise CredentialError("unable to read credential input file") from exc


def _set_symbols(store: ConfigStore, raw: str) -> list[str]:
    values = [value.strip() for value in raw.split(",") if value.strip()]
    normalized = normalize_symbols(values, quote_currency="USD")
    symbols = [item.symbol for item in normalized]

    def mutate(config: dict[str, Any]) -> None:
        config["settings"]["symbols"] = symbols

    store.update(mutate)
    return symbols


def command_setup(args: argparse.Namespace, store: ConfigStore) -> int:
    config = store.initialize()
    symbols = _set_symbols(store, args.symbols)
    if not args.sample:
        supplied_files = bool(args.key_name_file or args.private_key_file)
        if supplied_files and not (args.key_name_file and args.private_key_file):
            raise CredentialError(
                "both --key-name-file and --private-key-file are required"
            )
        if supplied_files:
            try:
                key_name = (
                    _read_bounded(args.key_name_file, 2_048).decode("utf-8").strip()
                )
            except UnicodeDecodeError as exc:
                raise CredentialError("API key name file must be UTF-8") from exc
            private_key = _read_bounded(args.private_key_file, 65_536)
            save_local_credentials(
                store.data_dir,
                key_name=key_name,
                private_key_pem=private_key,
                replace=args.replace_credentials,
            )
        elif not args.non_interactive:
            key_name = prompt_key_name()
            private_path = input("Path to downloaded ECDSA private-key PEM: ").strip()
            if not private_path:
                raise CredentialError("private-key path is required")
            private_key = _read_bounded(private_path, 65_536)
            save_local_credentials(
                store.data_dir,
                key_name=key_name,
                private_key_pem=private_key,
                replace=args.replace_credentials,
            )

    provision = None
    existing_devices = config.get("devices", {})
    should_add_device = not args.no_device and (
        bool(args.device_id or args.token_file or args.label) or not existing_devices
    )
    if should_add_device:
        provision = DeviceManager(store).add(
            device_id=args.device_id,
            label=args.label,
            token_path=args.token_file,
        )

    print("Setup complete (read-only bridge).")
    print(f"Config file: {store.path}")
    print("Symbols: " + ", ".join(symbols))
    if args.sample:
        print("Mode prepared: sample/offline (no Coinbase credentials used).")
    elif args.non_interactive and not supplied_files:
        print(
            "Credentials not stored; provide environment or file/Docker secrets "
            "at runtime."
        )
    else:
        print("Coinbase credentials stored in private files; values were not printed.")
    if provision:
        print(f"Device ID: {provision.device_id}")
        print(f"Bearer token saved mode 0600: {provision.token_path}")
        print(
            "The bearer token value was not printed. Transfer the file securely "
            "to the device."
        )
    elif not existing_devices and args.no_device:
        print("No device added; /v1/device-feed will deny all device requests.")
    return 0


@dataclass(slots=True)
class _QuickstartChanges:
    config_existed: bool
    original_config: dict[str, Any] | None
    config_initialized: bool = False
    credential_paths: tuple[Path, Path] | None = None
    provision: DeviceProvision | None = None

    @property
    def changed(self) -> bool:
        return bool(
            (self.config_initialized and not self.config_existed)
            or self.credential_paths
            or self.provision
        )


def _local_credentials_if_present(store: ConfigStore) -> Credentials | None:
    secrets_dir = store.data_dir / "secrets"
    bundle_path = secrets_dir / "coinbase_credentials"
    name_path = secrets_dir / "coinbase_api_key_name"
    private_path = secrets_dir / "coinbase_api_private_key"
    if bundle_path.is_file():
        return Credentials.load_local(store.data_dir)
    if name_path.is_file() != private_path.is_file():
        raise CredentialError(
            "local Coinbase credential files are incomplete; restore or remove the pair"
        )
    if not name_path.is_file():
        return None
    return Credentials.load_local(store.data_dir)


def _assert_live_key_is_view_only(
    credentials: Credentials, timeout: float = 8.0
) -> None:
    CoinbaseClient(JWTSigner(credentials), timeout=timeout).assert_view_only()


def _existing_quickstart_device(
    store: ConfigStore, config: dict[str, Any]
) -> DeviceProvision | None:
    for device_id, record in sorted(config["devices"].items()):
        token_path = store.data_dir / "secrets" / "devices" / f"{device_id}.token"
        if record["enabled"] and token_path.is_file():
            return DeviceProvision(device_id=device_id, token_path=token_path)
    return None


def _rollback_quickstart(store: ConfigStore, changes: _QuickstartChanges) -> None:
    if changes.config_existed and changes.original_config is not None:
        store.replace(changes.original_config)
    elif changes.config_initialized:
        try:
            store.path.unlink(missing_ok=True)
            store.lock_path.unlink(missing_ok=True)
        except OSError:
            pass
    if changes.provision is not None:
        try:
            changes.provision.token_path.unlink(missing_ok=True)
        except OSError:
            pass
    if changes.credential_paths is not None:
        for path in changes.credential_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
    for path in (
        store.data_dir / "secrets" / "devices",
        store.data_dir / "secrets",
        store.data_dir,
    ):
        try:
            path.rmdir()
        except OSError:
            pass


def _manual_service_command(store: ConfigStore, *, sample: bool) -> str:
    command = [
        sys.executable,
        "-m",
        "coinbase_amoled_bridge",
        "--data-dir",
        str(store.data_dir),
        "serve",
        "--host",
        "0.0.0.0",
        "--allow-insecure-public-bind",
    ]
    if sample:
        command.append("--sample")
    return shlex.join(command)


def _lan_feed_url() -> str:
    address = ""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.connect(("192.0.2.1", 9))
            address = str(connection.getsockname()[0])
        parsed = ipaddress.ip_address(address)
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_global:
            address = ""
    except (OSError, ValueError):
        address = ""
    host = address or "<this-computer's-LAN-IP>"
    return f"http://{host}:{DEFAULT_BRIDGE_PORT}/v1/device-feed"


def _print_quickstart_result(
    store: ConfigStore,
    provision: DeviceProvision,
    service: ServiceStartResult,
    *,
    sample: bool,
) -> None:
    print("Quickstart complete: read-only safety checks passed.")
    if sample:
        print("Mode: sample/offline; no Coinbase account was contacted.")
    if service.started:
        print("Background service: running.")
    else:
        reason = (
            "could not be started"
            if service.status == "failed"
            else "manager is unavailable"
        )
        print(f"Background service {reason}; run this command in a terminal:")
        print(_manual_service_command(store, sample=sample))
    print("\nPair your display:")
    print(f"Bridge feed URL: {_lan_feed_url()}")
    print(f"Device ID: {provision.device_id}")
    print(f"Device token file (mode 0600): {provision.token_path}")
    print(
        "Enter those values in the display pairing screen; the token was not printed."
    )
    print("Use this trusted-LAN URL only on a network you control.")


def command_quickstart(args: argparse.Namespace, store: ConfigStore) -> int:
    sample = _sample_requested(args.sample)
    config_existed = store.exists()
    original_config = store.load() if config_existed else None
    changes = _QuickstartChanges(config_existed, original_config)
    service = ServiceStartResult("unavailable", "none")

    credentials = None if sample else _local_credentials_if_present(store)
    if not sample and credentials is None:
        credentials = prompt_for_cdp_key()
    if credentials is not None:
        # Validate /key_permissions before writing any newly pasted credential.
        _assert_live_key_is_view_only(credentials)

    try:
        config = store.initialize()
        changes.config_initialized = True
        if credentials is not None and _local_credentials_if_present(store) is None:
            changes.credential_paths = save_local_credentials(
                store.data_dir,
                key_name=credentials.key_name,
                private_key_pem=credentials.private_key_pem,
            )

        provision = _existing_quickstart_device(store, config)
        if provision is None:
            provision = DeviceManager(store).add(label="AMOLED terminal")
            changes.provision = provision

        service = start_user_service()
        command_doctor(argparse.Namespace(sample=sample, local_only=True), store)
    except BaseException:
        if changes.changed:
            rollback_user_service(service)
            _rollback_quickstart(store, changes)
        raise

    _print_quickstart_result(store, provision, service, sample=sample)
    return 0


def command_device(args: argparse.Namespace, store: ConfigStore) -> int:
    manager = DeviceManager(store)
    if args.device_command == "add":
        provision = manager.add(
            device_id=args.device_id, label=args.label, token_path=args.token_file
        )
        print(f"Device ID: {provision.device_id}")
        print(f"Bearer token saved mode 0600: {provision.token_path}")
        print("The bearer token value was not printed.")
    elif args.device_command == "list":
        print(json.dumps(manager.list_public(), indent=2, sort_keys=True))
    elif args.device_command == "revoke":
        manager.set_enabled(args.device_id, False)
        print(f"Revoked device: {args.device_id}")
    elif args.device_command == "enable":
        manager.set_enabled(args.device_id, True)
        print(f"Enabled device: {args.device_id}")
    elif args.device_command == "rotate":
        provision = manager.rotate(
            args.device_id,
            token_path=args.token_file,
            replace_token_file=args.replace_token_file,
        )
        print(f"Rotated device: {provision.device_id}")
        print(f"New bearer token saved mode 0600: {provision.token_path}")
        print("The bearer token value was not printed; the prior token is invalid.")
    else:  # pragma: no cover - argparse prevents this
        raise ConfigError("unknown device command")
    return 0


def command_symbols(args: argparse.Namespace, store: ConfigStore) -> int:
    if args.symbols_command == "list":
        config = store.load()
        print("\n".join(config["settings"]["symbols"]))
    elif args.symbols_command == "set":
        symbols = _set_symbols(store, args.values)
        print("Symbols: " + ", ".join(symbols))
        print("Restart the service to apply market changes.")
    return 0


def command_doctor(args: argparse.Namespace, store: ConfigStore) -> int:
    config = store.load()
    enabled = [record for record in config["devices"].values() if record["enabled"]]
    if not enabled:
        raise ConfigError("no enabled device is allowlisted")
    if _sample_requested(args.sample):
        SampleFeedService(config["settings"]).get_feed()
        print("OK: config, allowlist, and sample feed are valid; read_only=true.")
        return 0
    credentials = (
        Credentials.load_local(store.data_dir)
        if getattr(args, "local_only", False)
        else Credentials.load(store.data_dir)
    )
    client = CoinbaseClient(
        JWTSigner(credentials),
        timeout=float(config["settings"]["upstream_timeout_seconds"]),
    )
    client.assert_view_only()
    first = normalize_symbols(config["settings"]["symbols"])[0]
    client.get_product(first.product_id)
    print("OK: config valid; Coinbase key is view-only; read-only GET check passed.")
    return 0


def command_serve(args: argparse.Namespace, store: ConfigStore) -> int:
    config = store.load()
    if not any(record["enabled"] for record in config["devices"].values()):
        raise ConfigError("at least one enabled device is required before serving")
    sample = _sample_requested(args.sample)
    if not 1 <= args.port <= 65_535:
        raise ConfigError("port must be in [1, 65535]")
    tls_enabled = bool(args.tls_cert and args.tls_key)
    if bool(args.tls_cert) != bool(args.tls_key):
        raise ConfigError("both --tls-cert and --tls-key are required")
    if (
        not is_loopback_host(args.host)
        and not tls_enabled
        and not args.allow_insecure_public_bind
    ):
        raise ConfigError(
            "plain HTTP public bind refused; configure TLS or explicitly use "
            "--allow-insecure-public-bind behind a trusted TLS reverse proxy"
        )

    if sample:
        feed_service = SampleFeedService(config["settings"])
        mode = "sample"
    else:
        credentials = Credentials.load(store.data_dir)
        client = CoinbaseClient(
            JWTSigner(credentials),
            timeout=float(config["settings"]["upstream_timeout_seconds"]),
        )
        # Mandatory safety gate: a trade- or transfer-capable key prevents bind.
        client.assert_view_only()
        feed_service = FeedService(client, config["settings"])
        mode = "live"

    registry = DeviceRegistry(store)
    app = BridgeApplication.from_settings(
        feed_service, registry, mode, config["settings"]
    )
    configure_logging(args.log_level)
    try:
        server = create_server(
            args.host,
            args.port,
            app,
            tls_cert=args.tls_cert,
            tls_key=args.tls_key,
        )
    except OSError as exc:
        raise ConfigError("unable to bind HTTP listener") from exc
    actual_port = int(server.server_address[1])
    logger = logging.getLogger("coinbase_amoled_bridge")
    log_event(
        logger,
        "service_started",
        mode=mode,
        port=actual_port,
        tls=tls_enabled,
        read_only=True,
    )

    shutdown_started = threading.Event()

    def request_shutdown(signum: int, frame: Any) -> None:
        if shutdown_started.is_set():
            return
        shutdown_started.set()
        threading.Thread(target=server.shutdown, name="shutdown", daemon=True).start()

    previous_handlers: dict[int, Any] = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        try:
            previous_handlers[signum] = signal.signal(signum, request_shutdown)
        except ValueError:
            pass
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        log_event(logger, "service_stopped", mode=mode, read_only=True)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        store = ConfigStore(args.data_dir)
        if args.command == "setup":
            return command_setup(args, store)
        if args.command == "quickstart":
            return command_quickstart(args, store)
        if args.command == "serve":
            return command_serve(args, store)
        if args.command == "doctor":
            return command_doctor(args, store)
        if args.command == "device":
            return command_device(args, store)
        if args.command == "symbols":
            return command_symbols(args, store)
        parser.error("unknown command")
    except (BridgeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    return 2
