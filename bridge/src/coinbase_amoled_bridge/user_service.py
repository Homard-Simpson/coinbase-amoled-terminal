"""Best-effort control of the installer-created per-user service."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

LAUNCHD_LABEL = "com.homardsimpson.coinbase-amoled-bridge"
SYSTEMD_UNIT = "coinbase-amoled-bridge.service"
SERVICE_TIMEOUT_SECONDS = 15


@dataclass(frozen=True, slots=True)
class ServiceStartResult:
    status: Literal["started", "unavailable", "failed"]
    manager: Literal["launchd", "systemd", "none"]
    was_active: bool = False
    loaded_by_quickstart: bool = False
    was_enabled: bool = False

    @property
    def started(self) -> bool:
        return self.status == "started"


def _home(environ: Mapping[str, str]) -> Path:
    value = environ.get("HOME")
    return Path(value).expanduser() if value else Path.home()


def _run(command: list[str]) -> int | None:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=SERVICE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed.returncode


ServiceStateObserver = Callable[[ServiceStartResult], None]


def _start_launchd(
    environ: Mapping[str, str],
    before_change: ServiceStateObserver | None = None,
) -> ServiceStartResult:
    launchctl = shutil.which("launchctl")
    plist = _home(environ) / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
    if launchctl is None or not plist.is_file():
        return ServiceStartResult("unavailable", "none")
    domain = f"gui/{os.getuid()}"
    target = f"{domain}/{LAUNCHD_LABEL}"
    print_status = _run([launchctl, "print", target])
    if print_status is None:
        return ServiceStartResult("failed", "launchd")
    was_active = print_status == 0
    loaded_by_quickstart = False
    if before_change is not None:
        before_change(
            ServiceStartResult(
                "started" if was_active else "unavailable",
                "launchd",
                was_active=was_active,
                loaded_by_quickstart=not was_active,
            )
        )
    if not was_active:
        bootstrap_status = _run([launchctl, "bootstrap", domain, str(plist)])
        if bootstrap_status != 0:
            return ServiceStartResult(
                "failed", "launchd", was_active=False, loaded_by_quickstart=True
            )
        loaded_by_quickstart = True
    if _run([launchctl, "kickstart", "-k", target]) != 0:
        # Preserve the prior state in the result. The transaction owner must
        # restore/stop the service only after it has restored prior credentials.
        return ServiceStartResult(
            "failed",
            "launchd",
            was_active=was_active,
            loaded_by_quickstart=loaded_by_quickstart,
        )
    return ServiceStartResult(
        "started",
        "launchd",
        was_active=was_active,
        loaded_by_quickstart=loaded_by_quickstart,
    )


def _systemd_unit_path(environ: Mapping[str, str]) -> Path:
    config_home = environ.get("XDG_CONFIG_HOME")
    base = Path(config_home).expanduser() if config_home else _home(environ) / ".config"
    return base / "systemd" / "user" / SYSTEMD_UNIT


def _start_systemd(
    environ: Mapping[str, str],
    before_change: ServiceStateObserver | None = None,
) -> ServiceStartResult:
    systemctl = shutil.which("systemctl")
    if systemctl is None or not _systemd_unit_path(environ).is_file():
        return ServiceStartResult("unavailable", "none")
    active_status = _run([systemctl, "--user", "is-active", "--quiet", SYSTEMD_UNIT])
    if active_status is None:
        return ServiceStartResult("failed", "systemd")
    was_active = active_status == 0
    enabled_status = _run([systemctl, "--user", "is-enabled", "--quiet", SYSTEMD_UNIT])
    if enabled_status is None:
        return ServiceStartResult("failed", "systemd", was_active=was_active)
    was_enabled = enabled_status == 0
    if before_change is not None:
        before_change(
            ServiceStartResult(
                "started" if was_active else "unavailable",
                "systemd",
                was_active=was_active,
                was_enabled=was_enabled,
            )
        )
    if _run([systemctl, "--user", "daemon-reload"]) != 0:
        return ServiceStartResult(
            "failed",
            "systemd",
            was_active=was_active,
            was_enabled=was_enabled,
        )
    if was_active:
        if _run([systemctl, "--user", "restart", SYSTEMD_UNIT]) != 0:
            return ServiceStartResult(
                "failed", "systemd", was_active=True, was_enabled=was_enabled
            )
    elif _run([systemctl, "--user", "enable", "--now", SYSTEMD_UNIT]) != 0:
        return ServiceStartResult(
            "failed", "systemd", was_active=False, was_enabled=was_enabled
        )
    return ServiceStartResult(
        "started",
        "systemd",
        was_active=was_active,
        was_enabled=was_enabled,
    )


def start_user_service(
    *,
    environ: Mapping[str, str] | None = None,
    system: str | None = None,
    before_change: ServiceStateObserver | None = None,
) -> ServiceStartResult:
    """Start the installed unit without invoking a shell or exposing secrets."""

    env = dict(os.environ if environ is None else environ)
    current_system = platform.system() if system is None else system
    if current_system == "Darwin":
        return _start_launchd(env, before_change)
    if current_system == "Linux":
        return _start_systemd(env, before_change)
    return ServiceStartResult("unavailable", "none")


def rollback_user_service(result: ServiceStartResult) -> bool:
    """Stop a service that was inactive before setup; report any failure."""

    if result.manager == "none" or result.was_active:
        return True
    if result.manager == "launchd":
        if not result.loaded_by_quickstart:
            return True
        launchctl = shutil.which("launchctl")
        if launchctl is None:
            return False
        domain = f"gui/{os.getuid()}"
        target = f"{domain}/{LAUNCHD_LABEL}"
        loaded_status = _run([launchctl, "print", target])
        if loaded_status is None:
            return False
        if loaded_status != 0:
            return True
        plist = (
            Path(os.environ.get("HOME", str(Path.home()))).expanduser()
            / "Library"
            / "LaunchAgents"
            / f"{LAUNCHD_LABEL}.plist"
        )
        return _run([launchctl, "bootout", domain, str(plist)]) == 0
    elif result.manager == "systemd":
        systemctl = shutil.which("systemctl")
        if systemctl is None:
            return False
        if result.was_enabled:
            stopped = _run([systemctl, "--user", "stop", SYSTEMD_UNIT]) == 0
            enabled = _run([systemctl, "--user", "enable", SYSTEMD_UNIT]) == 0
            return stopped and enabled
        return _run([systemctl, "--user", "disable", "--now", SYSTEMD_UNIT]) == 0
    return False


def restore_user_service(result: ServiceStartResult) -> bool:
    """Re-establish a service that was active before a failed restart."""

    if not result.was_active:
        return True
    if result.manager == "launchd":
        launchctl = shutil.which("launchctl")
        if launchctl is None:
            return False
        target = f"gui/{os.getuid()}/{LAUNCHD_LABEL}"
        return _run([launchctl, "kickstart", "-k", target]) == 0
    if result.manager == "systemd":
        systemctl = shutil.which("systemctl")
        if systemctl is None:
            return False
        return _run([systemctl, "--user", "restart", SYSTEMD_UNIT]) == 0
    return False
