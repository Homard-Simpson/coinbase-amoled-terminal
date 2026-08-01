from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from coinbase_amoled_bridge.user_service import (
    LAUNCHD_LABEL,
    SYSTEMD_UNIT,
    ServiceStartResult,
    rollback_user_service,
    start_user_service,
)


class UserServiceTests(unittest.TestCase):
    def test_systemd_unit_is_enabled_and_started_without_a_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config_home = Path(temporary) / "config with spaces"
            unit = config_home / "systemd" / "user" / SYSTEMD_UNIT
            unit.parent.mkdir(parents=True)
            unit.write_text("placeholder", encoding="utf-8")
            with (
                mock.patch(
                    "coinbase_amoled_bridge.user_service.shutil.which",
                    return_value="/bin/systemctl",
                ),
                mock.patch(
                    "coinbase_amoled_bridge.user_service._run",
                    side_effect=(1, 0, 0),
                ) as run,
            ):
                result = start_user_service(
                    environ={"HOME": temporary, "XDG_CONFIG_HOME": str(config_home)},
                    system="Linux",
                )
        self.assertEqual(result, ServiceStartResult("started", "systemd"))
        self.assertEqual(
            run.call_args_list,
            [
                mock.call(
                    [
                        "/bin/systemctl",
                        "--user",
                        "is-active",
                        "--quiet",
                        SYSTEMD_UNIT,
                    ]
                ),
                mock.call(["/bin/systemctl", "--user", "daemon-reload"]),
                mock.call(
                    [
                        "/bin/systemctl",
                        "--user",
                        "enable",
                        "--now",
                        SYSTEMD_UNIT,
                    ]
                ),
            ],
        )

    def test_launchd_bootstraps_then_kickstarts_installed_plist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plist = (
                Path(temporary) / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"
            )
            plist.parent.mkdir(parents=True)
            plist.write_text("placeholder", encoding="utf-8")
            with (
                mock.patch(
                    "coinbase_amoled_bridge.user_service.shutil.which",
                    return_value="/bin/launchctl",
                ),
                mock.patch(
                    "coinbase_amoled_bridge.user_service.os.getuid", return_value=501
                ),
                mock.patch(
                    "coinbase_amoled_bridge.user_service._run",
                    side_effect=(1, 0, 0),
                ) as run,
            ):
                result = start_user_service(
                    environ={"HOME": temporary}, system="Darwin"
                )
        self.assertTrue(result.started)
        self.assertTrue(result.loaded_by_quickstart)
        self.assertEqual(
            run.call_args_list,
            [
                mock.call(
                    [
                        "/bin/launchctl",
                        "print",
                        f"gui/501/{LAUNCHD_LABEL}",
                    ]
                ),
                mock.call(
                    [
                        "/bin/launchctl",
                        "bootstrap",
                        "gui/501",
                        str(plist),
                    ]
                ),
                mock.call(
                    [
                        "/bin/launchctl",
                        "kickstart",
                        "-k",
                        f"gui/501/{LAUNCHD_LABEL}",
                    ]
                ),
            ],
        )

    def test_missing_unit_or_manager_returns_safe_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch(
                "coinbase_amoled_bridge.user_service.shutil.which", return_value=None
            ):
                for system in ("Darwin", "Linux", "Other"):
                    with self.subTest(system=system):
                        result = start_user_service(
                            environ={"HOME": temporary}, system=system
                        )
                        self.assertEqual(result.status, "unavailable")
                        self.assertFalse(result.started)

    def test_new_or_partially_started_systemd_service_is_disabled_on_rollback(
        self,
    ) -> None:
        for status in ("started", "failed"):
            with (
                self.subTest(status=status),
                mock.patch(
                    "coinbase_amoled_bridge.user_service.shutil.which",
                    return_value="/bin/systemctl",
                ),
                mock.patch("coinbase_amoled_bridge.user_service._run") as run,
            ):
                rollback_user_service(ServiceStartResult(status, "systemd"))
                run.assert_called_once_with(
                    [
                        "/bin/systemctl",
                        "--user",
                        "disable",
                        "--now",
                        SYSTEMD_UNIT,
                    ]
                )

    def test_previously_active_service_is_not_stopped_on_rollback(self) -> None:
        with mock.patch("coinbase_amoled_bridge.user_service._run") as run:
            rollback_user_service(
                ServiceStartResult("started", "systemd", was_active=True)
            )
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
