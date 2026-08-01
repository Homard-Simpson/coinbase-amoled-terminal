from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"
RENDERER_PATH = ROOT / "installer" / "render_service.py"
LAUNCHD_TEMPLATE = ROOT / "installer" / "com.homardsimpson.coinbase-amoled-bridge.plist.in"
SYSTEMD_TEMPLATE = ROOT / "installer" / "coinbase-amoled-bridge.service.in"
SPEC = importlib.util.spec_from_file_location("service_renderer", RENDERER_PATH)
assert SPEC is not None and SPEC.loader is not None
RENDERER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RENDERER)


class ServiceTemplateTests(unittest.TestCase):
    def test_launchd_template_escapes_paths_and_renders_sample_mode(self) -> None:
        executable = '/opt/example/App & Tools/<bridge>"/bin/bridge'
        data_dir = "/opt/example/Config & State/<private>"
        rendered = RENDERER.render_launchd(
            LAUNCHD_TEMPLATE.read_text(encoding="utf-8"),
            executable=executable,
            data_dir=data_dir,
            sample=True,
        )
        root = ET.fromstring(rendered)  # noqa: S314 - fixed local template output
        arguments = [element.text for element in root.findall(".//array/string")]
        self.assertEqual(
            arguments,
            [
                executable,
                "--data-dir",
                data_dir,
                "serve",
                "--host",
                "0.0.0.0",  # noqa: S104 - intentional trusted-LAN service
                "--allow-insecure-public-bind",
                "--sample",
            ],
        )
        self.assertNotIn("@", rendered)

    def test_systemd_template_quotes_spaces_quotes_backslashes_and_percent(self) -> None:
        executable = '/opt/example/App % 100/bridge"tool'
        data_dir = "/opt/example/state path/with\\slash"
        rendered = RENDERER.render_systemd(
            SYSTEMD_TEMPLATE.read_text(encoding="utf-8"),
            executable=executable,
            data_dir=data_dir,
            sample=False,
        )
        exec_line = next(line for line in rendered.splitlines() if line.startswith("ExecStart="))
        self.assertIn('"/opt/example/App %% 100/bridge\\"tool"', exec_line)
        self.assertIn('"/opt/example/state path/with\\\\slash"', exec_line)
        self.assertNotIn("--sample", exec_line)
        self.assertNotIn("@EXECUTABLE", rendered)
        self.assertNotIn("@DATA_DIR", rendered)

    def test_renderer_rejects_relative_or_control_character_paths(self) -> None:
        template = SYSTEMD_TEMPLATE.read_text(encoding="utf-8")
        for executable, data_dir in (
            ("relative/bin", "/absolute/data"),
            ("/absolute/bin", "relative/data"),
            ("/absolute/bin\nother", "/absolute/data"),
        ):
            with self.subTest(executable=executable), self.assertRaises(ValueError):
                RENDERER.render_systemd(
                    template,
                    executable=executable,
                    data_dir=data_dir,
                    sample=False,
                )


class InstallerTests(unittest.TestCase):
    def _write_executable(self, path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def _fake_environment(
        self, temporary: Path, *, system: str = "Linux"
    ) -> tuple[dict[str, str], Path, Path]:
        fake_bin = temporary / "fake-bin"
        fake_bin.mkdir()
        home = temporary / "home"
        home.mkdir()
        invocation_log = temporary / "invocations.log"

        self._write_executable(
            fake_bin / "uname",
            f"#!/usr/bin/env bash\nprintf '%s\\n' '{system}'\n",
        )
        self._write_executable(
            fake_bin / "git",
            """#!/usr/bin/env bash
set -euo pipefail
while [[ "${1:-}" == "-c" ]]; do
  shift 2
done
if [[ "${1:-}" == "clone" ]]; then
  destination="${@: -1}"
  mkdir -p "$destination"
  cp -R "$INSTALL_TEST_SOURCE/installer" "$destination/installer"
  mkdir -p "$destination/.git"
  exit 0
fi
if [[ "${1:-}" == "-C" ]]; then
  shift 2
fi
case "${1:-}" in
  config) printf '%s\\n' 'https://github.com/Homard-Simpson/coinbase-amoled-terminal.git' ;;
  symbolic-ref) printf '%s\\n' 'main' ;;
  status) : ;;
  fetch) : ;;
  rev-parse) printf '%s\\n' '1111111111111111111111111111111111111111' ;;
  merge-base) : ;;
  merge) : ;;
  *) printf 'unexpected fake git call: %s\\n' "$*" >&2; exit 90 ;;
esac
""",
        )
        self._write_executable(
            fake_bin / "python3",
            """#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-c" ]]; then
  exec "$REAL_PYTHON" "$@"
fi
if [[ "${1:-}" == "-m" && "${2:-}" == "venv" ]]; then
  target="${3:?missing venv target}"
  mkdir -p "$target/bin"
  cat > "$target/bin/python" <<'PYTHON_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-m" && "${2:-}" == "pip" ]]; then
  exit 0
fi
exec "$REAL_PYTHON" "$@"
PYTHON_WRAPPER
  cat > "$target/bin/coinbase-amoled-bridge" <<'CLI_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$INSTALL_TEST_LOG"
CLI_WRAPPER
  chmod 755 "$target/bin/python" "$target/bin/coinbase-amoled-bridge"
  exit 0
fi
printf 'unexpected fake python call: %s\\n' "$*" >&2
exit 91
""",
        )
        self._write_executable(
            fake_bin / "systemctl",
            '#!/usr/bin/env bash\nprintf \'systemctl %s\\n\' "$*" >> "$INSTALL_TEST_LOG"\n',
        )

        environment = dict(os.environ)
        environment.update(
            {
                "HOME": str(home),
                "XDG_DATA_HOME": str(temporary / "data home"),
                "XDG_CONFIG_HOME": str(temporary / "config home"),
                "PATH": os.pathsep.join((str(fake_bin), environment["PATH"])),
                "REAL_PYTHON": sys.executable,
                "INSTALL_TEST_SOURCE": str(ROOT),
                "INSTALL_TEST_LOG": str(invocation_log),
            }
        )
        return environment, home, invocation_log

    def test_shell_syntax_and_static_security_invariants(self) -> None:
        subprocess.run(["/bin/bash", "-n", str(INSTALLER)], check=True)
        script = INSTALLER.read_text(encoding="utf-8")
        self.assertIn(
            'readonly REPOSITORY_URL="https://github.com/Homard-Simpson/'
            'coinbase-amoled-terminal.git"',
            script,
        )
        self.assertIn('readonly REPOSITORY_BRANCH="main"', script)
        self.assertNotIn("eval ", script)
        self.assertNotRegex(script, r"(?m)^\s*sudo\b")
        self.assertNotIn("curl ", script)
        self.assertNotIn("COINBASE_API_PRIVATE_KEY=", script)
        self.assertIn("quickstart_arguments=(--data-dir", script)
        self.assertIn("GitHub download failed", script)
        self.assertIn("-m pip --isolated install", script)
        self.assertIn("--index-url https://pypi.org/simple", script)

    def test_readme_frontloads_exact_two_step_command_before_screenshots(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        command = (
            "curl -fsSL https://raw.githubusercontent.com/Homard-Simpson/"
            "coinbase-amoled-terminal/main/install.sh | bash"
        )
        self.assertEqual(readme.count("## Step 1\n"), 1)
        self.assertEqual(readme.count("## Step 2\n"), 1)
        self.assertIn(command, readme)
        self.assertLess(readme.index("## Step 1"), readme.index("## Step 2"))
        self.assertLess(readme.index("## Step 2"), readme.index("## Actual interface"))

    def test_offline_sample_install_is_idempotent_and_uninstalls_safely(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            environment, home, invocation_log = self._fake_environment(temporary)
            for _ in range(2):
                completed = subprocess.run(
                    ["/bin/bash", str(INSTALLER), "--sample"],
                    check=False,
                    text=True,
                    capture_output=True,
                    env=environment,
                    timeout=30,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("No Docker or administrator access was used", completed.stdout)

            install_root = temporary / "data home" / "coinbase-amoled-terminal"
            state_dir = temporary / "config home" / "coinbase-amoled-bridge"
            unit = temporary / "config home" / "systemd" / "user" / "coinbase-amoled-bridge.service"
            self.assertTrue((install_root / "source" / ".git").is_dir())
            self.assertTrue(unit.is_file())
            unit_text = unit.read_text(encoding="utf-8")
            self.assertIn("--sample", unit_text)
            self.assertNotIn("@EXECUTABLE", unit_text)
            invocations = invocation_log.read_text(encoding="utf-8").splitlines()
            quickstarts = [line for line in invocations if " quickstart" in line]
            self.assertEqual(len(quickstarts), 2)
            self.assertTrue(all(line.endswith("quickstart --sample") for line in quickstarts))

            state_dir.mkdir(parents=True)
            marker = state_dir / "preserved-state"
            marker.write_text("keep", encoding="utf-8")
            removed = subprocess.run(
                ["/bin/bash", str(INSTALLER), "--uninstall"],
                check=False,
                text=True,
                capture_output=True,
                env=environment,
                timeout=30,
            )
            self.assertEqual(removed.returncode, 0, removed.stderr)
            self.assertFalse(install_root.exists())
            self.assertTrue(marker.is_file())
            user_command = home / ".local" / "bin" / "coinbase-amoled-bridge"
            self.assertFalse(user_command.exists())

            purged = subprocess.run(
                ["/bin/bash", str(INSTALLER), "--uninstall", "--purge"],
                check=False,
                text=True,
                capture_output=True,
                env=environment,
                timeout=30,
            )
            self.assertEqual(purged.returncode, 0, purged.stderr)
            self.assertFalse(state_dir.exists())

    def test_offline_macos_sample_install_renders_launch_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            environment, home, invocation_log = self._fake_environment(temporary, system="Darwin")
            completed = subprocess.run(
                ["/bin/bash", str(INSTALLER), "--sample"],
                check=False,
                text=True,
                capture_output=True,
                env=environment,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            plist = (
                home / "Library" / "LaunchAgents" / "com.homardsimpson.coinbase-amoled-bridge.plist"
            )
            self.assertTrue(plist.is_file())
            plist_text = plist.read_text(encoding="utf-8")
            self.assertIn("--sample", plist_text)
            self.assertIn("Library/Application Support", plist_text)
            self.assertNotIn("@SAMPLE_ARG", plist_text)
            self.assertIn("quickstart --sample", invocation_log.read_text())

    def test_clone_http_failure_is_clear_and_does_not_install_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            environment, _, _ = self._fake_environment(temporary)
            failing_git = temporary / "fake-bin" / "git"
            self._write_executable(
                failing_git,
                "#!/usr/bin/env bash\nprintf 'simulated HTTP failure\\n' >&2\nexit 9\n",
            )
            completed = subprocess.run(
                ["/bin/bash", str(INSTALLER), "--sample"],
                check=False,
                text=True,
                capture_output=True,
                env=environment,
                timeout=30,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("GitHub download failed", completed.stderr)
            source = temporary / "data home" / "coinbase-amoled-terminal" / "source"
            self.assertFalse(source.exists())


if __name__ == "__main__":
    unittest.main()
