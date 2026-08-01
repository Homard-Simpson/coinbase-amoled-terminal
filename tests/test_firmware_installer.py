from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "installer" / "firmware_installer.py"
SPEC = importlib.util.spec_from_file_location("firmware_installer", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
FIRMWARE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FIRMWARE
SPEC.loader.exec_module(FIRMWARE)

GENERATOR_PATH = ROOT / "scripts" / "generate-release-manifest.py"
GENERATOR_SPEC = importlib.util.spec_from_file_location("generate_release_manifest", GENERATOR_PATH)
assert GENERATOR_SPEC is not None and GENERATOR_SPEC.loader is not None
GENERATOR = importlib.util.module_from_spec(GENERATOR_SPEC)
sys.modules[GENERATOR_SPEC.name] = GENERATOR
GENERATOR_SPEC.loader.exec_module(GENERATOR)


def synthetic_esp_image(data: bytes, *, load_address: int) -> bytes:
    header = bytearray(24)
    header[0] = FIRMWARE.ESP_IMAGE_MAGIC
    header[1] = 1
    header[2] = 0x02
    header[3] = 0x4F
    struct.pack_into("<H", header, 12, FIRMWARE.ESP_IMAGE_CHIP_ESP32S3)
    header[23] = 1
    payload = bytearray(header)
    payload.extend(struct.pack("<II", load_address, len(data)))
    payload.extend(data)
    checksum = 0xEF
    for value in data:
        checksum ^= value
    hashed_end = (len(payload) + 1 + 15) & ~15
    payload.extend(b"\0" * (hashed_end - 1 - len(payload)))
    payload.append(checksum)
    payload.extend(hashlib.sha256(payload).digest())
    return bytes(payload)


def synthetic_application(board: str, *, release: str = "1.2.3") -> bytes:
    segment = bytearray(b"\xff" * 2048)
    struct.pack_into("<I", segment, 0, FIRMWARE.ESP_APP_DESC_MAGIC)
    for offset, value in (
        (16, f"{release}-{board}"),
        (48, "coinbase_amoled_terminal"),
        (112, "v5.5.2"),
    ):
        encoded = value.encode("ascii") + b"\0"
        segment[offset : offset + len(encoded)] = encoded
    return synthetic_esp_image(bytes(segment), load_address=0x3C000020)


def synthetic_bootloader(board: str) -> bytes:
    return synthetic_esp_image((f"boot-{board}-".encode("ascii") * 180), load_address=0x3FCE2820)


def synthetic_partition_table(
    overrides: dict[str, tuple[int, int, int, int]] | None = None,
) -> bytes:
    entries = dict(FIRMWARE.EXPECTED_PARTITIONS)
    entries.update(overrides or {})
    payload = bytearray()
    for label, (entry_type, subtype, offset, size) in entries.items():
        label_bytes = label.encode("ascii") + b"\0" * (16 - len(label))
        payload.extend(
            struct.pack("<HBBII16sI", 0x50AA, entry_type, subtype, offset, size, label_bytes, 0)
        )
    digest = hashlib.md5(payload, usedforsecurity=False).digest()
    payload.extend(struct.pack("<H", 0xEBEB) + b"\xff" * 14 + digest)
    payload.extend(b"\xff" * (0xC00 - len(payload)))
    return bytes(payload)


def release_fixture(
    root: Path,
    *,
    version: str = "v1.2.3",
) -> tuple[Path, dict[str, bytes], str]:
    blobs: dict[str, bytes] = {}
    variants: dict[str, object] = {}
    release = version.removeprefix("v")
    for board in ("v1", "v2"):
        board_dir = root / board
        board_dir.mkdir(parents=True, exist_ok=True)
        role_payloads = {
            "bootloader": synthetic_bootloader(board),
            "partition_table": synthetic_partition_table(),
            "ota_data": b"\xff" * 0x2000,
            "application": synthetic_application(board, release=release),
        }
        artifacts = []
        for role, offset in FIRMWARE.EXPECTED_OFFSETS.items():
            payload = role_payloads[role]
            path = board_dir / f"{role}.bin"
            path.write_bytes(payload)
            blobs[f"{board}:{role}"] = payload
            artifacts.append(
                {
                    "role": role,
                    "path": f"{board}/{role}.bin",
                    "offset": offset,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
        variants[board] = {
            "board_revision": board,
            "firmware_version": f"{release}-{board}",
            "artifacts": artifacts,
            "onboarding_partition": {
                "offset": FIRMWARE.ONBOARDING_OFFSET,
                "size": FIRMWARE.ONBOARDING_SIZE,
            },
        }
    manifest: dict[str, object] = {
        "schema_version": FIRMWARE.MANIFEST_SCHEMA_VERSION,
        "release_version": version,
        "build": {
            "esp_idf_version": FIRMWARE.ESP_IDF_VERSION,
            "container_image": FIRMWARE.ESP_IDF_CONTAINER_IMAGE,
            "container_digest": FIRMWARE.ESP_IDF_CONTAINER_DIGEST,
        },
        "release_evidence": {
            "production_ready": False,
            "controls_verified": False,
            "client_signature_verified": False,
            "hardware_attested": {"v1": False, "v2": False},
            "trust_blocker": GENERATOR.TRUST_BLOCKER,
        },
        "variants": variants,
    }
    manifest["manifest_id"] = FIRMWARE.compute_manifest_id(manifest)
    path = root / "firmware-manifest.json"
    path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return path, blobs, digest


def rewrite_manifest(path: Path, mutate) -> dict[str, object]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    mutate(raw)
    raw["manifest_id"] = FIRMWARE.compute_manifest_id(raw)
    path.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")
    return raw


class ManifestTrustTests(unittest.TestCase):
    def test_manifest_and_every_artifact_receive_semantic_and_sha256_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path, blobs, digest = release_fixture(root)
            manifest = FIRMWARE.load_manifest(
                path.as_uri(),
                expected_release_version="v1.2.3",
                expected_manifest_sha256=digest,
                allow_test_url=True,
            )
            downloaded = FIRMWARE.download_variant(
                manifest, "v2", root / "downloads", allow_test_url=True
            )
            self.assertEqual(
                {item.artifact.role for item in downloaded},
                set(FIRMWARE.EXPECTED_OFFSETS),
            )
            self.assertEqual(manifest.manifest_sha256, digest)
            self.assertEqual(
                {key.split(":")[1] for key in blobs if key.startswith("v2:")},
                set(FIRMWARE.EXPECTED_OFFSETS),
            )
            with self.assertRaisesRegex(
                FIRMWARE.FirmwareInstallError,
                "client-side signature verification",
            ):
                FIRMWARE.require_release_readiness(
                    manifest,
                    board="v2",
                    allow_unverified_test_artifacts=False,
                )
            FIRMWARE.require_release_readiness(
                manifest,
                board="v2",
                allow_unverified_test_artifacts=True,
            )

    def test_manifest_tamper_external_digest_and_canonical_identity_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path, _blobs, digest = release_fixture(root)
            raw = json.loads(path.read_text())
            raw["release_version"] = "v1.2.4"
            path.write_text(json.dumps(raw))
            with self.assertRaisesRegex(FIRMWARE.FirmwareInstallError, "identity"):
                FIRMWARE.load_manifest(
                    path.as_uri(),
                    expected_release_version="v1.2.3",
                    expected_manifest_sha256=digest,
                    allow_test_url=True,
                )

            path, _blobs, _digest = release_fixture(root)
            raw = json.loads(path.read_text())
            raw["variants"]["v1"]["firmware_version"] = "1.2.3-v2"
            path.write_text(json.dumps(raw))
            with self.assertRaisesRegex(FIRMWARE.FirmwareInstallError, "canonical identity"):
                FIRMWARE.load_manifest(path.as_uri(), allow_test_url=True)

    def test_release_version_binding_and_mutable_main_url_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path, _blobs, digest = release_fixture(Path(temporary))
            with self.assertRaisesRegex(FIRMWARE.FirmwareInstallError, "release version"):
                FIRMWARE.load_manifest(
                    path.as_uri(),
                    expected_release_version="v9.9.9",
                    expected_manifest_sha256=digest,
                    allow_test_url=True,
                )
        mutable = (
            "https://raw.githubusercontent.com/Homard-Simpson/"
            "coinbase-amoled-terminal/main/firmware-manifest.json"
        )
        with self.assertRaises(FIRMWARE.FirmwareInstallError):
            FIRMWARE.load_manifest(
                mutable,
                expected_release_version="v1.2.3",
                expected_manifest_sha256="0" * 64,
            )
        with self.assertRaisesRegex(FIRMWARE.FirmwareInstallError, "SHA-256"):
            FIRMWARE.load_manifest(
                FIRMWARE.official_manifest_url("v1.2.3"),
                expected_release_version="v1.2.3",
            )

    def test_oversize_timeout_redirect_and_unsafe_query_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "large.bin"
            path.write_bytes(b"x" * 33)
            with self.assertRaisesRegex(FIRMWARE.FirmwareInstallError, "size"):
                FIRMWARE._read_url(path.as_uri(), maximum=32, allow_test_url=True)

        handler = FIRMWARE._TrustedRedirectHandler(frozenset({"downloads.example.invalid"}))
        request = FIRMWARE.urllib.request.Request("https://downloads.example.invalid/release.bin")
        with self.assertRaisesRegex(FIRMWARE.FirmwareInstallError, "untrusted"):
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "https://evil.example.invalid/substituted.bin",
            )
        with self.assertRaises(FIRMWARE.FirmwareInstallError):
            FIRMWARE._read_url(
                "https://downloads.example.invalid/release.bin?mutable=1",
                maximum=32,
                allow_test_url=True,
            )

        class FakeResponse:
            headers = {"Content-Length": "1"}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def geturl(self):
                return "https://downloads.example.invalid/release.bin"

            def read(self, _size):
                return b"x"

        opener = mock.Mock()
        opener.open.return_value = FakeResponse()
        clock = mock.Mock(side_effect=(0.0, FIRMWARE.DOWNLOAD_TOTAL_TIMEOUT_SECONDS + 1))
        with self.assertRaisesRegex(FIRMWARE.FirmwareInstallError, "time limit"):
            FIRMWARE._read_url(
                "https://downloads.example.invalid/release.bin",
                maximum=32,
                allow_test_url=True,
                opener=opener,
                clock=clock,
            )

    def test_overlap_wrong_board_and_all_binary_semantics_fail_closed(self) -> None:
        artifacts = (
            FIRMWARE.Artifact("ota_data", "ota.bin", 0x10000, 0x2000, "0" * 64),
            FIRMWARE.Artifact("application", "app.bin", 0x11000, 0x2000, "0" * 64),
        )
        with self.assertRaisesRegex(FIRMWARE.FirmwareInstallError, "overlap"):
            FIRMWARE._validate_flash_layout(
                artifacts,
                onboarding_offset=FIRMWARE.ONBOARDING_OFFSET,
                onboarding_size=FIRMWARE.ONBOARDING_SIZE,
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path, blobs, _digest = release_fixture(root)
            wrong = blobs["v1:application"]
            (root / "v2" / "application.bin").write_bytes(wrong)

            def swap_app(raw):
                app = next(
                    item
                    for item in raw["variants"]["v2"]["artifacts"]
                    if item["role"] == "application"
                )
                app["size"] = len(wrong)
                app["sha256"] = hashlib.sha256(wrong).hexdigest()

            rewrite_manifest(path, swap_app)
            manifest = FIRMWARE.load_manifest(path.as_uri(), allow_test_url=True)
            with self.assertRaisesRegex(FIRMWARE.FirmwareInstallError, "metadata"):
                FIRMWARE.download_variant(
                    manifest,
                    "v2",
                    root / "wrong-board",
                    allow_test_url=True,
                )

        valid = {
            "bootloader": synthetic_bootloader("v1"),
            "partition_table": synthetic_partition_table(),
            "ota_data": b"\xff" * 0x2000,
            "application": synthetic_application("v1"),
        }
        for role, payload in valid.items():
            damaged = bytearray(payload)
            damaged[len(damaged) // 2] ^= 1
            with self.subTest(role=role), self.assertRaises(FIRMWARE.FirmwareInstallError):
                FIRMWARE.validate_release_artifact_payload(
                    role,
                    bytes(damaged),
                    firmware_version="1.2.3-v1",
                )

    def test_binary_secret_scan_rejects_real_key_blocks_and_private_hosts(self) -> None:
        private_key = (
            b"-----BEGIN "
            + b"PRIVATE KEY-----\n"
            + b"Q" * 128
            + b"\n-----END "
            + b"PRIVATE KEY-----"
        )
        with self.assertRaises(FIRMWARE.FirmwareInstallError):
            FIRMWARE.scan_release_artifact_for_secrets(private_key)
        private_host = b"bridge.personal-" + b"tailnet.ts.net"
        with self.assertRaises(FIRMWARE.FirmwareInstallError):
            FIRMWARE.scan_release_artifact_for_secrets(private_host)
        FIRMWARE.scan_release_artifact_for_secrets(synthetic_application("v1"))


class BoardSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        path, _blobs, _digest = release_fixture(Path(self.temporary.name))
        self.manifest = FIRMWARE.load_manifest(path.as_uri(), allow_test_url=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_explicit_v1_and_v2_never_read_application_identity(self) -> None:
        reader = mock.Mock(side_effect=AssertionError("application identity must not be read"))
        self.assertEqual(
            FIRMWARE.select_board(self.manifest, reader, requested="v1"),
            "v1",
        )
        self.assertEqual(
            FIRMWARE.select_board(self.manifest, reader, requested="v2"),
            "v2",
        )
        reader.assert_not_called()

    def test_corrective_explicit_selection_is_never_blocked_by_installed_image(self) -> None:
        installed_v2_reader = mock.Mock(return_value=synthetic_application("v2"))
        selected = FIRMWARE.select_board(
            self.manifest,
            installed_v2_reader,
            requested="v1",
        )
        self.assertEqual(selected, "v1")
        installed_v2_reader.assert_not_called()

    def test_unknown_ambiguous_and_friendly_prompt_fail_closed(self) -> None:
        with self.assertRaises(FIRMWARE.FirmwareInstallError):
            FIRMWARE.select_board(self.manifest, requested="unknown")
        with self.assertRaisesRegex(FIRMWARE.FirmwareInstallError, "explicit --board"):
            FIRMWARE.select_board(self.manifest, interactive=False)
        for answer, expected in (("1", "v1"), ("v2", "v2")):
            input_fn = mock.Mock(return_value=answer)
            self.assertEqual(
                FIRMWARE.select_board(self.manifest, input_fn=input_fn),
                expected,
            )
            self.assertIn(FIRMWARE.BOARD_HELP_URL, input_fn.call_args.args[0])
        with self.assertRaisesRegex(FIRMWARE.FirmwareInstallError, "nothing was flashed"):
            FIRMWARE.select_board(self.manifest, input_fn=mock.Mock(return_value="maybe"))


class IsolatedEsptoolTests(unittest.TestCase):
    def test_clean_temporary_venv_executes_esptool_from_exact_venv_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            venv = root / "isolated-venv"
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=60)
            python = venv / "bin" / "python"
            purelib = Path(
                subprocess.check_output(
                    [
                        str(python),
                        "-I",
                        "-c",
                        "import sysconfig;print(sysconfig.get_path('purelib'))",
                    ],
                    text=True,
                    timeout=30,
                ).strip()
            )
            package = purelib / "esptool"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "__main__.py").write_text(
                "import json, os, sys\n"
                "from pathlib import Path\n"
                "args=sys.argv[1:]\n"
                "Path(os.environ['ESPTOOL_VENV_PROBE']).write_text("
                "json.dumps({'executable':sys.executable,'prefix':sys.prefix}))\n"
                "index=args.index('read_flash')\n"
                "size=int(args[index+2],0)\n"
                "Path(args[index+3]).write_bytes(b'\\xff'*size)\n",
                encoding="utf-8",
            )
            subprocess.run(
                [str(python), "-I", "-c", "import esptool"],
                check=True,
                timeout=30,
            )
            probe = root / "probe.json"
            runner = FIRMWARE.EsptoolRunner(
                python=str(python),
                port="/dev/cu.usbmodem-test",
            )
            with mock.patch.dict(os.environ, {"ESPTOOL_VENV_PROBE": str(probe)}):
                payload = runner.read_flash(0x20000, 64)
            report = json.loads(probe.read_text())
            self.assertEqual(payload, b"\xff" * 64)
            self.assertEqual(runner.python, str(python))
            self.assertEqual(Path(report["prefix"]), venv)
            self.assertEqual(Path(report["executable"]), python)


class UsbProvisioningTests(unittest.TestCase):
    def metadata(self) -> FIRMWARE.SetupMetadata:
        return FIRMWARE.SetupMetadata(
            session_id="session_abcdefghijklmnop",
            setup_token="A" * 43,
            completion_token="C" * 43,
            csrf_token="B" * 43,
            endpoint_url="http://127.0.0.1:43123/v1/onboarding",
            local_page_url="http://127.0.0.1:43123/setup/session_abcdefghijklmnop",
            bridge_url="http://100.100.20.10:8788/v1/device-feed",
            expires_at=1_900_000_000,
        )

    def test_setup_partition_has_checksum_strict_padding_and_no_coinbase_key(self) -> None:
        image = FIRMWARE.build_setup_partition(self.metadata())
        parsed = FIRMWARE.parse_setup_partition(image)
        self.assertEqual(len(image), FIRMWARE.ONBOARDING_SIZE)
        self.assertEqual(parsed["session_id"], "session_abcdefghijklmnop")
        lower = image.lower()
        for marker in FIRMWARE.FORBIDDEN_ESP_MARKERS:
            self.assertNotIn(marker.lower(), lower)

        damaged = bytearray(image)
        damaged[-1] = 0
        with self.assertRaises(FIRMWARE.FirmwareInstallError):
            FIRMWARE.parse_setup_partition(bytes(damaged))
        invalid = replace(
            self.metadata(),
            endpoint_url="http://127.0.0.1:43123/v1/onboarding?secret",
        )
        with self.assertRaises(FIRMWARE.FirmwareInstallError):
            FIRMWARE.build_setup_partition(invalid)

    def test_flash_reverifies_bundle_preserves_nvs_and_only_writes_dedicated_setup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path, _blobs, _digest = release_fixture(root)
            manifest = FIRMWARE.load_manifest(path.as_uri(), allow_test_url=True)
            downloaded = FIRMWARE.download_variant(
                manifest,
                "v1",
                root / "downloads",
                allow_test_url=True,
            )
            setup = root / "setup.bin"
            setup.write_bytes(FIRMWARE.build_setup_partition(self.metadata()))
            runner = FIRMWARE.EsptoolRunner(
                python=sys.executable,
                port="/dev/cu.usbmodem-test",
            )
            with mock.patch.object(runner, "_run") as run:
                runner.flash(downloaded, setup)
            arguments = run.call_args.args[0]
            rendered = " ".join(arguments)
            self.assertIn("write_flash", arguments)
            self.assertIn(hex(FIRMWARE.ONBOARDING_OFFSET), arguments)
            self.assertNotIn("erase_flash", rendered)
            self.assertNotIn("erase_region", rendered)
            self.assertNotIn("0x9000", rendered)

            downloaded[0].path.write_bytes(b"changed")
            with self.assertRaisesRegex(FIRMWARE.FirmwareInstallError, "changed"):
                runner.flash(downloaded, setup)

    def test_read_only_status_supports_safe_interrupted_setup_recovery(self) -> None:
        app = synthetic_application("v1")
        setup = FIRMWARE.build_setup_partition(self.metadata())

        def reader(offset: int, size: int) -> bytes:
            if offset == 0x20000:
                return app[:size]
            if offset == 0x720000:
                return b"\xff" * size
            if offset == FIRMWARE.ONBOARDING_OFFSET:
                return setup
            raise AssertionError((offset, size))

        status = FIRMWARE.inspect_flash_status(reader)
        self.assertEqual(status["operation"], "read-only")
        self.assertEqual(status["physical_board_revision"], "unverified")
        self.assertEqual(status["app_slots"]["ota_0"]["state"], "recognized")
        self.assertEqual(status["app_slots"]["ota_1"]["state"], "blank")
        self.assertEqual(status["onboarding_partition"], "valid")
        self.assertNotIn("setup_token", json.dumps(status))


class ReleaseGeneratorAndRootBuildTests(unittest.TestCase):
    def test_generator_emits_both_variants_checksums_and_unsigned_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            fixture, _blobs, _digest = release_fixture(root / "fixture")
            fixture_raw = json.loads(fixture.read_text())
            for board in ("v1", "v2"):
                by_role = {
                    item["role"]: root / "fixture" / item["path"]
                    for item in fixture_raw["variants"][board]["artifacts"]
                }
                for role, relative in GENERATOR.INPUTS.items():
                    destination = build / board / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(by_role[role], destination)

            output = root / "dist"
            destination = GENERATOR.generate(
                build,
                output,
                "v1.2.3",
                source_commit="1" * 40,
                source_tree_clean=True,
            )
            manifest = json.loads(destination.read_text())
            loaded = FIRMWARE.load_manifest(destination.as_uri(), allow_test_url=True)
            provenance = json.loads((output / "firmware-provenance.json").read_text())
            attestation = json.loads((output / "firmware-attestation.intoto.jsonl").read_text())
            checksum_lines = (output / "SHA256SUMS").read_text().splitlines()

            self.assertEqual(set(manifest["variants"]), {"v1", "v2"})
            self.assertFalse(manifest["release_evidence"]["production_ready"])
            self.assertFalse(manifest["release_evidence"]["client_signature_verified"])
            self.assertEqual(loaded.manifest_id, manifest["manifest_id"])
            self.assertEqual(provenance["source"]["commit"], "1" * 40)
            self.assertTrue(provenance["source"]["tree_clean"])
            self.assertFalse(provenance["signed"])
            self.assertEqual(attestation["_type"], "https://in-toto.io/Statement/v1")
            self.assertEqual(len(checksum_lines), 11)
            for line in checksum_lines:
                digest, name = line.split("  ", 1)
                self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), digest)

    def test_root_build_entrypoint_passes_firmware_project_to_every_idf_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "firmware" / "scripts").mkdir(parents=True)
            shutil.copyfile(
                ROOT / "scripts" / "build-firmware.sh", root / "scripts/build-firmware.sh"
            )
            for relative in (
                "scripts/build.sh",
                "scripts/lib-idf.sh",
                "sdkconfig.defaults",
                "sdkconfig.v1.defaults",
                "sdkconfig.v2.defaults",
            ):
                source = ROOT / "firmware" / relative
                destination = root / "firmware" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            log = root / "idf.log"
            fake_idf = fake_bin / "idf.py"
            fake_idf.write_text(
                "#!/usr/bin/env bash\n"
                'printf \'%s\\n\' "$*" >> "$FAKE_IDF_LOG"\n'
                "if [[ \"${1:-}\" == '--version' ]]; then echo 'ESP-IDF v5.5.2'; fi\n",
                encoding="utf-8",
            )
            fake_idf.chmod(0o755)
            environment = dict(os.environ)
            environment.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                    "FAKE_IDF_LOG": str(log),
                    "FIRMWARE_RELEASE_VERSION": "v1.2.3",
                }
            )
            completed = subprocess.run(
                ["/bin/bash", "scripts/build-firmware.sh", "v1"],
                cwd=root,
                env=environment,
                check=False,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            invocations = [line for line in log.read_text().splitlines() if line != "--version"]
            self.assertEqual(len(invocations), 2)
            for invocation in invocations:
                self.assertIn(f"-C {root / 'firmware'}", invocation)
                self.assertIn(f"-B {root / 'firmware/build/v1'}", invocation)

    def test_workflows_pin_the_recorded_container_and_forward_release_version(self) -> None:
        for relative in (
            ".github/workflows/firmware.yml",
            ".github/workflows/release-firmware.yml",
        ):
            workflow = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn(FIRMWARE.ESP_IDF_CONTAINER_DIGEST, workflow)
            self.assertIn("espressif/idf:v5.5.2@sha256:", workflow)
            self.assertIn("FIRMWARE_RELEASE_VERSION", workflow)
            self.assertIn("docker run --rm", workflow)
            self.assertNotIn("esp-idf-ci-action", workflow)


if __name__ == "__main__":
    unittest.main()
