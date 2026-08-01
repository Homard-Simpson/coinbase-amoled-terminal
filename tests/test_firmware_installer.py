from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
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


def synthetic_application(board: str) -> bytes:
    payload = bytearray(b"\xff" * 2048)
    payload[0] = FIRMWARE.ESP_IMAGE_MAGIC
    struct.pack_into("<I", payload, FIRMWARE.ESP_APP_DESC_OFFSET, FIRMWARE.ESP_APP_DESC_MAGIC)
    for offset, value in (
        (FIRMWARE.ESP_APP_VERSION_OFFSET, f"1.2.3-{board}"),
        (FIRMWARE.ESP_APP_PROJECT_OFFSET, "coinbase_amoled_terminal"),
        (FIRMWARE.ESP_APP_IDF_OFFSET, "v5.5.2"),
    ):
        encoded = value.encode("ascii") + b"\0"
        payload[offset : offset + len(encoded)] = encoded
    return bytes(payload)


def release_fixture(root: Path, *, ready: bool = False) -> tuple[Path, dict[str, bytes]]:
    blobs: dict[str, bytes] = {}
    variants: dict[str, object] = {}
    for board in ("v1", "v2"):
        artifacts = []
        board_dir = root / board
        board_dir.mkdir(parents=True, exist_ok=True)
        for index, (role, offset) in enumerate(FIRMWARE.EXPECTED_OFFSETS.items()):
            payload = (
                synthetic_application(board)
                if role == "application"
                else (f"{board}-{role}-".encode("ascii") * 200) + bytes([index])
            )
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
        app = blobs[f"{board}:application"]
        variants[board] = {
            "board_revision": board,
            "firmware_version": f"1.2.3-{board}",
            "ready_for_production": ready,
            "controls_verified": ready,
            "hardware_attested": ready,
            "artifacts": artifacts,
            "detection": [
                {
                    "offset": 0x20000,
                    "size": len(app),
                    "sha256": hashlib.sha256(app).hexdigest(),
                },
                {
                    "offset": 0x720000,
                    "size": len(app),
                    "sha256": hashlib.sha256(app).hexdigest(),
                },
            ],
            "onboarding_partition": {
                "offset": FIRMWARE.ONBOARDING_OFFSET,
                "size": FIRMWARE.ONBOARDING_SIZE,
            },
        }
    manifest = {
        "schema_version": 1,
        "release_version": "v1.2.3",
        "esp_idf_version": "5.5.2",
        "variants": variants,
    }
    path = root / "firmware-manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path, blobs


class ManifestTests(unittest.TestCase):
    def test_manifest_and_all_artifact_checksums_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path, blobs = release_fixture(root, ready=True)
            manifest = FIRMWARE.load_manifest(path.as_uri(), allow_test_url=True)
            downloaded = FIRMWARE.download_variant(
                manifest, "v2", root / "downloads", allow_test_url=True
            )
            expected_roles = {key.split(":")[1] for key in blobs if key.startswith("v2:")}
            self.assertEqual({item.artifact.role for item in downloaded}, expected_roles)
            with self.assertRaises(FIRMWARE.FirmwareInstallError):
                FIRMWARE._validate_application_image(
                    synthetic_application("v1"), manifest.variants["v2"]
                )

            (root / "v2" / "application.bin").write_bytes(b"substituted")
            with self.assertRaises(FIRMWARE.FirmwareInstallError):
                FIRMWARE.download_variant(
                    manifest, "v2", root / "bad-download", allow_test_url=True
                )

    def test_non_release_url_and_unattested_bundle_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path, _ = release_fixture(Path(temporary), ready=False)
            with self.assertRaises(FIRMWARE.FirmwareInstallError):
                FIRMWARE.load_manifest(path.as_uri())
            with self.assertRaises(FIRMWARE.FirmwareInstallError):
                FIRMWARE.load_manifest(
                    path.as_uri() + "?credential-like-query",
                    allow_test_url=True,
                )
            manifest = FIRMWARE.load_manifest(path.as_uri(), allow_test_url=True)
            with self.assertRaises(FIRMWARE.FirmwareInstallError):
                FIRMWARE.require_release_readiness(
                    manifest,
                    board="v1",
                    allow_unverified_test_artifacts=False,
                )
            FIRMWARE.require_release_readiness(
                manifest,
                board="v1",
                allow_unverified_test_artifacts=True,
            )

    def test_manifest_rejects_wrong_board_offset_and_idf_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path, _ = release_fixture(root, ready=True)
            raw = json.loads(path.read_text())
            raw["variants"]["v1"]["artifacts"][0]["offset"] = 0x9000
            path.write_text(json.dumps(raw))
            with self.assertRaises(FIRMWARE.FirmwareInstallError):
                FIRMWARE.load_manifest(path.as_uri(), allow_test_url=True)

            path, _ = release_fixture(root, ready=True)
            raw = json.loads(path.read_text())
            raw["variants"]["v2"]["artifacts"][3]["size"] = 0x700001
            path.write_text(json.dumps(raw))
            with self.assertRaises(FIRMWARE.FirmwareInstallError):
                FIRMWARE.load_manifest(path.as_uri(), allow_test_url=True)

            path, _ = release_fixture(root, ready=True)
            raw = json.loads(path.read_text())
            raw["esp_idf_version"] = "5.4.0"
            path.write_text(json.dumps(raw))
            with self.assertRaises(FIRMWARE.FirmwareInstallError):
                FIRMWARE.load_manifest(path.as_uri(), allow_test_url=True)


class BoardSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        path, self.blobs = release_fixture(Path(self.temporary.name), ready=True)
        self.manifest = FIRMWARE.load_manifest(path.as_uri(), allow_test_url=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def reader_for(self, board: str):
        app = self.blobs[f"{board}:application"]

        def read(offset: int, size: int) -> bytes:
            if offset == 0x20000 and size == len(app):
                return app
            return b"\xff" * size

        return read

    def test_verified_existing_release_auto_detects_without_prompt(self) -> None:
        input_fn = mock.Mock(side_effect=AssertionError("must not prompt"))
        selected = FIRMWARE.select_board(self.manifest, self.reader_for("v2"), input_fn=input_fn)
        self.assertEqual(selected, "v2")
        input_fn.assert_not_called()

    def test_conflicting_explicit_choice_is_refused(self) -> None:
        with self.assertRaises(FIRMWARE.FirmwareInstallError):
            FIRMWARE.select_board(self.manifest, self.reader_for("v2"), requested="v1")

    def test_blank_board_gets_one_friendly_choice_and_invalid_input_fails(self) -> None:
        def blank_reader(offset: int, size: int) -> bytes:
            return b"\xff" * size

        input_fn = mock.Mock(return_value="1")
        self.assertEqual(
            FIRMWARE.select_board(self.manifest, blank_reader, input_fn=input_fn, interactive=True),
            "v1",
        )
        self.assertEqual(input_fn.call_count, 1)
        self.assertIn(FIRMWARE.BOARD_HELP_URL, input_fn.call_args.args[0])

        with self.assertRaises(FIRMWARE.FirmwareInstallError):
            FIRMWARE.select_board(
                self.manifest,
                blank_reader,
                interactive=False,
            )
        with self.assertRaises(FIRMWARE.FirmwareInstallError):
            FIRMWARE.select_board(
                self.manifest,
                blank_reader,
                input_fn=mock.Mock(return_value="maybe"),
            )


class UsbProvisioningTests(unittest.TestCase):
    def metadata(self) -> object:
        return FIRMWARE.SetupMetadata(
            session_id="session_abcdefghijklmnop",
            setup_token="A" * 43,
            csrf_token="B" * 43,
            endpoint_url="http://127.0.0.1:43123/v1/onboarding",
            local_page_url=("http://127.0.0.1:43123/setup/session_abcdefghijklmnop"),
            bridge_url="http://100.100.20.10:8788/v1/device-feed",
            expires_at=1_900_000_000,
        )

    def test_setup_partition_has_checksum_and_no_coinbase_key_material(self) -> None:
        image = FIRMWARE.build_setup_partition(self.metadata())
        parsed = FIRMWARE.parse_setup_partition(image)
        self.assertEqual(len(image), FIRMWARE.ONBOARDING_SIZE)
        self.assertEqual(parsed["session_id"], "session_abcdefghijklmnop")
        lower = image.lower()
        for marker in FIRMWARE.FORBIDDEN_ESP_MARKERS:
            self.assertNotIn(marker.lower(), lower)

        damaged = bytearray(image)
        damaged[60] ^= 1
        with self.assertRaises(FIRMWARE.FirmwareInstallError):
            FIRMWARE.parse_setup_partition(bytes(damaged))

        invalid = replace(
            self.metadata(),
            endpoint_url="http://127.0.0.1:43123/v1/onboarding?secret",
        )
        with self.assertRaises(FIRMWARE.FirmwareInstallError):
            FIRMWARE.build_setup_partition(invalid)

    def test_flash_command_preserves_nvs_and_writes_only_manifest_plus_setup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            downloaded = []
            for role, offset in FIRMWARE.EXPECTED_OFFSETS.items():
                path = root / f"{role}.bin"
                path.write_bytes(b"x" * 1024)
                artifact = FIRMWARE.Artifact(
                    role=role,
                    path=f"v1/{role}.bin",
                    offset=offset,
                    size=1024,
                    sha256=hashlib.sha256(b"x" * 1024).hexdigest(),
                )
                downloaded.append(FIRMWARE.DownloadedArtifact(artifact, path))
            setup = root / "setup.bin"
            setup.write_bytes(FIRMWARE.build_setup_partition(self.metadata()))
            runner = FIRMWARE.EsptoolRunner(python="/usr/bin/python3", port="/dev/cu.usbmodem-test")
            with mock.patch.object(runner, "_run") as run:
                runner.flash(tuple(downloaded), setup)
            arguments = run.call_args.args[0]
        rendered = " ".join(arguments)
        self.assertIn("write_flash", arguments)
        self.assertIn(hex(FIRMWARE.ONBOARDING_OFFSET), arguments)
        self.assertNotIn("erase_flash", rendered)
        self.assertNotIn("erase_region", rendered)
        self.assertNotIn("0x9000", rendered)


class ReleaseGeneratorTests(unittest.TestCase):
    def test_generator_stages_both_variants_with_unattested_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            build = root / "build"
            for board in ("v1", "v2"):
                for relative in GENERATOR.INPUTS.values():
                    path = build / board / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes((board + str(relative)).encode() * 100)
            destination = GENERATOR.generate(build, root / "dist", "v1.2.3")
            manifest = json.loads(destination.read_text())
        self.assertEqual(set(manifest["variants"]), {"v1", "v2"})
        for variant in manifest["variants"].values():
            self.assertFalse(variant["ready_for_production"])
            self.assertFalse(variant["controls_verified"])
            self.assertFalse(variant["hardware_attested"])
            self.assertEqual(
                variant["onboarding_partition"],
                {"offset": 0xE20000, "size": 0x2000},
            )


if __name__ == "__main__":
    unittest.main()
