"""New offline CLI path/JSON boundaries; no retained capture is executed."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from scripts import native_plugin_update_collection as cli
import test_native_phase3_plugin_update_live_binding as live_fixture

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE = (
    _ROOT
    / "benchmark/evidence/phase3-native-plugin-update-systemd-development-v2-2026-10-01.json"
)
_CAPTURE_PIN = "sha256:42acdf26c128c4d7ecdfd740ac04b17509e9e17e0b799e7d4a870bf5e82a9e12"


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class NativePluginUpdateCollectionCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def invoke(self, *args):
        output = StringIO()
        with redirect_stdout(output):
            code = cli.main(list(args))
        return code, json.loads(output.getvalue())

    def test_file_prepare_reviewed_retain_and_readonly_replay_json_contract(self):
        raw = _FIXTURE.read_bytes()
        self.assertEqual(_digest(raw), _CAPTURE_PIN)
        source = json.loads(raw)["source"]
        pins = [
            "--expected-capture-digest",
            _CAPTURE_PIN,
            "--expected-source-digest",
            _digest(canonical_json(source)),
            "--expected-source-commit",
            source["commit"],
        ]
        capture = self.root / "capture.json"
        capture.write_bytes(raw)
        process = subprocess.run(
            [
                sys.executable,
                "-S",
                "-B",
                "-m",
                "scripts.native_plugin_update_collection",
                "prepare",
                "--capture",
                str(capture),
                *pins,
            ],
            cwd=_ROOT,
            env={
                **os.environ,
                "PYTHONPATH": str(_ROOT / "src"),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(process.returncode, 0, process.stderr or process.stdout)
        prepared = json.loads(process.stdout)
        self.assertEqual(prepared["status"], "OK")
        self.assertFalse(prepared["result"]["fresh_campaign_execution"])
        self.assertEqual(list(self.root.iterdir()), [capture])
        # Explicitly supply the separately inspected canonical byte projection.
        proposed = prepared["result"]["deployment_raw"]
        self.assertEqual(proposed["encoding"], "utf-8")
        deployment_raw = proposed["text"].encode("utf-8")
        deployment = self.root / "reviewed-deployment.json"
        deployment.write_bytes(deployment_raw)
        deployment_pin = prepared["result"]["deployment_digest"]
        self.assertEqual(_digest(deployment_raw), deployment_pin)
        store = self.root / "cas"
        shared = [
            *pins,
            "--expected-deployment-digest",
            deployment_pin,
            "--cas",
            str(store),
        ]
        code, retained = self.invoke(
            "retain",
            "--capture",
            str(capture),
            "--deployment",
            str(deployment),
            *shared,
        )
        self.assertEqual(code, 0, retained)
        self.assertFalse(retained["result"]["collection"]["phase3_eligible"])
        before = {
            str(p.relative_to(store)): p.read_bytes()
            for p in store.rglob("*")
            if p.is_file()
        }
        with mock.patch.object(
            CAS, "put_expected", side_effect=AssertionError("replay must not write")
        ):
            code, replayed = self.invoke(
                "replay",
                "--expected-collection-digest",
                retained["result"]["collection_digest"],
                *shared,
            )
        self.assertEqual(code, 0, replayed)
        self.assertEqual(replayed["result"], retained["result"])
        self.assertEqual(
            before,
            {
                str(p.relative_to(store)): p.read_bytes()
                for p in store.rglob("*")
                if p.is_file()
            },
        )

    def test_missing_pins_and_live_option_refuse_without_dispatch(self):
        for arguments in (("prepare",), ("capture",), ("prepare", "--live")):
            with (
                self.subTest(arguments=arguments),
                mock.patch.object(cli, "_run") as run,
            ):
                code, result = self.invoke(*arguments)
            self.assertEqual(code, 2)
            self.assertEqual(result["status"], "REFUSED")
            run.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_symlink_oversize_and_changed_input_refuse(self):
        capture = self.root / "capture.json"
        capture.write_bytes(b"{}")
        linked = self.root / "linked.json"
        linked.symlink_to(capture)
        oversized = self.root / "oversized.json"
        oversized.write_bytes(b"x" * (cli._CAPTURE_LIMIT + 1))
        pins = [
            "--expected-capture-digest",
            "sha256:" + "0" * 64,
            "--expected-source-digest",
            "sha256:" + "1" * 64,
            "--expected-source-commit",
            "2" * 40,
        ]
        for path in (linked, oversized):
            with (
                self.subTest(path=path.name),
                mock.patch.object(
                    cli.collection, "prepare_native_plugin_update_collection"
                ) as prepare,
            ):
                code, result = self.invoke("prepare", "--capture", str(path), *pins)
            self.assertEqual(code, 2)
            self.assertEqual(result["status"], "REFUSED")
            prepare.assert_not_called()

        def changed(_raw, **_pins):
            capture.write_bytes(b'{"changed":true}')
            return {
                "source_raw": b"{}",
                "deployment_raw": b"{}",
                "identity_artifacts": {},
            }

        with mock.patch.object(
            cli.collection,
            "prepare_native_plugin_update_collection",
            side_effect=changed,
        ):
            code, result = self.invoke("prepare", "--capture", str(capture), *pins)
        self.assertEqual(code, 2)
        self.assertIn("input bytes or identity changed", result["error"])
        self.assertFalse((self.root / "cas").exists())

    def live_arguments(self):
        raw = _FIXTURE.read_bytes()
        self.assertEqual(_digest(raw), _CAPTURE_PIN)
        capture = json.loads(raw)
        sources = live_fixture._fixture(capture)
        raw = canonical_json(capture) + b"\n"
        source = capture["source"]
        base_pins = {
            "expected_capture_digest": _digest(raw),
            "expected_source_digest": _digest(canonical_json(source)),
            "expected_source_commit": source["commit"],
        }
        prepared = cli.collection.prepare_native_plugin_update_collection(
            raw, **base_pins
        )
        static_raw = canonical_json(capture["live_identity"]["static_pin_manifest"])
        paths = {
            name: self.root / (name + ".json")
            for name in ("capture", "deployment", "static")
        }
        paths["capture"].write_bytes(raw)
        paths["deployment"].write_bytes(prepared["deployment_raw"])
        paths["static"].write_bytes(static_raw)
        shared = []
        for name, pin in base_pins.items():
            shared.extend(("--" + name.replace("_", "-"), pin))
        shared.extend(
            (
                "--expected-deployment-digest",
                prepared["deployment_digest"],
                "--expected-live-identity-digest",
                _digest(canonical_json(capture["live_identity"])),
                "--expected-static-pin-manifest-digest",
                _digest(static_raw),
                "--cas",
                str(self.root / "live-cas"),
            )
        )
        files = [
            "--capture",
            str(paths["capture"]),
            "--deployment",
            str(paths["deployment"]),
            "--static-pin-manifest",
            str(paths["static"]),
        ]
        for role, name in cli._LIVE_SOURCE_ROLES.items():
            path = self.root / (role + ".py")
            path.write_bytes(sources[name])
            files.extend((f"--live-{role}-source", str(path)))
            shared.extend(
                (f"--expected-live-{role}-source-digest", _digest(sources[name]))
            )
        return shared, files

    def test_retain_live_and_module_replay_live_preserve_json_and_readonly_contract(
        self,
    ):
        shared, files = self.live_arguments()
        code, retained = self.invoke("retain-live", *files, *shared)
        self.assertEqual(code, 0, retained)
        self.assertEqual(
            retained["result"]["collection"]["schema"], cli.collection.LIVE_SCHEMA
        )
        store = self.root / "live-cas"
        before = {
            str(path): path.read_bytes() for path in store.rglob("*") if path.is_file()
        }
        process = subprocess.run(
            [
                sys.executable,
                "-S",
                "-B",
                "-m",
                "scripts.native_plugin_update_collection",
                "replay-live",
                "--expected-collection-digest",
                retained["result"]["collection_digest"],
                *shared,
            ],
            cwd=_ROOT,
            env={
                **os.environ,
                "PYTHONPATH": str(_ROOT / "src"),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(process.returncode, 0, process.stderr or process.stdout)
        replayed = json.loads(process.stdout)
        self.assertEqual(replayed["result"], retained["result"])
        self.assertFalse(
            replayed["result"]["verification"]["common_deployment_fully_verified"]
        )
        self.assertEqual(
            before,
            {
                str(path): path.read_bytes()
                for path in store.rglob("*")
                if path.is_file()
            },
        )

    def test_live_fixed_inputs_missing_pins_symlinks_and_postread_changes_refuse(self):
        shared, files = self.live_arguments()
        pin_index = shared.index("--expected-live-reader-source-digest")
        for args in (
            ["retain-live", *files, *shared[:pin_index], *shared[pin_index + 2 :]],
            ["retain-live", *files, *shared, "--live-arbitrary-source", "unused"],
            ["replay-live", *shared],
        ):
            with self.subTest(args=args[-2:]), mock.patch.object(cli, "_run") as run:
                code, output = self.invoke(*args)
            self.assertEqual(code, 2, output)
            run.assert_not_called()
        source_path = self.root / "reader.py"
        linked = self.root / "linked-reader.py"
        linked.symlink_to(source_path)
        linked_files = list(files)
        linked_files[linked_files.index("--live-reader-source") + 1] = str(linked)
        with mock.patch.object(
            cli.collection, "collect_native_plugin_update_live_observation"
        ) as collect:
            code, output = self.invoke("retain-live", *linked_files, *shared)
        self.assertEqual(code, 2, output)
        collect.assert_not_called()
        self.assertFalse((self.root / "live-cas").exists())

        def mutate_source(*_args, **_kwargs):
            source_path.write_bytes(b"replaced during offline retention")
            return {"inert": True}

        with mock.patch.object(
            cli.collection,
            "collect_native_plugin_update_live_observation",
            side_effect=mutate_source,
        ):
            code, output = self.invoke("retain-live", *files, *shared)
        self.assertEqual(code, 2, output)
        self.assertIn("input bytes or identity changed", output["error"])


if __name__ == "__main__":
    unittest.main()
