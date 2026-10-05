"""Inert successor wiring tests: never launch Docker, services or an update."""

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import capture_runtime_native_plugin_update_identity_check as subject


class NativePluginUpdateIdentityHostTests(unittest.TestCase):
    def setUp(self):
        self.manifest = {
            "schema": subject._STATIC_SCHEMA,
            "file_digests": {
                path: "sha256:" + "1" * 64 for path in subject._STATIC_PATHS
            },
        }
        self.manifest["file_digests"][subject.identity._ENTRY] = (
            subject.prior.prior.native.stage._ENTRYPOINT[1]
        )
        self.raw = subject._api._canonical(self.manifest)
        self.pin = subject._api._digest(self.raw)

    def test_manifest_requires_exact_caller_pinned_inventory_and_encoding(self):
        self.assertEqual(subject._pins(self.raw, self.pin), self.manifest)
        for raw, pin in (
            (self.raw, "sha256:" + "0" * 64),
            (self.raw + b"\n", subject._api._digest(self.raw + b"\n")),
            (b"{}", subject._api._digest(b"{}")),
        ):
            with self.subTest(raw=raw[:8], pin=pin):
                with self.assertRaises(Exception):
                    subject._pins(raw, pin)
        altered = copy.deepcopy(self.manifest)
        altered["file_digests"]["/unexpected"] = "sha256:" + "2" * 64
        raw = subject._api._canonical(altered)
        with self.assertRaises(Exception):
            subject._pins(raw, subject._api._digest(raw))

    def test_stage_bindings_reject_wrong_static_profile_pin(self):
        profile = {
            "files": [
                {"path": path, "digest": pin}
                for path, pin in self.manifest["file_digests"].items()
                if path != subject.identity._ENTRY
            ]
        }
        subject._stage_pins(profile, self.manifest["file_digests"])
        profile["files"][0]["digest"] = "sha256:" + "f" * 64
        with self.assertRaises(Exception):
            subject._stage_pins(profile, self.manifest["file_digests"])

    def test_direct_pin_read_rejects_symlink_and_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "pins"
            path.write_bytes(self.raw)
            self.assertEqual(subject._read_pins(path, self.pin), self.raw)
            alias = path.with_name("alias")
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                subject._read_pins(alias, self.pin)
            with self.assertRaises(Exception):
                subject._read_pins(path, "sha256:" + "0" * 64)

    def test_capture_preserves_old_observation_and_bundle_with_no_effect_retry(self):
        observation = self.observation()
        envelope = {
            "status": "OBSERVED",
            "update_observation": observation,
            "before": "raw",
        }
        source = {"commit": "a" * 40}
        profile = {
            "files": [
                {"path": path, "digest": pin}
                for path, pin in self.manifest["file_digests"].items()
            ]
        }
        bundle = {"files": list(range(13))}
        original_files = subject.prior._FILES

        def capture():
            subject.prior.prior.profile.stage_runtime_native_startup_profile("stage")
            result = subject.prior._invoke_guest(["exec", "container"], "container")
            return {
                "source": source,
                "observation": result,
                "input_bundle": bundle,
                "invocation": {"argv": ["docker", "exec", "container"]},
            }

        with (
            patch.object(subject.prior, "_capture", side_effect=capture),
            patch.object(subject.prior.prior, "_source", return_value=source),
            patch.object(
                subject.prior.prior.profile,
                "stage_runtime_native_startup_profile",
                return_value=profile,
            ),
            patch.object(
                subject._api,
                "_tree_file",
                side_effect=lambda commit, path: {"path": str(path)},
            ),
            patch.object(subject, "_invoke", return_value=envelope) as invoke,
        ):
            result = subject._capture(self.raw, self.pin)
        self.assertIs(result["observation"], observation)
        self.assertIs(result["input_bundle"], bundle)
        self.assertEqual(
            result["live_identity"], {"status": "OBSERVED", "before": "raw"}
        )
        self.assertEqual(set(result["live_identity_sources"]), set(subject._SOURCES))
        self.assertEqual(result["invocation"]["argv"][-1], self.pin)
        self.assertIs(subject.prior._FILES, original_files)
        invoke.assert_called_once()

    def observation(self):
        return {
            "schema": subject.prior.guest._SCHEMA,
            "authority": subject.prior.guest._AUTHORITY,
            "route_id": subject.prior.guest._ROUTE,
            "fixture_container": "container",
            "status": "OBSERVED",
            "branch": "TRACKED_LOCAL_MARKETPLACE_DIRECTORY_UPDATE",
            "input_mount_removed": True,
            "inherited_input_restored": True,
            "input_mount_source": str(subject.prior.guest._STAGED),
            "route_qualified": False,
            "phase3_eligible": False,
            "run_conformance_eligible": False,
            "production_activation_eligible": False,
        }

    def test_original_observation_preserves_cleanup_and_claim_ceiling_guards(self):
        value = self.observation()
        self.assertIs(subject._original_observation(value, "container"), value)
        for name, changed in (
            ("input_mount_removed", False),
            ("inherited_input_restored", False),
            ("route_qualified", True),
            ("phase3_eligible", True),
            ("schema", "other"),
            ("fixture_container", "other"),
        ):
            with self.subTest(name=name), self.assertRaises(Exception):
                subject._original_observation({**value, name: changed}, "container")

    def test_guest_transfer_accepts_bounded_refusal_and_never_retries(self):
        envelope = {
            "schema": subject._LIVE_SCHEMA,
            "authority": subject._LIVE_AUTHORITY,
            "route_id": subject.prior.guest._ROUTE,
            "branch": "TRACKED_LOCAL_MARKETPLACE_DIRECTORY_UPDATE",
            "fixture_container": "container",
            "static_pin_manifest": None,
            "static_pin_manifest_digest": self.pin,
            "status": "REFUSED",
            **dict.fromkeys(
                (
                    "route_qualified",
                    "phase3_eligible",
                    "run_conformance_eligible",
                    "production_activation_eligible",
                    "common_deployment_fully_verified",
                    "live_deployment_attested",
                ),
                False,
            ),
        }
        result = SimpleNamespace(
            returncode=126, stdout=subject._api._canonical(envelope) + b"\n", stderr=b""
        )
        with (
            patch.object(subject.prior.prior.existing, "_docker") as docker,
            patch.object(subject.subprocess, "run", return_value=result) as run,
        ):
            self.assertEqual(
                subject._invoke(["exec", "container"], "container", self.raw, self.pin),
                envelope,
            )
        self.assertEqual(docker.call_count, 2)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0][-1], self.pin)
        self.assertEqual(run.call_args.kwargs["timeout"], 240)

    def test_cli_invalid_pins_never_launch_capture_and_errors_are_redacted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / "pins"
            path.write_bytes(b"not a manifest")
            output = io.StringIO()
            with redirect_stdout(output), patch.object(subject, "_capture") as capture:
                code = subject.main(
                    [
                        "capture",
                        "--static-pins",
                        str(path),
                        "--expected-static-pins-digest",
                        self.pin,
                        "--out",
                        str(root / "out"),
                    ]
                )
            self.assertEqual(code, 2)
            result = json.loads(output.getvalue())
            self.assertEqual(result["status"], "REFUSED")
            self.assertEqual(
                result["reason"], "CAPTURE_PREREQUISITE_OR_EXECUTION_FAILED"
            )
            self.assertTrue(result["diagnostic"]["repository_frames"])
            self.assertFalse(result["diagnostic"]["exception_text_retained"])
            self.assertFalse(result["diagnostic"]["locals_retained"])
            capture.assert_not_called()
            self.assertFalse((root / "out").exists())

    def test_failure_location_omits_exception_text_locals_and_external_paths(self):
        try:
            subject._expect(False, "secret credential must not be retained")
        except Exception as error:
            result = subject._failure_location(error)
        self.assertNotIn("secret", json.dumps(result))
        self.assertTrue(result["repository_frames"])
        self.assertLessEqual(len(result["repository_frames"]), 8)
        for frame in result["repository_frames"]:
            self.assertEqual(set(frame), {"source", "line", "function"})
            self.assertTrue(frame["source"].startswith(("scripts/", "src/")))
            self.assertGreater(frame["line"], 0)
        self.assertFalse(result["retry_performed"])

    def test_help_has_explicit_capture_command_without_live_operation(self):
        with (
            redirect_stdout(io.StringIO()) as output,
            patch.object(subject, "_capture") as capture,
        ):
            with self.assertRaises(SystemExit) as raised:
                subject.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("capture", output.getvalue())
        capture.assert_not_called()


if __name__ == "__main__":
    unittest.main()
