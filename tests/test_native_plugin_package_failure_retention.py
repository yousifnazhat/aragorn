"""One first-run check of the new controlled-refusal retention path."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import capture_runtime_native_plugin_package_check as capture
from scripts import materialize_native_plugin_package_fixture as fixture
from scripts import runtime_native_plugin_package_check as guest


class NativePluginPackageFailureRetentionTests(unittest.TestCase):
    def test_refusal_is_retained_as_failure_only_after_capture_completes(self):
        adapter = fixture._adapter()
        diagnostic = adapter.diagnostic("DENIAL", "POLICY_DENIAL_NOT_ESTABLISHED")
        stderr = (
            b"native plugin package fixture refused: PLUGIN_PACKAGE_DENIAL: "
            b"adapter DENIAL/POLICY_DENIAL_NOT_ESTABLISHED\n"
            + adapter.canonical(diagnostic)
            + b"\n"
        )
        container = "a" * 64
        with patch.object(
            capture.subprocess,
            "run",
            return_value=types.SimpleNamespace(
                returncode=126, stdout=b"", stderr=stderr
            ),
        ) as invoke:
            refused = capture._invoke_guest(
                ["exec", container, "fixed-fixture"], container
            )
        self.assertEqual(invoke.call_count, 1)
        self.assertEqual(refused["status"], "REFUSED")
        self.assertEqual(refused["diagnostic"], diagnostic)
        self.assertEqual(refused["stderr_digest"], adapter.digest(stderr))
        self.assertEqual(
            refused["guest_cleanup_authority"], "NOT_ESTABLISHED_BY_DIAGNOSTIC"
        )
        self.assertNotIn("stderr", refused)
        self.assertIs(refused["phase3_eligible"], False)
        for unaccepted in (
            b"uncontrolled exception with a secret\n"
            + adapter.canonical(diagnostic)
            + b"\n",
            stderr + b"uncontrolled trailing diagnostics\n",
        ):
            with (
                patch.object(
                    capture.subprocess,
                    "run",
                    return_value=types.SimpleNamespace(
                        returncode=126, stdout=b"", stderr=unaccepted
                    ),
                ),
                self.assertRaises(RuntimeError) as failure,
            ):
                capture._invoke_guest(["exec", container, "fixed-fixture"], container)
            self.assertNotIn("secret", str(failure.exception))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / "refused.json"
            document = {
                "schema": capture._SCHEMA,
                "status": "REFUSED",
                "observation": refused,
                "phase3_eligible": False,
            }
            with (
                patch.object(capture, "_capture", return_value=document),
                contextlib.redirect_stdout(io.StringIO()) as printed,
            ):
                self.assertEqual(capture.main([str(output)]), 2)
            self.assertEqual(json.loads(output.read_bytes()), document)
            self.assertEqual(json.loads(printed.getvalue())["status"], "REFUSED")
            self.assertNotIn("uncontrolled", output.read_text())
            incomplete = output.with_name("cleanup-unconfirmed.json")
            with (
                patch.object(
                    capture, "_capture", side_effect=ValueError("cleanup unconfirmed")
                ),
                self.assertRaisesRegex(ValueError, "cleanup unconfirmed"),
            ):
                capture.main([str(incomplete)])
            self.assertFalse(incomplete.exists())
        self.assertEqual(refused["route_id"], guest._ROUTE)


if __name__ == "__main__":
    unittest.main()
