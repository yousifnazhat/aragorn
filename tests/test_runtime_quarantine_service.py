from __future__ import annotations

import io
import json
import os
import runpy
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aragorn import runtime_quarantine_service as subject
from aragorn.oci_worker_protocol import canonical_json
from tests.test_runtime_quarantine_response import _fixture, _marker

_ROOT = Path(__file__).resolve().parents[1]
_SHIM = _ROOT / "packaging/libexec/aragorn-runtime-quarantine-service.py"
_DIGESTS = ("sha256:" + "1" * 64, "sha256:" + "2" * 64)
_SECRET = "secret argument or credential must not appear"
_ENVELOPE = {"response": {"status": "development-only"}, "retained": True}


def _main(arguments=_DIGESTS):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = subject.main(arguments)
    return status, stdout.getvalue(), stderr.getvalue()


class RuntimeQuarantineServiceTests(unittest.TestCase):
    def test_only_two_canonical_digests_reach_the_core(self):
        with mock.patch.object(
            subject.response, "_quarantine_fixed_runtime_profile"
        ) as core:
            for arguments in (
                (),
                (_DIGESTS[0],),
                (*_DIGESTS, "--dispatch"),
                ("--help",),
                ("--retain-evidence", *_DIGESTS),
            ):
                with self.subTest(arguments=arguments):
                    status, stdout, stderr = _main(arguments)
                    self.assertEqual((status, stdout), (64, ""))
                    self.assertIn("usage:", stderr)
            for invalid in (
                "--dispatch",
                "/arbitrary/path",
                "sha256:" + "A" * 64,
                "sha256:" + "1" * 63,
                _DIGESTS[0] + "\n",
                " " + _DIGESTS[0],
                "sha256:+" + "1" * 63,
                "sha256:_" + "1" * 63,
                True,
                None,
                _SECRET,
            ):
                for index in (0, 1):
                    arguments = list(_DIGESTS)
                    arguments[index] = invalid
                    with self.subTest(invalid=invalid, index=index):
                        status, stdout, stderr = _main(arguments)
                        self.assertEqual((status, stdout), (126, ""))
                        self.assertEqual(
                            stderr, "aragorn runtime quarantine: REFUSED\n"
                        )
            core.assert_not_called()

    def test_exact_core_arguments_and_retained_envelope_are_not_rewrapped(self):
        with (
            mock.patch.object(
                subject.response,
                "_quarantine_fixed_runtime_profile",
                return_value=_ENVELOPE,
            ) as core,
            mock.patch.object(subject.response.response, "_retain_result") as retain,
            mock.patch.object(subject.sys, "argv", ["shim", *_DIGESTS]),
        ):
            self.assertEqual(
                _main(None),
                (0, canonical_json(_ENVELOPE).decode("ascii") + "\n", ""),
            )
            core.assert_called_once_with(*_DIGESTS)
            retain.assert_not_called()

    def test_real_composition_records_denial_and_retains_exactly_once(self):
        with _fixture() as fixture:
            status, stdout, stderr = _main((fixture["digest"], fixture["snapshot"]))
            self.assertEqual((status, stderr), (0, ""))
            envelope = json.loads(stdout)
            self.assertIs(envelope["retained"], True)
            self.assertEqual(
                envelope["response"]["expected_skill_digest"], fixture["digest"]
            )
            self.assertEqual(envelope["response"]["denial_record"], _marker(fixture))
            self.assertEqual(
                envelope["response"]["status"],
                "DIGEST_DENIAL_RECORDED_AND_FIXED_PROFILE_STOPPED_MASKED",
            )
            fixture["retain"].assert_called_once_with(envelope["response"])
            fixture["mask"].assert_called_once()

    def test_refusal_interrupt_and_indeterminate_exits_never_echo_inputs(self):
        for error, expected in (
            (subject.response.RuntimeQuarantineError(_SECRET), 126),
            (ValueError(_SECRET), 126),
            (OSError(_SECRET), 126),
            (KeyboardInterrupt(), 130),
            (subject.response.RuntimeQuarantineIndeterminate(_SECRET), 125),
        ):
            with (
                self.subTest(error=type(error)),
                mock.patch.object(
                    subject.response,
                    "_quarantine_fixed_runtime_profile",
                    side_effect=error,
                ),
            ):
                status, stdout, stderr = _main()
                self.assertEqual((status, stdout), (expected, ""))
                self.assertNotIn(_SECRET, stderr)
                self.assertNotIn(_DIGESTS[0], stderr)
                self.assertNotIn(_DIGESTS[1], stderr)
                if expected == 125:
                    self.assertIn("INDETERMINATE", stderr)
                elif expected == 126:
                    self.assertIn("REFUSED", stderr)
        for platform, uid in (("darwin", 0), ("linux", 1000)):
            with (
                self.subTest(platform=platform, uid=uid),
                mock.patch.object(subject.response.sys, "platform", platform),
                mock.patch.object(subject.response.os, "geteuid", return_value=uid),
                mock.patch.object(
                    subject.response.response, "_activation_guard"
                ) as guard,
            ):
                self.assertEqual(_main()[0], 126)
                guard.assert_not_called()

    def test_serialization_write_flush_and_delivery_interrupts_are_indeterminate(self):
        for operation in ("serialize", "write", "flush"):
            for error in (ValueError(_SECRET), OSError(_SECRET), KeyboardInterrupt()):
                output, diagnostics = io.StringIO(), io.StringIO()
                target = subject if operation == "serialize" else output
                name = "canonical_json" if operation == "serialize" else operation
                with (
                    self.subTest(operation=operation, error=type(error)),
                    mock.patch.object(
                        subject.response,
                        "_quarantine_fixed_runtime_profile",
                        return_value=_ENVELOPE,
                    ) as core,
                    redirect_stdout(output),
                    redirect_stderr(diagnostics),
                    mock.patch.object(target, name, side_effect=error),
                ):
                    self.assertEqual(subject.main(_DIGESTS), 125)
                    self.assertIsNone(subject.sys.stdout)
                core.assert_called_once_with(*_DIGESTS)
                self.assertIn("INDETERMINATE", diagnostics.getvalue())
                self.assertNotIn(_SECRET, diagnostics.getvalue())
                self.assertNotIn("REFUSED", diagnostics.getvalue())

    def test_failed_or_interrupted_diagnostics_preserve_response_status(self):
        for operation in ("write", "flush"):
            for error in (OSError(_SECRET), KeyboardInterrupt()):
                for status in (64, 126, 125):
                    output, diagnostics = io.StringIO(), io.StringIO()
                    with (
                        self.subTest(
                            operation=operation, error=type(error), status=status
                        ),
                        redirect_stdout(output),
                        redirect_stderr(diagnostics),
                        mock.patch.object(diagnostics, operation, side_effect=error),
                        mock.patch.object(
                            subject.response,
                            "_quarantine_fixed_runtime_profile",
                            return_value=_ENVELOPE,
                        ) as core,
                        mock.patch.object(
                            subject, "canonical_json", side_effect=OSError
                        ),
                    ):
                        arguments = {64: (), 126: ("bad", _DIGESTS[1]), 125: _DIGESTS}
                        self.assertEqual(subject.main(arguments[status]), status)
                        self.assertIsNone(subject.sys.stderr)
                        if status == 125:
                            self.assertIsNone(subject.sys.stdout)
                            core.assert_called_once_with(*_DIGESTS)
                        else:
                            core.assert_not_called()
                    self.assertNotIn(_SECRET, diagnostics.getvalue())

    def test_fixed_shim_and_broken_output_pipes_preserve_exact_nonzero_exit(self):
        main = mock.Mock(return_value=125)
        with (
            mock.patch(
                "importlib.import_module", return_value=SimpleNamespace(main=main)
            ) as imported,
            mock.patch.object(sys, "path", list(sys.path)),
            self.assertRaises(SystemExit) as exit_code,
        ):
            runpy.run_path(str(_SHIM), run_name="__main__")
        self.assertEqual(exit_code.exception.code, 125)
        imported.assert_called_once_with("aragorn.runtime_quarantine_service")
        main.assert_called_once_with()
        # Execute only the source shim and a stubbed core, never Linux services.
        program = "\n".join(
            (
                "import runpy, sys",
                f"sys.path.insert(0, {str(_ROOT / 'src')!r})",
                "from aragorn import runtime_quarantine_service as service",
                (
                    "service.response._quarantine_fixed_runtime_profile = "
                    "lambda *args: {'retained': True}"
                ),
                f"sys.argv = [{str(_SHIM)!r}, {_DIGESTS[0]!r}, {_DIGESTS[1]!r}]",
                f"runpy.run_path({str(_SHIM)!r}, run_name='__main__')",
            )
        )
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        error_read_fd, error_write_fd = os.pipe()
        os.close(error_read_fd)
        try:
            for closed_stderr in (False, True):
                with self.subTest(closed_stderr=closed_stderr):
                    result = subprocess.run(
                        [sys.executable, "-I", "-S", "-B", "-c", program],
                        stdin=subprocess.DEVNULL,
                        stdout=write_fd,
                        stderr=error_write_fd if closed_stderr else subprocess.PIPE,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 125, result.stderr)
                    if not closed_stderr:
                        self.assertIn(b"INDETERMINATE", result.stderr)
                        self.assertNotIn(b"Exception ignored", result.stderr)
                        self.assertNotIn(_DIGESTS[0].encode(), result.stderr)
        finally:
            os.close(write_fd)
            os.close(error_write_fd)
