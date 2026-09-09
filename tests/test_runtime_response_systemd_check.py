from __future__ import annotations

import subprocess
import sys
import unittest
from contextlib import ExitStack, contextmanager, redirect_stderr
from io import StringIO
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aragorn.oci_worker_protocol import canonical_json
from scripts import runtime_response_systemd_check as check

_SKILL = "sha256:" + "a" * 64
_SNAPSHOT = "sha256:" + "b" * 64
_BEFORE = [
    {"unit": {"Id": unit, "ControlGroup": f"/system.slice/{unit}"}}
    for unit in check.response._UNITS
]
_CHILD = {
    "pid": 123,
    "start_time_ticks": 456,
    "uid": 992,
    "gid": 992,
    "cgroup": "/system.slice/aragorn-agent-gateway.service",
}


@contextmanager
def _environment():
    process = SimpleNamespace(wait=Mock(return_value=-15), returncode=-15)
    calls = []

    @contextmanager
    def child(uid, gid):
        if (uid, gid) != (992, 992):
            raise AssertionError("wrong fixture child identity")
        yield process, _CHILD

    def response(arguments):
        calls.append(arguments)
        if len(arguments) == 2:
            print(
                "aragorn runtime response: REFUSED: requested digest is not the running binding",
                file=sys.stderr,
            )
            return 126
        print(
            canonical_json(
                {
                    "status": "TERMINATED_AND_REVOKED_FIXED_RUNTIME_PROFILE",
                    "expected_skill_digest": _SKILL,
                    "revocation_snapshot_digest": _SNAPSHOT,
                }
            ).decode("ascii")
        )
        return 0

    with ExitStack() as stack:
        for target, name, value in (
            (check.sys, "platform", "linux"),
            (check.os, "geteuid", Mock(return_value=0)),
            (
                check.response,
                "_identities",
                Mock(return_value=(998, 997, 997, 992, 992, 996, 996)),
            ),
            (check, "_running", Mock(return_value=_BEFORE)),
            (check, "_gateway_child", child),
            (check, "_child_identity", Mock(return_value=_CHILD)),
            (check.response, "main", response),
            (check, "_start_refused", Mock(return_value={"exit_code": 1})),
            (check.response, "_cgroup_empty", Mock(return_value={"status": "ABSENT"})),
        ):
            stack.enter_context(patch.object(target, name, value))
        yield process, calls


class RuntimeResponseSystemdCheckTests(unittest.TestCase):
    def test_one_negative_then_stop_revoke_and_direct_start_refusal(self):
        with _environment() as (process, calls):
            result = check._run(_SKILL, _SNAPSHOT)
            check._start_refused.assert_called_once_with()
            process.wait.assert_called_once_with(timeout=3)
        self.assertEqual(
            calls,
            [
                ["sha256:" + "0" + "a" * 63, _SNAPSHOT],
                ["--prevent-starts", _SKILL, _SNAPSHOT],
            ],
        )
        self.assertEqual(result["status"], "OBSERVED")
        self.assertFalse(result["phase3_eligible"])
        self.assertFalse(result["run_conformance_eligible"])
        self.assertEqual(result["extra_gateway_cgroup_member_exit_code"], -15)

    def test_wrong_skill_or_identity_failure_prevents_positive_call(self):
        for failure in ("accepted", "profile-changed", "child-changed"):
            with (
                self.subTest(failure=failure),
                _environment() as (_process, calls),
                ExitStack() as stack,
            ):
                if failure == "accepted":
                    stack.enter_context(
                        patch.object(
                            check,
                            "_invoke",
                            return_value={"exit_code": 0, "stdout": "", "stderr": ""},
                        )
                    )
                elif failure == "profile-changed":
                    check._running.side_effect = [_BEFORE, []]
                else:
                    check._child_identity.return_value = {
                        **_CHILD,
                        "start_time_ticks": 999,
                    }
                with self.assertRaises(RuntimeError):
                    check._run(_SKILL, _SNAPSHOT)
                self.assertFalse(any(call[0] == "--prevent-starts" for call in calls))
                check._start_refused.assert_not_called()

    def test_survivor_or_failed_restart_proof_never_produces_observation(self):
        for failure in ("child-survived", "start-not-refused", "cgroup-populated"):
            with self.subTest(failure=failure), _environment() as (process, _calls):
                if failure == "child-survived":
                    process.wait.side_effect = subprocess.TimeoutExpired(
                        "fixed child", 3
                    )
                elif failure == "start-not-refused":
                    check._start_refused.side_effect = RuntimeError("not masked")
                else:
                    check.response._cgroup_empty.side_effect = RuntimeError("populated")
                with self.assertRaises((RuntimeError, subprocess.SubprocessError)):
                    check._run(_SKILL, _SNAPSHOT)

    def test_owned_child_is_cleaned_up_on_check_failure(self):
        process = SimpleNamespace(
            pid=123,
            poll=Mock(return_value=None),
            terminate=Mock(),
            kill=Mock(),
            wait=Mock(return_value=-15),
        )
        with (
            patch.object(check.subprocess, "Popen", return_value=process) as popen,
            patch.object(check.os, "open", return_value=7) as opened,
            patch.object(check.os, "write", return_value=3) as written,
            patch.object(check.os, "close") as closed,
            patch.object(
                check, "_read_virtual_file", return_value=b"/usr/bin/sleep\x00600\x00"
            ),
            patch.object(check, "_child_identity", return_value=_CHILD),
            patch.object(
                check.response, "_service_cgroup", return_value=_CHILD["cgroup"]
            ),
            self.assertRaisesRegex(RuntimeError, "check failed"),
            check._gateway_child(992, 992),
        ):
            raise RuntimeError("check failed")
        self.assertEqual(
            popen.call_args.args[0],
            [
                "/usr/bin/setpriv",
                "--reuid=992",
                "--regid=992",
                "--clear-groups",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--no-new-privs",
                "/usr/bin/sleep",
                "600",
            ],
        )
        self.assertEqual(
            str(opened.call_args.args[0]),
            "/sys/fs/cgroup/system.slice/aragorn-agent-gateway.service/cgroup.procs",
        )
        written.assert_called_once_with(7, b"123")
        closed.assert_called_once_with(7)
        process.terminate.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=2)
        process.kill.assert_not_called()

    def test_restart_attempt_requires_both_exact_masks_and_fixed_units(self):
        path = Mock()
        path.__truediv__ = Mock(return_value=path)
        path.is_symlink.return_value = True
        native = SimpleNamespace(returncode=1, stdout=b"", stderr=b"Unit is masked.\n")
        with (
            patch.object(check, "Path", return_value=path),
            patch.object(check.os, "readlink", return_value="/dev/null") as link,
            patch.object(check.subprocess, "run", return_value=native) as run,
        ):
            result = check._start_refused()
            self.assertEqual(result["exit_code"], 1)
            self.assertEqual(
                run.call_args.args[0][-3:], ["start", *check.response._UNITS]
            )
            link.assert_has_calls([unittest.mock.call(path), unittest.mock.call(path)])
            run.reset_mock()
            link.return_value = "/somewhere-else"
            with self.assertRaises(RuntimeError):
                check._start_refused()
            run.assert_not_called()

    def test_platform_and_argument_gates_do_not_start_a_child(self):
        with (
            patch.object(check, "_gateway_child") as child,
            patch.object(check.sys, "platform", "darwin"),
            redirect_stderr(StringIO()),
        ):
            self.assertEqual(check.main([_SKILL, _SNAPSHOT]), 1)
            self.assertEqual(check.main(["arbitrary.service"]), 64)
            self.assertEqual(check.main(["arbitrary.service", _SNAPSHOT]), 1)
            child.assert_not_called()


if __name__ == "__main__":
    unittest.main()
