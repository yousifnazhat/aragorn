from __future__ import annotations

import os
import tempfile
import unittest
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import runtime_quarantine_systemd_check as subject
from tests.test_runtime_skill_startup import _fixture, _publish, _require_unlocked

_CONTAINER = "c" * 64
_SKILL = "sha256:" + "a" * 64
_REVOCATIONS = {"generation": 2, "skill_digests": [_SKILL]}
_SNAPSHOT = canonical_digest(_REVOCATIONS)
_BEFORE = [
    {"unit": {"Id": unit}, "process": {"pid": index + 10}}
    for index, unit in enumerate(subject.response._UNITS)
]
_INSTALLED = {
    "active_record_digest": "sha256:" + "b" * 64,
    "tree_digest": "sha256:" + "d" * 64,
    "skill_digest": _SKILL,
    "denial": None,
}
_DENIAL = {
    "schema": "aragorn/protected-skill-digest-denial/v1",
    "authority": "ROOT_RECORDED_DIGEST_DENIAL_ONLY_NOT_QUARANTINE_OR_PHASE3_QUALIFICATION",
    "skill_digest": _SKILL,
    "revocation_snapshot_digest": _SNAPSHOT,
}
_AFTER = {
    **_INSTALLED,
    "denial": {
        "name": ".aragorn-quarantined-skill-" + "a" * 64 + ".json",
        "identity": [1, 2, 3],
        "document": _DENIAL,
        "digest": canonical_digest(_DENIAL),
    },
}
_BARRIER = {
    "status": "PERSISTENT_FIXED_PROFILE_STARTS_MASKED",
    "directory_fsynced": True,
    "automatic_unmask_supported": False,
    "masks": [
        {
            "path": str(subject.response._MASK_ROOT / unit),
            "target": "/dev/null",
            "unit": {"Id": unit},
        }
        for unit in subject.response._UNITS
    ],
}
_RESULT = {
    "status": "DIGEST_DENIAL_RECORDED_AND_FIXED_PROFILE_STOPPED_MASKED",
    "expected_skill_digest": _SKILL,
    "revocation_snapshot_digest": _SNAPSHOT,
    "accepted_revocation": {"generation": 2},
    "before": _BEFORE,
    "denial_record": _DENIAL,
    "denial_record_digest": canonical_digest(_DENIAL),
    "active_record_digest": _INSTALLED["active_record_digest"],
    "tree_digest": _INSTALLED["tree_digest"],
    "future_start_barrier": _BARRIER,
}


def _startup(status=0):
    return {
        "Id": subject._WORKER,
        "InvocationID": ("1" if status == 0 else "2") * 32,
        "ActiveState": "active" if status == 0 else "failed",
        "SubState": "running" if status == 0 else "failed",
        "MainPID": "12" if status == 0 else "0",
        "ControlPID": "0",
        "ExecStartPre": "{ path=/usr/bin/python3.12 ; argv[]="
        + subject._STARTUP
        + " ; ignore_errors=no ; start_time=[now] ; stop_time=[now] ; pid=123 ; code=exited ; status="
        + str(status)
        + " }",
        "User": "aragorn-runtime",
        "Group": "aragorn-runtime",
        "NoNewPrivileges": "yes",
        "AmbientCapabilities": "",
        "CapabilityBoundingSet": "",
        "LimitNOFILE": "128",
        "LimitNOFILESoft": "128",
        "BindsTo": subject._SENSOR,
    }


@contextmanager
def _environment():
    with ExitStack() as stack:
        values = {
            "require": stack.enter_context(patch.object(subject, "_require_fixture")),
            "prepare": stack.enter_context(
                patch.object(
                    subject,
                    "_prepare",
                    return_value={
                        "skill_digest": _SKILL,
                        "revocations": _REVOCATIONS,
                        "startup": {"unit": _startup()},
                    },
                )
            ),
            "installed": stack.enter_context(
                patch.object(
                    subject,
                    "_installed",
                    side_effect=[
                        deepcopy(_INSTALLED),
                        deepcopy(_INSTALLED),
                        deepcopy(_AFTER),
                    ],
                )
            ),
            "invoke": stack.enter_context(
                patch.object(
                    subject,
                    "_invoke",
                    side_effect=[
                        {
                            "exit_code": 126,
                            "stdout": "",
                            "stderr": "aragorn runtime quarantine: REFUSED\n",
                        },
                        {
                            "exit_code": 0,
                            "stdout": canonical_json({"response": _RESULT}).decode()
                            + "\n",
                            "stderr": "",
                        },
                    ],
                )
            ),
            "inputs": stack.enter_context(
                patch.object(
                    subject, "_startup_inputs", return_value={"fixed": "digest"}
                )
            ),
            "counter": stack.enter_context(
                patch.object(
                    subject,
                    "_counterfactual_start",
                    return_value={
                        "gateway_containment_claim": False,
                        "denial_unchanged": True,
                    },
                )
            ),
            "stop": stack.enter_context(
                patch.object(
                    subject, "_stop_fixture", return_value={"fixed": "inactive"}
                )
            ),
            "running": stack.enter_context(
                patch.object(subject.prior, "_running", return_value=deepcopy(_BEFORE))
            ),
            "retain": stack.enter_context(
                patch.object(
                    subject.prior,
                    "_retained_response",
                    side_effect=lambda envelope: (
                        envelope["response"],
                        {"separate_process_readback": True},
                    ),
                )
            ),
            "masks": stack.enter_context(
                patch.object(
                    subject.prior, "_start_refused", return_value={"exit_code": 1}
                )
            ),
            "cgroups": stack.enter_context(
                patch.object(
                    subject.response, "_cgroup_empty", return_value={"status": "ABSENT"}
                )
            ),
        }
        stack.enter_context(
            patch.object(
                subject.response,
                "_identities",
                return_value=(998, 997, 997, 992, 992, 996, 996),
            )
        )
        stack.enter_context(
            patch.object(
                subject.response,
                "_command",
                side_effect=AssertionError("live systemd call forbidden"),
            )
        )
        stack.enter_context(
            patch.object(
                subject.subprocess,
                "run",
                side_effect=AssertionError("live subprocess forbidden"),
            )
        )
        yield values


class RuntimeQuarantineSystemdCheckTests(unittest.TestCase):
    def test_installed_snapshot_reads_real_transaction_and_immutable_denial(self):
        real_read = subject.read_quarantine_at

        def read(root_fd, digest, *, expected_uid):
            self.assertEqual(expected_uid, 0)
            return real_read(root_fd, digest, expected_uid=os.geteuid())

        with (
            _fixture() as fixture,
            patch.object(subject, "read_quarantine_at", side_effect=read),
        ):
            skill = fixture["binding"].active_skill_digest
            before = subject._installed(skill)
            self.assertIsNone(before["denial"])
            self.assertEqual(
                before["tree_digest"], fixture["transaction"]["tree_digest"]
            )
            _require_unlocked(fixture["root"])
            denial = _publish(fixture)
            after = subject._installed(skill)
            self.assertEqual({**after, "denial": None}, before)
            self.assertEqual(after["denial"]["document"], denial)
            self.assertEqual(after["denial"]["digest"], canonical_digest(denial))
            self.assertEqual(subject._installed(skill), after)
            _require_unlocked(fixture["root"])
            with self.assertRaises(RuntimeError):
                subject._installed("sha256:" + "0" * 64)
            _require_unlocked(fixture["root"])

    def test_exact_fixture_guard_precedes_all_effects_and_cleanup(self):
        for identity, platform, uid, cgroup in (
            ("bad", "linux", 0, "/docker/" + _CONTAINER + "/init.scope"),
            (_CONTAINER, "darwin", 0, "/docker/" + _CONTAINER + "/init.scope"),
            (_CONTAINER, "linux", 1, "/docker/" + _CONTAINER + "/init.scope"),
            (_CONTAINER, "linux", 0, "/system.slice/init.scope"),
            (_CONTAINER, "linux", 0, "/docker/" + "d" * 64 + "/init.scope"),
        ):
            with (
                self.subTest(
                    identity=identity, platform=platform, uid=uid, cgroup=cgroup
                ),
                patch.object(subject.sys, "platform", platform),
                patch.object(subject.os, "geteuid", return_value=uid),
                patch.object(subject.response, "_process_cgroup", return_value=cgroup),
                patch.object(subject, "_prepare") as prepare,
                patch.object(subject, "_stop_fixture") as cleanup,
            ):
                with self.assertRaises(RuntimeError):
                    subject._run(identity)
                prepare.assert_not_called()
                cleanup.assert_not_called()
        with (
            patch.object(subject.sys, "platform", "linux"),
            patch.object(subject.os, "geteuid", return_value=0),
            patch.object(
                subject.response,
                "_process_cgroup",
                return_value="/docker/" + _CONTAINER + "/init.scope",
            ),
        ):
            subject._require_fixture(_CONTAINER)

    def test_complete_observation_joins_manual_response_marker_and_cleanup(self):
        with _environment() as env:
            result = subject._run(_CONTAINER)
        self.assertEqual(result["status"], "OBSERVED")
        self.assertFalse(result["phase3_eligible"])
        self.assertFalse(result["run_conformance_eligible"])
        self.assertEqual(result["fixture_container"], _CONTAINER)
        self.assertEqual(result["installed_after"], _AFTER)
        self.assertEqual(result["fixture_stack_cleanup"], {"fixed": "inactive"})
        self.assertFalse(
            result["counterfactual_startup_denial"]["gateway_containment_claim"]
        )
        self.assertIn(
            "LEGACY_INITIAL_INSTALL_NOT_SUCCESSOR_PRODUCER_REINSTALL_ENFORCEMENT",
            result["limitations"],
        )
        env["stop"].assert_called_once_with()
        self.assertEqual(env["invoke"].call_args_list[-1].args, (_SKILL, _SNAPSHOT))
        self.assertEqual(
            env["counter"].call_args.args,
            (_CONTAINER, _BARRIER, _AFTER, {"unit": _startup()}, {"fixed": "digest"}),
        )

    def test_changed_proof_or_any_partial_failure_never_returns_observed(self):
        for field, changed in (
            ("status", "other"),
            ("expected_skill_digest", "wrong"),
            ("revocation_snapshot_digest", "wrong"),
            ("accepted_revocation", {"generation": 1}),
            ("before", []),
            ("denial_record", {**_DENIAL, "skill_digest": "wrong"}),
            ("denial_record_digest", "wrong"),
            ("active_record_digest", "wrong"),
            ("tree_digest", "wrong"),
        ):
            with self.subTest(field=field), _environment() as env:
                result = {**_RESULT, field: changed}
                env["retain"].side_effect = lambda _envelope, result=result: (
                    result,
                    {},
                )
                with self.assertRaises(RuntimeError):
                    subject._run(_CONTAINER)
                env["stop"].assert_called_once()
                env["counter"].assert_not_called()
        for failure in (
            "prepare",
            "installed",
            "invoke",
            "retain",
            "masks",
            "cgroups",
            "counter",
            "stop",
        ):
            with self.subTest(failure=failure), _environment() as env:
                env[failure].side_effect = RuntimeError("injected " + failure)
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    subject._run(_CONTAINER)
                env["stop"].assert_called_once()
        for failure in (
            "input-drift",
            "populated",
            "preexisting-denial",
            "installed-drift",
            "wrong-noop",
        ):
            with self.subTest(failure=failure), _environment() as env:
                if failure == "input-drift":
                    env["inputs"].side_effect = [
                        {"fixed": "digest"},
                        {"fixed": "changed"},
                    ]
                elif failure == "populated":
                    env["cgroups"].return_value = {"status": "POPULATED"}
                elif failure == "preexisting-denial":
                    env["installed"].side_effect = [deepcopy(_AFTER)]
                elif failure == "installed-drift":
                    env["installed"].side_effect = [
                        _INSTALLED,
                        _INSTALLED,
                        {**_AFTER, "tree_digest": "changed"},
                    ]
                else:
                    env["running"].side_effect = [_BEFORE, []]
                with self.assertRaises(RuntimeError):
                    subject._run(_CONTAINER)
                env["stop"].assert_called_once()

    def test_startup_proof_requires_exact_command_credentials_uid_and_real_exit(self):
        pairs = [
            '"worker-binding" "/etc/aragorn/runtime-action-worker.json"',
            '"openclaw-config" "/etc/aragorn/agent-gateway/openclaw.json"',
        ]
        for status in (0, 126):
            for ordering in (pairs, list(reversed(pairs))):
                with (
                    patch.object(
                        subject.response, "_show_unit", return_value=_startup(status)
                    ),
                    patch.object(
                        subject.response,
                        "_command",
                        return_value=("a(ss) 2 " + " ".join(ordering)).encode(),
                    ),
                    patch.object(subject.os.path, "lexists", return_value=False),
                ):
                    self.assertEqual(
                        subject._startup_state(status)["unit"], _startup(status)
                    )
        for field, value in (
            ("ExecStartPre", ""),
            (
                "ExecStartPre",
                _startup(126)["ExecStartPre"].replace(
                    "ignore_errors=no", "ignore_errors=yes"
                ),
            ),
            (
                "ExecStartPre",
                _startup(126)["ExecStartPre"].replace("-I -S -B", "-I -S"),
            ),
            (
                "ExecStartPre",
                _startup(126)["ExecStartPre"] + _startup(126)["ExecStartPre"],
            ),
            ("ExecStartPre", _startup(126)["ExecStartPre"].replace("pid=123", "pid=0")),
            (
                "ExecStartPre",
                _startup(126)["ExecStartPre"].replace("status=126", "status=0"),
            ),
            ("User", "root"),
            ("Group", "root"),
            ("NoNewPrivileges", "no"),
            ("AmbientCapabilities", "cap_sys_admin"),
            ("CapabilityBoundingSet", "cap_sys_admin"),
            ("LimitNOFILE", "64"),
            ("LimitNOFILESoft", "64"),
            ("BindsTo", subject._GATEWAY),
            ("InvocationID", ""),
            ("MainPID", "9"),
            ("ControlPID", "1"),
            ("ActiveState", "active"),
        ):
            with (
                self.subTest(field=field, value=value),
                patch.object(
                    subject.response,
                    "_show_unit",
                    return_value={**_startup(126), field: value},
                ),
                patch.object(
                    subject.response,
                    "_command",
                    return_value=("a(ss) 2 " + " ".join(pairs)).encode(),
                ),
                patch.object(subject.os.path, "lexists", return_value=False),
                self.assertRaises(RuntimeError),
            ):
                subject._startup_state(126)
        for credentials, socket in (
            ("a(ss) 1 " + pairs[0], False),
            ("a(ss) 3 " + " ".join(pairs + [pairs[0]]), False),
            ("a(ss) 2 " + " ".join(pairs), True),
        ):
            with (
                self.subTest(credentials=credentials, socket=socket),
                patch.object(
                    subject.response, "_show_unit", return_value=_startup(126)
                ),
                patch.object(
                    subject.response, "_command", return_value=credentials.encode()
                ),
                patch.object(subject.os.path, "lexists", return_value=socket),
                self.assertRaises(RuntimeError),
            ):
                subject._startup_state(126)

    def test_counterfactual_removes_only_verified_masks_preserves_denial_and_records_gateway(
        self,
    ):
        for failure in (
            None,
            "extra-mask",
            "wrong-target",
            "regular-mask",
            "denial-drift",
            "input-drift",
            "start-succeeded",
            "same-invocation",
        ):
            with (
                self.subTest(failure=failure),
                tempfile.TemporaryDirectory() as temporary,
                ExitStack() as stack,
            ):
                root = Path(temporary).resolve()
                for unit in subject.response._UNITS:
                    (root / unit).symlink_to("/dev/null")
                barrier = deepcopy(_BARRIER)
                for item, unit in zip(
                    barrier["masks"], subject.response._UNITS, strict=True
                ):
                    item["path"] = str(root / unit)
                if failure == "extra-mask":
                    barrier["masks"].append(deepcopy(barrier["masks"][0]))
                if failure == "wrong-target":
                    barrier["masks"][0]["target"] = "/elsewhere"
                if failure == "regular-mask":
                    (root / subject._GATEWAY).unlink()
                    (root / subject._GATEWAY).write_bytes(b"not a mask")
                real_stat = os.stat

                def metadata(*args, real_stat=real_stat, **kwargs):
                    result = real_stat(*args, **kwargs)
                    if kwargs.get("dir_fd") is not None:
                        return SimpleNamespace(
                            **{
                                key: getattr(result, key)
                                for key in (
                                    "st_dev",
                                    "st_ino",
                                    "st_mode",
                                    "st_nlink",
                                    "st_size",
                                    "st_mtime_ns",
                                    "st_ctime_ns",
                                )
                            },
                            st_uid=0,
                            st_gid=0,
                        )
                    return result

                stack.enter_context(patch.object(subject, "_require_fixture"))
                stack.enter_context(patch.object(subject.response, "_MASK_ROOT", root))
                stack.enter_context(
                    patch.object(
                        subject.response,
                        "_activation_guard",
                        side_effect=lambda: ExitStack(),
                    )
                )
                stack.enter_context(
                    patch.object(subject.response.broker, "_require_protected_ancestry")
                )
                stack.enter_context(
                    patch.object(subject.os, "stat", side_effect=metadata)
                )
                stack.enter_context(
                    patch.object(
                        subject,
                        "_installed",
                        return_value={}
                        if failure == "denial-drift"
                        else deepcopy(_AFTER),
                    )
                )
                stack.enter_context(
                    patch.object(
                        subject,
                        "_startup_inputs",
                        return_value={}
                        if failure == "input-drift"
                        else {"fixed": "digest"},
                    )
                )
                stack.enter_context(
                    patch.object(
                        subject,
                        "_startup_state",
                        return_value={
                            "unit": _startup(0 if failure == "same-invocation" else 126)
                        },
                    )
                )
                command = stack.enter_context(
                    patch.object(subject.response, "_command", return_value=b"")
                )
                gateway = {"ActiveState": "active", "MainPID": "999"}
                stack.enter_context(
                    patch.object(subject.response, "_unit_state", return_value=gateway)
                )
                run = stack.enter_context(
                    patch.object(
                        subject.subprocess,
                        "run",
                        return_value=SimpleNamespace(
                            returncode=0 if failure == "start-succeeded" else 1,
                            stdout=b"",
                            stderr=b"refused",
                        ),
                    )
                )
                arguments = (
                    _CONTAINER,
                    barrier,
                    _AFTER,
                    {"unit": _startup()},
                    {"fixed": "digest"},
                )
                if failure:
                    with self.assertRaises(RuntimeError):
                        subject._counterfactual_start(*arguments)
                    if failure in {
                        "extra-mask",
                        "wrong-target",
                        "regular-mask",
                        "denial-drift",
                        "input-drift",
                    }:
                        run.assert_not_called()
                        self.assertEqual(len(list(root.iterdir())), 2)
                else:
                    result = subject._counterfactual_start(*arguments)
                    self.assertEqual(list(root.iterdir()), [])
                    self.assertEqual(result["gateway_after"], gateway)
                    self.assertFalse(result["gateway_containment_claim"])
                    self.assertTrue(result["denial_unchanged"])
                    self.assertEqual(
                        run.call_args.args[0][-2:], ["start", subject._WORKER]
                    )
                    command.assert_called_once_with(
                        ["/usr/bin/systemctl", "daemon-reload"], timeout=5
                    )

    def test_fixed_entrypoint_arguments_and_output_limits(self):
        for status, stdout, stderr in (
            (0, b"{}\n", b""),
            (126, b"", b"REFUSED"),
            (125, b"", b"INDETERMINATE"),
        ):
            with patch.object(
                subject.subprocess,
                "run",
                return_value=SimpleNamespace(
                    returncode=status, stdout=stdout, stderr=stderr
                ),
            ) as run:
                result = subject._invoke(_SKILL, _SNAPSHOT)
                self.assertEqual(result["exit_code"], status)
                self.assertEqual(
                    run.call_args.args[0],
                    [
                        "/usr/bin/python3.12",
                        "-I",
                        "-S",
                        "-B",
                        subject._SHIM,
                        _SKILL,
                        _SNAPSHOT,
                    ],
                )
                self.assertEqual(run.call_args.kwargs["timeout"], 45)
                self.assertEqual(run.call_args.kwargs["env"], subject._ENV)
        for stdout, stderr in ((b"x" * 131073, b""), (b"", b"x" * 4097)):
            with (
                patch.object(
                    subject.subprocess,
                    "run",
                    return_value=SimpleNamespace(
                        returncode=0, stdout=stdout, stderr=stderr
                    ),
                ),
                self.assertRaises(RuntimeError),
            ):
                subject._invoke(_SKILL, _SNAPSHOT)

    def test_fixed_four_unit_cleanup_parses_bound_states_and_refuses_partial_stop(self):
        for failure in (None, "running", "wrong-id", "duplicate", "command", "reset"):
            calls = []

            def command(argv, *, timeout, calls=calls, failure=failure):
                calls.append((argv, timeout))
                if argv[1] == "stop":
                    self.assertEqual(argv[2:], list(subject._ALL_UNITS))
                    if failure == "command":
                        raise RuntimeError("stop failed")
                    return b""
                if argv[1] == "reset-failed":
                    self.assertEqual(argv[2:], [subject._WORKER])
                    self.assertEqual(timeout, 3)
                    if failure == "reset":
                        raise RuntimeError("reset failed")
                    return b""
                unit = argv[-1]
                state = {
                    "Id": "wrong" if failure == "wrong-id" else unit,
                    "ActiveState": "active" if failure == "running" else "inactive",
                    "MainPID": "0",
                    "ControlPID": "0",
                }
                raw = "".join(f"{key}={value}\n" for key, value in state.items())
                return (
                    raw + ("Id=" + unit + "\n" if failure == "duplicate" else "")
                ).encode()

            with (
                self.subTest(failure=failure),
                patch.object(subject.response, "_command", side_effect=command),
            ):
                if failure:
                    with self.assertRaises(RuntimeError):
                        subject._stop_fixture()
                else:
                    self.assertEqual(
                        set(subject._stop_fixture()), set(subject._ALL_UNITS)
                    )
                    self.assertEqual(len(calls), 6)

    def test_main_emits_success_only_after_complete_fixture_cleanup(self):
        for arguments in ([], [_CONTAINER, "extra"]):
            with patch.object(subject, "_run") as run, redirect_stderr(StringIO()):
                self.assertEqual(subject.main(arguments), 64)
                run.assert_not_called()
        output, error = StringIO(), StringIO()
        with (
            patch.object(subject, "_run", side_effect=RuntimeError("cleanup failed")),
            redirect_stdout(output),
            redirect_stderr(error),
        ):
            self.assertEqual(subject.main([_CONTAINER]), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("cleanup failed", error.getvalue())
        with _environment() as env:
            env["prepare"].side_effect = RuntimeError("initial operation failed")
            env["stop"].side_effect = RuntimeError("subsequent cleanup failed")
            with self.assertRaisesRegex(
                RuntimeError, "initial operation failed.*subsequent cleanup failed"
            ):
                subject._run(_CONTAINER)
            env["stop"].assert_called_once()


if __name__ == "__main__":
    unittest.main()
