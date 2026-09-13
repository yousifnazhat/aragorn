from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import runtime_endpoint_journal_systemd_check as subject
from scripts import stage_runtime_endpoint_journal_profile as stage

_CONTAINER = "c" * 64
_BOOT = "b" * 32
_DIGEST = "sha256:" + "a" * 64
_IDS = (998, 997, 997, 992, 992, 996, 996)


def _processes():
    result = {}
    for index, (role, uid, gid) in enumerate(
        (
            ("gateway", 992, 992),
            ("worker", 997, 997),
            ("sensor", 996, 996),
            ("broker", 998, 997),
        )
    ):
        unit = subject.prior._GATEWAY if role == "gateway" else subject._ROLES[role]
        shim, credentials = subject._COMMANDS.get(role, ("gateway", ()))
        argv = [
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/" + shim,
            *[f"/run/credentials/{unit}/{name}" for name in credentials],
        ]
        cgroup = f"/docker/{_CONTAINER}/system.slice/{unit}"
        state = {
            "Id": unit,
            "MainPID": str(100 + index),
            "ControlPID": "0",
            "ControlGroup": cgroup,
            "InvocationID": str(index + 1) * 32,
            "ActiveState": "active",
            "SubState": "running",
            "User": {
                "worker": "aragorn-runtime",
                "sensor": "aragorn-sensor",
                "broker": "aragorn-broker",
                "gateway": "aragorn-agent-gateway",
            }[role],
            "Group": "aragorn-sensor"
            if role == "sensor"
            else ("aragorn-agent-gateway" if role == "gateway" else "aragorn-runtime"),
            "StandardOutput": "journal",
            "ExecStart": "{ path=/usr/bin/python3.12 ; argv[]="
            + " ".join(argv)
            + " ; ignore_errors=no ; pid=123 ; code=(null) ; status=0/0 }",
            "FragmentPath": "/usr/lib/systemd/system/" + unit,
            "DropInPaths": "",
        }
        result[role] = {
            "unit": state,
            "process": {
                "pid": 100 + index,
                "uid": uid,
                "gid": gid,
                "uids": [uid, uid, uid, 997 if role == "sensor" else uid],
                "gids": [gid, gid, gid, 997 if role == "sensor" else gid],
                "start_time_ticks": 1000 + index,
                "cgroup": cgroup,
                "executable": "/usr/bin/python3.12",
                "command": " ".join(argv),
            },
        }
    return result


def _proof_values(processes):
    nested = {
        "request_digest": _DIGEST,
        "observation_digest": "sha256:" + "f" * 64,
        "verdict": "ALLOW",
        "effect_status": "CREATED",
        "reason_codes": [],
        "target_name": "runtime-worker-qualified.txt",
    }
    attribution = {
        key: processes["worker"]["process"][key]
        for key in ("pid", "uid", "gid", "start_time_ticks", "cgroup")
    }
    receipt = {
        "broker_result": nested,
        "broker_result_digest": canonical_digest(nested),
        "runtime_attribution": attribution,
        "runtime_attribution_digest": canonical_digest(attribution),
        "submission_digest": _DIGEST,
    }
    lease = {
        "grant_digest": _DIGEST,
        "runtime_attribution_digest": canonical_digest(attribution),
        "submission_digest": _DIGEST,
        "request_digest": _DIGEST,
    }
    correlation = {"session_id": "session", "run_id": "run", "tool_call_id": _DIGEST}
    claim = {
        "grant_digest": _DIGEST,
        "lease": lease,
        "lease_digest": canonical_digest(lease),
        "profile_claim": {
            "profile_pending": {"measured_action": correlation},
            "request_digest": lease["request_digest"],
            "submission_digest": lease["submission_digest"],
        },
    }
    result = {
        "grant_digest": _DIGEST,
        "lease_digest": canonical_digest(lease),
        "profile_result": {
            "lease_digest": canonical_digest(lease),
            "submission_digest": lease["submission_digest"],
            "profile_receipt_digest": canonical_digest(receipt),
            "broker_result_digest": canonical_digest(nested),
            "verdict": nested["verdict"],
            "effect_status": nested["effect_status"],
        },
    }
    before = {
        "grant_state": {
            "document": {
                "status": "AVAILABLE",
                "grant_digest": _DIGEST,
                "claim": None,
                "result": None,
            }
        },
        "target_exists": False,
        "receipt_exists": False,
        "pending_exists": False,
        "protected_entries": [],
        "staging_entries": [],
    }
    after = {
        **before,
        "grant_state": {
            "document": {
                "status": "CONSUMED",
                "grant_digest": _DIGEST,
                "claim": claim,
                "result": result,
            }
        },
        "target_exists": True,
        "receipt_exists": True,
        "protected_entries": ["runtime-worker-qualified.txt"],
    }
    driver = {
        "output": {
            "turn": {
                "identifiers": {
                    "session_id": "session",
                    "run_id": "run",
                    "tool_call_digest": _DIGEST,
                    "request_digest": _DIGEST,
                }
            }
        }
    }
    proof = {"receipt": receipt, "worker_request_digest": _DIGEST}
    return before, after, driver, proof


def _captured(processes):
    _, _, _, proof = _proof_values(processes)
    refused = {
        "client": {"pid": os.getpid(), "uid": 0, "gid": 0},
        "server_peer": {
            key: processes["worker"]["process"][key] for key in ("pid", "uid", "gid")
        },
        "outcome": "PEER_CLOSED",
    }
    result = {}
    counter = 0
    for role in subject._ROLES:
        rows = []
        for negative in (True, False) if role == "worker" else (False,):
            start = subject.journal._new(role)
            start["attempt_id"] = f"{counter + 1:032x}"
            end = {**start, "phase": "TERMINAL"}
            if negative:
                end.update(
                    peer=refused["client"],
                    handler_status="RAISED",
                    outcome="REJECTED_BEFORE_SUBMISSION",
                )
            else:
                preceding = {
                    "worker": "gateway",
                    "sensor": "worker",
                    "broker": "sensor",
                }[role]
                end.update(
                    peer={
                        key: processes[preceding]["process"][key]
                        for key in ("pid", "uid", "gid")
                    },
                    peer_expected=True,
                    handler_status="RETURNED",
                    stage="CLIENT_DELIVERY",
                    request_state="VALIDATED",
                    action_request_digest=_DIGEST,
                    submission="CORE_ENTERED" if role == "broker" else "SEND_ATTEMPTED",
                    result_digest=proof["receipt"]["broker_result_digest"],
                    client_delivery="FRAME_SENT_NOT_ACKNOWLEDGED",
                )
                if role == "sensor":
                    end.update(
                        result_kind="CANONICAL_REPLY_ONLY",
                        outcome="REPLY_RELAYED_EFFECT_UNVERIFIED",
                    )
                else:
                    end.update(
                        result_kind="VALIDATED_BROKER_RESULT",
                        outcome="BROKER_RESULT_OBSERVED",
                        verdict="ALLOW",
                        effect_status="CREATED",
                    )
                if role == "worker":
                    end.update(worker_request_digest=_DIGEST, worker_status="COMPLETED")
                else:
                    end["profile_attribution_digest"] = proof["receipt"][
                        "runtime_attribution_digest"
                    ]
            for event in (start, end):
                counter += 1
                identity = processes[role]["process"]
                row = {
                    "MESSAGE": canonical_json(event).decode(),
                    "_PID": str(identity["pid"]),
                    "_UID": str(identity["uid"]),
                    "_GID": str(identity["gid"]),
                    "_SYSTEMD_UNIT": subject._ROLES[role],
                    "_SYSTEMD_INVOCATION_ID": processes[role]["unit"]["InvocationID"],
                    "_BOOT_ID": _BOOT,
                    "_TRANSPORT": "stdout",
                    "_EXE": identity["executable"],
                    "_CMDLINE": identity["command"],
                    "__CURSOR": "s=fixture;i=" + str(counter),
                    "__MONOTONIC_TIMESTAMP": str(100 + counter),
                    "__REALTIME_TIMESTAMP": "123456789",
                }
                rows.append({"journal": row, "event": event})
        result[role] = {
            "rows": rows,
            "raw_jsonl": "".join(
                canonical_json(row["journal"]).decode() + "\n" for row in rows
            ),
        }
    return result, refused, proof


@contextmanager
def _environment():
    processes = _processes()
    before, after, driver, proof = _proof_values(processes)
    captured, refused, _ = _captured(processes)
    with ExitStack() as stack:
        mocks = {}
        for owner, key, value in (
            (subject.prior, "_require_fixture", None),
            (subject.prior, "_prepare", {"skill_digest": _DIGEST, "publication": None}),
            (subject.prior, "_installed", {"denial": None}),
            (subject.prior, "_stop_fixture", {"fixed": "inactive"}),
            (subject, "_sources", {"fixed": "source"}),
            (subject, "_processes", processes),
            (subject, "_boot", _BOOT),
            (subject, "_cursor", "s=baseline"),
            (subject, "_action", {"driver": driver}),
            (subject, "_proof", proof),
            (subject, "_collect", captured),
        ):
            mocks[key] = stack.enter_context(
                patch.object(owner, key, return_value=deepcopy(value))
            )
        import runtime_action_worker_openclaw_systemd_probe as p37b

        mocks["snapshots"] = stack.enter_context(
            patch.object(
                p37b, "_snapshot_effects", side_effect=[before, deepcopy(before), after]
            )
        )
        mocks["refusal"] = stack.enter_context(
            patch.object(p37b, "_unauthorized_worker_client", return_value=refused)
        )
        stack.enter_context(
            patch.object(
                subject.response,
                "_command",
                side_effect=AssertionError("no live commands"),
            )
        )
        yield mocks


class RuntimeEndpointJournalSystemdCheckTests(unittest.TestCase):
    def test_kernel_unit_snapshot_checks_real_effective_saved_and_filesystem_ids(self):
        for failure in (
            None,
            "uid",
            "fsuid",
            "gid",
            "cmdline",
            "exe",
            "stdout",
            "invocation",
            "mainpid",
            "unit",
            "dropin",
            "command",
            "cgroup",
            "reused-pid",
        ):
            expected = _processes()
            by_pid = {entry["process"]["pid"]: role for role, entry in expected.items()}
            starts = {}

            def command(argv, *, timeout):
                role = next(
                    role for role, unit in subject._ROLES.items() if unit == argv[-1]
                )
                state = deepcopy(expected[role]["unit"])
                if role == "sensor":
                    for case, key, value in (
                        ("invocation", "InvocationID", "0" * 32),
                        ("mainpid", "MainPID", "0"),
                        ("unit", "Id", "wrong"),
                        ("dropin", "DropInPaths", "/tmp/extra.conf"),
                        (
                            "command",
                            "ExecStart",
                            state["ExecStart"].replace(
                                "ignore_errors=no", "ignore_errors=yes"
                            ),
                        ),
                    ):
                        if failure == case:
                            state[key] = value
                return "".join(
                    f"{key}={state[key]}\n" for key in subject._PROPERTIES
                ).encode()

            def virtual(path, maximum):
                pid = int(path.parts[2])
                role = by_pid[pid]
                process = expected[role]["process"]
                if path.name == "cmdline":
                    return (
                        b"wrong\0"
                        if failure == "cmdline" and role == "sensor"
                        else b"\0".join(
                            value.encode() for value in process["command"].split()
                        )
                        + b"\0"
                    )
                uids, gids = list(process["uids"]), list(process["gids"])
                if role == "sensor":
                    if failure == "uid":
                        uids[0] = 997
                    if failure == "fsuid":
                        uids[3] = 996
                    if failure == "gid":
                        gids[1] = 997
                return (
                    "Uid:\t"
                    + " ".join(map(str, uids))
                    + "\nGid:\t"
                    + " ".join(map(str, gids))
                    + "\n"
                ).encode()

            def link(path):
                role = by_pid[int(Path(path).parts[2])]
                if str(path).endswith("/exe"):
                    return (
                        "/wrong"
                        if failure == "exe" and role == "sensor"
                        else "/usr/bin/python3.12"
                    )
                return (
                    "/dev/null"
                    if failure == "stdout" and role == "sensor"
                    else "socket:[123]"
                )

            def started(pid):
                starts[pid] = starts.get(pid, 0) + 1
                return expected[by_pid[pid]]["process"]["start_time_ticks"] + int(
                    failure == "reused-pid"
                    and by_pid[pid] == "sensor"
                    and starts[pid] > 1
                )

            with self.subTest(failure=failure), ExitStack() as stack:
                for owner, key, kwargs in (
                    (subject.response, "_identities", {"return_value": _IDS}),
                    (
                        subject.response,
                        "_unit_state",
                        {"return_value": expected["gateway"]["unit"]},
                    ),
                    (
                        subject.response,
                        "_process_identity",
                        {"return_value": expected["gateway"]["process"]},
                    ),
                    (subject.response, "_command", {"side_effect": command}),
                    (subject.response, "_process_start_time", {"side_effect": started}),
                    (
                        subject.response,
                        "_process_cgroup",
                        {
                            "side_effect": lambda pid: (
                                "/wrong"
                                if failure == "cgroup" and by_pid[pid] == "sensor"
                                else expected[by_pid[pid]]["process"]["cgroup"]
                            )
                        },
                    ),
                    (subject, "_read_virtual_file", {"side_effect": virtual}),
                    (subject.os, "readlink", {"side_effect": link}),
                ):
                    stack.enter_context(patch.object(owner, key, **kwargs))
                stack.enter_context(
                    patch.object(Path, "resolve", lambda path, **_: path)
                )
                if failure:
                    with self.assertRaises(RuntimeError):
                        subject._processes(_CONTAINER)
                else:
                    self.assertEqual(subject._processes(_CONTAINER), expected)

    def test_native_action_uses_only_fixed_driver_and_private_fixture_token(self):
        for failure in (
            None,
            "environment",
            "source",
            "source-drift",
            "mode-0644",
            "mode-0755",
            "mode-drift",
            "driver",
        ):
            with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
                root = Path(temporary).resolve()
                driver = root / "driver.mjs"
                driver.write_bytes(b"pinned inert source")
                driver.chmod(
                    {"mode-0644": 0o644, "mode-0755": 0o755}.get(failure, 0o555)
                )
                env = root / "environment"
                env.write_bytes(
                    b"OPENCLAW_GATEWAY_TOKEN=" + b"a" * 64 + b"\n"
                    if failure != "environment"
                    else b"OTHER=secret\n"
                )
                (root / "policy.json").write_bytes(b"{}")
                called = []

                def run(*args):
                    called.append(args)
                    if failure == "source-drift":
                        driver.chmod(0o755)
                        driver.write_bytes(b"drift")
                        driver.chmod(0o555)
                    if failure == "mode-drift":
                        driver.chmod(0o755)
                    if failure == "driver":
                        raise RuntimeError("fixed native driver failed")
                    return {"safe": "driver result"}

                p37b = SimpleNamespace(
                    subprocess=subprocess,
                    _DRIVER=driver,
                    _GATEWAY_ENVIRONMENT=env,
                    _DRIVER_ROOT=root / "driver-output",
                    lineage=SimpleNamespace(_CONTROL=root, _PROTECTED=root),
                    _TARGET="runtime-worker-qualified.txt",
                    _PAYLOAD=b"benign",
                    _action_digests=lambda *_: {},
                    openclaw=SimpleNamespace(_RUNTIME_DIGEST="old"),
                    _refresh_controls=lambda *_: {"counter": 2},
                    _run_driver=run,
                    _assert_driver_outcome=lambda *_: None,
                )
                stack.enter_context(
                    patch.object(
                        subject,
                        "_DRIVER_PIN",
                        (
                            len(driver.read_bytes()),
                            subject._digest(driver.read_bytes())
                            if failure != "source"
                            else _DIGEST,
                        ),
                    )
                )
                real_read = subject.response._read_regular

                def read(path, uid, modes):
                    if path == driver:
                        self.assertEqual(uid, 0)
                        self.assertEqual(modes, {0o555})
                        return real_read(path, os.geteuid(), modes)
                    return path.read_bytes()

                stack.enter_context(
                    patch.object(
                        subject.response,
                        "_read_regular",
                        side_effect=read,
                    )
                )
                stack.enter_context(
                    patch.object(subject.response, "_identities", return_value=_IDS)
                )
                journal_command = stack.enter_context(
                    patch.object(
                        subject.response, "_command", return_value=b"gateway failed"
                    )
                )
                with self.subTest(failure=failure):
                    if failure:
                        with self.assertRaises(RuntimeError):
                            subject._action(
                                p37b,
                                {"runtime_digest": _DIGEST, "skill_digest": _DIGEST},
                            )
                    else:
                        result = subject._action(
                            p37b, {"runtime_digest": _DIGEST, "skill_digest": _DIGEST}
                        )
                        self.assertNotIn("a" * 64, repr(result))
                        self.assertEqual(
                            called[0][:-1],
                            (
                                "endpoint-journal-allow",
                                "COMPLETED",
                                {"verdict": "ALLOW", "effect_status": "CREATED"},
                                "aragorn/runtime-action-worker-result/v1",
                            ),
                        )
                        self.assertEqual(
                            set(called[0][-1]),
                            {"OPENCLAW_GATEWAY_TOKEN", "ARAGORN_MOCK_PROVIDER_TOKEN"},
                        )
                        self.assertEqual(p37b.openclaw._RUNTIME_DIGEST, "old")
                        self.assertEqual(
                            (p37b._DRIVER_ROOT.stat().st_mode & 0o777), 0o700
                        )
                    self.assertIs(p37b.subprocess, subprocess)
                    self.assertEqual(
                        journal_command.call_count, int(failure == "driver")
                    )

    def test_failure_diagnostics_are_bounded_redacted_and_never_change_run(self):
        token = "f" * 64
        raw = (
            "prefix " + token + "\x1b\r" + "x" * 1000 + "\nprivate second line"
        ).encode()
        record = subject._diagnostic_bytes(raw, token)
        self.assertEqual(record["bytes"], len(raw))
        self.assertEqual(record["digest"], subject._digest(raw))
        encoded = json.dumps(record, ensure_ascii=True)
        self.assertNotIn(token, encoded)
        self.assertNotIn("private second line", encoded)
        self.assertIn("[REDACTED]", encoded)
        self.assertTrue(record["text_truncated"])
        self.assertLessEqual(len(json.dumps(record["text"])), 514)
        tail = subject._diagnostic_bytes(
            b"first\n" + b"y" * 1000 + token.encode(), token, tail=True
        )
        self.assertTrue(tail["text"].endswith("[REDACTED]"))
        self.assertNotIn("first", tail["text"])
        self.assertIsNone(subject._diagnostic_bytes(raw, None)["text"])
        for status in (0, 1):
            completed = subprocess.CompletedProcess(["fixed"], status, b"result", raw)
            original = SimpleNamespace(
                run=Mock(return_value=completed), forwarded=object()
            )
            diagnostics = subject._SubprocessDiagnostics(original, token)
            argv, kwargs = ["fixed"], {"timeout": 45, "env": {"TOKEN": token}}
            self.assertIs(diagnostics.run(argv, **kwargs), completed)
            original.run.assert_called_once_with(argv, **kwargs)
            self.assertIs(diagnostics.forwarded, original.forwarded)
            self.assertNotIn(token, repr(diagnostics.records))
        for failure in (
            RuntimeError("run failed"),
            KeyboardInterrupt(),
            subprocess.TimeoutExpired("fixed", 45, stderr=raw),
        ):
            original = SimpleNamespace(run=Mock(side_effect=failure))
            diagnostics = subject._SubprocessDiagnostics(original, token)
            with self.assertRaises(type(failure)) as caught:
                diagnostics.run(["fixed"], timeout=45)
            self.assertIs(caught.exception, failure)
            original.run.assert_called_once_with(["fixed"], timeout=45)
            self.assertNotIn(token, repr(diagnostics.records))
        failure = RuntimeError("original")
        with patch.object(
            subject.response, "_command", return_value=b"old\n" + raw
        ) as command:
            subject._gateway_failure(failure, token)
        command.assert_called_once_with(
            [
                "/usr/bin/journalctl",
                "--unit=" + subject.prior._GATEWAY,
                "--no-pager",
                "--all",
                "--output=cat",
                "--lines=20",
            ],
            timeout=3,
        )
        self.assertNotIn(token, repr(failure.__notes__))
        with patch.object(
            subject.response, "_command", side_effect=OSError("private " + token)
        ):
            subject._gateway_failure(failure, token)
        self.assertNotIn(token, repr(failure.__notes__))
        self.assertIn("OSError", failure.__notes__[-1])

    def test_cleanup_diagnostics_preserve_command_rejection_offsets_and_reaping(self):
        token = "f" * 64
        for case in ("success", "status", "stderr", "oversize", "timeout", "spawn"):
            with self.subTest(case=case), ExitStack() as stack:
                failure = subprocess.TimeoutExpired("fixed", 3)
                process = SimpleNamespace(
                    pid=123,
                    wait=Mock(
                        side_effect=[failure, 0] if case == "timeout" else None,
                        return_value=int(case == "status"),
                    ),
                )
                captured = []

                def popen(
                    *args, captured=captured, case=case, process=process, **kwargs
                ):
                    captured.append((args, kwargs))
                    if case == "spawn":
                        raise OSError("spawn failed")
                    kwargs["stdout"].write(b"safe")
                    if case in {"stderr", "status", "oversize"}:
                        kwargs["stderr"].write(
                            b"failed "
                            + token.encode()
                            + (
                                b"x" * (subject.response._MAX_BYTES + 1)
                                if case == "oversize"
                                else b""
                            )
                        )
                    kwargs["stdout"].flush()
                    kwargs["stderr"].flush()
                    return process

                original = SimpleNamespace(
                    Popen=Mock(side_effect=popen),
                    DEVNULL=subprocess.DEVNULL,
                    TimeoutExpired=subprocess.TimeoutExpired,
                )
                diagnostics = subject._SubprocessDiagnostics(original, token)
                stack.enter_context(
                    patch.object(subject.response, "subprocess", diagnostics)
                )
                kill = stack.enter_context(patch.object(subject.response.os, "killpg"))
                argv = ["/usr/bin/systemctl", "reset-failed", subject.prior._WORKER]
                if case == "success":
                    self.assertEqual(
                        subject.response._command(argv, timeout=3), b"safe"
                    )
                    self.assertEqual(diagnostics.records, [])
                else:
                    with self.assertRaises(
                        (RuntimeError, OSError, subprocess.TimeoutExpired)
                    ) as caught:
                        subject.response._command(argv, timeout=3)
                    self.assertTrue(diagnostics.records)
                    self.assertNotIn(token, repr(diagnostics.records))
                    self.assertEqual(diagnostics.records[0]["argv"], argv)
                    if case == "timeout":
                        self.assertIs(caught.exception, failure)
                        self.assertEqual(
                            process.wait.call_args_list,
                            [
                                unittest.mock.call(timeout=3),
                                unittest.mock.call(timeout=1),
                            ],
                        )
                        kill.assert_called_once_with(123, signal.SIGTERM)
                    elif case == "oversize":
                        self.assertFalse(
                            diagnostics.records[0]["captured_stderr_complete"]
                        )
                        self.assertIsNone(diagnostics.records[0]["stderr"]["text"])
                if case != "timeout":
                    kill.assert_not_called()
                original.Popen.assert_called_once()
                self.assertEqual(captured[0][0], (argv,))
                self.assertEqual(
                    captured[0][1]["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
                )
        with tempfile.TemporaryFile() as stderr:
            stderr.write(b"failure")
            stderr.seek(2)
            diagnostics = subject._SubprocessDiagnostics(SimpleNamespace(), token)
            process = subject._DiagnosticProcess(
                SimpleNamespace(wait=lambda **_: 1), diagnostics, ["fixed"], stderr
            )
            self.assertEqual(process.wait(timeout=3), 1)
            self.assertEqual(stderr.tell(), 2)
            self.assertEqual(
                diagnostics.records[0]["stderr"]["digest"], subject._digest(b"failure")
            )
        original = subject.response.subprocess
        fake = SimpleNamespace(
            Popen=Mock(side_effect=OSError("fixed spawn failure")),
            DEVNULL=subprocess.DEVNULL,
        )
        with (
            patch.object(subject.response, "subprocess", fake),
            patch.object(
                subject.response,
                "_read_regular",
                return_value=b"OPENCLAW_GATEWAY_TOKEN=" + token.encode() + b"\n",
            ),
            patch.object(
                subject.prior,
                "_stop_fixture",
                side_effect=lambda: subject.response._command(
                    ["/usr/bin/systemctl", "stop", *subject.prior._ALL_UNITS],
                    timeout=15,
                ),
            ),
        ):
            with self.assertRaisesRegex(OSError, "fixed spawn failure") as caught:
                subject._stop_fixture()
            self.assertIs(subject.response.subprocess, fake)
            self.assertIn("fixture_cleanup", caught.exception.__notes__[0])
            self.assertIn("OSError", caught.exception.__notes__[0])
            fake.Popen.assert_called_once()
        self.assertIs(subject.response.subprocess, original)

    def test_source_catalog_exactly_matches_staged_modules_shims_and_units(self):
        base, replacements = stage._verified_payloads()
        payloads = base | replacements
        self.assertEqual(len(subject._CODE), 10)
        for path, (size, digest, mode) in subject._CODE.items():
            _, actual_mode, raw = payloads[path[1:]]
            self.assertEqual(
                (len(raw), subject._digest(raw), actual_mode),
                (size, "sha256:" + digest, mode),
            )
        path = (
            Path(__file__).resolve().parents[1]
            / "benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs"
        )
        raw = path.read_bytes()
        self.assertEqual((len(raw), subject._digest(raw)), subject._DRIVER_PIN)

    def test_journal_metadata_requires_exact_canonical_single_values_and_window(self):
        processes = _processes()
        captured, _, _ = _captured(processes)
        for role in subject._ROLES:
            rows = subject._rows(
                captured[role]["raw_jsonl"].encode(),
                role,
                processes[role],
                _BOOT,
                100,
                200,
            )
            self.assertEqual(rows, captured[role]["rows"])
        original = captured["sensor"]["rows"][0]["journal"]
        mutations = [
            (key, "wrong")
            for key in (
                "_PID",
                "_UID",
                "_GID",
                "_SYSTEMD_UNIT",
                "_SYSTEMD_INVOCATION_ID",
                "_BOOT_ID",
                "_EXE",
                "_CMDLINE",
                "_TRANSPORT",
            )
        ]
        mutations += [
            ("_PID", [original["_PID"]]),
            ("_UID", 996),
            ("MESSAGE", []),
            ("__CURSOR", "a\nb"),
            ("__MONOTONIC_TIMESTAMP", "99"),
            ("__MONOTONIC_TIMESTAMP", "201"),
            ("__REALTIME_TIMESTAMP", "0"),
            ("MESSAGE", "{}"),
            ("MESSAGE", original["MESSAGE"] + " "),
        ]
        for key, value in mutations:
            with (
                self.subTest(key=key, value=value),
                self.assertRaises((RuntimeError, ValueError, TypeError)),
            ):
                subject._rows(
                    canonical_json({**original, key: value}) + b"\n",
                    "sensor",
                    processes["sensor"],
                    _BOOT,
                    100,
                    200,
                )
        for raw in (
            b"",
            canonical_json(original),
            b"x" * 65537,
            (canonical_json(original) + b"\n") * 9,
            b'{"_PID":"1","_PID":"2"}\n',
            canonical_json(
                {key: value for key, value in original.items() if key != "_GID"}
            )
            + b"\n",
        ):
            with (
                self.subTest(raw=raw[:30]),
                self.assertRaises((RuntimeError, ValueError, TypeError)),
            ):
                subject._rows(raw, "sensor", processes["sensor"], _BOOT, 100, 200)

    def test_pairing_refusal_and_result_join_mutations_fail_closed(self):
        processes = _processes()
        captured, refused, proof = _captured(processes)
        subject._pairs(captured, processes, refused, proof)
        changes = [
            ("worker", 1, key, value)
            for key, value in (
                ("peer_expected", True),
                ("submission", "SEND_ATTEMPTED"),
                ("request_state", "CANONICAL_FRAME_ONLY"),
                ("worker_status", "NOT_SUBMITTED"),
                ("worker_request_digest", _DIGEST),
                ("client_delivery", "SEND_ATTEMPTED"),
                ("stage", "REQUEST"),
                ("handler_status", "RETURNED"),
                ("outcome", "INDETERMINATE"),
            )
        ]
        changes += [
            (role, index, key, value)
            for role, index in (("worker", 3), ("sensor", 1), ("broker", 1))
            for key, value in (
                ("peer", {"pid": 1, "uid": 0, "gid": 0}),
                ("action_request_digest", "sha256:" + "c" * 64),
                ("result_digest", "sha256:" + "d" * 64),
                ("client_delivery", "SEND_ATTEMPTED"),
                ("handler_status", "RAISED"),
                ("stage", "CORE"),
            )
        ]
        changes += [
            ("worker", 3, "worker_request_digest", "wrong"),
            ("sensor", 1, "profile_attribution_digest", "wrong"),
            ("broker", 1, "profile_attribution_digest", "wrong"),
            ("worker", 3, "verdict", "BLOCK"),
            ("sensor", 1, "result_kind", "VALIDATED_BROKER_RESULT"),
        ]
        for role, index, key, value in changes:
            changed = deepcopy(captured)
            changed[role]["rows"][index]["event"][key] = value
            with (
                self.subTest(role=role, index=index, key=key),
                self.assertRaises(RuntimeError),
            ):
                subject._pairs(changed, processes, refused, proof)
        for name in (
            "missing",
            "duplicate-attempt",
            "same-cursor",
            "wrong-start",
            "reversed-time",
        ):
            changed = deepcopy(captured)
            if name == "missing":
                changed["worker"]["rows"].pop()
            elif name == "duplicate-attempt":
                for row in changed["sensor"]["rows"]:
                    row["event"]["attempt_id"] = changed["worker"]["rows"][0]["event"][
                        "attempt_id"
                    ]
            elif name == "same-cursor":
                changed["sensor"]["rows"][0]["journal"]["__CURSOR"] = changed["worker"][
                    "rows"
                ][0]["journal"]["__CURSOR"]
            elif name == "wrong-start":
                changed["sensor"]["rows"][0]["event"]["stage"] = "FRAME"
            else:
                changed["broker"]["rows"][1]["journal"]["__MONOTONIC_TIMESTAMP"] = "0"
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                subject._pairs(changed, processes, refused, proof)

    def test_journal_query_is_bounded_fixed_and_retains_actual_jsonl(self):
        processes = _processes()
        captured, _, _ = _captured(processes)
        calls = []

        def command(argv, *, timeout):
            calls.append((argv, timeout))
            if argv[1] == "--sync":
                return b""
            role = next(
                role
                for role, unit in subject._ROLES.items()
                if "_SYSTEMD_UNIT=" + unit in argv
            )
            self.assertIn(
                "_SYSTEMD_INVOCATION_ID=" + processes[role]["unit"]["InvocationID"],
                argv,
            )
            self.assertIn("_BOOT_ID=" + _BOOT, argv)
            self.assertIn("--after-cursor=s=baseline", argv)
            self.assertIn("--lines=9", argv)
            return captured[role]["raw_jsonl"].encode()

        with (
            patch.object(subject.response, "_command", side_effect=command),
            patch.object(subject.time, "monotonic_ns", return_value=200000),
        ):
            self.assertEqual(
                subject._collect("s=baseline", processes, _BOOT, 100), captured
            )
        self.assertEqual(len(calls), 4)
        with (
            patch.object(subject.response, "_command", return_value=b""),
            patch.object(subject.time, "monotonic", side_effect=[0, 4]),
            self.assertRaisesRegex(RuntimeError, "pairs"),
        ):
            subject._collect("s=baseline", processes, _BOOT, 100)

    def test_actual_receipt_grant_target_and_peer_binding_independent_of_journal(self):
        processes = _processes()
        aliases = {
            "claim-request": ("claim", "profile_claim", "request_digest"),
            "claim-submission": ("claim", "profile_claim", "submission_digest"),
            "result-lease": ("result", "profile_result", "lease_digest"),
            "result-submission": ("result", "profile_result", "submission_digest"),
            "result-verdict": ("result", "profile_result", "verdict"),
            "result-effect": ("result", "profile_result", "effect_status"),
        }
        for failure in (
            None,
            "payload",
            "available",
            "consumed",
            "lease",
            "receipt",
            "attribution",
            "native-correlation",
            "pending",
            "extra-target",
            "broker-accounting",
            *aliases,
        ):
            before, after, driver, proof = _proof_values(processes)
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                receipt = root / "receipt.json"
                target = root / "runtime-worker-qualified.txt"
                state = root / "state.json"
                receipt.write_bytes(canonical_json(proof["receipt"]))
                target.write_bytes(
                    b"benign fixture\n" if failure != "payload" else b"changed"
                )
                state.write_bytes(
                    canonical_json(
                        {
                            "consumed": []
                            if failure == "broker-accounting"
                            else [
                                {
                                    "request_digest": _DIGEST,
                                    "observation_digest": "sha256:" + "f" * 64,
                                }
                            ],
                            "effect_journal": None,
                        }
                    )
                )
                for path in (receipt, target, state):
                    path.chmod(0o400)
                p37b = SimpleNamespace(
                    lineage=SimpleNamespace(
                        _RECEIPT=receipt, _PROTECTED=root, _CONTROL=root
                    ),
                    _TARGET=target.name,
                    _PAYLOAD=b"benign fixture\n",
                    _driver_gateway_pid=lambda _: 100,
                )
                if failure == "available":
                    before["grant_state"]["document"]["claim"] = {}
                elif failure == "consumed":
                    after["grant_state"]["document"]["status"] = "CLAIMED"
                elif failure == "lease":
                    after["grant_state"]["document"]["claim"]["lease_digest"] = "wrong"
                elif failure == "receipt":
                    after["grant_state"]["document"]["result"]["profile_result"][
                        "profile_receipt_digest"
                    ] = "wrong"
                elif failure == "attribution":
                    processes = deepcopy(processes)
                    processes["worker"]["process"]["pid"] = 999
                elif failure == "native-correlation":
                    driver["output"]["turn"]["identifiers"]["run_id"] = "wrong"
                elif failure == "pending":
                    after["pending_exists"] = True
                elif failure == "extra-target":
                    after["protected_entries"].append("extra")
                elif failure in aliases:
                    outer, inner, key = aliases[failure]
                    after["grant_state"]["document"][outer][inner][key] = {
                        "verdict": "BLOCK",
                        "effect_status": "NOT_PERFORMED",
                    }.get(key, "sha256:" + "e" * 64)
                with (
                    self.subTest(failure=failure),
                    patch.object(
                        subject.response,
                        "_identities",
                        return_value=(
                            os.geteuid(),
                            997,
                            os.getegid(),
                            992,
                            992,
                            996,
                            996,
                        ),
                    ),
                ):
                    if failure:
                        with self.assertRaises(RuntimeError):
                            subject._proof(p37b, driver, before, after, processes)
                    else:
                        result = subject._proof(p37b, driver, before, after, processes)
                        self.assertEqual(result["receipt"], proof["receipt"])
                        self.assertEqual(
                            result["target_digest"],
                            subject._digest(b"benign fixture\n"),
                        )
            processes = _processes()

    def test_full_orchestration_cleanup_and_proof_ceilings(self):
        with _environment() as mocks:
            result = subject._run(_CONTAINER)
            mocks["_prepare"].assert_called_once_with(publish_revocation=False)
            mocks["_stop_fixture"].assert_called_once()
        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(result["fixture_container"], _CONTAINER)
        for key in (
            "phase3_eligible",
            "run_conformance_eligible",
            "durable_event_retention",
            "complete_event_coverage",
        ):
            self.assertIs(result[key], False)
        for name in (
            "_prepare",
            "_installed",
            "_action",
            "_proof",
            "_collect",
            "_processes",
            "_boot",
            "refusal",
            "_stop_fixture",
        ):
            with self.subTest(name=name), _environment() as mocks:
                mocks[name].side_effect = RuntimeError("injected " + name)
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    subject._run(_CONTAINER)
                mocks["_stop_fixture"].assert_called_once()
        for failure in ("_require_fixture", "_sources"):
            with self.subTest(pre_setup=failure), _environment() as mocks:
                mocks[failure].side_effect = RuntimeError("pre-setup refusal")
                with self.assertRaisesRegex(RuntimeError, "pre-setup refusal"):
                    subject._run(_CONTAINER)
                mocks["_stop_fixture"].assert_not_called()
                mocks["_prepare"].assert_not_called()
        with _environment() as mocks:
            first, cleanup = (
                RuntimeError("first failure"),
                RuntimeError("cleanup failure"),
            )
            subject._note(first, [{"operation": "native_driver"}])
            subject._note(cleanup, [{"operation": "fixture_cleanup"}])
            mocks["_action"].side_effect = first
            mocks["_stop_fixture"].side_effect = cleanup
            with self.assertRaisesRegex(
                RuntimeError, "first failure.*cleanup failure"
            ) as caught:
                subject._run(_CONTAINER)
            self.assertEqual(
                caught.exception.__notes__, first.__notes__ + cleanup.__notes__
            )
        for name in ("_sources", "_processes", "_boot", "_installed"):
            with self.subTest(drift=name), _environment() as mocks:
                initial = mocks[name].return_value
                mocks[name].side_effect = [initial, {}]
                with self.assertRaises(RuntimeError):
                    subject._run(_CONTAINER)
                mocks["_stop_fixture"].assert_called_once()

    def test_main_fixed_arguments_bounded_diagnostic_and_no_success_on_error(self):
        for argv in ([], [_CONTAINER, "extra"]):
            with patch.object(subject, "_run") as run, redirect_stderr(StringIO()):
                self.assertEqual(subject.main(argv), 64)
                run.assert_not_called()
        output, error = StringIO(), StringIO()
        with (
            patch.object(
                subject, "_run", side_effect=RuntimeError("fixed reason\n" + "x" * 2000)
            ),
            redirect_stdout(output),
            redirect_stderr(error),
        ):
            self.assertEqual(subject.main([_CONTAINER]), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("fixed reason", error.getvalue())
        self.assertLess(len(error.getvalue()), 1150)
        failure = RuntimeError("original refusal")
        subject._note(
            failure,
            [
                {
                    "operation": "native_driver",
                    "stderr": subject._diagnostic_bytes(
                        b"failed\x1b " + b"f" * 64, "f" * 64
                    ),
                }
            ],
        )
        output, error = StringIO(), StringIO()
        with (
            patch.object(subject, "_run", side_effect=failure),
            redirect_stdout(output),
            redirect_stderr(error),
        ):
            self.assertEqual(subject.main([_CONTAINER]), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("f" * 64, error.getvalue())
        self.assertNotIn("\x1b", error.getvalue())
        self.assertIn("native_driver", error.getvalue())
        self.assertIn("[REDACTED]", error.getvalue())


if __name__ == "__main__":
    unittest.main()
