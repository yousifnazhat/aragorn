"""One fixed-profile Linux stop/revoke integration observation, not qualification."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any

sys.path.insert(0, "/usr/lib/aragorn")

from aragorn import runtime_response_service as response
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_process_profile import _read_virtual_file

_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
_PUBLISHER = "aragorn-runtime-revocation-publisher.service"
_DISPATCH = "aragorn-runtime-revocation-response.service"
_PUBLICATION = Path("/etc/aragorn/runtime-action-revocation-publication.json")


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _running(identities: tuple[int, ...]) -> list[dict[str, Any]]:
    result = []
    for unit, (uid, gid) in zip(
        response._UNITS,
        ((identities[3], identities[4]), (identities[1], identities[2])),
        strict=True,
    ):
        state = response._unit_state(unit)
        result.append(
            {
                "unit": state,
                "process": response._process_identity(unit, state, uid, gid),
            }
        )
    return result


def _child_identity(
    process: subprocess.Popen[bytes], uid: int, gid: int
) -> dict[str, Any]:
    _expect(process.poll() is None, "fixture child exited before response")
    started = response._process_start_time(process.pid)
    response._require_process_status(process.pid, uid, gid)
    cgroup = response._process_cgroup(process.pid)
    _expect(
        cgroup == response._service_cgroup(response._UNITS[0])
        and _read_virtual_file(Path(f"/proc/{process.pid}/cmdline"), 4096)
        == b"/usr/bin/sleep\x00600\x00"
        and response._process_start_time(process.pid) == started,
        "fixture child identity is not the fixed gateway-cgroup sleeper",
    )
    return {
        "pid": process.pid,
        "start_time_ticks": started,
        "uid": uid,
        "gid": gid,
        "cgroup": cgroup,
    }


@contextmanager
def _gateway_child(uid: int, gid: int):
    # ponytail: one owned extra cgroup member; this is not gateway child genealogy.
    process = subprocess.Popen(
        [
            "/usr/bin/setpriv",
            f"--reuid={uid}",
            f"--regid={gid}",
            "--clear-groups",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--no-new-privs",
            "/usr/bin/sleep",
            "600",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=_ENV,
        start_new_session=True,
    )
    try:
        path = (
            response._CGROUP_ROOT
            / response._service_cgroup(response._UNITS[0]).lstrip("/")
            / "cgroup.procs"
        )
        descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            raw = str(process.pid).encode("ascii")
            _expect(
                os.write(descriptor, raw) == len(raw),
                "fixture cgroup move was incomplete",
            )
        finally:
            os.close(descriptor)
        deadline = time.monotonic() + 2
        while True:
            _expect(process.poll() is None, "fixture child failed to start")
            if (
                _read_virtual_file(Path(f"/proc/{process.pid}/cmdline"), 4096)
                == b"/usr/bin/sleep\x00600\x00"
            ):
                break
            _expect(time.monotonic() < deadline, "fixture child did not become sleep")
            time.sleep(0.01)
        yield process, _child_identity(process, uid, gid)
    finally:
        # Popen owns this unreaped child; never signal a caller-supplied PID.
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


def _invoke(arguments: list[str]) -> dict[str, Any]:
    stdout, stderr = StringIO(), StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = response.main(arguments)
    return {
        "argv": arguments,
        "exit_code": status,
        "stdout": stdout.getvalue(),
        "stderr": stderr.getvalue(),
    }


def _start_refused() -> dict[str, Any]:
    for unit in response._UNITS:
        path = Path("/etc/systemd/system") / unit
        _expect(
            path.is_symlink() and os.readlink(path) == "/dev/null",
            "persistent fixed-unit mask is missing",
        )
    argv = [
        "/usr/bin/systemctl",
        "--system",
        "--no-pager",
        "--no-ask-password",
        "start",
        *response._UNITS,
    ]
    result = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
        env=_ENV,
        check=False,
    )
    _expect(
        result.returncode != 0
        and not result.stdout
        and len(result.stderr) <= 4096
        and b"masked" in result.stderr,
        "direct fixed-profile start was not refused by systemd masks",
    )
    return {
        "argv": argv,
        "exit_code": result.returncode,
        "stdout": "",
        "stderr": result.stderr.decode("ascii"),
    }


def _retained_response(
    envelope: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    result = envelope["response"]
    raw = canonical_json(result)
    expected = {
        "cas_root": str(response._EVIDENCE_ROOT),
        "digest": canonical_digest(result),
        "bytes": len(raw),
        "readback_verified": True,
        "blob_and_directory_chain_fsynced": True,
    }
    _expect(
        set(envelope) == {"schema", "authority", "response", "evidence"}
        and envelope["schema"] == "aragorn/retained-runtime-response/v1"
        and envelope["authority"]
        == "LOCAL_ROOT_EVIDENCE_RETENTION_NOT_INDEPENDENT_QUALIFICATION"
        and canonical_json(envelope["evidence"]) == canonical_json(expected),
        "retained response envelope changed",
    )
    # Read from a separate process, not the writer's in-memory return value.
    program = "import sys;sys.path.insert(0,'/usr/lib/aragorn');from aragorn.cas import CAS;sys.stdout.buffer.write(CAS('/var/lib/aragorn-runtime-response',read_only=True).read(sys.argv[1],max_bytes=131072))"
    readback = subprocess.run(
        ["/usr/bin/python3.12", "-I", "-S", "-B", "-c", program, expected["digest"]],
        capture_output=True,
        timeout=5,
        check=False,
        env=_ENV,
    )
    _expect(
        readback.returncode == 0 and not readback.stderr and readback.stdout == raw,
        "separate-process evidence readback changed",
    )
    _expect(
        response._retain_result(result) == envelope,
        "deduplicated evidence retention changed",
    )
    return result, {
        **expected,
        "separate_process_readback": True,
        "deduplication_checked": True,
    }


def _service_state(unit: str) -> dict[str, str]:
    _expect(unit in {_PUBLISHER, _DISPATCH}, "unsupported fixture service")
    properties = (
        "Id",
        "InvocationID",
        "ActiveState",
        "SubState",
        "ControlPID",
        "ExecMainStatus",
        "Result",
    )
    raw = response._command(
        ["/usr/bin/systemctl", "show", "--property=" + ",".join(properties), unit],
        timeout=3,
    )
    pairs = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
    _expect(all(len(pair) == 2 for pair in pairs), "malformed service properties")
    state = dict(pairs)
    _expect(
        len(pairs) == len(properties)
        and set(state) == set(properties)
        and state["Id"] == unit,
        "incomplete or unbound service properties",
    )
    return state


def _wait_dispatch(previous: str = "", *, start_pre: bool = False) -> dict[str, str]:
    deadline = time.monotonic() + (3 if start_pre else 45)
    seen = ""
    while True:
        state = _service_state(_DISPATCH)
        if state["ActiveState"] == "failed" or time.monotonic() >= deadline:
            try:
                journal = response._command(
                    [
                        "/usr/bin/journalctl",
                        "--no-pager",
                        "--output=cat",
                        "-u",
                        _DISPATCH,
                        "-n",
                        "12",
                    ],
                    timeout=5,
                ).decode("utf-8", errors="replace")[-4096:]
            except (RuntimeError, OSError) as exc:
                journal = str(exc)
            raise RuntimeError(f"automatic response incomplete: {state}: {journal}")
        if (
            re.fullmatch(r"[0-9a-f]{32}", state["InvocationID"])
            and state["InvocationID"] != previous
        ):
            seen = state["InvocationID"]
            if start_pre and state["SubState"] == "start-pre":
                _expect(
                    state["ActiveState"] == "activating"
                    and int(state["ControlPID"]) > 0,
                    "dispatch fixture delay is not running",
                )
                return state
        if not start_pre and seen and state["ActiveState"] == "inactive":
            _expect(
                state["InvocationID"] in {"", seen}
                and state["SubState"] == "dead"
                and state["ExecMainStatus"] == "0"
                and state["Result"] == "success"
                and state["ControlPID"] == "0",
                "automatic response did not complete successfully",
            )
            return {**state, "observed_invocation_id": seen}
        time.sleep(0.02)


def _journal_result(
    unit: str, invocation: str = "", *, generation: int | None = None
) -> dict[str, Any]:
    _expect(
        unit in {_PUBLISHER, _DISPATCH}
        and (
            re.fullmatch(r"[0-9a-f]{32}", invocation) is not None
            or (not invocation and unit == _PUBLISHER and generation in {2, 3})
        ),
        "journal selection is not a fixed service invocation",
    )
    response._command(["/usr/bin/journalctl", "--sync"], timeout=5)
    raw = response._command(
        [
            "/usr/bin/journalctl",
            "--quiet",
            "--all",
            "--no-pager",
            "--output=json",
            "--output-fields=MESSAGE,_SYSTEMD_INVOCATION_ID,_SYSTEMD_UNIT",
            "_SYSTEMD_UNIT=" + unit,
            *(["_SYSTEMD_INVOCATION_ID=" + invocation] if invocation else []),
        ],
        timeout=5,
    )
    results = []
    for line in raw.splitlines():
        entry = json.loads(line)
        actual = entry.get("_SYSTEMD_INVOCATION_ID")
        _expect(
            entry.get("_SYSTEMD_UNIT") == unit
            and isinstance(actual, str)
            and re.fullmatch(r"[0-9a-f]{32}", actual) is not None
            and (not invocation or actual == invocation)
            and isinstance(entry.get("MESSAGE"), str),
            "journal result identity changed",
        )
        document = response.broker._parse_canonical_document(
            entry["MESSAGE"].encode("ascii"), "service journal result"
        )
        if generation is None or document.get("generation") == generation:
            results.append(
                {
                    "unit": unit,
                    "invocation_id": actual,
                    "journal": entry,
                    "result": document,
                }
            )
    _expect(len(results) == 1, "service journal does not contain one exact result")
    return results[0]


def _dispatch_publications(skill: str, snapshot: str) -> tuple[dict, dict, str]:
    first = response.broker._parse_canonical_document(
        response._read_regular(_PUBLICATION, 0, {0o400}), "fixture publication"
    )
    _expect(
        canonical_digest(first) == snapshot
        and first["skill_digests"] == []
        and first["generation"] == 2,
        "initial dispatch publication changed",
    )
    argv = ["/usr/bin/systemctl", "start", _PUBLISHER]
    response._command(argv, timeout=10)
    first_publisher = _service_state(_PUBLISHER)
    first_dispatch = _wait_dispatch(start_pre=True)
    now = int(time.time())
    second = {
        **first,
        "generation": 3,
        "observed_at_unix": now,
        "expires_at_unix": now + 15,
        "skill_digests": [skill],
    }
    # The first publisher exited, so its LoadCredential copy is already fixed.
    with _PUBLICATION.open("wb") as stream:
        stream.write(canonical_json(second))
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_ENV,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 1
        while True:
            jobs = response._command(
                [
                    "/usr/bin/systemctl",
                    "list-jobs",
                    "--no-legend",
                    "--no-pager",
                    "--plain",
                ],
                timeout=3,
            ).decode("ascii")
            if any(
                fields[1:] == [_PUBLISHER, "start", "waiting"]
                for fields in (line.split() for line in jobs.splitlines())
            ):
                break
            _expect(
                time.monotonic() < deadline,
                "next publication was not queued behind response",
            )
            time.sleep(0.01)
        held = _service_state(_DISPATCH)
        _expect(
            process.poll() is None
            and held["InvocationID"] == first_dispatch["InvocationID"]
            and held["SubState"] == "start-pre"
            and _service_state(_PUBLISHER) == first_publisher,
            "publication ran before the previous response completed",
        )
        stdout, stderr = process.communicate(timeout=45)
        _expect(
            process.returncode == 0 and not stdout and not stderr,
            "second fixture publication failed",
        )
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=2)
    final = _wait_dispatch(first_dispatch["InvocationID"])
    receipts = []
    for document, dispatch_id in (
        (first, first_dispatch["InvocationID"]),
        (second, final["observed_invocation_id"]),
    ):
        publication = _journal_result(_PUBLISHER, generation=document["generation"])
        receipt = _journal_result(_DISPATCH, dispatch_id)
        envelope = receipt["result"]
        result, retention = _retained_response(envelope)
        expected_digest = canonical_digest(document)
        _expect(
            publication["result"]["schema"]
            == "aragorn/runtime-revocation-publication-result/v1"
            and publication["result"]["generation"] == document["generation"]
            and publication["result"]["revocations_digest"] == expected_digest
            and result["expected_skill_digest"] == skill
            and result["revocation_snapshot_digest"] == expected_digest
            and result["accepted_revocation"]["generation"] == document["generation"],
            "automatic response did not join its accepted publication",
        )
        receipts.append(
            {"publication": publication, "response": receipt, "retention": retention}
        )
    _expect(
        receipts[0]["publication"]["invocation_id"]
        != receipts[1]["publication"]["invocation_id"],
        "publication invocation did not advance",
    )
    noop = receipts[0]["response"]["result"]["response"]
    _expect(
        noop["status"] == "NO_REVOCATION_FOR_ACTIVE_PROFILE"
        and noop["before"] == noop["after"]
        and "future_start_barrier" not in noop,
        "nonrevoking publication was not a no-op",
    )
    positive = {
        "argv": ["--dispatch"],
        "exit_code": int(final["ExecMainStatus"]),
        "stdout": canonical_json(receipts[1]["response"]["result"]).decode("ascii")
        + "\n",
        "stderr": "",
        "service": final,
    }
    return (
        positive,
        {
            "first_dispatch_start_pre": first_dispatch,
            "second_publisher_waiting_jobs": jobs,
            "held_dispatch": held,
            "publications": [first, second],
            "invocations": receipts,
        },
        canonical_digest(second),
    )


def _run(skill: str, snapshot: str, *, dispatch: bool = False) -> dict[str, Any]:
    response.broker._require_digest(skill, "expected skill digest")
    response.broker._require_digest(snapshot, "expected snapshot digest")
    _expect(
        sys.platform == "linux" and os.geteuid() == 0,
        "root Linux execution is required",
    )
    identities = response._identities()
    before = _running(identities)
    wrong = "sha256:" + ("0" if skill[7] != "0" else "1") + skill[8:]
    with _gateway_child(identities[3], identities[4]) as (child, child_before):
        negative = _invoke([wrong, snapshot])
        _expect(
            negative["exit_code"] == 126
            and not negative["stdout"]
            and negative["stderr"]
            == "aragorn runtime response: REFUSED: requested digest is not the running binding\n",
            "wrong-skill response did not refuse for the expected binding mismatch",
        )
        _expect(
            _running(identities) == before,
            "wrong-skill request changed the running profile",
        )
        _expect(
            _child_identity(child, identities[3], identities[4]) == child_before,
            "wrong-skill request changed the fixture child",
        )
        dispatch_proof = None
        if dispatch:
            positive, dispatch_proof, snapshot = _dispatch_publications(skill, snapshot)
        else:
            positive = _invoke(
                ["--prevent-starts", "--retain-evidence", skill, snapshot]
            )
        _expect(
            positive["exit_code"] == 0 and not positive["stderr"],
            "stop/revoke response was not confirmed: " + positive["stderr"][:2048],
        )
        raw = positive["stdout"].encode("ascii")
        _expect(raw.endswith(b"\n"), "response output is not newline terminated")
        envelope = response.broker._parse_canonical_document(
            raw[:-1], "response result"
        )
        if dispatch_proof is not None:
            result = envelope["response"]
            retention = dispatch_proof["invocations"][1]["retention"]
            _expect(
                result["before"] == before
                and dispatch_proof["invocations"][0]["response"]["result"]["response"][
                    "before"
                ]
                == before,
                "automatic dispatch changed the initial runtime identity",
            )
        else:
            result, retention = _retained_response(envelope)
        _expect(
            result["status"] == "TERMINATED_AND_REVOKED_FIXED_RUNTIME_PROFILE"
            and result["expected_skill_digest"] == skill
            and result["revocation_snapshot_digest"] == snapshot,
            "response result does not join the requested stop/revoke operation",
        )
        _expect(
            child.wait(timeout=3) < 0, "fixture child was not terminated by a signal"
        )
        start = _start_refused()
        cgroups = [
            response._cgroup_empty(unit, item["unit"])
            for unit, item in zip(response._UNITS, before, strict=True)
        ]
        _expect(
            all(item["status"] in {"EMPTY", "ABSENT"} for item in cgroups),
            "runtime cgroups are not empty after refused restart",
        )
    observation = {
        "schema": "aragorn/runtime-response-systemd-integration-observation/v1",
        "authority": "LOCAL_FIXED_PROFILE_INTEGRATION_OBSERVATION_NOT_RUN_OR_PHASE3_QUALIFICATION",
        "status": "OBSERVED",
        "before": before,
        "extra_gateway_cgroup_member": child_before,
        "wrong_skill_refusal": negative,
        "response_invocation": positive,
        "evidence_retention": retention,
        "direct_start_refusal": start,
        "cgroups_after_refused_start": cgroups,
        "extra_gateway_cgroup_member_exit_code": child.returncode,
        "run_conformance_eligible": False,
        "phase3_eligible": False,
        "limitations": [
            "ONE_MANUAL_ROOT_COMMAND_IN_A_LOCAL_SYSTEMD_FIXTURE",
            "EXTRA_CGROUP_MEMBER_NOT_GATEWAY_CHILD_GENEALOGY",
            "PERSISTENT_FIXED_PROFILE_MASK_NOT_INSTALLED_DIGEST_QUARANTINE",
            "NO_AUTOMATIC_RESPONSE_DISPATCH_OR_INDEPENDENT_QUALIFICATION",
        ],
    }
    if dispatch:
        observation["automatic_dispatch"] = dispatch_proof
        observation["limitations"][0] = (
            "TWO_ORDERED_PUBLICATIONS_IN_A_LOCAL_SYSTEMD_FIXTURE"
        )
        observation["limitations"][-1] = (
            "NO_INDEPENDENT_QUALIFICATION_OR_EVENT_DETECTION_CLAIM"
        )
    return observation


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    dispatch = bool(arguments and arguments[0] == "--dispatch")
    if dispatch:
        arguments.pop(0)
    if len(arguments) != 2:
        print(
            "usage: runtime-response-systemd-check [--dispatch] EXPECTED_SKILL_DIGEST EXPECTED_REVOCATION_SNAPSHOT_DIGEST",
            file=sys.stderr,
        )
        return 64
    try:
        print(canonical_json(_run(*arguments, dispatch=dispatch)).decode("ascii"))
        return 0
    except (
        OSError,
        ValueError,
        KeyError,
        RuntimeError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"runtime response integration not confirmed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
