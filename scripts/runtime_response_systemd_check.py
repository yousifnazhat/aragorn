"""One fixed-profile Linux stop/revoke integration observation, not qualification."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any

sys.path.insert(0, "/usr/lib/aragorn")

from aragorn import runtime_response_service as response
from aragorn.oci_worker_protocol import canonical_json
from aragorn.runtime_process_profile import _read_virtual_file

_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


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


def _run(skill: str, snapshot: str) -> dict[str, Any]:
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
        positive = _invoke(["--prevent-starts", skill, snapshot])
        _expect(
            positive["exit_code"] == 0 and not positive["stderr"],
            "stop/revoke response was not confirmed: " + positive["stderr"][:2048],
        )
        raw = positive["stdout"].encode("ascii")
        _expect(raw.endswith(b"\n"), "response output is not newline terminated")
        result = response.broker._parse_canonical_document(raw[:-1], "response result")
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
    return {
        "schema": "aragorn/runtime-response-systemd-integration-observation/v1",
        "authority": "LOCAL_FIXED_PROFILE_INTEGRATION_OBSERVATION_NOT_RUN_OR_PHASE3_QUALIFICATION",
        "status": "OBSERVED",
        "before": before,
        "extra_gateway_cgroup_member": child_before,
        "wrong_skill_refusal": negative,
        "response_invocation": positive,
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


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 2:
        print(
            "usage: runtime-response-systemd-check EXPECTED_SKILL_DIGEST EXPECTED_REVOCATION_SNAPSHOT_DIGEST",
            file=sys.stderr,
        )
        return 64
    try:
        print(canonical_json(_run(*arguments)).decode("ascii"))
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
