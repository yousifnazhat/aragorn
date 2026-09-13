"""Observe fixed endpoint journal pairs in one disposable systemd fixture."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path[:0] = [
    "/usr/lib/aragorn",
    str(Path(__file__).resolve().parent),
    "/src/scripts",
]

# The shared capture retains the older helper's hyphenated installed filename.
_SHARED = Path(__file__).with_name("runtime-quarantine-systemd-check.py")
if _SHARED.exists():
    _SPEC = importlib.util.spec_from_file_location("_journal_fixture_setup", _SHARED)
    assert _SPEC is not None and _SPEC.loader is not None
    prior = importlib.util.module_from_spec(_SPEC)
    _SPEC.loader.exec_module(prior)
else:
    import runtime_quarantine_systemd_check as prior

from aragorn import runtime_endpoint_journal as journal
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_process_profile import _read_virtual_file

response = prior.response
_ROLES = {"worker": prior._WORKER, "sensor": prior._SENSOR, "broker": prior._BROKER}
_COMMANDS = {
    "worker": ("aragorn-runtime-action-worker-service.py", ("worker-binding",)),
    "sensor": (
        "aragorn-runtime-observation-service-v4.py",
        ("observation-binding", "capability-grant"),
    ),
    "broker": (
        "aragorn-runtime-action-service-v5.py",
        ("runtime-binding", "capability-grant"),
    ),
}
_CODE = {
    "/usr/lib/aragorn/aragorn/runtime_action_worker.py": (
        38599,
        "1a03136a202e5e9f758175b0de9905f1aa1cee3e8e540fc063f8136f7f3b3bf4",
        0o644,
    ),
    "/usr/lib/aragorn/aragorn/runtime_action_observation_publisher_v4.py": (
        12882,
        "becb54691aba35e902c6c65c7a459ccd2e1aeef6018f679c918826e84c18a34b",
        0o644,
    ),
    "/usr/lib/aragorn/aragorn/runtime_action_broker_v5.py": (
        11716,
        "fe0861eec5a3439b142d81e59d50f02516b8ca346408e18465f5276bc60ec496",
        0o644,
    ),
    "/usr/lib/aragorn/aragorn/runtime_endpoint_journal.py": (
        13110,
        "19221eb7c3ed6ce74122e544b776447ccd72e7f966671f922dffd6c4e344b569",
        0o644,
    ),
    "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py": (
        338,
        "5274f51d50293ba7559c6348fe79c5eb43753ecb09024525cfd09c368cc360f8",
        0o755,
    ),
    "/usr/libexec/aragorn/aragorn-runtime-observation-service-v4.py": (
        356,
        "dba9cf34f9103073f9583f29bf0a83ae7f3162ca511ec2d76ec250ab161167cf",
        0o755,
    ),
    "/usr/libexec/aragorn/aragorn-runtime-action-service-v5.py": (
        349,
        "9dd8e3836176e3d2a6d2ab8d6a036e078dd868a188f10a74d3808b51290405fc",
        0o755,
    ),
    "/usr/lib/systemd/system/aragorn-runtime-action-worker.service": (
        2750,
        "4572460c7d54e29f8608fa16c9d97e645c2b32ea233377b5ae38e130461817d7",
        0o644,
    ),
    "/usr/lib/systemd/system/aragorn-runtime-lineage-capability-observation-publisher.service": (
        2777,
        "f48258b00213c2c1ff4c5c95d0f1c446f78593d1d04780719cba79bf8dd73d8a",
        0o644,
    ),
    "/usr/lib/systemd/system/aragorn-runtime-lineage-capability-action-broker.service": (
        2725,
        "e0273dbeb4ed40a203193a52eb6146f81ecbc6abca605fa0bfff69774676b2db",
        0o644,
    ),
}
_JOURNAL_FIELDS = (
    "MESSAGE",
    "_PID",
    "_UID",
    "_GID",
    "_SYSTEMD_UNIT",
    "_SYSTEMD_INVOCATION_ID",
    "_BOOT_ID",
    "_TRANSPORT",
    "_EXE",
    "_CMDLINE",
    "__CURSOR",
    "__MONOTONIC_TIMESTAMP",
    "__REALTIME_TIMESTAMP",
)
_PROPERTIES = (
    "Id",
    "MainPID",
    "ControlPID",
    "ControlGroup",
    "InvocationID",
    "ActiveState",
    "SubState",
    "User",
    "Group",
    "StandardOutput",
    "ExecStart",
    "FragmentPath",
    "DropInPaths",
)
_DRIVER_PIN = (
    39431,
    "sha256:e6e1803e9593d8c1bcb1ad4a3fdf2cb5c3657f1b4bd06e65470b8ad16e9e0140",
)


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _sources() -> dict[str, Any]:
    result = {}
    for name, (size, digest, mode) in _CODE.items():
        path = Path(name)
        before = path.lstat()
        raw = response._read_regular(path, 0, {mode})
        _expect(
            path.resolve(strict=True) == path
            and before.st_gid == 0
            and response.broker._file_identity(before)
            == response.broker._file_identity(path.lstat())
            and len(raw) == size
            and _digest(raw) == "sha256:" + digest,
            "installed journal producer source changed",
        )
        result[name] = {
            "bytes": size,
            "digest": _digest(raw),
            "identity": list(response.broker._file_identity(before)),
        }
    return result


def _boot() -> str:
    raw = _read_virtual_file(Path("/proc/sys/kernel/random/boot_id"), 64)
    _expect(
        re.fullmatch(rb"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\n", raw)
        is not None,
        "boot identity is malformed",
    )
    return raw.decode("ascii").strip().replace("-", "")


def _processes(container: str) -> dict[str, Any]:
    broker, worker, worker_gid, gateway, gateway_gid, sensor, sensor_gid = (
        response._identities()
    )
    expected = {
        "worker": (worker, worker_gid, "aragorn-runtime", "aragorn-runtime"),
        "sensor": (sensor, sensor_gid, "aragorn-sensor", "aragorn-sensor"),
        "broker": (broker, worker_gid, "aragorn-broker", "aragorn-runtime"),
    }
    # Existing production helpers deliberately support only gateway and worker.
    gateway_state = response._unit_state(prior._GATEWAY)
    result = {
        "gateway": {
            "unit": gateway_state,
            "process": response._process_identity(
                prior._GATEWAY, gateway_state, gateway, gateway_gid
            ),
        }
    }
    for role, unit in _ROLES.items():
        raw = response._command(
            ["/usr/bin/systemctl", "show", "--property=" + ",".join(_PROPERTIES), unit],
            timeout=3,
        )
        pairs = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
        _expect(all(len(pair) == 2 for pair in pairs), "unit state is malformed")
        state = dict(pairs)
        _expect(
            len(pairs) == len(_PROPERTIES) and set(state) == set(_PROPERTIES),
            "unit state fields changed",
        )
        uid, gid, user, group = expected[role]
        cgroup = f"/docker/{container}/system.slice/{unit}"
        _expect(
            re.fullmatch(r"[1-9][0-9]*", state["MainPID"]) is not None,
            "endpoint PID is invalid",
        )
        pid = int(state["MainPID"])
        shim, credentials = _COMMANDS[role]
        argv = [
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "/usr/libexec/aragorn/" + shim,
            *[f"/run/credentials/{unit}/{name}" for name in credentials],
        ]
        _expect(
            state["Id"] == unit
            and state["ActiveState"] == "active"
            and state["SubState"] == "running"
            and state["ControlPID"] == "0"
            and state["ControlGroup"] == cgroup
            and state["User"] == user
            and state["Group"] == group
            and state["StandardOutput"] == "journal"
            and state["DropInPaths"] == ""
            and Path(state["FragmentPath"]).resolve(strict=True)
            == Path("/usr/lib/systemd/system") / unit
            and re.fullmatch(r"[0-9a-f]{32}", state["InvocationID"]) is not None
            and state["InvocationID"] != "0" * 32
            and state["ExecStart"].startswith(
                "{ path=/usr/bin/python3.12 ; argv[]="
                + " ".join(argv)
                + " ; ignore_errors=no ; "
            )
            and state["ExecStart"].count("argv[]=") == 1,
            "endpoint unit identity changed",
        )
        started = response._process_start_time(pid)
        fields = dict(
            line.split(":", 1)
            for line in _read_virtual_file(Path(f"/proc/{pid}/status"), 8192)
            .decode("ascii")
            .splitlines()
            if ":" in line
        )
        uids = [int(value) for value in fields["Uid"].split()]
        gids = [int(value) for value in fields["Gid"].split()]
        command = _read_virtual_file(Path(f"/proc/{pid}/cmdline"), 4096)
        executable = os.readlink(f"/proc/{pid}/exe")
        _expect(
            uids == [uid, uid, uid, worker if role == "sensor" else uid]
            and gids == [gid, gid, gid, worker_gid if role == "sensor" else gid]
            and command == b"\0".join(item.encode("ascii") for item in argv) + b"\0"
            and executable == str(Path("/usr/bin/python3.12").resolve(strict=True))
            and response._process_cgroup(pid) == cgroup
            and response._process_start_time(pid) == started
            and re.fullmatch(
                r"socket:\[[1-9][0-9]*\]", os.readlink(f"/proc/{pid}/fd/1")
            )
            is not None,
            "endpoint kernel process identity changed",
        )
        result[role] = {
            "unit": state,
            "process": {
                "pid": pid,
                "uid": uid,
                "gid": gid,
                "uids": uids,
                "gids": gids,
                "start_time_ticks": started,
                "cgroup": cgroup,
                "executable": executable,
                "command": " ".join(argv),
            },
        }
    _expect(
        len({entry["process"]["pid"] for entry in result.values()}) == 4,
        "fixture processes are not distinct",
    )
    return result


def _cursor() -> str:
    response._command(["/usr/bin/journalctl", "--sync"], timeout=5)
    raw = response._command(
        ["/usr/bin/journalctl", "-n", "0", "--show-cursor", "--no-pager"], timeout=3
    ).decode("ascii")
    lines = [
        line.removeprefix("-- cursor: ")
        for line in raw.splitlines()
        if line.startswith("-- cursor: ")
    ]
    _expect(
        len(lines) == 1
        and re.fullmatch(r"[A-Za-z0-9;=_-]{1,1024}", lines[0]) is not None,
        "journal baseline cursor is invalid",
    )
    return lines[0]


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value = dict(pairs)
    _expect(len(value) == len(pairs), "duplicate journal JSON field")
    return value


def _rows(
    raw: bytes, role: str, process: dict, boot: str, lower: int, upper: int
) -> list[dict]:
    _expect(
        len(raw) <= 65536 and raw.endswith(b"\n") and len(raw.splitlines()) <= 8,
        "journal query is empty, truncated, or oversized",
    )
    result = []
    for line in raw.splitlines():
        row = json.loads(line, object_pairs_hook=_object)
        _expect(
            type(row) is dict
            and set(row) == set(_JOURNAL_FIELDS)
            and all(type(value) is str for value in row.values()),
            "journal metadata is incomplete or multivalued",
        )
        identity, unit = process["process"], process["unit"]
        _expect(
            row["_PID"] == str(identity["pid"])
            and row["_UID"] == str(identity["uid"])
            and row["_GID"] == str(identity["gid"])
            and row["_SYSTEMD_UNIT"] == _ROLES[role]
            and row["_SYSTEMD_INVOCATION_ID"] == unit["InvocationID"]
            and row["_BOOT_ID"] == boot
            and row["_TRANSPORT"] == "stdout"
            and row["_EXE"] == identity["executable"]
            and row["_CMDLINE"] == identity["command"]
            and re.fullmatch(r"[A-Za-z0-9;=_-]{1,1024}", row["__CURSOR"]) is not None
            and re.fullmatch(r"[1-9][0-9]*", row["__REALTIME_TIMESTAMP"]) is not None
            and re.fullmatch(r"[0-9]+", row["__MONOTONIC_TIMESTAMP"]) is not None
            and lower <= int(row["__MONOTONIC_TIMESTAMP"]) <= upper,
            "journal service/process/time binding changed",
        )
        message = row["MESSAGE"].encode("ascii")
        _expect(len(message) + 1 <= journal._MAX_BYTES, "journal event is oversized")
        event = response.broker._parse_canonical_document(message, "endpoint journal")
        _expect(
            journal._valid_event(event) and event["role"] == role,
            "journal event contract changed",
        )
        result.append({"journal": row, "event": event})
    _expect(
        len({row["journal"]["__CURSOR"] for row in result}) == len(result),
        "duplicate journal cursor",
    )
    return result


def _collect(cursor: str, processes: dict, boot: str, lower: int) -> dict[str, Any]:
    deadline = time.monotonic() + 3
    while True:
        response._command(["/usr/bin/journalctl", "--sync"], timeout=5)
        captured = {}
        for role, unit in _ROLES.items():
            raw = response._command(
                [
                    "/usr/bin/journalctl",
                    "--quiet",
                    "--all",
                    "--no-pager",
                    "--output=json",
                    "--output-fields=" + ",".join(_JOURNAL_FIELDS),
                    "--lines=9",
                    "--after-cursor=" + cursor,
                    "_SYSTEMD_UNIT=" + unit,
                    "_SYSTEMD_INVOCATION_ID=" + processes[role]["unit"]["InvocationID"],
                    "_BOOT_ID=" + boot,
                ],
                timeout=3,
            )
            captured[role] = {
                "raw_jsonl": raw.decode("ascii"),
                "rows": _rows(
                    raw, role, processes[role], boot, lower, time.monotonic_ns() // 1000
                )
                if raw
                else [],
            }
        counts = {role: len(value["rows"]) for role, value in captured.items()}
        if counts == {"worker": 4, "sensor": 2, "broker": 2}:
            return captured
        _expect(
            all(counts[role] <= (4 if role == "worker" else 2) for role in counts)
            and time.monotonic() < deadline,
            "expected bounded journal pairs were not observed",
        )
        time.sleep(0.02)


def _pairs(captured: dict, processes: dict, refused: dict, proof: dict) -> None:
    attempts = set()
    cursors = [
        row["journal"]["__CURSOR"]
        for value in captured.values()
        for row in value["rows"]
    ]
    _expect(len(cursors) == len(set(cursors)), "journal cursors are not distinct")
    terminals = {}
    for role in _ROLES:
        rows = captured[role]["rows"]
        _expect(
            len(rows) == (4 if role == "worker" else 2), "journal pair count changed"
        )
        values = []
        for index in range(0, len(rows), 2):
            first, last = rows[index : index + 2]
            start, end = first["event"], last["event"]
            expected = journal._new(role)
            expected["attempt_id"] = start["attempt_id"]
            _expect(
                start == expected
                and end["phase"] == "TERMINAL"
                and start["attempt_id"] == end["attempt_id"]
                and start["attempt_id"] not in attempts
                and int(first["journal"]["__MONOTONIC_TIMESTAMP"])
                <= int(last["journal"]["__MONOTONIC_TIMESTAMP"]),
                "journal START/TERMINAL pairing changed",
            )
            attempts.add(start["attempt_id"])
            values.append(end)
        if role == "worker":
            negative = values.pop(0)
            _expect(
                negative["peer"] == refused["client"]
                and negative["peer_expected"] is False
                and negative["stage"] == "PEER"
                and negative["outcome"] == "REJECTED_BEFORE_SUBMISSION"
                and negative["handler_status"] == "RAISED"
                and negative["submission"] == "NOT_STARTED"
                and negative["request_state"] == "UNAVAILABLE"
                and all(negative[key] is None for key in journal._DIGEST_FIELDS)
                and negative["result_kind"] == "NONE"
                and negative["worker_status"] is None
                and negative["client_delivery"] == "NOT_STARTED",
                "root peer refusal journal is unbound",
            )
        terminals[role] = values[0]
    receipt = proof["receipt"]
    broker_result = receipt["broker_result"]
    for role, event in terminals.items():
        preceding = {"worker": "gateway", "sensor": "worker", "broker": "sensor"}[role]
        peer = {
            key: processes[preceding]["process"][key] for key in ("pid", "uid", "gid")
        }
        _expect(
            event["peer"] == peer
            and event["peer_expected"] is True
            and event["handler_status"] == "RETURNED"
            and event["stage"] == "CLIENT_DELIVERY"
            and event["client_delivery"] == "FRAME_SENT_NOT_ACKNOWLEDGED"
            and event["action_request_digest"] == broker_result["request_digest"]
            and event["result_digest"] == receipt["broker_result_digest"]
            and event["submission"]
            == ("CORE_ENTERED" if role == "broker" else "SEND_ATTEMPTED")
            and event["request_state"] == "VALIDATED",
            "successful endpoint journal is not joined to the retained result",
        )
        if role == "sensor":
            _expect(
                event["result_kind"] == "CANONICAL_REPLY_ONLY"
                and event["outcome"] == "REPLY_RELAYED_EFFECT_UNVERIFIED"
                and event["profile_attribution_digest"]
                == receipt["runtime_attribution_digest"],
                "sensor journal exceeds its observation boundary",
            )
        else:
            _expect(
                event["result_kind"] == "VALIDATED_BROKER_RESULT"
                and event["outcome"] == "BROKER_RESULT_OBSERVED"
                and event["verdict"] == "ALLOW"
                and event["effect_status"] == "CREATED",
                "broker result journal is inconsistent",
            )
        if role == "worker":
            _expect(
                event["worker_status"] == "COMPLETED"
                and event["worker_request_digest"] == proof["worker_request_digest"],
                "worker/native request digest changed",
            )
        elif role == "broker":
            _expect(
                event["profile_attribution_digest"]
                == receipt["runtime_attribution_digest"],
                "broker profile attribution changed",
            )


def _action(p37b: Any, setup: dict) -> dict[str, Any]:
    source = response._read_regular(p37b._DRIVER, 0, {0o644})
    _expect(
        (len(source), _digest(source)) == _DRIVER_PIN,
        "native fixture driver source changed",
    )
    # Credentials stay private: neither this token nor the environment is returned.
    raw = response._read_regular(p37b._GATEWAY_ENVIRONMENT, 0, {0o400})
    match = re.fullmatch(rb"OPENCLAW_GATEWAY_TOKEN=([0-9a-f]{64})\n", raw)
    _expect(match is not None, "fixed gateway environment changed")
    token = match[1].decode("ascii")
    p37b._DRIVER_ROOT.mkdir(mode=0o700)
    policy = response.broker._parse_canonical_document(
        response._read_regular(
            p37b.lineage._CONTROL / "policy.json", response._identities()[0], {0o400}
        ),
        "fixture policy",
    )
    fd = os.open(
        p37b.lineage._PROTECTED,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        action = p37b._action_digests(fd, p37b._TARGET, p37b._PAYLOAD)
    finally:
        os.close(fd)
    with patch.object(p37b.openclaw, "_RUNTIME_DIGEST", setup["runtime_digest"]):
        controls = p37b._refresh_controls(
            policy,
            action,
            setup["skill_digest"],
            response._identities()[0],
            response._identities()[2],
            2,
        )
    driver = p37b._run_driver(
        "endpoint-journal-allow",
        "COMPLETED",
        {"verdict": "ALLOW", "effect_status": "CREATED"},
        "aragorn/runtime-action-worker-result/v1",
        {"OPENCLAW_GATEWAY_TOKEN": token, "ARAGORN_MOCK_PROVIDER_TOKEN": token},
    )
    p37b._assert_driver_outcome(
        driver, "COMPLETED", {"verdict": "ALLOW", "effect_status": "CREATED"}
    )
    _expect(
        response._read_regular(p37b._DRIVER, 0, {0o644}) == source,
        "native fixture driver changed during invocation",
    )
    return {
        "driver": driver,
        "controls": controls,
        "driver_source_digest": _DRIVER_PIN[1],
    }


def _proof(p37b: Any, driver: dict, before: dict, after: dict, processes: dict) -> dict:
    broker_uid, _, worker_gid, *_ = response._identities()
    receipt_raw = response._read_regular(p37b.lineage._RECEIPT, broker_uid, {0o400})
    receipt = response.broker._parse_canonical_document(receipt_raw, "fixture receipt")
    broker_state = response.broker._parse_canonical_document(
        response._read_regular(
            p37b.lineage._CONTROL / "state.json", broker_uid, {0o400}
        ),
        "fixture broker state",
    )
    target = p37b.lineage._PROTECTED / p37b._TARGET
    payload = response._read_regular(target, broker_uid, {0o400})
    _expect(
        target.lstat().st_gid == worker_gid
        and p37b.lineage._RECEIPT.lstat().st_gid == worker_gid,
        "fixture result group changed",
    )
    state = after["grant_state"]["document"]
    claim, result = state["claim"], state["result"]
    lease = claim["lease"]
    nested = receipt["broker_result"]
    attribution = receipt["runtime_attribution"]
    identifiers = driver["output"]["turn"]["identifiers"]
    correlation = claim["profile_claim"]["profile_pending"]["measured_action"]
    worker = processes["worker"]["process"]
    _expect(
        before["grant_state"]["document"]["status"] == "AVAILABLE"
        and before["grant_state"]["document"]["claim"] is None
        and before["grant_state"]["document"]["result"] is None
        and not before["target_exists"]
        and not before["receipt_exists"]
        and not before["pending_exists"]
        and before["protected_entries"] == before["staging_entries"] == []
        and state["status"] == "CONSUMED"
        and state["grant_digest"]
        == before["grant_state"]["document"]["grant_digest"]
        == claim["grant_digest"]
        == result["grant_digest"]
        == lease["grant_digest"]
        and claim["lease_digest"] == result["lease_digest"] == canonical_digest(lease)
        and claim["profile_claim"]["request_digest"] == lease["request_digest"]
        and claim["profile_claim"]["submission_digest"] == lease["submission_digest"]
        and result["profile_result"]["lease_digest"] == claim["lease_digest"]
        and result["profile_result"]["submission_digest"] == lease["submission_digest"]
        and result["profile_result"]["profile_receipt_digest"]
        == canonical_digest(receipt)
        and receipt["broker_result_digest"]
        == canonical_digest(nested)
        == result["profile_result"]["broker_result_digest"]
        and receipt["runtime_attribution_digest"]
        == canonical_digest(attribution)
        == lease["runtime_attribution_digest"]
        and receipt["submission_digest"] == lease["submission_digest"]
        and nested["request_digest"] == lease["request_digest"]
        and result["profile_result"]["verdict"] == nested["verdict"]
        and result["profile_result"]["effect_status"] == nested["effect_status"]
        and nested["verdict"] == "ALLOW"
        and nested["effect_status"] == "CREATED"
        and nested["reason_codes"] == []
        and nested["target_name"] == p37b._TARGET
        and payload == p37b._PAYLOAD
        and after["protected_entries"] == [p37b._TARGET]
        and after["staging_entries"] == []
        and not after["pending_exists"]
        and after["receipt_exists"]
        and all(
            attribution[key] == worker[key]
            for key in ("pid", "uid", "gid", "start_time_ticks", "cgroup")
        )
        and p37b._driver_gateway_pid(driver) == processes["gateway"]["process"]["pid"]
        and identifiers["session_id"] == correlation["session_id"]
        and identifiers["run_id"] == correlation["run_id"]
        and identifiers["tool_call_digest"] == correlation["tool_call_id"],
        "native action, consumed grant, receipt, or installed effect is unbound",
    )
    _expect(
        broker_state["effect_journal"] is None
        and len(broker_state["consumed"]) == 1
        and broker_state["consumed"][0]["request_digest"] == nested["request_digest"]
        and broker_state["consumed"][0]["observation_digest"]
        == nested["observation_digest"],
        "broker effect accounting is not one completed request",
    )
    return {
        "receipt": receipt,
        "receipt_digest": _digest(receipt_raw),
        "target_digest": _digest(payload),
        "grant_state_digest": canonical_digest(state),
        "worker_request_digest": identifiers["request_digest"],
    }


def _run(container: str) -> dict[str, Any]:
    prior._require_fixture(container)
    try:
        sources = _sources()
        setup = prior._prepare(publish_revocation=False)
        import runtime_action_worker_openclaw_systemd_probe as p37b

        processes = _processes(container)
        boot = _boot()
        installed = prior._installed(setup["skill_digest"])
        _expect(
            installed["denial"] is None and setup["publication"] is None,
            "journal fixture is already revoked or denied",
        )
        before = p37b._snapshot_effects()
        cursor = _cursor()
        lower = time.monotonic_ns() // 1000
        refused = p37b._unauthorized_worker_client()
        _expect(
            refused["outcome"] == "PEER_CLOSED"
            and refused["client"] == {"pid": os.getpid(), "uid": 0, "gid": 0}
            and refused["server_peer"]
            == {
                key: processes["worker"]["process"][key]
                for key in ("pid", "uid", "gid")
            }
            and p37b._snapshot_effects() == before,
            "unauthorized root connection was not an inert refusal",
        )
        action = _action(p37b, setup)
        after = p37b._snapshot_effects()
        proof = _proof(p37b, action["driver"], before, after, processes)
        captured = _collect(cursor, processes, boot, lower)
        _pairs(captured, processes, refused, proof)
        _expect(
            _processes(container) == processes
            and _boot() == boot
            and _sources() == sources
            and prior._installed(setup["skill_digest"]) == installed,
            "source, process, boot, or installed lineage changed during journal check",
        )
        observation = {
            "schema": "aragorn/runtime-endpoint-journal-systemd-integration-observation/v1",
            "authority": "LOCAL_JOURNAL_DELIVERY_OBSERVATION_NOT_DURABILITY_COMPLETENESS_OR_RUN_AUTHORITY",
            "status": "OBSERVED",
            "fixture_container": container,
            "setup": setup,
            "installed_sources": sources,
            "processes": processes,
            "boot_id": boot,
            "journal_after_cursor": cursor,
            "journal_lower_monotonic_us": lower,
            "journal": captured,
            "unauthorized_peer_refusal": refused,
            "native_action": action,
            "effect_proof": proof,
            "fixture_installed_skill": installed,
            "phase3_eligible": False,
            "run_conformance_eligible": False,
            "durable_event_retention": False,
            "complete_event_coverage": False,
            "limitations": [
                "ONE_OWNED_DISPOSABLE_FIXTURE_NOT_PRODUCTION_DEPLOYMENT",
                "EIGHT_SELECTED_STDOUT_JOURNAL_RECORDS_NOT_LOSSLESS_OR_DURABLE_DELIVERY",
                "ENDPOINT_LOCAL_STATES_AND_DIGEST_JOINS_NOT_GENERAL_TOOL_OR_SKILL_CAUSATION",
                "JOURNAL_STREAM_CREDENTIALS_NOT_PER_WRITE_KERNEL_ATTESTATION",
                "NO_LATENCY_QUALIFICATION_OR_AUTOMATIC_EVENT_LOSS_ENFORCEMENT",
            ],
        }
    finally:
        pending = sys.exception()
        try:
            cleanup = prior._stop_fixture()
        except (RuntimeError, OSError, ValueError) as exc:
            if pending is not None:
                raise RuntimeError(
                    f"journal fixture operation failed: {pending}; cleanup failed: {exc}"
                ) from exc
            raise
    observation["fixture_stack_cleanup"] = cleanup
    return observation


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print(
            "usage: runtime_endpoint_journal_systemd_check OWNED_CONTAINER_ID",
            file=sys.stderr,
        )
        return 64
    try:
        result = _run(arguments[0])
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as exc:
        reason = str(exc).encode("ascii", errors="backslashreplace").decode("ascii")
        reason = reason.replace("\n", " ").replace("\r", " ")[:1024]
        print(
            f"endpoint journal fixture not confirmed: {type(exc).__name__}: {reason}",
            file=sys.stderr,
        )
        return 1
    print(canonical_json(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
