"""Two fresh accepted-health publications in the owned native fixture only."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import sys
import time
from pathlib import Path
from typing import Any

sys.path[:0] = [
    "/usr/lib/aragorn",
    str(Path(__file__).resolve().parent),
    "/src/scripts",
]

import runtime_response_systemd_check as retained

from aragorn.oci_worker_protocol import canonical_digest, canonical_json

response = retained.response
_PUBLISHER = "aragorn-runtime-health-publisher.service"
_DISPATCH = "aragorn-runtime-health-response.service"
_UNITS = (_PUBLISHER, _DISPATCH)
_PUBLICATION = Path("/etc/aragorn/runtime-action-health-publication.json")
_HOOK_SOURCE = Path("/usr/share/aragorn/systemd/50-runtime-health-response.conf")
_HOOK = Path("/etc/systemd/system") / (_PUBLISHER + ".d") / _HOOK_SOURCE.name
_HOOK_RAW = b"[Unit]\nOnSuccess=aragorn-runtime-health-response.service\nOnSuccessJobMode=fail\n"
_CODE = {
    "/usr/lib/aragorn/aragorn/runtime_health_service.py": (
        3381,
        "1518e5afa3450d88b878f27baa79e670e0fd48decc5719ecf249e7a351343817",
        0o644,
    ),
    "/usr/libexec/aragorn/aragorn-runtime-health-service.py": (
        350,
        "d9801ec5532735c20ff5ff46e320a9192e847f64cb70a2bec2db4292467c7ae7",
        0o755,
    ),
    "/usr/libexec/aragorn/aragorn-runtime-response-service.py": (
        349,
        "69e7eb1b13901e6d700799e473ae5bbfef1a17b2f7cc257559a66d2b0064c35c",
        0o755,
    ),
    "/usr/lib/systemd/system/aragorn-runtime-health-publisher.service": (
        1822,
        "c52a88c5c95b39b51e017d8fc76f177a9f99f433aa33365164e6220acab11893",
        0o644,
    ),
    "/usr/lib/systemd/system/aragorn-runtime-health-response.service": (
        2049,
        "b165c021537b14be356ec67396fc359844474f65b1406239e5863029e6ed730f",
        0o644,
    ),
    str(_HOOK_SOURCE): (
        79,
        "0de3ae4657861631e8479d1cab194de46d84a18283b1a2c1eb2272bb1d3d505a",
        0o644,
    ),
    "/usr/libexec/aragorn/activate-runtime-action-worker-host.sh": (
        39602,
        "d22a9fbce56a5fa13ea5f2605b5ff89c16ba12e83402f6b97367b57a3099edce",
        0o755,
    ),
}
_STATE = (
    "Id",
    "InvocationID",
    "ActiveState",
    "SubState",
    "MainPID",
    "ControlPID",
    "ExecMainStatus",
    "Result",
)
_JOURNAL_FIELDS = {
    "MESSAGE",
    "_SYSTEMD_INVOCATION_ID",
    "_SYSTEMD_UNIT",
    "_BOOT_ID",
    "__CURSOR",
    "__MONOTONIC_TIMESTAMP",
    "__REALTIME_TIMESTAMP",
}


class HealthFixtureError(RuntimeError):
    """Only fixed internal assertions; external exception text is never wrapped."""


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise HealthFixtureError(message)


def _guard(container: str | None = None) -> None:
    actual = response._process_cgroup(1)
    _expect(
        sys.platform == "linux"
        and os.geteuid() == 0
        and re.fullmatch(r"/docker/[0-9a-f]{64}/init\.scope", actual) is not None
        and (
            container is None
            or (
                type(container) is str
                and re.fullmatch(r"[0-9a-f]{64}", container) is not None
                and actual == "/docker/" + container + "/init.scope"
            )
        ),
        "health check requires the exact owned root Docker/systemd fixture",
    )


def _sources() -> dict:
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
            and (len(raw), canonical_digest_bytes(raw)) == (size, "sha256:" + digest),
            "installed health source changed",
        )
        result[name] = {"bytes": size, "digest": "sha256:" + digest}
    return result


def canonical_digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _show(unit: str, properties: tuple[str, ...] = _STATE) -> dict[str, str]:
    _expect(unit in _UNITS, "unsupported health unit selector")
    raw = response._command(
        ["/usr/bin/systemctl", "show", "--property=" + ",".join(properties), unit],
        timeout=3,
    )
    pairs = [line.split("=", 1) for line in raw.decode("ascii").splitlines()]
    _expect(all(len(pair) == 2 for pair in pairs), "malformed health unit state")
    state = dict(pairs)
    _expect(
        len(pairs) == len(properties)
        and set(state) == set(properties)
        and state["Id"] == unit,
        "incomplete health unit state",
    )
    return state


def _property(unit: str, name: str) -> list[str]:
    _expect(
        unit in _UNITS and name in {"LoadCredential", "BindPaths", "BindReadOnlyPaths"},
        "unsupported health property selector",
    )
    object_path = "/org/freedesktop/systemd1/unit/" + unit.replace("-", "_2d").replace(
        ".", "_2e"
    )
    raw = response._command(
        [
            "/usr/bin/busctl",
            "get-property",
            "org.freedesktop.systemd1",
            object_path,
            "org.freedesktop.systemd1.Service",
            name,
        ],
        timeout=3,
    )
    return shlex.split(raw.decode("ascii"))


def _units(*, installed: bool) -> dict:
    result = {}
    properties = (
        "Id",
        "LoadState",
        "FragmentPath",
        "DropInPaths",
        "User",
        "Group",
        "Type",
        "RemainAfterExit",
        "RefuseManualStart",
        "OnSuccess",
        "OnSuccessJobMode",
        "Before",
        "After",
        "ExecStart",
        "ExecStartPre",
        "ExecStartPost",
        "NoNewPrivileges",
        "PrivateNetwork",
        "PrivateMounts",
        "ProtectSystem",
    )
    for unit in _UNITS:
        state = _show(unit, properties)
        publisher = unit == _PUBLISHER
        command = "/usr/bin/python3.12 -I -S -B /usr/libexec/aragorn/aragorn-runtime-"
        command += (
            f"health-service.py /run/credentials/{unit}/runtime-binding /run/credentials/{unit}/health"
            if publisher
            else "response-service.py --health-dispatch"
        )
        expected = {
            "LoadState": "loaded",
            "FragmentPath": "/usr/lib/systemd/system/" + unit,
            "DropInPaths": str(_HOOK) if publisher and installed else "",
            "User": "aragorn-broker" if publisher else "root",
            "Group": "aragorn-runtime" if publisher else "root",
            "Type": "oneshot",
            "RemainAfterExit": "no",
            "RefuseManualStart": "no" if publisher else "yes",
            "OnSuccess": _DISPATCH if publisher and installed else "",
            "OnSuccessJobMode": "fail" if publisher and installed else "replace",
            "ExecStartPre": "",
            "ExecStartPost": "",
            "NoNewPrivileges": "yes",
            "PrivateNetwork": "yes",
            "PrivateMounts": "yes",
            "ProtectSystem": "strict",
        }
        _expect(
            all(state[key] == value for key, value in expected.items())
            and state["ExecStart"].startswith(
                "{ path=/usr/bin/python3.12 ; argv[]="
                + command
                + " ; ignore_errors=no ; "
            )
            and state["ExecStart"].count("argv[]=") == 1
            and state["ExecStart"].count("path=") == 1
            and (
                publisher
                or (
                    _PUBLISHER in state["Before"].split()
                    and _PUBLISHER not in state["After"].split()
                )
            ),
            "effective health unit contract changed",
        )
        result[unit] = state
    credentials = _property(_PUBLISHER, "LoadCredential")
    pairs = [
        ("runtime-binding", "/etc/aragorn/runtime-action-runtime.json"),
        ("health", str(_PUBLICATION)),
    ]
    _expect(
        credentials
        in [["a(ss)", "2", *pairs[0], *pairs[1]], ["a(ss)", "2", *pairs[1], *pairs[0]]],
        "health publisher credential projection changed",
    )
    alias = _property(_DISPATCH, "BindPaths")
    # This is a strict expected effective contract, not a historical observation.
    _expect(
        alias
        == [
            "a(ssbt)",
            "1",
            "/run/credentials/aragorn-runtime-action-worker.service",
            "/run/aragorn-runtime-response-worker-credential",
            "true",
            "16384",
        ]
        and _property(_DISPATCH, "BindReadOnlyPaths") == ["a(ssbt)", "0"],
        "health response credential alias changed",
    )
    _expect(
        _property(_DISPATCH, "LoadCredential") == ["a(ss)", "0"],
        "unexpected health response credentials",
    )
    return {
        "units": result,
        "publisher_credentials": credentials,
        "response_bind_paths": alias,
    }


def _install_hook() -> dict:
    before = _units(installed=False)
    for unit in _UNITS:
        state = _show(unit)
        _expect(
            state["ActiveState"] == "inactive"
            and state["SubState"] == "dead"
            and state["MainPID"] == state["ControlPID"] == "0",
            "health units already executing",
        )
    _expect(
        response._read_regular(_HOOK_SOURCE, 0, {0o644}) == _HOOK_RAW
        and not os.path.lexists(_HOOK.parent),
        "health hook is not fresh or exact",
    )
    parent = _HOOK.parent.parent
    parent_before = parent.lstat()
    _expect(
        parent.resolve(strict=True) == parent
        and stat.S_ISDIR(parent_before.st_mode)
        and parent_before.st_uid == parent_before.st_gid == 0
        and not stat.S_IMODE(parent_before.st_mode) & 0o022,
        "health hook parent custody changed",
    )
    _HOOK.parent.mkdir(mode=0o755)
    fd = os.open(
        _HOOK,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o644,
    )
    try:
        _expect(
            os.write(fd, _HOOK_RAW) == len(_HOOK_RAW),
            "health hook publication incomplete",
        )
        os.fchmod(fd, 0o644)
        os.fsync(fd)
    finally:
        os.close(fd)
    _expect(
        response._read_regular(_HOOK, 0, {0o644}) == _HOOK_RAW
        and sorted(item.name for item in _HOOK.parent.iterdir()) == [_HOOK.name],
        "health hook readback changed",
    )
    response._command(["/usr/bin/systemctl", "daemon-reload"], timeout=5)
    return {
        "before": before,
        "after": _units(installed=True),
        "hook_digest": canonical_digest_bytes(_HOOK_RAW),
    }


def _journal(unit: str, cursor: str, boot: str) -> list[dict]:
    _expect(
        unit in _UNITS
        and re.fullmatch(r"[A-Za-z0-9;=_-]{1,1024}", cursor) is not None
        and re.fullmatch(r"[0-9a-f]{32}", boot) is not None,
        "unbounded health journal selector",
    )
    raw = response._command(
        [
            "/usr/bin/journalctl",
            "--quiet",
            "--all",
            "--no-pager",
            "--output=json",
            "--output-fields=" + ",".join(sorted(_JOURNAL_FIELDS)),
            "--cursor=" + cursor,
            "--lines=3",
            "_SYSTEMD_UNIT=" + unit,
            "_BOOT_ID=" + boot,
        ],
        timeout=5,
    )
    _expect(
        len(raw) <= 131072
        and (not raw or raw.endswith(b"\n"))
        and len(raw.splitlines()) <= 2,
        "health journal is ambiguous or oversized",
    )
    rows = []
    seen = set()
    for line in raw.splitlines():
        row = json.loads(line, object_pairs_hook=_object)
        _expect(
            type(row) is dict
            and set(row) == _JOURNAL_FIELDS
            and all(type(value) is str for value in row.values())
            and row["_SYSTEMD_UNIT"] == unit
            and row["_BOOT_ID"] == boot
            and row["__CURSOR"] not in seen
            and re.fullmatch(r"[A-Za-z0-9;=_-]{1,1024}", row["__CURSOR"]) is not None
            and all(
                re.fullmatch(r"[0-9]{1,20}", row[key]) is not None
                and 0 < int(row[key]) < 2**64
                for key in ("__MONOTONIC_TIMESTAMP", "__REALTIME_TIMESTAMP")
            )
            and re.fullmatch(r"[0-9a-f]{32}", row["_SYSTEMD_INVOCATION_ID"])
            is not None,
            "health journal invocation is unbound",
        )
        document = response.broker._parse_canonical_document(
            row["MESSAGE"].encode("ascii"), "health journal result"
        )
        seen.add(row["__CURSOR"])
        if row["__CURSOR"] == cursor:
            continue
        rows.append(
            {
                "journal": row,
                "invocation_id": row["_SYSTEMD_INVOCATION_ID"],
                "result": document,
            }
        )
    _expect(len(rows) <= 1, "health journal has multiple new results")
    return rows


def _object(pairs: list[tuple[str, Any]]) -> dict:
    result = dict(pairs)
    _expect(len(result) == len(pairs), "duplicate health journal field")
    return result


def _publish(p37b: Any, document: dict, cursor: str, boot: str) -> dict:
    if os.path.lexists(_PUBLICATION):
        response._read_regular(_PUBLICATION, 0, {0o400})
    p37b._write_document(_PUBLICATION, document)
    _expect(
        response._read_regular(_PUBLICATION, 0, {0o400}) == canonical_json(document),
        "health credential readback changed",
    )
    response._command(["/usr/bin/systemctl", "start", _PUBLISHER], timeout=10)
    deadline = time.monotonic() + 45
    while True:
        states = {unit: _show(unit) for unit in _UNITS}
        _expect(
            all(state["ActiveState"] != "failed" for state in states.values()),
            "health dispatch failed",
        )
        rows = {unit: _journal(unit, cursor, boot) for unit in _UNITS}
        if all(
            rows[unit] and states[unit]["ActiveState"] == "inactive" for unit in _UNITS
        ):
            for unit, state in states.items():
                _expect(
                    state["SubState"] == "dead"
                    and state["MainPID"]
                    == state["ControlPID"]
                    == state["ExecMainStatus"]
                    == "0"
                    and state["Result"] == "success"
                    and state["InvocationID"] in {"", rows[unit][0]["invocation_id"]},
                    "health unit completion is unconfirmed",
                )
            return {
                "publication": rows[_PUBLISHER][0],
                "response": rows[_DISPATCH][0],
                "units": states,
            }
        _expect(
            time.monotonic() < deadline,
            "health response did not complete within fixed deadline",
        )
        time.sleep(0.02)


def _controls(setup: dict) -> dict:
    identities = response._identities()
    binding = response._read_bindings(identities[1])
    _expect(
        binding.runtime_digest == setup["runtime_digest"]
        and binding.policy_digest == canonical_digest(setup["policy"])
        and binding.active_skill_digest == setup["skill_digest"]
        and binding.policy_version == setup["policy"]["version"],
        "health worker binding changed",
    )
    config = response._broker_config(identities, binding)
    with response._broker_guard(config) as fd:
        policy = response.broker._parse_canonical_document(
            response._read_regular(
                config.policy_path, identities[0], {0o400}, dir_fd=fd
            ),
            "health fixture policy",
        )
        state = response.broker._state(
            response.broker._parse_canonical_document(
                response._read_regular(
                    config.state_path, identities[0], {0o400}, dir_fd=fd
                ),
                "health fixture state",
            )
        )
        _expect(policy == setup["policy"], "health policy changed")
        return state


def _effect_snapshot(p37b: Any, observation: dict) -> dict:
    broker_uid = response._identities()[0]
    effect = p37b._snapshot_effects()
    target = response._read_regular(
        p37b.lineage._PROTECTED / p37b._TARGET, broker_uid, {0o400}
    )
    receipt = response._read_regular(p37b.lineage._RECEIPT, broker_uid, {0o400})
    _expect(
        canonical_digest_bytes(target) == observation["effect_proof"]["target_digest"]
        and canonical_digest_bytes(receipt)
        == observation["effect_proof"]["receipt_digest"]
        and canonical_digest(effect["grant_state"]["document"])
        == observation["effect_proof"]["grant_state_digest"],
        "native target or broker receipt changed",
    )
    return {
        **effect,
        "controls": {
            key: value
            for key, value in effect["controls"].items()
            if key not in {"health.json", "state.json"}
        },
    }


def _join(
    captured: dict, document: dict, setup: dict, before: list[dict], *, unhealthy: bool
) -> dict:
    published = captured["publication"]["result"]
    _expect(
        published
        == {
            "schema": "aragorn/runtime-health-publication-result/v1",
            "authority": "LOCAL_PROCESS_RESULT_ONLY_NOT_DURABLE_PROVENANCE_OR_RESPONSE_AUTHORITY",
            "health_digest": canonical_digest(document),
            "epoch": document["epoch"],
            "health_status": document["status"],
        },
        "health publication result changed",
    )
    result, evidence = retained._retained_response(captured["response"]["result"])
    accepted = {
        "snapshot_digest": canonical_digest(document),
        "status": document["status"],
        "epoch": document["epoch"],
        "minimum_mediator_health_epoch": document["epoch"],
        "policy_digest": canonical_digest(setup["policy"]),
        "worker_runtime_digest": setup["runtime_digest"],
        "sensor_digest": document["sensor_digest"],
        "expires_at_unix": document["expires_at_unix"],
    }
    _expect(
        result["authority"]
        == "LOCAL_ROOT_RESPONSE_RESULT_NOT_RUN_OR_PHASE3_CONFORMANCE"
        and result["expected_skill_digest"] == setup["skill_digest"]
        and result["health_snapshot_digest"] == canonical_digest(document)
        and result["accepted_health"] == accepted
        and result["before"] == before,
        "health response snapshot or running identity is unbound",
    )
    if not unhealthy:
        _expect(
            result["status"] == "ACCEPTED_HEALTHY_FIXED_RUNTIME_PROFILE"
            and result["after"] == before
            and "future_start_barrier" not in result,
            "healthy response was not a no-op",
        )
    else:
        barrier = result["future_start_barrier"]
        _expect(
            result["status"] == "SUSPENDED_UNHEALTHY_FIXED_RUNTIME_PROFILE"
            and barrier["status"] == "PERSISTENT_FIXED_PROFILE_STARTS_MASKED"
            and barrier["directory_fsynced"] is True
            and barrier["automatic_unmask_supported"] is False
            and len(barrier["masks"]) == 2
            and [item["unit"]["Id"] for item in result["after"]]
            == list(response._UNITS)
            and all(
                item["unit"]["ActiveState"] == "inactive"
                and item["unit"]["MainPID"] == item["unit"]["ControlPID"] == "0"
                and item["cgroup"]["status"] in {"EMPTY", "ABSENT"}
                for item in result["after"]
            ),
            "unhealthy response did not stop and mask the fixed profile",
        )
    return {**captured, "document": document, "retention": evidence}


def run_after_native(container: str, observation: dict, native: Any) -> dict:
    _guard(container)
    import runtime_action_worker_openclaw_systemd_probe as p37b

    _expect(
        observation["fixture_container"] == container
        and observation["status"] == "OBSERVED"
        and observation["phase3_eligible"] is False
        and observation["run_conformance_eligible"] is False,
        "health predecessor observation is unbound",
    )
    setup, sources = observation["setup"], _sources()
    _expect(
        native.prior._processes(container) == observation["processes"]
        and native.prior._boot() == observation["boot_id"],
        "health predecessor processes changed",
    )
    before = retained._running(response._identities())
    effects = _effect_snapshot(p37b, observation)
    state = _controls(setup)
    floor = state["minimum_mediator_health_epoch"]
    _expect(
        type(floor) is int and 0 < floor < 2**53 - 2, "health accepted floor is invalid"
    )
    hook = _install_hook()
    invocations = []
    for index, status in enumerate(("healthy", "unhealthy"), 1):
        cursor = native.prior._cursor()
        now = int(time.time())
        document = {
            "schema": "aragorn/runtime-mediator-health/v1",
            "runtime_digest": setup["runtime_digest"],
            "sensor_digest": setup["policy"]["sensor_digest"],
            "epoch": floor + index,
            "status": status,
            "observed_at_unix": now,
            "expires_at_unix": now + 15,
        }
        captured = _publish(p37b, document, cursor, observation["boot_id"])
        invocations.append(
            _join(captured, document, setup, before, unhealthy=index == 2)
        )
        if index == 1:
            _expect(
                native.prior._processes(container) == observation["processes"]
                and retained._running(response._identities()) == before,
                "healthy publication changed running processes",
            )
            current = _controls(setup)
            _expect(
                current
                == {**state, "minimum_mediator_health_epoch": document["epoch"]},
                "healthy publication changed broker effects",
            )
    _expect(
        len(
            {
                item[part]["invocation_id"]
                for item in invocations
                for part in ("publication", "response")
            }
        )
        == 4,
        "health service invocations were not distinct",
    )
    start = retained._start_refused()
    # Worker stopped: its original persistent stream remains readable, not reset.
    receipts = native._snapshot(setup["provisioning"]["genesis_digest"], 4)
    _expect(
        receipts == observation["receipt_store_after_create"]
        and _effect_snapshot(p37b, observation) == effects
        and _sources() == sources
        and native.prior._boot() == observation["boot_id"],
        "health response changed retained native evidence or effects",
    )
    # The normal reader requires a running worker. Read final broker state directly
    # after stop and allow only the already-bound monotonic health floor advance.
    final_state = response.broker._state(
        response.broker._parse_canonical_document(
            response._read_regular(
                p37b.lineage._CONTROL / "state.json", response._identities()[0], {0o400}
            ),
            "final health fixture state",
        )
    )
    _expect(
        final_state == {**state, "minimum_mediator_health_epoch": floor + 2},
        "unhealthy publication changed broker effects",
    )
    return {
        "schema": "aragorn/native-health-systemd-observation/v1",
        "status": "OBSERVED",
        "fixture_container": container,
        "authority": "OWNED_ACCEPTED_HEALTH_RESPONSE_ONLY_NOT_SENSOR_LOSS_OR_RUN_QUALIFICATION",
        "installed_sources": sources,
        "hook": hook,
        "accepted_floor_before": floor,
        "invocations": invocations,
        "persistent_start_refusal": start,
        "native_receipts_retained": receipts["state_digest"],
        "native_target_and_broker_receipt_unchanged": True,
        "phase3_eligible": False,
        "run_conformance_eligible": False,
        "sensor_loss_detection": False,
        "watchdog_or_stale_health_coverage": False,
        "durable_dispatch_queue": False,
        "production_activation_eligible": False,
    }


def stop_extra_units() -> dict:
    _guard()
    response._command(["/usr/bin/systemctl", "stop", *_UNITS], timeout=15)
    states = {unit: _show(unit) for unit in _UNITS}
    _expect(
        all(
            state["ActiveState"] == "inactive"
            and state["SubState"] == "dead"
            and state["MainPID"] == state["ControlPID"] == "0"
            for state in states.values()
        ),
        "health fixture cleanup is unconfirmed",
    )
    return states
