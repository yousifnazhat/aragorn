"""One owned read/create receipt fixture; never deployment or RUN qualification."""

from __future__ import annotations

import fcntl
import itertools
import os
import re
import secrets
import shlex
import stat
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

import runtime_endpoint_journal_systemd_check as prior

from aragorn import runtime_native_tool_provisioning as provision
from aragorn import runtime_native_tool_receipts as core
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

response = prior.response
setup_prior = prior.prior
_RUNTIME = "sha256:06335e3b80e89aa0157b037b1eea0d4078b40bf35d3c3960640a35a215d5bcd3"
_READ_PATH = Path("/var/lib/aragorn-agent-gateway/workspace/native-receipt-read.txt")
_READ_BYTES = b"Aragorn inert native receipt read."
_DRIVER = Path("/opt/aragorn/native-receipt-read-create-driver-v1.mjs")
_DRIVER_PIN = (
    13466,
    "sha256:58545a7412c660235ac38c96b4857637ea311c86a894d0df4ed973201ae5e7b0",
)
_ACTIVATOR_PIN = (
    38837,
    "sha256:d24da2fba266b302da6f633fc0c161513f3e7f2e60f804572a749a3bdce3c1ea",
)
_PHASE = "PRECHECK"
_EXTRA_CODE = {
    "/usr/lib/aragorn/aragorn/runtime_action_worker.py": (
        46629,
        "df55f788ed29d188c71ca201d5778e7bff734b9a2f09445d8247c4ab6f40cd32",
        0o644,
    ),
    "/usr/lib/aragorn/aragorn/runtime_endpoint_journal.py": (
        17052,
        "c6decbe2de6c0ba48af7b2ccda10a38cd98769f43b186fe2f7ef125f01a977f2",
        0o644,
    ),
    "/usr/lib/aragorn/aragorn/runtime_native_tool_receipts.py": (
        22210,
        "b1d3c1d1fcdc3745a166ea39a8123260574a98a0d5e3a0361bf92a43d7581459",
        0o644,
    ),
    "/usr/lib/aragorn/aragorn/runtime_native_tool_provisioning.py": (
        15105,
        "d5944c938677dc4e5c693627629194e3869a76abbf695b710d8f9965833aaee0",
        0o644,
    ),
    "/usr/lib/aragorn/aragorn/runtime_native_gateway_credentials.py": (
        10362,
        "7cfdcf2a6ac8ee49af900b486f0e67ec9a44a5e86c0f752fd891dc1225adcaae",
        0o644,
    ),
    "/usr/libexec/aragorn/aragorn-runtime-native-gateway-credentials.py": (
        353,
        "30fea987fff036b206852e008b67f0eea4e9d805a43449e3f73ed3c8327b2865",
        0o755,
    ),
    "/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/index.js": (
        35434,
        "193415bea885023664ac44931d9faa096e02b3bc64aafc47113c17aca664566c",
        0o644,
    ),
    "/usr/lib/aragorn/openclaw/aragorn-runtime-native-tool-client/integration.cjs": (
        5149,
        "a542165168c1d5655cad4fdde1e69609cfd87bfea2b9909a9343bcde00e1bbad",
        0o644,
    ),
    "/usr/lib/systemd/system/aragorn-runtime-action-worker.service": (
        2946,
        "dd8b741f13be3e1bd4c646bbabb5995c4cc843792a5d29efde862c43da283665",
        0o644,
    ),
    "/usr/lib/systemd/system/aragorn-agent-gateway.service": (
        3564,
        "7c9993591363e382ceed407f055a48fe2b5fc539387342487f43ce3575d27317",
        0o644,
    ),
    "/usr/libexec/aragorn/activate-runtime-action-worker-host.sh": (
        *_ACTIVATOR_PIN[:1],
        _ACTIVATOR_PIN[1][7:],
        0o755,
    ),
}


class _FixtureRefusal(RuntimeError):
    """Only fixed checker assertions; never wraps external diagnostic text."""


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise _FixtureRefusal(message)


def _phase(value: str) -> None:
    global _PHASE
    _expect(
        value
        in {
            "PRECHECK",
            "SOURCES",
            "FRESH_INPUTS",
            "PROVISION",
            "ACTIVATION",
            "STARTUP",
            "READ",
            "READ_RECEIPTS",
            "CREATE_CONTROLS",
            "CREATE",
            "EFFECT_PROOF",
            "FINAL_RECEIPTS",
            "JOURNAL",
            "FINAL_IDENTITIES",
            "CLEANUP",
        },
        "unknown fixture phase",
    )
    _PHASE = value


def _sources() -> dict:
    # Replace only the frozen helper's pin inventory for this bounded successor.
    with patch.object(prior, "_CODE", prior._CODE | _EXTRA_CODE):
        result = prior._sources()
    raw = response._read_regular(_DRIVER, 0, {0o444})
    _expect(
        (len(raw), prior._digest(raw)) == _DRIVER_PIN, "native fixture driver changed"
    )
    result[str(_DRIVER)] = {"bytes": len(raw), "digest": prior._digest(raw)}
    return result


def _credentials(raw: str, unit: str) -> None:
    common = ("native-tool-genesis", "/etc/aragorn/runtime-native-tool-genesis.json")
    config = ("openclaw-config", "/etc/aragorn/agent-gateway/openclaw.json")
    values = (config, common)
    if unit == setup_prior._WORKER:
        values = (
            ("worker-binding", "/etc/aragorn/runtime-action-worker.json"),
            *values,
        )
    else:
        _expect(unit == setup_prior._GATEWAY, "unexpected credential unit")
    fields = shlex.split(raw)
    _expect(
        any(
            fields == ["a(ss)", str(len(values)), *itertools.chain.from_iterable(order)]
            for order in itertools.permutations(values)
        ),
        "native credential projection changed",
    )


def _startup() -> dict:
    result = {}
    for unit in (setup_prior._WORKER, setup_prior._GATEWAY):
        object_path = "/org/freedesktop/systemd1/unit/" + unit.replace(
            "-", "_2d"
        ).replace(".", "_2e")
        raw = (
            response._command(
                [
                    "/usr/bin/busctl",
                    "get-property",
                    "org.freedesktop.systemd1",
                    object_path,
                    "org.freedesktop.systemd1.Service",
                    "LoadCredential",
                ],
                timeout=3,
            )
            .decode("ascii")
            .strip()
        )
        _credentials(raw, unit)
        result[unit] = raw
    state = response._show_unit(
        setup_prior._WORKER,
        (
            "Id",
            "ActiveState",
            "MainPID",
            "ControlPID",
            "ExecStartPre",
            "StateDirectory",
            "StateDirectoryMode",
            "RuntimeDirectory",
            "RuntimeDirectoryMode",
            "LimitNOFILE",
            "LimitNOFILESoft",
            "BindsTo",
        ),
    )
    _expect(
        state["ActiveState"] == "active"
        and re.fullmatch(r"[1-9][0-9]*", state["MainPID"]) is not None
        and state["ControlPID"] == "0"
        and state["StateDirectory"] == "aragorn-runtime-tool-receipts"
        and state["StateDirectoryMode"] == "0700"
        and state["RuntimeDirectory"] == "aragorn-runtime-action-worker"
        and state["RuntimeDirectoryMode"] == "0711"
        and state["LimitNOFILE"] == state["LimitNOFILESoft"] == "128"
        and state["BindsTo"] == setup_prior._SENSOR
        and state["ExecStartPre"].startswith(
            "{ path=/usr/bin/python3.12 ; argv[]="
            + setup_prior._STARTUP
            + " ; ignore_errors=no ; "
        )
        and state["ExecStartPre"].count("argv[]=") == 1
        and re.search(
            r"; pid=[1-9][0-9]* ; code=exited ; status=0(?:/SUCCESS)? }$",
            state["ExecStartPre"],
        )
        is not None,
        "mandatory native startup check changed",
    )
    return {"worker": state, "load_credentials": result}


def _prepare() -> dict:
    _phase("FRESH_INPUTS")
    import runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe as v3

    combined, p37c = v3.combined, v3.p37c
    p37b, openclaw = p37c.p37b, p37c.openclaw
    broker_uid, worker_uid, worker_gid, gateway_uid, gateway_gid, *_ = (
        response._identities()
    )
    # Fresh container only: never initialize/reset a previously provisioned stream.
    provision._stopped()
    _expect(
        not os.path.lexists(provision._STORE)
        and not os.path.lexists(provision._GENESIS_SOURCE),
        "native stream already exists",
    )
    response._EVIDENCE_ROOT.mkdir(mode=0o700)
    combined._reset_transient_request_directory()
    p37b.prior.lineage._reset()
    producer = p37b.prior._prepare_producer(worker_gid)
    p37b.prior._producer = producer
    skill_path = producer["paths"]["skill"]
    skill_raw = skill_path.read_bytes()
    skill = prior._digest(skill_raw)
    _expect(skill == v3._SKILL_DIGEST, "fixed external skill changed")
    p37b._reset_action_plane()
    with patch.object(combined, "_CONFIG", v3._CONFIG):
        config, _, _, _ = combined._prepare_gateway(
            gateway_uid, gateway_gid, worker_uid, producer["skill_name"], skill_raw
        )
    fd = os.open(p37c.lineage._PROTECTED, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        action = p37c._action_digests(fd, p37b._TARGET, p37b._PAYLOAD)
    finally:
        os.close(fd)
    policy = {
        "schema": "aragorn/runtime-action-policy/v1",
        "id": "owned-native-receipt-read-create",
        "version": 1,
        "default": "BLOCK",
        "sensor_digest": openclaw._SENSOR_DIGEST,
        "revocation_source_digest": openclaw._REVOCATION_SOURCE,
        "allow": [{"runtime_digest": _RUNTIME, "active_skill_digest": skill, **action}],
    }
    binding = {
        "schema": "aragorn/runtime-action-worker-binding/v1",
        "runtime_digest": _RUNTIME,
        "active_skill_digest": skill,
        "policy_digest": canonical_digest(policy),
        "policy_version": 1,
    }
    document, profile = p37b._profile(
        runtime_digest=_RUNTIME,
        executable_digest=p37c._file(p37b._PYTHON.resolve(strict=True))["digest"],
        cgroup=p37b._predicted_service_cgroup(p37b._WORKER_UNIT),
        skill_path=skill_path,
    )
    now = int(time.time())
    with patch.object(openclaw, "_RUNTIME_DIGEST", _RUNTIME):
        grant = p37c._grant(
            profile_digest=profile.digest,
            policy=policy,
            action=action,
            producer=producer,
            skill_digest=skill,
            issued_at=now - 1,
            expires_at=now + 240,
        )
        controls = p37b._controls(policy, action, skill, now, 1)
        p37b._write_stack_inputs(
            profile_document=document,
            profile_digest=profile.digest,
            worker_binding=binding,
            grant=grant,
            controls=controls,
            broker_uid=broker_uid,
            worker_gid=worker_gid,
        )
    # Must precede activator/StateDirectory. This is a separate root operation;
    # neither gateway nor worker can choose its externally bound genesis.
    _phase("PROVISION")
    provisioned = provision.provision_runtime_native_tool_receipts()
    _expect(
        provisioned["runtime_digest"] == _RUNTIME
        and provisioned["policy_digest"] == binding["policy_digest"]
        and provisioned["receipts"] == 0
        and provisioned["activation_performed"] is False,
        "provisioning binding changed",
    )
    empty = _snapshot(provisioned["genesis_digest"], 0)
    read_fd = os.open(
        _READ_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444
    )
    try:
        _expect(
            os.write(read_fd, _READ_BYTES) == len(_READ_BYTES),
            "inert read file incomplete",
        )
        os.fchmod(read_fd, 0o444)
        os.fsync(read_fd)
    finally:
        os.close(read_fd)
    _phase("ACTIVATION")
    activation = p37c._command([str(p37c._ACTIVATOR)], timeout=60)
    _expect(activation["exit_code"] == 0, "native fixture activation failed")
    _phase("STARTUP")
    return {
        "runtime_digest": _RUNTIME,
        "configuration_digest": canonical_digest(config),
        "skill_digest": skill,
        "producer_transaction": producer["transaction"],
        "producer_authority": "LEGACY_INITIAL_FIXTURE_INSTALL_NOT_SUCCESSOR_PRODUCER_DEPLOYMENT",
        "worker_binding": binding,
        "runtime_profile": document,
        "grant": grant,
        "policy": policy,
        "provisioning": provisioned,
        "empty_store": empty,
        "startup": _startup(),
        "activation_exit_code": 0,
    }


def _chain(
    genesis: dict, state: dict, receipts: list[dict], expected: str, count: int
) -> None:
    core._exact(genesis, core._GENESIS_FIELDS)
    for name in ("stream_id", "runtime_digest", "policy_digest"):
        core._digest(genesis[name])
    for name in ("worker_uid", "worker_gid"):
        core._uint(genesis[name], 2**32 - 1, 1)
    core._uint(genesis["policy_version"], 2**53 - 1, 1)
    _expect(
        genesis["schema"] == "aragorn/native-tool-receipt-genesis/v1"
        and genesis["authority"]
        == "ROOT_PROVISIONED_WORKER_RECEIPT_STREAM_NOT_RUN_AUTHORITY"
        and canonical_digest(genesis) == expected
        and genesis["runtime_digest"] == _RUNTIME,
        "native genesis changed",
    )
    core._exact(state, {"schema", "authority", "genesis_digest", "receipts"})
    _expect(
        state["schema"] == "aragorn/native-tool-receipt-state/v1"
        and state["authority"] == core._RETAINED_AUTHORITY
        and state["genesis_digest"] == expected
        and type(state["receipts"]) is list
        and len(state["receipts"]) == count
        and type(count) is int
        and count in {0, 2, 4}
        and type(receipts) is list
        and len(receipts) == count
        and len(set(state["receipts"])) == count,
        "native state count changed",
    )
    previous = expected
    keys = set()
    for index, receipt in enumerate(receipts):
        core._exact(
            receipt,
            {
                "schema",
                "authority",
                "genesis_digest",
                "sequence",
                "previous_digest",
                "event",
            },
        )
        digest = canonical_digest(receipt)
        _expect(
            receipt["schema"] == "aragorn/native-tool-receipt/v1"
            and receipt["authority"] == core._RETAINED_AUTHORITY
            and type(receipt["sequence"]) is int
            and receipt["sequence"] == index + 1
            and receipt["previous_digest"] == previous
            and receipt["genesis_digest"] == expected
            and state["receipts"][index] == digest,
            "native receipt chain changed",
        )
        event = core._event(receipt["event"], terminal=bool(index % 2))
        if index % 2:
            core._joins_terminal(event, receipts[index - 1])
        else:
            key = core._call_key(event, expected)
            _expect(key not in keys, "native call repeated")
            keys.add(key)
        previous = digest


def _snapshot(expected: str, count: int) -> dict:
    _, uid, gid, *_ = response._identities()
    held = []
    lock = None
    try:
        etc = provision._root_directory(provision._GENESIS_SOURCE.parent, held)
        source = provision._hold_file(
            etc, provision._GENESIS_SOURCE.name, 0, 0, 0o400, 4096, held
        )
        parent = provision._root_directory(provision._STORE.parent, held)

        def directory(parent_fd: int, name: str) -> int:
            fd = os.open(name, provision._DIRECTORY_FLAGS, dir_fd=parent_fd)
            try:
                metadata = os.fstat(fd)
                entry = provision._Held(
                    parent_fd,
                    name,
                    fd,
                    response.broker._directory_identity(metadata),
                    True,
                )
                held.append(entry)
            except BaseException:
                os.close(fd)
                raise
            _expect(
                stat.S_ISDIR(metadata.st_mode)
                and stat.S_IMODE(metadata.st_mode) == 0o700
                and metadata.st_uid == uid
                and metadata.st_gid == gid
                and metadata.st_nlink > 0,
                "native store directory changed",
            )
            provision._recheck([entry])
            return fd

        root = directory(parent, provision._STORE.name)
        lock = provision._hold_file(root, "receipt.lock", uid, gid, 0o600, 0, held)
        fcntl.flock(lock.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        core._inventory(root, {"genesis.json", "state.json", "receipt.lock", "cas"})
        genesis_file = provision._hold_file(
            root, "genesis.json", uid, gid, 0o400, 4096, held
        )
        state_file = provision._hold_file(
            root, "state.json", uid, gid, 0o400, 4096, held
        )
        _expect(genesis_file.raw == source.raw, "store and root genesis differ")
        genesis = response.broker._parse_canonical_document(
            source.raw, "native genesis"
        )
        state = response.broker._parse_canonical_document(
            state_file.raw, "native state"
        )
        _expect(
            genesis["worker_uid"] == uid
            and genesis["worker_gid"] == gid
            and type(state.get("receipts")) is list
            and len(state["receipts"]) == count <= 4,
            "native snapshot ownership or count changed",
        )
        parent = directory(root, "cas")
        for name in ("blobs", "sha256"):
            core._inventory(parent, {name})
            parent = directory(parent, name)
        for digest in state["receipts"]:
            core._digest(digest)
        prefixes = {digest[7:9] for digest in state["receipts"]}
        core._inventory(parent, prefixes)
        documents = {}
        for prefix in sorted(prefixes):
            prefix_fd = directory(parent, prefix)
            names = {
                digest[9:] for digest in state["receipts"] if digest[7:9] == prefix
            }
            core._inventory(prefix_fd, names)
            for name in sorted(names):
                item = provision._hold_file(
                    prefix_fd, name, uid, gid, 0o444, core._MAX_EVENT_BYTES, held
                )
                digest = "sha256:" + prefix + name
                _expect(prior._digest(item.raw) == digest, "native CAS digest changed")
                documents[digest] = response.broker._parse_canonical_document(
                    item.raw, "native receipt"
                )
        receipts = [documents[digest] for digest in state["receipts"]]
        _chain(genesis, state, receipts, expected, count)
        provision._recheck(held)
        result = {
            "genesis": genesis,
            "state": state,
            "receipts": receipts,
            "state_digest": canonical_digest(state),
        }
    finally:
        try:
            if lock is not None:
                fcntl.flock(lock.fd, fcntl.LOCK_UN)
        finally:
            provision._close(held)
    return result


def _receipt_proof(snapshot: dict, drivers: list[dict]) -> list[dict]:
    _expect(type(drivers) is list and len(drivers) == 2, "native driver pair changed")
    receipts = snapshot["receipts"]
    expected = canonical_digest(snapshot["genesis"])
    _chain(snapshot["genesis"], snapshot["state"], receipts, expected, 4)
    acks = []
    for index, driver in enumerate(drivers):
        identifiers = driver["turn"]["identifiers"]
        correlation = {name: identifiers[name] for name in core._CORRELATION}
        tool = "read" if index == 0 else "aragorn_runtime_create"
        _expect(
            driver["tool_name"] == tool
            and driver["status"] == "OBSERVED"
            and driver["phase3_eligible"] is False
            and driver["run_conformance_eligible"] is False,
            "driver authority changed",
        )
        projection = driver["native_projection"]
        core._exact(projection, {"params", "result"})
        for item in projection.values():
            core._exact(item, {"bytes", "digest"})
            core._uint(item["bytes"], core._MAX_REPORTED_BYTES)
            core._digest(item["digest"])
        attempt, terminal = receipts[2 * index : 2 * index + 2]
        _expect(
            attempt["event"]
            == {
                "schema": "aragorn/native-tool-attempt/v1",
                "authority": core._AUTHORITY,
                "tool_name": tool,
                **correlation,
                "params_digest": projection["params"]["digest"],
                "params_bytes": projection["params"]["bytes"],
                "worker_request_digest": identifiers["request_digest"],
            }
            and terminal["event"]
            == {
                "schema": "aragorn/native-tool-terminal/v1",
                "authority": core._AUTHORITY,
                "tool_name": tool,
                **correlation,
                "attempt_digest": canonical_digest(attempt),
                "outcome": "RETURNED",
                "result_digest": projection["result"]["digest"],
                "result_bytes": projection["result"]["bytes"],
                "error_code": None,
            },
            "native driver final params/result and receipt differ",
        )
        for receipt, status in (
            (attempt, "ATTEMPT_RECORDED_EXECUTE_ONCE"),
            (terminal, "TERMINAL_RECORDED"),
        ):
            acks.append(
                {
                    "schema": "aragorn/native-tool-receipt-ack/v1",
                    "authority": core._RETAINED_AUTHORITY,
                    "genesis_digest": expected,
                    "receipt_digest": canonical_digest(receipt),
                    "event_digest": canonical_digest(receipt["event"]),
                    "sequence": receipt["sequence"],
                    "status": status,
                    "effect_authorized": False,
                    "run_qualified": False,
                }
            )
    return acks


def _driver(p37b: Any, kind: str, nonce: str, token: str) -> dict:
    input_path = p37b._DRIVER_ROOT / f"native-{kind}-{nonce}.input.json"
    output_path = p37b._DRIVER_ROOT / f"native-{kind}-{nonce}.output.json"
    driver_input = {
        "schema": "aragorn/openclaw-worker-driver-input/v1",
        "scenario": {
            "id": f"native-{kind}-{nonce}",
            "target_name": p37b._TARGET,
            "content": p37b._PAYLOAD.decode("ascii"),
            "expected_result": {
                "schema": "aragorn/runtime-action-worker-result/v1",
                "status": "COMPLETED",
                "broker_result": {"verdict": "ALLOW", "effect_status": "CREATED"},
            },
        },
    }
    _expect(not os.path.lexists(input_path), "native driver input already exists")
    # The legacy driver's input contract requires exactly one final newline;
    # control documents intentionally use a different, no-newline encoding.
    p37b.openclaw.profile_prior._write_file(
        input_path, canonical_json(driver_input) + b"\n", 0, 0, 0o400
    )
    argv = [str(p37b._NODE), str(_DRIVER), kind, str(input_path), str(output_path)]
    completed = p37b.subprocess.run(
        argv,
        capture_output=True,
        check=False,
        timeout=50,
        env={
            "HOME": str(p37b._GATEWAY_HOME),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "NO_PROXY": "127.0.0.1,localhost",
            "OPENCLAW_CONFIG_PATH": str(p37b._GATEWAY_CONFIG),
            "OPENCLAW_STATE_DIR": str(p37b._GATEWAY_STATE),
            "OPENCLAW_GATEWAY_TOKEN": token,
            "ARAGORN_MOCK_PROVIDER_TOKEN": token,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TZ": "UTC",
        },
    )
    if completed.returncode != 0 or completed.stdout or completed.stderr:
        failure = _FixtureRefusal("native driver refused")
        prior._note(
            failure,
            [
                {
                    "operation": "native_driver",
                    "returncode": completed.returncode,
                    "stderr": prior._diagnostic_bytes(completed.stderr, token),
                }
            ],
        )
        prior._stack_failure(failure, token)
        raise failure
    held = []
    try:
        parent = provision._root_directory(output_path.parent, held)
        output_file = provision._hold_file(
            parent, output_path.name, 0, 0, 0o600, 131072, held
        )
        raw = output_file.raw
        provision._recheck(held)
    finally:
        provision._close(held)
    output = response.broker._parse_canonical_document(raw, "native driver")
    _expect(
        output["schema"] == "aragorn/native-receipt-tool-driver/v1"
        and output["status"] == "OBSERVED"
        and output["tool_name"]
        == ("read" if kind == "read" else "aragorn_runtime_create")
        and output["provider"]["request_count"] == 2
        and output["provider"]["error_count"] == 0
        and len(output["provider"]["records"]) == 2
        and output["native_ack_wire_capture"] is False
        and output["phase3_eligible"] is False
        and output["run_conformance_eligible"] is False,
        "native driver result changed",
    )
    return {"argv": argv, "output": output, "output_digest": prior._digest(raw)}


def _collect(cursor: str, processes: dict, boot: str, lower: int) -> dict:
    deadline = time.monotonic() + 3
    while True:
        response._command(["/usr/bin/journalctl", "--sync"], timeout=5)
        result = {}
        for role, unit in prior._ROLES.items():
            limit = 10 if role == "worker" else 2
            raw = response._command(
                [
                    "/usr/bin/journalctl",
                    "--quiet",
                    "--all",
                    "--no-pager",
                    "--output=json",
                    "--output-fields=" + ",".join(prior._JOURNAL_FIELDS),
                    "--lines=" + str(limit + 1),
                    "--cursor=" + cursor,
                    "_SYSTEMD_UNIT=" + unit,
                    "_SYSTEMD_INVOCATION_ID=" + processes[role]["unit"]["InvocationID"],
                    "_BOOT_ID=" + boot,
                ],
                timeout=3,
            )
            lines = raw.splitlines(keepends=True)
            _expect(
                len(raw) <= 65536 and len(lines) <= limit, "native journal overflow"
            )
            rows = []
            # Preserve every strict old metadata check and its 8-row per-parser bound.
            for offset in range(0, len(lines), 8):
                rows.extend(
                    prior._rows(
                        b"".join(lines[offset : offset + 8]),
                        role,
                        processes[role],
                        boot,
                        lower,
                        time.monotonic_ns() // 1000,
                    )
                )
            _expect(
                all(row["journal"]["__CURSOR"] != cursor for row in rows),
                "journal baseline returned",
            )
            result[role] = {"raw_jsonl": raw.decode("ascii"), "rows": rows}
        if {role: len(item["rows"]) for role, item in result.items()} == {
            "worker": 10,
            "sensor": 2,
            "broker": 2,
        }:
            return result
        _expect(time.monotonic() < deadline, "native journal records missing")
        time.sleep(0.02)


def _journal_proof(
    captured: dict, processes: dict, acks: list[dict], effect: dict
) -> None:
    _expect(
        set(captured) == set(prior._ROLES) and len(acks) == 4,
        "native journal inventory changed",
    )
    cursors, attempts, terminals = set(), set(), {}
    for role, item in captured.items():
        rows = item["rows"]
        _expect(
            len(rows) == (10 if role == "worker" else 2), "native journal count changed"
        )
        terminals[role] = []
        for first, last in zip(rows[::2], rows[1::2], strict=True):
            start, end = first["event"], last["event"]
            expected = prior.journal._new(role)
            expected["attempt_id"] = start["attempt_id"]
            _expect(
                start == expected
                and end["attempt_id"] == start["attempt_id"]
                and end["phase"] == "TERMINAL"
                and start["attempt_id"] not in attempts
                and int(first["journal"]["__MONOTONIC_TIMESTAMP"])
                <= int(last["journal"]["__MONOTONIC_TIMESTAMP"]),
                "native journal pair changed",
            )
            attempts.add(start["attempt_id"])
            for row in (first, last):
                cursor = row["journal"]["__CURSOR"]
                _expect(cursor not in cursors, "duplicate native journal cursor")
                cursors.add(cursor)
            peer = processes[
                {"worker": "gateway", "sensor": "worker", "broker": "sensor"}[role]
            ]["process"]
            _expect(
                end["peer"] == {key: peer[key] for key in ("pid", "uid", "gid")}
                and end["peer_expected"] is True
                and end["handler_status"] == "RETURNED"
                and end["stage"] == "CLIENT_DELIVERY"
                and end["client_delivery"] == "FRAME_SENT_NOT_ACKNOWLEDGED"
                and end["request_state"] == "VALIDATED",
                "native endpoint peer/delivery changed",
            )
            terminals[role].append(end)
    for end, ack in zip(
        [terminals["worker"][i] for i in (0, 1, 2, 4)], acks, strict=True
    ):
        _expect(
            end["receipt_operation"]
            == ("ATTEMPT" if ack["sequence"] % 2 else "TERMINAL")
            and end["receipt_state"] == ack["status"]
            and end["result_kind"] == "LOCAL_RECEIPT_ACK"
            and end["outcome"] == "LOCAL_RECEIPT_ACK_OBSERVED"
            and end["submission"] == "NOT_STARTED"
            and end["action_request_digest"] is None
            and end["profile_attribution_digest"] is None
            and end["worker_status"] is None
            and end["worker_request_digest"] == ack["event_digest"]
            and end["result_digest"] == canonical_digest(ack),
            "native receipt journal ACK digest differs",
        )
    receipt = effect["receipt"]
    for role, end in (
        ("worker", terminals["worker"][3]),
        ("sensor", terminals["sensor"][0]),
        ("broker", terminals["broker"][0]),
    ):
        _expect(
            end["receipt_operation"] is None
            and end["receipt_state"] is None
            and end["action_request_digest"]
            == receipt["broker_result"]["request_digest"]
            and end["result_digest"] == receipt["broker_result_digest"]
            and end["submission"]
            == ("CORE_ENTERED" if role == "broker" else "SEND_ATTEMPTED"),
            "ordinary create journal result differs",
        )
        if role == "worker":
            _expect(
                end["worker_request_digest"] == effect["worker_request_digest"]
                and end["worker_status"] == "COMPLETED",
                "ordinary worker request differs",
            )
        else:
            _expect(
                end["profile_attribution_digest"]
                == receipt["runtime_attribution_digest"],
                "profile attribution differs",
            )
        if role == "sensor":
            _expect(
                end["result_kind"] == "CANONICAL_REPLY_ONLY"
                and end["outcome"] == "REPLY_RELAYED_EFFECT_UNVERIFIED",
                "sensor exceeds its reply observation",
            )
        else:
            _expect(
                end["result_kind"] == "VALIDATED_BROKER_RESULT"
                and end["outcome"] == "BROKER_RESULT_OBSERVED"
                and end["verdict"] == "ALLOW"
                and end["effect_status"] == "CREATED",
                "create journal effect outcome differs",
            )


def _run(container: str) -> dict:
    _phase("PRECHECK")
    setup_prior._require_fixture(container)
    _phase("SOURCES")
    sources = _sources()
    try:
        setup = _prepare()
        import runtime_action_worker_openclaw_systemd_probe as p37b

        processes, boot = prior._processes(container), prior._boot()
        installed = setup_prior._installed(setup["skill_digest"])
        _expect(installed["denial"] is None, "fresh native fixture is denied")
        read_identity = response.broker._file_identity(_READ_PATH.lstat())
        _expect(
            response._read_regular(_READ_PATH, 0, {0o444}) == _READ_BYTES,
            "inert read input changed",
        )
        p37b._DRIVER_ROOT.mkdir(mode=0o700)
        raw = response._read_regular(p37b._GATEWAY_ENVIRONMENT, 0, {0o400})
        match = re.fullmatch(rb"OPENCLAW_GATEWAY_TOKEN=([0-9a-f]{64})\n", raw)
        _expect(match is not None, "fixture token unavailable")
        token = match[1].decode("ascii")
        cursor, lower, nonce = (
            prior._cursor(),
            time.monotonic_ns() // 1000,
            secrets.token_hex(8),
        )
        before = p37b._snapshot_effects()
        _phase("READ")
        read = _driver(p37b, "read", nonce, token)
        _expect(
            p37b._driver_gateway_pid(read) == processes["gateway"]["process"]["pid"],
            "read used another gateway process",
        )
        _phase("READ_RECEIPTS")
        middle = _snapshot(setup["provisioning"]["genesis_digest"], 2)
        _expect(p37b._snapshot_effects() == before, "read changed broker effects")
        _phase("CREATE_CONTROLS")
        with patch.object(p37b.openclaw, "_RUNTIME_DIGEST", _RUNTIME):
            # Fresh fixture control snapshot only, before the sole create. This
            # neither changes the grant nor renews its fixed wall/mono lifetime.
            fd = os.open(
                p37b.lineage._PROTECTED, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            try:
                action = p37b._action_digests(fd, p37b._TARGET, p37b._PAYLOAD)
            finally:
                os.close(fd)
            p37b._refresh_controls(
                setup["policy"],
                action,
                setup["skill_digest"],
                response._identities()[0],
                response._identities()[2],
                2,
            )
        before_create = p37b._snapshot_effects()
        _phase("CREATE")
        create = _driver(p37b, "create", nonce, token)
        _phase("EFFECT_PROOF")
        after = p37b._snapshot_effects()
        effect = prior._proof(p37b, create, before_create, after, processes)
        _phase("FINAL_RECEIPTS")
        final = _snapshot(setup["provisioning"]["genesis_digest"], 4)
        _expect(
            final["genesis"] == middle["genesis"] == setup["empty_store"]["genesis"]
            and final["receipts"][:2] == middle["receipts"],
            "native receipt prefix changed",
        )
        acks = _receipt_proof(final, [read["output"], create["output"]])
        _phase("JOURNAL")
        captured = _collect(cursor, processes, boot, lower)
        _journal_proof(captured, processes, acks, effect)
        _phase("FINAL_IDENTITIES")
        _expect(
            prior._processes(container) == processes
            and prior._boot() == boot
            and _sources() == sources
            and setup_prior._installed(setup["skill_digest"]) == installed
            and response.broker._file_identity(_READ_PATH.lstat()) == read_identity
            and response._read_regular(_READ_PATH, 0, {0o444}) == _READ_BYTES,
            "native fixture changed unexpectedly",
        )
        observation = {
            "schema": "aragorn/runtime-native-receipt-systemd-integration-observation/v1",
            "authority": "OWNED_LOCAL_READ_CREATE_OBSERVATION_NOT_COMPLETE_CAPTURE_OR_RUN_AUTHORITY",
            "status": "OBSERVED",
            "fixture_container": container,
            "setup": setup,
            "installed_sources": sources,
            "processes": processes,
            "boot_id": boot,
            "read": read,
            "create": create,
            "receipt_store_after_read": middle,
            "receipt_store_after_create": final,
            "expected_acknowledgements": acks,
            "journal": captured,
            "effect_proof": effect,
            "phase3_eligible": False,
            "run_conformance_eligible": False,
            "complete_event_coverage": False,
            "native_ack_wire_capture": False,
            "limitations": [
                "ONE_OWNED_INERT_READ_AND_NONEXECUTING_CREATE_NOT_GENERAL_TOOL_COMPATIBILITY",
                "GATEWAY_REPORTS_AND_PINNED_HOOK_PATH_NOT_HOSTILE_SAME_PROCESS_CAUSATION",
                "ACK_DIGEST_JOURNAL_JOIN_AND_CLIENT_PATH_NOT_WIRE_CAPTURE_OR_JOURNAL_DURABILITY",
                "NO_PROGRESS_TRANSCRIPT_POSTPROCESSING_OR_INTERMEDIATE_EFFECT_COVERAGE",
                "NO_HOSTILE_OWNER_ROLLBACK_LATENCY_EXTERNAL_COLLECTOR_HEALTH_OR_RUN_QUALIFICATION",
            ],
        }
    finally:
        previous_phase = _PHASE
        _phase("CLEANUP")
        cleanup = prior._stop_fixture()
        _phase(previous_phase)
    observation["fixture_stack_cleanup"] = cleanup
    return observation


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print(
            "usage: runtime_native_receipt_systemd_check OWNED_CONTAINER_ID",
            file=sys.stderr,
        )
        return 64
    try:
        result = _run(arguments[0])
    except Exception as exc:  # noqa: BLE001 - never emit arbitrary fixture or credential diagnostics
        print(
            "native receipt fixture not confirmed: "
            + _PHASE
            + ":"
            + (exc.args[0] if type(exc) is _FixtureRefusal else type(exc).__name__),
            file=sys.stderr,
        )
        if type(exc) is _FixtureRefusal:
            # Only this checker's fresh refusal receives the bounded, token-redacted
            # notes above; inherited exceptions and their notes remain suppressed.
            for note in getattr(exc, "__notes__", ())[:2]:
                print(note, file=sys.stderr)
        return 126
    print(canonical_json(result).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
