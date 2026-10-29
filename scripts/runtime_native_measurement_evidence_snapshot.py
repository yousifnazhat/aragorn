"""Read only the fixed public ingress and effective-receipt closure.

This exporter never opens the broker input CAS or a grant credential, discovers
arbitrary digest graphs, executes a workload, or treats local reads as capture
qualification. It is called once by the already-owned attempt controller.
"""

from __future__ import annotations

import grp
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import threading

if not __package__:
    sys.path.insert(0, "/usr/lib/aragorn")

from aragorn import native_phase3_live_identity as protected
from aragorn import runtime_worker_ingress_verify as worker
from aragorn import runtime_broker_effective_receipt_verify as effective
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/native-measurement-evidence-snapshot/v1"
AUTHORITY = "OWNED_PUBLIC_RECORD_READBACK_NOT_FULL_CAPTURE_OR_MEASUREMENT_VERIFICATION"
SOURCE_PATH = "/opt/aragorn/runtime_native_measurement_evidence_snapshot.py"
WORKER_HELPER = "/usr/lib/aragorn/aragorn/runtime_worker_ingress_measurement.py"
BROKER_HELPER = "/usr/lib/aragorn/aragorn/runtime_broker_decision_measurement.py"
WORKER_ROOT = "/var/lib/aragorn-runtime-worker-measurement"
CONTROL = "/var/lib/aragorn-runtime-action/control"
EVIDENCE = CONTROL + "/decision-measurement-evidence"
_CONTROL_NAMES = {
    "pending": "decision-measurement-pending.json",
    "completion": "decision-measurement-complete.json",
}
_BROKER_FIELDS = {
    "consumed_grant_state": "consumed_grant_state_digest",
    "profile_receipt": "profile_receipt_digest",
    "broker_result": "broker_result_digest",
}
_EVIDENCE_FIELDS = {
    "schema",
    "authority",
    "pending",
    "effective_final_decision",
    *_BROKER_FIELDS.values(),
    "decision",
    "limitations",
}
_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_LIMIT = 128 * 1024
MAX_RESULT = 12 * 1024 * 1024
FALSE_FLAGS = (
    "full_input_closure_verified",
    "independent_capture_replay_complete",
    "measurement_collected",
    "elapsed_time_derived",
    "clock_domain_verified",
    "blocked_pre_effect",
    "causal_attribution",
    "route_qualified",
    "run_conformance_eligible",
    "metrics_eligible",
    "phase3_eligible",
    "live_deployment_attested",
)
LIMITATIONS = (
    "FIXED_SIX_RECORDS_AND_FIVE_PUBLIC_BROKER_BLOBS_ONLY_NOT_WHOLE_STORE_INVENTORY",
    "NO_PRIVATE_INPUT_CAS_GRANT_CREDENTIAL_OR_ARBITRARY_DIGEST_GRAPH_EXPORT",
    "PUBLIC_RECEIPT_JOINS_WITHOUT_PRIVATE_GRANT_SCHEDULE_DEPLOYMENT_INPUT_CLOSURE",
    "CALLER_PINS_AND_SELECTED_SOURCE_BYTES_NOT_LOADED_CODE_OR_EXTERNAL_ATTESTATION",
    "HELD_PIDFD_AND_POINT_IN_TIME_READBACKS_NOT_CONTINUOUS_IMMUTABILITY",
    "MISSING_DRIVER_REQUEST_PINS_ALLOW_PARTIAL_READBACK_ONLY_NEVER_SUCCESS",
    "OUTER_BLOCKED_CREATE_AND_CLOCK_INTERVAL_REPLAY_REMAIN_REQUIRED",
    "NO_EXECUTION_POLICY_CAUSALITY_ELAPSED_TIME_OR_QUALIFICATION_AUTHORITY",
)


class NativeMeasurementEvidenceSnapshotError(ValueError):
    """Fixed public refusal; underlying diagnostics are never exported."""


def _require(value, reason):
    if not value:
        raise NativeMeasurementEvidenceSnapshotError(reason)


def _record(raw):
    return {
        "text": raw.decode("ascii"),
        "bytes": len(raw),
        "digest": protected._digest(raw),
    }


def _raw(record):
    return record["text"].encode("ascii")


def _parse(raw, limit=_LIMIT):
    return effective.prior._parse(raw, limit)


def _exact(value, keys):
    return effective.prior._exact(value, keys)


def _environment(container):
    _require(
        type(container) is str
        and re.fullmatch(r"[0-9a-f]{64}", container)
        and sys.platform == "linux"
        and os.geteuid() == os.getegid() == 0
        and os.getpid() == threading.get_native_id(),
        "OWNED_LINUX_ROOT_MAIN_THREAD_REQUIRED",
    )
    _require(
        protected.process._read_virtual_file(Path("/proc/1/cgroup"), 1024)
        == f"0::/docker/{container}/init.scope\n".encode("ascii"),
        "OWNED_INIT_CGROUP_CHANGED",
    )


def _accounts(expected_worker, expected_broker):
    runtime = pwd.getpwnam("aragorn-runtime")
    broker = pwd.getpwnam("aragorn-broker")
    runtime_gid = grp.getgrnam("aragorn-runtime").gr_gid
    _require(
        runtime.pw_uid == expected_worker["uid"]
        and runtime.pw_gid
        == runtime_gid
        == expected_worker["gid"]
        == expected_broker["gid"]
        and broker.pw_uid == expected_broker["uid"]
        and runtime.pw_uid != broker.pw_uid,
        "FIXED_SERVICE_ACCOUNTS_CHANGED",
    )


def _guard(container, expected_worker, expected_broker, held):
    _environment(container)
    for fd in held.values():
        protected.process.require_live_pidfd(fd)
    for role, expected in (("worker", expected_worker), ("broker", expected_broker)):
        pid = expected["pid"]
        protected.process._require_process_status(pid, expected["uid"], expected["gid"])
        _require(
            protected.process._process_start_time(pid) == expected["start_time_ticks"]
            and protected.process._process_cgroup(pid)
            == f"/docker/{container}/system.slice/{protected._UNITS[role]}",
            "FIXED_PROCESS_EPOCH_OR_CGROUP_CHANGED",
        )
    boot = (
        protected.process._read_virtual_file(
            Path("/proc/sys/kernel/random/boot_id"), 64
        )
        .decode("ascii")
        .strip()
    )
    _require(
        boot == expected_broker["boot_id"]
        and os.readlink(f"/proc/{expected_broker['pid']}/ns/mnt")
        == expected_broker["mount_namespace"],
        "BROKER_BOOT_OR_MOUNT_NAMESPACE_CHANGED",
    )
    namespace = os.stat(f"/proc/{expected_worker['pid']}/ns/time")
    return {"device": namespace.st_dev, "inode": namespace.st_ino}


class _Custody:
    """Held exact directory chain; the existing reader holds every file ancestry."""

    def __init__(self, runtime, broker):
        self.runtime, self.broker = runtime, broker
        self.fds, self.nodes, self.reads, self.partial_reads = [], {}, [], {}
        root = os.open("/", _FLAGS)
        self.fds.append(root)
        try:
            metadata = os.fstat(root)
            _require(
                stat.S_ISDIR(metadata.st_mode)
                and metadata.st_uid == metadata.st_gid == 0
                and not stat.S_IMODE(metadata.st_mode) & 0o022,
                "ROOT_CUSTODY_REFUSED",
            )
        except BaseException as exc:
            try:
                os.close(root)
            except BaseException:
                exc._snapshot_cleanup_failures = ("ROOT_DESCRIPTOR_CLOSE_REFUSED",)
            raise
        self.root = root
        self.nodes["/"] = (
            root,
            None,
            None,
            protected.broker._directory_identity(metadata),
        )

    def _profile(self, path):
        if path == WORKER_ROOT:
            return self.runtime["uid"], self.runtime["gid"], 0o700
        if path == CONTROL:
            return self.broker["uid"], self.broker["gid"], 0o710
        if path == EVIDENCE or path.startswith(EVIDENCE + "/"):
            suffix = path[len(EVIDENCE) :].strip("/")
            _require(
                suffix in ("", "blobs", "blobs/sha256")
                or re.fullmatch(r"blobs/sha256/[0-9a-f]{2}", suffix),
                "UNSUPPORTED_EVIDENCE_DIRECTORY",
            )
            return self.broker["uid"], self.broker["gid"], 0o700
        _require(
            path in ("/var", "/var/lib", "/var/lib/aragorn-runtime-action"),
            "UNSUPPORTED_HELD_DIRECTORY",
        )
        return 0, 0, 0o755 if path.endswith("aragorn-runtime-action") else None

    def hold(self, path):
        if path in self.nodes:
            return self.nodes[path][0]
        parent = self.hold(str(Path(path).parent))
        name = Path(path).name
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        fd = os.open(name, _FLAGS, dir_fd=parent)
        self.fds.append(fd)
        item = os.fstat(fd)
        uid, gid, mode = self._profile(path)
        _require(
            stat.S_ISDIR(item.st_mode)
            and (item.st_uid, item.st_gid) == (uid, gid)
            and not stat.S_IMODE(item.st_mode) & 0o022
            and (mode is None or stat.S_IMODE(item.st_mode) == mode)
            and protected.broker._directory_identity(item)
            == protected.broker._directory_identity(before),
            "PUBLIC_DIRECTORY_CUSTODY_REFUSED",
        )
        self.nodes[path] = (
            fd,
            parent,
            name,
            protected.broker._directory_identity(item),
        )
        return fd

    def guard(self):
        for fd, parent, name, identity in self.nodes.values():
            _require(
                protected.broker._directory_identity(os.fstat(fd)) == identity,
                "HELD_DIRECTORY_CHANGED",
            )
            if parent is not None:
                _require(
                    protected.broker._directory_identity(
                        os.stat(name, dir_fd=parent, follow_symlinks=False)
                    )
                    == identity,
                    "NAMED_DIRECTORY_CHANGED",
                )

    def read(self, path, uid, gid, mode, limit):
        self.guard()
        raw, metadata = protected._read_at(
            self.root, path, owner=uid, owner_gid=gid, modes={mode}, limit=limit
        )
        self.reads.append((path, uid, gid, mode, limit, raw, metadata))
        self.partial_reads[path] = raw
        self.guard()
        return raw

    def worker_inventory(self):
        fd = self.hold(WORKER_ROOT)
        scan = os.open(".", _FLAGS, dir_fd=fd)
        self.fds.append(scan)
        names = set()
        with os.scandir(scan) as entries:
            for index, entry in enumerate(entries):
                _require(index < 4, "WORKER_PUBLIC_INVENTORY_EXCEEDED")
                names.add(entry.name)
        _require(
            names == {stage + ".json" for stage in worker.STAGES},
            "WORKER_PUBLIC_INVENTORY_INCOMPLETE",
        )

    def final_readbacks(self, failures):
        interruption = None
        for index, (path, uid, gid, mode, limit, raw, metadata) in enumerate(
            self.reads
        ):
            try:
                current, current_metadata = protected._read_at(
                    self.root, path, owner=uid, owner_gid=gid, modes={mode}, limit=limit
                )
                _require(
                    current == raw and current_metadata == metadata,
                    "PUBLIC_READBACK_CHANGED",
                )
            except BaseException as exc:
                failures.append("PUBLIC_READBACK_" + str(index) + "_REFUSED")
                if not isinstance(exc, Exception) and interruption is None:
                    interruption = exc
        try:
            self.guard()
        except BaseException as exc:
            failures.append("HELD_DIRECTORIES_FINAL_REFUSED")
            if not isinstance(exc, Exception) and interruption is None:
                interruption = exc
        return interruption

    def close(self, failures):
        interruption = None
        for fd in reversed(self.fds):
            try:
                os.close(fd)
            except BaseException as exc:
                failures.append("PUBLIC_DESCRIPTOR_CLOSE_REFUSED")
                if not isinstance(exc, Exception) and interruption is None:
                    interruption = exc
        return interruption


def _evidence(document):
    value = _exact(document, _EVIDENCE_FIELDS)
    _require(
        value["schema"] == "aragorn/runtime-broker-decision-measurement/v2"
        and value["authority"]
        == "VALIDATED_GRANT_REDEMPTION_TIMING_ONLY_NOT_FULL_REQUEST_LATENCY_OR_PHASE3"
        and value["limitations"] == effective._RETAINED_LIMITS,
        "EFFECTIVE_EVIDENCE_CONTRACT_CHANGED",
    )
    flags = _exact(
        value["decision"],
        {"phase3_exit_eligible", "run_eligible", "quantitative_metrics_eligible"},
    )
    _require(
        all(flag is False for flag in flags.values()), "EVIDENCE_AUTHORITY_ESCALATION"
    )
    return value


def _public_joins(
    report,
    plan,
    expected_worker,
    expected_broker,
    worker_binding,
    genesis,
    request_pin,
    action_pin,
    namespace,
):
    records = report["records"]
    verified = worker.verify_worker_ingress_records(
        *(_raw(records[stage]) for stage in worker.STAGES),
        expected_record_digests=report["record_digests"],
        expected_worker=expected_worker,
        expected_binding_digest=worker_binding,
        expected_genesis_digest=genesis,
    )
    startup = _parse(_raw(records["startup"]), worker.MAX_RECORD_BYTES)
    _require(
        startup["time_namespace"] == namespace, "RETAINED_WORKER_TIME_NAMESPACE_CHANGED"
    )
    pending = _parse(_raw(records["pending"]))
    completion = _exact(
        _parse(_raw(records["completion"]), 4096),
        {"schema", "pending_digest", "evidence_digest"},
    )
    evidence = _evidence(
        _parse(_raw(report["broker_blobs"][completion["evidence_digest"]]))
    )
    _exact(
        pending,
        {
            "schema",
            "binding",
            "process",
            "clock_id",
            "acceptance_boundary",
            "accepted_boottime_ns",
            "action_request_digest",
            "submission_digest",
            "lease_digest",
            "runtime_attribution_digest",
        },
    )
    _require(
        pending["schema"] == "aragorn/runtime-broker-decision-measurement-pending/v1"
        and pending["binding"] == plan
        and pending["process"] == expected_broker
        and pending["clock_id"] == "CLOCK_BOOTTIME"
        and pending["acceptance_boundary"] == effective.prior._ACCEPTED
        and pending == evidence["pending"]
        and records["pending"]["digest"] == completion["pending_digest"],
        "PENDING_BINDING_PROCESS_OR_COMPLETION_CHANGED",
    )
    _require(
        request_pin is not None and action_pin is not None,
        "DRIVER_REQUEST_PINS_UNAVAILABLE",
    )
    _require(
        verified["worker_request_digest"] == request_pin
        and verified["action_request_digest"]
        == action_pin
        == pending["action_request_digest"],
        "ACTUAL_DRIVER_REQUEST_PIN_CHANGED",
    )
    documents = {
        name: _parse(_raw(report["broker_blobs"][pin]))
        for name, pin in report["broker_blob_digests"].items()
    }
    state = effective.v4._state(documents["consumed_grant_state"], plan["grant_digest"])
    action = _parse(_raw(records["action"]), worker.MAX_RECORD_BYTES)["body"][
        "action_request"
    ]
    submission = effective.prior._canonical_profiled_submission(
        documents["profiled_submission"]
    )
    attribution = effective.prior._profile_attribution(submission)
    _require(
        submission["envelope"]["request"] == action
        and all(
            type(attribution[key]) is int and attribution[key] == expected_worker[key]
            for key in expected_worker
        )
        and all(action[key] == plan[key] for key in effective.prior._MATCH)
        and canonical_digest(attribution) == pending["runtime_attribution_digest"],
        "PUBLIC_SUBMISSION_WORKER_OR_ACTION_CHANGED",
    )
    result = documents["broker_result"]
    joined = effective._result_record(
        state["claim"], documents["profile_receipt"], result, action
    )
    final = _exact(
        evidence["effective_final_decision"],
        {
            "finalized_boottime_ns",
            "verdict",
            "reason_codes",
            "observation_digest",
            "policy_decision_digest",
        },
    )
    _require(
        state["status"] == "CONSUMED"
        and state["result"] == joined
        and canonical_digest(state["claim"]["lease"]) == pending["lease_digest"]
        and state["claim"]["profile_claim"]["submission_digest"]
        == pending["submission_digest"]
        and result["request_digest"] == action_pin
        and all(
            final[key] == result[key]
            for key in ("verdict", "reason_codes", "observation_digest")
        )
        and final["policy_decision_digest"]
        == (
            canonical_digest(result["decision"])
            if result["decision"] is not None
            else None
        )
        and effective.prior._integer(final["finalized_boottime_ns"])
        > effective.prior._integer(pending["accepted_boottime_ns"]),
        "PUBLIC_EFFECTIVE_RECEIPT_JOIN_CHANGED",
    )
    return {
        "worker_ingress_records_joined": True,
        "public_effective_receipt_records_joined": True,
        "private_input_closure_verified": False,
    }


def _classify_public(name, raw, report, plan, epoch, broker, binding, genesis):
    """Recognize fixed public roles before export, independently of final joins.

    This is not a general data declassifier or hostile-owner attestation. A
    missing dependency can prevent classification; its bytes remain local to
    custody, with only a length/digest refusal exported. No prefix is invented.
    """
    value = _parse(raw, worker.MAX_RECORD_BYTES if name in worker.STAGES else _LIMIT)
    core = effective.prior.broker

    def measured_action(item, action):
        _require(
            item
            == {
                "schema": "aragorn/measured-runtime-action/v1",
                **{key: action[key] for key in effective.prior._MEASURED},
            },
            "PUBLIC_MEASURED_ACTION_CHANGED",
        )

    def pending(item):
        _exact(
            item,
            {
                "schema",
                "binding",
                "process",
                "clock_id",
                "acceptance_boundary",
                "accepted_boottime_ns",
                "action_request_digest",
                "submission_digest",
                "lease_digest",
                "runtime_attribution_digest",
            },
        )
        _require(
            item["schema"] == "aragorn/runtime-broker-decision-measurement-pending/v1"
            and item["binding"] == plan
            and item["process"] == broker
            and item["clock_id"] == "CLOCK_BOOTTIME"
            and item["acceptance_boundary"] == effective.prior._ACCEPTED,
            "PUBLIC_PENDING_ROLE_CHANGED",
        )
        effective.prior._integer(item["accepted_boottime_ns"])
        for key in (
            "action_request_digest",
            "submission_digest",
            "lease_digest",
            "runtime_attribution_digest",
        ):
            protected._pin(item[key])

    def result(item):
        _exact(
            item,
            {
                "schema",
                "authority",
                "request_digest",
                "observation_digest",
                "target_name",
                "verdict",
                "reason_codes",
                "effect_status",
                "decision",
            },
        )
        _require(
            item["schema"] == "aragorn/runtime-action-broker-result/v1"
            and item["authority"]
            == "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
            and (item["verdict"], item["effect_status"])
            in (("ALLOW", "CREATED"), ("BLOCK", "NOT_PERFORMED"))
            and type(item["target_name"]) is str
            and re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", item["target_name"]),
            "PUBLIC_BROKER_RESULT_ROLE_CHANGED",
        )
        protected._pin(item["request_digest"])
        protected._pin(item["observation_digest"])
        effective._reasons(item["reason_codes"])
        if item["decision"] is not None:
            action = _parse(_raw(report["records"]["action"]), worker.MAX_RECORD_BYTES)[
                "body"
            ]["action_request"]
            effective._policy(item["decision"], action)

    if name in worker.STAGES:
        value = worker._parse(raw, protected._digest(raw))
        if value["previous_digest"] is not None:
            protected._pin(value["previous_digest"])
        worker._record(value, name, value["previous_digest"], epoch, binding)
        body = value["body"]
        if name == "startup":
            _exact(body, set())
        elif name == "ingress":
            _, payload = worker._ingress(body)
            _require(
                protected._digest(payload) == plan["payload_digest"],
                "PUBLIC_INGRESS_PAYLOAD_CHANGED",
            )
        elif name == "attempt":
            _exact(
                body,
                {
                    "attempt",
                    "attempt_digest",
                    "receipt_state",
                    "receipt_state_digest",
                    "genesis_digest",
                    "worker_request_digest",
                },
            )
            for key in (
                "attempt_digest",
                "receipt_state_digest",
                "genesis_digest",
                "worker_request_digest",
            ):
                protected._pin(body[key])
            receipt = _exact(
                body["attempt"],
                {
                    "schema",
                    "authority",
                    "genesis_digest",
                    "sequence",
                    "previous_digest",
                    "event",
                },
            )
            state = _exact(
                body["receipt_state"],
                {"schema", "authority", "genesis_digest", "receipts"},
            )
            _require(
                receipt["schema"] == "aragorn/native-tool-receipt/v1"
                and state["schema"] == "aragorn/native-tool-receipt-state/v1"
                and receipt["authority"]
                == state["authority"]
                == worker._RECEIPT_AUTHORITY
                and receipt["genesis_digest"]
                == state["genesis_digest"]
                == body["genesis_digest"]
                == genesis,
                "PUBLIC_ATTEMPT_ROLE_CHANGED",
            )
            # An intact prefix enables the existing complete body validator.
            # Without it, do not export an unclassified nested event object.
            ingress = _parse(
                _raw(report["records"]["ingress"]), worker.MAX_RECORD_BYTES
            )
            request, _ = worker._ingress(ingress["body"])
            worker._attempt(body, request, genesis)
        else:
            _exact(
                body,
                {
                    "action_request",
                    "action_request_digest",
                    "worker_request_digest",
                    "attempt_digest",
                },
            )
            action = core._validate_runtime_action_request(body["action_request"])
            for key in (
                "action_request_digest",
                "worker_request_digest",
                "attempt_digest",
            ):
                protected._pin(body[key])
            _require(
                canonical_digest(action) == body["action_request_digest"]
                and all(action[key] == plan[key] for key in effective.prior._MATCH),
                "PUBLIC_ACTION_ROLE_CHANGED",
            )
    elif name == "pending":
        pending(value)
    elif name == "completion":
        _exact(value, {"schema", "pending_digest", "evidence_digest"})
        _require(
            value["schema"]
            == "aragorn/runtime-broker-decision-measurement-complete/v2",
            "PUBLIC_COMPLETION_ROLE_CHANGED",
        )
        protected._pin(value["pending_digest"])
        protected._pin(value["evidence_digest"])
    elif name == "evidence":
        _evidence(value)
        pending(value["pending"])
        final = _exact(
            value["effective_final_decision"],
            {
                "finalized_boottime_ns",
                "verdict",
                "reason_codes",
                "observation_digest",
                "policy_decision_digest",
            },
        )
        effective.prior._integer(final["finalized_boottime_ns"])
        _require(final["verdict"] in ("ALLOW", "BLOCK"), "PUBLIC_FINAL_VERDICT_CHANGED")
        effective._reasons(final["reason_codes"])
        protected._pin(final["observation_digest"])
        if final["policy_decision_digest"] is not None:
            protected._pin(final["policy_decision_digest"])
        for field in _BROKER_FIELDS.values():
            protected._pin(value[field])
    elif name == "consumed_grant_state":
        state = effective.v4._state(value, plan["grant_digest"])
        _require(state["status"] == "CONSUMED", "PUBLIC_CONSUMED_STATE_REQUIRED")
        profile = state["claim"]["profile_claim"]["profile_pending"]
        effective.prior._profile_attribution(profile)
        action = _parse(_raw(report["records"]["action"]), worker.MAX_RECORD_BYTES)[
            "body"
        ]["action_request"]
        measured_action(profile["measured_action"], action)
    elif name == "broker_result":
        result(value)
    elif name == "profile_receipt":
        _exact(
            value,
            {
                "schema",
                "authority",
                "submission_digest",
                "runtime_attribution",
                "runtime_attribution_digest",
                "broker_result",
                "broker_result_digest",
            },
        )
        _require(
            value["schema"] == "aragorn/runtime-process-profile-receipt/v1"
            and value["authority"]
            == "BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
            "PUBLIC_PROFILE_RECEIPT_ROLE_CHANGED",
        )
        effective.prior._profile_attribution(value)
        result(value["broker_result"])
        for key in (
            "submission_digest",
            "runtime_attribution_digest",
            "broker_result_digest",
        ):
            protected._pin(value[key])
        _require(
            canonical_digest(value["runtime_attribution"])
            == value["runtime_attribution_digest"]
            and canonical_digest(value["broker_result"])
            == value["broker_result_digest"],
            "PUBLIC_PROFILE_CONTENT_CHANGED",
        )
    elif name == "profiled_submission":
        submission = effective.prior._canonical_profiled_submission(value)
        effective.prior._profile_attribution(submission)
        legacy = {
            key: item
            for key, item in submission.items()
            if key != "runtime_attribution"
        }
        legacy["schema"] = "aragorn/runtime-observed-create-submission/v1"
        core._observed_submission(legacy)
        action, _, payload = core._request_effect(submission["envelope"])
        core._validate_runtime_action_request(action)
        measured_action(submission["measured_action"], action)
        _require(
            all(action[key] == plan[key] for key in effective.prior._MATCH)
            and protected._digest(payload) == plan["payload_digest"],
            "PUBLIC_SUBMISSION_ACTION_CHANGED",
        )
    else:
        raise NativeMeasurementEvidenceSnapshotError("UNKNOWN_PUBLIC_ROLE")
    return value


def snapshot_native_measurement_evidence(
    *,
    expected_container_id,
    expected_worker,
    expected_broker_process,
    expected_worker_binding_digest,
    expected_genesis_digest,
    expected_measurement_binding_raw,
    expected_measurement_binding_digest,
    expected_worker_request_digest,
    expected_action_request_digest,
    expected_source_digest,
    expected_worker_helper_digest,
):
    """One bounded observation; None driver pins preserve partial reads only."""
    report = {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "status": "REFUSED",
        "container_id": expected_container_id,
        "records": {},
        "record_digests": {},
        "broker_blobs": {},
        "broker_blob_digests": {},
        "expected_binding": None,
        "source_pins": {},
        "sources": {},
        "public_joins": None,
        "failures": [],
        "postcondition_failures": [],
        "cleanup_failures": [],
        "unclassified_reads": [],
        "limitations": list(LIMITATIONS),
        **dict.fromkeys(FALSE_FLAGS, False),
    }
    custody, held, interruption = None, {}, None

    def attempt(phase, action):
        nonlocal interruption
        try:
            return action()
        except BaseException as exc:
            report["cleanup_failures"].extend(
                getattr(exc, "_snapshot_cleanup_failures", ())
            )
            report["failures"].append(
                {"phase": phase, "reason": "FIXED_PUBLIC_READ_OR_JOIN_REFUSED"}
            )
            if not isinstance(exc, Exception) and interruption is None:
                interruption = exc
            return None

    try:
        _environment(expected_container_id)
        plan = effective.prior._binding(
            expected_measurement_binding_raw, expected_measurement_binding_digest
        )
        broker = effective.prior._process(expected_broker_process, plan["boot_id"])
        epoch = worker._exact(
            expected_worker, {"pid", "start_time_ticks", "uid", "gid"}, "caller worker"
        )
        _require(
            all(worker._uint(value, 1) for value in epoch.values())
            and epoch["pid"] != broker["pid"],
            "INVALID_EXPECTED_PROCESS_EPOCH",
        )
        for pin in (
            expected_worker_binding_digest,
            expected_genesis_digest,
            expected_source_digest,
            expected_worker_helper_digest,
        ):
            protected._pin(pin)
        for pin in (expected_worker_request_digest, expected_action_request_digest):
            if pin is not None:
                protected._pin(pin)
        _accounts(epoch, broker)
        report["expected_binding"] = _record(expected_measurement_binding_raw)
        for role, identity in (
            ("init", {"pid": 1}),
            ("worker", epoch),
            ("broker", broker),
        ):
            held[role] = protected._open_pidfd(identity)
        namespace = _guard(expected_container_id, epoch, broker, held)
        custody = _Custody(epoch, broker)
        source_pins = {
            SOURCE_PATH: expected_source_digest,
            WORKER_HELPER: expected_worker_helper_digest,
            BROKER_HELPER: plan["source_pins"][
                "runtime_broker_decision_measurement.py"
            ],
        }
        report["source_pins"] = source_pins
        for path, pin in source_pins.items():
            raw = custody.read(
                path, 0, 0, 0o444 if path == SOURCE_PATH else 0o644, 1024 * 1024
            )
            _require(protected._digest(raw) == pin, "INSTALLED_SOURCE_PIN_CHANGED")
            report["sources"][path] = {"bytes": len(raw), "digest": pin}

        def classify(name, raw):
            primary = sys.exception()
            try:
                return _classify_public(
                    name,
                    raw,
                    report,
                    plan,
                    epoch,
                    broker,
                    expected_worker_binding_digest,
                    expected_genesis_digest,
                )
            except Exception:
                report["unclassified_reads"].append(
                    {"role": name, "bytes": len(raw), "digest": protected._digest(raw)}
                )
                if primary is not None:
                    primary.add_note("PUBLIC_ROLE_CLASSIFICATION_REFUSED")
                    raise primary
                raise

        def read_named(name, path, uid, gid, limit):
            custody.hold(str(Path(path).parent))
            try:
                raw = custody.read(path, uid, gid, 0o400, limit)
            finally:
                retained = custody.partial_reads.get(path)
                if retained is not None:
                    classify(name, retained)
                    report["records"][name] = _record(retained)
                    if name in worker.STAGES:
                        report["record_digests"][name] = protected._digest(retained)
            return _parse(raw, limit)

        for stage in worker.STAGES:
            attempt(
                "WORKER_" + stage.upper(),
                lambda stage=stage: read_named(
                    stage,
                    WORKER_ROOT + "/" + stage + ".json",
                    epoch["uid"],
                    epoch["gid"],
                    worker.MAX_RECORD_BYTES,
                ),
            )
        attempt("WORKER_INVENTORY", custody.worker_inventory)
        for name, leaf in _CONTROL_NAMES.items():
            attempt(
                "BROKER_" + name.upper(),
                lambda name=name, leaf=leaf: read_named(
                    name,
                    CONTROL + "/" + leaf,
                    broker["uid"],
                    broker["gid"],
                    4096 if name == "completion" else _LIMIT,
                ),
            )

        def read_blob(name, pin):
            protected._pin(pin)
            _require(
                name not in report["broker_blob_digests"]
                and len(report["broker_blob_digests"]) < 5,
                "PUBLIC_BLOB_INVENTORY_EXCEEDED",
            )
            hex_pin = pin.removeprefix("sha256:")
            parent = EVIDENCE + "/blobs/sha256/" + hex_pin[:2]
            custody.hold(parent)
            path = parent + "/" + hex_pin[2:]
            try:
                raw = custody.read(path, broker["uid"], broker["gid"], 0o444, _LIMIT)
            finally:
                retained = custody.partial_reads.get(path)
                if retained is not None and protected._digest(retained) == pin:
                    classify(name, retained)
                    report["broker_blobs"][pin] = _record(retained)
                    report["broker_blob_digests"][name] = pin
            _require(protected._digest(raw) == pin, "PUBLIC_BLOB_DIGEST_CHANGED")
            return _parse(raw)

        def read_evidence():
            completion = _exact(
                _parse(_raw(report["records"]["completion"]), 4096),
                {"schema", "pending_digest", "evidence_digest"},
            )
            _require(
                completion["schema"]
                == "aragorn/runtime-broker-decision-measurement-complete/v2",
                "EFFECTIVE_COMPLETION_V2_REQUIRED",
            )
            protected._pin(completion["pending_digest"])
            return _evidence(read_blob("evidence", completion["evidence_digest"]))

        evidence = attempt("BROKER_EVIDENCE", read_evidence)
        if evidence is not None:
            for name, field in _BROKER_FIELDS.items():
                attempt(
                    "BROKER_" + name.upper(),
                    lambda name=name, field=field: read_blob(name, evidence[field]),
                )
            attempt(
                "BROKER_PROFILED_SUBMISSION",
                lambda: read_blob(
                    "profiled_submission", evidence["pending"]["submission_digest"]
                ),
            )
        if not report["failures"]:
            report["public_joins"] = attempt(
                "PUBLIC_JOINS",
                lambda: _public_joins(
                    report,
                    plan,
                    epoch,
                    broker,
                    expected_worker_binding_digest,
                    expected_genesis_digest,
                    expected_worker_request_digest,
                    expected_action_request_digest,
                    namespace,
                ),
            )
        final_namespace = attempt(
            "PROCESS_FINAL", lambda: _guard(expected_container_id, epoch, broker, held)
        )
        _require(final_namespace == namespace, "WORKER_TIME_NAMESPACE_CHANGED")
    except BaseException as exc:
        report["cleanup_failures"].extend(
            getattr(exc, "_snapshot_cleanup_failures", ())
        )
        report["failures"].append(
            {"phase": "SNAPSHOT_GUARD", "reason": "FIXED_PUBLIC_SNAPSHOT_REFUSED"}
        )
        if not isinstance(exc, Exception) and interruption is None:
            interruption = exc
    finally:
        if custody is not None:
            for operation, failures, label in (
                (
                    custody.final_readbacks,
                    report["postcondition_failures"],
                    "PUBLIC_FINAL_READBACKS_REFUSED",
                ),
                (custody.close, report["cleanup_failures"], "PUBLIC_CLOSE_REFUSED"),
            ):
                try:
                    caught = operation(failures)
                    if interruption is None:
                        interruption = caught
                except BaseException as exc:
                    failures.append(label)
                    if not isinstance(exc, Exception) and interruption is None:
                        interruption = exc
        for fd in reversed(list(held.values())):
            try:
                os.close(fd)
            except BaseException as exc:
                report["cleanup_failures"].append("PIDFD_CLOSE_REFUSED")
                if not isinstance(exc, Exception) and interruption is None:
                    interruption = exc
    if not (
        report["failures"]
        or report["postcondition_failures"]
        or report["cleanup_failures"]
    ):
        report["status"] = "SNAPSHOTTED"
    _require(len(canonical_json(report)) <= MAX_RESULT, "PUBLIC_REPORT_BOUND_EXCEEDED")
    if interruption is not None:
        interruption._native_measurement_evidence_snapshot = report
        raise interruption
    return report
