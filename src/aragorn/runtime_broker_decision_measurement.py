"""One opt-in validated grant-redemption measurement; never Phase 3 qualification.

Only the successor service configures this module, from a systemd credential.
The final-decision hook performs no filesystem operations. A durable pending
latch precedes grant claiming; failures never clear it or authorize a retry.
Completed evidence is retained only after the original grant is CONSUMED.
"""

from __future__ import annotations

import contextvars
import hashlib
import os
import re
import stat
import sys
import time
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

from . import runtime_action_broker as broker
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path("/var/lib/aragorn-runtime-action/control")
_INPUT = _ROOT / "decision-measurement-inputs"
_OUTPUT = _ROOT / "decision-measurement-evidence"
_BOOT = Path("/run/aragorn-broker-boot-id")
_PENDING = "decision-measurement-pending.json"
_COMPLETE = "decision-measurement-complete.json"
_LIMIT = 128 * 1024
_MATCH = {
    "runtime_digest",
    "policy_digest",
    "active_skill_digest",
    "operation_digest",
    "path_digest",
    "payload_digest",
}
_SOURCES = {
    "runtime_action_broker.py",
    "runtime_action_broker_v4.py",
    "runtime_action_broker_v5.py",
    "runtime_action_service_v5.py",
    "runtime_broker_decision_measurement.py",
    "phase3_deployment.py",
    "phase3_quantitative_metrics.py",
}
_BINDING_KEYS = {
    "schema",
    "boot_id",
    "attempt_id",
    "deployment_identity_digest",
    "measurement_schedule_digest",
    "collection_commitment_digest",
    "scheduled_measurement_request_digest",
    "grant_digest",
    "runtime_profile_digest",
    "sensor_digest",
    "source_pins",
    *_MATCH,
}
_PLAN: dict | None = None
_PROCESS: dict | None = None
_CURRENT: contextvars.ContextVar[Trace | None] = contextvars.ContextVar(
    "broker_decision_measurement", default=None
)


def _require(condition: bool) -> None:
    if not condition:
        # Attribute lookup is deliberately late: the rendered core imports us.
        raise broker.RuntimeActionBrokerError("broker decision measurement refused")


def _digest(value: object) -> None:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )


def _stamp() -> int:
    _require(sys.platform == "linux" and hasattr(time, "CLOCK_BOOTTIME"))
    try:
        value = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    except Exception as exc:
        raise broker.RuntimeActionBrokerError(
            "broker measurement clock unavailable"
        ) from exc
    _require(type(value) is int and 0 <= value < 2**63)
    return value


def _small(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode))
        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)
        _require(
            len(raw) <= limit
            and broker._file_identity(before)
            == broker._file_identity(after)
            == broker._file_identity(path.lstat())
        )
        return raw
    finally:
        os.close(fd)


def _identity() -> dict:
    _require(sys.platform == "linux" and os.geteuid() > 0)
    boot = _small(_BOOT, 64).decode("ascii").strip()
    _require(
        re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot) is not None
    )
    pid = os.getpid()
    raw = _small(Path(f"/proc/{pid}/stat"), 4096)
    tail = raw[raw.rfind(b") ") + 2 :].split()
    _require(
        raw.startswith(str(pid).encode() + b" (")
        and len(tail) >= 20
        and tail[19].isdigit()
    )
    namespace = os.readlink(f"/proc/{pid}/ns/mnt")
    _require(re.fullmatch(r"mnt:\[[0-9]+\]", namespace) is not None)
    return {
        "boot_id": boot,
        "pid": pid,
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "start_time_ticks": int(tail[19]),
        "mount_namespace": namespace,
    }


def _sources(plan: dict) -> None:
    _require(type(plan["source_pins"]) is dict and set(plan["source_pins"]) == _SOURCES)
    for name, digest in plan["source_pins"].items():
        _digest(digest)
        path = Path(__file__).parent / name
        metadata = path.lstat()
        _require(metadata.st_uid == 0 and not stat.S_IMODE(metadata.st_mode) & 0o022)
        _require(
            "sha256:" + hashlib.sha256(_small(path, 1024 * 1024)).hexdigest() == digest
        )


def _inputs(plan: dict) -> None:
    """Resolve the frozen plan, without interpreting identity artifacts as attestation."""
    from .phase3_deployment import resolve_phase3_deployment_identity
    from .phase3_quantitative_metrics import build_phase3_measurement_schedule

    store = CAS(_INPUT, read_only=True)
    commitment = broker._parse_canonical_document(
        store.read(plan["collection_commitment_digest"], max_bytes=1024 * 1024),
        "measurement commitment",
    )
    _require(
        commitment["schema"] == "aragorn/phase3-measurement-collection-commitment/v1"
        and commitment["schedule_digest"] == plan["measurement_schedule_digest"]
        and commitment["clock_id"] == "CLOCK_BOOTTIME"
    )
    resolve_phase3_deployment_identity(
        canonical_json(commitment["deployment"]),
        expected_digest=plan["deployment_identity_digest"],
        evidence_cas=store,
    )
    raw = store.read(plan["measurement_schedule_digest"], max_bytes=1024 * 1024)
    schedule = broker._parse_canonical_document(raw, "measurement schedule")
    attempt, overhead = schedule["attempt_schedule"], schedule["overhead_schedule"]
    rebuilt = build_phase3_measurement_schedule(
        expected_attempt_ids=attempt["attempt_ids"],
        expected_attempt_families=attempt["attempt_families"],
        expected_unattributed_attempt_id=attempt[
            "unattributed_negative_control_attempt_id"
        ],
        expected_overhead_pair_bindings=overhead["pair_bindings"],
        **{"expected_" + key: value for key, value in schedule["bindings"].items()},
    )
    _require(
        canonical_json(rebuilt) == raw
        and schedule["bindings"]["runtime_identity_digest"]
        == plan["deployment_identity_digest"]
        and plan["attempt_id"] in attempt["attempt_ids"]
    )
    request = {
        "kind": "attempt",
        "attempt_id": plan["attempt_id"],
        "family": attempt["attempt_families"][plan["attempt_id"]],
        "negative_control": plan["attempt_id"]
        == attempt["unattributed_negative_control_attempt_id"],
        "collection_digest": plan["collection_commitment_digest"],
        "deployment_digest": plan["deployment_identity_digest"],
    }
    _require(canonical_digest(request) == plan["scheduled_measurement_request_digest"])


def configure(raw: bytes, expected_uid: int) -> None:
    """Called once by the successor service after strict credential custody reads."""
    global _PLAN, _PROCESS
    try:
        _require(_PLAN is None and type(raw) is bytes and 0 < len(raw) <= 4096)
        plan = broker._parse_canonical_document(raw, "broker measurement binding")
        _require(
            set(plan) == _BINDING_KEYS
            and plan["schema"]
            == "aragorn/runtime-broker-decision-measurement-binding/v1"
        )
        for key in _BINDING_KEYS - {"schema", "boot_id", "attempt_id", "source_pins"}:
            _digest(plan[key])
        _require(
            type(plan["attempt_id"]) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", plan["attempt_id"])
            is not None
        )
        process = _identity()
        _require(
            process["uid"] == expected_uid and process["boot_id"] == plan["boot_id"]
        )
        _sources(plan)
        _inputs(plan)
        _require(
            not os.path.lexists(_ROOT / _PENDING)
            and not os.path.lexists(_ROOT / _COMPLETE)
            and not os.path.lexists(_OUTPUT)
        )
        _PLAN, _PROCESS = plan, process
    except Exception as exc:
        raise broker.RuntimeActionBrokerError(
            "broker measurement configuration refused"
        ) from exc


@dataclass
class Trace:
    pending: dict
    token: Any = None
    final: dict | None = None


def begin(
    config: Any,
    grant: dict,
    legacy: dict,
    attribution: dict,
    submission_digest: str,
    lease: dict,
    deadline: float | None,
) -> Trace:
    """One validated V4 redemption; durably mark it pending before grant claiming."""
    from . import runtime_action_broker_v4 as v4

    try:
        _require(
            _PLAN is not None
            and _CURRENT.get() is None
            and config.broker.broker.control_root == _ROOT
        )
        accepted = _stamp()
        plan = _PLAN
        _require(_identity() == _PROCESS and _PROCESS["boot_id"] == plan["boot_id"])
        _sources(plan)
        _inputs(plan)
        request = legacy["envelope"]["request"]
        _require(
            all(request[key] == plan[key] for key in _MATCH)
            and canonical_digest(grant) == plan["grant_digest"]
            and config.broker.broker.expected_runtime_digest == plan["runtime_digest"]
            and config.broker.expected_runtime_profile_digest
            == attribution["profile_digest"]
            == plan["runtime_profile_digest"]
            and legacy["sensor_digest"] == plan["sensor_digest"]
            and all(
                grant[key] == plan[key]
                for key in (_MATCH - {"path_digest", "payload_digest"})
                | {"runtime_profile_digest", "sensor_digest"}
            )
            and legacy["request_digest"] == canonical_digest(request)
        )
        trace = Trace(
            {
                "schema": "aragorn/runtime-broker-decision-measurement-pending/v1",
                "binding": plan,
                "process": _PROCESS,
                "clock_id": "CLOCK_BOOTTIME",
                "acceptance_boundary": "V4_ISSUED_SUBMISSION_VALIDATED_BEFORE_GRANT_CLAIM",
                "accepted_boottime_ns": accepted,
                "action_request_digest": legacy["request_digest"],
                "submission_digest": submission_digest,
                "lease_digest": canonical_digest(lease),
                "runtime_attribution_digest": canonical_digest(attribution),
            }
        )

        def retain_pending(fd: int) -> None:
            state = v4._load_state(fd, config, plan["grant_digest"])
            _require(state["status"] == "AVAILABLE")
            for name in (_PENDING, _COMPLETE):
                try:
                    os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                _require(False)
            _require(not os.path.lexists(_OUTPUT))
            v4._publish_immutable_at(
                fd,
                _PENDING,
                canonical_json(trace.pending),
                config,
                "measurement pending",
            )

        v4._with_profile_lock(config.broker, deadline, retain_pending)
        trace.token = _CURRENT.set(trace)
        return trace
    except Exception as exc:
        raise broker.RuntimeActionBrokerError(
            "broker measurement acceptance refused"
        ) from exc


def final_decision(
    request_digest: str,
    observation_digest: str,
    decision: dict | None,
    allowed: bool,
    reasons: list[str],
) -> None:
    """Pure memory/clock hook; no proc reads, source reads, locks, or file writes."""
    trace = _CURRENT.get()
    if trace is None:
        return  # The same rendered shared core still supports unmeasured legacy callers.
    _require(
        trace.final is None
        and type(allowed) is bool
        and request_digest == trace.pending["action_request_digest"]
    )
    _require(
        type(reasons) is list
        and all(
            type(code) is str
            and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", code) is not None
            for code in reasons
        )
        and (allowed == (reasons == []))
    )
    _digest(observation_digest)
    stamp = _stamp()
    _require(stamp > trace.pending["accepted_boottime_ns"])
    trace.final = {
        "finalized_boottime_ns": stamp,
        "verdict": "ALLOW" if allowed else "BLOCK",
        "reason_codes": list(reasons),
        "observation_digest": observation_digest,
        "policy_decision_digest": canonical_digest(decision)
        if decision is not None
        else None,
    }


def _sync_store(parent: int) -> None:
    """Persist fresh CAS ancestry, not just blobs/prefixes, before COMPLETE."""
    held = []
    try:
        for name in (_OUTPUT.name, "blobs", "sha256"):
            fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=parent,
            )
            identity = broker._directory_identity(os.fstat(fd))
            held.append((fd, parent, name, identity))
            metadata = os.fstat(fd)
            _require(
                metadata.st_uid == os.geteuid()
                and stat.S_IMODE(metadata.st_mode) == 0o700
            )
            parent = fd
        for fd, parent, name, identity in reversed(held):
            os.fsync(fd)
            _require(
                identity
                == broker._directory_identity(os.fstat(fd))
                == broker._directory_identity(
                    os.stat(name, dir_fd=parent, follow_symlinks=False)
                )
            )
    finally:
        for fd, _, _, _ in reversed(held):
            os.close(fd)


def retain(
    trace: Trace, config: Any, claim: dict, result: dict, deadline: float | None
) -> None:
    """Join original durable consumption under its lock, then publish one sample."""
    from . import runtime_action_broker_v4 as v4

    try:
        _require(
            _CURRENT.get() is trace
            and trace.final is not None
            and _identity() == _PROCESS
        )
        _sources(_PLAN)
        _inputs(_PLAN)
        final = trace.final
        _require(
            result["request_digest"] == trace.pending["action_request_digest"]
            and result["verdict"] == final["verdict"]
            and result["reason_codes"] == final["reason_codes"]
            and result["observation_digest"] == final["observation_digest"]
            and (
                canonical_digest(result["decision"])
                if result["decision"] is not None
                else None
            )
            == final["policy_decision_digest"]
        )

        def publish(fd: int) -> None:
            state = v4._load_state(fd, config, claim["grant_digest"])
            receipt = v4._load_profile_receipt(fd, config)
            record = v4._result_record(claim, receipt)
            _require(
                state["status"] == "CONSUMED"
                and state["claim"] == claim
                and state["result"] == record
                and record["profile_result"]["broker_result_digest"]
                == canonical_digest(result)
                and receipt["broker_result"] == result
                and receipt["runtime_attribution_digest"]
                == trace.pending["runtime_attribution_digest"]
                and receipt["submission_digest"] == trace.pending["submission_digest"]
                and claim["lease_digest"] == trace.pending["lease_digest"]
                and claim["grant_digest"] == _PLAN["grant_digest"]
            )
            pending = broker._read_owned_bytes_at(
                fd,
                _PENDING,
                max_bytes=_LIMIT,
                expected_uid=config.broker.broker.expected_broker_uid,
                exact_mode=0o400,
                label="measurement pending",
            )
            _require(
                pending == canonical_json(trace.pending)
                and not os.path.lexists(_ROOT / _COMPLETE)
                and not os.path.lexists(_OUTPUT)
            )
            store = CAS(_OUTPUT)

            def put(value: dict) -> str:
                raw = canonical_json(value)
                digest = canonical_digest(value)
                _require(
                    0 < len(raw) <= _LIMIT
                    and store.put_expected(
                        BytesIO(raw), expected_digest=digest, max_bytes=_LIMIT
                    )
                    == digest
                    and store.read(digest, max_bytes=_LIMIT) == raw
                )
                return digest

            evidence = {
                "schema": "aragorn/runtime-broker-decision-measurement/v1",
                "authority": "VALIDATED_GRANT_REDEMPTION_TIMING_ONLY_NOT_FULL_REQUEST_LATENCY_OR_PHASE3",
                "pending": trace.pending,
                "effective_final_decision": final,
                "consumed_grant_state_digest": put(state),
                "profile_receipt_digest": put(receipt),
                "broker_result_digest": put(result),
                "decision": {
                    "phase3_exit_eligible": False,
                    "run_eligible": False,
                    "quantitative_metrics_eligible": False,
                },
                "limitations": [
                    "EXCLUDES_V5_LINEAGE_TRANSPORT_AND_ISSUANCE_VALIDATION",
                    "NOT_SINK_RESIDUE_OR_INDEPENDENT_CAUSAL_ATTRIBUTION_PROOF",
                    "NOT_TASK_BASELINE_OR_OVERHEAD_MEASUREMENT",
                    "EXISTING_CONSUMPTION_CHECKS_CAN_REFUSE_REPLAY_OR_MIXED_VERDICT_BLOCKS",
                    "ROOT_OPERATOR_AND_BROKER_CUSTODY_NOT_EXTERNAL_ATTESTATION",
                ],
            }
            digest = put(evidence)
            _require(_identity() == _PROCESS)
            _sources(_PLAN)
            _inputs(_PLAN)
            for pin in (
                evidence["consumed_grant_state_digest"],
                evidence["profile_receipt_digest"],
                evidence["broker_result_digest"],
                digest,
            ):
                store.verify(pin, max_bytes=_LIMIT)
            _sync_store(fd)
            index = {
                "schema": "aragorn/runtime-broker-decision-measurement-complete/v1",
                "pending_digest": canonical_digest(trace.pending),
                "evidence_digest": digest,
            }
            v4._publish_immutable_at(
                fd, _COMPLETE, canonical_json(index), config, "measurement completion"
            )
            # Keep PENDING permanently: neither success nor failure permits reuse.

        v4._with_profile_lock(config.broker, deadline, publish)
    except Exception as exc:
        if result.get("effect_status") == "CREATED":
            raise broker.RuntimeActionEffectIndeterminate(
                "runtime create committed but decision measurement retention failed"
            ) from exc
        raise broker.RuntimeActionBrokerError(
            "blocked decision measurement retention failed"
        ) from exc


def close(trace: Trace) -> None:
    _CURRENT.reset(trace.token)
