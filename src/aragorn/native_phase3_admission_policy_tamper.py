"""Finite callback-only policy tamper recorder; performs no native operations."""
from __future__ import annotations

from .oci_worker_protocol import canonical_json
from .native_phase3_admission_policy_tamper_verify import (
    ACTION_LIMIT, EvidenceChecks, FLAGS, OPERATIONS, PATHS, PREFIX, RECORD_LIMIT,
    SNAPSHOT_LIMIT, digest, encode, require,
)


class PolicyTamperRecordingError(ValueError):
    """Bounded retained partial bytes, including the callback that failed validation."""

    def __init__(self, partial: bytes):
        super().__init__("POLICY_TAMPER_RECORDING_REFUSED")
        self.partial = partial


def record_policy_tamper(*, context_raw: bytes, bindings: dict,
                         read_snapshot, attempt_mutation, invoke_policy) -> bytes:
    events = []
    # Reserve envelope overhead; partial payloads share a finite raw-byte budget.
    remaining = 2 * 1024 * 1024
    phase = "PRECONDITIONS"

    def retain(label, raw, limit):
        nonlocal remaining
        event = {"phase": label, "returned_bytes": type(raw) is bytes}
        if type(raw) is bytes:
            kept = raw[:min(limit, remaining)]
            remaining -= len(kept)
            event.update(raw_base64=encode(kept), bytes=len(raw), digest=digest(raw),
                         truncated=len(kept) != len(raw))
        events.append(event)

    def obtain(label, callback, limit, *args):
        nonlocal phase
        phase = label
        try:
            raw = callback(*args)
        except BaseException as error:
            partial = vars(error).get("partial_bytes")
            if type(partial) is bytes:
                retain(label + ":CALLBACK_PARTIAL", partial, limit)
            raise
        retain(label, raw, limit)
        return raw

    try:
        require(all(callable(cb) for cb in (read_snapshot, attempt_mutation, invoke_policy)),
                "MISSING_PROVIDER")
        retain("CONTEXT", context_raw, SNAPSHOT_LIMIT)
        checks = EvidenceChecks(context_raw, bindings)
        before = obtain("BEFORE", read_snapshot, SNAPSHOT_LIMIT)
        snapshot = checks.snapshot(before)
        catalog = snapshot["catalog_digest"]
        attempts = []
        for resource in PATHS:
            for operation in OPERATIONS:
                raw_action = obtain(resource + ":" + operation, attempt_mutation,
                                    ACTION_LIMIT, resource, operation)
                action = checks.mutation(raw_action, resource, operation, snapshot["observed_ns"])
                raw_snapshot = obtain(resource + ":" + operation + ":AFTER",
                                      read_snapshot, SNAPSHOT_LIMIT)
                snapshot = checks.snapshot(raw_snapshot, action["finished_ns"], catalog)
                attempts.append({"operation_base64": encode(raw_action),
                                 "snapshot_base64": encode(raw_snapshot)})
                # Refuse an unrepresentable record before any subsequent callback.
                require(len(canonical_json(attempts)) + len(encode(before))
                        < RECORD_LIMIT - 2 * SNAPSHOT_LIMIT, "RECORD_BOUND")
        raw_invocation = obtain("INVOCATION", invoke_policy, ACTION_LIMIT)
        invocation = checks.invocation(raw_invocation, snapshot["observed_ns"])
        after = obtain("AFTER", read_snapshot, SNAPSHOT_LIMIT)
        checks.snapshot(after, invocation["finished_ns"], catalog)
        record = canonical_json({
            "schema": PREFIX + "record/v1", "context_digest": checks.bindings["context"],
            "before": encode(before), "attempts": attempts,
            "invocation": encode(raw_invocation), "after": encode(after),
            **{key: False for key in FLAGS},
        })
        require(len(record) <= RECORD_LIMIT, "RECORD_BOUND")
        return record
    except BaseException as error:
        # Callback diagnostics can contain secrets; retain type and phase, never its message.
        partial = canonical_json({"schema": PREFIX + "partial/v1", "phase": phase,
                                  "failure_type": type(error).__name__[:128], "events": events,
                                  **{key: False for key in FLAGS}})
        raise PolicyTamperRecordingError(partial) from None
