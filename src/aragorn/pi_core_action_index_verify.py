"""Read the B31 private action journal for offline replay; a prefix is not a terminal seal."""
from hashlib import sha256

from .cas import CAS
from .oci_worker_protocol import canonical_digest
from .pi_core_action_boundary_verify import _current
from .pi_core_action_terminal_verify import _verify_action_terminal
from .pi_core_provider_evidence import ACTION_SCHEMA, AUTHORITY, _MAX_INDEX, _MAX_RECORD, _MAX_RECORDS
from .pi_core_service_configuration import validate_service_configurations
from .pi_core_source_observation_verify import _document, _fields, _pin, _require, _same, _uint
from .pi_core_worker_identity import validate_activation


_READBACK = (["ROOT", "LOCK_IDENTITY"] + ["FILE_IDENTITY", "FILE_BYTES"] * 3
             + ["ABSENCE"] * 3 + ["JOINED"])


def read_action_index(*, evidence_cas, expected_index_digest, expected_activation, storage):
    """Return ordered references and verified original records, never an effect or cleanup verdict."""
    _require(type(evidence_cas) is CAS and evidence_cas.read_only is True, "ACTION_INDEX_READ_ONLY_CAS")
    activation = validate_activation(expected_activation)
    activation_digest = canonical_digest(activation)
    _fields(storage, {"schema", "authority", "status", "activation_digest", "references", "pending_reference",
                      "index_digest", "index_bytes", "index_status", "owned_handles_closed", "uncertainty",
                      "phase3_eligible"})
    _require(storage["schema"] == ACTION_SCHEMA and storage["authority"] == AUTHORITY
             and storage["activation_digest"] == activation_digest and storage["status"] == "CLOSED"
             and storage["index_status"] == "DURABLE_PREFIX" and storage["index_digest"] == _pin(expected_index_digest)
             and storage["pending_reference"] is None and storage["owned_handles_closed"] is True
             and storage["phase3_eligible"] is False and storage["uncertainty"] == []
             and type(storage["references"]) is list and 0 < len(storage["references"]) <= _MAX_RECORDS,
             "ACTION_INDEX_OWNER_DISAGREES")
    raw = evidence_cas.read(expected_index_digest, max_bytes=_uint(storage["index_bytes"], 1, _MAX_INDEX))
    _require(len(raw) == storage["index_bytes"] and raw.endswith(b"\n"), "ACTION_INDEX_TRUNCATED")
    lines = raw[:-1].split(b"\n")
    _require(len(lines) == 1 + len(storage["references"]), "ACTION_INDEX_REFERENCE_COUNT")
    _same(_document(lines[0]), {"schema": "aragorn/pi-core-action-evidence-index/v1",
          "authority": "DURABLE_REFERENCE_PREFIX_ONLY_NOT_COMPLETED_CAPTURE", "sequence": 0,
          "kind": "HEADER", "activation_id": activation["activation_id"], "activation_digest": activation_digest},
          "ACTION_INDEX_HEADER")

    prefix = sha256(lines[0] + b"\n")
    refs = []
    for sequence, line in enumerate(lines[1:], 1):
        row = _fields(_document(line), {"schema", "sequence", "previous_prefix_digest", "kind", "digest", "bytes"})
        _require(row["schema"] == "aragorn/pi-core-action-evidence-reference/v1"
                 and _uint(row["sequence"], 1, _MAX_RECORDS) == sequence
                 and row["previous_prefix_digest"] == "sha256:" + prefix.hexdigest()
                 and type(row["kind"]) is str, "ACTION_INDEX_REFERENCE_CHAIN")
        ref = {"kind": row["kind"], "digest": _pin(row["digest"]), "bytes": _uint(row["bytes"], 1, _MAX_RECORD)}
        _same(ref, storage["references"][sequence - 1], "ACTION_INDEX_REFERENCE_DIFFERS")
        refs.append(ref)
        prefix.update(line + b"\n")

    kinds = [r["kind"] for r in refs]
    count = kinds.count("CHECK")
    _require(1 <= count <= 16 and kinds == ["REQUEST_FRAME", "REQUEST_FRAME", "REQUEST_CONTEXT"]
             + ["CHECK", "CURRENT_ATTEMPT"] * count + ["ACTION_DONE", "SENSOR_DONE", "ACTION_RESULT",
             "CURRENT_SEND_SUMMARY"] + ["CONTROL_READBACK"] * len(_READBACK), "ACTION_INDEX_INCOMPLETE_OR_OUT_OF_ORDER")
    values = []
    for ref in refs:
        original = evidence_cas.read(ref["digest"], max_bytes=ref["bytes"])
        _require(len(original) == ref["bytes"], "ACTION_INDEX_BLOB_SIZE")
        values.append(_document(original))
    _require([doc.get("phase") for doc in values[-len(_READBACK):]] == _READBACK, "ACTION_INDEX_READBACK_INCOMPLETE")
    return refs, values


def verify_retained_action(*, evidence_cas, expected_owner_digest, expected_index_digest,
                           expected_grant_digest, expected_configuration_digest, expected_activation,
                           expected_request, expected_broker_nonce, expected_deadline_ns,
                           expected_summary_digest, selections, source_expectations):
    """Check a nominated B31 closed owner and its original B77 sends; never open a live control or target."""
    _require(type(evidence_cas) is CAS and evidence_cas.read_only is True, "ACTION_REPLAY_READ_ONLY_CAS")
    activation = validate_activation(expected_activation)
    owner = _document(evidence_cas.read(_pin(expected_owner_digest), max_bytes=_MAX_RECORD))
    fixed = dict(schema="aragorn/pi-core-native-action-evidence/v1",
                 authority="RETAINED_ACTION_RECORDS_ONLY_NOT_EFFECT_TIMING_HEALTH_OR_PHASE3", status="CLOSED",
                 activation_digest=canonical_digest(activation), grant_digest=_pin(expected_grant_digest),
                 configuration_digest=_pin(expected_configuration_digest), receipt_join_verified=True,
                 owned_handles_closed=True, cleanup_uncertainty=[], capture_complete=False, effect_verified=False,
                 timing_verified=False, health_verified=False, phase3_exit_eligible=False)
    _fields(owner, {*fixed, "retained_evidence", "readback"})
    _same({k: owner[k] for k in fixed}, fixed, "ACTION_REPLAY_CLOSED_OWNER")
    configs = _document(evidence_cas.read(expected_configuration_digest, max_bytes=1 << 20))
    action = validate_service_configurations(configs)["action"]
    _require(canonical_digest(action["capability_grant"]) == expected_grant_digest,
             "ACTION_REPLAY_CONFIGURED_GRANT")
    _same(action["identities"]["worker"], {k: activation[k] for k in ("uid", "gid")}, "ACTION_REPLAY_WORKER")
    references, values = read_action_index(evidence_cas=evidence_cas, expected_index_digest=expected_index_digest,
                                           expected_activation=activation, storage=owner["retained_evidence"])
    _require(type(selections) in (tuple, list) and 1 <= len(selections) <= 16, "ACTION_REPLAY_SEQUENCE_COUNT")
    for selection in selections:
        _fields(selection, {"check_digest", "attempt_digest", "observation_digest", "challenge"})
    selected = [(kind, pin) for sel in selections for kind, pin in
                (("CHECK", _pin(sel["check_digest"])), ("CURRENT_ATTEMPT", _pin(sel["attempt_digest"])))]
    selected.append(("CURRENT_SEND_SUMMARY", _pin(expected_summary_digest)))
    _require([(r["kind"], r["digest"]) for r in references
              if r["kind"] in {"CHECK", "CURRENT_ATTEMPT", "CURRENT_SEND_SUMMARY"}] == selected,
             "ACTION_REPLAY_INDEX_SELECTION")
    originals = {r["digest"]: (r["bytes"], v) for r, v in zip(references, values, strict=True)}

    def indexed(pin, maximum):
        size, value = originals[_pin(pin)]
        _require(size <= maximum, "ACTION_REPLAY_RECORD_BOUND")
        return value

    terminal = _verify_action_terminal(values=values, expected_activation=activation,
        expected_request=expected_request, expected_broker_nonce=expected_broker_nonce,
        expected_deadline_ns=expected_deadline_ns, owner=owner, expected_action_principal=action["identities"]["action"])
    _require(terminal["grant_digest"] == expected_grant_digest, "ACTION_REPLAY_TERMINAL_GRANT")
    current = _current(evidence_cas, activation, expected_request, expected_broker_nonce,
                       expected_deadline_ns, expected_summary_digest, selections, source_expectations, indexed)
    return dict(schema="aragorn/pi-core-retained-action-replay/v1", status="CONSISTENT_RECORDED_ACTION",
                owner_digest=expected_owner_digest, index_digest=expected_index_digest, **terminal,
                completed_sequences=current["completed_sequences"], terminal_records_matched=True,
                acquisition_authenticity_verified=False, effect_verified=False, timing_verified=False,
                recovery_executed=False, sensor_health_verified=False, phase3_qualified=False)
