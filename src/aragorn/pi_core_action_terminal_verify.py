"""Replay the original native action wire and read-only control receipts; do not execute recovery."""
import base64
import stat

from . import pi_core_request_handoff as handoff
from . import pi_core_request_recovery as recovery
from . import pi_core_sensor_channel as sensor
from . import pi_core_worker_identity as identity
from . import runtime_action_broker as broker
from . import runtime_action_broker_v4 as grants
from . import runtime_action_worker as worker
from .oci_worker_protocol import canonical_digest, canonical_json
from .pi_core_source_observation_verify import _fields, _require, _same, _uint
from .runtime_active_skill_lineage import VERIFIED_LINEAGE_AUTHORITY, VERIFIED_LINEAGE_SCHEMA
from .runtime_capability_grant import parse_runtime_capability_grant


def _verify_action_terminal(*, values, expected_activation, expected_request, expected_broker_nonce,
                           expected_deadline_ns, owner, expected_action_principal):
    """Consume the complete, ordered values returned by read_action_index."""
    activation = identity.validate_activation(expected_activation)
    request, _ = worker._worker_request(expected_request)
    raw = canonical_json(request)
    _require(0 < len(raw) <= broker._MAX_FRAME_BYTES, "ACTION_TERMINAL_FRAME_SIZE")
    frame = dict(schema="aragorn/pi-core-action-frame/v1",
                 header_base64=base64.b64encode(broker._FRAME_HEADER.pack(len(raw))).decode("ascii"),
                 body_base64=None, body_complete=False, eof_verified=False, parsed=False)
    _same(values[0], frame, "ACTION_TERMINAL_HEADER")
    _same(values[1], {**frame, "body_base64": base64.b64encode(raw).decode("ascii"), "body_complete": True},
          "ACTION_TERMINAL_BODY")
    context = _fields(values[2], {"schema","request","activation","grant","measurement","lineage","challenge","offer_intent"})
    fields = dict(nonce=expected_broker_nonce, deadline_ns=expected_deadline_ns,
                  activation_digest=canonical_digest(activation), request_digest=canonical_digest(request))
    _require(context["schema"] == "aragorn/pi-core-action-context/v1", "ACTION_TERMINAL_CONTEXT_SCHEMA")
    _same(context["request"], request, "ACTION_TERMINAL_REQUEST")
    _same(context["activation"], activation, "ACTION_TERMINAL_ACTIVATION")
    _same(handoff._validate_packet(context["challenge"], terminal_ack=True),
          handoff._packet("CHALLENGE", terminal_ack=True, nonce=expected_broker_nonce), "ACTION_TERMINAL_CHALLENGE")
    _same(handoff._validate_packet(context["offer_intent"], terminal_ack=True),
          handoff._packet("OFFER", terminal_ack=True, **fields, activation=activation, worker_request=request), "ACTION_TERMINAL_OFFER")
    grant = parse_runtime_capability_grant(canonical_json(context["grant"]))
    pin = canonical_digest(grant)
    _require(pin == owner["grant_digest"] and grant["runtime_profile_digest"] == activation["profile_digest"] and
             all(grant[k] == activation[k] for k in ("install_context_digest", "source_manifest_digest")),
             "ACTION_TERMINAL_GRANT")
    done, sensor_done, result, _summary = values[-16:-12]
    handoff._validate_packet(done, terminal_ack=True)
    sensor._validate_packet(sensor_done, terminal_ack=True)
    _require(done["kind"] == sensor_done["kind"] == "DONE" and result.get("status") == "COMPLETED",
             "ACTION_TERMINAL_NOT_COMPLETED")
    _same({k:done[k] for k in fields}, fields, "ACTION_TERMINAL_DONE_BINDING")
    _same(done["result"], result, "ACTION_TERMINAL_DONE_RESULT")
    binding = worker.RuntimeActionWorkerBinding(grant["runtime_digest"], grant["active_skill_digest"],
                                                grant["policy_digest"], grant["policy_version"])
    _same(handoff._result(done["envelope"], result, request, activation, binding), result, "ACTION_TERMINAL_PROJECTION")
    _require(grant["operation_digest"] == done["envelope"]["request"]["operation_digest"], "ACTION_TERMINAL_OPERATION")
    _require(sensor_done["request_digest"] == fields["request_digest"] and
             sensor_done["deadline_ns"] == fields["deadline_ns"] and
             sensor_done["broker_result_digest"] == canonical_digest(result["broker_result"]), "ACTION_TERMINAL_SENSOR")
    # The sensor owns a separate nonce; this action index contains no sensor challenge or ACK.
    measured, lineage = context["measurement"], context["lineage"]
    _require(lineage["schema"] == VERIFIED_LINEAGE_SCHEMA and lineage["authority"] == VERIFIED_LINEAGE_AUTHORITY,
             "ACTION_TERMINAL_LINEAGE_FORMAT")
    _same({k:measured[k] for k in identity._ATTRIBUTION_FIELDS},
          {k:activation[k] for k in identity._ATTRIBUTION_FIELDS}, "ACTION_TERMINAL_WORKER")
    for k, target in (("active_skill_digest","active_skill_digest"), ("context_digest","install_context_digest"),
                      ("manifest_digest","source_manifest_digest"), ("tree_digest","tree_digest"),
                      ("active_record_digest","active_record_digest")):
        _same(lineage[k], activation[target], "ACTION_TERMINAL_LINEAGE")
    _same(lineage["runtime_skill_path"], measured["skill_path"], "ACTION_TERMINAL_SKILL")
    rows = iter(values[-12:])
    schema = "aragorn/pi-core-action-control-readback/v1"

    def row(phase, *names, **fixed):
        doc = next(rows)
        expected = dict(schema=schema, grant_digest=pin, phase=phase, **fixed)
        _fields(doc, {*expected, *names})
        _same({k:doc[k] for k in expected}, expected, "ACTION_TERMINAL_CONTROL_PHASE")
        return doc

    uid, gid = expected_action_principal["uid"], expected_action_principal["gid"]

    def original(ids, mode, size=None):
        directory = stat.S_ISDIR(mode)
        _require(type(ids) is list and len(ids) == (5 if directory else 9), "ACTION_TERMINAL_IDENTITY")
        for n in ids:
            _uint(n)
        _require(ids[1] > 0 and ids[2:5] == [mode,uid,gid] and (directory or ids[5:7] == [1,size]),
                 "ACTION_TERMINAL_CONTROL_METADATA")
        return ids

    root = original(row("ROOT", "identity")["identity"], stat.S_IFDIR | 0o710)
    lock = original(row("LOCK_IDENTITY", "identity")["identity"], stat.S_IFREG | 0o600, 0)
    files, documents = {}, {}
    for name, limit in (("state.json",broker._MAX_CONTROL_BYTES), ("capability-grant-state.json",grants._MAX_STATE_BYTES),
                        ("profile-receipt.json",grants._MAX_STATE_BYTES)):
        ids = row("FILE_IDENTITY", "identity", name=name)["identity"]
        encoded = row("FILE_BYTES", "bytes_base64", name=name, encoding="base64")["bytes_base64"]
        _require(type(encoded) is str and 0 < len(encoded) <= 4*((limit+2)//3), "ACTION_TERMINAL_FILE_SIZE")
        data = base64.b64decode(encoded, validate=True)
        _require(len(data) <= limit and base64.b64encode(data).decode("ascii") == encoded, "ACTION_TERMINAL_FILE_BASE64")
        original(ids, stat.S_IFREG | 0o400, len(data))
        doc = broker._parse_canonical_document(data, "retained action control file")
        files[name], documents[name] = dict(identity=ids, digest=canonical_digest(doc)), doc
    absent = {}
    for name in ("profile-pending.json", grants._archive_name("state",pin), grants._archive_name("profile-receipt",pin)):
        row("ABSENCE", name=name, absent=True)
        absent[name] = True
    base, state, receipt = (documents[n] for n in ("state.json", "capability-grant-state.json", "profile-receipt.json"))
    _same(broker._state(base), base, "ACTION_TERMINAL_BASE_STATE")
    _same(grants._state(state, pin), state, "ACTION_TERMINAL_GRANT_STATE")
    _require(base["effect_journal"] is None and state["status"] == "CONSUMED", "ACTION_TERMINAL_OPEN")
    _same(receipt["runtime_attribution"], measured, "ACTION_TERMINAL_RECEIPT_PRINCIPAL")
    _same(receipt["broker_result"], result["broker_result"], "ACTION_TERMINAL_RECEIPT_RESULT")
    _same(recovery._result_record(state["claim"], receipt), state["result"], "ACTION_TERMINAL_RECOVERY")
    _require(state["claim"]["profile_claim"]["request_digest"] == canonical_digest(done["envelope"]["request"]),
             "ACTION_TERMINAL_CLAIM")
    receipt_pin = canonical_digest(receipt)
    row("JOINED", receipt_digest=receipt_pin, state_digest=canonical_digest(state))
    _same(owner["readback"], dict(schema=schema, status="JOINED", read_only=True, grant_digest=pin,
          root_identity=root, lock_identity=lock, files=files, absence=absent, receipt_join_verified=True,
          owned_handles_closed=True, cleanup_uncertainty=[]), "ACTION_TERMINAL_OWNER_READBACK")
    effective = receipt["broker_result"]
    return dict(recorded_verdict=effective["verdict"], recorded_effect_status=effective["effect_status"],
                grant_digest=pin, receipt_digest=receipt_pin)
