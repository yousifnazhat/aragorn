"""Compare the local B27 packet journal to one B93 request, not network traffic or a file."""
from hashlib import sha256

from aragorn import pi_core_provider_mediation as mediation, pi_core_provider_service as service
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest
from aragorn.pi_core_provider_evidence import _MAX_INDEX, _MAX_RECORD, _MAX_RECORDS
from aragorn.pi_core_source_observation_verify import _document, _fields, _pin, _require, _same, _uint
from aragorn.pi_core_worker_identity import _ATTRIBUTION_FIELDS, validate_activation
from aragorn.runtime_action_worker import _worker_request


def compare_provider_records(archive, nomination_digest, *, activation, worker_request, skill_bytes, task_bytes):
    _require(type(archive) is CAS and archive.read_only is True, "PILOT_PROVIDER_READ_ONLY")
    n = _document(archive.read(_pin(nomination_digest), max_bytes=4096))
    _fields(n, ("schema", "index_digest", "activation_digest", "request_digest", "route_digest",
                "profile_digest", "nonce", "deadline_ns"))
    for field in ("index_digest", "activation_digest", "request_digest", "route_digest", "profile_digest"):
        _pin(n[field])
    activation = validate_activation(activation)
    worker, payload = _worker_request(worker_request)
    _require(n["schema"] == "aragorn/pi-core-pilot-provider-nomination/v1"
             and canonical_digest(activation) == n["activation_digest"]
             and (worker["session_id"], worker["run_id"]) == (activation["session_id"], activation["run_id"])
             and _uint(n["deadline_ns"], 1) <= activation["expires_at_monotonic_ns"], "PILOT_PROVIDER_NOMINATION")
    raw = archive.read(n["index_digest"], max_bytes=_MAX_INDEX)
    _require(raw.endswith(b"\n"), "PILOT_PROVIDER_INDEX_TRUNCATED")
    lines = raw[:-1].split(b"\n")
    _require(1 < len(lines) <= _MAX_RECORDS + 1, "PILOT_PROVIDER_INDEX_LENGTH")
    _same(_document(lines[0]), dict(schema="aragorn/pi-core-provider-evidence-index/v1",
          authority="DURABLE_REFERENCE_PREFIX_ONLY_NOT_COMPLETED_CAPTURE", sequence=0, kind="HEADER",
          activation_id=activation["activation_id"], activation_digest=n["activation_digest"]), "PILOT_PROVIDER_HEADER")
    prefix, seq = sha256(lines[0] + b"\n"), 0

    def take(kind):
        nonlocal seq
        seq += 1
        _require(seq < len(lines), "PILOT_PROVIDER_INDEX_TRUNCATED")
        line = lines[seq]
        ref = _fields(_document(line), ("schema", "sequence", "previous_prefix_digest", "kind", "digest", "bytes"))
        _require(ref["schema"] == "aragorn/pi-core-provider-evidence-reference/v1" and ref["kind"] == kind
                 and _uint(ref["sequence"], 1, _MAX_RECORDS) == seq
                 and ref["previous_prefix_digest"] == "sha256:" + prefix.hexdigest(), "PILOT_PROVIDER_INDEX_ORDER")
        prefix.update(line + b"\n")
        blob = archive.read(_pin(ref["digest"]), max_bytes=_uint(ref["bytes"], 1, _MAX_RECORD))
        _require(len(blob) == ref["bytes"], "PILOT_PROVIDER_RECORD_SIZE")
        return _document(blob), ref["digest"]

    request, pin = take("REQUEST")
    _require(pin == n["request_digest"], "PILOT_PROVIDER_REQUEST")
    mediation.validate_provider_request(request)
    _same(request["payload"]["messages"], [
        dict(role="system", content=skill_bytes.decode("utf-8"), timestamp=0, toolsAdded=[mediation._TOOL]),
        dict(role="user", content=[dict(type="text", text=task_bytes.decode("utf-8"))], timestamp=0)
    ], "PILOT_PROVIDER_INPUTS")
    _require(request["activation_id"] == activation["activation_id"] and request["route_digest"] == n["route_digest"]
             and take("ACTIVATION")[1] == n["activation_digest"], "PILOT_PROVIDER_ACTIVATION")
    measurement = take("MEASUREMENT")[0]
    _same({k: measurement[k] for k in _ATTRIBUTION_FIELDS}, {k: activation[k] for k in _ATTRIBUTION_FIELDS},
          "PILOT_PROVIDER_WORKER")
    lineage = take("LINEAGE")[0]
    expected_lineage = {k: activation[k] for k in ("tree_digest", "active_skill_digest", "active_record_digest")}
    expected_lineage.update(context_digest=activation["install_context_digest"], manifest_digest=activation["source_manifest_digest"],
                            runtime_skill_path=measurement["skill_path"])
    _same({k: lineage[k] for k in expected_lineage}, expected_lineage, "PILOT_PROVIDER_LINEAGE")
    approval, _ = mediation._approval(take("APPROVAL")[0], request, activation)
    _require(approval["data_class"] == "FABRICATED_OWNED_LAB", "PILOT_PROVIDER_DATA_CLASS")
    action_pin = canonical_digest(approval["request"])

    def boundary(phase, source_digest):
        value, _ = take("SOURCE_BOUNDARY")
        _require(value["phase"] == phase and value["source_digest"] == source_digest, "PILOT_PROVIDER_SOURCE_LINK")

    def decision():
        pins = {key: take(label)[1] for label, key in (("POLICY", "policy_digest"),
                ("REVOCATIONS", "revocation_snapshot_digest"), ("GLOBAL_HEALTH", "mediator_health_digest"))}
        observation, observation_pin = take("OBSERVATION")
        entry, _ = take("DECISION")
        _require(entry["verdict"] == "ALLOW" and entry["request_digest"] == action_pin and
                 pins["policy_digest"] == activation["policy_digest"] and
                 entry["active_context_digest"] == canonical_digest(observation["active"]) and
                 entry["measured_action_digest"] == canonical_digest(observation["measured_action"]) and
                 all(entry[key] == pin for key, pin in pins.items()),
                 "PILOT_PROVIDER_DECISION")
        return observation_pin

    source = take("SOURCE_HEALTH")[1]
    boundary("PRE_POLICY", source)
    boundary("POLICY_PUBLICATION", source)
    observed = decision()
    _require(decision() == observed, "PILOT_PROVIDER_OBSERVATION")
    start = service.validate_packet(take("SERVICE_REQUEST")[0])
    _require(start["kind"] == "REQUEST" and canonical_digest(start["profile"]) == n["profile_digest"]
             and canonical_digest(start["route"]) == n["route_digest"] and start["route"] == approval["route"],
             "PILOT_PROVIDER_SERVICE_PROFILE")
    _same(start["request"], request, "PILOT_PROVIDER_SERVICE_REQUEST")
    base = dict(nonce=n["nonce"], deadline_ns=n["deadline_ns"], request_digest=n["request_digest"],
                wire_digest=canonical_digest(start["wire"]))

    def binding(packet, kind):
        _require(packet["kind"] == kind and all(packet[k] == v for k, v in base.items()), "PILOT_PROVIDER_PACKET")

    binding(start, "REQUEST")
    for sequence, phase in ((1, "CONNECT"), (2, "SEND")):
        check = service.validate_packet(take("SERVICE_CHECK")[0])
        binding(check, "CHECK")
        _require(check["sequence"] == sequence and check["phase"] == phase, "PILOT_PROVIDER_CHECK_PHASE")
        _require(decision() == observed, "PILOT_PROVIDER_OBSERVATION")
        source = take("SOURCE_HEALTH")[1]
        boundary(phase, source)
        permit = service.validate_packet(take("SERVICE_PERMIT")[0])
        binding(permit, "CURRENT")
        _require(permit["sequence"] == sequence and permit["phase"] == phase, "PILOT_PROVIDER_PERMIT_PHASE")
        boundary(phase + "_PERMIT_CHECK", source)

    terminal = service.validate_packet(take("SERVICE_RESULT")[0])
    binding(terminal, "RESULT")
    result, result_pin = take("PROVIDER_RESULT")
    _require(seq == len(lines) - 1 and canonical_digest(terminal["result"]) == result_pin
             and result["status"] == "COMPLETED" and result["completion"]["stop_reason"] == "toolUse",
             "PILOT_PROVIDER_TERMINAL")
    # validate_packet checked the result's schema, exactly one fixed tool, and the transport outcome.
    call, = (item for item in result["completion"]["content"] if item["type"] == "toolCall")
    _require(worker["tool_call_digest"] == "sha256:" + sha256(call["id"].encode("utf-8")).hexdigest()
             and worker["target_name"] == call["arguments"]["target_name"]
             and payload == call["arguments"]["content"].encode("utf-8"), "PILOT_PROVIDER_WORKER_TOOL")
    return dict(provider_index_digest=n["index_digest"], provider_result_digest=result_pin,
                recorded_tool_call_matches_worker_request=True)
