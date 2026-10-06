"""Join retained native BLOCK return, receipt attribution and two sink reads.

This pure consumer never invokes a driver, observer, controller, clock or writer.
Empty held-directory observations are point-in-time reports, not evidence that
no transient effect occurred. A returned BLOCK does not establish policy cause.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import stat

from . import runtime_broker_effective_receipt_verify as broker
from . import runtime_native_tool_receipts as receipts
from . import runtime_worker_ingress_verify as worker
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/native-blocked-create-verification/v1"
AUTHORITY = "RETAINED_BLOCK_RETURN_RECEIPT_AND_POINT_IN_TIME_SINK_JOINS_ONLY"
DRIVER_SCHEMA = "aragorn/native-blocked-create-tool-driver/v1"
DRIVER_AUTHORITY = "OWNED_FIXTURE_TOOL_RELAY_OBSERVATION_NOT_SINK_ATTRIBUTION_OR_TIMING"
TARGET = "runtime-worker-qualified.txt"
PAYLOAD = b"Aragorn P3.7b distinct worker create\n"
FALSE_FLAGS = (
    "phase3_eligible",
    "run_conformance_eligible",
    "metrics_eligible",
    "quantitative_metrics_eligible",
    "common_deployment_fully_verified",
    "live_deployment_attested",
    "application_acknowledged",
    "effect_observed",
    "blocked_pre_effect_verified",
    "residue_verified",
    "causal_attribution_verified",
    "policy_causality_verified",
    "elapsed_time_derived",
    "clock_domain_verified",
    "generic_collector_semantics_eligible",
)
LIMITATIONS = (
    "CALLER_PINNED_LOCAL_REPORTS_NOT_SOURCE_PLACEMENT_OR_EXECUTION_ATTESTATION",
    "NATIVE_CALLBACK_BYTES_ARE_SOURCE_DERIVED_PROJECTION_NOT_WIRE_ACK_CAPTURE",
    "TWO_EMPTY_FIXED_SINK_READS_NOT_CONTINUOUS_ABSENCE_OR_NO_TRANSIENT_EFFECT_PROOF",
    "RETURNED_EFFECTIVE_BLOCK_NOT_INDEPENDENT_POLICY_CORRECTNESS_OR_CAUSALITY",
    "SINK_SOURCE_AND_PROCESS_EXPECTATIONS_ARE_CALLER_CUSTODY_NOT_ATTESTATION",
    "NO_CROSS_PROCESS_TIME_ORDER_INTERVAL_OR_LATENCY_DERIVED",
    "ONE_NATIVE_CREATE_NOT_GENERIC_COLLECTOR_SEMANTICS_OR_CAMPAIGN_QUALIFICATION",
)
_EPOCH = ("pid", "start_time_ticks", "uid", "gid")
_MAX_DRIVER = 512 * 1024


class NativeBlockedCreateVerificationError(ValueError):
    """The retained records do not support this bounded workload association."""


def _require(value, reason):
    if not value:
        raise NativeBlockedCreateVerificationError(reason)


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _exact(value, keys, label):
    _require(type(value) is dict and set(value) == set(keys), label + " shape changed")
    return value


def _parse(raw, limit):
    _require(
        type(raw) is bytes and 0 < len(raw) <= limit, "unbounded retained document"
    )
    value = json.loads(
        raw, object_pairs_hook=worker._pairs, parse_constant=worker._noninteger
    )
    _require(
        type(value) is dict and canonical_json(value) == raw,
        "noncanonical retained document",
    )
    return value


def _recorded(record, label):
    _exact(record, {"document", "bytes", "digest"}, label)
    raw = canonical_json(record["document"])
    _require(
        type(record["bytes"]) is int
        and 0 < record["bytes"] == len(raw) <= 65536
        and record["digest"] == _digest(raw),
        label + " bytes differ",
    )
    return record["document"]


def _command(value):
    _exact(
        value,
        {
            "completed_at",
            "error",
            "exit_code",
            "pid",
            "signal",
            "started_at",
            "stderr_bytes",
            "stdout_bytes",
        },
        "driver command",
    )
    _require(
        value["error"] is None
        and value["signal"] is None
        and type(value["exit_code"]) is int
        and value["exit_code"] == 0
        and worker._uint(value["pid"], 1)
        and all(
            worker._uint(value[key], 0, 16 * 1024 * 1024)
            for key in ("stderr_bytes", "stdout_bytes")
        )
        and all(
            type(value[key]) is str and 0 < len(value[key]) <= 64
            for key in ("started_at", "completed_at")
        ),
        "driver command did not complete",
    )


def _driver(value, request, source_result, expected_gateway):
    keys = {
        "schema",
        "authority",
        "status",
        "container_id",
        "tool_name",
        "gateway",
        "provider",
        "turn",
        "native_projection",
        "relay",
        "read_transcript",
        "raw_callback_projection_is_source_derived",
        "native_ack_wire_capture",
        "phase3_eligible",
        "run_conformance_eligible",
        "worker_request",
        "source_result",
        "transcript_checks",
        "native_callback",
        "sink_observed",
        "attribution_verified",
        "elapsed_time_derived",
    }
    _exact(value, keys, "blocked create driver")
    _require(
        value["schema"] == DRIVER_SCHEMA
        and value["authority"] == DRIVER_AUTHORITY
        and value["status"] == "OBSERVED"
        and value["tool_name"] == "aragorn_runtime_create"
        and value["read_transcript"] is None
        and value["raw_callback_projection_is_source_derived"] is True
        and all(
            value[key] is False
            for key in (
                "native_ack_wire_capture",
                "phase3_eligible",
                "run_conformance_eligible",
                "sink_observed",
                "attribution_verified",
                "elapsed_time_derived",
            )
        ),
        "driver outcome/authority changed",
    )
    _require(
        canonical_json(_recorded(value["worker_request"], "driver request"))
        == canonical_json(request)
        and canonical_json(_recorded(value["source_result"], "driver result"))
        == canonical_json(source_result),
        "driver request or source result changed",
    )
    _exact(value["gateway"], {"system_info"}, "driver gateway")
    info = _exact(
        value["gateway"]["system_info"], {"command", "response"}, "gateway observation"
    )
    _exact(info["response"], {"pid"}, "gateway PID")
    _require(
        type(info["response"]["pid"]) is int
        and info["response"]["pid"] == expected_gateway["pid"],
        "driver used another gateway",
    )
    _command(info["command"])
    turn = _exact(value["turn"], {"identifiers", "send", "wait", "history"}, "turn")
    ids = _exact(
        turn["identifiers"],
        {
            "run_id",
            "session_id",
            "session_key_digest",
            "tool_call_digest",
            "request_digest",
            "tool_call_id",
        },
        "turn identifiers",
    )
    _require(
        ids["session_id"] == request["session_id"]
        and ids["run_id"] == request["run_id"]
        and ids["request_digest"] == canonical_digest(request)
        and type(ids["tool_call_id"]) is str
        and re.fullmatch(r"aragorn[0-9a-f]{32}", ids["tool_call_id"]) is not None
        and ids["tool_call_digest"]
        == request["tool_call_digest"]
        == _digest(ids["tool_call_id"].encode("ascii")),
        "driver turn identity differs",
    )
    worker._pin(ids["session_key_digest"])
    for name, extras in (
        ("send", {"run_id": ids["run_id"]}),
        ("wait", {"run_id": ids["run_id"], "status": "ok"}),
        ("history", {"session_id": ids["session_id"]}),
    ):
        row = _exact(turn[name], {"command", *extras}, "turn " + name)
        _require(
            all(row[key] == expected for key, expected in extras.items()),
            "turn command correlation changed",
        )
        _command(row["command"])
    _require(
        value["transcript_checks"]
        == {
            "exact_rpc_history_shape_without_details": True,
            "exact_transcript_rpc_tool_result_join": True,
            "transcript_regular_nonsymlink_bounded": True,
        }
        and all(item is True for item in value["transcript_checks"].values()),
        "transcript join not reported",
    )
    callback = _exact(
        value["native_callback"], {"params_json", "result_json"}, "callback projection"
    )
    projection = _exact(
        value["native_projection"], {"params", "result"}, "native projection"
    )
    parsed = {}
    for name in ("params", "result"):
        text = callback[name + "_json"]
        _require(type(text) is str, "callback bytes missing")
        raw = text.encode("utf-8")
        _require(0 < len(raw) <= 65536, "callback bound changed")
        _exact(projection[name], {"bytes", "digest"}, "callback pin")
        _require(
            type(projection[name]["bytes"]) is int
            and projection[name]["bytes"] == len(raw)
            and projection[name]["digest"] == _digest(raw),
            "callback projection digest differs",
        )
        parsed[name] = json.loads(
            raw, object_pairs_hook=worker._pairs, parse_constant=worker._noninteger
        )
    expected_params = {
        "content": PAYLOAD.decode("ascii"),
        "target_name": TARGET,
        "__aragorn_run_id": ids["run_id"],
        "__aragorn_session_id": ids["session_id"],
        "__aragorn_session_key_digest": ids["session_key_digest"],
        "__aragorn_tool_call_digest": ids["tool_call_digest"],
    }
    _require(
        canonical_json(parsed["params"]) == canonical_json(expected_params),
        "fixed native params changed",
    )
    result = _exact(parsed["result"], {"content", "details"}, "native callback result")
    _require(
        type(result["content"]) is list and len(result["content"]) == 1,
        "native result content changed",
    )
    content = _exact(result["content"][0], {"type", "text"}, "native result text")
    _require(
        content["type"] == "text" and type(content["text"]) is str,
        "native result text missing",
    )
    retained = _parse(content["text"].encode("utf-8"), 65536)
    _exact(retained, {"schema", "message", "result"}, "retained source text")
    _require(
        retained["schema"] == "aragorn/runtime-action-worker-tool-result-text/v1"
        and type(retained["message"]) is str
        and len(retained["message"].encode("utf-8")) <= 512
        and canonical_json(retained["result"]) == canonical_json(source_result)
        and canonical_json(result["details"])
        == canonical_json(
            {
                "schema": "aragorn/runtime-action-worker-openclaw-details/v1",
                "status": "blocked",
                "source_result": source_result,
            }
        ),
        "actual callback source or blocked details differs",
    )
    nested = source_result["broker_result"]
    observed = {
        "schema": "aragorn/openclaw-worker-driver-relay-summary/v1",
        "source_schema": source_result["schema"],
        "source_authority": source_result["authority"],
        "status": "COMPLETED",
        "request_digest": canonical_digest(request),
        "broker_result": {
            "source_schema": nested["schema"],
            "source_authority": nested["authority"],
            **{
                key: nested[key]
                for key in ("verdict", "effect_status", "reason_codes", "target_name")
            },
        },
    }
    expected_relay = {
        "details_checks": {
            "exact_transcript_details_schema_and_status": True,
            "transcript_details_source_result_matches_public_content": True,
        },
        "observed": observed,
    }
    _require(
        canonical_json(value["relay"]) == canonical_json(expected_relay),
        "relay summary or details joins differ",
    )
    provider = _exact(
        value["provider"], {"request_count", "error_count", "records"}, "provider"
    )
    _require(
        type(provider["request_count"]) is int
        and provider["request_count"] == 2
        and type(provider["error_count"]) is int
        and provider["error_count"] == 0
        and type(provider["records"]) is list
        and len(provider["records"]) == 2,
        "provider request count changed",
    )
    for index, record in enumerate(provider["records"], 1):
        _exact(
            record,
            {
                "authorization_valid",
                "contract_valid",
                "content_type",
                "emitted_tool_call_id",
                "message_prefix_continuity_valid",
                "method",
                "path",
                "received_at",
                "request_bytes",
                "sequence",
                "tool_contract_valid",
                "tool_result_summary_digest",
            },
            "provider record",
        )
        _require(
            all(
                record[key] is True
                for key in (
                    "authorization_valid",
                    "contract_valid",
                    "tool_contract_valid",
                )
            )
            and record["content_type"] == "application/json"
            and record["method"] == "POST"
            and record["path"] == "/v1/chat/completions"
            and type(record["sequence"]) is int
            and record["sequence"] == index
            and worker._uint(record["request_bytes"], 1, 16 * 1024 * 1024)
            and type(record["received_at"]) is str
            and 0 < len(record["received_at"]) <= 64
            and record["emitted_tool_call_id"]
            == (ids["tool_call_id"] if index == 1 else None)
            and record["message_prefix_continuity_valid"]
            is (None if index == 1 else True)
            and record["tool_result_summary_digest"]
            == (None if index == 1 else canonical_digest(observed)),
            "provider callback association changed",
        )
    return ids, projection


def _chain(snapshot, count, genesis_pin, expected_worker, binding):
    _exact(
        snapshot,
        {"genesis", "state", "receipts", "state_digest"},
        "native receipt snapshot",
    )
    genesis = _exact(snapshot["genesis"], receipts._GENESIS_FIELDS, "native genesis")
    for key in ("stream_id", "runtime_digest", "policy_digest"):
        receipts._digest(genesis[key])
    for key in ("worker_uid", "worker_gid"):
        receipts._uint(genesis[key], 2**32 - 1, 1)
    receipts._uint(genesis["policy_version"], 2**53 - 1, 1)
    _require(
        genesis["schema"] == "aragorn/native-tool-receipt-genesis/v1"
        and genesis["authority"]
        == "ROOT_PROVISIONED_WORKER_RECEIPT_STREAM_NOT_RUN_AUTHORITY"
        and canonical_digest(genesis) == genesis_pin
        and genesis["worker_uid"] == expected_worker["uid"]
        and genesis["worker_gid"] == expected_worker["gid"]
        and all(
            genesis[key] == binding[key]
            for key in ("runtime_digest", "policy_digest", "policy_version")
        ),
        "native genesis differs from worker identity/binding",
    )
    state = _exact(
        snapshot["state"],
        {"schema", "authority", "genesis_digest", "receipts"},
        "native receipt state",
    )
    _require(
        state["schema"] == "aragorn/native-tool-receipt-state/v1"
        and state["authority"] == receipts._RETAINED_AUTHORITY
        and state["genesis_digest"] == genesis_pin
        and type(state["receipts"]) is list
        and type(snapshot["receipts"]) is list
        and len(state["receipts"]) == len(snapshot["receipts"]) == count
        and len(set(state["receipts"])) == count
        and snapshot["state_digest"] == canonical_digest(state),
        "native receipt count or state changed",
    )
    previous = genesis_pin
    for index, receipt in enumerate(snapshot["receipts"]):
        _exact(
            receipt,
            {
                "schema",
                "authority",
                "genesis_digest",
                "sequence",
                "previous_digest",
                "event",
            },
            "native receipt",
        )
        _require(
            receipt["schema"] == "aragorn/native-tool-receipt/v1"
            and receipt["authority"] == receipts._RETAINED_AUTHORITY
            and receipt["genesis_digest"] == genesis_pin
            and type(receipt["sequence"]) is int
            and receipt["sequence"] == index + 1
            and receipt["previous_digest"] == previous
            and state["receipts"][index] == canonical_digest(receipt)
            and len(canonical_json(receipt)) <= 4096,
            "native receipt chain changed",
        )
        event = receipts._event(receipt["event"], terminal=bool(index))
        _require(
            event["tool_name"] == "aragorn_runtime_create",
            "receipt is not the sole create",
        )
        if index:
            receipts._joins_terminal(event, snapshot["receipts"][0])
        previous = canonical_digest(receipt)
    return snapshot["receipts"]


_SINK_FLAGS = (
    "blocked_pre_effect",
    "causal_attribution",
    "transient_effects_excluded",
    "route_qualified",
    "run_conformance_eligible",
    "metrics_eligible",
    "phase3_eligible",
    "live_deployment_attested",
)
_SINK_LIMITATIONS = (
    "POINT_IN_TIME_DIRECTORY_AND_TARGET_READS_NOT_CONTINUOUS_EFFECT_MONITORING",
    "FIXED_PROTECTED_AND_STAGING_ROOTS_ONLY_NOT_WORKSPACE_OR_GLOBAL_RESIDUE",
    "ROOT_LOCAL_READBACK_NOT_HOSTILE_ROOT_RESISTANT_OR_EXTERNAL_ATTESTATION",
    "NO_EFFECT_POLICY_CAUSALITY_REQUEST_ATTRIBUTION_OR_QUALIFICATION",
)


def _sinks(before, after, container, source_pin, accounts, descriptor):
    keys = {
        "schema",
        "authority",
        "phase",
        "container_id",
        "observer_source_digest",
        "observer_source",
        "path_descriptor",
        "accounts",
        "directories",
        "target",
        "limitations",
        *_SINK_FLAGS,
    }
    for phase, value in (("BEFORE", before), ("AFTER", after)):
        _exact(value, keys, "fixed sink observation")
        _require(
            value["schema"] == "aragorn/native-denied-create-sink/v1"
            and value["authority"]
            == "LOCAL_HELD_DIRECTORY_READBACK_NOT_EFFECT_OR_CAUSALITY_PROOF"
            and value["phase"] == phase
            and value["container_id"] == container
            and value["observer_source_digest"] == source_pin
            and canonical_json(value["accounts"]) == canonical_json(accounts)
            and canonical_json(value["path_descriptor"]) == canonical_json(descriptor)
            and value["limitations"] == list(_SINK_LIMITATIONS)
            and all(value[key] is False for key in _SINK_FLAGS),
            "sink identity, descriptor or ceiling changed",
        )
        source = _exact(
            value["observer_source"],
            {"bytes", "digest", "identity"},
            "sink source readback",
        )
        identity = source["identity"]
        _require(
            type(identity) is list
            and len(identity) == 9
            and all(worker._uint(number) for number in identity)
            and identity[1] > 0
            and stat.S_ISREG(identity[2])
            and stat.S_IMODE(identity[2]) == 0o444
            and identity[3:6] == [0, 0, 1]
            and type(source["bytes"]) is int
            and 0 < source["bytes"] == identity[6] <= 1024 * 1024
            and source["digest"] == source_pin,
            "sink source custody claim changed",
        )
        directories = _exact(
            value["directories"], {"protected", "staging"}, "sink directories"
        )
        for role, mode, gid in (
            ("protected", 0o710, accounts["runtime_gid"]),
            ("staging", 0o700, accounts["broker_gid"]),
        ):
            row = _exact(
                directories[role],
                {
                    "path",
                    "identity",
                    "empty",
                    "scan_complete",
                    "entry_count_lower_bound",
                },
                "sink directory",
            )
            identity = row["identity"]
            _require(
                row["path"] == "/var/lib/aragorn-runtime-action/" + role
                and type(identity) is list
                and len(identity) == 5
                and all(worker._uint(number) for number in identity)
                and identity[1] > 0
                and stat.S_ISDIR(identity[2])
                and stat.S_IMODE(identity[2]) == mode
                and identity[3:] == [accounts["broker_uid"], gid]
                and row["empty"] is True
                and row["scan_complete"] is True
                and type(row["entry_count_lower_bound"]) is int
                and row["entry_count_lower_bound"] == 0,
                "fixed sink was not reported empty under required custody",
            )
        protected, staging = (
            directories[key]["identity"] for key in ("protected", "staging")
        )
        _require(
            protected[:2] == [descriptor["root_device"], descriptor["root_inode"]]
            and protected[0] == staging[0]
            and protected[1] != staging[1]
            and value["target"]
            == {"name": TARGET, "status": "ABSENT", "identity": None},
            "fixed sink target or root differs",
        )
    _require(
        canonical_json(before["directories"]) == canonical_json(after["directories"])
        and canonical_json(before["observer_source"])
        == canonical_json(after["observer_source"]),
        "sink root/source custody changed between reads",
    )


def verify_native_blocked_create(
    *,
    driver_raw,
    expected_driver_digest,
    receipt_before_raw,
    expected_receipt_before_digest,
    receipt_after_raw,
    expected_receipt_after_digest,
    sink_before_raw,
    expected_sink_before_digest,
    sink_after_raw,
    expected_sink_after_digest,
    startup_raw,
    ingress_raw,
    attempt_raw,
    action_raw,
    expected_record_digests,
    completion_raw,
    expected_completion_digest,
    expected_binding_raw,
    expected_binding_digest,
    expected_worker,
    expected_gateway,
    expected_broker_process,
    expected_worker_binding_digest,
    expected_genesis_digest,
    expected_container_id,
    expected_sink_source_digest,
    expected_sink_accounts,
    input_cas,
    evidence_cas,
):
    """Verify retained return/attribution/sink associations, never prevention.

    All explicit records must already be in the read-only evidence CAS, except
    the broker binding and its existing input closure in the read-only input CAS.
    Expectations are independently caller-held pins, not values inferred from a
    driver summary. No observation is reinterpreted as a timing boundary.
    """
    try:
        _require(
            type(input_cas) is CAS
            and input_cas.read_only is True
            and type(evidence_cas) is CAS
            and evidence_cas.read_only is True,
            "exact read-only CAS required",
        )
        worker._exact(expected_worker, set(_EPOCH), "expected worker")
        worker._exact(expected_gateway, {"pid", "uid", "gid"}, "expected gateway")
        _exact(
            expected_sink_accounts,
            {"broker_uid", "broker_gid", "runtime_gid"},
            "expected sink accounts",
        )
        (
            expected_worker,
            expected_gateway,
            expected_broker_process,
            expected_sink_accounts,
            pins,
        ) = json.loads(
            canonical_json(
                [
                    expected_worker,
                    expected_gateway,
                    expected_broker_process,
                    expected_sink_accounts,
                    expected_record_digests,
                ]
            )
        )
        _require(
            all(
                worker._uint(value, 1, 2**32 - 1)
                for value in expected_sink_accounts.values()
            )
            and all(worker._uint(value, 1) for value in expected_gateway.values())
            and type(expected_container_id) is str
            and re.fullmatch(r"[0-9a-f]{64}", expected_container_id) is not None,
            "caller workload identity changed",
        )
        worker._pin(expected_sink_source_digest)
        retained = {}

        def read(store, pin, limit):
            worker._pin(pin)
            raw = store.read(pin, max_bytes=limit)
            _require(
                type(raw) is bytes and 0 < len(raw) <= limit and _digest(raw) == pin,
                "retained workload bytes changed",
            )
            key = (store, pin)
            _require(
                key not in retained or retained[key] == raw, "workload read changed"
            )
            retained[key] = raw
            return raw

        explicit = {
            "driver": (driver_raw, expected_driver_digest, _MAX_DRIVER),
            "receipt_before": (
                receipt_before_raw,
                expected_receipt_before_digest,
                32768,
            ),
            "receipt_after": (receipt_after_raw, expected_receipt_after_digest, 32768),
            "sink_before": (sink_before_raw, expected_sink_before_digest, 16384),
            "sink_after": (sink_after_raw, expected_sink_after_digest, 16384),
            "completion": (completion_raw, expected_completion_digest, 4096),
        }
        _exact(pins, set(worker.STAGES), "worker record pins")
        for stage, raw in zip(
            worker.STAGES,
            (startup_raw, ingress_raw, attempt_raw, action_raw),
            strict=True,
        ):
            explicit[stage] = (raw, pins[stage], worker.MAX_RECORD_BYTES)
        documents = {}
        for name, (raw, pin, limit) in explicit.items():
            _require(
                type(raw) is bytes and read(evidence_cas, pin, limit) == raw,
                "workload input not retained",
            )
            documents[name] = _parse(raw, limit)
        _require(
            read(input_cas, expected_binding_digest, 4096) == expected_binding_raw,
            "broker binding not retained",
        )
        ingress = worker.verify_worker_ingress_records(
            startup_raw,
            ingress_raw,
            attempt_raw,
            action_raw,
            expected_record_digests=pins,
            expected_worker=expected_worker,
            expected_binding_digest=expected_worker_binding_digest,
            expected_genesis_digest=expected_genesis_digest,
        )
        broker_arguments = dict(
            completion_raw=completion_raw,
            expected_completion_digest=expected_completion_digest,
            expected_binding_raw=expected_binding_raw,
            expected_binding_digest=expected_binding_digest,
            expected_process_identity=expected_broker_process,
            input_cas=input_cas,
            evidence_cas=evidence_cas,
        )
        final = broker.verify_broker_effective_receipt(**broker_arguments)
        _require(
            final["recorded_broker_outcome"]["verdict"] == "BLOCK"
            and final["recorded_broker_outcome"]["effect_status"] == "NOT_PERFORMED"
            and final["scheduled_request"]["kind"] == "attempt"
            and final["scheduled_request"]["negative_control"] is False,
            "only one attributed effective BLOCK is supported",
        )
        submission = _parse(
            read(evidence_cas, final["submission_digest"], 128 * 1024), 128 * 1024
        )
        request = documents["ingress"]["body"]["worker_request"]
        action = documents["action"]["body"]["action_request"]
        _require(
            request["target_name"] == TARGET
            and request["payload_base64"] == base64.b64encode(PAYLOAD).decode("ascii")
            and canonical_json(action)
            == canonical_json(submission["envelope"]["request"])
            and canonical_digest(action) == final["action_request_digest"]
            and all(
                type(submission["runtime_attribution"][key]) is int
                and submission["runtime_attribution"][key] == expected_worker[key]
                for key in _EPOCH
            )
            and canonical_json(submission["runtime_peer"])
            == canonical_json(
                {key: expected_worker[key] for key in ("pid", "uid", "gid")}
            )
            and canonical_json(documents["ingress"]["body"]["gateway_peer"])
            == canonical_json(expected_gateway),
            "native request, worker epoch or gateway attribution differs",
        )
        evidence = _parse(
            read(evidence_cas, final["evidence_digest"], 1024 * 1024), 1024 * 1024
        )
        broker_result = _parse(
            read(evidence_cas, evidence["broker_result_digest"], 16384), 16384
        )
        source_result = {
            "schema": "aragorn/runtime-action-worker-result/v1",
            "authority": "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
            "status": "COMPLETED",
            "request_digest": canonical_digest(request),
            "broker_result": broker_result,
        }
        driver = documents["driver"]
        _require(
            driver["container_id"] == expected_container_id, "driver fixture differs"
        )
        ids, projections = _driver(driver, request, source_result, expected_gateway)
        binding = documents["startup"]["worker_binding"]
        before, after = documents["receipt_before"], documents["receipt_after"]
        _chain(before, 0, expected_genesis_digest, expected_worker, binding)
        attempt, terminal = _chain(
            after, 2, expected_genesis_digest, expected_worker, binding
        )
        _require(
            canonical_json(before["genesis"]) == canonical_json(after["genesis"])
            and canonical_json(attempt)
            == canonical_json(documents["attempt"]["body"]["attempt"])
            and documents["attempt"]["body"]["receipt_state"]["receipts"]
            == [canonical_digest(attempt)],
            "native receipt prefix/ingress attempt differs",
        )
        correlation = {key: ids[key] for key in receipts._CORRELATION}
        expected_attempt = {
            "schema": "aragorn/native-tool-attempt/v1",
            "authority": receipts._AUTHORITY,
            "tool_name": "aragorn_runtime_create",
            **correlation,
            "params_digest": projections["params"]["digest"],
            "params_bytes": projections["params"]["bytes"],
            "worker_request_digest": canonical_digest(request),
        }
        expected_terminal = {
            "schema": "aragorn/native-tool-terminal/v1",
            "authority": receipts._AUTHORITY,
            "tool_name": "aragorn_runtime_create",
            **correlation,
            "attempt_digest": canonical_digest(attempt),
            "outcome": "RETURNED",
            "result_digest": projections["result"]["digest"],
            "result_bytes": projections["result"]["bytes"],
            "error_code": None,
        }
        _require(
            canonical_json(attempt["event"]) == canonical_json(expected_attempt)
            and canonical_json(terminal["event"]) == canonical_json(expected_terminal),
            "actual native callback bytes differ from attempt/terminal receipt",
        )
        descriptor = _parse(read(input_cas, action["path_digest"], 4096), 4096)
        _require(
            expected_sink_accounts["broker_uid"] == expected_broker_process["uid"]
            and expected_sink_accounts["runtime_gid"]
            == expected_worker["gid"]
            == expected_broker_process["gid"],
            "sink account expectation differs from fixed common runtime",
        )
        _sinks(
            documents["sink_before"],
            documents["sink_after"],
            expected_container_id,
            expected_sink_source_digest,
            expected_sink_accounts,
            descriptor,
        )
        _require(
            canonical_json(broker.verify_broker_effective_receipt(**broker_arguments))
            == canonical_json(final),
            "broker closure changed during workload joins",
        )
        for (store, pin), raw in retained.items():
            _require(read(store, pin, len(raw)) == raw, "final workload custody lost")
        return {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "status": "RETAINED_BLOCKED_CREATE_WORKLOAD_JOINS_VERIFIED",
            "input_digests": {name: pin for name, (_, pin, _) in explicit.items()}
            | {
                "broker_binding": expected_binding_digest,
                "profiled_submission": final["submission_digest"],
            },
            "worker_request_digest": canonical_digest(request),
            "action_request_digest": canonical_digest(action),
            "native_attempt_digest": canonical_digest(attempt),
            "native_terminal_digest": canonical_digest(terminal),
            "native_callback_result_digest": projections["result"]["digest"],
            "recorded_return": {
                "status": "COMPLETED",
                **final["recorded_broker_outcome"],
            },
            "recorded_sink_reads": {
                "before": "FIXED_DIRECTORIES_EMPTY_TARGET_ABSENT",
                "after": "FIXED_DIRECTORIES_EMPTY_TARGET_ABSENT",
            },
            "component_verification_digests": {
                "worker_ingress": canonical_digest(ingress),
                "broker_effective_receipt": canonical_digest(final),
            },
            "decision": dict.fromkeys(FALSE_FLAGS, False),
            "limitations": list(LIMITATIONS),
        }
    except NativeBlockedCreateVerificationError:
        raise
    except Exception as exc:
        raise NativeBlockedCreateVerificationError(
            "retained blocked-create verification refused"
        ) from exc
