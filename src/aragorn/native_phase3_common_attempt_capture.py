"""Retained public attempt joins, not private measurement replay or attestation.

No guest controller, probe or clock is imported. Public source, custody and
execution records remain claims. This consumer independently checks their exact
retained joins and the public preparation; it deliberately cannot replay private
grant/writer semantics or qualify an attempt, interval, RUN or Phase 3 gate.
"""

from __future__ import annotations

from . import native_phase3_common_attempt_inputs as inputs
from . import native_phase3_common_setup_capture as base
from .cas import CAS
from .oci_worker_protocol import canonical_json

SCHEMA = "aragorn/native-common-attempt-capture/v1"
AUTHORITY = "OWNED_COMMON_ATTEMPT_CAPTURE_NOT_RUN_OR_PHASE3_QUALIFICATION"
NAME_PREFIX = "aragorn-native-common-attempt-"
MAX_CAPTURE = 144 * 1024 * 1024
MAX_GUEST = 128 * 1024 * 1024
MAX_PUBLIC_BLOB = 16 * 1024 * 1024
MAX_PUBLIC_TOTAL = 32 * 1024 * 1024
MAX_PUBLIC_BLOBS = 256
FALSE_FLAGS = (
    "deployment_attested",
    "admission_qualified",
    "run_qualified",
    "quantitative_metrics_eligible",
    "phase3_exit_eligible",
    "generic_collector_semantics_eligible",
    "blocked_pre_effect",
    "causal_attribution",
    "transient_effects_excluded",
    "host_capture_verified",
)
PUBLIC_ROLES = frozenset(
    (
        "common_public_input",
        "original_schedule",
        "original_commitment",
        "original_collection_preparation",
        "selected_request",
        "protected_descriptor",
        "measurement_binding",
        "measurement_preparation",
        "common_measured_request",
        "plan_report",
        "handoff",
        "request",
        "provisioning",
        "claim",
        "identity_before",
        "identity_after",
        "process_before",
        "process_after",
        "clock_before",
        "clock_after",
        "workload",
        "measurement_snapshot",
        "broker_blob",
        "independent_verification",
    )
    + tuple(
        "workload_" + name
        for name in (
            "identity_before",
            "identity_after",
            "receipt_before",
            "receipt_after",
            "sink_before",
            "sink_after",
            "driver_input",
            "driver",
        )
    )
    + tuple(
        "measurement_" + name
        for name in (
            "startup",
            "ingress",
            "attempt",
            "action",
            "pending",
            "completion",
        )
    )
)


class NativeCommonAttemptCaptureError(ValueError):
    """An incomplete or inconsistent public capture cannot be replayed."""


def _require(condition, reason):
    if not condition:
        raise NativeCommonAttemptCaptureError(reason)


_digest, _pin = base._digest, base._pin


def _false(value):
    _require(
        all(value.get(key) is False for key in FALSE_FLAGS),
        "qualification ceiling changed",
    )


def _public(capture, read):
    guest, report = capture["guest"], capture["guest"]["attempt"]
    journal, rows = report["public_blob_attempts"], guest["public_blobs"]
    _require(
        type(journal) is list and 1 <= len(journal) <= MAX_PUBLIC_BLOBS,
        "public journal bound",
    )
    candidates, roles = {}, {}
    for row in journal:
        _require(
            type(row) is dict
            and set(row) == {"role", "digest", "bytes"}
            and row["role"] in PUBLIC_ROLES
            and type(row["bytes"]) is int
            and 0 < row["bytes"] <= MAX_PUBLIC_BLOB,
            "public role or bound changed",
        )
        pin = _pin(row["digest"])
        _require(
            pin not in candidates or candidates[pin] == row["bytes"],
            "duplicate pin length changed",
        )
        candidates[pin] = row["bytes"]
        roles.setdefault(row["role"], set()).add(pin)
    _require(
        type(rows) is list
        and len(rows) == len(candidates)
        and sum(candidates.values()) <= MAX_PUBLIC_TOTAL
        and report["public_blob_digests"] == sorted(candidates),
        "public closure inventory changed",
    )
    exported = {}
    for row in rows:
        _require(
            type(row) is dict and set(row) == {"digest", "bytes", "text"},
            "public export shape changed",
        )
        pin = _pin(row["digest"])
        _require(
            type(row["text"]) is str and type(row["bytes"]) is int,
            "public export types changed",
        )
        raw = row["text"].encode("utf-8")
        _require(
            pin not in exported
            and pin in candidates
            and 0 < len(raw) == row["bytes"] == candidates[pin]
            and _digest(raw) == pin
            and read(pin) == raw,
            "public export missing, extra or changed",
        )
        exported[pin] = raw
    order = [row["digest"] for row in rows]
    _require(
        capture["guest_publication"]
        == {
            "attempted": order,
            "retained": order,
            "failed": [],
            "complete": True,
        },
        "host publication incomplete",
    )
    return exported, roles


def _attempt(report, bound, container, exported, roles, read):
    _require(
        type(report) is dict
        and len(canonical_json(report)) <= 2 * 1024 * 1024
        and report["schema"] == "aragorn/native-common-attempt/v1"
        and report["authority"]
        == "OWNED_FIRST_ACTIVATION_BOUNDED_ATTEMPT_NOT_HOST_OR_CAMPAIGN_AUTHORITY"
        and report["status"] == "BOUNDED_NATIVE_ATTEMPT_VERIFIED"
        and report["refusal"] is None
        and report["postcondition_failures"] == []
        and report["public_readback_failures"] == [],
        "bounded guest attempt incomplete",
    )
    _false(report)
    for count in (
        "callback_count",
        "workload_count",
        "snapshot_count",
        "cleanup_count",
    ):
        _require(
            type(report[count]) is int and report[count] == 1, "once-only count changed"
        )
    state = report["setup_state"]
    _require(
        type(state["activation_count"]) is int
        and state["activation_count"] == 1
        and state["pins_frozen_before_activation"] is True,
        "first activation claim changed",
    )
    _require(
        not set(state["provisioning_file_digests"].values()).intersection(exported),
        "private writer pin exported",
    )
    cleanup = report["fixture_stack_cleanup"]
    _require(set(cleanup) == set(base._UNITS), "four-service cleanup incomplete")
    for unit, record in cleanup.items():
        _require(
            record["Id"] == unit
            and record["ActiveState"] == "inactive"
            and record["MainPID"] == record["ControlPID"] == "0",
            "service cleanup incomplete",
        )

    def document(pin, role):
        _require(pin in roles.get(role, set()), "public role binding missing")
        return base._parse(exported[pin], MAX_PUBLIC_BLOB)

    # These are byte joins to asserted producer reports, NOT a second execution
    # of their private semantic verifiers.
    for key, role in (
        ("plan", "plan_report"),
        ("handoff", "handoff"),
        ("verification", "independent_verification"),
    ):
        raw = canonical_json(report[key])
        _require(
            document(_digest(raw), role) == report[key],
            "public report differs from retained bytes",
        )

    def record_join(record, role):
        _require(
            type(record) is dict
            and set(record) == {"text", "bytes", "digest"}
            and type(record["text"]) is str
            and type(record["bytes"]) is int,
            "embedded public record shape changed",
        )
        raw = record["text"].encode("utf-8")
        _require(
            0 < len(raw) == record["bytes"] <= MAX_PUBLIC_BLOB
            and _digest(raw) == record["digest"]
            and record["digest"] in roles.get(role, set())
            and exported[record["digest"]] == raw,
            "embedded public record differs",
        )

    for role in ("request", "provisioning", "claim"):
        document(report["handoff"][role + "_digest"], role)
    for key, role, status in (
        ("workload", "workload", "OBSERVED"),
        ("snapshot", "measurement_snapshot", "SNAPSHOTTED"),
    ):
        summary = report[key]
        full = document(summary["digest"], role)
        _require(
            set(summary) == {"status", "digest"}
            and summary["status"] == status
            and full["status"] == status,
            "public report summary differs from retained report",
        )
        names = (
            {
                "identity_before",
                "identity_after",
                "receipt_before",
                "receipt_after",
                "sink_before",
                "sink_after",
                "driver_input",
                "driver",
            }
            if key == "workload"
            else {"startup", "ingress", "attempt", "action", "pending", "completion"}
        )
        _require(
            type(full["records"]) is dict and set(full["records"]) == names,
            "public report record inventory incomplete",
        )
        for name, record in full["records"].items():
            record_join(
                record, ("workload_" if key == "workload" else "measurement_") + name
            )
        if key == "snapshot":
            _require(
                set(full["broker_blob_digests"])
                == {
                    "evidence",
                    "consumed_grant_state",
                    "profile_receipt",
                    "broker_result",
                    "profiled_submission",
                }
                and set(full["broker_blobs"])
                == set(full["broker_blob_digests"].values()),
                "broker public closure changed",
            )
            for pin, record in full["broker_blobs"].items():
                _require(record["digest"] == pin, "broker record pin changed")
                record_join(record, "broker_blob")
    plan = report["plan"]
    _require(
        plan["status"] == "ORIGINAL_PLAN_PREPARED_NOT_PROVISIONED"
        and plan["container_id"] == container,
        "original plan identity changed",
    )
    public_common = {
        pin: exported[pin] for pin in roles.get("common_public_input", set())
    }
    common = document(plan["common_preparation_digest"], "common_public_input")
    setup = {
        "container_id": container,
        "preparation": {
            "preparation": common,
            "preparation_digest": plan["common_preparation_digest"],
            "retained_blob_digests": sorted(public_common),
            "local_readback": True,
        },
    }
    prepared, baseline, _ = base._public_preparation(
        setup, bound["base_bound"], public_common, read
    )
    _require(
        prepared["provisioning_file_digests"] == state["provisioning_file_digests"],
        "writer pin joins changed",
    )
    collection = document(
        plan["collection_preparation_digest"], "original_collection_preparation"
    )
    commitment = document(plan["commitment_digest"], "original_commitment")
    schedule = collection["schedule"]
    _require(
        document(_digest(canonical_json(schedule)), "original_schedule") == schedule
        and collection["commitment"] == commitment
        and collection["commitment_digest"] == plan["commitment_digest"],
        "collection joins changed",
    )
    args = bound["plan_arguments"]
    _require(
        schedule["attempt_schedule"]
        == {
            "attempt_count": 100,
            "attempt_ids": args["expected_attempt_ids"],
            "attempt_families": args["expected_attempt_families"],
            "unattributed_negative_control_attempt_id": args[
                "expected_unattributed_attempt_id"
            ],
        },
        "caller attempt inventory changed",
    )
    _require(
        schedule["overhead_schedule"]
        == {
            "pair_count": 100,
            "pair_bindings": args["expected_overhead_pair_bindings"],
        },
        "caller pair inventory changed",
    )
    for key in ("gate_manifest_digest", "campaign_contract_digest"):
        _require(
            schedule["bindings"][key] == args["expected_" + key],
            "caller campaign pin changed",
        )
    _require(
        schedule["bindings"]["runtime_identity_digest"]
        == prepared["deployment_digest"],
        "deployment join changed",
    )
    selected = plan["scheduled_request"]
    _require(
        document(_digest(canonical_json(selected)), "selected_request") == selected
        and selected
        == {
            "kind": "attempt",
            "attempt_id": args["selected_attempt_id"],
            "family": args["expected_attempt_families"][args["selected_attempt_id"]],
            "negative_control": False,
            "collection_digest": plan["commitment_digest"],
            "deployment_digest": prepared["deployment_digest"],
        },
        "selected request changed",
    )
    binding = document(plan["binding_digest"], "measurement_binding")
    request = document(plan["request_digest"], "common_measured_request")
    measured = document(plan["measurement_prepared_digest"], "measurement_preparation")
    _require(
        measured["binding"] == binding
        and measured["binding_digest"] == plan["binding_digest"]
        and request["container_id"] == container
        and request["measurement_binding_digest"] == plan["binding_digest"]
        and binding["collection_commitment_digest"] == plan["commitment_digest"]
        and binding["scheduled_measurement_request_digest"]
        == _digest(canonical_json(selected))
        and binding["attempt_id"] == args["selected_attempt_id"],
        "measurement public joins changed",
    )
    _require(
        plan["request_digest"] in roles.get("request", set()), "handoff request differs"
    )
    _require(
        report["handoff"]["request_digest"] == plan["request_digest"],
        "handoff uses another request",
    )
    for role in (
        "provisioning",
        "claim",
        "identity_before",
        "identity_after",
        "process_before",
        "process_after",
        "clock_before",
        "clock_after",
        "measurement_startup",
        "measurement_ingress",
        "measurement_attempt",
        "measurement_action",
        "measurement_pending",
        "measurement_completion",
    ):
        _require(len(roles.get(role, set())) == 1, "required public observation absent")
    return baseline, prepared["deployment_digest"]


def _generated_driver(report, bound):
    _require(
        report["schema"] == "aragorn/native-blocked-create-driver-source-overlay/v1"
        and report["authority"]
        == "PINNED_FIXED_WORKLOAD_SOURCE_ONLY_NOT_CAPTURE_OR_DEPLOYMENT_AUTHORITY"
        and report["files"]
        == [
            {"name": path.rsplit("/", 1)[1], **row}
            for path, row in inputs.GENERATED_FILES.items()
        ],
        "generated driver output changed",
    )
    for key, paths in (
        ("source_inputs", inputs.DRIVER_SOURCE_PATHS[2:]),
        (
            "required_checkout_dependencies_not_included",
            inputs.DRIVER_SOURCE_PATHS[1:2],
        ),
    ):
        _require(
            report[key]
            == [
                {
                    "name": path,
                    "bytes": len(bound["source_raws"][path]),
                    "digest": _digest(bound["source_raws"][path]),
                }
                for path in paths
            ],
            "generated driver source closure changed",
        )
    _require(
        all(
            report[key] is False
            for key in (
                "standalone_executable",
                "capture_performed",
                "production_activation_eligible",
                "sink_observed",
                "attribution_verified",
                "elapsed_time_derived",
                "run_eligible",
                "phase3_eligible",
            )
        ),
        "driver authority changed",
    )


def _private_retention_metadata(capture, read):
    """Join optional private-custody metadata; never read or attest private bytes."""
    attempted = capture.get("private_input_transfer_attempted", False)
    value = capture.get("private_measurement_inputs")
    _require(type(attempted) is bool, "private transfer marker changed")
    if not attempted:
        _require(value is None, "unattempted private transfer has metadata")
        return
    _require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "authority",
            "status",
            "container_id",
            "prepared_digest",
            "binding_digest",
            "grant_digest",
            "grant_bytes",
            "input_blobs",
            "input_set_digest",
            "fixture_before",
            "fixture_after",
            "grant_source_before",
            "grant_source_after",
            "scratch_directory",
            "copy_count",
            "input_validation_complete",
            "postcondition_failures",
            "refusal",
            *FALSE_FLAGS,
        }
        and len(canonical_json(value)) <= 32768,
        "private retention metadata inventory changed",
    )
    _require(
        value["schema"] == "aragorn/native-common-measurement-input-retention/v1"
        and value["authority"]
        == "PRIVATE_HOST_CAS_RETENTION_NOT_MEASUREMENT_OR_QUALIFICATION"
        and value["status"] == "PRIVATE_INPUTS_RETAINED"
        and value["container_id"] == capture["fixture_container"]
        and type(value["copy_count"]) is int
        and value["copy_count"] == 1
        and value["input_validation_complete"] is True
        and value["postcondition_failures"] == []
        and value["refusal"] is None,
        "private retention incomplete",
    )
    _false(value)
    plan = capture["guest"]["attempt"]["plan"]
    prepared = base._parse(read(plan["measurement_prepared_digest"], 32768), 32768)
    _require(
        value["prepared_digest"] == plan["measurement_prepared_digest"]
        and value["binding_digest"] == plan["binding_digest"]
        and value["grant_digest"] == prepared["binding"]["grant_digest"]
        and value["input_blobs"] == prepared["input_blobs"]
        and value["input_set_digest"] == _digest(canonical_json(value["input_blobs"]))
        and type(value["grant_bytes"]) is int
        and 0 < value["grant_bytes"] <= 65536
        and {"digest": value["grant_digest"], "bytes": value["grant_bytes"]}
        in value["input_blobs"],
        "private retention plan changed",
    )
    fixture = value["fixture_before"]
    _require(
        type(fixture) is dict
        and set(fixture)
        == {
            "container_id",
            "name",
            "owner",
            "source_commit",
            "image",
            "network_mode",
            "pid",
            "started_at",
        }
        and fixture == value["fixture_after"]
        and fixture["container_id"] == capture["fixture_container"]
        and fixture["name"] == capture["fixture_name"]
        and fixture["owner"] == capture["fixture_owner"]
        and fixture["source_commit"] == capture["source"]["commit"]
        and fixture["image"] == capture["fixture_image"]["Id"]
        and fixture["network_mode"] == "none"
        and type(fixture["pid"]) is int
        and fixture["pid"] > 0
        and type(fixture["started_at"]) is str
        and 0 < len(fixture["started_at"]) <= 128,
        "private retention fixture changed",
    )
    metadata = value["grant_source_before"]
    base.live._metadata(metadata, owners={(0, 0)}, modes={0o444})
    _require(
        metadata == value["grant_source_after"]
        and metadata["digest"] == value["grant_digest"]
        and metadata["bytes"] == value["grant_bytes"],
        "private grant source custody changed",
    )
    scratch = value["scratch_directory"]
    _require(
        type(scratch) is str
        and 0 < len(scratch) <= 4096
        and scratch.startswith("/")
        and scratch.endswith("/native-common-measurement-input-retention")
        and not {".", "..", ""}.intersection(scratch.split("/")[1:])
        and "\x00" not in scratch,
        "private scratch location changed",
    )


def verify_native_common_attempt_capture(
    capture_raw, *, expected_capture_digest, store
):
    """Only a complete successful envelope is replayable; refusals stay retained."""
    try:
        _require(
            type(store) is CAS and store.read_only is True,
            "read-only evidence CAS required",
        )
        _require(
            type(capture_raw) is bytes
            and _digest(capture_raw) == _pin(expected_capture_digest),
            "capture pin changed",
        )
        capture = base._parse(capture_raw, MAX_CAPTURE, newline=True)
        retained = set()

        def read(pin, limit=MAX_PUBLIC_BLOB):
            pin = _pin(pin)
            raw = store.read(pin, max_bytes=limit)
            _require(
                type(raw) is bytes and 0 < len(raw) <= limit and _digest(raw) == pin,
                "retained bytes changed",
            )
            retained.add(pin)
            return raw

        _require(
            read(expected_capture_digest, MAX_CAPTURE) == capture_raw,
            "capture not retained",
        )
        _require(
            set(capture)
            - {"private_input_transfer_attempted", "private_measurement_inputs"}
            == {
                "schema",
                "authority",
                "status",
                "input_bundle_digest",
                "source",
                "build_observation",
                "fixture_helpers",
                "fixture_aliases",
                "fixture_image",
                "parent_identity",
                "parent_before",
                "parent_after",
                "runtime_before",
                "runtime_after",
                "fixture_container",
                "fixture_name",
                "fixture_owner",
                "container_inspect",
                "staged_profile",
                "generated_driver",
                "guest",
                "guest_recovery",
                "guest_publication",
                "cleanup",
                "cleanup_failure",
                "refusal",
                "fixture_creation_attempted",
                "invocation_started",
                "fixture_preserved",
                "cleanup_deferred_reason",
                "invocation_failure",
                "preservation_suspension",
                "postcondition_failures",
                "independent_capture_replay_complete",
                *FALSE_FLAGS,
            },
            "capture envelope changed",
        )
        _require(
            ("private_input_transfer_attempted" in capture)
            == ("private_measurement_inputs" in capture),
            "private retention envelope incomplete",
        )
        _require(
            capture["schema"] == SCHEMA
            and capture["authority"] == AUTHORITY
            and capture["status"] == "CAPTURED_BOUNDED_ATTEMPT"
            and capture["refusal"] is None
            and capture["cleanup_failure"] is None
            and capture["postcondition_failures"] == []
            and capture["fixture_creation_attempted"] is True
            and capture["invocation_started"] is True
            and capture["fixture_preserved"] is False
            and capture["cleanup_deferred_reason"] is None
            and capture["invocation_failure"] is None
            and capture["preservation_suspension"] is None
            and capture["independent_capture_replay_complete"] is False,
            "capture incomplete",
        )
        _false(capture)
        pin = _pin(capture["input_bundle_digest"])
        bound = inputs.inspect_common_attempt_inputs(
            read(pin, inputs.MAX_BUNDLE), expected_bundle_digest=pin
        )
        for input_pin, raw in bound["input_blobs"].items():
            _require(
                read(input_pin, inputs.MAX_BUNDLE) == raw, "input closure incomplete"
            )
        guest = capture["guest"]
        _require(
            set(guest)
            == {
                "schema",
                "authority",
                "status",
                "container_id",
                "input_bundle_digest",
                "attempt",
                "public_blobs",
                "export_failures",
                "refusal",
                "input_bundle_readback",
                "controller_sources",
                "controller_sources_after",
                "postcondition_failures",
                "recovery",
                "public_export_complete",
                "preserve_fixture_for_evidence",
                "interrupted",
                "limitations",
                *FALSE_FLAGS,
            },
            "guest envelope changed",
        )
        _require(
            len(canonical_json(guest)) <= MAX_GUEST
            and guest["schema"] == "aragorn/native-common-attempt-guest/v1"
            and guest["authority"]
            == "OWNED_ONCE_ATTEMPT_PUBLIC_EXPORT_NOT_PHASE3_QUALIFICATION"
            and guest["status"] == "EXPORTED_BOUNDED_ATTEMPT"
            and guest["container_id"] == capture["fixture_container"]
            and guest["input_bundle_digest"] == pin
            and guest["input_bundle_readback"] is True
            and guest["export_failures"] == guest["postcondition_failures"] == []
            and guest["refusal"] is None
            and guest["interrupted"] is False
            and guest["public_export_complete"] is True
            and guest["preserve_fixture_for_evidence"] is False,
            "guest export incomplete",
        )
        _false(guest)
        _require(
            guest["recovery"]["status"] == "NOT_REQUIRED"
            and guest["recovery"]["public_blob_attempts"]
            == guest["recovery"]["failures"]
            == []
            and guest["recovery"]["claim_metadata"] is None,
            "successful capture has partial recovery",
        )
        _require(
            capture["guest_recovery"] == guest["recovery"], "host recovery join changed"
        )
        for path in (inputs.WRAPPER_SOURCE, inputs.CONSUMER_SOURCE):
            base._readback(
                guest["controller_sources"][path], bound["source_raws"][path]
            )
        _require(
            set(guest["controller_sources"])
            == {inputs.WRAPPER_SOURCE, inputs.CONSUMER_SOURCE}
            and guest["controller_sources"] == guest["controller_sources_after"],
            "guest controller custody changed",
        )
        exported, roles = _public(capture, read)
        baseline, deployment = _attempt(
            guest["attempt"], bound, capture["fixture_container"], exported, roles, read
        )
        _private_retention_metadata(capture, read)
        _generated_driver(capture["generated_driver"], bound)
        base._outer(
            capture,
            bound,
            baseline,
            fixture_helpers=inputs.FIXTURE_HELPERS,
            name_prefix=NAME_PREFIX,
        )
        _require(
            capture["fixture_name"] == capture["cleanup"]["name"]
            and capture["fixture_owner"] == capture["cleanup"]["owner"],
            "fixture identity changed",
        )
        aliases = capture["fixture_aliases"]
        _require(set(aliases) == set(inputs.HELPER_ALIASES), "alias inventory changed")
        for target, path in inputs.HELPER_ALIASES.items():
            _require(
                aliases[target]
                == dict(capture["fixture_helpers"][path], installed_path=target),
                "alias source or mode changed",
            )
        return {
            "schema": "aragorn/native-common-attempt-public-replay/v1",
            "status": "BOUNDED_PUBLIC_ATTEMPT_CAPTURE_REPLAY_VERIFIED",
            "capture_digest": expected_capture_digest,
            "input_bundle_digest": pin,
            "deployment_digest": deployment,
            "retained_blob_digests": sorted(retained),
            "public_capture_joins_verified": True,
            "private_writer_semantics_replayed": False,
            "private_measurement_input_semantics_replayed": False,
            "independent_full_measurement_replay_complete": False,
            "limitations": [
                "RETAINED_CLAIMS_NOT_FRESH_EXECUTION_OR_SIGNATURE_ATTESTATION",
                "PUBLIC_BYTE_JOINS_NOT_PRIVATE_GRANT_OR_MEASUREMENT_SEMANTIC_REPLAY",
                "NO_ADMISSION_RUN_TIMING_OR_PHASE3_QUALIFICATION",
            ],
            **dict.fromkeys(FALSE_FLAGS, False),
        }
    except NativeCommonAttemptCaptureError:
        raise
    except Exception as error:
        raise NativeCommonAttemptCaptureError(
            "public attempt capture replay refused"
        ) from error
