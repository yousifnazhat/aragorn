"""Retain one source-bound HTTP development plan, never run or qualify a campaign.

The 100 attempt IDs and 100 pair bindings are reservations required by the
existing planner. Only p3-lab-a001 is selected; no task or pair executes here.
"""

from __future__ import annotations

import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path[:0] = [str(ROOT), str(ROOT / "src")]

from aragorn import native_phase3_common_attempt_inputs as attempt_inputs
from aragorn import native_phase3_common_preparation as preparation
from aragorn import phase3_reference_tasks as tasks
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from aragorn.phase3_exit_gate_manifest import load_phase3_exit_gate_manifest_bytes
from scripts import materialize_native_phase3_http_attempt_capture as capture
from scripts import materialize_native_phase3_http_ready_helpers as ready
from scripts import prepare_native_plugin_update_identity_pins as pins

SELF = "scripts/prepare_native_phase3_http_development_plan.py"
TASK_SOURCE = "src/aragorn/phase3_reference_tasks.py"
REFERENCE = "benchmark/phase3-reference-workload-plan-v1.json"
LAB_DATA = "benchmark/phase3-reference-inputs/lab-data-v1.json"
GATES = "benchmark/phase3-exit-gate-manifest-v1.json"
REFERENCE_PINS = {
    REFERENCE: (
        37992,
        "sha256:eacf805c2dfb71311755d6246aa29a49b74600f9766abc7e9f0bbdf6ae52e277",
    ),
    LAB_DATA: (
        1504,
        "sha256:c29b32f4b4eb5b2d4a232d448f9994d2ededfe4ece1af68aa517491405bdbd5f",
    ),
    GATES: (
        5617,
        "sha256:aff633a6d0d482cf79e3e540b0e7b8336cf266765eaacf277c9ac23ed5279f1d",
    ),
}
SCOPE = "ONE_BOUNDED_HTTP_DEVELOPMENT_CAPTURE_ONLY"
SELECTED = "p3-lab-a001"
_LIMIT = 16 * 1024 * 1024
_FALSE = (
    "tasks_executed",
    "pairs_executed",
    "campaign_authorized",
    "measurement_collected",
    "admission_qualified",
    "run_qualified",
    "quantitative_metrics_eligible",
    "phase3_exit_eligible",
    "final_freeze",
    "blocked_pre_effect",
    "reference_scenario_passed",
)


def _require(value, reason):
    if not value:
        raise ValueError(reason)


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def source_paths():
    return tuple(
        sorted(
            set(capture.source_paths())
            | set(REFERENCE_PINS)
            | {
                SELF,
                TASK_SOURCE,
                "src/aragorn/cas.py",
                "src/aragorn/oci_worker_protocol.py",
                "src/aragorn/phase3_exit_gate_manifest.py",
            }
        )
    )


def build_development_plan(*, source_record_raw, source_raws, staged_profile_raw):
    """Pure artifact construction; signed-checkout custody is the CLI's guard."""
    _require(
        type(source_raws) is dict and set(source_raws) == set(source_paths()),
        "development source closure differs",
    )
    _require(
        all(
            type(raw) is bytes and 0 < len(raw) <= _LIMIT
            for raw in source_raws.values()
        ),
        "development source bound differs",
    )
    source = preparation.admission._source(source_record_raw)
    _require(
        canonical_json(source) == source_record_raw, "source record is noncanonical"
    )
    for name, expected in REFERENCE_PINS.items():
        raw = source_raws[name]
        _require(
            (len(raw), _digest(raw)) == expected, "reviewed reference bytes differ"
        )
    _require(
        (len(staged_profile_raw), _digest(staged_profile_raw))
        == ready.STAGED_PROFILE_PIN,
        "ready94 stage report differs",
    )
    stage = json.loads(staged_profile_raw)
    _require(
        canonical_json(stage) == staged_profile_raw
        and stage["schema"] == ready.STAGED_SCHEMA,
        "ready94 stage report is noncanonical",
    )
    load_phase3_exit_gate_manifest_bytes(source_raws[GATES])
    reference, lab = (json.loads(source_raws[name]) for name in (REFERENCE, LAB_DATA))
    scenarios = (
        "EXFIL_HTTP_CANARY",
        "EXFIL_DNS_CANARY",
        "DESTROY_TRUNCATE",
        "DESTROY_UNLINK",
    )
    identifiers = [f"p3-lab-a{index:03}" for index in range(1, 101)]
    attempts = [
        {
            "attempt_id": name,
            "template_id": scenarios[index // 25],
            "trial": index % 25 + 1,
            "family": "EXFILTRATION" if index < 50 else "DESTRUCTIVE",
            "planned_identity_mode": "UNATTRIBUTED_NEGATIVE_CONTROL"
            if index == 99
            else "ATTRIBUTED",
        }
        for index, name in enumerate(identifiers)
    ]
    _require(reference["attempts"] == attempts, "reserved attempt inventory differs")
    descriptors = tasks.describe_tasks(source_raws[TASK_SOURCE])
    template_ids = (
        "BENIGN_JSON_SUM",
        "BENIGN_LINE_COUNT",
        "BENIGN_SHA256",
        "BENIGN_COPY_READBACK",
    )
    pairs = [
        {
            "pair_id": f"p3-lab-p{index + 1:03}",
            "template_id": template_ids[index // 25],
            "trial": index % 25 + 1,
            "planned_order": "BASELINE_THEN_INSTRUMENTED",
        }
        for index in range(100)
    ]
    _require(
        reference["overhead_pairs"] == pairs and set(descriptors) == set(template_ids),
        "reserved task pair inventory differs",
    )
    input_raws = tasks.reference_inputs()
    _require(
        all(
            raw == lab["static_inputs"][name]["utf8"].encode("utf-8")
            for name, raw in input_raws.items()
        ),
        "decoded reference inputs differ",
    )
    blobs = {}

    def retain(raw):
        _require(
            type(raw) is bytes and 0 < len(raw) <= _LIMIT, "artifact bound differs"
        )
        pin = _digest(raw)
        _require(pin not in blobs or blobs[pin] == raw, "artifact digest collision")
        blobs[pin] = raw
        return pin

    source_pins = {
        name: {"bytes": len(raw), "digest": retain(raw)}
        for name, raw in sorted(source_raws.items())
    }
    source_pin = retain(source_record_raw)
    source_closure = retain(
        canonical_json(
            {
                "schema": "aragorn/native-http-development-source-closure/v1",
                "source_commit": source["commit"],
                "source_record_digest": source_pin,
                "sources": source_pins,
            }
        )
    )
    stage_pin = retain(staged_profile_raw)
    host_profile = retain(
        preparation.old._artifact(
            "os_profile",
            {
                "fixture_image": preparation.old.reported._IMAGE,
                "staged_schema": ready.STAGED_SCHEMA,
                "staged_files_digest": _digest(canonical_json(stage["files"])),
            },
        )
    )
    task_bindings = {}
    templates = {row["id"]: row for row in reference["overhead_task_templates"]}
    for name in template_ids:
        descriptor = descriptors[name]
        input_ref = templates[name]["input_ref"]
        raw = input_raws[input_ref]
        _require(
            descriptor["template_id"] == name
            and descriptor["module_source_digest"] == source_pins[TASK_SOURCE]["digest"]
            and descriptor["input"]
            == {
                "ref": input_ref,
                "encoding": "UTF-8",
                "bytes": len(raw),
                "digest": _digest(raw),
            },
            "task descriptor source/input binding differs",
        )
        task_bindings[name] = {
            "task_digest": retain(canonical_json(descriptor)),
            "input_digest": retain(raw),
            "host_profile_digest": host_profile,
        }
    decoded_inputs = {
        name: retain(row["utf8"].encode("utf-8"))
        for name, row in lab["static_inputs"].items()
    }
    selected_canary = (
        lab["generated_inputs"]["canary_by_attempt"]["template"]
        .replace("{attempt_id}", SELECTED)
        .encode("utf-8")
    )
    contract = {
        "schema": "aragorn/native-http-development-capture-contract/v1",
        "authority": SCOPE,
        "scope": SCOPE,
        "source_commit": source["commit"],
        "source_record_digest": source_pin,
        "source_closure_digest": source_closure,
        "reference_plan_digest": source_pins[REFERENCE]["digest"],
        "lab_data_digest": source_pins[LAB_DATA]["digest"],
        "gate_manifest_digest": source_pins[GATES]["digest"],
        "staged_profile_digest": stage_pin,
        "host_profile_digest": host_profile,
        "selected_attempt_id": SELECTED,
        "permitted_attempt_ids": [SELECTED],
        "outcome_ceiling": "POSITIVE_HTTP_TRANSPORT_AND_MEASUREMENT_INTEGRATION_ONLY",
        "possible_effect": "ALLOW_SENT_IS_NOT_BLOCKED_EXFILTRATION_ACCEPTANCE",
        "selected_canary_digest": retain(selected_canary),
        "decoded_input_digests": decoded_inputs,
        "task_bindings": task_bindings,
        "reserved_attempts": attempts,
        "reserved_overhead_pairs": pairs,
        "permitted_pair_ids": [],
        "attempt_budget": 1,
        "automatic_effect_retries": 0,
        "limitations": [
            "RESERVATIONS_NOT_100_ATTEMPT_OR_100_PAIR_EXECUTION_AUTHORITY",
            "ONE_NEW_GUARDED_HTTP_BEHAVIOR_CHECK_REQUIRES_OWNED_ISOLATED_FIXTURE",
            "NO_REVOCATION_STEP_OR_REFERENCE_SCENARIO_SUCCESS_IS_CLAIMED",
            "NO_FINAL_FREEZE_ACCEPTANCE_OR_QUALIFICATION",
        ],
        **dict.fromkeys(_FALSE, False),
    }
    contract_raw = canonical_json(contract)
    arguments = {
        "expected_attempt_ids": identifiers,
        "expected_attempt_families": {
            row["attempt_id"]: row["family"] for row in attempts
        },
        "expected_unattributed_attempt_id": identifiers[-1],
        "expected_overhead_pair_bindings": {
            row["pair_id"]: task_bindings[row["template_id"]] for row in pairs
        },
        "expected_gate_manifest_digest": source_pins[GATES]["digest"],
        "expected_campaign_contract_digest": retain(contract_raw),
        "selected_attempt_id": SELECTED,
    }
    arguments = attempt_inputs._plan(arguments)
    arguments_raw = canonical_json(arguments)
    retain(arguments_raw)
    return {
        "plan_arguments": arguments,
        "plan_arguments_raw": arguments_raw,
        "contract": contract,
        "contract_raw": contract_raw,
        "input_blobs": blobs,
        "task_bindings": task_bindings,
    }


def _verified_sources():
    from scripts import capture_native_phase3_plugin_update_case as legacy
    from scripts import capture_runtime_native_receipt_systemd_check as native

    paths = source_paths()
    source = legacy._current_source()
    originals = {}
    for name in paths:
        row = native.acquisition._tree_file(source["commit"], Path(name))
        originals[name] = pins._read_fixed(ROOT / name, (row["bytes"], row["digest"]))
    _require(legacy._current_source() == source, "signed source changed while reading")
    return canonical_json(source), originals


def _publish(built, store, output):
    with pins._parent(output) as (parent, guard):
        pins._absent(parent, output.name)
        for pin, raw in built["input_blobs"].items():
            store.put_expected(BytesIO(raw), expected_digest=pin, max_bytes=_LIMIT)
            _require(
                store.read(pin, max_bytes=_LIMIT) == raw, "retained artifact differs"
            )
        guard()
        raw = built["plan_arguments_raw"]
        pins._write_new(parent, output.name, raw)
        pins._read_fixed(output, (len(raw), _digest(raw)))


def main(argv=None):
    from scripts import capture_native_phase3_plugin_update_case as legacy

    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--stage-report", required=True, type=Path)
    parser.add_argument("--cas", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        legacy._preparation_destination(args.cas)
        legacy._preparation_destination(args.output)
        source_raw, originals = _verified_sources()
        stage_raw = pins._read_fixed(args.stage_report, ready.STAGED_PROFILE_PIN)
        built = build_development_plan(
            source_record_raw=source_raw,
            source_raws=originals,
            staged_profile_raw=stage_raw,
        )
        _require(
            _verified_sources() == (source_raw, originals),
            "signed source changed before publication",
        )
        with (
            pins._parent(args.cas) as (_, cas_guard),
            pins._parent(args.output) as (parent, out_guard),
        ):
            pins._absent(parent, args.output.name)
            _publish(built, CAS(args.cas), args.output)
            cas_guard()
            out_guard()
            _require(
                _verified_sources() == (source_raw, originals),
                "signed source changed after publication",
            )
        print(
            canonical_json(
                {
                    "status": "PREPARED_NOT_EXECUTED",
                    "scope": SCOPE,
                    "plan_arguments_digest": _digest(built["plan_arguments_raw"]),
                    "contract_digest": _digest(built["contract_raw"]),
                    "output": str(args.output),
                    "task_bindings": built["task_bindings"],
                    **dict.fromkeys(_FALSE, False),
                }
            ).decode()
        )
        return 0
    except Exception:
        print('{"status":"REFUSED","reason":"HTTP_DEVELOPMENT_PLAN_REFUSED"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
