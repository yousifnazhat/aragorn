"""Pure public inputs for one owned common attempt, never execution authority.

The original setup bundle remains byte-for-byte nested. The caller supplies the
real complete plan inventory; only its public shape is checked here. The actual
seven-writer planner must bind the real deployment, boot and protected inode.
No controller, probe, clock or filesystem observer is imported or invoked.
"""

from __future__ import annotations

import json

from . import native_phase3_common_setup_capture as base
from . import phase3_quantitative_metrics as metrics
from .oci_worker_protocol import canonical_json

BUNDLE_PATH = "/opt/aragorn/native-common-attempt-inputs.json"
BUNDLE_SCHEMA = "aragorn/native-common-attempt-inputs/v1"
BUNDLE_AUTHORITY = (
    "PUBLIC_ATTEMPT_EXPECTATIONS_NOT_EXECUTION_OR_QUALIFICATION_AUTHORITY"
)
MAX_BUNDLE = 16 * 1024 * 1024
MAX_PLAN = 128 * 1024
MAX_SOURCE = 1024 * 1024
HOST_SOURCE = "scripts/capture_native_phase3_common_attempt.py"
WRAPPER_SOURCE = "scripts/runtime_native_common_attempt_capture.py"
CONSUMER_SOURCE = "src/aragorn/native_phase3_common_attempt_inputs.py"
CAPTURE_CONSUMER_SOURCE = "src/aragorn/native_phase3_common_attempt_capture.py"
ATTEMPT_SOURCE = "scripts/runtime_native_common_attempt.py"
STAGER_SOURCE = base.STAGER_SOURCE
DRIVER_MATERIALIZER_SOURCE = (
    "scripts/materialize_runtime_native_blocked_create_driver.py"
)
DRIVER_SOURCE_PATHS = (
    DRIVER_MATERIALIZER_SOURCE,
    "scripts/materialize_protected_install_quarantine_producers.py",
    "benchmark/admission/openclaw-v2026.7.1/native-receipt-read-create-driver-v1.mjs",
    "benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs",
)
GENERATED_FILES = {
    "/opt/aragorn/native-blocked-create-driver-v1.mjs": {
        "bytes": 16293,
        "digest": "sha256:e898ba4ab7b5cbd8742bc36c8e1ae578c7e73f45280aa660afc5815fec386df4",
        "mode": "0444",
    },
}

_SCRIPT_NAMES = (
    "runtime_native_common_attempt",
    "runtime_native_common_attempt_plan",
    "runtime_native_common_measurement_handoff",
    "runtime_native_blocked_create_workload",
    "runtime_native_blocked_create_revocation",
    "runtime_native_measurement_evidence_snapshot",
    "runtime_native_common_attempt_capture",
)
_MODULE_NAMES = (
    "native_phase3_common_attempt_inputs",
    "native_phase3_denied_create_sink",
    "native_phase3_clock_domain",
    "native_phase3_clock_domain_verify",
    "native_phase3_blocked_create_verify",
    "native_phase3_ingress_interval_verify",
    "runtime_worker_ingress_verify",
    "runtime_broker_effective_receipt_verify",
    "runtime_broker_measurement_plan",
    "phase3_measurement_collector",
)
EXTRA_HELPERS = {
    **{f"scripts/{name}.py": f"/opt/aragorn/{name}.py" for name in _SCRIPT_NAMES},
    **{
        f"src/aragorn/{name}.py": f"/usr/lib/aragorn/aragorn/{name}.py"
        for name in _MODULE_NAMES
    },
}
# The frozen bootstrap requires the hyphenated name, while the standalone common
# observer imports the underscore spelling. Install the exact same pinned bytes
# at both explicit destinations; never rename or replace the old bootstrap.
HELPER_ALIASES = {
    "/opt/aragorn/runtime_native_receipt_systemd_check.py": "scripts/runtime_native_receipt_systemd_check.py",
}
FIXTURE_HELPERS = base.FIXTURE_HELPERS | EXTRA_HELPERS
EXTRA_SOURCE_PATHS = tuple(
    sorted(
        (
            set(EXTRA_HELPERS)
            | {HOST_SOURCE, CAPTURE_CONSUMER_SOURCE}
            | set(DRIVER_SOURCE_PATHS)
        )
        - set(base.SOURCE_PATHS)
    )
)
SOURCE_PATHS = tuple(sorted(set(base.SOURCE_PATHS) | set(EXTRA_SOURCE_PATHS)))

# A data-only mirror of the fixed guest controller's checked inventory. Focused
# inert tests compare it to the controller; importing it here would cross the
# public contract's no-producer boundary.
ATTEMPT_SOURCE_PATHS = (
    "/opt/aragorn/runtime_native_common_attempt.py",
    "/opt/aragorn/runtime_native_common_case_setup.py",
    "/opt/aragorn/runtime_native_common_attempt_plan.py",
    "/opt/aragorn/runtime_native_common_measurement_handoff.py",
    "/opt/aragorn/runtime_native_blocked_create_workload.py",
    "/opt/aragorn/runtime_native_blocked_create_revocation.py",
    "/usr/lib/aragorn/aragorn/native_phase3_denied_create_sink.py",
    "/opt/aragorn/runtime_native_measurement_evidence_snapshot.py",
    "/opt/aragorn/runtime_phase3_common_process_observer.py",
    "/usr/lib/aragorn/aragorn/native_phase3_common_identity.py",
    "/usr/lib/aragorn/aragorn/native_phase3_common_process_verifier.py",
    "/usr/lib/aragorn/aragorn/native_phase3_clock_domain.py",
    "/usr/lib/aragorn/aragorn/native_phase3_blocked_create_verify.py",
    "/usr/lib/aragorn/aragorn/native_phase3_ingress_interval_verify.py",
)
PLAN_ARGUMENTS = frozenset(
    {
        "expected_attempt_ids",
        "expected_attempt_families",
        "expected_unattributed_attempt_id",
        "expected_overhead_pair_bindings",
        "expected_gate_manifest_digest",
        "expected_campaign_contract_digest",
        "selected_attempt_id",
    }
)
FALSE_FLAGS = (
    "activation_performed",
    "request_published",
    "measurement_provisioned",
    "measurement_collected",
    "resumable",
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
LIMITATIONS = (
    "PUBLIC_INVENTORY_EXPECTATIONS_NOT_EXECUTED_100_ATTEMPT_OR_100_PAIR_CAMPAIGN",
    "ACTUAL_SEVEN_WRITER_PLANNER_REMAINS_DEPLOYMENT_AND_PLAN_SEMANTIC_AUTHORITY",
    "NESTED_SETUP_SOURCE_RECORD_REQUIRES_SEPARATE_SIGNED_HOST_SOURCE_CUSTODY",
    "SOURCE_BYTES_NOT_SIGNATURE_INSTALL_EXECUTION_OR_LOADED_CODE_ATTESTATION",
    "NO_ACTIVATION_RESUME_EFFECT_TIMING_ADMISSION_RUN_OR_PHASE3_AUTHORITY",
)


class NativeCommonAttemptInputsError(ValueError):
    """The fixed public input closure is incomplete or inconsistent."""


def _require(value, reason):
    if not value:
        raise NativeCommonAttemptInputsError(reason)


_digest = base._digest
_pin = base._pin


def _plan(value):
    _require(
        type(value) is dict and set(value) == PLAN_ARGUMENTS,
        "plan argument inventory changed",
    )
    raw = canonical_json(value)
    _require(0 < len(raw) <= MAX_PLAN, "plan argument bound changed")
    # Validate the original containers before JSON detaches them: a tuple must
    # not silently become a list, nor insertion order conceal unsorted pairs.
    identifiers = metrics._inventory(
        value["expected_attempt_ids"],
        expected=metrics.EXPECTED_ATTEMPTS,
        label="expected attempt IDs",
    )
    metrics._attempt_families(value["expected_attempt_families"], identifiers)
    metrics._overhead_pair_bindings(value["expected_overhead_pair_bindings"])
    negative = metrics._identifier(
        value["expected_unattributed_attempt_id"], "negative-control attempt ID"
    )
    selected = metrics._identifier(value["selected_attempt_id"], "selected attempt ID")
    _require(
        negative in identifiers and selected in identifiers and selected != negative,
        "selected attempt or negative-control inventory changed",
    )
    for key in ("expected_gate_manifest_digest", "expected_campaign_contract_digest"):
        metrics._digest(value[key], key)
    return json.loads(raw)


def prepare_common_attempt_inputs(
    *,
    setup_bundle_raw,
    expected_setup_bundle_digest,
    plan_arguments,
    source_raws,
):
    """Bind exact public bytes; no native preparation, writes or observations.

    ``source_raws`` contains exactly EXTRA_SOURCE_PATHS. Existing sources are
    recovered only from the pinned setup bundle; they cannot be overridden.
    """
    try:
        base_bound = base.inspect_common_setup_inputs(
            setup_bundle_raw, expected_bundle_digest=expected_setup_bundle_digest
        )
        plan = _plan(plan_arguments)
        _require(
            type(source_raws) is dict
            and set(source_raws) == set(EXTRA_SOURCE_PATHS)
            and not set(source_raws).intersection(base_bound["source_raws"]),
            "additional source inventory changed",
        )
        sources = base_bound["source_raws"] | source_raws
        _require(set(sources) == set(SOURCE_PATHS), "combined source inventory changed")
        retained = dict(base_bound["input_blobs"])
        texts = {}
        for path in EXTRA_SOURCE_PATHS:
            raw = source_raws[path]
            _require(
                type(raw) is bytes and 0 < len(raw) <= MAX_SOURCE,
                "additional source bound changed",
            )
            texts[path] = raw.decode("utf-8")
            retained[_digest(raw)] = raw
        targets = (
            list(FIXTURE_HELPERS.values())
            + list(HELPER_ALIASES)
            + list(GENERATED_FILES)
        )
        stage = json.loads(base_bound["stage_raw"])
        _require(
            len(targets) == len(set(targets))
            and all(path in sources for path in HELPER_ALIASES.values())
            and not set(targets).intersection(row["path"] for row in stage["files"])
            and BUNDLE_PATH not in targets
            and BUNDLE_PATH not in {row["path"] for row in stage["files"]},
            "helper/stage overlap",
        )
        target_sources = {target: source for source, target in FIXTURE_HELPERS.items()}
        _require(
            set(ATTEMPT_SOURCE_PATHS) <= set(target_sources),
            "attempt source install inventory incomplete",
        )
        bundle = {
            "schema": BUNDLE_SCHEMA,
            "authority": BUNDLE_AUTHORITY,
            "base_setup_bundle": setup_bundle_raw.decode("utf-8"),
            "base_setup_bundle_digest": base_bound["bundle_digest"],
            "plan_arguments": plan,
            "sources": texts,
            "decision": dict.fromkeys(FALSE_FLAGS, False),
            "limitations": list(LIMITATIONS),
        }
        raw = canonical_json(bundle)
        _require(len(raw) <= MAX_BUNDLE, "attempt input bundle too large")
        pin = _digest(raw)
        retained[pin] = raw
        common = {
            key: value
            for key, value in base_bound["setup_arguments"].items()
            if key != "expected_setup_digest"
        }
        return {
            "bundle": bundle,
            "bundle_raw": raw,
            "bundle_digest": pin,
            "input_blobs": retained,
            "base_bound": base_bound,
            "source_raws": sources,
            "stage_raw": base_bound["stage_raw"],
            "source_raw": base_bound["source_raw"],
            "common_arguments": common,
            "plan_arguments": plan,
            "expected_setup_digest": base_bound["setup_arguments"][
                "expected_setup_digest"
            ],
            "expected_source_digests": {
                path: _digest(sources[target_sources[path]])
                for path in ATTEMPT_SOURCE_PATHS
            },
        }
    except NativeCommonAttemptInputsError:
        raise
    except Exception as exc:
        raise NativeCommonAttemptInputsError(
            "public attempt input preparation refused"
        ) from exc


def inspect_common_attempt_inputs(bundle_raw, *, expected_bundle_digest):
    """Reconstruct the same closure, rejecting any altered or extra fields."""
    try:
        _require(
            type(bundle_raw) is bytes
            and 0 < len(bundle_raw) <= MAX_BUNDLE
            and _digest(bundle_raw) == _pin(expected_bundle_digest),
            "attempt bundle differs from caller pin",
        )
        value = json.loads(bundle_raw)
        _require(
            type(value) is dict and canonical_json(value) == bundle_raw,
            "noncanonical attempt bundle",
        )
        built = prepare_common_attempt_inputs(
            setup_bundle_raw=value["base_setup_bundle"].encode("utf-8"),
            expected_setup_bundle_digest=value["base_setup_bundle_digest"],
            plan_arguments=value["plan_arguments"],
            source_raws={
                path: raw.encode("utf-8") for path, raw in value["sources"].items()
            },
        )
        _require(built["bundle_raw"] == bundle_raw, "attempt bundle contract changed")
        return built
    except NativeCommonAttemptInputsError:
        raise
    except Exception as exc:
        raise NativeCommonAttemptInputsError(
            "public attempt input inspection refused"
        ) from exc
