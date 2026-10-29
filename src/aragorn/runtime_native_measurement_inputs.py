"""Read-only closure for installing one already-prepared native measurement plan.

This consumes the existing preparation contract; it does not create a schedule,
sample a clock, evaluate policy, execute callback code or manufacture workload
evidence. Actual installed identities, grant liveness, ownership and the fixed
protected path must be checked separately by the root provisioner.
"""

from __future__ import annotations

from . import runtime_broker_decision_measurement_verify as retained
from . import phase3_quantitative_metrics as metrics
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .runtime_action_broker import _TARGET_NAME
from .runtime_capability_grant import parse_runtime_capability_grant

_LIMIT = 1024 * 1024
_REPORT_LIMIT = 32768
_LIMITATIONS = [
    "OPERATOR_PINS_NOT_LIVE_DEPLOYMENT_OR_CLOCK_DOMAIN_ATTESTATION",
    "NO_GRANT_LIVENESS_CHECK_OR_RUNTIME_STATE_RESET",
    "REQUIRES_EXPLICIT_ROOT_CREDENTIAL_AND_BROKER_OWNED_INPUT_INSTALLATION",
    "RAW_PROFILED_SUBMISSION_MUST_BE_RETAINED_SEPARATELY_FOR_RECEIPT_VERIFICATION",
    "NO_UNATTRIBUTED_CONTROL_FULL_REQUEST_LATENCY_RESIDUE_OR_TASK_TIMING",
]


class NativeMeasurementInputError(ValueError):
    """The caller-pinned preparation does not close over one exact input set."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise NativeMeasurementInputError(reason)


def validate_prepared_native_measurement_inputs(
    *,
    prepared_raw: bytes,
    expected_prepared_digest: str,
    expected_binding_digest: str,
    expected_broker_source_pins: dict[str, str],
    source_cas: CAS,
) -> dict:
    """Resolve exact prepared bytes without writing to either input or runtime.

    Returned raw blobs are detached immutable bytes. A caller may install only
    this finite closure, never arbitrary extras supplied in an input manifest.
    The payload digest is a caller expectation, not retained payload content.
    A binding for the unattributed control is refused by this V4-only boundary.
    """
    try:
        return _validate(
            prepared_raw,
            expected_prepared_digest,
            expected_binding_digest,
            expected_broker_source_pins,
            source_cas,
        )
    except NativeMeasurementInputError:
        raise
    except Exception as error:
        raise NativeMeasurementInputError("prepared native inputs refused") from error


def _validate(raw, expected, binding_pin, source_pins, store):
    _require(isinstance(store, CAS) and store.read_only, "read-only source required")
    _require(
        type(raw) is bytes
        and 0 < len(raw) <= _REPORT_LIMIT
        and retained._digest(raw) == retained._pin(expected),
        "prepared report differs from caller pin",
    )
    prepared = retained._exact(
        retained._parse(raw, _REPORT_LIMIT),
        {
            "schema",
            "authority",
            "binding",
            "binding_digest",
            "input_blobs",
            "decision",
            "limitations",
        },
    )
    _require(
        prepared["schema"] == "aragorn/runtime-broker-measurement-prepared-inputs/v1"
        and prepared["authority"]
        == "CALLER_OWNED_INPUT_STAGING_ONLY_NOT_PROVISIONING_OR_MEASUREMENT"
        and prepared["limitations"] == _LIMITATIONS,
        "unsupported prepared-input authority",
    )
    decision = retained._exact(
        prepared["decision"],
        {
            "deployed",
            "measurement_collected",
            "quantitative_metrics_eligible",
            "phase3_exit_eligible",
        },
    )
    _require(
        all(value is False for value in decision.values()),
        "preparation exceeds authority",
    )
    binding_raw = canonical_json(prepared["binding"])
    binding = retained._binding(binding_raw, binding_pin)
    _require(
        prepared["binding_digest"] == binding_pin
        and type(source_pins) is dict
        and binding["source_pins"] == source_pins
        and binding["source_pins"]["phase3_quantitative_metrics.py"]
        == metrics.metrics_implementation_digest(),
        "binding differs from caller source pins",
    )
    blobs = {}

    def read(source: CAS, pin: str, limit: int = _LIMIT) -> bytes:
        _require(source is store and 0 < limit <= _LIMIT, "unexpected input reader")
        content = source.read(retained._pin(pin), max_bytes=limit)
        _require(
            type(content) is bytes
            and 0 < len(content) <= limit
            and retained._digest(content) == pin
            and (pin not in blobs or blobs[pin] == content),
            "prepared input bytes changed",
        )
        blobs[pin] = content
        return content

    scheduled = retained._scheduled_request(binding, read, store)
    _require(
        scheduled["negative_control"] is False, "unattributed attempt not supported"
    )
    commitment = retained._parse(blobs[binding["collection_commitment_digest"]], _LIMIT)
    callbacks = commitment["sources"]
    _require(
        callbacks["execute"]["module"] != callbacks["verify"]["module"]
        and callbacks["execute"]["path"] != callbacks["verify"]["path"]
        and all(value["path"].startswith("/") for value in callbacks.values()),
        "committed callbacks are not separated absolute source identities",
    )
    _require(
        read(store, binding["deployment_identity_digest"])
        == canonical_json(commitment["deployment"])
        and read(store, binding_pin, 4096) == binding_raw,
        "retained deployment or binding differs from prepared bytes",
    )
    grant = parse_runtime_capability_grant(read(store, binding["grant_digest"], 65536))
    _require(
        all(
            grant[key] == binding[key]
            for key in (
                "runtime_profile_digest",
                "sensor_digest",
                "runtime_digest",
                "policy_digest",
                "active_skill_digest",
                "operation_digest",
            )
        )
        and binding["operation_digest"]
        == canonical_digest(
            {"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}
        ),
        "prepared grant does not join the native create binding",
    )
    descriptor = retained._exact(
        retained._parse(read(store, binding["path_digest"], 4096), 4096),
        {"schema", "root_device", "root_inode", "target_name"},
    )
    _require(
        descriptor["schema"] == "aragorn/runtime-protected-path/v1"
        and type(descriptor["root_device"]) is int
        and 0 <= descriptor["root_device"] < 2**63
        and type(descriptor["root_inode"]) is int
        and 0 < descriptor["root_inode"] < 2**63
        and type(descriptor["target_name"]) is str
        and _TARGET_NAME.fullmatch(descriptor["target_name"]) is not None,
        "invalid native protected descriptor",
    )
    _require(1 <= len(blobs) <= 13, "unbounded prepared closure")
    _require(
        type(prepared["input_blobs"]) is list
        and canonical_json(prepared["input_blobs"])
        == canonical_json(
            [
                {"digest": pin, "bytes": len(content)}
                for pin, content in sorted(blobs.items())
            ]
        ),
        "prepared inventory has missing, extra or rebound bytes",
    )
    # Every semantically required blob is re-read; no manifest-only member is copied.
    for pin, content in blobs.items():
        _require(
            store.read(pin, max_bytes=len(content)) == content,
            "final source custody changed",
        )
    return {
        "binding": binding,
        "binding_raw": binding_raw,
        "prepared_digest": expected,
        "binding_digest": binding_pin,
        "input_blobs": dict(blobs),
        "grant": grant,
        "path_descriptor": descriptor,
        "scheduled_request": scheduled,
    }
