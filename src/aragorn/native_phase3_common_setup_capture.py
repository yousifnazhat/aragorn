"""Pure public setup inputs and retained-report joins, never private writer replay.

No controller or probe is imported. Source signature, execution, file custody and
cleanup are retained claims; the verifier checks their consistency, not their
external truth. Raw seven-writer credentials are deliberately outside this API.
"""

from __future__ import annotations

import hashlib
import json
import re

from . import native_phase3_common_preparation as preparation
from . import native_phase3_plugin_update_live_binding as live
from . import native_phase3_plugin_update_binding as reported
from .cas import CAS
from .oci_worker_protocol import canonical_json
from .phase3_deployment import build_phase3_deployment_identity

BUNDLE_PATH = "/opt/aragorn/native-common-setup-inputs.json"
MAX_BUNDLE = 8 * 1024 * 1024
MAX_RESULT = 48 * 1024 * 1024
MAX_CAPTURE = 64 * 1024 * 1024
MAX_PUBLIC_BLOBS = 32
MAX_PUBLIC_BLOB = 1024 * 1024
MAX_PUBLIC_TOTAL = 8 * 1024 * 1024
BUNDLE_SCHEMA = "aragorn/native-common-setup-inputs/v1"
BUNDLE_AUTHORITY = "PUBLIC_SETUP_EXPECTATIONS_NOT_ACTIVATION_OR_RESUME_AUTHORITY"
CAPTURE_SCHEMA = "aragorn/native-common-setup-capture/v1"
CAPTURE_AUTHORITY = "OWNED_COMMON_SETUP_CAPTURE_NOT_ACTIVATION_OR_QUALIFICATION"
GUEST_SCHEMA = "aragorn/native-common-setup-guest/v1"
GUEST_AUTHORITY = "OWNED_SETUP_ONLY_PUBLIC_EXPORT_NOT_PRIVATE_WRITER_REPLAY"
GUEST_LIMITATIONS = (
    "SETUP_ONLY_NOT_ACTIVATION_OR_RESUME_AUTHORITY",
    "PUBLIC_JOURNAL_EXPORT_NOT_INDEPENDENT_PRIVATE_WRITER_REPLAY",
    "ROOT_GUEST_READBACK_NOT_HOST_OR_LOADED_CODE_ATTESTATION",
    "NO_CAS_ENUMERATION_OR_UNJOURNALED_BLOB_EXPORT",
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
)
HOST_SOURCE = "scripts/capture_native_phase3_common_setup.py"
SETUP_SOURCE = "scripts/runtime_native_common_case_setup.py"
WRAPPER_SOURCE = "scripts/runtime_native_common_setup_capture.py"
CONSUMER_SOURCE = "src/aragorn/native_phase3_common_setup_capture.py"
STAGER_SOURCE = "scripts/stage_runtime_phase3_ingress_profile.py"
_SCRIPT_NAMES = (
    "runtime_response_systemd_check",
    "runtime_endpoint_journal_systemd_check",
    "runtime_native_health_systemd_check",
    "runtime_native_cgroup_prerequisite",
    "runtime_native_plugin_update_check",
    "runtime_native_plugin_package_check",
    "runtime_native_plugin_update_identity_check",
    "runtime_native_plugin_update_case",
    "runtime_native_admission_case",
    "runtime_native_admission_direct_write",
    "runtime_native_admission_path_mutation",
)
_MODULE_NAMES = (
    "native_phase3_live_identity",
    "native_phase3_plugin_update_binding",
    "native_phase3_plugin_update_live_binding",
    "native_phase3_plugin_update_case",
    "native_phase3_admission_case",
    "native_phase3_admission_direct_write",
    "native_phase3_admission_path_mutation",
    "runtime_broker_decision_measurement_verify",
    "native_phase3_common_setup_capture",
)
IMPLEMENTATION_PATHS = {
    name: "/usr/lib/aragorn/" + name.removeprefix("src/")
    if name.startswith("src/")
    else "/opt/aragorn/" + name.rsplit("/", 1)[1]
    for name in preparation.IMPLEMENTATION_SOURCE_PATHS
}
FIXTURE_HELPERS = {
    **{f"scripts/{name}.py": f"/opt/aragorn/{name}.py" for name in _SCRIPT_NAMES},
    **{
        f"src/aragorn/{name}.py": f"/usr/lib/aragorn/aragorn/{name}.py"
        for name in _MODULE_NAMES
    },
    "scripts/runtime_quarantine_systemd_check.py": "/opt/aragorn/runtime-quarantine-systemd-check.py",
    "scripts/runtime_native_receipt_systemd_check.py": "/opt/aragorn/runtime-native-receipt-systemd-check.py",
    "benchmark/admission/openclaw-v2026.7.1/native-receipt-read-create-driver-v1.mjs": "/opt/aragorn/native-receipt-read-create-driver-v1.mjs",
    **IMPLEMENTATION_PATHS,
    SETUP_SOURCE: "/opt/aragorn/runtime_native_common_case_setup.py",
    WRAPPER_SOURCE: "/opt/aragorn/runtime_native_common_setup_capture.py",
}
SOURCE_PATHS = tuple(sorted(set(FIXTURE_HELPERS) | {HOST_SOURCE, STAGER_SOURCE}))
_SETUP_LIMITATIONS = (
    "SETUP_ONLY_CHECKPOINT_NOT_RESUMABLE_AUTHORITY",
    "OWNING_HOST_MUST_RETAIN_EVIDENCE_AND_DESTROY_DISPOSABLE_FIXTURE",
    "NO_MEASUREMENT_BINDING_REQUEST_WORKLOAD_OR_ACTIVATION",
    "LOCAL_SOURCE_AND_WRITER_READBACKS_NOT_LOADED_CODE_OR_SIGNED_HOST_ATTESTATION",
)
LIMITATIONS = (
    "RETAINED_PUBLIC_REPORT_JOINS_NOT_SIGNATURE_EXECUTION_OR_LOADED_CODE_ATTESTATION",
    "SEVEN_WRITER_DIGEST_AND_METADATA_JOINS_NOT_PRIVATE_WRITER_SEMANTIC_REPLAY",
    "REPORTED_SOURCE_CUSTODY_NONACTIVATION_ISOLATION_AND_CLEANUP_NOT_FRESH_OBSERVATIONS",
    "NO_ACTIVATION_RESUME_REQUEST_MEASUREMENT_PERFORMANCE_OR_PHASE3_AUTHORITY",
)


class NativeCommonSetupCaptureError(ValueError):
    """A public input or successful retained setup does not close exactly."""


def _require(value: bool, reason: str) -> None:
    if not value:
        raise NativeCommonSetupCaptureError(reason)


_digest = preparation.old._digest
_pin = preparation.old._pin


def _parse(raw, limit=MAX_PUBLIC_BLOB, *, newline=False):
    _require(type(raw) is bytes and 0 < len(raw) <= limit, "unbounded public bytes")
    value = json.loads(raw)
    _require(
        type(value) is dict
        and canonical_json(value) + (b"\n" if newline else b"") == raw,
        "noncanonical public document",
    )
    return value


def _false(value, flags=FALSE_FLAGS):
    _require(
        type(value) is dict and all(value.get(key) is False for key in flags),
        "setup qualification ceiling changed",
    )


def prepare_common_setup_inputs(
    *,
    case_id,
    nonce,
    source_record_raw,
    implementation_source_raws,
    static_pin_manifest_raw,
    staged_profile_raw,
    baseline_capture_raw,
    setup_source_raw,
    wrapper_source_raw,
    host_source_raw,
    source_raws,
):
    """Build only public input bytes; no CAS publication or native operation."""
    try:
        _require(
            type(case_id) is str and case_id in preparation.CASE_BRANCHES,
            "unsupported common case",
        )
        _require(
            type(nonce) is str and re.fullmatch(r"[0-9a-f]{64}", nonce) is not None,
            "invalid nonce",
        )
        preparation.admission._source(source_record_raw)
        baseline, _ = preparation.admission._baseline(baseline_capture_raw)
        stage = preparation._stage(staged_profile_raw, baseline)
        preparation._static(static_pin_manifest_raw, stage, baseline)
        _require(
            type(source_raws) is dict and set(source_raws) == set(SOURCE_PATHS),
            "source inventory changed",
        )
        _require(
            type(implementation_source_raws) is dict
            and set(implementation_source_raws) == set(IMPLEMENTATION_PATHS),
            "implementation inventory changed",
        )
        _require(
            all(
                source_raws[path] == raw
                for path, raw in implementation_source_raws.items()
            ),
            "implementation source differs",
        )
        _require(
            all(
                source_raws[path] == raw
                for path, raw in (
                    (SETUP_SOURCE, setup_source_raw),
                    (WRAPPER_SOURCE, wrapper_source_raw),
                    (HOST_SOURCE, host_source_raw),
                )
            ),
            "controller source differs",
        )
        retained = {}

        def text(raw):
            _require(
                type(raw) is bytes and 0 < len(raw) <= MAX_PUBLIC_BLOB,
                "source/input bound changed",
            )
            retained[_digest(raw)] = raw
            return raw.decode("utf-8")

        bundle = {
            "schema": BUNDLE_SCHEMA,
            "authority": BUNDLE_AUTHORITY,
            "case_id": case_id,
            "nonce": nonce,
            "source_record": text(source_record_raw),
            "static_pin_manifest": text(static_pin_manifest_raw),
            "staged_profile": text(staged_profile_raw),
            "baseline_capture": text(baseline_capture_raw),
            "sources": {path: text(source_raws[path]) for path in SOURCE_PATHS},
            "decision": dict.fromkeys(FALSE_FLAGS, False),
        }
        destinations = {row["path"] for row in stage["files"]}
        _require(
            len(set(FIXTURE_HELPERS.values())) == len(FIXTURE_HELPERS)
            and not destinations.intersection(FIXTURE_HELPERS.values()),
            "helper/stage overlap",
        )
        raw = canonical_json(bundle)
        _require(len(raw) <= MAX_BUNDLE, "public input bundle too large")
        pin = _digest(raw)
        retained[pin] = raw
        return {
            "bundle": bundle,
            "bundle_raw": raw,
            "bundle_digest": pin,
            "input_blobs": retained,
        }
    except NativeCommonSetupCaptureError:
        raise
    except Exception as exc:
        raise NativeCommonSetupCaptureError("public input preparation refused") from exc


def inspect_common_setup_inputs(bundle_raw, *, expected_bundle_digest):
    """Reconstruct exact public inputs without filesystem access or publication."""
    try:
        _require(
            _digest(bundle_raw) == _pin(expected_bundle_digest),
            "bundle differs from caller pin",
        )
        value = _parse(bundle_raw, MAX_BUNDLE)
        sources = {path: raw.encode("utf-8") for path, raw in value["sources"].items()}
        arguments = {
            "case_id": value["case_id"],
            "nonce": value["nonce"],
            "source_record_raw": value["source_record"].encode("utf-8"),
            "implementation_source_raws": {
                path: sources[path] for path in IMPLEMENTATION_PATHS
            },
            "static_pin_manifest_raw": value["static_pin_manifest"].encode("utf-8"),
            "staged_profile_raw": value["staged_profile"].encode("utf-8"),
            "baseline_capture_raw": value["baseline_capture"].encode("utf-8"),
        }
        built = prepare_common_setup_inputs(
            **arguments,
            setup_source_raw=sources[SETUP_SOURCE],
            wrapper_source_raw=sources[WRAPPER_SOURCE],
            host_source_raw=sources[HOST_SOURCE],
            source_raws=sources,
        )
        _require(built["bundle_raw"] == bundle_raw, "bundle contract changed")
        return built | {
            "setup_arguments": arguments
            | {"expected_setup_digest": _digest(sources[SETUP_SOURCE])},
            "stage_raw": arguments["staged_profile_raw"],
            "source_raw": arguments["source_record_raw"],
            "source_raws": sources,
        }
    except NativeCommonSetupCaptureError:
        raise
    except Exception as exc:
        raise NativeCommonSetupCaptureError("public input inspection refused") from exc


def _public_preparation(setup, bound, exported, read):
    """Recompute only artifacts supported by public bytes, never seven secrets."""
    retained = setup["preparation"]
    _require(
        type(retained) is dict
        and set(retained)
        == {
            "preparation",
            "preparation_digest",
            "retained_blob_digests",
            "local_readback",
        }
        and retained["local_readback"] is True,
        "preparation retention incomplete",
    )
    pin = _pin(retained["preparation_digest"])
    raw = read(pin, 16384)
    value = _parse(raw, 16384)
    _require(
        canonical_json(retained["preparation"]) == raw,
        "preparation report differs from retained bytes",
    )
    args = bound["setup_arguments"]
    source = preparation.admission._source(args["source_record_raw"])
    baseline, original = preparation.admission._baseline(args["baseline_capture_raw"])
    stage = preparation._stage(args["staged_profile_raw"], baseline)
    static = preparation._static(args["static_pin_manifest_raw"], stage, baseline)
    pins = preparation.old._pins(
        value["provisioning_file_digests"], preparation.old.PROVISIONING_PATHS
    )
    source_pins = {
        path: _digest(raw) for path, raw in args["implementation_source_raws"].items()
    }
    adapters = {preparation.admission.UPDATE_CASE: original["adapter"]}
    for selected in (
        preparation.admission.DIRECT_WRITE_CASE,
        *preparation.admission.MUTATION_CASE_BRANCHES,
    ):
        paths = (
            preparation.admission.DIRECT_SOURCE_PATHS
            if selected == preparation.admission.DIRECT_WRITE_CASE
            else preparation.admission.CASE_SOURCE_PATHS
        )
        adapters[selected] = preparation.old._artifact(
            "adapter",
            {
                "route_id": selected,
                "branch": preparation.CASE_BRANCHES[selected],
                "probe_sources": {
                    path: {
                        "bytes": len(args["implementation_source_raws"][path]),
                        "digest": source_pins[path],
                    }
                    for path in paths
                },
            },
        )
    artifact_pins = value["artifact_digests"]
    worker_raw = read(artifact_pins["worker"], MAX_PUBLIC_BLOB)
    worker = _parse(worker_raw)["identity"]["binding"]
    _require(
        type(worker) is dict
        and set(worker)
        == {
            "schema",
            "runtime_digest",
            "active_skill_digest",
            "policy_digest",
            "policy_version",
        }
        and worker["schema"] == "aragorn/runtime-action-worker-binding/v1"
        and type(worker["policy_version"]) is int
        and 0 < worker["policy_version"] < 2**53,
        "public worker binding changed",
    )
    for key in ("runtime_digest", "active_skill_digest", "policy_digest"):
        _pin(worker[key])
    _require(
        _digest(canonical_json(worker)) == pins[live._WORKER]
        and worker["policy_digest"] == pins[live._POLICY]
        and pins[live._CONFIG] == preparation.old._CONFIG_PIN
        and worker["runtime_digest"] == reported._RUNTIME["tree_digest"]
        and worker["policy_version"] == 1,
        "public worker/configuration writer pins differ",
    )
    artifacts = original | {
        "configuration": preparation.old._artifact(
            "configuration", {"configuration_digest": pins[live._CONFIG]}
        ),
        "worker": preparation.old._artifact(
            "worker", {**preparation._worker_code(stage, static), "binding": worker}
        ),
        "policy": preparation.old._artifact(
            "policy", {"policy_digest": pins[live._POLICY]}
        ),
        "adapter": preparation.old._artifact(
            "adapter",
            {
                "implementation_source_digests": source_pins,
                "case_adapters": {
                    selected: {
                        "branch": preparation.CASE_BRANCHES[selected],
                        "artifact_digest": _digest(data),
                    }
                    for selected, data in adapters.items()
                },
            },
        ),
        "os_profile": preparation.old._artifact(
            "os_profile",
            {
                "fixture_image": reported._IMAGE,
                "staged_schema": preparation.STAGED_SCHEMA,
                "staged_files_digest": _digest(canonical_json(stage["files"])),
            },
        ),
        "aragorn_version": preparation.old._artifact(
            "aragorn_version",
            {
                "source_commit": source["commit"],
                "source_record_digest": _digest(args["source_record_raw"]),
            },
        ),
    }
    deployment = build_phase3_deployment_identity(
        {name: _digest(data) for name, data in artifacts.items()}
    )
    expected = {
        "schema": preparation.PREPARATION_SCHEMA,
        "authority": preparation.PREPARATION_AUTHORITY,
        "case_id": args["case_id"],
        "branch": preparation.CASE_BRANCHES[args["case_id"]],
        "nonce": args["nonce"],
        "container_id": setup["container_id"],
        "source_commit": source["commit"],
        "source_record_digest": _digest(args["source_record_raw"]),
        "implementation_source_digests": source_pins,
        "staged_profile_digest": _digest(args["staged_profile_raw"]),
        "static_pin_manifest_digest": _digest(args["static_pin_manifest_raw"]),
        "baseline_capture_digest": _digest(args["baseline_capture_raw"]),
        "case_adapter_digest": _digest(adapters[args["case_id"]]),
        "artifact_digests": deployment["bindings"],
        "deployment_digest": _digest(canonical_json(deployment)),
        "provisioning_file_digests": pins,
        "decision": dict.fromkeys(preparation._FALSE, False),
        "limitations": list(preparation._LIMITATIONS),
    }
    _require(
        canonical_json(expected) == raw, "public preparation contract or joins changed"
    )
    closure = {
        _digest(data): data
        for data in (
            args["source_record_raw"],
            args["static_pin_manifest_raw"],
            args["staged_profile_raw"],
            args["baseline_capture_raw"],
            *args["implementation_source_raws"].values(),
            *artifacts.values(),
            *adapters.values(),
            canonical_json(deployment),
            raw,
        )
    }
    _require(
        set(closure) == set(exported)
        and retained["retained_blob_digests"] == sorted(closure),
        "public preparation closure is not exact",
    )
    _require(
        not set(pins.values()).intersection(closure),
        "raw writer credential included in public closure",
    )
    for digest, data in closure.items():
        _require(
            read(digest, MAX_PUBLIC_BLOB) == exported[digest] == data,
            "public artifact differs from retained derivation",
        )
    return expected, baseline, stage


_OVERRIDE_PATHS = (
    "/usr/lib/aragorn/aragorn/runtime_action_worker.py",
    "/usr/lib/systemd/system/aragorn-runtime-action-worker.service",
    "/usr/libexec/aragorn/activate-runtime-action-worker-host.sh",
    "/usr/lib/systemd/system/aragorn-agent-gateway.service",
    "/usr/lib/aragorn/aragorn/runtime_action_broker.py",
    "/usr/lib/aragorn/aragorn/runtime_action_broker_v4.py",
    "/usr/lib/aragorn/aragorn/runtime_action_service_v5.py",
    "/usr/lib/systemd/system/aragorn-runtime-lineage-capability-action-broker.service",
    "/usr/libexec/aragorn/activate-runtime-capability-host.sh",
    "/usr/lib/aragorn/aragorn/runtime_broker_decision_measurement.py",
    "/usr/lib/aragorn/aragorn/phase3_deployment.py",
    "/usr/lib/aragorn/aragorn/phase3_quantitative_metrics.py",
    "/usr/lib/aragorn/aragorn/runtime_worker_ingress_measurement.py",
)
_UNITS = {
    "aragorn-agent-gateway.service": ("aragorn-agent-gateway", "aragorn-agent-gateway"),
    "aragorn-runtime-action-worker.service": ("aragorn-runtime", "aragorn-runtime"),
    "aragorn-runtime-lineage-capability-action-broker.service": (
        "aragorn-broker",
        "aragorn-runtime",
    ),
    "aragorn-runtime-lineage-capability-observation-publisher.service": (
        "aragorn-sensor",
        "aragorn-sensor",
    ),
}


def _readback(record, raw):
    live._metadata(record, owners={(0, 0)}, modes={0o444})
    _require(
        record["bytes"] == len(raw) and record["digest"] == _digest(raw),
        "reported source readback differs",
    )


def _setup_readbacks(setup, guest, bound, value, baseline, stage):
    sources = bound["source_raws"]
    expected = {
        target: sources[path] for path, target in IMPLEMENTATION_PATHS.items()
    } | {FIXTURE_HELPERS[SETUP_SOURCE]: sources[SETUP_SOURCE]}
    before, after = (
        setup["implementation_sources"],
        setup["implementation_sources_after"],
    )
    _require(
        type(before) is dict
        and set(before) == set(expected)
        and canonical_json(before) == canonical_json(after),
        "implementation source readbacks changed",
    )
    for path, raw in expected.items():
        _readback(before[path], raw)
    controllers = {WRAPPER_SOURCE, CONSUMER_SOURCE}
    before, after = guest["controller_sources"], guest["controller_sources_after"]
    _require(
        type(before) is dict
        and set(before) == controllers
        and canonical_json(before) == canonical_json(after),
        "wrapper/consumer source readbacks changed",
    )
    for path in controllers:
        _readback(before[path], sources[path])
    before, after = setup["installed_sources"], setup["installed_sources_after"]
    expected_paths = set(baseline["observation"]["installed_sources"]) | set(
        _OVERRIDE_PATHS
    )
    _require(
        type(before) is dict
        and set(before) == expected_paths
        and canonical_json(before) == canonical_json(after),
        "staged source readbacks changed",
    )
    files = {row["path"]: row for row in stage["files"]}
    driver = "/opt/aragorn/native-receipt-read-create-driver-v1.mjs"
    for path, record in before.items():
        if path == driver:
            _require(
                record
                == {
                    "bytes": 13884,
                    "digest": "sha256:a34452c8ef7ee1fa9257848759fdb7f3f045b93ac7bc0e59cc5727129b257cbc",
                },
                "driver readback changed",
            )
        else:
            row = files[path]
            live._metadata(record, owners={(0, 0)}, modes={int(row["mode"], 8)})
            _require(
                record["bytes"] == row["bytes"] and record["digest"] == row["digest"],
                "installed source differs from common74",
            )
    before, after = setup["writer_readback"], setup["writer_readback_after"]
    pins = value["provisioning_file_digests"]
    _require(
        type(before) is dict
        and set(before) == set(pins)
        and canonical_json(before) == canonical_json(after),
        "seven writer readbacks changed",
    )
    for path, record in before.items():
        owner = tuple(record["identity"][3:5]) if path == live._POLICY else (0, 0)
        if path == live._POLICY:
            _require(
                all(type(number) is int and 0 < number < 2**32 for number in owner),
                "reported policy account changed",
            )
        live._metadata(record, owners={owner}, modes={0o400})
        _require(
            record["digest"] == pins[path]
            and record["bytes"] <= preparation.old._MAX_INPUT,
            "seven writer digest/size differs",
        )
    _require(
        canonical_json(setup["setup_state"])
        == canonical_json(
            {
                "activation_count": 0,
                "pins_frozen_before_activation": True,
                "provisioning_file_digests": pins,
            }
        ),
        "reported setup chronology changed",
    )
    _require(
        setup["ingress_absent"]
        == {
            "path": "/var/lib/aragorn-runtime-worker-measurement",
            "status": "ABSENT",
            "created": False,
        }
        and setup["ingress_absent"]["created"] is False,
        "ingress absence not reported",
    )
    unused = setup["measurement_unused"]
    _require(
        set(unused) == {"status", "units", "reset_authorized", "activation_performed"}
        and unused["status"] == "MEASUREMENT_PATHS_ABSENT"
        and unused["reset_authorized"] is False
        and unused["activation_performed"] is False
        and set(unused["units"]) == set(_UNITS),
        "unused measurement report changed",
    )
    properties = {
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
        "ControlPID",
        "ControlGroup",
        "User",
        "Group",
        "KillMode",
        "Delegate",
        "Restart",
    }
    for unit, (user, group) in _UNITS.items():
        row = unused["units"][unit]
        state = row["unit"]
        path = "/docker/" + setup["container_id"] + "/system.slice/" + unit
        _require(
            set(row) == {"unit", "cgroup"}
            and set(state) == properties
            and state
            == {
                "Id": unit,
                "LoadState": "loaded",
                "ActiveState": "inactive",
                "SubState": "dead",
                "MainPID": "0",
                "ControlPID": "0",
                "ControlGroup": state["ControlGroup"],
                "User": user,
                "Group": group,
                "KillMode": "control-group",
                "Delegate": "no",
                "Restart": "no",
            }
            and state["ControlGroup"] in {"", path}
            and row["cgroup"]
            in ({"path": path, "status": "ABSENT"}, {"path": path, "status": "EMPTY"}),
            "preparation service state changed",
        )
    cleanup = setup["fixture_stack_cleanup"]
    _require(
        type(cleanup) is dict and set(cleanup) == set(_UNITS),
        "service cleanup incomplete",
    )
    for unit in _UNITS:
        _require(
            cleanup[unit]
            == {
                "Id": unit,
                "ActiveState": "inactive",
                "MainPID": "0",
                "ControlPID": "0",
            },
            "service cleanup not inactive",
        )


def _outer(
    capture,
    bound,
    baseline,
    *,
    fixture_helpers=FIXTURE_HELPERS,
    name_prefix="aragorn-native-common-setup-",
):
    """Shared retained ownership/isolation/cleanup joins, not execution proof."""
    _require(
        canonical_json(capture["source"]) == bound["source_raw"]
        and canonical_json(capture["staged_profile"]) == bound["stage_raw"],
        "source/stage differs from public bundle",
    )
    _require(
        capture["parent_identity"] == baseline["parent_identity"]
        and capture["build_observation"] == baseline["build_observation"],
        "fixed parent/build identity changed",
    )
    helpers = capture["fixture_helpers"]
    _require(
        type(helpers) is dict and set(helpers) == set(fixture_helpers),
        "copied helper inventory changed",
    )
    for path, target in fixture_helpers.items():
        row, raw = helpers[path], bound["source_raws"][path]
        blob = hashlib.sha1(
            b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
        ).hexdigest()
        _require(
            set(row)
            == {
                "path",
                "mode",
                "blob",
                "bytes",
                "digest",
                "installed_path",
                "installed_mode",
            }
            and row["path"] == path
            and row["mode"] == "100644"
            and row["blob"] == blob
            and type(row["bytes"]) is int
            and row["bytes"] == len(raw)
            and row["digest"] == _digest(raw)
            and row["installed_path"] == target
            and row["installed_mode"] == "0444",
            "copied source binding changed",
        )
    container, item, cleanup = (
        capture["fixture_container"],
        capture["container_inspect"],
        capture["cleanup"],
    )
    _require(
        type(container) is str and re.fullmatch(r"[0-9a-f]{64}", container) is not None,
        "invalid fixture container",
    )
    owner, name = cleanup["owner"], cleanup["name"]
    _require(
        type(owner) is str
        and re.fullmatch(r"[0-9a-f]{64}", owner) is not None
        and name == name_prefix + owner[:16]
        and cleanup["removed_id"] == container
        and cleanup["image"] == reported._IMAGE,
        "owned cleanup identity changed",
    )
    _require(
        all(
            cleanup[key] is True
            for key in (
                "container_name_absent",
                "removed_id_absent",
                "daemon_reachable",
            )
        )
        and cleanup["owned_container"]
        == {
            "id": container,
            "image": reported._IMAGE,
            "name": "/" + name,
            "owner": owner,
        },
        "owned cleanup not confirmed",
    )

    def owned(record):
        _require(
            record["Id"] == container
            and record["Name"] == "/" + name
            and record["Image"] == reported._IMAGE
            and record["Config"]["Labels"]["dev.aragorn.snapshot-owner"] == owner
            and record["Config"]["Labels"]["dev.aragorn.source-commit"]
            == capture["source"]["commit"],
            "fixture ownership changed",
        )

    owned(item)
    _require(
        item["Config"]["Image"] == capture["fixture_image"]["Id"] == reported._IMAGE,
        "fixture image changed",
    )
    expected = {
        "NetworkMode": "none",
        "Privileged": True,
        "CgroupnsMode": "host",
        "Binds": ["/sys/fs/cgroup:/sys/fs/cgroup:rw"],
        "Mounts": [
            {
                "Type": "volume",
                "Source": reported._VOLUME,
                "Target": "/runtime",
                "ReadOnly": True,
            }
        ],
        "Tmpfs": {
            path: "rw,nosuid,nodev,noexec,mode=755" for path in ("/run", "/run/lock")
        },
        "SecurityOpt": ["label=disable"],
        "IpcMode": "private",
        "UsernsMode": "",
        "Runtime": "runc",
    }
    _require(
        canonical_json({key: item["HostConfig"][key] for key in expected})
        == canonical_json(expected),
        "fixture isolation changed",
    )
    mounts = {row["Destination"]: row for row in item["Mounts"]}
    _require(
        len(mounts) == len(item["Mounts"]) == 2
        and set(mounts) == {"/runtime", "/sys/fs/cgroup"}
        and mounts["/runtime"]["Type"] == "volume"
        and mounts["/runtime"]["Name"] == reported._VOLUME
        and mounts["/runtime"]["RW"] is False
        and mounts["/sys/fs/cgroup"]["Type"] == "bind"
        and mounts["/sys/fs/cgroup"]["Source"] == "/sys/fs/cgroup"
        and mounts["/sys/fs/cgroup"]["RW"] is True,
        "fixture mount inventory changed",
    )
    before, after = capture["parent_before"], capture["parent_after"]
    _require(
        before["image_inspect"] == after["image_inspect"]
        and before["volume_inspect"] == after["volume_inspect"]
        and before["content"]["runtime_tree_before"]
        == after["content"]["runtime_tree_after"]
        and {
            key: row["content_base64"]
            for key, row in before["content"]["contract_files"].items()
        }
        == {
            key: row["content_base64"]
            for key, row in after["content"]["contract_files"].items()
        },
        "frozen parent changed",
    )
    _require(
        before["image_inspect"]["Id"] == capture["parent_identity"]["image_id"]
        and before["volume_inspect"]["Name"]
        == capture["parent_identity"]["runtime_volume"],
        "parent identity snapshot differs",
    )
    layers = before["image_inspect"]["RootFS"]["Layers"]
    image = capture["fixture_image"]
    _require(
        image["RootFS"]["Type"] == "layers"
        and image["RootFS"]["Layers"][: len(layers)] == layers
        and len(image["RootFS"]["Layers"]) > len(layers),
        "fixture parent layers changed",
    )
    for key in ("runtime_before", "runtime_after"):
        runtime = capture[key]
        _require(
            runtime["content"]["runtime_tree_before"]
            == runtime["content"]["runtime_tree_after"]
            == reported._RUNTIME
            and runtime["volume_inspect"]["Name"] == reported._VOLUME
            and runtime["running_users_before"] == runtime["running_users_after"] == [],
            "runtime snapshot changed",
        )
        mount = runtime["content"]["mount"]
        _require(
            mount["path"] == "/runtime"
            and mount["error"] is None
            and mount["read_only"] is True
            and len(mount["records"]) == 1
            and mount["records"][0]["root"]
            == f"/docker/volumes/{reported._VOLUME}/_data"
            and "ro" in mount["records"][0]["mount_options"]
            and "rw" not in mount["records"][0]["mount_options"],
            "runtime snapshot mount changed",
        )
    _require(
        capture["runtime_before"]["volume_inspect"]
        == capture["runtime_after"]["volume_inspect"],
        "runtime volume changed",
    )
    listing = ["container", "ls", "--all", "--no-trunc", "--filter"]
    by_name = [*listing, "name=^/" + name + "$", "--format", "{{.ID}}"]
    expected_commands = [
        by_name,
        ["container", "inspect", container],
        ["container", "rm", "--force", container],
        ["info", "--format", "{{.ServerVersion}}"],
        by_name,
        [*listing, "id=" + container, "--format", "{{.ID}}"],
    ]
    commands = cleanup["commands"]
    _require(
        type(commands) is list and len(commands) == len(expected_commands),
        "cleanup command inventory changed",
    )
    for command, argv in zip(commands, expected_commands, strict=True):
        _require(
            command["argv"] == reported._DOCKER + argv
            and type(command["exit_code"]) is int
            and command["exit_code"] == 0,
            "cleanup command changed",
        )
    _require(
        commands[0]["stdout"] == commands[2]["stdout"] == container + "\n"
        and commands[4]["stdout"] == commands[5]["stdout"] == "",
        "fixture removal not observed",
    )
    records = json.loads(
        commands[1]["stdout"],
        object_pairs_hook=reported._pairs,
        parse_constant=reported._constant,
    )
    _require(
        type(records) is list and len(records) == 1, "cleanup inspect inventory changed"
    )
    owned(records[0])


def verify_native_common_setup_capture(capture_raw, *, expected_capture_digest, store):
    """Replay a successful bounded public setup report, using only retained CAS.

    A normal return never means fresh execution, private-writer semantic replay,
    activation, resume authority, route qualification or performance eligibility.
    Refused/partial captures remain retainable but cannot pass this consumer.
    """
    try:
        _require(
            type(store) is CAS and store.read_only is True,
            "read-only evidence CAS required",
        )
        _require(
            type(capture_raw) is bytes
            and _digest(capture_raw) == _pin(expected_capture_digest),
            "capture differs from caller pin",
        )
        capture = _parse(capture_raw, MAX_CAPTURE, newline=True)
        retained = {}

        def read(pin, limit=MAX_PUBLIC_BLOB):
            pin = _pin(pin)
            raw = store.read(pin, max_bytes=limit)
            _require(
                type(raw) is bytes and 0 < len(raw) <= limit and _digest(raw) == pin,
                "retained public bytes changed",
            )
            _require(
                pin not in retained or retained[pin] == raw, "retained read changed"
            )
            retained[pin] = raw
            return raw

        _require(
            read(expected_capture_digest, MAX_CAPTURE) == capture_raw,
            "capture not retained",
        )
        keys = {
            "schema",
            "authority",
            "status",
            "input_bundle_digest",
            "source",
            "build_observation",
            "fixture_helpers",
            "fixture_image",
            "parent_identity",
            "parent_before",
            "parent_after",
            "runtime_before",
            "runtime_after",
            "fixture_container",
            "container_inspect",
            "staged_profile",
            "guest",
            "guest_publication",
            "cleanup",
            "cleanup_failure",
            "refusal",
            "fixture_creation_attempted",
            "postcondition_failures",
            "independent_capture_replay_complete",
            *FALSE_FLAGS,
        }
        _require(
            set(capture) == keys
            and capture["schema"] == CAPTURE_SCHEMA
            and capture["authority"] == CAPTURE_AUTHORITY
            and capture["status"] == "PREPARED_NOT_ACTIVATED"
            and capture["refusal"] is None
            and capture["cleanup_failure"] is None
            and capture["postcondition_failures"] == []
            and capture["fixture_creation_attempted"] is True
            and capture["independent_capture_replay_complete"] is False,
            "capture incomplete or contract changed",
        )
        _false(capture)
        bundle_pin = _pin(capture["input_bundle_digest"])
        bound = inspect_common_setup_inputs(
            read(bundle_pin, MAX_BUNDLE), expected_bundle_digest=bundle_pin
        )
        for pin, raw in bound["input_blobs"].items():
            _require(
                read(pin, MAX_BUNDLE if pin == bundle_pin else MAX_PUBLIC_BLOB) == raw,
                "input closure not retained",
            )
        guest = capture["guest"]
        guest_keys = {
            "schema",
            "authority",
            "status",
            "container_id",
            "input_bundle_digest",
            "setup",
            "public_blobs",
            "export_failures",
            "refusal",
            "input_bundle_readback",
            "limitations",
            "controller_sources",
            "controller_sources_after",
            "postcondition_failures",
            *FALSE_FLAGS,
        }
        _require(
            type(guest) is dict
            and set(guest) == guest_keys
            and len(canonical_json(guest)) <= MAX_RESULT
            and guest["schema"] == GUEST_SCHEMA
            and guest["authority"] == GUEST_AUTHORITY
            and guest["status"] == "PREPARED_NOT_ACTIVATED"
            and guest["container_id"] == capture["fixture_container"]
            and guest["input_bundle_digest"] == bundle_pin
            and guest["input_bundle_readback"] is True
            and guest["export_failures"] == []
            and guest["refusal"] is None
            and guest["postcondition_failures"] == []
            and guest["limitations"] == list(GUEST_LIMITATIONS),
            "guest setup/export incomplete",
        )
        _false(guest)
        setup = guest["setup"]
        setup_keys = {
            "schema",
            "authority",
            "status",
            "container_id",
            "setup_source_digest",
            "preparation",
            "public_blob_attempts",
            "installed_sources",
            "installed_sources_after",
            "implementation_sources",
            "implementation_sources_after",
            "measurement_unused",
            "ingress_absent",
            "writer_readback",
            "writer_readback_after",
            "setup_state",
            "fixture_stack_cleanup",
            "cleanup_failure",
            "postcondition_failures",
            "refusal",
            "limitations",
            *FALSE_FLAGS,
        }
        _require(
            type(setup) is dict
            and set(setup) == setup_keys
            and len(canonical_json(setup)) <= 2 * MAX_PUBLIC_BLOB
            and setup["schema"] == "aragorn/native-common-case-setup/v1"
            and setup["authority"]
            == "OWNED_SEVEN_WRITER_PREPARATION_ONLY_NOT_ACTIVATION_OR_RESUME_AUTHORITY"
            and setup["status"] == "PREPARED_NOT_ACTIVATED"
            and setup["container_id"] == capture["fixture_container"]
            and setup["setup_source_digest"]
            == _digest(bound["source_raws"][SETUP_SOURCE])
            and setup["cleanup_failure"] is None
            and setup["refusal"] is None
            and setup["postcondition_failures"] == []
            and setup["limitations"] == list(_SETUP_LIMITATIONS),
            "setup report incomplete",
        )
        _false(setup)
        journal, rows = setup["public_blob_attempts"], guest["public_blobs"]
        _require(
            type(journal) is list
            and type(rows) is list
            and 1 <= len(journal) == len(rows) <= MAX_PUBLIC_BLOBS,
            "public export journal incomplete",
        )
        exported = {}
        for attempt, row in zip(journal, rows, strict=True):
            _require(
                type(attempt) is dict
                and set(attempt) == {"digest", "bytes"}
                and type(row) is dict
                and set(row) == {"digest", "bytes", "text"}
                and type(row["text"]) is str
                and type(row["bytes"]) is int
                and type(attempt["bytes"]) is int
                and 0 < row["bytes"] <= MAX_PUBLIC_BLOB,
                "public export shape changed",
            )
            raw = row["text"].encode("utf-8")
            pin = _pin(row["digest"])
            _require(
                attempt == {"digest": pin, "bytes": len(raw)}
                and row["bytes"] == len(raw)
                and _digest(raw) == pin
                and pin not in exported
                and read(pin) == raw,
                "public export differs from journal/retention",
            )
            exported[pin] = raw
        _require(
            sum(map(len, exported.values())) <= MAX_PUBLIC_TOTAL
            and journal[-1]["digest"] == setup["preparation"]["preparation_digest"],
            "public export ordering/budget changed",
        )
        ordered = list(exported)
        _require(
            canonical_json(capture["guest_publication"])
            == canonical_json(
                {"attempted": ordered, "retained": ordered, "complete": True}
            ),
            "host publication incomplete",
        )
        value, baseline, stage = _public_preparation(setup, bound, exported, read)
        _setup_readbacks(setup, guest, bound, value, baseline, stage)
        _outer(capture, bound, baseline)
        for pin, raw in retained.items():
            _require(
                store.read(pin, max_bytes=len(raw)) == raw,
                "final retained public closure lost",
            )
        return {
            "schema": "aragorn/native-common-setup-capture-replay/v1",
            "authority": "RETAINED_PUBLIC_SETUP_JOINS_NOT_PRIVATE_WRITER_OR_EXECUTION_ATTESTATION",
            "status": "BOUNDED_PUBLIC_SETUP_REPLAY_VERIFIED",
            "capture_digest": expected_capture_digest,
            "input_bundle_digest": bundle_pin,
            "preparation_digest": setup["preparation"]["preparation_digest"],
            "deployment_digest": value["deployment_digest"],
            "case_id": value["case_id"],
            "independent_capture_replay_complete": True,
            "private_writer_semantics_replayed": False,
            "writer_semantics_independently_replayed": False,
            "signature_verified": False,
            "reported_policy_account_independently_verified": False,
            "public_blob_count": len(exported),
            "writer_digest_count": 7,
            "limitations": list(LIMITATIONS),
            **dict.fromkeys(FALSE_FLAGS, False),
        }
    except NativeCommonSetupCaptureError:
        raise
    except Exception as exc:
        raise NativeCommonSetupCaptureError("public setup replay refused") from exc
