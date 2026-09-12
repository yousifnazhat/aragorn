"""Bind a fresh chat-session snapshot consumer observation; never qualify it."""

from __future__ import annotations

import binascii
import json
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn import (
    admission_openclaw_final_v3_chat_session_snapshot_subfixture as semantic,
)
from aragorn import (
    admission_protected_final_combined_v3_chat_session_snapshot_consumer as old,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_openclaw_final_v3_campaign_dispatch import (
    dispatch_openclaw_final_v3_campaign_case,
)
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import materialize_openclaw_final_v3_rebound_probes as materializer
from scripts import openclaw_final_v3_case_checks as checks

_ROOT = Path(__file__).resolve().parents[1]
_CASE = old._ROUTE
_STEM = "chat-session-snapshot-consumer"
_RECIPE = old._COLLECTOR_ARTIFACTS["capture_recipe"][2]
_MATERIALIZER = old._SOURCE_ARTIFACTS["rebound_materializer"][2]
_PROBE = "protected-chat-session-snapshot-consumer-v3-probe.mjs"
_PROVISIONAL_ROOT = "/campaign/cases/17-adm-02-reload-chat-session-snapshot-consumer"
_NATIVE_ROOT = "/route-input/chat-session-snapshot-consumer"
SOURCE_PATHS = tuple(
    sorted(
        {item[2] for item in old._SOURCE_ARTIFACTS.values()}
        | {item[2] for item in old._COLLECTOR_ARTIFACTS.values()}
    )
)
_SCHEMA = "aragorn/runtime-action-worker-final-combined-v3-chat-session-snapshot-consumer-systemd-observation/v1"
_AUTHORITY = "BOUND_FINAL_COMBINED_V3_RAW_CHAT_SESSION_SNAPSHOT_CONSUMER_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
_ADDED_LAYERS = [
    "sha256:197d97f99e6768639b6577f524f37c0eae1649e008d327bf02eb2b50013fd901",
    "sha256:fca38aa67c3fc9e8c03d483f672603997746053536a6e07adc6a59b59db62684",
    "sha256:158da5f1f9009c0d14119c52cc28e6dad24e782bbca99ebe8a37f1bd78328410",
    "sha256:0cf017f7ab5fbfa2b8f94d94e984b026a74c7be1e88666c8fd50d03ff9eec901",
]
_OUTER_DECISION = {
    "status": "FINAL_COMBINED_V3_CHAT_SESSION_SNAPSHOT_CONSUMER_OBSERVED_PROFILE_NOT_TESTED",
    "route_observation_status": "OBSERVED",
    "route_pass_count": 0,
    "route_fail_count": 0,
    "route_not_tested_count": 21,
    **{key: False for key in old.contract._ELIGIBILITY_KEYS},
}
# This older frozen route has equivalent composition helpers with different names.
_COMMON = SimpleNamespace(
    config=old.current,
    contract=old.contract,
    _RAW_LIMITATIONS=old._RAW_LIMITATIONS,
    _COMPOSITION_DECISION=old.v3_contract._COMPOSITION_DECISION,
    _verify_sources=old._verify_source_artifacts,
)


def _native_json(document: dict[str, Any]) -> bytes:
    """Preserve the fixed probe's compact sorted UTF-8 serialization and LF."""
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError("chat-session-snapshot campaign " + message)


def prepare_case(
    contract: dict[str, Any], request: dict[str, Any], *, directory: Path
) -> dict[str, Any]:
    """Reuse the frozen two-file materializer with an explicit native path mapping."""
    try:
        contract = campaign.validate_openclaw_final_v3_campaign_contract(contract)
        expected = campaign.build_openclaw_final_v3_subfixture_request(contract, _CASE)
        _expect(
            type(request) is dict and checks._same(request, expected), "request changed"
        )
        _expect(
            isinstance(directory, Path)
            and directory.is_dir()
            and not any(path.is_symlink() for path in (directory, *directory.parents)),
            "staging directory changed",
        )
        sources = checks.historical_sources(old._SOURCE, SOURCE_PATHS)
        descriptor = dispatch_openclaw_final_v3_campaign_case(_CASE)["descriptor"]
        files = [dict(item) for item in old._PROBE_BUNDLE]
        mapping = [
            {
                "provisional": _PROVISIONAL_ROOT + "/" + item["name"],
                "native": _NATIVE_ROOT + "/" + item["name"],
                "bytes": item["bytes"],
                "digest": item["digest"],
                "role": "probe" if item["name"] == _PROBE else "probe-dependency",
            }
            for item in files
        ]
        _expect(
            descriptor["materializer"] is None
            and descriptor["argv"]
            == ["/usr/local/bin/node", _PROVISIONAL_ROOT + "/" + _PROBE]
            and descriptor["bundle"]
            == [
                {"path": item["provisional"], "role": item["role"]} for item in mapping
            ],
            "historical descriptor changed",
        )
        bundle = directory / "bundle"
        manifest = materializer.materialize_openclaw_final_v3_rebound_case(
            _CASE, bundle
        )
        _expect(
            checks._same(
                manifest,
                {
                    "schema": "aragorn/openclaw-final-admission-v3-materialized-probe-bundle/v1",
                    "authority": "PINNED_V3_PROBE_BUNDLE_ONLY_NOT_EXECUTION_OR_QUALIFICATION_AUTHORITY",
                    "case_id": _CASE,
                    "files": files,
                },
            )
            and stat.S_IMODE(bundle.lstat().st_mode) == 0o555
            and {path.name for path in bundle.iterdir()}
            == {item["name"] for item in files},
            "native bundle changed",
        )
        for item in files:
            checks.bounded._read_file(
                bundle / item["name"], item["bytes"], item["digest"], mode=0o444
            )
        return {
            "schema": "aragorn/openclaw-final-v3-chat-session-snapshot-case-preparation/v1",
            "authority": "LOCAL_REQUEST_AND_BUNDLE_PREPARATION_NOT_EXECUTION_OR_QUALIFICATION_AUTHORITY",
            "contract": contract,
            "request": expected,
            "descriptor": descriptor,
            "source_files": sources,
            "bundle_files": files,
            "native_materializer": {
                "authority": "PINNED_NATIVE_RECIPE_TRANSFORMATION_NOT_DECLARED_DISPATCH_MATERIALIZER",
                "source": next(
                    item for item in sources if item["path"] == _MATERIALIZER
                ),
                "entrypoint": "materialize_openclaw_final_v3_rebound_case",
                "transform": "EXACT_V3_CONFIGURATION_AND_CHAT_ROUTE_SCHEMA_REPLACEMENT",
            },
            "path_mapping": {
                "authority": "EXPLICIT_HISTORICAL_NATIVE_PATH_MAPPING_NOT_LITERAL_DISPATCH_EXECUTION",
                "provisional_root": _PROVISIONAL_ROOT,
                "native_root": _NATIVE_ROOT,
                "literal_dispatch_argv_equality": False,
                "native_probe_argv": [
                    "/usr/local/bin/node",
                    _NATIVE_ROOT + "/" + _PROBE,
                ],
                "files": mapping,
            },
            "decision": checks._decision(
                "CHAT_SESSION_SNAPSHOT_REQUEST_AND_LOCAL_BUNDLE_PREPARED_NOT_EXECUTED"
            ),
        }
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        RuntimeError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid chat-session-snapshot preparation: {exc}"
        ) from exc


def _verify_composition(evidence: dict[str, Any], parent: dict[str, Any]) -> None:
    artifact = checks.verify_native_composition(
        evidence,
        parent,
        verifier=_COMMON,
        schema=_SCHEMA,
        authority=_AUTHORITY,
        artifact_key="final_combined_v3_chat_session_snapshot_consumer",
    )
    _expect(set(artifact) == set(old._ARTIFACT_DIGESTS), "artifact inventory changed")
    old._verify_collector_artifacts(artifact["collector"])
    old._verify_probe_artifact(artifact["chat_session_snapshot_consumer_probe"])
    checks.verify_native_lean_artifacts(artifact)


def verify_capture(
    raw: bytes,
    prepared: dict[str, Any],
    *,
    source: dict[str, Any],
    invocation: dict[str, Any],
) -> dict[str, Any]:
    """Verify native bytes and actual joins; caller owns live cleanup and retention."""
    try:
        with TemporaryDirectory(
            prefix="aragorn-chat-session-snapshot-case-recheck-"
        ) as temporary:
            expected = prepare_case(
                prepared["contract"],
                prepared["request"],
                directory=Path(temporary).resolve(),
            )
        _expect(checks._same(prepared, expected), "prepared binding changed")
        checks.verify_source(prepared, source)
        evidence = checks.det.semantic._load_canonical(
            raw, "chat-session-snapshot observation"
        )
        _expect(
            set(evidence)
            == {
                "authority",
                "composition",
                "decision",
                "harness",
                "limitations",
                "recorded_at",
                "route_id",
                "route_observation",
                "schema",
                "source_artifacts",
            }
            and set(evidence["harness"]) == {"digest", "document", "file"},
            "observation inventory changed",
        )
        checks._numeric_types(evidence)
        old.session.semantics._verify_scalar_types(evidence)
        old.current._verify_no_positive_eligibility(evidence)
        _expect(
            evidence["schema"] == _SCHEMA
            and evidence["authority"] == _AUTHORITY
            and evidence["route_id"] == _CASE
            and evidence["limitations"] == old._RAW_LIMITATIONS
            and checks._same(evidence["decision"], _OUTER_DECISION),
            "observation authority changed",
        )
        action = evidence["composition"]["action"]
        parent = prepared["request"]["frozen_parent"]["identity"]
        host = checks.verify_harness(
            evidence["harness"],
            action,
            source=source,
            parent=parent,
            stem=_STEM,
            image_id=old._IMAGE,
        )
        checks.verify_host(host, parent, stem=_STEM)
        _expect(
            host["image_lineage"]["added_layers"] == _ADDED_LAYERS,
            "child image layers changed",
        )
        _verify_composition(evidence, parent)
        route = evidence["route_observation"]
        _expect(
            set(route)
            == {
                "bundle",
                "document",
                "execution",
                "gateway_pid_binding",
                "raw",
                "route",
                "stack_before",
            }
            and set(route["raw"])
            == {
                "base64",
                "bytes",
                "canonical_digest",
                "digest",
                "raw_is_canonical_json_lf",
            },
            "route inventory changed",
        )
        document = checks.old._decode(route["raw"])
        _expect(
            checks._same(document, route["document"])
            and checks._record_bytes(route["raw"]) == _native_json(document)
            and _native_json(document) != canonical_json(document) + b"\n"
            and route["raw"]["raw_is_canonical_json_lf"] is False
            and checks._same(route["route"], document["route"])
            and checks._same(route["bundle"], prepared["bundle_files"]),
            "route raw/document/bundle join changed",
        )
        semantics = semantic.verify_openclaw_final_v3_chat_session_snapshot_semantic_compatibility(
            document
        )
        execution, binding, stack = (
            route["execution"],
            route["gateway_pid_binding"],
            route["stack_before"],
        )
        pid, gateway = binding["pid"], "aragorn-agent-gateway.service"
        native_action = document["action"]
        _expect(
            set(execution)
            == {
                "argv",
                "completed_at",
                "effective_identity",
                "environment_names",
                "exit_code",
                "started_at",
                "stderr",
            }
            and execution["environment_names"]
            == [
                "ARAGORN_GATEWAY_PID",
                "ARAGORN_MOCK_PROVIDER_TOKEN",
                "HOME",
                "LANG",
                "LC_ALL",
                "NO_COLOR",
                "NO_PROXY",
                "OPENCLAW_CONFIG_PATH",
                "OPENCLAW_GATEWAY_TOKEN",
                "OPENCLAW_STATE_DIR",
                "PATH",
                "TZ",
            ]
            and checks._same(
                binding,
                {
                    "environment_name": "ARAGORN_GATEWAY_PID",
                    "mount_namespace": f"/proc/{pid}/ns/mnt",
                    "pid": pid,
                    "unit": gateway,
                },
            )
            and stack["processes"][gateway]["groups"] == [992]
            and stack["processes"][gateway]["cmdline"] == ["openclaw-gateway"]
            and native_action["prerequisites"]["boundary_before"]["probe"]["records"][
                0
            ]["root"]
            == f"/docker/volumes/{host['route_input_volume_identity']['name']}/_data"
            and type(invocation["exit_code"]) is int
            and invocation["exit_code"] == 0
            and len(invocation["argv"]) == 3
            and invocation["argv"][:2] == ["/bin/sh", str(_ROOT / _RECIPE)]
            and Path(invocation["argv"][2]).is_absolute(),
            "native execution binding changed",
        )
        checks.verify_execution(
            route,
            document,
            host=host,
            action=action,
            invocation=invocation,
            native_argv=prepared["path_mapping"]["native_probe_argv"],
            recorded_at=evidence["recorded_at"],
            prerequisite=native_action["prerequisites"]["gateway_process_before"],
        )
        commands = native_action["commands"]
        timestamp = checks.det._timestamp
        _expect(
            len(commands) == 7
            and not {command["pid"] for command in commands}
            & set(stack["pids"].values())
            and timestamp(execution["started_at"])
            <= timestamp(commands[0]["started_at"])
            and timestamp(commands[-1]["completed_at"])
            <= timestamp(document["recorded_at"])
            and timestamp(execution["completed_at"])
            <= timestamp(action["recorded_at"])
            <= timestamp(evidence["composition"]["recorded_at"])
            <= timestamp(evidence["recorded_at"]),
            "command identity or composition chronology changed",
        )
        return {
            "native_capture": evidence,
            "harness": host,
            "proof": {
                "authority": "DEVELOPMENT_ROUTE_OBSERVATION_ONLY_NOT_PASS_OR_CAMPAIGN_QUALIFICATION",
                "request_digest": canonical_digest(prepared["request"]),
                "prepared_digest": canonical_digest(prepared),
                "native_capture_digest": checks.det._digest(raw),
                "historical_source": dict(old._SOURCE),
                "current_source_commit": source["commit"],
                "path_mapping": prepared["path_mapping"],
                "actual_native_argv": execution["argv"],
                "semantic_compatibility_digest": canonical_digest(semantics),
                "limitations": [
                    "HOST_WRAPPER_REQUEST_ASSOCIATION_NOT_NATIVE_COLLECTOR_NONCE",
                    "MAPPED_HISTORICAL_ROUTE_NOT_LITERAL_CAMPAIGN_DISPATCH_ARGV",
                    "CHAT_SNAPSHOT_PERSISTENCE_OBSERVATION_NOT_PROVIDER_OR_MODEL_SUCCESS",
                    "DETERMINISTIC_COMPILED_REPLAY_NOT_NATIVE_AGENT_EXECUTION",
                    "FOURTEEN_SELECTED_MODULES_NOT_FULL_TRANSITIVE_IMPORT_CLOSURE",
                    "ENTRY_AND_STORE_RAW_BYTES_NOT_CAPTURED_REPORTED_DIGEST_JOINS_ONLY",
                    "SIGNED_RENDER_TEMPLATE_SUBSTITUTION_NOT_LOCAL_REEXECUTION",
                    "NO_INDEPENDENT_ROUTE_OR_INHERITED_ACTIVATION_QUALIFICATION",
                    "CALLER_OWNS_LIVE_PARENT_SNAPSHOTS_CLEANUP_AND_SIGNED_RETENTION",
                    "NO_FINAL_CAMPAIGN_RESUME_ADMISSION_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
                ],
            },
            "decision": checks._decision(
                "CHAT_SESSION_SNAPSHOT_DEVELOPMENT_ROUTE_OBSERVED_NOT_QUALIFIED"
            ),
        }
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        binascii.Error,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        RuntimeError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid chat-session-snapshot capture: {exc}"
        ) from exc
