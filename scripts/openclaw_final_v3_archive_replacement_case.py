"""Bind a fresh archive-source replacement observation; never qualify it."""

from __future__ import annotations

import binascii
import json
import re
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any

from aragorn import (
    admission_openclaw_final_v3_archive_replacement_subfixture as semantic,
)
from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn import admission_protected_final_combined_v3_archive_replacement as old
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_openclaw_final_v3_campaign_dispatch import (
    dispatch_openclaw_final_v3_campaign_case,
)
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import materialize_openclaw_final_v3_rebound_probes as materializer
from scripts import openclaw_final_v3_case_checks as checks

_ROOT = Path(__file__).resolve().parents[1]
_CASE = old._ROUTE
_STEM = "archive-source-force-replacement"
_RECIPE = old._COLLECTOR_ARTIFACTS["capture_recipe"][2]
_MATERIALIZER = old._SOURCE_ARTIFACTS["rebound_materializer"][2]
_PROBE = "protected-archive-replacement-probe.mjs"
_PROVISIONAL_ROOT = "/campaign/cases/08-adm-02-update-archive-source-force-replacement"
_NATIVE_ROOT = "/route-input/archive-source-force-replacement"
_ARCHIVE_FIXTURE = {
    "path": "benchmark/fixtures/phase3-protected-archive-replacement/SKILL.md",
    "bytes": 144,
    "digest": "sha256:d30e0a2e568941e37c5f9427b920917a9edf694beadb41f8a5469e820c0dfdf1",
}
_ARTIFACT_KEYS = {
    "activator",
    "activator_source",
    "archive_source_force_replacement_probe",
    "collector",
    "config",
    "plugin",
    "policy_command",
    "preflight",
    "profile",
    "runtime_lock",
    "skill",
}
SOURCE_PATHS = tuple(
    sorted(
        {item[2] for item in old._SOURCE_ARTIFACTS.values()}
        | {item[2] for item in old._COLLECTOR_ARTIFACTS.values()}
        | {_ARCHIVE_FIXTURE["path"]}
    )
)
_SCHEMA = "aragorn/runtime-action-worker-final-combined-v3-archive-source-force-replacement-systemd-observation/v1"
_AUTHORITY = "BOUND_FINAL_COMBINED_V3_RAW_ARCHIVE_SOURCE_FORCE_REPLACEMENT_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
_ADDED_LAYERS = [
    "sha256:6908de5a0d83d30a1712f15bbbebc0c8f2304f1ac200d7a135ef99b8da763235",
    "sha256:b8025fae5ac05ed3fb3e9bc0ab1288706e79fa8fc82a44468e271b0a1c7c90a4",
    "sha256:f80003bcb42d3cf0062e31f2d33aaadf3a58023da43d3fe91ee0c27b053364cf",
    "sha256:3b378e0db40625506fcc258ed8181b7429ed732a5e95be95125a4537af46dfd0",
]
_OUTER_DECISION = {
    "status": "FINAL_COMBINED_V3_ARCHIVE_SOURCE_FORCE_REPLACEMENT_OBSERVED_PROFILE_NOT_TESTED",
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
        raise AdmissionEvidenceError("archive-replacement campaign " + message)


def prepare_case(
    contract: dict[str, Any], request: dict[str, Any], *, directory: Path
) -> dict[str, Any]:
    """Reuse the frozen single-file materializer with an explicit native path mapping."""
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
        fixture = next(
            item for item in sources if item["path"] == _ARCHIVE_FIXTURE["path"]
        )
        _expect(
            checks._same(
                {key: fixture[key] for key in _ARCHIVE_FIXTURE}, _ARCHIVE_FIXTURE
            ),
            "signed archive fixture changed",
        )
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
            "schema": "aragorn/openclaw-final-v3-archive-replacement-case-preparation/v1",
            "authority": "LOCAL_REQUEST_AND_BUNDLE_PREPARATION_NOT_EXECUTION_OR_QUALIFICATION_AUTHORITY",
            "contract": contract,
            "request": expected,
            "descriptor": descriptor,
            "source_files": sources,
            "bundle_files": files,
            "archive_source_fixture": dict(_ARCHIVE_FIXTURE),
            "native_materializer": {
                "authority": "PINNED_NATIVE_RECIPE_TRANSFORMATION_NOT_DECLARED_DISPATCH_MATERIALIZER",
                "source": next(
                    item for item in sources if item["path"] == _MATERIALIZER
                ),
                "entrypoint": "materialize_openclaw_final_v3_rebound_case",
                "transform": "EXACT_V3_CONFIGURATION_DIGEST_AND_SIZE_REPLACEMENT",
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
                "ARCHIVE_REPLACEMENT_REQUEST_AND_LOCAL_BUNDLE_PREPARED_NOT_EXECUTED"
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
            f"invalid archive-replacement preparation: {exc}"
        ) from exc


def _verify_composition(evidence: dict[str, Any], parent: dict[str, Any]) -> None:
    artifact = checks.verify_native_composition(
        evidence,
        parent,
        verifier=_COMMON,
        schema=_SCHEMA,
        authority=_AUTHORITY,
        artifact_key="final_combined_v3_archive_source_force_replacement",
    )
    _expect(set(artifact) == set(_ARTIFACT_KEYS), "artifact inventory changed")
    old._verify_collector_artifacts(artifact["collector"])
    old._verify_probe_artifact(artifact["archive_source_force_replacement_probe"])
    checks.verify_native_lean_artifacts(artifact)


def _verify_archive_host(
    host: dict[str, Any], parent: dict[str, Any], *, source: dict[str, Any]
) -> None:
    """Check all added archive fields before applying the unchanged base host check."""
    volume = host["archive_source_volume_identity"]
    match = re.fullmatch(
        re.escape("aragorn-phase3-final-combined-v3-" + _STEM)
        + r"-archive-source-([1-9][0-9]*)",
        volume["name"],
    )
    _expect(match is not None, "archive source volume name changed")
    prefix = "aragorn-phase3-final-combined-v3-" + _STEM
    _expect(
        host["route_input_volume_identity"]["name"]
        == prefix + "-route-input-" + match[1]
        and checks._same(
            volume,
            {
                "driver": "local",
                "labels": {
                    "dev.aragorn.capture-owner": source["commit"] + ":" + match[1],
                    "dev.aragorn.role": "final-combined-v3-"
                    + _STEM
                    + "-archive-source",
                    "dev.aragorn.route": _CASE,
                    "dev.aragorn.source-commit": source["commit"],
                },
                "name": volume["name"],
                "options": None,
                "scope": "local",
            },
        )
        and checks._same(
            host["archive_source_mount"],
            {
                "destination": "/sources",
                "driver": "local",
                "mode": "ro",
                "rw": False,
                "source": volume["name"],
                "type": "volume",
            },
        ),
        "archive source owner or mount changed",
    )
    fixture = host["archive_source_fixture"]
    _expect(
        set(fixture) == {"base64", *_ARCHIVE_FIXTURE}
        and checks._same(
            {key: fixture[key] for key in _ARCHIVE_FIXTURE}, _ARCHIVE_FIXTURE
        )
        and checks._record_bytes(fixture)
        == checks.bounded._read_source(
            _ARCHIVE_FIXTURE["path"],
            _ARCHIVE_FIXTURE["bytes"],
            _ARCHIVE_FIXTURE["digest"],
        ),
        "archive source fixture bytes changed",
    )
    base_binds = [
        "/sys/fs/cgroup:/sys/fs/cgroup:rw",
        parent["runtime_volume"] + ":/runtime:ro",
        host["route_input_volume_identity"]["name"] + ":/route-input:ro",
    ]
    _expect(
        host["host_config"]["binds"]
        == sorted([*base_binds, volume["name"] + ":/sources:ro"]),
        "archive source host bind inventory changed",
    )
    # Raw harness custody above binds the full host; only fully checked additions
    # are projected out for the fixed three-mount helper. Evidence stays untouched.
    base_host = {
        key: value
        for key, value in host.items()
        if key
        not in {
            "archive_source_fixture",
            "archive_source_mount",
            "archive_source_volume_identity",
        }
    }
    base_host["host_config"] = {**host["host_config"], "binds": base_binds}
    checks.verify_host(base_host, parent, stem=_STEM)


def _verify_public_mounts(document: dict[str, Any], host: dict[str, Any]) -> None:
    for boundary in (
        document["protected_boundary"],
        document["action"]["observations"]["boundary_after"],
    ):
        for name, field in (
            ("probe", "route_input_volume_identity"),
            ("source", "archive_source_volume_identity"),
        ):
            _expect(
                boundary["inputs"][name]["records"][0]["root"]
                == "/docker/volumes/" + host[field]["name"] + "/_data",
                "public source/probe mount join changed",
            )


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
            prefix="aragorn-archive-replacement-case-recheck-"
        ) as temporary:
            expected = prepare_case(
                prepared["contract"],
                prepared["request"],
                directory=Path(temporary).resolve(),
            )
        _expect(checks._same(prepared, expected), "prepared binding changed")
        checks.verify_source(prepared, source)
        evidence = checks.det.semantic._load_canonical(
            raw, "archive-replacement observation"
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
        old.semantics.base._verify_scalar_types(evidence)
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
        _verify_archive_host(host, parent, source=source)
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
        semantics = semantic.verify_openclaw_final_v3_archive_replacement_semantic_compatibility(
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
            and type(invocation["exit_code"]) is int
            and invocation["exit_code"] == 0
            and len(invocation["argv"]) == 3
            and invocation["argv"][:2] == ["/bin/sh", str(_ROOT / _RECIPE)]
            and Path(invocation["argv"][2]).is_absolute(),
            "native execution binding changed",
        )
        _verify_public_mounts(document, host)
        checks.verify_execution(
            route,
            document,
            host=host,
            action=action,
            invocation=invocation,
            native_argv=prepared["path_mapping"]["native_probe_argv"],
            recorded_at=evidence["recorded_at"],
            prerequisite=native_action["prerequisites"]["gateway_process"],
        )
        commands = native_action["commands"]
        timestamp = checks.det._timestamp
        _expect(
            not {command["pid"] for command in commands} & set(stack["pids"].values())
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
                    "UPLOAD_DENIAL_AND_EXCLUDED_WORKSPACE_WRITE_NOT_GLOBAL_NO_WRITE",
                    "NO_INDEPENDENT_ROUTE_OR_INHERITED_ACTIVATION_QUALIFICATION",
                    "CALLER_OWNS_LIVE_PARENT_SNAPSHOTS_CLEANUP_AND_SIGNED_RETENTION",
                    "NO_FINAL_CAMPAIGN_RESUME_ADMISSION_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
                ],
            },
            "decision": checks._decision(
                "ARCHIVE_REPLACEMENT_DEVELOPMENT_ROUTE_OBSERVED_NOT_QUALIFIED"
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
            f"invalid archive-replacement capture: {exc}"
        ) from exc
