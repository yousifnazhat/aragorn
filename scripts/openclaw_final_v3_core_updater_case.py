"""Prepare and verify one development core-updater observation, never a PASS."""

from __future__ import annotations

import ast
import binascii
import runpy
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn import admission_openclaw_final_v3_core_updater_qualification as old
from aragorn import admission_openclaw_final_v3_det01_binding as bounded
from aragorn import admission_openclaw_final_v3_det01_qualification as det
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_openclaw_final_v3_campaign_dispatch import (
    dispatch_openclaw_final_v3_campaign_case,
)
from aragorn.oci_worker_protocol import canonical_digest
from scripts import openclaw_final_v3_case_checks as checks

_ROOT = Path(__file__).resolve().parents[1]
_CASE = "ADM-02/update/core-updater-plugin-replacement"
_RECIPE = "scripts/capture_runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd.sh"
_INHERITED = "scripts/capture_runtime_action_worker_final_combined_v3_workshop_proposal_apply_systemd.sh"
_MATERIALIZER = (
    "scripts/materialize_openclaw_final_v3_core_updater_plugin_replacement.py"
)
_COLLECTOR = "scripts/runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd_probe.py"
_NATIVE_ROOT = "/route-input/core-updater-plugin-replacement"
_PROVISIONAL_ROOT = "/campaign/cases/11-adm-02-update-core-updater-plugin-replacement"
_PROBE = "protected-core-updater-plugin-replacement-v3-probe.mjs"
_SOURCE_PATHS = tuple(
    sorted(
        [
            _RECIPE,
            _INHERITED,
            _MATERIALIZER,
            _COLLECTOR,
            "scripts/materialize_fixed_admission_probes.py",
            "scripts/materialize_openclaw_final_v3_rebound_probes.py",
            "scripts/runtime_action_worker_final_combined_v2_systemd_probe.py",
            "scripts/runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe.py",
            "scripts/runtime_action_worker_final_combined_v3_workshop_proposal_apply_systemd_probe.py",
            "scripts/runtime_action_worker_final_route_systemd_probe.py",
            "src/aragorn/admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture.py",
            "benchmark/runtime-action-worker-final-combined-v3-core-updater-plugin-replacement-systemd/Dockerfile",
            "benchmark/fixtures/phase1-protected-workshop/PROPOSAL.md",
            *[
                "benchmark/admission/openclaw-v2026.7.1/" + name
                for name in (
                    _PROBE,
                    "protected-route-probe.mjs",
                    "core-updater-plugin-replacement-audit-listener.mjs",
                    "core-updater-plugin-replacement-index.js",
                    "core-updater-plugin-replacement-openclaw.plugin.json",
                    "core-updater-plugin-replacement-package.json",
                )
            ],
        ]
    )
)
SOURCE_PATHS = _SOURCE_PATHS


def _expect(value: bool, message: str) -> None:
    if not value:
        raise AdmissionEvidenceError("core-updater campaign " + message)


_same = checks._same
_decision = checks._decision


def _historical_sources() -> list[dict[str, Any]]:
    return checks.historical_sources(old._SOURCE, _SOURCE_PATHS)


def _verify_bundle(bundle: Path, files: list[dict[str, Any]]) -> None:
    _expect(len(files) == 6, "bundle file count changed")
    for directory, expected in (
        (bundle, {item["name"].split("/")[0] for item in files}),
        (
            bundle / "candidate-source",
            {item["name"].split("/")[1] for item in files if "/" in item["name"]},
        ),
    ):
        metadata = directory.lstat()
        _expect(
            stat.S_ISDIR(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o555
            and {item.name for item in directory.iterdir()} == expected,
            "bundle directory changed",
        )
    for item in files:
        bounded._read_file(
            bundle / item["name"], item["bytes"], item["digest"], mode=0o444
        )


def prepare_case(
    contract: dict[str, Any], request: dict[str, Any], *, directory: Path
) -> dict[str, Any]:
    """Bind the caller's request to local bytes and an explicit native-path mapping."""
    try:
        contract = campaign.validate_openclaw_final_v3_campaign_contract(contract)
        expected = campaign.build_openclaw_final_v3_subfixture_request(contract, _CASE)
        _expect(
            type(request) is dict and _same(request, expected),
            "caller-held request changed",
        )
        _expect(
            isinstance(directory, Path)
            and directory.is_dir()
            and not any(path.is_symlink() for path in (directory, *directory.parents)),
            "staging directory changed",
        )
        sources = _historical_sources()
        descriptor = dispatch_openclaw_final_v3_campaign_case(_CASE)["descriptor"]
        declared = descriptor["materializer"]["source"]
        source = next(item for item in sources if item["path"] == _MATERIALIZER)
        _expect(
            _same(
                declared,
                {
                    "path": "/src/" + _MATERIALIZER,
                    "bytes": source["bytes"],
                    "digest": source["digest"],
                },
            )
            and descriptor["materializer"]["argv"]
            == ["/usr/local/bin/python3.12", "/src/" + _MATERIALIZER, _PROVISIONAL_ROOT]
            and descriptor["argv"]
            == [
                "/usr/local/bin/node",
                _PROVISIONAL_ROOT + "/" + _PROBE,
                "--route-id",
                _CASE,
            ],
            "descriptor materializer or argv changed",
        )
        # The historical materializer and both rebound stages were checked above;
        # this only writes six fixed files in private host staging, never a probe.
        materializer = runpy.run_path(str(_ROOT / _MATERIALIZER))
        manifest = materializer[
            "materialize_openclaw_final_v3_core_updater_plugin_replacement"
        ](directory / "bundle")
        files = manifest["files"]
        _expect(
            manifest["case_id"] == _CASE
            and _same(
                descriptor["bundle"],
                [
                    {
                        "path": _PROVISIONAL_ROOT + "/" + item["name"],
                        "role": item["role"],
                    }
                    for item in files
                ],
            ),
            "descriptor bundle paths or roles changed",
        )
        _verify_bundle(directory / "bundle", files)
        return {
            "schema": "aragorn/openclaw-final-v3-core-updater-case-preparation/v1",
            "authority": "LOCAL_REQUEST_AND_BUNDLE_PREPARATION_NOT_EXECUTION_OR_QUALIFICATION_AUTHORITY",
            "contract": contract,
            "request": expected,
            "descriptor": descriptor,
            "source_files": sources,
            "bundle_files": files,
            "path_mapping": {
                "authority": "EXPLICIT_HISTORICAL_NATIVE_PATH_MAPPING_NOT_LITERAL_DISPATCH_EXECUTION",
                "provisional_root": _PROVISIONAL_ROOT,
                "native_root": _NATIVE_ROOT,
                "literal_dispatch_argv_equality": False,
                "native_probe_argv": [
                    "/usr/local/bin/node",
                    _NATIVE_ROOT + "/" + _PROBE,
                    "--route-id",
                    _CASE,
                ],
                "files": [
                    {
                        "provisional": _PROVISIONAL_ROOT + "/" + item["name"],
                        "native": _NATIVE_ROOT + "/" + item["name"],
                        "bytes": item["bytes"],
                        "digest": item["digest"],
                        "role": item["role"],
                    }
                    for item in files
                ],
            },
            "decision": _decision(
                "CORE_UPDATER_REQUEST_AND_LOCAL_BUNDLE_PREPARED_NOT_EXECUTED"
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
            f"invalid core-updater preparation: {exc}"
        ) from exc


def _collector_literals() -> dict[str, Any]:
    fields = {"_SCHEMA", "_AUTHORITY", "_LIMITATIONS"}
    tree = ast.parse((_ROOT / _COLLECTOR).read_bytes())
    return {
        target.id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name) and target.id in fields
    }


def verify_capture(
    raw: bytes,
    prepared: dict[str, Any],
    *,
    source: dict[str, Any],
    invocation: dict[str, Any],
) -> dict[str, Any]:
    """Recompute raw route joins offline; source retention and cleanup are caller-owned."""
    try:
        with TemporaryDirectory(prefix="aragorn-core-case-recheck-") as temporary:
            expected = prepare_case(
                prepared["contract"],
                prepared["request"],
                directory=Path(temporary).resolve(),
            )
        _expect(_same(prepared, expected), "prepared binding changed")
        checks.verify_source(prepared, source)
        evidence = det.semantic._load_canonical(raw, "fresh core-updater observation")
        checks._numeric_types(evidence)
        old.custody.parent.v3_contract.config._verify_no_positive_eligibility(evidence)
        literals = _collector_literals()
        _expect(
            set(evidence)
            == {
                "schema",
                "authority",
                "recorded_at",
                "route_id",
                "harness",
                "composition",
                "source_artifacts",
                "route_observation",
                "decision",
                "limitations",
            }
            and evidence["schema"] == literals["_SCHEMA"]
            and evidence["authority"] == literals["_AUTHORITY"]
            and evidence["route_id"] == _CASE
            and evidence["limitations"] == literals["_LIMITATIONS"]
            and _same(
                evidence["decision"],
                {
                    **{key: False for key in old.semantic._ELIGIBILITY_KEYS},
                    "status": "FINAL_COMBINED_V3_CORE_UPDATER_PLUGIN_REPLACEMENT_OBSERVED_PROFILE_NOT_TESTED",
                    "route_observation_status": "OBSERVED",
                    "route_pass_count": 0,
                    "route_fail_count": 0,
                    "route_not_tested_count": 21,
                },
            ),
            "native observation envelope changed",
        )
        harness, composition = evidence["harness"], evidence["composition"]
        host, action = harness["document"], composition["action"]
        parent = prepared["request"]["frozen_parent"]["identity"]
        checks.verify_harness(
            harness,
            action,
            source=source,
            parent=parent,
            stem="core-updater-plugin-replacement",
            image_id=old._IMAGE,
        )
        checks.verify_parent(composition, action, parent)
        route = evidence["route_observation"]
        document = old._decode(route["raw"])
        _expect(_same(document, route["document"]), "route raw/document changed")
        semantics = old.semantic.verify_openclaw_final_v3_core_updater_plugin_replacement_semantic_compatibility(
            document
        )
        _expect(
            _same(route["route"], document["routes"][0])
            and _same(route["bundle"], prepared["bundle_files"])
            and _same(
                evidence["source_artifacts"]["probe_bundle"], prepared["bundle_files"]
            ),
            "route or native bundle changed",
        )
        checks.verify_execution(
            route,
            document,
            host=host,
            action=action,
            invocation=invocation,
            native_argv=prepared["path_mapping"]["native_probe_argv"],
            recorded_at=evidence["recorded_at"],
        )
        # This lower-level helper binds materializer/source/runtime bundle bytes
        # against the unchanged historical source. It does not qualify a capture.
        old._verify_materialization(evidence)
        return {
            "native_capture": evidence,
            "harness": host,
            "proof": {
                "authority": "DEVELOPMENT_ROUTE_OBSERVATION_ONLY_NOT_PASS_OR_CAMPAIGN_QUALIFICATION",
                "request_digest": canonical_digest(prepared["request"]),
                "prepared_digest": canonical_digest(prepared),
                "native_capture_digest": det._digest(raw),
                "historical_source": dict(old._SOURCE),
                "current_source_commit": source["commit"],
                "path_mapping": prepared["path_mapping"],
                "actual_native_argv": route["execution"]["argv"],
                "semantic_compatibility_digest": canonical_digest(semantics),
                "limitations": [
                    "HOST_WRAPPER_REQUEST_ASSOCIATION_NOT_NATIVE_COLLECTOR_NONCE",
                    "MAPPED_HISTORICAL_ROUTE_NOT_LITERAL_CAMPAIGN_DISPATCH_ARGV",
                    "NO_RETAINED_NATIVE_MODULE_ACQUISITION_OR_INDEPENDENT_ROUTE_QUALIFICATION",
                    "CALLER_OWNS_LIVE_PARENT_SNAPSHOTS_CLEANUP_AND_SIGNED_RETENTION",
                    "NO_FINAL_CAMPAIGN_RESUME_ADMISSION_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
                ],
            },
            "decision": _decision(
                "CORE_UPDATER_DEVELOPMENT_ROUTE_OBSERVED_NOT_QUALIFIED"
            ),
        }
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        binascii.Error,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        RuntimeError,
    ) as exc:
        raise AdmissionEvidenceError(f"invalid core-updater capture: {exc}") from exc
