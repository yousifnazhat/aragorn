"""Bind one native workshop-invalidation development observation, never a PASS."""

from __future__ import annotations

import ast
import binascii
import runpy
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn import admission_openclaw_final_v3_workshop_invalidation_subfixture as old
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_openclaw_final_v3_campaign_dispatch import (
    dispatch_openclaw_final_v3_campaign_case,
)
from aragorn.oci_worker_protocol import canonical_digest
from scripts import openclaw_final_v3_case_checks as checks

_ROOT = Path(__file__).resolve().parents[1]
_CASE = "ADM-02/reload/workshop-invalidation"
_RECIPE = old._CAPTURE_SOURCES["capture_recipe"][4]
_MATERIALIZER = old._SOURCE_ARTIFACTS["dedicated_materializer"]["path"]
_COLLECTOR = old._SOURCE_ARTIFACTS["collector"]["path"]
_ENTRYPOINT = "materialize_openclaw_final_v3_workshop_invalidation"
_PROBE = "protected-workshop-invalidation-v3-probe.mjs"
_PROVISIONAL_ROOT = "/campaign/cases/28-adm-02-reload-workshop-invalidation"
_NATIVE_ROOT = "/route-input/workshop-invalidation"
SOURCE_PATHS = tuple(
    sorted(
        {item["path"] for item in old._SOURCE_ARTIFACTS.values()}
        | {item[4] for item in old._CAPTURE_SOURCES.values()}
    )
)


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError("workshop-invalidation campaign " + message)


def prepare_case(
    contract: dict[str, Any], request: dict[str, Any], *, directory: Path
) -> dict[str, Any]:
    """Keep the provisional descriptor intact and bind the separate native recipe."""
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
        _expect(
            descriptor["materializer"] is None
            and descriptor["argv"]
            == [
                "/usr/local/bin/node",
                _PROVISIONAL_ROOT + "/" + _PROBE,
                "--route-id",
                _CASE,
            ],
            "historical descriptor changed",
        )
        manifest = runpy.run_path(str(_ROOT / _MATERIALIZER))[_ENTRYPOINT](
            directory / "bundle"
        )
        files = manifest["files"]
        _expect(
            manifest["case_id"] == _CASE
            and checks._same(files, old._probe_bundle())
            and sorted(descriptor["bundle"], key=lambda item: item["path"])
            == sorted(
                [
                    {
                        "path": _PROVISIONAL_ROOT + "/" + item["name"],
                        "role": item["role"],
                    }
                    for item in files
                ],
                key=lambda item: item["path"],
            ),
            "native/descriptor bundle changed",
        )
        bundle = directory / "bundle"
        metadata = bundle.lstat()
        _expect(
            stat.S_ISDIR(metadata.st_mode)
            and stat.S_IMODE(metadata.st_mode) == 0o555
            and {item.name for item in bundle.iterdir()}
            == {item["name"] for item in files},
            "native bundle directory changed",
        )
        for item in files:
            checks.bounded._read_file(
                bundle / item["name"], item["bytes"], item["digest"], mode=0o444
            )
        return {
            "schema": "aragorn/openclaw-final-v3-workshop-invalidation-case-preparation/v1",
            "authority": "LOCAL_REQUEST_AND_BUNDLE_PREPARATION_NOT_EXECUTION_OR_QUALIFICATION_AUTHORITY",
            "contract": contract,
            "request": expected,
            "descriptor": descriptor,
            "source_files": sources,
            "bundle_files": files,
            "native_materializer": {
                "authority": "PINNED_NATIVE_RECIPE_MATERIALIZER_NOT_DECLARED_DISPATCH_MATERIALIZER",
                "source": next(
                    item for item in sources if item["path"] == _MATERIALIZER
                ),
                "entrypoint": _ENTRYPOINT,
            },
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
            "decision": checks._decision(
                "WORKSHOP_INVALIDATION_REQUEST_AND_LOCAL_BUNDLE_PREPARED_NOT_EXECUTED"
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
            f"invalid workshop-invalidation preparation: {exc}"
        ) from exc


def verify_capture(
    raw: bytes,
    prepared: dict[str, Any],
    *,
    source: dict[str, Any],
    invocation: dict[str, Any],
) -> dict[str, Any]:
    """Verify unmodified native bytes; the caller owns live cleanup and retention."""
    try:
        with TemporaryDirectory(prefix="aragorn-workshop-case-recheck-") as temporary:
            expected = prepare_case(
                prepared["contract"],
                prepared["request"],
                directory=Path(temporary).resolve(),
            )
        _expect(checks._same(prepared, expected), "prepared binding changed")
        checks.verify_source(prepared, source)
        evidence = checks.det.semantic._load_canonical(
            raw, "fresh workshop-invalidation observation"
        )
        checks._numeric_types(evidence)
        old.parent.v3_contract.config._verify_no_positive_eligibility(evidence)
        tree = ast.parse((_ROOT / _COLLECTOR).read_bytes())
        literals = {
            target.id: ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name)
            and target.id in {"_SCHEMA", "_AUTHORITY", "_LIMITATIONS"}
        }
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
            and evidence["limitations"] == literals["_LIMITATIONS"]
            and evidence["route_id"] == _CASE
            and checks._same(
                evidence["decision"],
                {
                    **{key: False for key in old._ELIGIBILITY_KEYS},
                    "status": "FINAL_COMBINED_V3_WORKSHOP_INVALIDATION_OBSERVED_PROFILE_NOT_TESTED",
                    "route_observation_status": "OBSERVED",
                    "route_pass_count": 0,
                    "route_fail_count": 0,
                    "route_not_tested_count": 21,
                },
            ),
            "native observation envelope changed",
        )
        composition = evidence["composition"]
        action = composition["action"]
        parent = prepared["request"]["frozen_parent"]["identity"]
        host = checks.verify_harness(
            evidence["harness"],
            action,
            source=source,
            parent=parent,
            stem="workshop-invalidation",
            image_id=old._IMAGE,
        )
        inherited = checks.verify_parent(composition, action, parent)
        dedicated = action["artifacts"]["final_combined_v3_workshop_invalidation"]
        signed = old._verify_source_artifacts(evidence["source_artifacts"])
        old._verify_dedicated_artifact(
            dedicated, evidence["source_artifacts"], inherited
        )
        old._verify_materialization(evidence["source_artifacts"], dedicated, signed)
        route = evidence["route_observation"]
        document = checks.old._decode(route["raw"])
        _expect(
            checks._same(document, route["document"])
            and checks._same(route["route"], document["routes"][0])
            and checks._same(route["bundle"], prepared["bundle_files"])
            and checks._same(
                evidence["source_artifacts"]["probe_bundle"], prepared["bundle_files"]
            ),
            "route raw/document/bundle join changed",
        )
        semantics = (
            old.verify_openclaw_final_v3_workshop_invalidation_semantic_compatibility(
                document
            )
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
                "actual_native_argv": route["execution"]["argv"],
                "semantic_compatibility_digest": canonical_digest(semantics),
                "limitations": [
                    "HOST_WRAPPER_REQUEST_ASSOCIATION_NOT_NATIVE_COLLECTOR_NONCE",
                    "MAPPED_HISTORICAL_ROUTE_NOT_LITERAL_CAMPAIGN_DISPATCH_ARGV",
                    "NO_INDEPENDENT_ROUTE_QUALIFICATION",
                    "CALLER_OWNS_LIVE_PARENT_SNAPSHOTS_CLEANUP_AND_SIGNED_RETENTION",
                    "NO_FINAL_CAMPAIGN_RESUME_ADMISSION_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
                ],
            },
            "decision": checks._decision(
                "WORKSHOP_INVALIDATION_DEVELOPMENT_ROUTE_OBSERVED_NOT_QUALIFIED"
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
            f"invalid workshop-invalidation capture: {exc}"
        ) from exc
