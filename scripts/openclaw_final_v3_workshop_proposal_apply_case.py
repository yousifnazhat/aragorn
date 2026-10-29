"""Bind one native workshop proposal/apply development observation, never a PASS."""

from __future__ import annotations

import binascii
import os
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn import (
    admission_openclaw_final_v3_workshop_proposal_apply_subfixture as semantic,
)
from aragorn import admission_protected_final_combined_v3_workshop_proposal_apply as old
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_openclaw_final_v3_campaign_dispatch import (
    dispatch_openclaw_final_v3_campaign_case,
)
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import openclaw_final_v3_case_checks as checks

_ROOT = Path(__file__).resolve().parents[1]
_CASE = old._ROUTE
_RECIPE = old._COLLECTOR_ARTIFACTS["capture_recipe"]["path"]
_MATERIALIZER = old._SOURCE_ARTIFACTS["materializer"]["path"]
_PROVISIONAL_ROOT = "/campaign/cases/16-adm-02-update-workshop-proposal-apply"
_NATIVE_ROOT = "/route-input/workshop-proposal-apply"
_PROBE = "protected-route-probe.mjs"
SOURCE_PATHS = tuple(
    sorted(
        {old._SOURCE_ARTIFACTS[name]["path"] for name in old._SIGNED_SOURCE_ARTIFACTS}
        | {item["path"] for item in old._COLLECTOR_ARTIFACTS.values()}
    )
)
_SCHEMA = "aragorn/runtime-action-worker-final-combined-v3-workshop-proposal-apply-systemd-observation/v1"
_AUTHORITY = "BOUND_FINAL_COMBINED_V3_RAW_WORKSHOP_PROPOSAL_APPLY_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
_COUNTS = {"route_pass_count": 0, "route_fail_count": 0, "route_not_tested_count": 21}
_NATIVE_INELIGIBLE = {key: False for key in old.v3_contract.contract._ELIGIBILITY_KEYS}


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError("workshop proposal/apply campaign " + message)


def prepare_case(
    contract: dict[str, Any], request: dict[str, Any], *, directory: Path
) -> dict[str, Any]:
    """Bind the unchanged descriptor to the frozen native two-file transformation."""
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
        files = [dict(item) for item in old._PROBES]
        _expect(
            descriptor["materializer"] is None
            and descriptor["argv"]
            == [old._NODE, _PROVISIONAL_ROOT + "/" + _PROBE, "--route-id", _CASE]
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
            "historical descriptor changed",
        )
        probe, proposal = old._verify_materialization()
        bundle = directory / "bundle"
        bundle.mkdir(mode=0o700)
        for item, raw in zip(files, (proposal, probe), strict=True):
            path = bundle / item["name"]
            fd = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444
            )
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                os.fchmod(stream.fileno(), 0o444)
            checks.bounded._read_file(path, item["bytes"], item["digest"], mode=0o444)
        bundle.chmod(0o555)
        _expect(
            stat.S_IMODE(bundle.lstat().st_mode) == 0o555
            and {path.name for path in bundle.iterdir()}
            == {item["name"] for item in files},
            "native bundle directory changed",
        )
        return {
            "schema": "aragorn/openclaw-final-v3-workshop-proposal-apply-case-preparation/v1",
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
                "entrypoint": "transformed_final_combined_v2_probe",
                "transform": "EXACT_V3_CONFIGURATION_DIGEST_AND_SIZE_REPLACEMENT",
            },
            "path_mapping": {
                "authority": "EXPLICIT_HISTORICAL_NATIVE_PATH_MAPPING_NOT_LITERAL_DISPATCH_EXECUTION",
                "provisional_root": _PROVISIONAL_ROOT,
                "native_root": _NATIVE_ROOT,
                "literal_dispatch_argv_equality": False,
                "native_probe_argv": [
                    old._NODE,
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
                "WORKSHOP_PROPOSAL_APPLY_REQUEST_AND_LOCAL_BUNDLE_PREPARED_NOT_EXECUTED"
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
            f"invalid workshop proposal/apply preparation: {exc}"
        ) from exc


def _verify_composition(evidence: dict[str, Any], parent: dict[str, Any]) -> None:
    composition = evidence["composition"]
    action = composition["action"]
    artifact = checks.verify_parent(composition, action, parent)
    _expect(
        set(composition)
        == {
            "action",
            "authority",
            "bindings",
            "decision",
            "limitations",
            "profile",
            "recorded_at",
            "schema",
        }
        and set(artifact) == set(old._ARTIFACT_DIGESTS)
        and composition["schema"] == _SCHEMA
        and composition["authority"] == _AUTHORITY
        and composition["limitations"] == old._RAW_LIMITATIONS
        and checks._same(
            composition["decision"],
            {
                **_NATIVE_INELIGIBLE,
                "status": "FINAL_COMBINED_V3_ACTION_OBSERVED_PROFILE_NOT_TESTED",
                **_COUNTS,
                "p3_7c_activation_action_observed": True,
            },
        )
        and checks._same(
            composition["bindings"],
            {
                "config_materialization": "canonical_json_without_trailing_lf",
                "network": "none",
                "openclaw_test_fast": "absent",
                "runtime_digest": old.v3_contract.config._RUNTIME_TREE["tree_digest"],
                "runtime_volume": parent["runtime_volume"],
                "sandbox": "off",
                "sessions": "fresh-only",
                "skill_digest": old.v3_contract.config._SOURCES["skill"]["digest"],
            },
        )
        and checks._same(
            action["identities"],
            {
                "broker": {"gid": 997, "uid": 995},
                "gateway": {"gid": 992, "uid": 992},
                "sensor": {"gid": 996, "uid": 996},
                "worker": {"gid": 997, "uid": 997},
            },
        )
        and checks._same(
            action["secret_checks"],
            {
                "forbidden_driver_fields": [],
                "gateway_environment_bytes_retained": False,
                "gateway_environment_digest_retained": False,
                "provider_and_gateway_token_values_retained": False,
            },
        )
        and checks._same(
            action["runtime"],
            {
                "entrypoint": old._OPENCLAW,
                "entrypoint_digest": old.v3_contract.contract._RUNTIME[
                    "entrypoint_digest"
                ],
                "expected_version": old.v3_contract.contract._RUNTIME["version_output"],
                "root": "/runtime",
                "tree": old.v3_contract.config._RUNTIME_TREE,
                "version_output": old.v3_contract.contract._RUNTIME["version_output"],
            },
        ),
        "composition contract changed",
    )
    old._verify_source_artifacts(evidence["source_artifacts"])
    old._verify_collector_artifacts(artifact["collector"])
    old._verify_probe_artifact(artifact["workshop_proposal_apply_probe"])


def _verify_execution_joins(
    evidence: dict[str, Any], host: dict[str, Any], invocation: dict[str, Any]
) -> None:
    route = evidence["route_observation"]
    execution = route["execution"]
    document = route["document"]
    pid = route["gateway_pid_binding"]["pid"]
    gateway = "aragorn-agent-gateway.service"
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
        and checks._same(
            route["gateway_pid_binding"],
            {
                "environment_name": "ARAGORN_GATEWAY_PID",
                "mount_namespace": f"/proc/{pid}/ns/mnt",
                "pid": pid,
                "unit": gateway,
            },
        )
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
        and route["stack_before"]["processes"][gateway]["groups"] == [992]
        and route["stack_before"]["processes"][gateway]["cmdline"]
        == ["openclaw-gateway"]
        and document["actions"][0]["prerequisites"]["draft"]["mount"]["records"][0][
            "root"
        ]
        == f"/docker/volumes/{host['route_input_volume_identity']['name']}/_data"
        and type(invocation["exit_code"]) is int
        and invocation["exit_code"] == 0
        and len(invocation["argv"]) == 3
        and invocation["argv"][:2] == ["/bin/sh", str(_ROOT / _RECIPE)]
        and Path(invocation["argv"][2]).is_absolute(),
        "native execution binding changed",
    )
    timestamp = checks.det._timestamp
    _expect(
        timestamp(execution["started_at"])
        <= timestamp(
            document["actions"][0]["prerequisites"]["commands"][0]["started_at"]
        )
        and timestamp(execution["completed_at"])
        <= timestamp(evidence["composition"]["recorded_at"])
        <= timestamp(evidence["recorded_at"]),
        "composition chronology changed",
    )


def verify_capture(
    raw: bytes,
    prepared: dict[str, Any],
    *,
    source: dict[str, Any],
    invocation: dict[str, Any],
) -> dict[str, Any]:
    """Check actual fresh identities; live cleanup and retention remain caller-owned."""
    try:
        with TemporaryDirectory(prefix="aragorn-proposal-case-recheck-") as temporary:
            expected = prepare_case(
                prepared["contract"],
                prepared["request"],
                directory=Path(temporary).resolve(),
            )
        _expect(checks._same(prepared, expected), "prepared binding changed")
        checks.verify_source(prepared, source)
        evidence = checks.det.semantic._load_canonical(
            raw, "workshop proposal/apply observation"
        )
        # Telemetry may alternate between integer and float JSON numbers. Check
        # trust-boundary inventories, not a retained whole-run type fingerprint.
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
            },
            "observation inventory changed",
        )
        _expect(
            set(evidence["harness"]) == {"digest", "document", "file"},
            "harness inventory changed",
        )
        _expect(
            set(evidence["route_observation"])
            == {
                "bundle",
                "document",
                "execution",
                "gateway_pid_binding",
                "raw",
                "route",
                "stack_before",
            },
            "route inventory changed",
        )
        checks._numeric_types(evidence)
        old._verify_scalar_types(evidence)
        old.v3_contract.config._verify_no_positive_eligibility(evidence)
        _expect(
            evidence["schema"] == _SCHEMA
            and evidence["authority"] == _AUTHORITY
            and evidence["route_id"] == _CASE
            and evidence["limitations"] == old._RAW_LIMITATIONS
            and checks._same(
                evidence["decision"],
                {
                    **_NATIVE_INELIGIBLE,
                    "status": "FINAL_COMBINED_V3_WORKSHOP_PROPOSAL_APPLY_OBSERVED_PROFILE_NOT_TESTED",
                    **_COUNTS,
                    "route_observation_status": "OBSERVED",
                },
            ),
            "native observation envelope changed",
        )
        action = evidence["composition"]["action"]
        parent = prepared["request"]["frozen_parent"]["identity"]
        host = checks.verify_harness(
            evidence["harness"],
            action,
            source=source,
            parent=parent,
            stem="workshop-proposal-apply",
            image_id=old._IMAGE,
        )
        checks.verify_host(host, parent, stem="workshop-proposal-apply")
        _verify_composition(evidence, parent)
        route = evidence["route_observation"]
        _expect(
            set(route["raw"])
            == {
                "base64",
                "bytes",
                "canonical_digest",
                "digest",
                "raw_is_canonical_json_lf",
            },
            "raw record inventory changed",
        )
        document = checks.old._decode(route["raw"])
        _expect(
            checks._same(document, route["document"])
            and route["raw"]["raw_is_canonical_json_lf"]
            is (checks._record_bytes(route["raw"]) == canonical_json(document) + b"\n")
            and checks._same(route["route"], document["routes"][0])
            and checks._same(route["bundle"], prepared["bundle_files"]),
            "route raw/document/bundle join changed",
        )
        semantics = semantic.verify_openclaw_final_v3_workshop_proposal_apply_semantic_compatibility(
            document
        )
        _verify_execution_joins(evidence, host, invocation)
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
                    "NO_INDEPENDENT_ROUTE_OR_INHERITED_ACTIVATION_QUALIFICATION",
                    "CALLER_OWNS_LIVE_PARENT_SNAPSHOTS_CLEANUP_AND_SIGNED_RETENTION",
                    "NO_FINAL_CAMPAIGN_RESUME_ADMISSION_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
                ],
            },
            "decision": checks._decision(
                "WORKSHOP_PROPOSAL_APPLY_DEVELOPMENT_ROUTE_OBSERVED_NOT_QUALIFIED"
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
            f"invalid workshop proposal/apply capture: {exc}"
        ) from exc
