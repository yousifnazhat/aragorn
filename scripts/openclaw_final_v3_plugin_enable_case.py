"""Bind one fresh plugin-enable persistence denial; never qualify a campaign."""

from __future__ import annotations

import binascii
import os
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn import admission_openclaw_final_v3_plugin_enable_subfixture as semantic
from aragorn import admission_protected_final_combined_v3_plugin_enable as old
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_openclaw_final_v3_campaign_dispatch import (
    dispatch_openclaw_final_v3_campaign_case,
)
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import openclaw_final_v3_case_checks as checks

_ROOT = Path(__file__).resolve().parents[1]
_CASE = old._ROUTE
_STEM = "plugin-enable"
_RECIPE = old._COLLECTOR_ARTIFACTS["capture_recipe"]["path"]
_PROBE = old._PROBE["name"]
_PROVISIONAL_ROOT = "/campaign/cases/13-adm-02-update-plugin-enable-activation"
_NATIVE_ROOT = "/route-input/plugin-enable-activation"
SOURCE_PATHS = tuple(
    sorted(
        {old._SOURCE_ARTIFACTS[name]["path"] for name in old._SIGNED_SOURCE_ARTIFACTS}
        | {item["path"] for item in old._COLLECTOR_ARTIFACTS.values()}
    )
)
_SCHEMA = "aragorn/runtime-action-worker-final-combined-v3-plugin-enable-systemd-observation/v1"
_AUTHORITY = "BOUND_FINAL_COMBINED_V3_RAW_PLUGIN_ENABLE_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
_ADDED_LAYERS = [
    "sha256:86d678ec2731c58b36666ad71281618776a5cefc7968d4f6dbb0d3b4c6c72261",
    "sha256:9ccec6e4a81e24c82554d3afb3d116a6ea1eeae9e0c4345f08d38a42fce3d082",
    "sha256:886974f09fb31d4af061b11c3a4a938ebaeab81b81aa765b75960fbe36043ffd",
    "sha256:4fefd3c304635585a459372f65bbc47a9a459d08261c8c087d584fab5ca8f6b0",
]


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError("plugin-enable campaign " + message)


def prepare_case(
    contract: dict[str, Any], request: dict[str, Any], *, directory: Path
) -> dict[str, Any]:
    """Reconstruct the exact frozen probe without changing the dispatch descriptor."""
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
            == ["/usr/local/bin/node", _PROVISIONAL_ROOT + "/" + _PROBE]
            and descriptor["bundle"]
            == [{"path": _PROVISIONAL_ROOT + "/" + _PROBE, "role": "probe"}],
            "historical descriptor changed",
        )
        raw = old._verify_probe_transform(checks.old._git)
        bundle = directory / "bundle"
        bundle.mkdir(mode=0o700)
        path = bundle / _PROBE
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            os.fchmod(stream.fileno(), 0o444)
        checks.bounded._read_file(
            path, old._PROBE["bytes"], old._PROBE["digest"], mode=0o444
        )
        bundle.chmod(0o555)
        _expect(
            stat.S_IMODE(bundle.lstat().st_mode) == 0o555
            and [item.name for item in bundle.iterdir()] == [_PROBE],
            "native bundle changed",
        )
        return {
            "schema": "aragorn/openclaw-final-v3-plugin-enable-case-preparation/v1",
            "authority": "LOCAL_REQUEST_AND_BUNDLE_PREPARATION_NOT_EXECUTION_OR_QUALIFICATION_AUTHORITY",
            "contract": contract,
            "request": expected,
            "descriptor": descriptor,
            "source_files": sources,
            "bundle_files": [dict(old._PROBE)],
            "native_materializer": {
                "authority": "PINNED_NATIVE_RECIPE_TRANSFORMATION_NOT_DECLARED_DISPATCH_MATERIALIZER",
                "source": next(
                    item
                    for item in sources
                    if item["path"] == old._COLLECTOR_ARTIFACTS["dockerfile"]["path"]
                ),
                "entrypoint": "dockerfile_fixed_probe_transform",
                "transform": old._TRANSFORM,
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
                "files": [
                    {
                        "provisional": _PROVISIONAL_ROOT + "/" + _PROBE,
                        "native": _NATIVE_ROOT + "/" + _PROBE,
                        "bytes": old._PROBE["bytes"],
                        "digest": old._PROBE["digest"],
                        "role": "probe",
                    }
                ],
            },
            "decision": checks._decision(
                "PLUGIN_ENABLE_REQUEST_AND_LOCAL_BUNDLE_PREPARED_NOT_EXECUTED"
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
            f"invalid plugin-enable preparation: {exc}"
        ) from exc


def _verify_composition(evidence: dict[str, Any], parent: dict[str, Any]) -> None:
    artifact = checks.verify_native_composition(
        evidence,
        parent,
        verifier=old,
        schema=_SCHEMA,
        authority=_AUTHORITY,
        artifact_key="final_combined_v3_plugin_enable",
    )
    checks.verify_native_artifacts(
        artifact,
        verifier=old,
        probe_key="plugin_enable_probe",
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
            prefix="aragorn-plugin-enable-case-recheck-"
        ) as temporary:
            expected = prepare_case(
                prepared["contract"],
                prepared["request"],
                directory=Path(temporary).resolve(),
            )
        _expect(checks._same(prepared, expected), "prepared binding changed")
        checks.verify_source(prepared, source)
        evidence = checks.det.semantic._load_canonical(raw, "plugin-enable observation")
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
        old.enable._verify_scalar_types(evidence)
        old.config._verify_no_positive_eligibility(evidence)
        _expect(
            evidence["schema"] == _SCHEMA
            and evidence["authority"] == _AUTHORITY
            and evidence["route_id"] == _CASE
            and evidence["limitations"] == old._RAW_LIMITATIONS
            and checks._same(evidence["decision"], old._OUTER_DECISION),
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
            and checks._record_bytes(route["raw"]) == canonical_json(document) + b"\n"
            and route["raw"]["raw_is_canonical_json_lf"] is True
            and checks._same(route["route"], document["route"])
            and checks._same(route["bundle"], prepared["bundle_files"]),
            "route raw/document/bundle join changed",
        )
        semantics = (
            semantic.verify_openclaw_final_v3_plugin_enable_semantic_compatibility(
                document
            )
        )
        execution, binding, stack = (
            route["execution"],
            route["gateway_pid_binding"],
            route["stack_before"],
        )
        pid = binding["pid"]
        gateway = "aragorn-agent-gateway.service"
        old._verify_execution(execution, binding)
        _expect(
            checks._same(
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
            and document["action"]["prerequisites"]["boundary_before"]["route_input"][
                "records"
            ][0]["root"]
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
            prerequisite=document["action"]["prerequisites"]["gateway_process_before"],
        )
        commands = document["action"]["commands"]
        _expect(
            not {command["pid"] for command in commands} & set(stack["pids"].values())
            and checks.det._timestamp(execution["started_at"])
            <= checks.det._timestamp(commands[0]["started_at"]),
            "command service identity or start chronology changed",
        )
        timestamp = checks.det._timestamp
        _expect(
            timestamp(execution["completed_at"])
            <= timestamp(action["recorded_at"])
            <= timestamp(evidence["composition"]["recorded_at"])
            <= timestamp(evidence["recorded_at"]),
            "composition chronology changed",
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
                    "PLUGIN_ENABLE_PRE_EFFECT_CREDENTIAL_LOCK_DENIAL_NOT_SUCCESSFUL_PLUGIN_ACTIVATION",
                    "NO_INDEPENDENT_ROUTE_OR_INHERITED_ACTIVATION_QUALIFICATION",
                    "CALLER_OWNS_LIVE_PARENT_SNAPSHOTS_CLEANUP_AND_SIGNED_RETENTION",
                    "NO_FINAL_CAMPAIGN_RESUME_ADMISSION_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
                ],
            },
            "decision": checks._decision(
                "PLUGIN_ENABLE_DEVELOPMENT_ROUTE_OBSERVED_NOT_QUALIFIED"
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
        raise AdmissionEvidenceError(f"invalid plugin-enable capture: {exc}") from exc
