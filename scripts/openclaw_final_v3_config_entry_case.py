"""Bind one fresh config-entry persistence denial; never qualify a campaign."""

from __future__ import annotations

import binascii
import os
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn import admission_openclaw_final_v3_config_entry_subfixture as semantic
from aragorn import admission_protected_final_combined_v3_config_entry_activation as old
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_openclaw_final_v3_campaign_dispatch import (
    dispatch_openclaw_final_v3_campaign_case,
)
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import openclaw_final_v3_case_checks as checks

_ROOT = Path(__file__).resolve().parents[1]
_CASE = old._ROUTE
_STEM = "config-entry-activation"
_RECIPE = old._COLLECTOR_ARTIFACTS["capture_recipe"]["path"]
_PROBE = old._PROBE["name"]
_PROVISIONAL_ROOT = "/campaign/cases/10-adm-02-update-config-entry-activation"
_NATIVE_ROOT = "/route-input/config-entry-activation"
SOURCE_PATHS = tuple(
    sorted(
        {old._SOURCE_ARTIFACTS[name]["path"] for name in old._SIGNED_SOURCE_ARTIFACTS}
        | {item["path"] for item in old._COLLECTOR_ARTIFACTS.values()}
    )
)
_SCHEMA = "aragorn/runtime-action-worker-final-combined-v3-config-entry-activation-systemd-observation/v1"
_AUTHORITY = "BOUND_FINAL_COMBINED_V3_RAW_CONFIG_ENTRY_ENABLED_TRUE_PERSISTENCE_ATTEMPT_OBSERVATION_ONLY_NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise AdmissionEvidenceError("config-entry campaign " + message)


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
            "schema": "aragorn/openclaw-final-v3-config-entry-case-preparation/v1",
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
                    if item["path"] == old._MATERIALIZER["path"]
                ),
                "entrypoint": "transformed_final_combined_v2_probe",
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
                "CONFIG_ENTRY_REQUEST_AND_LOCAL_BUNDLE_PREPARED_NOT_EXECUTED"
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
            f"invalid config-entry preparation: {exc}"
        ) from exc


def _verify_artifact(artifact: dict[str, Any]) -> None:
    """Use the frozen content contract, not retained inode-dependent record hashes."""
    _expect(
        set(artifact) == set(old._ARTIFACT_DIGESTS)
        and set(artifact["collector"]) == set(old._COLLECTOR_ARTIFACTS)
        and checks._same(
            artifact["installed_runtime"],
            artifact["runtime_lock"]["document"]["installed_runtime"],
        ),
        "artifact inventory/runtime changed",
    )
    git = checks.old._git
    for expected in old.parent._CONTRACT_FILES.values():
        old._verify_signed_bytes(git, expected)
    activation = artifact["runtime_lock"]["document"]["deployment_bindings"][
        "activation_contract"
    ]
    for name, installed, source_path, size, source_mode, installed_mode in (
        (
            "activator",
            activation["activator"],
            "packaging/activate-runtime-action-worker-host-v3.sh",
            30504,
            "0555",
            "0755",
        ),
        (
            "preflight",
            activation["preflight"],
            "src/aragorn/runtime_action_worker.py",
            37878,
            "0444",
            "0644",
        ),
    ):
        expected = {"path": source_path, "bytes": size, "digest": installed["digest"]}
        # The activator is generated in the frozen parent, not tracked at this
        # route's source commit; the verified runtime lock pins its exact bytes.
        if name == "preflight":
            old._verify_signed_bytes(git, expected)
        for key, path, mode in (
            (name, installed["path"], installed_mode),
            (name + "_source", "/src/" + source_path, source_mode),
        ):
            old.enable_route._verify_file_record(
                artifact[key],
                path=path,
                bytes_=size,
                digest=installed["digest"],
                mode=mode,
                label=key,
            )
    for name, expected in old._COLLECTOR_ARTIFACTS.items():
        old.enable_route._verify_file_record(
            artifact["collector"][name],
            path="/src/" + expected["path"],
            bytes_=expected["bytes"],
            digest=expected["digest"],
            mode=expected["mode"],
            label=name,
        )
        old._verify_signed_bytes(git, expected)
    plugin = {
        "index.js": (
            23860,
            "sha256:71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b",
        ),
        "openclaw.plugin.json": (
            723,
            "sha256:d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036",
        ),
        "package.json": (
            134,
            "sha256:0097f2e532b1a5d99e3cfc4990d4bbf83a01c10ee11d567b139bd9144a859ad2",
        ),
    }
    _expect(set(artifact["plugin"]) == set(plugin), "plugin inventory changed")
    for name, (size, digest) in plugin.items():
        old.enable_route._verify_file_record(
            artifact["plugin"][name],
            path="/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/" + name,
            bytes_=size,
            digest=digest,
            mode="0644",
            label=name,
        )
    old.enable_route._verify_file_record(
        artifact["skill"]["file"],
        path=old._TARGET_ROOT + "/SKILL.md",
        bytes_=140,
        digest=old.config._SOURCES["skill"]["digest"],
        mode="0444",
        label="skill",
    )
    old._verify_artifact_probe(artifact["config_entry_activation_probe"], git)


def _verify_composition(evidence: dict[str, Any], parent: dict[str, Any]) -> None:
    composition = evidence["composition"]
    action = composition["action"]
    artifact = checks.verify_parent(
        composition,
        action,
        parent,
        artifact_key="final_combined_v3_config_entry_activation",
    )
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
        and composition["schema"] == _SCHEMA
        and composition["authority"] == _AUTHORITY
        and composition["limitations"] == old._RAW_LIMITATIONS
        and checks._same(composition["decision"], old._COMPOSITION_DECISION)
        and checks._same(
            composition["bindings"],
            {
                "config_materialization": "canonical_json_without_trailing_lf",
                "network": "none",
                "openclaw_test_fast": "absent",
                "runtime_digest": old.config._RUNTIME_TREE["tree_digest"],
                "runtime_volume": parent["runtime_volume"],
                "sandbox": "off",
                "sessions": "fresh-only",
                "skill_digest": old.config._SOURCES["skill"]["digest"],
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
                "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
                "entrypoint_digest": old.contract._RUNTIME["entrypoint_digest"],
                "expected_version": old.contract._RUNTIME["version_output"],
                "root": "/runtime",
                "tree": old.config._RUNTIME_TREE,
                "version_output": old.contract._RUNTIME["version_output"],
            },
        ),
        "composition contract changed",
    )
    old._verify_sources(evidence["source_artifacts"])
    _verify_artifact(artifact)


def verify_capture(
    raw: bytes,
    prepared: dict[str, Any],
    *,
    source: dict[str, Any],
    invocation: dict[str, Any],
) -> dict[str, Any]:
    """Verify native bytes and actual joins; caller owns live cleanup and retention."""
    try:
        with TemporaryDirectory(prefix="aragorn-config-case-recheck-") as temporary:
            expected = prepare_case(
                prepared["contract"],
                prepared["request"],
                directory=Path(temporary).resolve(),
            )
        _expect(checks._same(prepared, expected), "prepared binding changed")
        checks.verify_source(prepared, source)
        evidence = checks.det.semantic._load_canonical(raw, "config-entry observation")
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
            host["image_lineage"]["added_layers"] == old._ADDED_LAYERS,
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
            semantic.verify_openclaw_final_v3_config_entry_semantic_compatibility(
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
            and document["action"]["prerequisites"]["boundary_before"]["probe"][
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
        old._verify_commands(
            document["action"],
            document["recorded_at"],
            evidence["recorded_at"],
            execution=execution,
            service_pids=set(stack["pids"].values()),
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
                    "ENABLED_TRUE_PERSISTENCE_DENIAL_NOT_DISABLED_TO_ENABLED_ACTIVATION",
                    "NO_INDEPENDENT_ROUTE_OR_INHERITED_ACTIVATION_QUALIFICATION",
                    "CALLER_OWNS_LIVE_PARENT_SNAPSHOTS_CLEANUP_AND_SIGNED_RETENTION",
                    "NO_FINAL_CAMPAIGN_RESUME_ADMISSION_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
                ],
            },
            "decision": checks._decision(
                "CONFIG_ENTRY_DEVELOPMENT_ROUTE_OBSERVED_NOT_QUALIFIED"
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
        raise AdmissionEvidenceError(f"invalid config-entry capture: {exc}") from exc
