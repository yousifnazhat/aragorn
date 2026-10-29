"""Bind the new current-parent plugin-force fixture; never qualify a capture."""

from __future__ import annotations

import ast
import binascii
import json
import os
import re
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any

from aragorn import admission_openclaw_final_v3_campaign as campaign
from aragorn import admission_openclaw_final_v3_plugin_force_subfixture as semantic
from aragorn import admission_protected_final_combined_v3_plugin_force_reinstall as old
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.admission_openclaw_final_v3_campaign_dispatch import (
    dispatch_openclaw_final_v3_campaign_case,
)
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import (
    materialize_openclaw_final_v3_plugin_force_current_parent as materializer,
)
from scripts import openclaw_final_v3_case_checks as checks

_ROOT = Path(__file__).resolve().parents[1]
_CASE = old._ROUTE
_STEM = "plugin-force-reinstall"
_PROBE = "protected-plugin-force-reinstall-v3-probe.py"
_RECIPE = materializer._RECIPE
_NATIVE_ROOT = "/route-input/plugin-force-reinstall"
_PROVISIONAL_ROOT = "/campaign/cases/14-adm-02-update-plugin-force-reinstall"
_SOURCE = {
    "commit": "a5249377cc3f4ef24e441e58ee98f0828c31e963",
    "parent": "0a4808c330cb2ba090ac7eaa7e3e6fb5b253557b",
    "tree": "641aeaa84b66e4cad535b52da6cd674bc33a76e7",
}
_IMAGE = "sha256:afcdb0862ff0a431a0c8f62ff2b12d242603699bd89f46c008e47005117c123f"
_ADDED_LAYERS = [
    "sha256:43d60978c721011e1c97be4caf06201a00f3cf5b85ed7082d65eedabfb3f1ea9",
    "sha256:14933820acfd52013c131fda22863af24fe7271fd7f4ad818f012b0536a4c953",
    "sha256:9efe8b173097b34d307c9d03b46d583d440dcc44e858dde736965b792d6631d8",
]
SOURCE_PATHS = tuple(sorted({materializer._MATERIALIZER, *materializer._INPUTS}))
_BUNDLE = [
    {
        "name": name,
        "bytes": size,
        "digest": digest,
        "role": "probe" if name == _PROBE else "fixture",
    }
    for name, (_, size, digest) in materializer._BUNDLE.items()
]
_ARTIFACT = "final_combined_v3_plugin_force_reinstall"


def _expect(value: bool, message: str) -> None:
    if not value:
        raise AdmissionEvidenceError("plugin-force campaign " + message)


def _bundle(directory: Path) -> None:
    directory.mkdir(mode=0o755)
    for name in ("baseline-source", "candidate-source"):
        materializer.overlay._write_overlay(
            directory / name,
            {
                item["name"].split("/", 1)[1]: checks.bounded._read_source(
                    old._BUNDLE_PATHS[item["name"]], item["bytes"], item["digest"]
                )
                for item in _BUNDLE
                if item["name"].startswith(name + "/")
            },
            (),
        )
    item = _BUNDLE[-1]
    raw = checks.bounded._read_source(
        old._BUNDLE_PATHS[_PROBE], item["bytes"], item["digest"]
    )
    fd = os.open(
        directory / _PROBE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444
    )
    try:
        written = 0
        while written < len(raw):
            count = os.write(fd, raw[written:])
            _expect(count > 0, "probe write made no progress")
            written += count
        os.fchmod(fd, 0o444)
        os.fsync(fd)
    finally:
        os.close(fd)
    checks.bounded._read_file(
        directory / _PROBE, item["bytes"], item["digest"], mode=0o444
    )
    directory.chmod(0o555)


def prepare_case(
    contract: dict[str, Any], request: dict[str, Any], *, directory: Path
) -> dict[str, Any]:
    """Prepare fixed sources only; the current-parent recipe remains unexecuted."""
    try:
        contract = campaign.validate_openclaw_final_v3_campaign_contract(contract)
        expected = campaign.build_openclaw_final_v3_subfixture_request(contract, _CASE)
        _expect(
            type(request) is dict and checks._same(request, expected), "request changed"
        )
        _expect(
            isinstance(directory, Path)
            and directory.is_dir()
            and not any(p.is_symlink() for p in (directory, *directory.parents)),
            "staging directory changed",
        )
        sources = checks.historical_sources(_SOURCE, SOURCE_PATHS)
        descriptor = dispatch_openclaw_final_v3_campaign_case(_CASE)["descriptor"]
        ordered = [_BUNDLE[-1], *_BUNDLE[:-1]]
        _expect(
            descriptor["materializer"] is None
            and descriptor["argv"]
            == ["/usr/local/bin/python3.12", _PROVISIONAL_ROOT + "/" + _PROBE]
            and descriptor["bundle"]
            == [
                {"path": _PROVISIONAL_ROOT + "/" + item["name"], "role": item["role"]}
                for item in ordered
            ],
            "descriptor changed",
        )
        build_sources = (
            materializer.materialize_openclaw_final_v3_plugin_force_current_parent(
                directory / "build-sources"
            )
        )
        _expect(
            build_sources["parent_image_id"]
            == old._IMAGE
            == expected["frozen_parent"]["identity"]["image_id"],
            "current parent changed",
        )
        _bundle(directory / "bundle")
        return {
            "schema": "aragorn/openclaw-final-v3-plugin-force-case-preparation/v1",
            "authority": "LOCAL_REQUEST_AND_BUNDLE_PREPARATION_NOT_EXECUTION_OR_QUALIFICATION_AUTHORITY",
            "contract": contract,
            "request": expected,
            "descriptor": descriptor,
            "source_files": sources,
            "bundle_files": [dict(item) for item in _BUNDLE],
            "build_sources": build_sources,
            "path_mapping": {
                "authority": "EXPLICIT_HISTORICAL_NATIVE_PATH_MAPPING_NOT_LITERAL_DISPATCH_EXECUTION",
                "provisional_root": _PROVISIONAL_ROOT,
                "native_root": _NATIVE_ROOT,
                "literal_dispatch_argv_equality": False,
                "native_probe_argv": [
                    "/usr/local/bin/python3.12",
                    _NATIVE_ROOT + "/" + _PROBE,
                ],
                "files": [
                    {
                        "provisional": _PROVISIONAL_ROOT + "/" + item["name"],
                        "native": _NATIVE_ROOT + "/" + item["name"],
                        "bytes": item["bytes"],
                        "digest": item["digest"],
                        "role": item["role"],
                    }
                    for item in _BUNDLE
                ],
            },
            "decision": checks._decision(
                "PLUGIN_FORCE_REQUEST_AND_LOCAL_BUNDLE_PREPARED_NOT_EXECUTED"
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
            f"invalid plugin-force preparation: {exc}"
        ) from exc


def _literals() -> dict[str, Any]:
    tree = ast.parse(materializer._verified_inputs()[materializer._COLLECTOR])
    return {
        target.id: ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
        and target.id in {"_SCHEMA", "_AUTHORITY", "_LIMITATIONS"}
    }


def _file(
    item: dict[str, Any], *, path: str, size: int, digest: str, mode: str
) -> None:
    checks.records._verify_file_record(
        item,
        path=path,
        bytes_=size,
        digest=digest,
        mode=mode,
        label="plugin-force source",
    )


def _sources(value: dict[str, Any]) -> None:
    _expect(
        set(value) == {*old._SOURCE_ARTIFACTS, "probe_bundle"}
        and checks._same(value["probe_bundle"], _BUNDLE),
        "source inventory changed",
    )
    for name, source in old._SOURCE_ARTIFACTS.items():
        if name == "collector":
            size, digest = materializer._OUTPUTS[materializer._COLLECTOR]
            path = "/src/scripts/" + materializer._COLLECTOR
        else:
            size, digest, path = (
                source["bytes"],
                source["digest"],
                "/src/" + source["path"],
            )
        _file(value[name], path=path, size=size, digest=digest, mode=source["mode"])


def _composition(
    evidence: dict[str, Any], parent: dict[str, Any], literals: dict[str, Any]
) -> None:
    reference = json.loads(semantic._reference_bytes())
    verifier = SimpleNamespace(
        config=checks.old.custody.parent.v3_contract.config,
        contract=old.contract,
        _RAW_LIMITATIONS=literals["_LIMITATIONS"],
        _COMPOSITION_DECISION=reference["composition"]["decision"],
        _verify_sources=_sources,
    )
    artifact = checks.verify_native_composition(
        evidence,
        parent,
        verifier=verifier,
        schema=literals["_SCHEMA"],
        authority=literals["_AUTHORITY"],
        artifact_key=_ARTIFACT,
    )
    _expect(
        set(artifact)
        == {
            "activator",
            "activator_source",
            "collector",
            "config",
            "force_probe",
            "plugin",
            "policy_command",
            "preflight",
            "profile",
            "runtime_lock",
            "skill",
        },
        "artifact inventory changed",
    )
    checks.verify_native_lean_artifacts(artifact)
    collector = artifact["collector"]
    _expect(
        set(collector)
        == {
            "capture_recipe",
            "dockerfile",
            "probe",
            "inherited_combined_base",
            "inherited_route_injector",
        },
        "collector inventory changed",
    )
    for key, name, path, mode in (
        ("capture_recipe", _RECIPE, "/src/scripts/" + _RECIPE, "0555"),
        (
            "probe",
            materializer._COLLECTOR,
            "/src/scripts/" + materializer._COLLECTOR,
            "0555",
        ),
        (
            "dockerfile",
            "Dockerfile",
            "/src/" + materializer._DOCKER_DIRECTORY + "/Dockerfile",
            "0444",
        ),
    ):
        size, digest = materializer._OUTPUTS[name]
        _file(collector[key], path=path, size=size, digest=digest, mode=mode)
    for key in ("inherited_combined_base", "inherited_route_injector"):
        _expect(
            checks._same(collector[key], evidence["source_artifacts"][key]),
            "source alias changed",
        )
    _expect(
        checks._same(collector["probe"], evidence["source_artifacts"]["collector"])
        and set(artifact["force_probe"]) == {"source", "runtime"},
        "probe alias changed",
    )
    probe = old._SOURCE_ARTIFACTS["force_probe"]
    for key, path in (
        ("source", "/src/" + probe["path"]),
        ("runtime", _NATIVE_ROOT + "/" + _PROBE),
    ):
        _file(
            artifact["force_probe"][key],
            path=path,
            size=probe["bytes"],
            digest=probe["digest"],
            mode="0444",
        )
    _expect(
        checks._same(
            artifact["force_probe"]["source"],
            evidence["source_artifacts"]["force_probe"],
        ),
        "checked-in probe alias changed",
    )


def verify_capture(
    raw: bytes,
    prepared: dict[str, Any],
    *,
    source: dict[str, Any],
    invocation: dict[str, Any],
) -> dict[str, Any]:
    """Bind reported native evidence, not freshness, qualification or live cleanup."""
    try:
        with TemporaryDirectory(prefix="aragorn-plugin-force-recheck-") as temporary:
            expected = prepare_case(
                prepared["contract"],
                prepared["request"],
                directory=Path(temporary).resolve(),
            )
        _expect(checks._same(prepared, expected), "prepared binding changed")
        checks.verify_source(prepared, source)
        checks.old._verify_commit(
            {key: source[key] for key in ("commit", "parent", "tree")}
        )
        evidence = checks.det.semantic._load_canonical(raw, "plugin-force observation")
        checks._numeric_types(evidence)
        old.parent.parent._verify_scalar_types(evidence)
        old.parent.config._verify_no_positive_eligibility(evidence)
        literals = _literals()
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
            and set(evidence["harness"]) == {"digest", "document", "file"}
            and evidence["schema"] == literals["_SCHEMA"]
            and evidence["authority"] == literals["_AUTHORITY"]
            and evidence["limitations"] == literals["_LIMITATIONS"]
            and evidence["route_id"] == _CASE
            and checks._same(evidence["decision"], old._OUTER_DECISION),
            "outer authority changed",
        )
        action = evidence["composition"]["action"]
        parent = prepared["request"]["frozen_parent"]["identity"]
        host = checks.verify_harness(
            evidence["harness"],
            action,
            source=source,
            parent=parent,
            stem=_STEM,
            image_id=_IMAGE,
        )
        checks.verify_host(host, parent, stem=_STEM)
        layers = json.loads(semantic._reference_bytes())["harness"]["document"][
            "image_lineage"
        ]["child"]["layers"]
        _expect(
            checks._same(
                host["image_lineage"],
                {
                    "parent": {
                        "id": old._IMAGE,
                        "layers": layers,
                        "rootfs_type": "layers",
                    },
                    "child": {
                        "id": _IMAGE,
                        "layers": layers + _ADDED_LAYERS,
                        "rootfs_type": "layers",
                    },
                    "added_layers": _ADDED_LAYERS,
                },
            ),
            "new child ancestry changed",
        )
        _composition(evidence, parent, literals)
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
            and checks._same(route["bundle"], _BUNDLE),
            "raw document/bundle join changed",
        )
        semantics = (
            semantic.verify_openclaw_final_v3_plugin_force_semantic_compatibility(
                document
            )
        )
        execution, binding, stack = (
            route["execution"],
            route["gateway_pid_binding"],
            route["stack_before"],
        )
        pid, gateway = binding["pid"], "aragorn-agent-gateway.service"
        argv = invocation["argv"]
        recipe = next(
            item
            for item in prepared["build_sources"]["files"]
            if item["name"] == _RECIPE
        )
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
            and type(invocation["exit_code"]) is int
            and invocation["exit_code"] == 0
            and len(argv) == 4
            and argv[0] == "/bin/sh"
            and argv[2] == str(_ROOT)
            and type(argv[1]) is str
            and Path(argv[1]).is_absolute()
            and Path(argv[1]).name == _RECIPE
            and Path(argv[1]).parent.name == "build"
            and re.fullmatch(
                r"aragorn-v3-case-logs-[A-Za-z0-9_-]+", Path(argv[1]).parent.parent.name
            )
            is not None
            and str(Path(argv[1])) == argv[1]
            and ".." not in Path(argv[1]).parts
            and Path(argv[3]).is_absolute()
            and checks._same(invocation["recipe"], recipe),
            "native invocation binding changed",
        )
        before = document["action"]["prerequisites"]
        public = before["boundary_before"]
        _expect(
            public["route_input_mount"]["records"][0]["root"]
            == "/docker/volumes/"
            + host["route_input_volume_identity"]["name"]
            + "/_data",
            "public input volume join changed",
        )
        prerequisite = {
            **public["gateway_process"],
            "hostname": before["system_info_before"]["response"]["value"]["hostname"],
        }
        checks.verify_execution(
            route,
            document,
            host=host,
            action=action,
            invocation=invocation,
            native_argv=prepared["path_mapping"]["native_probe_argv"],
            recorded_at=evidence["recorded_at"],
            prerequisite=prerequisite,
        )
        commands = document["action"]["commands"]
        timestamp = checks.det._timestamp
        _expect(
            not {c["pid"] for c in commands} & set(stack["pids"].values())
            and timestamp(execution["started_at"])
            <= timestamp(commands[0]["started_at"])
            and timestamp(commands[-1]["completed_at"])
            <= timestamp(document["recorded_at"])
            and timestamp(execution["completed_at"])
            <= timestamp(action["recorded_at"])
            <= timestamp(evidence["composition"]["recorded_at"])
            <= timestamp(evidence["recorded_at"]),
            "native chronology changed",
        )
        return {
            "native_capture": evidence,
            "harness": host,
            "proof": {
                "authority": "DEVELOPMENT_ROUTE_OBSERVATION_ONLY_NOT_PASS_OR_CAMPAIGN_QUALIFICATION",
                "request_digest": canonical_digest(prepared["request"]),
                "prepared_digest": canonical_digest(prepared),
                "native_capture_digest": checks.det._digest(raw),
                "current_source_commit": source["commit"],
                "build_source": dict(_SOURCE),
                "child_image_id": _IMAGE,
                "path_mapping": prepared["path_mapping"],
                "actual_native_argv": execution["argv"],
                "semantic_compatibility_digest": canonical_digest(semantics),
                "limitations": [
                    "HOST_WRAPPER_ASSOCIATION_NOT_NATIVE_NONCE_OR_CAPTURE_FRESHNESS_PROOF",
                    "OLD_V2_ANCESTRY_AND_RETAINED_HOST_ARE_NOT_CURRENT_PARENT_CAPTURES",
                    "SQLITE_REPORTED_DIGEST_METADATA_DELTA_NOT_RAW_OR_LOGICAL_EQUIVALENCE",
                    "CALLER_OWNS_LIVE_PARENT_SNAPSHOTS_CLEANUP_AND_SIGNED_RETENTION",
                    "NO_INDEPENDENT_RUN_PHASE3_EDR_ADMISSION_OR_RELEASE_QUALIFICATION",
                ],
            },
            "decision": checks._decision(
                "PLUGIN_FORCE_DEVELOPMENT_ROUTE_OBSERVED_NOT_QUALIFIED"
            ),
        }
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        RuntimeError,
        binascii.Error,
    ) as exc:
        raise AdmissionEvidenceError(f"invalid plugin-force capture: {exc}") from exc
