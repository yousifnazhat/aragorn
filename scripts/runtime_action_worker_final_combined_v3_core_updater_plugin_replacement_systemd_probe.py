#!/usr/bin/env python3
"""Observe one dedicated core-updater plugin replacement attempt under V3."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

sys.path.insert(0, "/usr/lib/aragorn")
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runtime_action_worker_final_combined_v3_workshop_proposal_apply_systemd_probe as proposal

combined = proposal.combined
p37c = proposal.p37c

_INHERITED_HARNESS = proposal._harness
_INHERITED_ARTIFACTS = proposal._artifacts
_INHERITED_HARNESS_SCHEMA = proposal._HARNESS_SCHEMA
_HARNESS = Path("/run/aragorn-harness.json")
_OUTPUT = Path(
    "/evidence/runtime-action-worker-final-combined-v3-"
    "core-updater-plugin-replacement-systemd.json"
)
_ROUTE = "ADM-02/update/core-updater-plugin-replacement"
_ROUTE_ROOT = Path("/route-input/core-updater-plugin-replacement")
_ROUTE_PROBE = _ROUTE_ROOT / "protected-core-updater-plugin-replacement-v3-probe.mjs"
_ADMISSION = Path("/src/benchmark/admission/openclaw-v2026.7.1")
_SOURCE_PROBE = _ADMISSION / "protected-core-updater-plugin-replacement-v3-probe.mjs"
_SOURCE_AUDIT = _ADMISSION / "core-updater-plugin-replacement-audit-listener.mjs"
_MATERIALIZER = Path(
    "/src/scripts/materialize_openclaw_final_v3_core_updater_plugin_replacement.py"
)
_REBINDER = Path("/src/scripts/materialize_openclaw_final_v3_rebound_probes.py")
_VERIFIER = Path(
    "/src/src/aragorn/"
    "admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture.py"
)
_PROBE_DIGEST = (
    "sha256:e7c38a03ee2d1d2927a228444cf7172ad67dc5dbbd11acfeaaf11345cd67c30c"
)
_DELEGATED_DIGEST = (
    "sha256:2e655f7039cf6f2c06f815b281bb7a5ca7a84ed48ef44cf4d2ce8dfdc7df6902"
)
_AUDIT_DIGEST = (
    "sha256:37aa36c0d9b6d66dd3af8a7ca3d0bd557bb9a727383d8fb9126dd5d7e2426edc"
)
_CANDIDATE = {
    "index.js": (
        "core-updater-plugin-replacement-index.js",
        154,
        "sha256:67ecfc8f10e39dcc60ec880a587fadeacdb0040b1911ef93a995575f2aa5bbf2",
    ),
    "openclaw.plugin.json": (
        "core-updater-plugin-replacement-openclaw.plugin.json",
        698,
        "sha256:a9d62834481462f8f474fe16bab4fb3d466942d9fc2602c618592897bf427d82",
    ),
    "package.json": (
        "core-updater-plugin-replacement-package.json",
        134,
        "sha256:86f83ebce70efcb741663859444a059de21eb8906fbe45dc220aed6c94eb5803",
    ),
}
_ROUTES = {
    _ROUTE: {
        "directories": ("candidate-source",),
        "files": (
            "protected-core-updater-plugin-replacement-v3-probe.mjs",
            "protected-route-action-probe.mjs",
            "core-updater-plugin-replacement-audit-listener.mjs",
            "candidate-source/index.js",
            "candidate-source/openclaw.plugin.json",
            "candidate-source/package.json",
        ),
        "fixtures": (
            "candidate-source/index.js",
            "candidate-source/openclaw.plugin.json",
            "candidate-source/package.json",
        ),
        "probe": "protected-core-updater-plugin-replacement-v3-probe.mjs",
        "schema": (
            "aragorn/openclaw-protected-core-updater-plugin-replacement-"
            "observation/v1"
        ),
    }
}
_EXPECTED_BUNDLE = {
    "protected-core-updater-plugin-replacement-v3-probe.mjs": {
        "bytes": 27_682,
        "digest": _PROBE_DIGEST,
        "role": "probe",
    },
    "protected-route-action-probe.mjs": {
        "bytes": 45_137,
        "digest": _DELEGATED_DIGEST,
        "role": "probe-dependency",
    },
    "core-updater-plugin-replacement-audit-listener.mjs": {
        "bytes": 3_177,
        "digest": _AUDIT_DIGEST,
        "role": "probe-dependency",
    },
    **{
        f"candidate-source/{name}": {
            "bytes": bytes_,
            "digest": digest,
            "role": "fixture",
        }
        for name, (_source, bytes_, digest) in _CANDIDATE.items()
    },
}
_SCHEMA = (
    "aragorn/runtime-action-worker-final-combined-v3-"
    "core-updater-plugin-replacement-systemd-observation/v1"
)
_HARNESS_SCHEMA = (
    "aragorn/runtime-action-worker-final-combined-v3-"
    "core-updater-plugin-replacement-systemd-harness/v1"
)
_AUTHORITY = (
    "BOUND_FINAL_COMBINED_V3_RAW_CORE_UPDATER_PLUGIN_REPLACEMENT_"
    "OBSERVATION_ONLY_NOT_PASS_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_"
    "RELEASE_AUTHORITY"
)
_LIMITATIONS = [
    "OBSERVED_IS_NOT_PASS",
    "PROFILE_LEDGER_REMAINS_ZERO_PASS_ZERO_FAIL_TWENTY_ONE_NOT_TESTED",
    "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "DEDICATED_CORE_UPDATER_PLUGIN_REPLACEMENT_ROUTE_AND_ACTION_ID_ONLY",
    "EPHEMERAL_WRITABLE_CONFIG_COPY_USED_FOR_FAILURE_BOOKKEEPING",
    "PINNED_INSTALLED_PLUGIN_INDEX_WRITER_LOCATED_FROM_PRIVATE_BUILD",
    "TRUSTED_DIAGNOSTIC_METADATA_BOUND_NOT_INDEPENDENT_CALL_SITE_ATTESTATION",
    "TARGET_BYTES_UNCHANGED_AFTER_POLICY_DENIAL",
    "NO_CONFIG_DISABLEMENT_ROLLBACK_OR_GENERAL_UPDATE_CLAIM",
    "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "PUBLIC_NETWORK_DENIED",
    "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]


def _route_input_volume_name(
    document: dict[str, Any], source_commit: str
) -> str | None:
    return combined._ephemeral_input_volume_name(
        document,
        source_commit,
        stem="route_input",
        destination="/route-input",
        name_pattern=(
            r"aragorn-phase3-final-combined-v3-core-updater-plugin-"
            r"replacement-route-input-([1-9][0-9]*)"
        ),
        role="final-combined-v3-core-updater-plugin-replacement-route-input",
    )


def _harness() -> dict[str, Any]:
    retained = p37c._stable_document_snapshot(_HARNESS)
    document = retained["document"]
    combined._expect(
        document.get("schema") == _HARNESS_SCHEMA
        and document.get("image_reference")
        == "aragorn-phase3-final-combined-v3-core-updater-plugin-replacement-systemd"
        and document.get("profile_label")
        == "phase3-final-combined-v3-core-updater-plugin-replacement",
        "outer V3 core-updater harness identity changed",
    )
    normalized = proposal.json.loads(p37c.canonical_json(document))
    normalized["schema"] = _INHERITED_HARNESS_SCHEMA
    normalized["image_reference"] = (
        "aragorn-phase3-final-combined-v3-workshop-proposal-apply-systemd"
    )
    normalized["profile_label"] = "phase3-final-combined-v3-workshop-proposal-apply"
    descriptor, name = tempfile.mkstemp(prefix="aragorn-v3-core-updater-harness-", dir="/run")
    path = Path(name)
    try:
        remaining = memoryview(p37c.canonical_json(normalized))
        while remaining:
            written = os.write(descriptor, remaining)
            combined._expect(written > 0, "normalized harness write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        with (
            mock.patch.object(proposal, "_HARNESS", path),
            mock.patch.object(proposal, "_HARNESS_SCHEMA", _INHERITED_HARNESS_SCHEMA),
            mock.patch.object(proposal, "_route_input_volume_name", _route_input_volume_name),
        ):
            base = _INHERITED_HARNESS()
    finally:
        path.unlink(missing_ok=True)
    combined._expect(base["document"] == normalized, "normalized core-updater harness changed")
    return retained


def _custody(record: dict[str, Any]) -> dict[str, Any]:
    return {
        key: record["stat"][key]
        for key in ("gid", "mode", "nlink", "type", "uid")
    }


def _artifacts() -> dict[str, Any]:
    with (
        mock.patch.object(proposal, "_ROUTE_PROBE", proposal._TRANSFORMED_PROBE),
        mock.patch.object(proposal, "_ROUTE_PROPOSAL", proposal._V2_PROPOSAL),
    ):
        inherited = _INHERITED_ARTIFACTS()
    source_probe = p37c._file(_SOURCE_PROBE)
    runtime_probe = p37c._file(_ROUTE_PROBE)
    source_audit = p37c._file(_SOURCE_AUDIT)
    runtime_audit = p37c._file(
        _ROUTE_ROOT / "core-updater-plugin-replacement-audit-listener.mjs"
    )
    delegated = p37c._file(_ROUTE_ROOT / "protected-route-action-probe.mjs")
    materializer = p37c._file(_MATERIALIZER)
    rebound_materializer = p37c._file(_REBINDER)
    verifier = p37c._file(_VERIFIER)
    collector = p37c._file(Path(__file__).resolve())
    capture_recipe = p37c._file(
        Path(
            "/src/scripts/capture_runtime_action_worker_final_combined_v3_"
            "core_updater_plugin_replacement_systemd.sh"
        )
    )
    dockerfile = p37c._file(
        Path(
            "/src/benchmark/runtime-action-worker-final-combined-v3-core-"
            "updater-plugin-replacement-systemd/Dockerfile"
        )
    )
    combined._expect(
        source_probe["bytes"]
        == runtime_probe["bytes"]
        == _EXPECTED_BUNDLE[_ROUTE_PROBE.name]["bytes"]
        and source_probe["digest"] == runtime_probe["digest"] == _PROBE_DIGEST
        and source_audit["bytes"]
        == runtime_audit["bytes"]
        == _EXPECTED_BUNDLE[_SOURCE_AUDIT.name]["bytes"]
        and source_audit["digest"] == runtime_audit["digest"] == _AUDIT_DIGEST
        and delegated["bytes"]
        == _EXPECTED_BUNDLE["protected-route-action-probe.mjs"]["bytes"]
        and delegated["digest"] == _DELEGATED_DIGEST
        and _custody(source_probe)
        == _custody(runtime_probe)
        == _custody(source_audit)
        == _custody(runtime_audit)
        == _custody(delegated)
        == {"gid": 0, "mode": "0444", "nlink": 1, "type": "file", "uid": 0}
        and _custody(materializer)
        == _custody(rebound_materializer)
        == _custody(collector)
        == _custody(capture_recipe)
        == {"gid": 0, "mode": "0555", "nlink": 1, "type": "file", "uid": 0}
        and _custody(verifier)
        == _custody(dockerfile)
        == {"gid": 0, "mode": "0444", "nlink": 1, "type": "file", "uid": 0},
        "V3 core-updater derivative custody changed",
    )
    candidates = {}
    for name, (source_name, bytes_, digest) in _CANDIDATE.items():
        source = p37c._file(_ADMISSION / source_name)
        runtime = p37c._file(_ROUTE_ROOT / "candidate-source" / name)
        combined._expect(
            source["bytes"] == runtime["bytes"] == bytes_
            and source["digest"] == runtime["digest"] == digest
            and _custody(source)
            == _custody(runtime)
            == {"gid": 0, "mode": "0444", "nlink": 1, "type": "file", "uid": 0},
            f"V3 core-updater candidate changed: {name}",
        )
        candidates[name] = {"checked_in_source": source, "runtime": runtime}
    return {
        **inherited,
        "final_combined_v3_core_updater_plugin_replacement": {
            "audit_listener": {"checked_in_source": source_audit, "runtime": runtime_audit},
            "candidate_source": candidates,
            "collector": {
                "capture_recipe": capture_recipe,
                "dockerfile": dockerfile,
                "probe": collector,
            },
            "delegated_probe": delegated,
            "inherited_workshop_proposal_apply": inherited[
                "final_combined_v3_workshop_proposal_apply"
            ],
            "materializer": materializer,
            "rebound_materializer": rebound_materializer,
            "probe": {"checked_in_source": source_probe, "runtime": runtime_probe},
            "semantic_verifier_source": verifier,
        },
    }


def _probe_bundle() -> list[dict[str, Any]]:
    specification = _ROUTES[_ROUTE]
    actual_files = []
    actual_directories = []
    for path in _ROUTE_ROOT.rglob("*"):
        metadata = path.lstat()
        relative = str(path.relative_to(_ROUTE_ROOT))
        combined._expect(not stat.S_ISLNK(metadata.st_mode), "core-updater route bundle symlink")
        if stat.S_ISREG(metadata.st_mode):
            actual_files.append(relative)
        elif stat.S_ISDIR(metadata.st_mode):
            actual_directories.append(relative)
        else:
            combined._expect(False, "core-updater route bundle special file")
    combined._expect(
        tuple(sorted(actual_files)) == tuple(sorted(specification["files"]))
        and actual_directories == ["candidate-source"],
        "V3 core-updater route bundle inventory changed",
    )
    bundle = []
    for name in specification["files"]:
        record = p37c._file(_ROUTE_ROOT / name)
        expected = _EXPECTED_BUNDLE[name]
        combined._expect(
            _custody(record)
            == {"gid": 0, "mode": "0444", "nlink": 1, "type": "file", "uid": 0}
            and {key: record[key] for key in ("bytes", "digest")}
            == {key: expected[key] for key in ("bytes", "digest")},
            f"V3 core-updater route input changed: {name}",
        )
        bundle.append(
            {
                "name": name,
                "bytes": record["bytes"],
                "digest": record["digest"],
                "role": expected["role"],
            }
        )
    return bundle


def _decision(status: str) -> dict[str, Any]:
    combined._expect(status in {"NOT_TESTED", "OBSERVED"}, "core-updater route status changed")
    return {
        "status": (
            "FINAL_COMBINED_V3_CORE_UPDATER_PLUGIN_REPLACEMENT_"
            "OBSERVED_PROFILE_NOT_TESTED"
            if status == "OBSERVED"
            else "FINAL_COMBINED_V3_CORE_UPDATER_PLUGIN_REPLACEMENT_"
            "NOT_TESTED_PROFILE_NOT_TESTED"
        ),
        "route_observation_status": status,
        "route_pass_count": 0,
        "route_fail_count": 0,
        "route_not_tested_count": 21,
        **{key: False for key in sorted(proposal._ELIGIBILITY_KEYS)},
    }


def _run_route(tokens: dict[str, str], gateway_pid: int) -> dict[str, Any]:
    inherited_run = proposal.v1_route.subprocess.run

    def run_with_selector(command: list[str], *args: Any, **kwargs: Any) -> Any:
        combined._expect(
            command[-2:] == ["/usr/local/bin/node", str(_ROUTE_PROBE)]
            and "--route-id" not in command,
            "V3 core-updater route command changed",
        )
        command.extend(["--route-id", _ROUTE])
        process = inherited_run(command, *args, **kwargs)
        if process.returncode != 0:
            token_values = [value.encode("ascii") for value in tokens.values()]
            combined._expect(
                all(
                    token not in process.stdout and token not in process.stderr
                    for token in token_values
                ),
                "failed core-updater route retained a token",
            )
            stderr = process.stderr.decode("utf-8", errors="replace").strip()
            raise combined.openclaw.ProbeError(
                f"core-updater route exited {process.returncode}: {stderr[:2048]}"
            )
        return process

    bundle = _probe_bundle()
    harness = {"document": {"probe_bundle": bundle}}
    with (
        mock.patch.object(proposal.v1_route, "_ROUTES", _ROUTES),
        mock.patch.object(proposal.v1_route, "_PROBE_ROOT", _ROUTE_ROOT),
        mock.patch.object(proposal.v1_route, "_SELECTED_ROUTE", _ROUTE),
        mock.patch.object(
            proposal.v1_route,
            "_probe_bundle",
            side_effect=lambda _harness: _probe_bundle(),
        ),
        mock.patch.object(
            proposal.v1_route.subprocess, "run", side_effect=run_with_selector
        ),
    ):
        return proposal.v1_route._run_route(tokens, harness, gateway_pid)


def _collect() -> dict[str, Any]:
    with (
        mock.patch.object(proposal, "_HARNESS", _HARNESS),
        mock.patch.object(proposal, "_OUTPUT", _OUTPUT),
        mock.patch.object(proposal, "_ROUTE", _ROUTE),
        mock.patch.object(proposal, "_ROUTE_ROOT", _ROUTE_ROOT),
        mock.patch.object(proposal, "_ROUTE_PROBE", _ROUTE_PROBE),
        mock.patch.object(proposal, "_ROUTES", _ROUTES),
        mock.patch.object(proposal, "_EXPECTED_BUNDLE", _EXPECTED_BUNDLE),
        mock.patch.object(proposal, "_SCHEMA", _SCHEMA),
        mock.patch.object(proposal, "_HARNESS_SCHEMA", _HARNESS_SCHEMA),
        mock.patch.object(proposal, "_AUTHORITY", _AUTHORITY),
        mock.patch.object(proposal, "_LIMITATIONS", _LIMITATIONS),
        mock.patch.object(proposal, "_harness", _harness),
        mock.patch.object(proposal, "_artifacts", _artifacts),
        mock.patch.object(proposal, "_decision", _decision),
        mock.patch.object(proposal, "_run_route", _run_route),
        mock.patch.object(proposal, "_probe_bundle", _probe_bundle),
        mock.patch.object(proposal, "_route_input_volume_name", _route_input_volume_name),
    ):
        result = proposal._collect()
    inherited_collector = result["source_artifacts"]["collector"]
    result["source_artifacts"].update(
        {
            "collector": p37c._file(Path(__file__).resolve()),
            "dedicated_materializer": p37c._file(_MATERIALIZER),
            "inherited_workshop_proposal_collector": inherited_collector,
            "semantic_verifier_source": p37c._file(_VERIFIER),
            "source_audit_listener": p37c._file(_SOURCE_AUDIT),
            "source_probe": p37c._file(_SOURCE_PROBE),
        }
    )
    document = result["route_observation"]["document"]
    preflight = document.get("core_updater_preflight", {})
    audit = preflight.get("trusted_policy_audit", {})
    event = audit.get("event", {})
    installed = preflight.get("installed_index", {})
    combined._expect(
        result["route_id"] == _ROUTE
        and document.get("schema") == _ROUTES[_ROUTE]["schema"]
        and document.get("selected_route_ids") == [_ROUTE]
        and document.get("routes")
        == [
            {
                "action_id": "core-updater-plugin-replacement",
                "id": _ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ]
        and preflight.get("ready") is True
        and preflight.get("target_before") == preflight.get("target_after")
        and installed.get("managed_repository_before")
        == installed.get("managed_repository_after")
        and event.get("action") == "plugin.audit.failed"
        and event.get("outcome") == "denied"
        and event.get("reason") == "security_scan_blocked"
        and event.get("attributes") == {"mode": "update", "source_family": "git"}
        and audit.get("metadata") == {"trusted": True}
        and result["decision"]["route_pass_count"] == 0
        and result["decision"]["route_fail_count"] == 0
        and all(result["decision"][key] is False for key in proposal._ELIGIBILITY_KEYS),
        "V3 core-updater dedicated observation changed",
    )
    return result


def _failure(exc: Exception) -> dict[str, Any]:
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "recorded_at": proposal._iso_now(),
        "route_id": _ROUTE,
        "decision": _decision("NOT_TESTED"),
        "failure": {
            "code": "LIVE_CAPTURE_FAILED_CLOSED",
            "stage": proposal._STAGE,
            "type": type(exc).__name__,
            "message": str(exc),
        },
        "limitations": ["NO_ROUTE_OR_ADMISSION_AUTHORITY_FROM_FAILED_CAPTURE"],
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        print(
            "usage: runtime_action_worker_final_combined_v3_"
            "core_updater_plugin_replacement_systemd_probe.py",
            file=sys.stderr,
        )
        return 64
    try:
        result = _collect()
        status = 0
    except Exception as exc:  # noqa: BLE001 - failed captures self-describe
        result = _failure(exc)
        status = 2
    p37c._publish(_OUTPUT, result)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
