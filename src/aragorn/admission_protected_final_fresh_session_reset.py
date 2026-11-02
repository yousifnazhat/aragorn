"""Add one exact fresh-session reset PASS to the final-profile coverage."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Mapping
from datetime import datetime, timezone
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_final_disabled_routes as parent
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError

_ROUTE = "ADM-02/reload/fresh-session-reset"
_SESSION_KEY = "agent:main:aragorn-protected-routes-v1"
_NODE = "/usr/local/bin/node"
_OPENCLAW = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_NETWORK_ERROR = (
    "⚠️ Agent failed before reply: LLM request failed: network connection error.\n"
    "Logs: openclaw logs --follow"
)
_UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_PARENT = {
    "canonical_digest": (
        "sha256:62dc1f68469422e5cc8ae8116fe8f6a9fef02f57256a39a0b3981541e50c8790"
    ),
    "implementation_digest": (
        "sha256:81def345547dff3b684cf6db6ee941095e2f20cc3ddfcd0e7dacd6657571a682"
    ),
    "path": "src/aragorn/admission_protected_final_disabled_routes.py",
}
_EVIDENCE = {
    "bytes": 475_665,
    "canonical_bytes": 475_664,
    "canonical_digest": (
        "sha256:e326608572b2bd3cb1e2e8e6f61a785e4b6b3837e79a132ed2b125ea5699a944"
    ),
    "digest": (
        "sha256:4a6d1d3a4901dd63899026fe50004d6d710bcfad61badb01ef2038bdc6bcad3f"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-route-fresh-session-reset-"
        "systemd-p3-final-2026-08-13.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 25_072,
    "canonical_bytes": 25_119,
    "canonical_digest": (
        "sha256:8c6ea3c83ae9a7a689a5c25ca23f4aa68ce9590976c3605d2f692f95d219d5a4"
    ),
    "digest": (
        "sha256:ecb69c9c4c0ca74cbc7aae9f9d2db7406ec7ad1038cea5321a917241a2bac60f"
    ),
}
_ENVELOPES = {
    "composition": (
        "sha256:8bc49df46b53a45f288695286c42a7e393c5d65d7f1b6be83ad604b403a341b3"
    ),
    "composition_boundaries": (
        "sha256:d920a0d8391d0fa7a7b9991b721d1af6412ca0a4e28d3cf840eccf0f5af1f3ab"
    ),
    "harness": (
        "sha256:164d7be3e545578681fdbba2b4f06ff7122ba5cc5321df70ef44e398214ef3c2"
    ),
    "route_observation": (
        "sha256:44dc0889952dbb20aae021687bd3e24d3a5d1eb3d2793ed6508054c19c604755"
    ),
    "stack_before": (
        "sha256:58868a8a122c99dcc60e34ec21748003685e67d59fb689aa2dac9136c3c8622b"
    ),
    "boundary": (
        "sha256:28983524fcc7afb6332e631c24270f8c163df43e77e101cdd88f5da95b708a1c"
    ),
    "action": (
        "sha256:61a48f68706e92168e1c827c16c7026c48cefc2aa2c71049e6506142e61733c5"
    ),
}
_ROUTE_SOURCE = {
    "commit": "95bb49456627928a60f9d75427bede1c3e33739a",
    "parent": "07daeae06cd0357f087bbc146d0fd2fd920c59af",
    "tree": "5fbec15258eb2e7d5d47d9a8e4df5889a2386e67",
}
_RETENTION = {
    "commit": "3404009245a1ad7c568551da8d6d2773beb843de",
    "parent": _ROUTE_SOURCE["commit"],
    "tree": "f006df0949f5128e7e542b4cb3adefe722677c55",
    "signing_key": parent._SIGNATURE["key"],
}
_RETENTION_BLOB_OID = "1bc95f3306e86eb6a12c0161f4ecb06a8be1e3bf"
_ALLOWED_SIGNER = (
    "yousif.snazhat@gmail.com ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIP+34WpE4lJYYXs96Dbx/j7GMMm0WahOQl267+T2ESDA\n"
).encode("ascii")
_SIGNED_NESTED_OBJECTS = {
    "execution": {
        "bytes": 780,
        "digest": (
            "sha256:d852a69a987895e711b172dd57522d9c898370db34e187cc89ae708817c28613"
        ),
    },
    "protected_boundary": {
        "bytes": 3_500,
        "digest": _ENVELOPES["boundary"],
    },
    "runtime_files": {
        "bytes": 546,
        "digest": (
            "sha256:45a6a55eaad53c59adcb597e1891e415f2b5eee3d37d1d61e5884aa584c8a199"
        ),
    },
    "system_info": {
        "bytes": 1_664,
        "digest": (
            "sha256:00f544fd5f33a838cef95e04f10525295e5f5785ca0d70695da4fb7d2ca1fba8"
        ),
    },
}
_COLLECTOR = {
    "capture_recipe": {
        "bytes": 20_665,
        "digest": (
            "sha256:124a73de0189dc316e01d49aa01862b8699e76c470120bdd8006487dbfa3d93a"
        ),
        "runtime_path": (
            "/route-input/scripts/capture_runtime_action_worker_final_route_systemd.sh"
        ),
        "source_path": "scripts/capture_runtime_action_worker_final_route_systemd.sh",
    },
    "materializer": {
        "bytes": 58_976,
        "digest": (
            "sha256:29f710cb5ce24143287ee6ca4ebbf2e9d4f4d4c108bfbd90b93bd1da9e1ab4c6"
        ),
        "runtime_path": "/route-input/scripts/materialize_fixed_admission_probes.py",
        "source_path": "scripts/materialize_fixed_admission_probes.py",
    },
    "probe": {
        "bytes": 20_729,
        "digest": (
            "sha256:18f6fe8c98c64aaf59c6c35d4785780da2a4dc3ac2a719ac72941dd3ab1a1664"
        ),
        "runtime_path": (
            "/route-input/scripts/runtime_action_worker_final_route_systemd_probe.py"
        ),
        "source_path": "scripts/runtime_action_worker_final_route_systemd_probe.py",
    },
}
_PROBE = {
    "bytes": 44_825,
    "digest": (
        "sha256:fc5f7499141f3a09e9347355dcac2284d781133b16ea05c0b2ee95fd8e6ce820"
    ),
    "name": "protected-route-probe.mjs",
}
_READY_CHECK = {
    "catalog_exact": True,
    "prompt_exact": True,
    "ready": True,
    "session_id_valid": True,
    "snapshot_present": True,
    "snapshot_version_valid": True,
}
_LIMITATIONS = [
    "FIVE_EXACT_STATIC_GATE_OR_DENY_ROUTE_PASSES_COMPOSED_FROM_PINNED_PARENT",
    "FIVE_STATIC_GATE_OR_DENY_ROUTE_TRANSITIONS_NOT_DYNAMICALLY_EXERCISED",
    "ONE_EXACT_DYNAMIC_FRESH_SESSION_RESET_PASS_ONLY",
    "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
    "PROBE_ENTERED_EXACT_GATEWAY_MOUNT_NAMESPACE_FOR_CREDENTIAL_VISIBILITY",
    "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "PUBLIC_NETWORK_DENIED",
    "MODEL_PROVIDER_OR_REPLY_SUCCESS_NOT_REQUIRED_OR_CLAIMED",
    "TERMINAL_MODEL_ERROR_COMPLETES_SNAPSHOT_ROUTE_CAUSALITY_ONLY",
    "FIFTEEN_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
    "NO_AGGREGATE_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
]


def verify_openclaw_final_fresh_session_reset(*, evidence_cas: CAS) -> dict[str, Any]:
    """Return 6/15 coverage after one exact final-profile reset observation."""

    try:
        _verify_parent_dependency()
        qualified = parent.verify_openclaw_final_disabled_routes(
            evidence_cas=evidence_cas
        )
        _verify_parent_result(qualified)
        retained_raw = _verify_retained_evidence()
        raw = parent._read_blob(evidence_cas, _EVIDENCE, "fresh-session reset")
        if raw != retained_raw:
            raise AdmissionEvidenceError(
                "fresh-session reset CAS differs from signed retention"
            )
        evidence = parent._load_canonical_json(raw, _EVIDENCE, "fresh-session reset")
        _verify_evidence(evidence, evidence_cas)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        binascii.Error,
        CASError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(
            f"invalid final fresh-session reset evidence: {exc}"
        ) from exc

    result = copy.deepcopy(qualified)
    for route in result["profile"]["routes"]:
        if route["id"] == _ROUTE:
            route["status"] = "PASS"
            break
    else:
        raise AdmissionEvidenceError("final fresh-session reset route missing")
    result.update(
        {
            "schema": (
                "aragorn/admission-protected-final-fresh-session-reset-"
                "route-coverage/v1"
            ),
            "assurance": (
                "EXACT_STATIC_GATE_OR_DENY_PLUS_ONE_SEMANTICALLY_VERIFIED_"
                "PRIVATE_FRESH_SESSION_RESET_ROUTE_ONLY"
            ),
            "route_semantics": {
                "dynamically_exercised_routes": [_ROUTE],
                "pass_basis": (
                    "FIVE_STATIC_GATE_OR_DENY_PLUS_ONE_EXACT_RESET_TRANSITION"
                ),
                "transitions_dynamically_exercised": True,
            },
            "limitations": list(_LIMITATIONS),
            "source_recorded_at": evidence["recorded_at"],
        }
    )
    result["profile"]["counts"] = {"PASS": 6, "NOT_TESTED": 15}
    result["decision"] = {
        "status": "PARTIAL_STATIC_AND_DYNAMIC_ROUTE_COVERAGE",
        **{key: False for key in parent._ELIGIBILITY_KEYS},
    }
    result["bindings"].update(
        {
            "parent_qualification_canonical_digest": _PARENT["canonical_digest"],
            "parent_verifier": {
                "digest": _PARENT["implementation_digest"],
                "path": _PARENT["path"],
            },
            "fresh_session_reset_observation": {
                **_EVIDENCE,
                "retention": dict(_RETENTION),
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_ROUTE_SOURCE,
                    "signature": dict(parent._SIGNATURE),
                },
            },
            "parent_verifier_implementation_digest": _PARENT["implementation_digest"],
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        }
    )
    return result


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_digest(value: Any) -> str:
    return _digest(parent.oci_worker_protocol.canonical_json(value))


def _git(arguments: list[str], *, maximum: int = 1024 * 1024) -> bytes:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    root = Path(__file__).resolve(strict=True).parents[2]
    try:
        completed = subprocess.run(
            [
                "/usr/bin/git",
                "--no-replace-objects",
                "-C",
                str(root),
                *arguments,
            ],
            cwd=root,
            capture_output=True,
            check=False,
            timeout=60,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdmissionEvidenceError(f"cannot verify signed retention: {exc}") from exc
    if completed.returncode != 0:
        raise AdmissionEvidenceError("signed retention Git verification failed")
    if len(completed.stdout) > maximum or len(completed.stderr) > 64 * 1024:
        raise AdmissionEvidenceError("signed retention Git output exceeds its bound")
    return completed.stdout


def _git_with_signer(arguments: list[str], allowed_signers: Path) -> bytes:
    return _git(
        [
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.allowedSignersFile={allowed_signers}",
            "-c",
            "gpg.ssh.program=/usr/bin/ssh-keygen",
            *arguments,
        ]
    )


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    repository = _git(["rev-parse", "--show-toplevel"]).decode("utf-8").strip()
    if Path(repository).resolve(strict=True) != root:
        raise AdmissionEvidenceError("signed retention repository root changed")
    if _git(["rev-parse", "--show-object-format"]).strip() != b"sha1":
        raise AdmissionEvidenceError("signed retention object format changed")

    commit = _RETENTION["commit"]
    with tempfile.TemporaryDirectory(
        prefix="aragorn-fresh-reset-retention-signer-"
    ) as temporary:
        allowed_signers = Path(temporary) / "allowed_signers"
        allowed_signers.write_bytes(_ALLOWED_SIGNER)
        _git_with_signer(["verify-commit", "--raw", commit], allowed_signers)
        metadata = _git_with_signer(
            [
                "show",
                "-s",
                "--format=%H%x00%T%x00%P%x00%G?%x00%GF%x00%GS%x00%GT",
                commit,
            ],
            allowed_signers,
        ).rstrip(b"\n")
    try:
        fields = [field.decode("ascii") for field in metadata.split(b"\0")]
    except UnicodeDecodeError as exc:
        raise AdmissionEvidenceError("signed retention metadata is not ASCII") from exc
    if fields != [
        commit,
        _RETENTION["tree"],
        _RETENTION["parent"],
        "G",
        parent._SIGNATURE["key"],
        parent._SIGNATURE["signer"],
        "fully",
    ]:
        raise AdmissionEvidenceError("signed retention commit identity changed")

    commit_raw = _git(["cat-file", "commit", commit], maximum=64 * 1024)
    commit_id = hashlib.sha1(
        f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw,
        usedforsecurity=False,
    ).hexdigest()
    if (
        commit_id != commit
        or not commit_raw.startswith(
            f"tree {_RETENTION['tree']}\nparent {_RETENTION['parent']}\n".encode(
                "ascii"
            )
        )
        or b"\ngpgsig -----BEGIN SSH SIGNATURE-----\n" not in commit_raw
    ):
        raise AdmissionEvidenceError("signed retention commit object changed")

    path = _EVIDENCE["path"]
    entry = _git(["ls-tree", "-z", "--full-name", commit, "--", path])
    expected_entry = f"100644 blob {_RETENTION_BLOB_OID}\t{path}".encode() + b"\0"
    if entry != expected_entry:
        raise AdmissionEvidenceError("signed retention evidence tree entry changed")
    raw = _git(["cat-file", "blob", _RETENTION_BLOB_OID], maximum=512 * 1024)
    blob_id = hashlib.sha1(
        f"blob {len(raw)}\0".encode("ascii") + raw,
        usedforsecurity=False,
    ).hexdigest()
    if (
        blob_id != _RETENTION_BLOB_OID
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("signed retention evidence blob changed")
    return raw


def _verify_signed_nested_object(value: Any, name: str) -> None:
    expected = _SIGNED_NESTED_OBJECTS[name]
    raw = parent.oci_worker_protocol.canonical_json(value)
    if len(raw) != expected["bytes"] or _digest(raw) != expected["digest"]:
        raise AdmissionEvidenceError(f"signed fresh-session {name} changed")


def _verify_parent_dependency() -> None:
    path = Path(parent.__file__).resolve(strict=True)
    expected = (Path(__file__).resolve(strict=True).parent / path.name).resolve(
        strict=True
    )
    if (
        path != expected
        or path.name != Path(_PARENT["path"]).name
        or _digest(path.read_bytes()) != _PARENT["implementation_digest"]
    ):
        raise AdmissionEvidenceError("final fresh-session parent dependency changed")


def _verify_parent_result(qualified: Mapping[str, Any]) -> None:
    statuses = {item["id"]: item["status"] for item in qualified["profile"]["routes"]}
    if (
        _canonical_digest(qualified) != _PARENT["canonical_digest"]
        or qualified["schema"]
        != "aragorn/admission-protected-final-disabled-route-coverage/v1"
        or qualified["profile"]["counts"] != {"PASS": 5, "NOT_TESTED": 16}
        or list(statuses.values()).count("PASS") != 5
        or statuses.get(_ROUTE) != "NOT_TESTED"
        or qualified["bindings"]["verifier_implementation_digest"]
        != _PARENT["implementation_digest"]
        or set(qualified["decision"]) != {"status", *parent._ELIGIBILITY_KEYS}
        or any(
            qualified["decision"][key] is not False for key in parent._ELIGIBILITY_KEYS
        )
    ):
        raise AdmissionEvidenceError("final five-route parent qualification changed")


def _verify_evidence(evidence: Mapping[str, Any], evidence_cas: CAS) -> None:
    if (
        set(evidence)
        != {
            "authority",
            "composition",
            "decision",
            "harness",
            "limitations",
            "recorded_at",
            "route_id",
            "route_observation",
            "schema",
        }
        or evidence["schema"]
        != "aragorn/runtime-action-worker-final-route-systemd-observation/v1"
        or evidence["authority"]
        != (
            "BOUNDED_FINAL_PROFILE_RAW_ROUTE_OBSERVATION_ONLY_NOT_ADMISSION_"
            "RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or evidence["recorded_at"] != "2026-08-13T21:44:45.774419Z"
        or evidence["route_id"] != _ROUTE
        or evidence["decision"]
        != {
            "status": "FINAL_ROUTE_OBSERVED_PROFILE_NOT_QUALIFIED",
            "route_observation_status": "OBSERVED",
            "route_pass_count": 0,
            "route_fail_count": 0,
            "route_not_tested_count": 21,
            **{key: False for key in parent._ELIGIBILITY_KEYS},
        }
        or evidence["limitations"]
        != [
            "RAW_ROUTE_OBSERVATION_IS_NOT_INDEPENDENT_CONFORMANCE_AUTHORITY",
            "PROFILE_LEDGER_REMAINS_ZERO_PASS_ZERO_FAIL_TWENTY_ONE_NOT_TESTED",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PROBE_ENTERED_EXACT_GATEWAY_MOUNT_NAMESPACE_FOR_CREDENTIAL_VISIBILITY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
            "MODEL_PROVIDER_OR_REPLY_SUCCESS_NOT_REQUIRED_OR_CLAIMED",
            "TERMINAL_MODEL_ERROR_CAN_COMPLETE_SNAPSHOT_ROUTE_CAUSALITY_ONLY",
            "NO_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
        ]
    ):
        raise AdmissionEvidenceError("final fresh-session wrapper changed")

    documents = {}
    for name in ("composition", "configuration", "profile", "runtime_lock"):
        identity = parent._SOURCES[name]
        raw = parent._read_blob(evidence_cas, identity, name)
        documents[name] = parent._load_canonical_json(raw, identity, name)
    _verify_composition(
        evidence["composition"],
        evidence["harness"],
        documents,
        stack_snapshot_before=evidence["route_observation"]["execution"]["started_at"],
    )
    _verify_harness(
        evidence["harness"],
        trusted_final_harness=documents["composition"]["action"]["harness"],
    )
    _verify_route_observation(
        evidence["route_observation"],
        outer_recorded_at=evidence["recorded_at"],
        harness=evidence["harness"],
        composition_boundaries=evidence["composition"]["action"]["boundaries"],
        trusted_boundaries=documents["composition"]["action"]["boundaries"],
        container_id=evidence["harness"]["final_combined"]["document"]["container_id"],
    )


def _verify_composition(
    composition: Mapping[str, Any],
    harness: Mapping[str, Any],
    documents: Mapping[str, Mapping[str, Any]],
    *,
    stack_snapshot_before: str,
) -> None:
    action = composition["action"]
    final = action["artifacts"]["final_combined"]
    decision = composition["decision"]
    if (
        _canonical_digest(composition) != _ENVELOPES["composition"]
        or composition["schema"]
        != "aragorn/runtime-action-worker-final-combined-systemd-observation/v1"
        or composition["authority"]
        != (
            "BOUNDED_FINAL_COMBINED_P3_7C_ACTION_OBSERVATION_ONLY_PROFILE_ROUTES_"
            "REMAIN_NOT_TESTED_NOT_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or composition["profile"]["before"] != composition["profile"]["after"]
        or composition["profile"]["before"] != final["profile"]
        or final["config"]["document"] != documents["configuration"]
        or final["profile"]["document"] != documents["profile"]
        or final["runtime_lock"]["document"] != documents["runtime_lock"]
        or action["inputs"]["gateway_config"] != documents["configuration"]
        or final["profile"]["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or composition["bindings"]
        != {
            "config_materialization": "canonical_json_without_trailing_lf",
            "network": "none",
            "openclaw_test_fast": "absent",
            "runtime_digest": parent._RUNTIME["runtime_digest"],
            "runtime_volume": parent._RUNTIME["runtime_volume"],
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": parent._SOURCES["skill"]["digest"],
        }
        or decision
        != {
            "status": "FINAL_COMBINED_ACTION_OBSERVED_PROFILE_NOT_TESTED",
            "p3_7c_activation_action_observed": True,
            "route_pass_count": 0,
            "route_fail_count": 0,
            "route_not_tested_count": 21,
            **{key: False for key in parent._ELIGIBILITY_KEYS},
        }
        or action["decision"]["verifier_status"] != "NOT_TESTED"
        or action["inputs"]["gateway_environment_bytes_retained"] is not False
        or action["inputs"]["gateway_environment_digest_retained"] is not False
        or _canonical_digest(action["boundaries"])
        != _ENVELOPES["composition_boundaries"]
        or action["harness"] != harness["final_combined"]
        or _parse_time(composition["recorded_at"])
        > _parse_time("2026-08-13T21:44:45.774419Z")
    ):
        raise AdmissionEvidenceError("final fresh-session composition changed")
    parent._verify_embedded_sources(final)
    _verify_activation_boundary(
        action["boundaries"],
        trusted=documents["composition"]["action"]["boundaries"],
        container_id=harness["final_combined"]["document"]["container_id"],
        snapshot_before=stack_snapshot_before,
    )


def _verify_harness(
    harness: Mapping[str, Any], *, trusted_final_harness: Mapping[str, Any]
) -> None:
    document = harness["document"]
    raw = parent.oci_worker_protocol.canonical_json(document)
    final = harness["final_combined"]
    if (
        _canonical_digest(harness) != _ENVELOPES["harness"]
        or set(harness) != {"bytes", "digest", "document", "final_combined"}
        or len(raw) != harness["bytes"]
        or _digest(raw) != harness["digest"]
        or document
        != {
            "baseline_composition": {
                "bytes": parent._SOURCES["composition"]["bytes"],
                "digest": parent._SOURCES["composition"]["digest"],
                "path": (
                    "benchmark/evidence/runtime-action-worker-final-combined-"
                    "systemd-composition-p3-final-2026-08-13.json"
                ),
            },
            "capture_disposition": "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE",
            "child_image_id": parent._CHILD_IMAGE,
            "collector": _COLLECTOR,
            "composition_harness_digest": final["digest"],
            "image_source_commit": parent._CAPTURE_SOURCE_COMMIT,
            "probe_bundle": [_PROBE],
            "route_id": _ROUTE,
            "route_source_commit": _ROUTE_SOURCE["commit"],
            "route_source_commit_verification": document[
                "route_source_commit_verification"
            ],
            "schema": "aragorn/runtime-action-worker-final-route-systemd-harness/v1",
        }
        or _canonical_digest(final["document"]) != final["digest"]
        or final["document"]["image_id"] != parent._CHILD_IMAGE
        or final["document"]["source_commit"] != parent._CAPTURE_SOURCE_COMMIT
        or final["document"]["host_config"]["network_mode"] != "none"
        or final["document"]["host_config"]["privileged"] is not True
    ):
        raise AdmissionEvidenceError("final fresh-session harness changed")
    if _decode_record(final["file"], expected_extra={"path", "stat"}) != (
        parent.oci_worker_protocol.canonical_json(final["document"])
    ):
        raise AdmissionEvidenceError("final composition harness bytes changed")
    _verify_harness_file(final["file"])
    _verify_final_harness_join(final, trusted_final_harness)
    _verify_route_source(document["route_source_commit_verification"])


def _verify_final_harness_join(
    final: Mapping[str, Any], trusted: Mapping[str, Any]
) -> None:
    actual = final["document"]
    expected = trusted["document"]
    if (
        set(actual) != set(expected)
        or not isinstance(actual["container_id"], str)
        or re.fullmatch(r"[0-9a-f]{64}", actual["container_id"]) is None
        or parent.oci_worker_protocol.canonical_json(
            {
                key: value
                for key, value in actual.items()
                if key not in {"container_id", "host_config"}
            }
        )
        != parent.oci_worker_protocol.canonical_json(
            {
                key: value
                for key, value in expected.items()
                if key not in {"container_id", "host_config"}
            }
        )
    ):
        raise AdmissionEvidenceError("final fresh-session trusted harness join changed")
    actual_host = actual["host_config"]
    expected_host = expected["host_config"]
    if set(actual_host) != set(
        expected_host
    ) or parent.oci_worker_protocol.canonical_json(
        {key: value for key, value in actual_host.items() if key != "binds"}
    ) != parent.oci_worker_protocol.canonical_json(
        {key: value for key, value in expected_host.items() if key != "binds"}
    ):
        raise AdmissionEvidenceError("final fresh-session trusted host config changed")
    binds = actual_host["binds"]
    if (
        binds[:2] != expected_host["binds"]
        or len(binds) != 3
        or not binds[2].endswith(":/route-input:ro")
        or binds[2].count(":") != 2
    ):
        raise AdmissionEvidenceError("final fresh-session trusted route bind changed")


def _verify_harness_file(value: Mapping[str, Any]) -> None:
    stat = value["stat"]
    if (
        value["path"] != "/run/aragorn-harness.json"
        or type(value["bytes"]) is not int
        or value["bytes"] != 17_796
        or set(stat)
        != {
            "ctime_ns",
            "device",
            "gid",
            "inode",
            "mode",
            "mtime_ns",
            "nlink",
            "size",
            "type",
            "uid",
        }
        or type(stat["uid"]) is not int
        or stat["uid"] != 0
        or type(stat["gid"]) is not int
        or stat["gid"] != 0
        or stat["mode"] != "0600"
        or type(stat["nlink"]) is not int
        or stat["nlink"] != 1
        or type(stat["size"]) is not int
        or stat["size"] != value["bytes"]
        or stat["type"] != "file"
        or any(
            type(stat[key]) is not int or stat[key] <= 0
            for key in ("ctime_ns", "device", "inode", "mtime_ns")
        )
    ):
        raise AdmissionEvidenceError("final fresh-session harness custody changed")


def _verify_route_source(verification: Mapping[str, Any]) -> None:
    commit_raw = _decode_record(verification["commit_object"])
    stdout = _decode_record(verification["stdout"])
    stderr = _decode_record(verification["stderr"])
    commit_id = hashlib.sha1(
        f"commit {len(commit_raw)}\0".encode() + commit_raw
    ).hexdigest()
    expected_prefix = (
        f"tree {_ROUTE_SOURCE['tree']}\nparent {_ROUTE_SOURCE['parent']}\n".encode()
    )
    expected_stderr = (
        f'Good "git" signature for {parent._SIGNATURE["signer"]} with ED25519 key '
        f"{parent._SIGNATURE['key']}\n"
    ).encode()
    if (
        set(verification)
        != {"command", "commit_object", "exit_code", "stderr", "stdout"}
        or verification["command"]
        != ["git", "verify-commit", "--raw", _ROUTE_SOURCE["commit"]]
        or verification["exit_code"] != 0
        or commit_id != _ROUTE_SOURCE["commit"]
        or not commit_raw.startswith(expected_prefix)
        or b"\ngpgsig -----BEGIN SSH SIGNATURE-----\n" not in commit_raw
        or not commit_raw.endswith(b"\nQualify disabled final admission surfaces\n")
        or stdout != b""
        or stderr != expected_stderr
    ):
        raise AdmissionEvidenceError("final fresh-session signed route source changed")


def _decode_record(
    value: Mapping[str, Any], *, expected_extra: set[str] | None = None
) -> bytes:
    expected = {"base64", "bytes", "digest"} | (expected_extra or set())
    if set(value) != expected:
        raise AdmissionEvidenceError("final fresh-session retained shape changed")
    raw = base64.b64decode(value["base64"], validate=True)
    if len(raw) != value["bytes"] or _digest(raw) != value["digest"]:
        raise AdmissionEvidenceError("final fresh-session retained identity changed")
    return raw


def _verify_route_observation(
    observation: Mapping[str, Any],
    *,
    outer_recorded_at: str,
    harness: Mapping[str, Any],
    composition_boundaries: Mapping[str, Any],
    trusted_boundaries: Mapping[str, Any],
    container_id: str,
) -> None:
    if _canonical_digest(observation) != _ENVELOPES["route_observation"] or set(
        observation
    ) != {
        "bundle",
        "document",
        "execution",
        "gateway_pid_binding",
        "profile_paths",
        "raw",
        "route",
        "stack_before",
    }:
        raise AdmissionEvidenceError("final fresh-session route wrapper changed")
    document = _decode_route_raw(observation["raw"])
    if document != observation["document"]:
        raise AdmissionEvidenceError("final fresh-session nested document changed")
    if (
        observation["bundle"] != [_PROBE]
        or observation["bundle"] != harness["document"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("final fresh-session probe bundle changed")

    stack = observation["stack_before"]
    binding = observation["gateway_pid_binding"]
    execution = observation["execution"]
    gateway_pid = 2946
    _verify_stack_join(stack, composition_boundaries)
    _verify_stack_boundary(
        stack,
        trusted=trusted_boundaries,
        container_id=container_id,
        snapshot_before=execution["started_at"],
    )
    _verify_signed_nested_object(execution, "execution")
    if (
        _canonical_digest(stack) != _ENVELOPES["stack_before"]
        or binding
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{gateway_pid}/ns/mnt",
            "pid": gateway_pid,
            "unit": "aragorn-agent-gateway.service",
        }
        or observation["profile_paths"]
        != {
            "config": (
                "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
            ),
            "home": "/var/lib/aragorn-agent-gateway/home",
            "state": "/var/lib/aragorn-agent-gateway/state",
            "workspace": "/var/lib/aragorn-agent-gateway/workspace",
        }
        or stack["pids"]["aragorn-agent-gateway.service"] != gateway_pid
        or stack["gateway_listener"]["pid"] != gateway_pid
        or stack["processes"]["aragorn-agent-gateway.service"]
        != {
            "capabilities_effective": "0000000000000000",
            "cmdline": ["openclaw-gateway"],
            "gids": [992, 992, 992, 992],
            "groups": [992],
            "mount_namespace": "mnt:[4026532603]",
            "network_namespace": "net:[4026532355]",
            "no_new_privileges": 1,
            "pid": gateway_pid,
            "start_time_ticks": "6593232",
            "uids": [992, 992, 992, 992],
        }
        or stack["units"]["aragorn-agent-gateway.service"]["MainPID"]
        != str(gateway_pid)
    ):
        raise AdmissionEvidenceError("final fresh-session gateway binding changed")
    _verify_execution(
        execution, gateway_pid, document["recorded_at"], outer_recorded_at
    )
    if observation["route"] != document["routes"][0]:
        raise AdmissionEvidenceError("final fresh-session selected route changed")
    _verify_route_document(document, execution, container_id=container_id)


def _verify_stack_join(
    stack: Mapping[str, Any], composition_boundaries: Mapping[str, Any]
) -> None:
    shared = (
        "enablement",
        "gateway_listener",
        "processes",
        "service_state",
        "sockets",
        "units",
    )
    if set(stack) != {"pids", *shared} or any(
        stack[name] != composition_boundaries[name] for name in shared
    ):
        raise AdmissionEvidenceError("final fresh-session stack join changed")
    services = set(composition_boundaries["units"])
    if (
        set(stack["pids"]) != services
        or set(composition_boundaries["processes"]) != services
        or set(composition_boundaries["service_state"]["units"]) != services
        or len(set(stack["pids"].values())) != len(services)
    ):
        raise AdmissionEvidenceError("final fresh-session stack service set changed")
    for service in services:
        pid = stack["pids"][service]
        if (
            type(pid) is not int
            or pid <= 1
            or pid != int(composition_boundaries["units"][service]["MainPID"])
            or pid
            != int(
                composition_boundaries["service_state"]["units"][service]["properties"][
                    "MainPID"
                ]
            )
            or pid != composition_boundaries["processes"][service]["pid"]
        ):
            raise AdmissionEvidenceError("final fresh-session stack PID join changed")


def _verify_stack_boundary(
    stack: Mapping[str, Any],
    *,
    trusted: Mapping[str, Any],
    container_id: str,
    snapshot_before: str,
) -> None:
    services = set(trusted["units"])
    socket_paths = set(trusted["sockets"])
    if (
        set(stack)
        != {
            "enablement",
            "gateway_listener",
            "pids",
            "processes",
            "service_state",
            "sockets",
            "units",
        }
        or parent.oci_worker_protocol.canonical_json(stack["enablement"])
        != parent.oci_worker_protocol.canonical_json(trusted["enablement"])
        or set(stack["enablement"]) != services
        or set(stack["units"]) != services
        or set(stack["processes"]) != services
        or set(stack["service_state"]["units"]) != services
        or set(stack["sockets"]) != socket_paths
    ):
        raise AdmissionEvidenceError("final fresh-session stack inventory changed")
    _verify_process_projection(stack["processes"], trusted["processes"])
    _verify_unit_projection(
        stack["units"], trusted["units"], stack["processes"], container_id
    )
    _verify_socket_projection(stack["sockets"], trusted["sockets"])
    _verify_service_state(
        stack["service_state"],
        trusted=trusted["service_state"],
        processes=stack["processes"],
        units=stack["units"],
        enablement=stack["enablement"],
        sockets=stack["sockets"],
        container_id=container_id,
        snapshot_before=snapshot_before,
    )
    _verify_gateway_listener(stack["gateway_listener"], stack["processes"])


def _verify_activation_boundary(
    value: Mapping[str, Any],
    *,
    trusted: Mapping[str, Any],
    container_id: str,
    snapshot_before: str,
) -> None:
    services = set(trusted["units"])
    socket_paths = set(trusted["sockets"])
    if (
        set(value) != set(trusted)
        or parent.oci_worker_protocol.canonical_json(value["activation_lock"])
        != parent.oci_worker_protocol.canonical_json(trusted["activation_lock"])
        or parent.oci_worker_protocol.canonical_json(value["enablement"])
        != parent.oci_worker_protocol.canonical_json(trusted["enablement"])
        or set(value["enablement"]) != services
        or set(value["units"]) != services
        or set(value["processes"]) != services
        or set(value["service_state"]["units"]) != services
        or set(value["sockets"]) != socket_paths
        or not isinstance(container_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
    ):
        raise AdmissionEvidenceError("final fresh-session activation inventory changed")
    _verify_process_projection(value["processes"], trusted["processes"])
    _verify_unit_projection(
        value["units"], trusted["units"], value["processes"], container_id
    )
    _verify_socket_projection(value["sockets"], trusted["sockets"])
    _verify_service_state(
        value["service_state"],
        trusted=trusted["service_state"],
        processes=value["processes"],
        units=value["units"],
        enablement=value["enablement"],
        sockets=value["sockets"],
        container_id=container_id,
        snapshot_before=snapshot_before,
    )
    _verify_gateway_listener(value["gateway_listener"], value["processes"])


def _verify_process_projection(
    actual: Mapping[str, Any], trusted: Mapping[str, Any]
) -> None:
    mount_namespaces: set[str] = set()
    network_namespaces: set[str] = set()
    for service in trusted:
        process = actual[service]
        expected = trusted[service]
        if set(process) != set(expected):
            raise AdmissionEvidenceError("final fresh-session process shape changed")
        projected = {
            key: value
            for key, value in process.items()
            if key
            not in {"pid", "start_time_ticks", "mount_namespace", "network_namespace"}
        }
        expected_projected = {
            key: value
            for key, value in expected.items()
            if key
            not in {"pid", "start_time_ticks", "mount_namespace", "network_namespace"}
        }
        if (
            parent.oci_worker_protocol.canonical_json(projected)
            != parent.oci_worker_protocol.canonical_json(expected_projected)
            or type(process["pid"]) is not int
            or process["pid"] <= 1
            or not isinstance(process["start_time_ticks"], str)
            or re.fullmatch(r"[1-9][0-9]*", process["start_time_ticks"]) is None
            or not isinstance(process["mount_namespace"], str)
            or re.fullmatch(r"mnt:\[[1-9][0-9]*\]", process["mount_namespace"]) is None
            or not isinstance(process["network_namespace"], str)
            or re.fullmatch(r"net:\[[1-9][0-9]*\]", process["network_namespace"])
            is None
        ):
            raise AdmissionEvidenceError(
                f"final fresh-session process contract changed: {service}"
            )
        mount_namespaces.add(process["mount_namespace"])
        network_namespaces.add(process["network_namespace"])
    if len(mount_namespaces) != len(trusted) or len(network_namespaces) != len(trusted):
        raise AdmissionEvidenceError("final fresh-session namespace isolation changed")


def _verify_unit_projection(
    actual: Mapping[str, Any],
    trusted: Mapping[str, Any],
    processes: Mapping[str, Any],
    container_id: str,
) -> None:
    for service in trusted:
        unit = actual[service]
        expected = trusted[service]
        if set(unit) != set(expected):
            raise AdmissionEvidenceError("final fresh-session unit shape changed")
        unit_projection = _unit_projection(unit)
        expected_projection = _unit_projection(expected)
        _normalized, start_time, displayed_pid = _normalized_exec_start(
            unit["ExecStart"]
        )
        _expected_normalized, expected_start, expected_displayed_pid = (
            _normalized_exec_start(expected["ExecStart"])
        )
        pid = processes[service]["pid"]
        expected_dynamic_display = expected_displayed_pid != 0
        if (
            parent.oci_worker_protocol.canonical_json(unit_projection)
            != parent.oci_worker_protocol.canonical_json(expected_projection)
            or not isinstance(unit["MainPID"], str)
            or re.fullmatch(r"[1-9][0-9]*", unit["MainPID"]) is None
            or int(unit["MainPID"]) != pid
            or unit["ControlGroup"] != f"/docker/{container_id}/system.slice/{service}"
            or (expected_dynamic_display and displayed_pid != pid)
            or (
                expected_dynamic_display
                and re.fullmatch(
                    r"[A-Z][a-z]{2} [0-9]{4}-[0-9]{2}-[0-9]{2} "
                    r"[0-9]{2}:[0-9]{2}:[0-9]{2} UTC",
                    start_time,
                )
                is None
            )
            or (not expected_dynamic_display and displayed_pid != 0)
            or (not expected_dynamic_display and start_time != expected_start)
        ):
            raise AdmissionEvidenceError(
                f"final fresh-session unit contract changed: {service}"
            )


def _unit_projection(unit: Mapping[str, Any]) -> dict[str, Any]:
    projected = {
        key: value
        for key, value in unit.items()
        if key not in {"ControlGroup", "MainPID"}
    }
    projected["ExecStart"] = _normalized_exec_start(unit["ExecStart"])[0]
    projected["LoadCredential"] = _normalized_credentials(unit["LoadCredential"])
    return projected


def _normalized_exec_start(value: Any) -> tuple[tuple[str, ...], str, int]:
    if not isinstance(value, str):
        raise AdmissionEvidenceError("final fresh-session ExecStart type changed")
    match = re.fullmatch(
        r"(?P<loaded>\{ path=[^\n]+) ; ignore_errors=(?P<ignore>[^ ;\n]+) ; "
        r"start_time=\[(?P<start>[^\]\n]+)\] ; stop_time=\[(?P<stop>[^\]\n]+)\] ; "
        r"pid=(?P<pid>[0-9]+) ; code=\((?P<code>[^)\n]+)\) ; "
        r"status=(?P<status>[0-9]+/[0-9]+) \}",
        value,
    )
    if match is None:
        raise AdmissionEvidenceError("final fresh-session ExecStart display changed")
    return (
        (
            match["loaded"],
            match["ignore"],
            match["stop"],
            match["code"],
            match["status"],
        ),
        match["start"],
        int(match["pid"]),
    )


def _normalized_credentials(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, str):
        raise AdmissionEvidenceError("final fresh-session credential type changed")
    match = re.fullmatch(
        r'a\(ss\) (?P<count>[1-9][0-9]*)(?P<pairs>(?: "[^"\n]*"){2,})', value
    )
    if match is None:
        raise AdmissionEvidenceError("final fresh-session credential display changed")
    items = re.findall(r'"([^"\n]*)"', match["pairs"])
    count = int(match["count"])
    if len(items) != count * 2:
        raise AdmissionEvidenceError("final fresh-session credential count changed")
    return tuple(sorted(zip(items[::2], items[1::2], strict=True)))


def _verify_socket_projection(
    actual: Mapping[str, Any], trusted: Mapping[str, Any]
) -> None:
    identities: set[tuple[int, int]] = set()
    for path in trusted:
        record = actual[path]
        expected = trusted[path]
        if set(record) != set(expected) or set(record["metadata"]) != set(
            expected["metadata"]
        ):
            raise AdmissionEvidenceError("final fresh-session socket shape changed")
        metadata = dict(record["metadata"])
        expected_metadata = dict(expected["metadata"])
        inode = metadata.pop("inode")
        expected_metadata.pop("inode")
        if (
            parent.oci_worker_protocol.canonical_json({**record, "metadata": metadata})
            != parent.oci_worker_protocol.canonical_json(
                {**expected, "metadata": expected_metadata}
            )
            or type(inode) is not int
            or inode <= 0
        ):
            raise AdmissionEvidenceError(
                f"final fresh-session socket contract changed: {path}"
            )
        identity = (record["metadata"]["device"], inode)
        if identity in identities:
            raise AdmissionEvidenceError("final fresh-session socket identity reused")
        identities.add(identity)


def _verify_service_state(
    state: Mapping[str, Any],
    *,
    trusted: Mapping[str, Any],
    processes: Mapping[str, Any],
    units: Mapping[str, Any],
    enablement: Mapping[str, Any],
    sockets: Mapping[str, Any],
    container_id: str,
    snapshot_before: str,
) -> None:
    if (
        set(state) != {"sockets", "units"}
        or parent.oci_worker_protocol.canonical_json(state["sockets"])
        != parent.oci_worker_protocol.canonical_json(sockets)
        or set(state["units"]) != set(trusted["units"])
    ):
        raise AdmissionEvidenceError("final fresh-session service state shape changed")
    invocation_ids: set[str] = set()
    dynamic_properties = {
        "ActiveEnterTimestampMonotonic",
        "ControlGroup",
        "ExecMainStartTimestampMonotonic",
        "InvocationID",
        "MainPID",
    }
    dynamic_command = {
        "completed_at",
        "completed_monotonic_ns",
        "elapsed_ns",
        "started_at",
        "started_monotonic_ns",
        "stdout",
    }
    for service in trusted["units"]:
        entry = state["units"][service]
        expected = trusted["units"][service]
        properties = entry["properties"]
        expected_properties = expected["properties"]
        command = entry["command"]
        expected_command = expected["command"]
        pid = processes[service]["pid"]
        if (
            set(entry) != {"cgroup_members", "command", "properties"}
            or set(properties) != set(expected_properties)
            or parent.oci_worker_protocol.canonical_json(
                {
                    key: value
                    for key, value in properties.items()
                    if key not in dynamic_properties
                }
            )
            != parent.oci_worker_protocol.canonical_json(
                {
                    key: value
                    for key, value in expected_properties.items()
                    if key not in dynamic_properties
                }
            )
            or set(command) != set(expected_command)
            or parent.oci_worker_protocol.canonical_json(
                {
                    key: value
                    for key, value in command.items()
                    if key not in dynamic_command
                }
            )
            != parent.oci_worker_protocol.canonical_json(
                {
                    key: value
                    for key, value in expected_command.items()
                    if key not in dynamic_command
                }
            )
            or entry["cgroup_members"] != [str(pid)]
            or properties["MainPID"] != str(pid)
            or properties["ControlGroup"]
            != f"/docker/{container_id}/system.slice/{service}"
            or properties["ControlGroup"] != units[service]["ControlGroup"]
            or properties["UnitFileState"] != enablement[service]
        ):
            raise AdmissionEvidenceError(
                f"final fresh-session service contract changed: {service}"
            )
        _verify_service_command(command, properties)
        invocation_id = properties["InvocationID"]
        start = properties["ExecMainStartTimestampMonotonic"]
        active = properties["ActiveEnterTimestampMonotonic"]
        if (
            not isinstance(invocation_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", invocation_id) is None
            or not isinstance(start, str)
            or re.fullmatch(r"[1-9][0-9]*", start) is None
            or not isinstance(active, str)
            or re.fullmatch(r"[1-9][0-9]*", active) is None
            or int(active) < int(start)
            or abs(int(start) - int(processes[service]["start_time_ticks"]) * 10_000)
            >= 30_000
            or int(active) * 1_000 > command["completed_monotonic_ns"]
            or _parse_time(command["completed_at"]) > _parse_time(snapshot_before)
        ):
            raise AdmissionEvidenceError(
                f"final fresh-session service dynamics changed: {service}"
            )
        invocation_ids.add(invocation_id)
    if len(invocation_ids) != len(trusted["units"]):
        raise AdmissionEvidenceError("final fresh-session service invocation reused")


def _verify_service_command(
    command: Mapping[str, Any], properties: Mapping[str, Any]
) -> None:
    stdout = _decode_record(command["stdout"])
    stderr = _decode_record(command["stderr"])
    try:
        lines = stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise AdmissionEvidenceError(
            "final fresh-session service output changed"
        ) from exc
    pairs = [line.split("=", 1) for line in lines if line.count("=") >= 1]
    if (
        stderr != b""
        or len(lines) != len(properties)
        or len(pairs) != len(lines)
        or len({key for key, _value in pairs}) != len(pairs)
        or dict(pairs) != properties
        or type(command["started_monotonic_ns"]) is not int
        or type(command["completed_monotonic_ns"]) is not int
        or type(command["elapsed_ns"]) is not int
        or command["started_monotonic_ns"] <= 0
        or command["completed_monotonic_ns"] <= command["started_monotonic_ns"]
        or command["elapsed_ns"]
        != command["completed_monotonic_ns"] - command["started_monotonic_ns"]
        or _parse_time(command["started_at"]) > _parse_time(command["completed_at"])
    ):
        raise AdmissionEvidenceError("final fresh-session service snapshot changed")


def _verify_gateway_listener(
    listener: Mapping[str, Any], processes: Mapping[str, Any]
) -> None:
    if set(listener) != {"fd_owners", "listener", "pid", "proc_net_tcp"}:
        raise AdmissionEvidenceError("final fresh-session listener shape changed")
    try:
        tcp = _decode_record(listener["proc_net_tcp"]).decode("ascii")
    except UnicodeDecodeError as exc:
        raise AdmissionEvidenceError(
            "final fresh-session listener bytes changed"
        ) from exc
    lines = tcp.splitlines()
    data_lines = [line for line in lines[1:] if line]
    matches = [
        line
        for line in data_lines
        if len(line.split()) >= 10
        and line.split()[1] == "0100007F:4965"
        and line.split()[2] == "00000000:0000"
        and line.split()[3] == "0A"
        and line.split()[7] == "992"
    ]
    gateway_pid = processes["aragorn-agent-gateway.service"]["pid"]
    if len(lines) != 2 or len(data_lines) != 1 or len(matches) != 1:
        raise AdmissionEvidenceError("final fresh-session listener inventory changed")
    match = matches[0]
    inode = int(match.split()[9])
    if (
        listener["pid"] != gateway_pid
        or type(listener["listener"]["inode"]) is not int
        or listener["listener"] != {"inode": inode, "line": match}
        or inode <= 0
        or not isinstance(listener["fd_owners"], list)
        or len(listener["fd_owners"]) != 1
        or re.fullmatch(
            rf"/proc/{gateway_pid}/fd/[1-9][0-9]*", listener["fd_owners"][0]
        )
        is None
    ):
        raise AdmissionEvidenceError("final fresh-session gateway listener changed")


def _decode_route_raw(value: Mapping[str, Any]) -> dict[str, Any]:
    if (
        set(value)
        != {"base64", "bytes", "canonical_digest", "digest", "raw_is_canonical_json_lf"}
        or value["bytes"] != _ROUTE_RAW["bytes"]
        or value["digest"] != _ROUTE_RAW["digest"]
        or value["canonical_digest"] != _ROUTE_RAW["canonical_digest"]
        or value["raw_is_canonical_json_lf"] is not False
    ):
        raise AdmissionEvidenceError("final fresh-session raw route identity changed")
    raw = base64.b64decode(value["base64"], validate=True)
    if len(raw) != _ROUTE_RAW["bytes"] or _digest(raw) != _ROUTE_RAW["digest"]:
        raise AdmissionEvidenceError("final fresh-session raw route bytes changed")
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=parent._reject_duplicates,
            parse_constant=parent._reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(
            f"invalid final fresh-session nested JSON: {exc}"
        ) from exc
    canonical = parent.oci_worker_protocol.canonical_json(document)
    if (
        not isinstance(document, dict)
        or len(canonical) != _ROUTE_RAW["canonical_bytes"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or raw == canonical + b"\n"
        or not raw.endswith(b"\n")
        or b"\n" in raw[:-1]
        or b"\r" in raw
    ):
        raise AdmissionEvidenceError(
            "final fresh-session parsed route identity changed"
        )
    return document


def _verify_execution(
    execution: Mapping[str, Any],
    gateway_pid: int,
    route_recorded_at: str,
    outer_recorded_at: str,
) -> None:
    expected_argv = [
        "nsenter",
        "--target",
        str(gateway_pid),
        "--mount",
        "--",
        "setpriv",
        "--reuid=992",
        "--regid=992",
        "--groups=992",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--bounding-set=-all",
        "--no-new-privs",
        _NODE,
        "/route-input/probe/protected-route-probe.mjs",
        "--route-id",
        _ROUTE,
    ]
    if (
        execution["argv"] != expected_argv
        or execution["effective_identity"] != {"uid": 992, "gid": 992, "groups": [992]}
        or execution["environment_names"]
        != sorted(
            {
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
            }
        )
        or execution["exit_code"] != 0
        or execution["stderr"] != {"bytes": 0, "digest": _digest(b""), "excerpt": ""}
        or not (
            _parse_time(execution["started_at"])
            < _parse_time(route_recorded_at)
            <= _parse_time(execution["completed_at"])
            < _parse_time(outer_recorded_at)
        )
    ):
        raise AdmissionEvidenceError("final fresh-session route execution changed")


def _verify_route_document(
    document: Mapping[str, Any], execution: Mapping[str, Any], *, container_id: str
) -> None:
    nonce = document["run_nonce"]
    route = {
        "action_id": "fresh-session-reset",
        "id": _ROUTE,
        "reason_codes": [],
        "status": "OBSERVED",
    }
    if (
        _canonical_digest(document) != _ROUTE_RAW["canonical_digest"]
        or set(document)
        != {
            "actions",
            "assurance",
            "implementation_digest",
            "protected_boundary",
            "recorded_at",
            "routes",
            "run_nonce",
            "runtime_binding",
            "schema",
            "selected_route_ids",
        }
        or document["schema"]
        != "aragorn/openclaw-protected-route-action-observations/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digest"] != _PROBE["digest"]
        or document["runtime_binding"]
        != {
            "commit": parent._OPENCLAW["commit"],
            "node_path": _NODE,
            "openclaw_digest": parent._RUNTIME["entrypoint_digest"],
            "openclaw_path": _OPENCLAW,
            "version": parent._OPENCLAW["version"],
        }
        or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
        or document["selected_route_ids"] != [_ROUTE]
        or document["routes"] != [route]
        or len(document["actions"]) != 1
    ):
        raise AdmissionEvidenceError("final fresh-session route document changed")
    _verify_boundary(document["protected_boundary"])
    _verify_action(
        document["actions"][0],
        nonce=nonce,
        recorded_at=document["recorded_at"],
        execution=execution,
        container_id=container_id,
    )


def _verify_boundary(boundary: Mapping[str, Any]) -> None:
    _verify_signed_nested_object(boundary, "protected_boundary")
    roots = {
        "extensions": "/var/lib/aragorn-agent-gateway/state/extensions",
        "managed_skills": "/var/lib/aragorn-agent-gateway/state/skills",
        "personal_agents": "/var/lib/aragorn-agent-gateway/home/.agents/skills",
        "plugin_skills": "/var/lib/aragorn-agent-gateway/state/plugin-skills",
        "project_agents": ("/var/lib/aragorn-agent-gateway/workspace/.agents/skills"),
        "workspace_skills": "/var/lib/aragorn-agent-gateway/workspace/skills",
    }
    config = boundary["configuration"]
    file = config["file"]
    runtime = boundary["runtime"]
    expected_config_mount = {
        "entry": {
            "device": 81,
            "entries": ["openclaw-config"],
            "entries_truncated": False,
            "entry_count": 1,
            "exists": True,
            "gid": 0,
            "inode": 225_036,
            "mode": "500",
            "nlink": 2,
            "path": "/run/credentials/aragorn-agent-gateway.service",
            "size": 0,
            "type": "directory",
            "uid": 992,
        },
        "error": None,
        "explicit": True,
        "path": "/run/credentials/aragorn-agent-gateway.service",
        "read_only": True,
        "ready": True,
        "records": [
            {
                "filesystem": "ramfs",
                "mount_options": ["nodev", "noexec", "nosuid", "relatime", "ro"],
                "mount_point": "/run/credentials/aragorn-agent-gateway.service",
                "root": "/",
                "source": "ramfs",
                "super_options": ["mode=700", "rw"],
            }
        ],
    }
    expected_runtime = {
        "entry": {
            "device": 64_785,
            "entries": ["bin", "lib"],
            "entries_truncated": False,
            "entry_count": 2,
            "exists": True,
            "gid": 0,
            "inode": 262_290,
            "mode": "755",
            "nlink": 4,
            "path": "/runtime",
            "size": 4_096,
            "type": "directory",
            "uid": 0,
        },
        "error": None,
        "explicit": True,
        "path": "/runtime",
        "read_only": True,
        "ready": True,
        "records": [
            {
                "filesystem": "ext4",
                "mount_options": ["nosuid", "relatime", "ro"],
                "mount_point": "/runtime",
                "root": f"/docker/volumes/{parent._RUNTIME['runtime_volume']}/_data",
                "source": "/dev/vdb1",
                "super_options": ["rw"],
            }
        ],
    }
    if (
        _canonical_digest(boundary) != _ENVELOPES["boundary"]
        or set(boundary)
        != {"configuration", "effective_identity", "ready", "roots", "runtime"}
        or boundary["ready"] is not True
        or boundary["effective_identity"] != {"uid": 992, "gid": 992}
        or set(boundary["roots"]) != set(roots)
        or config["ready"] is not True
        or config["parse_error"] is not None
        or config["json_object"] is not True
        or config["canonical_digest"]
        != parent._SOURCES["configuration"]["canonical_digest"]
        or config["expected_canonical_digest"]
        != parent._SOURCES["configuration"]["canonical_digest"]
        or file
        != {
            "device": 81,
            "digest": parent._SOURCES["configuration"]["canonical_digest"],
            "digest_error": None,
            "exists": True,
            "gid": 0,
            "inode": 225037,
            "mode": "400",
            "nlink": 1,
            "path": "/run/credentials/aragorn-agent-gateway.service/openclaw-config",
            "size": parent._SOURCES["configuration"]["canonical_bytes"],
            "type": "file",
            "uid": 992,
        }
        or parent.oci_worker_protocol.canonical_json(config["mount"])
        != parent.oci_worker_protocol.canonical_json(expected_config_mount)
        or parent.oci_worker_protocol.canonical_json(runtime)
        != parent.oci_worker_protocol.canonical_json(expected_runtime)
    ):
        raise AdmissionEvidenceError("final fresh-session protected boundary changed")
    for name, path in roots.items():
        value = boundary["roots"][name]
        entry = value["observation"]
        if (
            value["ready"] is not True
            or value["writable"] is not True
            or entry["path"] != path
            or entry["exists"] is not True
            or entry["type"] != "directory"
            or entry["uid"] != 992
            or entry["gid"] != 992
            or entry["mode"] != "700"
            or entry["entries"] != []
            or entry["entry_count"] != 0
            or entry["entries_truncated"] is not False
        ):
            raise AdmissionEvidenceError(
                f"final fresh-session discovery root changed: {name}"
            )


def _verify_action(
    action: Mapping[str, Any],
    *,
    nonce: str,
    recorded_at: str,
    execution: Mapping[str, Any],
    container_id: str,
) -> None:
    before = action["prerequisites"]
    observed = action["observations"]
    initial = observed["initialization_turn"]
    rebuild = observed["rebuild_turn"]
    commands = [*before["commands"], *action["commands"]]
    if (
        _canonical_digest(action) != _ENVELOPES["action"]
        or set(action)
        != {
            "commands",
            "execution_error",
            "id",
            "observations",
            "prerequisites",
            "reason_codes",
            "status",
        }
        or action["id"] != "fresh-session-reset"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or parent.oci_worker_protocol.canonical_json(action["commands"])
        != parent.oci_worker_protocol.canonical_json(
            [*initial["commands"], *rebuild["commands"]]
        )
        or [item["pid"] for item in commands] != [3314, 3321, 3333, 3345, 3357, 3369]
        or len({item["pid"] for item in commands}) != len(commands)
        or any(
            _parse_time(left["completed_at"]) > _parse_time(right["started_at"])
            for left, right in pairwise(commands)
        )
        or not (
            _parse_time(execution["started_at"])
            <= _parse_time(commands[0]["started_at"])
            < _parse_time(commands[-1]["completed_at"])
            <= _parse_time(recorded_at)
        )
    ):
        raise AdmissionEvidenceError("final fresh-session action changed")
    _verify_prerequisites(before, container_id=container_id)
    _verify_turn(
        initial, label="fresh-session-initialize", nonce=nonce, pids=(3333, 3345)
    )
    _verify_turn(rebuild, label="fresh-session-rebuild", nonce=nonce, pids=(3357, 3369))
    _verify_transition(observed, nonce=nonce, recorded_at=recorded_at)


def _verify_prerequisites(before: Mapping[str, Any], *, container_id: str) -> None:
    commands = before["commands"]
    gateway = before["gateway_process"]
    runtime_files = before["runtime_files"]
    _verify_signed_nested_object(runtime_files, "runtime_files")
    _verify_signed_nested_object(before["system_info"], "system_info")
    if (
        set(before)
        != {
            "commands",
            "gateway_process",
            "ready",
            "reason_codes",
            "runtime_files",
            "system_info",
        }
        or before["ready"] is not True
        or before["reason_codes"] != []
        or gateway
        != {
            "cmdline": ["openclaw-gateway"],
            "hostname": "e9c2570949ba",
            "pid": 2946,
            "start_time_ticks": "6593232",
        }
        or gateway["hostname"] != container_id[:12]
        or len(commands) != 2
        or before["system_info"]["command"] != commands[1]
        or before["system_info"]["response"]["parsed"] is not True
        or before["system_info"]["response"]["value"]["pid"] != gateway["pid"]
        or before["system_info"]["response"]["value"]["hostname"] != gateway["hostname"]
        or before["system_info"]["response"]["value"]["machineName"]
        != gateway["hostname"]
        or before["system_info"]["response"]["value"]["diskPath"]
        != "/var/lib/aragorn-agent-gateway/state"
    ):
        raise AdmissionEvidenceError("final fresh-session prerequisites changed")
    node = runtime_files["node"]
    openclaw = runtime_files["openclaw"]
    if (
        node["executable"] is not True
        or node["file"]["path"] != _NODE
        or node["file"]["exists"] is not True
        or node["file"]["type"] != "file"
        or node["file"]["size"] != 121_333_752
        or type(node["file"]["nlink"]) is not int
        or node["file"]["nlink"] != 1
        or node["file"]["digest"] is not None
        or node["file"]["digest_error"] != "FILE_EXCEEDS_CONTROL_LIMIT"
        or node["file"]["uid"] != 0
        or node["file"]["gid"] != 0
        or node["file"]["mode"] != "755"
        or openclaw["executable"] is not True
        or openclaw["file"]["path"] != _OPENCLAW
        or openclaw["file"]["exists"] is not True
        or openclaw["file"]["type"] != "file"
        or openclaw["file"]["digest"] != parent._RUNTIME["entrypoint_digest"]
        or openclaw["file"]["digest_error"] is not None
        or openclaw["file"]["uid"] != 0
        or openclaw["file"]["gid"] != 0
        or openclaw["file"]["mode"] != "755"
        or type(openclaw["file"]["nlink"]) is not int
        or openclaw["file"]["nlink"] != 1
        or openclaw["file"]["size"] != 23_463
    ):
        raise AdmissionEvidenceError("final fresh-session runtime files changed")
    _verify_command(
        commands[0],
        [_NODE, _OPENCLAW, "--version"],
        expected_pid=3314,
        stdout_exact=parent._RUNTIME["version_output"] + "\n",
    )
    _verify_command(
        commands[1],
        _gateway_argv("system.info", "5000"),
        expected_pid=3321,
        stdout_value=before["system_info"]["response"]["value"],
    )


def _gateway_argv(
    method: str, timeout: str, params: Mapping[str, Any] | None = None
) -> list[str]:
    argv = [_NODE, _OPENCLAW, "gateway", "call", method, "--json", "--timeout", timeout]
    if params is not None:
        argv.extend(
            ["--params", json.dumps(params, sort_keys=True, separators=(",", ":"))]
        )
    return argv


def _verify_command(
    command: Mapping[str, Any],
    argv: list[str],
    *,
    expected_pid: int,
    stdout_value: Mapping[str, Any] | None = None,
    stdout_exact: str | None = None,
) -> None:
    stdout = command["stdout_excerpt"]
    if (
        set(command)
        != {
            "argv",
            "completed_at",
            "error",
            "exit_code",
            "pid",
            "signal",
            "started_at",
            "stderr_bytes",
            "stderr_digest",
            "stderr_excerpt",
            "stdout_bytes",
            "stdout_digest",
            "stdout_excerpt",
        }
        or command["argv"] != argv
        or type(command["pid"]) is not int
        or command["pid"] != expected_pid
        or type(command["exit_code"]) is not int
        or command["exit_code"] != 0
        or command["signal"] is not None
        or command["error"] is not None
        or _parse_time(command["started_at"]) >= _parse_time(command["completed_at"])
        or command["stderr_excerpt"] != ""
        or type(command["stderr_bytes"]) is not int
        or command["stderr_bytes"] < 0
        or command["stderr_bytes"] != 0
        or command["stderr_digest"] != _digest(b"")
        or type(command["stdout_bytes"]) is not int
        or command["stdout_bytes"] < 0
        or command["stdout_bytes"] != len(stdout.encode())
        or command["stdout_digest"] != _digest(stdout.encode())
        or (stdout_exact is not None and stdout != stdout_exact)
    ):
        raise AdmissionEvidenceError("final fresh-session command changed")
    if stdout_value is not None and _strict_json(stdout) != stdout_value:
        raise AdmissionEvidenceError("final fresh-session command output changed")


def _verify_turn(
    turn: Mapping[str, Any], *, label: str, nonce: str, pids: tuple[int, int]
) -> None:
    run_id = f"aragorn-protected-route-{label}-{nonce}"
    message = {
        "fresh-session-initialize": "Inert protected-route session initialization.",
        "fresh-session-rebuild": "Inert protected-route post-reset snapshot rebuild.",
    }[label]
    send_params = {
        "deliver": False,
        "idempotencyKey": run_id,
        "message": message,
        "sessionKey": _SESSION_KEY,
        "timeoutMs": 5000,
    }
    wait_params = {"runId": run_id, "timeoutMs": 10_000}
    send_value = {"runId": run_id, "status": "started"}
    wait_value = {
        "runId": run_id,
        "status": "error",
        "endedAt": turn["wait"]["response"]["value"]["endedAt"],
        "error": _NETWORK_ERROR,
    }
    if (
        set(turn) != {"commands", "confirmed", "send", "wait"}
        or turn["confirmed"] is not True
        or set(turn["send"]) != {"command", "response"}
        or set(turn["wait"]) != {"command", "response"}
        or parent.oci_worker_protocol.canonical_json(turn["commands"])
        != parent.oci_worker_protocol.canonical_json(
            [turn["send"]["command"], turn["wait"]["command"]]
        )
        or turn["send"]["response"].get("parsed") is not True
        or turn["send"]["response"] != {"parsed": True, "value": send_value}
        or turn["wait"]["response"].get("parsed") is not True
        or turn["wait"]["response"] != {"parsed": True, "value": wait_value}
        or type(wait_value["endedAt"]) is not int
        or wait_value["endedAt"] <= 0
        or not (
            _epoch_ms(turn["wait"]["command"]["started_at"])
            <= wait_value["endedAt"]
            <= _epoch_ms(turn["wait"]["command"]["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("final fresh-session terminal turn changed")
    _verify_command(
        turn["send"]["command"],
        _gateway_argv("chat.send", "5000", send_params),
        expected_pid=pids[0],
        stdout_value=send_value,
    )
    _verify_command(
        turn["wait"]["command"],
        _gateway_argv("agent.wait", "12000", wait_params),
        expected_pid=pids[1],
        stdout_value=wait_value,
    )


def _verify_transition(
    observed: Mapping[str, Any], *, nonce: str, recorded_at: str
) -> None:
    before = observed["session_before_reset"]
    rotated = observed["session_after_rotation"]
    after = observed["session_after_reset"]
    reset = observed["reset_turn"]
    reset_id = f"aragorn-protected-route-fresh-session-reset-{nonce}"
    before_id = "55919938-328f-4b07-a4a5-f3f23318e423"
    after_id = "e874d51d-6f99-4fb2-9710-70041245af1f"
    if (
        set(observed)
        != {
            "initialization_turn",
            "rebuild_turn",
            "rebuilt_snapshot_matches_baseline",
            "reset_snapshot_cleared",
            "reset_turn",
            "rotation_observed_at",
            "session_after_reset",
            "session_after_reset_check",
            "session_after_rotation",
            "session_before_reset",
            "session_before_reset_check",
            "session_id_rotated",
        }
        or observed["session_id_rotated"] is not True
        or observed["reset_snapshot_cleared"] is not True
        or observed["rebuilt_snapshot_matches_baseline"] is not True
        or set(observed["session_before_reset_check"]) != set(_READY_CHECK)
        or any(
            observed["session_before_reset_check"][key] is not True
            for key in _READY_CHECK
        )
        or set(observed["session_after_reset_check"]) != set(_READY_CHECK)
        or any(
            observed["session_after_reset_check"][key] is not True
            for key in _READY_CHECK
        )
        or _UUID4.fullmatch(before_id) is None
        or _UUID4.fullmatch(after_id) is None
        or before["entry"]["session_id"] != before_id
        or after["entry"]["session_id"] != after_id
        or rotated["entry"]["session_id"] != after_id
        or reset["accepted"] is not True
        or reset["params"]["deliver"] is not False
        or reset
        != {
            "accepted": True,
            "completed_at": "2026-08-13T21:44:42.967Z",
            "error": None,
            "method": "chat.send",
            "params": {
                "deliver": False,
                "idempotencyKey": reset_id,
                "message": "/new",
                "sessionKey": _SESSION_KEY,
                "timeoutMs": 5000,
            },
            "response": {"runId": reset_id, "status": "started"},
            "scopes": ["operator.admin", "operator.write"],
            "started_at": "2026-08-13T21:44:42.928Z",
            "transport": "openclaw/plugin-sdk/gateway-runtime.callGatewayFromCli",
        }
    ):
        raise AdmissionEvidenceError("final fresh-session reset transition changed")
    _verify_snapshot(before, label="before", session_id=before_id)
    _verify_rotated_snapshot(rotated, session_id=after_id)
    _verify_snapshot(after, label="after", session_id=after_id)
    initial = observed["initialization_turn"]
    rebuild = observed["rebuild_turn"]
    if (
        before["entry"]["prompt"] != after["entry"]["prompt"]
        or before["entry"]["skill_names"] != after["entry"]["skill_names"]
        or before["entry"]["snapshot_version"] != after["entry"]["snapshot_version"]
        or len(
            {before["file"]["inode"], rotated["file"]["inode"], after["file"]["inode"]}
        )
        != 3
        or not (
            _parse_time(initial["wait"]["command"]["completed_at"])
            <= _parse_time(reset["started_at"])
            <= _parse_time(reset["completed_at"])
            <= _parse_time(observed["rotation_observed_at"])
            <= _parse_time(rebuild["send"]["command"]["started_at"])
            < _parse_time(recorded_at)
        )
        or not (
            _epoch_ms(initial["send"]["command"]["completed_at"])
            <= before["entry"]["started_at"]
            <= before["entry"]["ended_at"]
            <= before["entry"]["updated_at"]
            <= initial["wait"]["response"]["value"]["endedAt"]
            <= _epoch_ms(initial["wait"]["command"]["completed_at"])
        )
        or not (
            _epoch_ms(rebuild["send"]["command"]["completed_at"])
            <= after["entry"]["started_at"]
            <= after["entry"]["ended_at"]
            <= after["entry"]["updated_at"]
            <= rebuild["wait"]["response"]["value"]["endedAt"]
            <= _epoch_ms(rebuild["wait"]["command"]["completed_at"])
        )
    ):
        raise AdmissionEvidenceError("final fresh-session custody or timing changed")


def _verify_snapshot(
    snapshot: Mapping[str, Any], *, label: str, session_id: str
) -> None:
    expected = {
        "before": {
            "digest": "sha256:f884d626278e4828243fef5925ca51d1432f4f4b0569c08f6e46f71b72366e79",
            "runtime_ms": 1287,
            "started_at": 1786657481613,
            "ended_at": 1786657482900,
            "updated_at": 1786657482903,
            "store_digest": "sha256:577bec39912d5d71d3b3d40eccc0555dbfd512e55abfb7ebb1c106f743e06eef",
            "store_inode": 1114935,
            "store_size": 6242,
        },
        "after": {
            "digest": "sha256:ee7f9af781f4939c008c54c545f1ffaa714b6771c1bd303d83f96d6f53fbbea7",
            "runtime_ms": 1440,
            "started_at": 1786657483879,
            "ended_at": 1786657485319,
            "updated_at": 1786657485322,
            "store_digest": "sha256:752d748f5ed5e94b5bf3dcaa9d6b523d38353793c0426d743ea2dd01c4504e3c",
            "store_inode": 1114939,
            "store_size": 6435,
        },
    }[label]
    entry = snapshot["entry"]
    prompt = entry["prompt"]
    file = prompt["file"]
    store = snapshot["file"]
    prompt_digest = (
        "sha256:60f42ebfec9cc92e1819496ec6340adf3584da099524d40e2b1ba918e271b501"
    )
    if (
        _canonical_digest(snapshot) != expected["digest"]
        or snapshot["present"] is not True
        or entry["session_id"] != session_id
        or entry["skill_names"] != ["template-skill"]
        or entry["snapshot_present"] is not True
        or entry["snapshot_version"] != 1786657468064
        or entry["status"] != "timeout"
        or entry["runtime_ms"] != expected["runtime_ms"]
        or entry["started_at"] != expected["started_at"]
        or entry["ended_at"] != expected["ended_at"]
        or entry["updated_at"] != expected["updated_at"]
        or prompt["storage"] != "promptRef"
        or prompt["bytes"] != 737
        or prompt["digest"] != prompt_digest
        or prompt["expected_digest"] != prompt_digest
        or file
        != {
            "device": 45,
            "digest": prompt_digest,
            "digest_error": None,
            "exists": True,
            "gid": 992,
            "inode": 1112528,
            "mode": "600",
            "nlink": 1,
            "path": (
                "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/"
                "skills-prompts/sha256/60/"
                "60f42ebfec9cc92e1819496ec6340adf3584da099524d40e2b1ba918e271b501.txt"
            ),
            "size": 737,
            "type": "file",
            "uid": 992,
        }
        or store
        != {
            "device": 45,
            "digest": expected["store_digest"],
            "digest_error": None,
            "exists": True,
            "gid": 992,
            "inode": expected["store_inode"],
            "mode": "600",
            "nlink": 1,
            "path": "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/sessions.json",
            "size": expected["store_size"],
            "type": "file",
            "uid": 992,
        }
    ):
        raise AdmissionEvidenceError(f"final fresh-session {label} snapshot changed")


def _verify_rotated_snapshot(snapshot: Mapping[str, Any], *, session_id: str) -> None:
    if (
        _canonical_digest(snapshot)
        != "sha256:6a62cb92762823b3e15cf5c8739915d64ecc5ee8d23e66c600cff64cea539b6c"
        or snapshot
        != {
            "entry": {
                "ended_at": None,
                "prompt": {
                    "bytes": None,
                    "digest": None,
                    "storage": "absent-or-invalid",
                },
                "runtime_ms": None,
                "session_id": session_id,
                "skill_names": [],
                "snapshot_present": False,
                "snapshot_version": None,
                "started_at": None,
                "status": None,
                "updated_at": 1786657482973,
            },
            "file": {
                "device": 45,
                "digest": "sha256:4cafc71533ecb20750658814b6c4122a77760b2fb36a974d4a5e620140991186",
                "digest_error": None,
                "exists": True,
                "gid": 992,
                "inode": 1114936,
                "mode": "600",
                "nlink": 1,
                "path": "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/sessions.json",
                "size": 5905,
                "type": "file",
                "uid": 992,
            },
            "present": True,
        }
    ):
        raise AdmissionEvidenceError("final fresh-session cleared snapshot changed")


def _strict_json(value: str) -> Any:
    try:
        return json.loads(
            value,
            object_pairs_hook=parent._reject_duplicates,
            parse_constant=parent._reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise AdmissionEvidenceError(
            f"invalid final fresh-session command JSON: {exc}"
        ) from exc


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise AdmissionEvidenceError("final fresh-session timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def _epoch_ms(value: str) -> int:
    return int(_parse_time(value).timestamp() * 1000)
