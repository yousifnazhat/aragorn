"""Qualify one V2 archive replacement route without broad authority."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from copy import deepcopy
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_final_combined_v2_config_activation as base
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError

_ROUTE = "ADM-02/update/archive-source-force-replacement"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v2"
_SOURCE_ROOT = "/sources/replacement"
_TARGET_ROOT = "/opt/aragorn/runtime-profile/template-skill"
_WORKSPACE_SKILLS = "/var/lib/aragorn-agent-gateway/workspace/skills"
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_ROUTE_VOLUME = "aragorn-phase3-final-combined-v2-route-input-70754"
_ARCHIVE_VOLUME = "aragorn-phase3-final-combined-v2-archive-source-70754"
_EMPTY_DIGEST = "sha256:" + hashlib.sha256(b"").hexdigest()

_BASE = {
    "digest": (
        "sha256:3caf8e9955de6355717f16ed420c5785a4e5495c5575763964863001d8cdeae6"
    ),
    "path": "src/aragorn/admission_protected_final_combined_v2_config_activation.py",
}
_EVIDENCE = {
    "bytes": 451_702,
    "canonical_bytes": 451_701,
    "canonical_digest": (
        "sha256:96448b65ae590033408f43fe62df57bffe64706496985d63ec348e75982dddd6"
    ),
    "digest": (
        "sha256:3f6c258002ee8bd02ca764151145dbf11e58ecf80558f4635a773b6504d37e5b"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v2-route-"
        "archive-source-force-replacement-systemd-p3-final-source-fixed-"
        "2026-08-22.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 31_129,
    "canonical_digest": (
        "sha256:3dd737c6759fca730ff2d6a16a076267c945149cc56b3af6a2dbc6e7cda7fd66"
    ),
    "digest": (
        "sha256:8d3ab8bfc39ccaeeb49c5062ef18ef64f3a70bdc4e4e5ea66c4878fb549a19ab"
    ),
}
_SOURCE = {
    "commit": "805ba91ffa9aaeb9acbf44166b0c774fd6ee010c",
    "parent": "e6c81f797c1b948da21e2271e4b247522b9af215",
    "tree": "03822662024a43ac28e6879fc8ebaf5e606623f9",
}
_RETENTION = {
    "commit": "38bfa5d6b830906946ac3a1e8526ec937a3ddf7c",
    "parent": _SOURCE["commit"],
    "tree": "38c71572c04cd4ddfd5a69ec7848cb1410cfad35",
}
_RETENTION_BLOB = "ea7197d6d3b9e782eb03b7e1feffb862f45ced21"
_IMAGE = "sha256:d6d3015f4ef174eb873241f2a5935f78278b6c763e598253fd235c00faf975d7"
_PARENT_IMAGE = (
    "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
)
_PROBE = {
    "bytes": 25_498,
    "digest": (
        "sha256:4ead71ad73da16579fb85bc1287cb760a8b8b90838de9a9ea0ad2091fca87479"
    ),
    "name": "protected-archive-replacement-probe.mjs",
}
_SOURCE_ARTIFACTS = {
    "collector": {
        "bytes": 10_887,
        "digest": (
            "sha256:85760e3914ef07278295caf411980bc6362b9c87b15ffc91c1390c206331b642"
        ),
        "path": "/src/scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py",
    },
    "materializer": {
        "bytes": 74_674,
        "digest": (
            "sha256:bd3e6092a4c802f0026535fdb14b248a7216c5088a6a192ba902f25aba75c09c"
        ),
        "path": "/src/scripts/materialize_fixed_admission_probes.py",
    },
    "v1_route_injector": {
        "bytes": 20_729,
        "digest": (
            "sha256:18f6fe8c98c64aaf59c6c35d4785780da2a4dc3ac2a719ac72941dd3ab1a1664"
        ),
        "path": "/src/scripts/runtime_action_worker_final_route_systemd_probe.py",
    },
}
_DIGESTS = {
    "action": "sha256:feb9038a4715df97ce04c4b39b35e67f36dd366b6314430733b01b6bfb0050cb",
    "composition": (
        "sha256:7ab4470ffa44b05fac7c0543e335d8d686e6e4d259b161e7cdd5044c372cc901"
    ),
    "composition_action": (
        "sha256:5b028cf7c9778516badfb864f334ac0085c599aa9d34bd8657caf92a05a622c0"
    ),
    "execution": (
        "sha256:0d348d1672c9056b09603e3f50e84612338b2ec2f104be2bc170c7fa9ea877ba"
    ),
    "gateway_binding": (
        "sha256:c7406a39c5c5c0b333f28b2380581ffe72cca5500325d9bc4e0b25fde9794687"
    ),
    "harness": (
        "sha256:a731aa18649e894c496e674092b0c9df2926a0330b4d1fc1a8be8758d7f0ca00"
    ),
    "host_config": (
        "sha256:7179683bb96a1ef2c9093b83c005c8d69edeef05879eef1b665cc1514198f40f"
    ),
    "source_artifacts": (
        "sha256:6be0265397ba5c2b59e4c4bf9a934e22104f63dc95130a79b2f460c1d4460d97"
    ),
    "stack": "sha256:411ca8f02eaed18ab587b63d9e2c527528b6481a163b5d2f5ad3ec5330feba2a",
}
_STATIC_DIGESTS = {
    "boundary_after": (
        "sha256:466f2cf4382ad1c3203ca98fa02630b688c42093ba5581d62ffa8aa6faa57e07"
    ),
    "boundary_before": (
        "sha256:b6471bdd1ededbd265e4e0ae264f4f50d7093e742d19eea454f0f3713a68f7dd"
    ),
    "discovery_after": (
        "sha256:773251e6418261673cc15267600cd506171477326d0e9992dd69579caf8febcf"
    ),
    "discovery_before": (
        "sha256:199559efe54fd247c20c3ed8b6a98851c09c3b31ff728914efa4064367c0e713"
    ),
    "gateway": "sha256:6b704618f84b5894656d8cd2ae7bb7691d9eff2bc1ff17024310074208c62ef0",
    "openclaw": "sha256:9fb51d4462f014dc9d86a349adafd2007d69f3f3658a0ddebffaf62451565e57",
    "positive_control": (
        "sha256:1fa6d628372d6bd3e1d668201a83f618110c376793fc6fbf3ef3aae81b025688"
    ),
    "runtime_tree": (
        "sha256:d50dd0e151492afe35222106e0859cdecdbd200345fe2d8abfa393f5179d257b"
    ),
    "source": "sha256:451c3fdf18e541e8e33f2ac27c70da1e1512df096ad16563db0fb47e0a2a22e8",
    "source_install": (
        "sha256:8ff41d27bbd48c12aaa49352dde91addac4571e3cdb23a133733f23301f45745"
    ),
    "system": "sha256:3ba5bc451bbad06c464063e88d4dcda24964994859889c30b41ea12eadeb6113",
    "target": "sha256:951685b1267f0d1b668bca18e185c5ebe95cff25b64be3146672a2e47f8fd782",
    "upload_begin": (
        "sha256:400e65a7341457a93340101abd70bdc20e9086f4d17cbf32655992d55c90c4be"
    ),
    "upload_install": (
        "sha256:706cbc9fbe7d3af0bd4de5d2db2c449fb346204bb4362161296d876cf4227533"
    ),
    "version": "sha256:29c70d228925a64d31817bfd643ad55a90e99a6604c307d6a0d5c32154882344",
}
_SOURCE_BYTES = (
    b"---\n"
    b"name: requesting-code-review\n"
    b"description: Inert protected archive replacement source v2.\n"
    b"---\n\n"
    b"This replacement fixture performs no actions.\n"
)
_SOURCE_DIGEST = (
    "sha256:d30e0a2e568941e37c5f9427b920917a9edf694beadb41f8a5469e820c0dfdf1"
)
_SOURCE_TREE_DIGEST = (
    "sha256:88557624b787a629c415ff9bf2924269bea8e1bce1fb08144ec990b4426a5a75"
)
_TARGET_DIGEST = base._SOURCES["skill"]["digest"]
_INSTALL_ARGV = [
    "/usr/local/bin/node",
    "/runtime/lib/node_modules/openclaw/openclaw.mjs",
    "skills",
    "install",
    _SOURCE_ROOT,
    "--as",
    "template-skill",
    "--force",
    "--agent",
    "main",
]
_INFO_ARGV = [
    "/usr/local/bin/node",
    "/runtime/lib/node_modules/openclaw/openclaw.mjs",
    "skills",
    "info",
    "template-skill",
    "--agent",
    "main",
    "--json",
]
_CATALOG_REJECTION = (
    "Error: External skill activation authority rejected the catalog: selected "
    "skill set differs from the declared sources\n"
)


def verify_openclaw_final_combined_v2_archive_replacement(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return exact 1/20 coverage for post-write activation prevention."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = base.base.legacy.parent._read_blob(
            evidence_cas, _EVIDENCE, "V2 archive replacement"
        )
        if raw != retained:
            raise AdmissionEvidenceError(
                "V2 archive replacement CAS differs from signed retention"
            )
        evidence = base.base.legacy.parent._load_canonical_json(
            raw, _EVIDENCE, "V2 archive replacement"
        )
        profile = _verify_evidence(evidence)
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
            f"invalid V2 archive replacement evidence: {exc}"
        ) from exc

    routes = [
        {
            "id": route["id"],
            "status": "PASS" if route["id"] == _ROUTE else "NOT_TESTED",
        }
        for route in profile["routes"]
    ]
    return {
        "schema": (
            "aragorn/admission-protected-final-combined-v2-archive-source-force-"
            "replacement-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V2_POST_WRITE_ARCHIVE_"
            "ACTIVATION_PREVENTION_ROUTE_ONLY"
        ),
        "bindings": {
            "archive_replacement_observation": {
                **_EVIDENCE,
                "retention": {
                    **_RETENTION,
                    "signing_key": base.base.legacy.parent._SIGNATURE["key"],
                },
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_SOURCE,
                    "signature": dict(base.base.legacy.parent._SIGNATURE),
                },
            },
            "configuration": dict(base._SOURCES["configuration"]),
            "image": _IMAGE,
            "profile": dict(base._SOURCES["profile"]),
            "runtime": dict(base.base.legacy.parent._RUNTIME),
            "runtime_lock": dict(base._SOURCES["runtime_lock"]),
            "skill": dict(base._SOURCES["skill"]),
            "source_artifacts": {
                **{
                    name: dict(identity) for name, identity in _SOURCE_ARTIFACTS.items()
                },
                "probe_bundle": [dict(_PROBE)],
            },
            "verifier_base": dict(_BASE),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
            **{key: False for key in base.base.legacy.parent._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_ARCHIVE_REPLACEMENT_PASS_ONLY",
            "TWENTY_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "DIRECTORY_INSTALL_SUCCEEDED_AND_LEFT_EXCLUDED_WORKSPACE_SKILL_RESIDUE",
            "POST_WRITE_CATALOG_REJECTION_MAY_DENY_SKILL_DISCOVERY_AVAILABILITY",
            "WORKSPACE_RESIDUE_CONTENTS_NOT_DIRECTLY_HASHED_AFTER_INSTALL",
            "ARCHIVE_UPLOAD_PATHS_DENIED_BEFORE_ARCHIVE_INGESTION",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
            "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "profile": {
            "counts": {"PASS": 1, "NOT_TESTED": 20},
            "name": _PROFILE,
            "routes": routes,
        },
        "route_semantics": {
            "dynamically_exercised_routes": [_ROUTE],
            "pass_basis": (
                "SIGNED_EXACT_UPLOAD_DENIAL_AND_EXCLUDED_WORKSPACE_WRITE_"
                "FOLLOWED_BY_EXTERNAL_SINGLETON_CATALOG_REJECTION_WITH_"
                "PROTECTED_TARGET_PRESERVED"
            ),
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(profile["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_digest(value: Any) -> str:
    return _digest(base.base.legacy.parent.oci_worker_protocol.canonical_json(value))


def _verify_dependencies() -> None:
    path = Path(base.__file__).resolve(strict=True)
    expected = (Path(__file__).resolve(strict=True).parent / path.name).resolve(
        strict=True
    )
    if (
        path != expected
        or path.name != Path(_BASE["path"]).name
        or _digest(path.read_bytes()) != _BASE["digest"]
    ):
        raise AdmissionEvidenceError("V2 archive replacement verifier base changed")
    base._verify_dependencies()


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    git = base.base.legacy._git
    if (
        Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve(
            strict=True
        )
        != root
        or git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("V2 archive replacement repository changed")
    base.base._verify_commit(_SOURCE)
    base.base._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError("V2 archive replacement signed tree entry changed")
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=512 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V2 archive replacement signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    base._verify_scalar_types(evidence)
    base._verify_no_positive_eligibility(evidence)
    if (
        set(evidence)
        != {
            "authority",
            "composition",
            "decision",
            "limitations",
            "recorded_at",
            "route_id",
            "route_observation",
            "schema",
            "source_artifacts",
        }
        or evidence["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-route-systemd-observation/v1"
        or evidence["route_id"] != _ROUTE
        or evidence["recorded_at"] != "2026-08-22T10:26:14.967341Z"
        or evidence["authority"]
        != (
            "BOUND_FINAL_COMBINED_V2_RAW_ROUTE_OBSERVATION_ONLY_NOT_ADMISSION_"
            "RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or evidence["decision"]
        != {
            "status": "FINAL_COMBINED_V2_ROUTE_OBSERVED_PROFILE_NOT_TESTED",
            "route_observation_status": "OBSERVED",
            "route_pass_count": 0,
            "route_fail_count": 0,
            "route_not_tested_count": 21,
            **{key: False for key in base.base.legacy.parent._ELIGIBILITY_KEYS},
        }
        or evidence["limitations"]
        != [
            "OBSERVED_IS_NOT_PASS",
            "PROFILE_LEDGER_REMAINS_ZERO_PASS_ZERO_FAIL_TWENTY_ONE_NOT_TESTED",
            "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PROBE_ENTERED_EXACT_GATEWAY_MOUNT_NAMESPACE_FOR_CREDENTIAL_VISIBILITY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
            "SEMANTIC_CONFORMANCE_VERIFIER_NOT_COMPOSED",
            "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ]
        or _canonical_digest(evidence["composition"]) != _DIGESTS["composition"]
        or _canonical_digest(evidence["source_artifacts"])
        != _DIGESTS["source_artifacts"]
    ):
        raise AdmissionEvidenceError("V2 archive replacement wrapper changed")

    profile = _verify_composition(evidence["composition"], evidence["source_artifacts"])
    observation = evidence["route_observation"]
    document = _decode_route_raw(observation["raw"])
    harness = evidence["composition"]["action"]["harness"]["document"]
    if (
        set(observation)
        != {
            "bundle",
            "document",
            "execution",
            "gateway_pid_binding",
            "raw",
            "route",
            "stack_before",
        }
        or document != observation["document"]
        or observation["route"] != document["route"]
        or observation["bundle"] != [_PROBE]
        or observation["bundle"] != evidence["source_artifacts"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("V2 archive replacement nested custody changed")
    _verify_execution(
        observation,
        evidence["composition"]["action"]["boundaries"],
        harness,
    )
    _verify_action(
        document,
        harness=harness,
        execution=observation["execution"],
        composition_recorded_at=evidence["composition"]["recorded_at"],
        outer_recorded_at=evidence["recorded_at"],
    )
    return profile


def _verify_composition(
    composition: Mapping[str, Any], source_artifacts: Mapping[str, Any]
) -> Mapping[str, Any]:
    if (
        set(composition)
        != {
            "action",
            "authority",
            "bindings",
            "decision",
            "limitations",
            "profile",
            "recorded_at",
            "schema",
        }
        or composition["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-systemd-observation/v1"
        or composition["recorded_at"] != "2026-08-22T10:26:14.967106Z"
        or composition["authority"]
        != (
            "BOUNDED_FINAL_COMBINED_V2_P3_7C_ACTION_OBSERVATION_ONLY_PROFILE_"
            "ROUTES_REMAIN_NOT_TESTED_NOT_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or composition["bindings"]
        != {
            "config_materialization": "canonical_json_without_trailing_lf",
            "network": "none",
            "openclaw_test_fast": "absent",
            "runtime_digest": base._RUNTIME_TREE["tree_digest"],
            "runtime_volume": _RUNTIME_VOLUME,
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": _TARGET_DIGEST,
        }
        or composition["decision"]
        != {
            "admission_profile_eligible": False,
            "aggregate_admission_eligible": False,
            "edr_eligible": False,
            "installer_work_eligible": False,
            "p3_7c_activation_action_observed": True,
            "phase3_exit_eligible": False,
            "release_eligible": False,
            "route_fail_count": 0,
            "route_not_tested_count": 21,
            "route_pass_count": 0,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "run_eligible": False,
            "status": "FINAL_COMBINED_V2_ACTION_OBSERVED_PROFILE_NOT_TESTED",
        }
    ):
        raise AdmissionEvidenceError("V2 archive replacement composition changed")

    action = composition["action"]
    profile_before = composition["profile"]["before"]
    profile_after = composition["profile"]["after"]
    profile = profile_after["document"]
    source = action["artifacts"]["final_combined_v2"]
    if (
        _canonical_digest(action) != _DIGESTS["composition_action"]
        or profile_before != profile_after
        or profile_before != source["profile"]
        or action["inputs"]["gateway_config"] != source["config"]["document"]
        or profile["name"] != _PROFILE
        or [route["id"] for route in profile["routes"]]
        != list(base.base.legacy.parent._ROUTES)
        or any(route["outcome"] != "NOT_TESTED" for route in profile["routes"])
        or profile_after["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or profile["runtime"]
        != {
            **base.base.legacy.parent._OPENCLAW,
            "name": "openclaw-protected-final-combined-v2",
        }
        or action["runtime"]
        != {
            "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "entrypoint_digest": base.base.legacy.parent._RUNTIME["entrypoint_digest"],
            "expected_version": base.base.legacy.parent._RUNTIME["version_output"],
            "root": "/runtime",
            "tree": base._RUNTIME_TREE,
            "version_output": base.base.legacy.parent._RUNTIME["version_output"],
        }
    ):
        raise AdmissionEvidenceError("V2 archive replacement profile changed")
    base._verify_configuration(source)
    _verify_source_artifacts(source_artifacts)
    _verify_harness(action["harness"], action["identities"], action["secret_checks"])
    return profile


def _verify_source_artifacts(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError("V2 archive replacement source bundle changed")
    for name, identity in _SOURCE_ARTIFACTS.items():
        base._verify_bound_file(
            value[name], identity, path=identity["path"], mode="0555"
        )
    if value["probe_bundle"] != [_PROBE]:
        raise AdmissionEvidenceError("V2 archive replacement probe bundle changed")


def _raw_record(value: Mapping[str, Any], *, label: str) -> bytes:
    if set(value) != {"base64", "bytes", "digest"}:
        raise AdmissionEvidenceError(f"V2 archive replacement {label} shape changed")
    raw = base64.b64decode(value["base64"], validate=True)
    if value["bytes"] != len(raw) or value["digest"] != _digest(raw):
        raise AdmissionEvidenceError(f"V2 archive replacement {label} changed")
    return raw


def _verify_harness(
    envelope: Mapping[str, Any],
    identities: Mapping[str, Any],
    secret_checks: Mapping[str, Any],
) -> None:
    document = envelope["document"]
    raw_file = envelope["file"]
    raw = base64.b64decode(raw_file["base64"], validate=True)
    parsed = json.loads(
        raw.decode("ascii"),
        object_pairs_hook=base.base.legacy.parent._reject_duplicates,
        parse_constant=base.base.legacy.parent._reject_constant,
    )
    canonical = base.base.legacy.parent.oci_worker_protocol.canonical_json(document)
    lineage = document["image_lineage"]
    fixture = document["archive_source_fixture"]
    fixture_raw = base64.b64decode(fixture["base64"], validate=True)
    verification = document["source_commit_verification"]
    commit_raw = _raw_record(verification["commit_object"], label="commit object")
    stdout = _raw_record(verification["stdout"], label="signature stdout")
    stderr = _raw_record(verification["stderr"], label="signature stderr")
    signature = base.base.legacy.parent._SIGNATURE
    expected_stderr = (
        f'Good "git" signature for {signature["signer"]} with ED25519 key '
        f"{signature['key']}\n"
    ).encode()
    expected_host = {
        "binds": sorted(
            [
                "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                f"{_RUNTIME_VOLUME}:/runtime:ro",
                f"{_ARCHIVE_VOLUME}:/sources:ro",
                f"{_ROUTE_VOLUME}:/route-input:ro",
            ]
        ),
        "cgroupns_mode": "host",
        "ipc_mode": "private",
        "network_mode": "none",
        "privileged": True,
        "readonly_rootfs": False,
        "runtime": "runc",
        "security_opt": ["label=disable"],
        "tmpfs": {
            "/run": "rw,nosuid,nodev,noexec,mode=755",
            "/run/lock": "rw,nosuid,nodev,noexec,mode=755",
        },
        "userns_mode": "",
    }
    if (
        set(document)
        != {
            "archive_source_fixture",
            "archive_source_mount",
            "archive_source_volume_identity",
            "capture_disposition",
            "container_id",
            "host_config",
            "image_id",
            "image_lineage",
            "image_reference",
            "openclaw_runtime_mount",
            "openclaw_runtime_volume",
            "openclaw_runtime_volume_identity",
            "parent_image_id",
            "platform",
            "profile_label",
            "route_input_mount",
            "route_input_volume_identity",
            "run_image_reference",
            "schema",
            "source_commit",
            "source_commit_verification",
        }
        or set(envelope) != {"digest", "document", "file"}
        or parsed != document
        or raw != canonical
        or envelope["digest"] != _DIGESTS["harness"]
        or _digest(raw) != _DIGESTS["harness"]
        or _canonical_digest(document) != _DIGESTS["harness"]
        or raw_file["bytes"] != len(raw)
        or raw_file["digest"] != _DIGESTS["harness"]
        or raw_file["path"] != "/run/aragorn-harness.json"
        or document["schema"]
        != "aragorn/runtime-action-worker-final-combined-v2-systemd-harness/v1"
        or document["capture_disposition"]
        != "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        or document["source_commit"] != _SOURCE["commit"]
        or document["image_id"] != _IMAGE
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or document["platform"] != "linux"
        or document["profile_label"] != "phase3-final-combined-v2"
        or lineage["child"]["id"] != _IMAGE
        or lineage["parent"]["id"] != _PARENT_IMAGE
        or not lineage["added_layers"]
        or lineage["child"]["layers"]
        != lineage["parent"]["layers"] + lineage["added_layers"]
        or lineage["child"]["rootfs_type"] != "layers"
        or lineage["parent"]["rootfs_type"] != "layers"
        or _canonical_digest(document["host_config"]) != _DIGESTS["host_config"]
        or document["host_config"] != expected_host
        or fixture_raw != _SOURCE_BYTES
        or set(fixture) != {"base64", "bytes", "digest", "path"}
        or fixture["bytes"] != len(_SOURCE_BYTES)
        or fixture["digest"] != _SOURCE_DIGEST
        or fixture["path"]
        != "benchmark/fixtures/phase3-protected-archive-replacement/SKILL.md"
        or verification["command"]
        != ["git", "verify-commit", "--raw", _SOURCE["commit"]]
        or verification["exit_code"] != 0
        or stdout != b""
        or stderr != expected_stderr
        or hashlib.sha1(
            f"commit {len(commit_raw)}\0".encode() + commit_raw,
            usedforsecurity=False,
        ).hexdigest()
        != _SOURCE["commit"]
        or identities
        != {
            "broker": {"gid": 997, "uid": 995},
            "gateway": {"gid": 992, "uid": 992},
            "sensor": {"gid": 996, "uid": 996},
            "worker": {"gid": 997, "uid": 997},
        }
        or secret_checks
        != {
            "forbidden_driver_fields": [],
            "gateway_environment_bytes_retained": False,
            "gateway_environment_digest_retained": False,
            "provider_and_gateway_token_values_retained": False,
        }
    ):
        raise AdmissionEvidenceError("V2 archive replacement harness changed")
    _verify_volume(
        document["openclaw_runtime_mount"],
        document["openclaw_runtime_volume_identity"],
        destination="/runtime",
        name=_RUNTIME_VOLUME,
        labels={
            "io.aragorn.phase": "phase3-final",
            "io.aragorn.role": "installed-runtime",
            "io.aragorn.source-commit": base.base.legacy.parent._OPENCLAW["commit"],
            "io.aragorn.source-tree": base.base.legacy.parent._OPENCLAW["source_tree"],
        },
    )
    if document["openclaw_runtime_volume"] != _RUNTIME_VOLUME:
        raise AdmissionEvidenceError("V2 archive replacement runtime volume changed")
    _verify_volume(
        document["route_input_mount"],
        document["route_input_volume_identity"],
        destination="/route-input",
        name=_ROUTE_VOLUME,
        labels={
            "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:70754",
            "dev.aragorn.role": "final-combined-v2-route-input",
            "dev.aragorn.source-commit": _SOURCE["commit"],
        },
    )
    _verify_volume(
        document["archive_source_mount"],
        document["archive_source_volume_identity"],
        destination="/sources",
        name=_ARCHIVE_VOLUME,
        labels={
            "dev.aragorn.capture-owner": f"{_SOURCE['commit']}:70754",
            "dev.aragorn.role": "final-combined-v2-archive-source",
            "dev.aragorn.route": _ROUTE,
            "dev.aragorn.source-commit": _SOURCE["commit"],
        },
    )
    stat = raw_file["stat"]
    if (
        set(stat)
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
        or any(
            type(stat[name]) is not int
            for name in ("ctime_ns", "device", "inode", "mtime_ns", "size")
        )
        or stat["ctime_ns"] <= 0
        or stat["mtime_ns"] != stat["ctime_ns"]
        or stat["gid"] != 0
        or stat["uid"] != 0
        or stat["mode"] != "0600"
        or stat["nlink"] != 1
        or stat["size"] != len(raw)
        or stat["type"] != "file"
    ):
        raise AdmissionEvidenceError("V2 archive replacement harness file changed")


def _verify_volume(
    mount: Mapping[str, Any],
    identity: Mapping[str, Any],
    *,
    destination: str,
    name: str,
    labels: Mapping[str, Any],
) -> None:
    if mount != {
        "destination": destination,
        "driver": "local",
        "mode": "ro",
        "rw": False,
        "source": name,
        "type": "volume",
    } or identity != {
        "driver": "local",
        "labels": dict(labels),
        "name": name,
        "options": None,
        "scope": "local",
    }:
        raise AdmissionEvidenceError(
            f"V2 archive replacement volume changed: {destination}"
        )


def _decode_route_raw(value: Mapping[str, Any]) -> Mapping[str, Any]:
    if set(value) != {
        "base64",
        "bytes",
        "canonical_digest",
        "digest",
        "raw_is_canonical_json_lf",
    }:
        raise AdmissionEvidenceError("V2 archive replacement raw envelope changed")
    raw = base64.b64decode(value["base64"], validate=True)
    document = json.loads(
        raw.decode(),
        object_pairs_hook=base.base.legacy.parent._reject_duplicates,
        parse_constant=base.base.legacy.parent._reject_constant,
    )
    canonical = base.base.legacy.parent.oci_worker_protocol.canonical_json(document)
    if (
        not isinstance(document, dict)
        or len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or value["bytes"] != len(raw)
        or value["digest"] != _digest(raw)
        or value["canonical_digest"] != _digest(canonical)
        or value["raw_is_canonical_json_lf"] is not False
    ):
        raise AdmissionEvidenceError("V2 archive replacement raw identity changed")
    base._verify_scalar_types(document)
    return document


def _verify_execution(
    observation: Mapping[str, Any],
    boundaries: Mapping[str, Any],
    harness: Mapping[str, Any],
) -> None:
    execution = observation["execution"]
    binding = observation["gateway_pid_binding"]
    stack = observation["stack_before"]
    container_id = harness["container_id"]
    gateway_unit = "aragorn-agent-gateway.service"
    pid = binding["pid"]
    units = {
        gateway_unit,
        "aragorn-runtime-action-worker.service",
        "aragorn-runtime-lineage-capability-action-broker.service",
        "aragorn-runtime-lineage-capability-observation-publisher.service",
    }
    if (
        _canonical_digest(execution) != _DIGESTS["execution"]
        or _canonical_digest(binding) != _DIGESTS["gateway_binding"]
        or _canonical_digest(stack) != _DIGESTS["stack"]
        or not isinstance(container_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        or type(pid) is not int
        or pid <= 0
        or binding
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{pid}/ns/mnt",
            "pid": pid,
            "unit": gateway_unit,
        }
        or execution["argv"]
        != [
            "nsenter",
            "--target",
            str(pid),
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
            "/usr/local/bin/node",
            (
                "/route-input/archive-source-force-replacement/"
                "protected-archive-replacement-probe.mjs"
            ),
        ]
        or execution["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or execution["environment_names"]
        != [
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
        or execution["exit_code"] != 0
        or execution["stderr"] != {"bytes": 0, "digest": _EMPTY_DIGEST, "excerpt": ""}
        or set(stack["units"]) != units
        or set(stack["pids"]) != units
        or set(stack["processes"]) != units
        or stack["pids"][gateway_unit] != pid
        or stack["gateway_listener"]["pid"] != pid
        or stack["processes"][gateway_unit]["pid"] != pid
        or stack["processes"][gateway_unit]["uids"] != [992, 992, 992, 992]
        or stack["processes"][gateway_unit]["gids"] != [992, 992, 992, 992]
        or stack["processes"][gateway_unit]["groups"] != [992]
        or stack["processes"][gateway_unit]["capabilities_effective"]
        != "0000000000000000"
        or stack["processes"][gateway_unit]["no_new_privileges"] != 1
        or any(
            boundaries[name] != stack[name]
            for name in (
                "enablement",
                "gateway_listener",
                "processes",
                "service_state",
                "sockets",
                "units",
            )
        )
        or any(
            stack["units"][name]["ControlGroup"]
            != f"/docker/{container_id}/system.slice/{name}"
            for name in units
        )
    ):
        raise AdmissionEvidenceError(
            "V2 archive replacement execution boundary changed"
        )


def _verify_action(
    document: Mapping[str, Any],
    *,
    harness: Mapping[str, Any],
    execution: Mapping[str, Any],
    composition_recorded_at: str,
    outer_recorded_at: str,
) -> None:
    if (
        set(document)
        != {
            "action",
            "assurance",
            "implementation_digest",
            "protected_boundary",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
        or document["schema"]
        != "aragorn/openclaw-protected-archive-replacement-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digest"] != _PROBE["digest"]
        or document["recorded_at"] != "2026-08-22T10:26:14.615Z"
        or document["route"]
        != {
            "action_id": "archive-source-force-replacement",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or re.fullmatch(r"[0-9a-f]{32}", document["run_nonce"]) is None
        or document["runtime_binding"]
        != {
            "commit": base.base.legacy.parent._OPENCLAW["commit"],
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": base.base.legacy.parent._RUNTIME["entrypoint_digest"],
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": base._RUNTIME_TREE["tree_digest"],
            "version": "2026.7.1",
        }
        or _canonical_digest(document["action"]) != _DIGESTS["action"]
        or _canonical_digest(document["protected_boundary"])
        != _STATIC_DIGESTS["boundary_before"]
    ):
        raise AdmissionEvidenceError("V2 archive replacement route changed")

    action = document["action"]
    before = action["prerequisites"]
    after = action["observations"]
    if (
        set(action)
        != {
            "commands",
            "execution_error",
            "id",
            "observations",
            "prerequisites",
            "reason_codes",
            "status",
        }
        or set(before)
        != {
            "discovery",
            "gateway_process",
            "openclaw",
            "positive_control",
            "ready",
            "reason_codes",
            "runtime_tree",
            "source",
            "system_info",
            "target_before",
            "version",
        }
        or set(after)
        != {
            "boundary_after",
            "discovery_after",
            "gateway_after",
            "runtime_tree_after",
            "source_after",
            "source_install",
            "staging_after",
            "staging_before",
            "target_after",
            "upload_begin",
            "upload_install",
        }
        or action["id"] != "archive-source-force-replacement"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or before["ready"] is not True
        or before["reason_codes"] != []
        or after["staging_before"] != []
        or after["staging_after"] != []
        or after["source_after"] != before["source"]
        or after["target_after"] != before["target_before"]
        or after["runtime_tree_after"] != before["runtime_tree"]
        or after["gateway_after"] != before["gateway_process"]
    ):
        raise AdmissionEvidenceError("V2 archive replacement state changed")

    for name, value in (
        ("boundary_before", document["protected_boundary"]),
        ("boundary_after", after["boundary_after"]),
        ("discovery_before", before["discovery"]),
        ("discovery_after", after["discovery_after"]),
        ("gateway", before["gateway_process"]),
        ("openclaw", before["openclaw"]),
        ("positive_control", before["positive_control"]),
        ("runtime_tree", before["runtime_tree"]),
        ("source", before["source"]),
        ("source_install", after["source_install"]),
        ("system", before["system_info"]),
        ("target", before["target_before"]),
        ("upload_begin", after["upload_begin"]),
        ("upload_install", after["upload_install"]),
        ("version", before["version"]),
    ):
        if _canonical_digest(value) != _STATIC_DIGESTS[name]:
            raise AdmissionEvidenceError(
                f"V2 archive replacement {name} identity changed"
            )

    _verify_boundary(document["protected_boundary"], workspace_residue=False)
    _verify_boundary(after["boundary_after"], workspace_residue=True)
    _verify_boundary_delta(document["protected_boundary"], after["boundary_after"])
    _verify_source_tree(before["source"])
    base._verify_target(before["target_before"])
    if (
        before["target_before"]["root"]["exists"] is not True
        or before["target_before"]["entries"][0]["exists"] is not True
    ):
        raise AdmissionEvidenceError("V2 archive replacement target absent")
    _verify_gateway_process(before["gateway_process"], harness["container_id"])
    base._verify_openclaw(before["openclaw"])
    if before["runtime_tree"] != base._RUNTIME_TREE:
        raise AdmissionEvidenceError("V2 archive replacement runtime tree changed")
    base._verify_system(before["system_info"], before["gateway_process"])
    base._verify_version(before["version"])
    base._verify_discovery(before["discovery"])
    _verify_positive_control(before["positive_control"])
    _verify_upload_denial(after["upload_begin"], method="skills.upload.begin")
    _verify_upload_denial(after["upload_install"], method="skills.install")
    _verify_source_install(after["source_install"])
    _verify_catalog_rejection(after["discovery_after"])

    commands = action["commands"]
    expected = [
        before["version"],
        before["system_info"]["command"],
        before["positive_control"]["install"],
        before["discovery"]["command"],
        after["upload_begin"]["command"],
        after["upload_install"]["command"],
        after["source_install"]["command"],
        after["discovery_after"]["command"],
    ]
    parse_time = base.base.legacy._parse_time
    if (
        commands != expected
        or any(
            parse_time(command["started_at"]) > parse_time(command["completed_at"])
            for command in commands
        )
        or any(
            parse_time(current["completed_at"]) > parse_time(next_["started_at"])
            for current, next_ in pairwise(commands)
        )
        or not (
            parse_time(execution["started_at"])
            <= parse_time(commands[0]["started_at"])
            <= parse_time(commands[-1]["completed_at"])
            <= parse_time(document["recorded_at"])
            <= parse_time(execution["completed_at"])
            <= parse_time(composition_recorded_at)
            <= parse_time(outer_recorded_at)
        )
    ):
        raise AdmissionEvidenceError("V2 archive replacement command causality changed")


def _verify_boundary(value: Mapping[str, Any], *, workspace_residue: bool) -> None:
    if (
        set(value)
        != {
            "configuration",
            "effective_identity",
            "inputs",
            "ready",
            "roots",
            "runtime",
        }
        or value["ready"] is not True
        or value["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or set(value["inputs"]) != {"probe", "source"}
        or set(value["roots"])
        != {
            "extensions",
            "managed_skills",
            "personal_agents",
            "plugin_skills",
            "project_agents",
            "workspace_skills",
        }
    ):
        raise AdmissionEvidenceError("V2 archive replacement boundary changed")
    base._verify_config(value["configuration"])
    _verify_input_mount(
        value["inputs"]["probe"],
        path="/route-input",
        source=f"/docker/volumes/{_ROUTE_VOLUME}/_data",
        uid=0,
        gid=0,
        mode="555",
        entries=[
            "archive-source-force-replacement",
            "config-entry-activation",
            "cron-rescan",
            "fresh-session-reset",
            "missing-prompt-blob-rebuild",
            "session-snapshot-consumer",
        ],
    )
    _verify_input_mount(
        value["inputs"]["source"],
        path="/sources",
        source=f"/docker/volumes/{_ARCHIVE_VOLUME}/_data",
        uid=0,
        gid=992,
        mode="750",
        entries=["replacement"],
    )
    _verify_input_mount(
        value["runtime"],
        path="/runtime",
        source=f"/docker/volumes/{_RUNTIME_VOLUME}/_data",
        uid=0,
        gid=0,
        mode="755",
        entries=["bin", "lib"],
    )
    paths = {
        "extensions": "/var/lib/aragorn-agent-gateway/state/extensions",
        "managed_skills": "/var/lib/aragorn-agent-gateway/state/skills",
        "personal_agents": "/var/lib/aragorn-agent-gateway/home/.agents/skills",
        "plugin_skills": "/var/lib/aragorn-agent-gateway/state/plugin-skills",
        "project_agents": "/var/lib/aragorn-agent-gateway/workspace/.agents/skills",
        "workspace_skills": _WORKSPACE_SKILLS,
    }
    for name, path in paths.items():
        root = value["roots"][name]
        entry = root["observation"]
        entries = (
            ["template-skill"]
            if workspace_residue and name == "workspace_skills"
            else []
        )
        if (
            root["ready"] is not True
            or root["writable"] is not True
            or entry["path"] != path
            or entry["exists"] is not True
            or entry["type"] != "directory"
            or entry["uid"] != 992
            or entry["gid"] != 992
            or entry["mode"] != "700"
            or entry["entries"] != entries
            or entry["entry_count"] != len(entries)
            or entry["entries_truncated"] is not False
            or entry["nlink"] != 2 + len(entries)
        ):
            raise AdmissionEvidenceError(
                f"V2 archive replacement conventional root changed: {name}"
            )


def _verify_input_mount(
    value: Mapping[str, Any],
    *,
    path: str,
    source: str,
    uid: int,
    gid: int,
    mode: str,
    entries: list[str],
) -> None:
    base._verify_read_only_mount(value, path=path, source=source)
    entry = value["entry"]
    if (
        entry["path"] != path
        or entry["exists"] is not True
        or entry["type"] != "directory"
        or entry["uid"] != uid
        or entry["gid"] != gid
        or entry["mode"] != mode
        or entry["entries"] != entries
        or entry["entry_count"] != len(entries)
        or entry["entries_truncated"] is not False
    ):
        raise AdmissionEvidenceError(f"V2 archive replacement mount changed: {path}")


def _verify_gateway_process(value: Mapping[str, Any], container_id: str) -> None:
    pid = value["pid"]
    start_time_ticks = value["start_time_ticks"]
    if (
        set(value) != {"cmdline", "hostname", "pid", "start_time_ticks"}
        or value["cmdline"] != ["openclaw-gateway"]
        or value["hostname"] != container_id[:12]
        or type(pid) is not int
        or pid <= 0
        or not isinstance(start_time_ticks, str)
        or not start_time_ticks.isascii()
        or not start_time_ticks.isdigit()
        or int(start_time_ticks) <= 0
    ):
        raise AdmissionEvidenceError("V2 archive replacement gateway process changed")


def _verify_boundary_delta(before: Mapping[str, Any], after: Mapping[str, Any]) -> None:
    expected = deepcopy(before)
    workspace = expected["roots"]["workspace_skills"]["observation"]
    workspace["entries"] = ["template-skill"]
    workspace["entry_count"] = 1
    workspace["nlink"] = 3
    if after != expected:
        raise AdmissionEvidenceError(
            "V2 archive replacement unexpected post-write boundary delta"
        )


def _verify_source_tree(value: Mapping[str, Any]) -> None:
    root = value["root"]
    skill = value["entries"][0]
    if (
        value["ready"] is not True
        or value["tree_digest"] != _SOURCE_TREE_DIGEST
        or len(value["entries"]) != 1
        or root["path"] != _SOURCE_ROOT
        or root["exists"] is not True
        or root["type"] != "directory"
        or root["uid"] != 0
        or root["gid"] != 992
        or root["mode"] != "750"
        or root["nlink"] != 2
        or root["entries"] != ["SKILL.md"]
        or root["entry_count"] != 1
        or root["entries_truncated"] is not False
        or skill["path"] != "SKILL.md"
        or skill["exists"] is not True
        or skill["type"] != "file"
        or skill["uid"] != 0
        or skill["gid"] != 992
        or skill["mode"] != "440"
        or skill["nlink"] != 1
        or skill["size"] != len(_SOURCE_BYTES)
        or skill["digest"] != _SOURCE_DIGEST
        or skill["digest_error"] is not None
    ):
        raise AdmissionEvidenceError("V2 archive replacement source tree changed")


def _verify_positive_control(value: Mapping[str, Any]) -> None:
    target = value["target_after"]
    root = target["root"]
    entries = {entry["path"]: entry for entry in target["entries"]}
    skill = entries["SKILL.md"]
    origin = entries[".openclaw/source-origin.json"]
    if (
        value["ready"] is not True
        or value["configuration_digest"]
        != "sha256:9b584ae1e25f46b4708aa135fe896f67358ef0229f4263d42dbf4a60af343d87"
        or value["target_before"]
        != {
            "exists": False,
            "path": (
                "/tmp/aragorn-final-archive-control/workspace/skills/template-skill"
            ),
        }
        or value["install"]["argv"] != _INSTALL_ARGV
        or not base._command_succeeded_clean(value["install"])
        or not base._command_output_is_exact(value["install"])
        or value["install"]["stdout_excerpt"]
        != (
            "Installing to /tmp/aragorn-final-archive-control/workspace/skills/"
            "template-skill…\nInstalled template-skill from path -> /tmp/aragorn-"
            "final-archive-control/workspace/skills/template-skill\n"
        )
        or target["ready"] is not True
        or target["tree_digest"]
        != "sha256:9af3df5b19c7fe177e3ddadd91f7f00233a67516ecbf641bb797d71bd4439bb0"
        or root["path"]
        != "/tmp/aragorn-final-archive-control/workspace/skills/template-skill"
        or root["uid"] != 992
        or root["gid"] != 992
        or root["mode"] != "700"
        or root["entries"] != [".openclaw", "SKILL.md"]
        or root["entry_count"] != 2
        or set(entries) != {".openclaw", "SKILL.md", ".openclaw/source-origin.json"}
        or skill["uid"] != 992
        or skill["gid"] != 992
        or skill["mode"] != "440"
        or skill["size"] != len(_SOURCE_BYTES)
        or skill["digest"] != _SOURCE_DIGEST
        or origin["uid"] != 992
        or origin["gid"] != 992
        or origin["mode"] != "600"
        or origin["size"] != 133
        or origin["digest"]
        != "sha256:f8e569cd688f3f335b1cd1aaf53a2b43408a54d66ff25700eb2a92204050bd0e"
    ):
        raise AdmissionEvidenceError("V2 archive replacement positive control changed")


def _verify_upload_denial(value: Mapping[str, Any], *, method: str) -> None:
    command = value["command"]
    error = {
        "code": "UNAVAILABLE",
        "message": (
            "Uploaded skill archive installs are disabled by "
            "skills.install.allowUploadedArchives"
        ),
        "retryable": False,
        "type": "gateway_request_error",
    }
    params = (
        "{}"
        if method == "skills.upload.begin"
        else (
            '{"agentId":"main","force":true,"sha256":"'
            + "a" * 64
            + '","slug":"template-skill","source":"upload","uploadId":"'
            + "a" * 32
            + '"}'
        )
    )
    if (
        value["response"] != {"parsed": True, "value": {"error": error, "ok": False}}
        or command["argv"]
        != [
            "/usr/local/bin/node",
            "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "gateway",
            "call",
            method,
            "--json",
            "--timeout",
            "5000",
            "--params",
            params,
        ]
        or command["exit_code"] != 1
        or command["error"] is not None
        or command["signal"] is not None
        or command["stderr_bytes"] != 0
        or command["stderr_digest"] != _EMPTY_DIGEST
        or command["stderr_excerpt"] != ""
        or not base._command_output_is_exact(command)
        or json.loads(command["stdout_excerpt"]) != value["response"]["value"]
    ):
        raise AdmissionEvidenceError(
            f"V2 archive replacement upload denial changed: {method}"
        )


def _verify_source_install(value: Mapping[str, Any]) -> None:
    command = value["command"]
    if (
        value["response"] != {"parsed": False, "value": None}
        or command["argv"] != _INSTALL_ARGV
        or not base._command_succeeded_clean(command)
        or not base._command_output_is_exact(command)
        or command["stdout_excerpt"]
        != (
            f"Installing to {_WORKSPACE_SKILLS}/template-skill…\n"
            f"Installed template-skill from path -> {_WORKSPACE_SKILLS}/"
            "template-skill\n"
        )
    ):
        raise AdmissionEvidenceError(
            "V2 archive replacement excluded-root install changed"
        )


def _verify_catalog_rejection(value: Mapping[str, Any]) -> None:
    command = value["command"]
    if (
        value["response"] != {"parsed": False, "value": None}
        or command["argv"] != _INFO_ARGV
        or command["exit_code"] != 1
        or command["error"] is not None
        or command["signal"] is not None
        or command["stdout_bytes"] != 0
        or command["stdout_digest"] != _EMPTY_DIGEST
        or command["stdout_excerpt"] != ""
        or command["stderr_excerpt"] != _CATALOG_REJECTION
        or not base._command_output_is_exact(command)
    ):
        raise AdmissionEvidenceError(
            "V2 archive replacement external catalog rejection changed"
        )
