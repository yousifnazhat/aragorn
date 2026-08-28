"""Qualify one exact V3 native-policy plugin force-reinstall block."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from itertools import pairwise
from pathlib import Path
from typing import Any

from . import admission_protected_final_combined_v2_plugin_force_reinstall as parent
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_digest, canonical_json

contract = parent.contract

_ROUTE = "ADM-02/update/plugin-force-reinstall"
_PROFILE = "openclaw-2026.7.1-protected-final-combined-v3"
_PLUGIN_ID = "aragorn-force-reinstall-fixture"
_SOURCE_ROOT = "/route-input/plugin-force-reinstall/candidate-source"
_TARGET = f"/var/lib/aragorn-agent-gateway/state/extensions/{_PLUGIN_ID}"
_VERIFIER_PATH = (
    "src/aragorn/admission_protected_final_combined_v3_plugin_force_reinstall.py"
)

_BASE = {
    "digest": "sha256:675804ea995a48d8e94e39174f09e350ed675c9a20865128acff89f94d1a24f1",
    "path": "src/aragorn/admission_protected_final_combined_v2_plugin_force_reinstall.py",
}
_EVIDENCE = {
    "bytes": 571_895,
    "canonical_bytes": 571_894,
    "canonical_digest": (
        "sha256:4d9086438c113e7cced7a86e260433350d7cc2950cdde092336855344738afe5"
    ),
    "digest": (
        "sha256:800684a30faca6c42d4a9229949b90e56076e9eef87d8a075321931888e42962"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v3-route-plugin-"
        "force-reinstall-systemd-p3-final-2026-08-28.json"
    ),
}
_ROUTE_RAW = {
    "bytes": 60_276,
    "canonical_digest": (
        "sha256:1295bd9a60633376094da34257a7cd8d6a1f3924b337dd4a64e54b9be1753594"
    ),
    "digest": (
        "sha256:b9a6355dc0ce4af50a46022e3149ce6329fee87697019ac05d515888bb56d88f"
    ),
}
_SOURCE = {
    "commit": "66ef3a7169ea6f1359c8aaf1f367e7dc02374c2b",
    "parent": "59ce238da589993bb279f01bb9eb27d0bad70b62",
    "tree": "3b5178f0210e1cf6146230c4803f64a8d87e0ff4",
}
_RETENTION = {
    "commit": "17f954a355ac25dd09fe3a37ecd6f67429dc59b8",
    "parent": _SOURCE["commit"],
    "tree": "93235f2e2d2eeb40974a99c6df05565f810973ae",
}
_RETENTION_BLOB = "00bc4c36e8008676c6d97999bd37b517e1bfe41d"
_IMAGE = "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
_PARENT_IMAGE = (
    "sha256:21184b7a6a096a8625994b524203bf5b521d749b24e415378a69decd4e78009b"
)

_CONTRACT_FILES = {
    "config": {
        "bytes": 2_160,
        "canonical_bytes": 2_159,
        "canonical_digest": (
            "sha256:dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c"
        ),
        "digest": (
            "sha256:2855474d8b709654fb8902c0dc69ec1f0a3a378518ec23bfb12c1eb9630824ab"
        ),
        "path": (
            "benchmark/admission/openclaw-v2026.7.1/"
            "protected-final-combined-config-v3.json"
        ),
    },
    "profile": {
        "bytes": 5_302,
        "canonical_bytes": 5_301,
        "canonical_digest": (
            "sha256:9e73029de2f4e26b8dea9c8ac8bc5bc182c9669b01fb20657ec6177d99d31532"
        ),
        "digest": (
            "sha256:3229bd747088199d8bae074bbc27a415169fa21f86462408434ecdb43c5b2a6c"
        ),
        "path": (
            "benchmark/admission/openclaw-v2026.7.1/"
            "protected-final-combined-profile-v3.json"
        ),
    },
    "runtime_lock": {
        "bytes": 7_620,
        "canonical_bytes": 7_619,
        "canonical_digest": (
            "sha256:4b58803f600def6a63737e68882cff0de09e3c1780b417c9f93caa8a9d37d43c"
        ),
        "digest": (
            "sha256:3bbcc6568cf713f9e534f84f7a92e313b5aa357065759bd01b5f24a594fb5822"
        ),
        "path": (
            "benchmark/admission/openclaw-v2026.7.1/"
            "protected-final-combined-runtime-v3.lock.json"
        ),
    },
}
_SOURCE_ARTIFACTS = {
    "collector": {
        "bytes": 28_860,
        "digest": "sha256:c9e3e43e4d122575cc362e2ec73b2fc4b57d4ad465a1d49e4b94291d935217ad",
        "mode": "0555",
        "path": "scripts/runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe.py",
    },
    "force_probe": {
        "bytes": 30_362,
        "digest": "sha256:58ba8c44ef474588dd48c8afaca01681c26d8a0b45c153994463c87e719f115a",
        "mode": "0444",
        "path": "benchmark/admission/openclaw-v2026.7.1/protected-plugin-force-reinstall-v3-probe.py",
    },
    "inherited_combined_base": {
        "bytes": 30_093,
        "digest": "sha256:03fcf63cd6f68521e261ecb8dc558c2a906b59338ce96a20688098f2066dc550",
        "mode": "0555",
        "path": "scripts/runtime_action_worker_final_combined_v2_systemd_probe.py",
    },
    "inherited_route_injector": {
        "bytes": 21_470,
        "digest": "sha256:50e96d42459a40d0a87ce2cdd215bace14072a626281a3fc733efb5b22831355",
        "mode": "0555",
        "path": "scripts/runtime_action_worker_final_route_systemd_probe.py",
    },
}
_BUNDLE_PATHS = {
    "baseline-source/index.js": (
        "benchmark/admission/openclaw-v2026.7.1/plugin-force-reinstall-baseline-index.js"
    ),
    "baseline-source/openclaw.plugin.json": (
        "benchmark/admission/openclaw-v2026.7.1/"
        "plugin-force-reinstall-baseline-openclaw.plugin.json"
    ),
    "baseline-source/package.json": (
        "benchmark/admission/openclaw-v2026.7.1/plugin-force-reinstall-baseline-package.json"
    ),
    "candidate-source/index.js": (
        "benchmark/admission/openclaw-v2026.7.1/"
        "plugin-force-reinstall-replacement-index.js"
    ),
    "candidate-source/openclaw.plugin.json": (
        "benchmark/admission/openclaw-v2026.7.1/"
        "plugin-force-reinstall-replacement-openclaw.plugin.json"
    ),
    "candidate-source/package.json": (
        "benchmark/admission/openclaw-v2026.7.1/"
        "plugin-force-reinstall-replacement-package.json"
    ),
    "protected-plugin-force-reinstall-v3-probe.py": _SOURCE_ARTIFACTS["force_probe"][
        "path"
    ],
}

_DIGESTS = {
    "composition": "sha256:540b225664177731f6f1083b35c6598e30acc64d52b6a492f869d4673bdabb54",
    "source_artifacts": "sha256:70a96f7b69a0e65f90e5ce0e56851331b93402e028e21a3d67a9c73c9f321e36",
    "harness": "sha256:00719b2254c5d12063fadc959a33ba85aa5d84095746c310108a72e92e7be041",
    "route_observation": "sha256:2b42d848bb0f40cd40625a42885684595695a136c5420237dc0c29e656e886b1",
    "execution": "sha256:393118b04bce422d3ff68ffc47db85edd33259049f0dcd385ea887b8b95bd8e5",
    "gateway": "sha256:e1305f362cf7b202e4a9a71652fba6a412f7f0919110556100f7c16bb6cb7ce5",
    "stack": "sha256:5cd45e16dc744cc2e69ed64d4888f9b81ab08b18746c3b8a06552d029a17dcc8",
    "document": _ROUTE_RAW["canonical_digest"],
    "action": "sha256:dbdee9156116b8de6c236f08a3a274db82a089d85110e199bf355b25c2834794",
    "v3_artifact": "sha256:0cce331e8f3e09c1a34537ef420ac629e83b354c59a987ff46ef4dd56f8861e8",
}
# These projections are intentionally separate from the repinnable envelope digests.
_SEMANTIC_DIGESTS = {
    "baseline_source": "sha256:277b7e973267c2781ed15233073dd8d13229b13930a504379a2514ccce3fbfac",
    "candidate_source": "sha256:f0e68a7b858d9561312d47a5cb6baba03559db4d3da60e5abfd38dd9c4a985f8",
    "config": "sha256:0253fb9355fbf5fc9cdc85bc47a6fc4d80e99bba200881a74811e35044f7cc38",
    "config_lock": "sha256:13eb5262c45f934421b78219b9e381e86042397ac2c7bf5e1c41807f4d6c91d2",
    "discovery_roots": "sha256:9f5bacb8f36e0476adcbb822e1c6577fa8b6bf193374f5076cafee0bc9f9f8ce",
    "gateway_process": "sha256:0c4fa4d70794695c1613d363b5918c1774788d48c9b069d6a2b0502678aafd3c",
    "install_policy_command": "sha256:5a647287071ae141c7cf5e2082d1cca48e7c2922ad5977a7716762e8bb4e7680",
    "openclaw": "sha256:9fb51d4462f014dc9d86a349adafd2007d69f3f3658a0ddebffaf62451565e57",
    "route_input_mount": "sha256:d7271d857096d0baa26f4c6ed17055db0d6492919abc4a851743899d0b8a0138",
    "target_plugin": "sha256:6445360430db1d11b015fa496130ec46f822b6e25870dc8a252117a19c709750",
    "state_store_before": "sha256:36085e18ab0703401b628967ff4e3d01b622276454ab9a6990e63ada092801f2",
    "state_store_after": "sha256:8eb1b6910053e24cb5b07234f3b57c3a06c5dfc48b8f9a9d9c67e6a6c6707deb",
    "plugin": "sha256:5a19d1eb7aff316bc83386aee3c9a8751f3c57b903f575747bcac2f2685f5ea2",
    "skills": "sha256:557a9975c7553ffbbe71e9ececd8c045de2cdffa1908b23045dc6bc38ddcd184",
    "force": "sha256:06e61dc7fc8da88aaedaedfef1417cb20be5028cce010632f66afbf953691834",
    "force_command": "sha256:91056768bd24d5958aeb1e91b7c6a19b79ab810cf93f29140fcd57a027ea3e9a",
    "state_invariants": "sha256:d017122cb7335ac5248120be30f70ecd744ef1faba889d0b7444348bd842ad19",
    "containment": "sha256:7430da8eaeba9390bb308ec07c2dba5e26c823658cc658cad2077f00ddbd3cc4",
}

_OUTER_DECISION = {
    "admission_profile_eligible": False,
    "aggregate_admission_eligible": False,
    "edr_eligible": False,
    "installer_work_eligible": False,
    "phase3_exit_eligible": False,
    "release_eligible": False,
    "route_fail_count": 0,
    "route_not_tested_count": 21,
    "route_observation_status": "OBSERVED",
    "route_pass_count": 0,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "run_eligible": False,
    "status": "FINAL_COMBINED_V3_PLUGIN_FORCE_REINSTALL_OBSERVED_PROFILE_NOT_TESTED",
}
_POLICY = {
    "enabled": True,
    "exec": {
        "args": [
            "%s",
            '{"protocolVersion":1,"decision":"block","reason":"plugin installs disabled by Aragorn protected profile"}',
        ],
        "command": "/usr/bin/printf",
        "source": "exec",
        "trustedDirs": ["/usr/bin"],
    },
    "targets": ["plugin"],
}
_FORCE_ARGV = [
    "/usr/local/bin/node",
    "/runtime/lib/node_modules/openclaw/openclaw.mjs",
    "plugins",
    "install",
    _SOURCE_ROOT,
    "--force",
]
_STDERR = (
    "blocked by install policy: plugin installs disabled by Aragorn protected profile\n"
)
_STDOUT = (
    'Plugin manifest id "aragorn-force-reinstall-fixture" differs from npm package '
    'name "@aragorn/plugin-force-reinstall-fixture"; using manifest id as the config key.\n'
    "Install policy target=plugin:aragorn-force-reinstall-fixture request=plugin-dir/update "
    "origin=plugin-package pathKind=directory source=local-path/user: blocked by install "
    "policy: plugin installs disabled by Aragorn protected profile\n"
)


def verify_openclaw_final_combined_v3_plugin_force_reinstall(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return one narrowly qualified V3 PASS and twenty NOT_TESTED routes."""

    try:
        _verify_dependencies()
        retained = _verify_retained_evidence()
        raw = contract._read_blob(evidence_cas, _EVIDENCE, "V3 plugin force reinstall")
        if raw != retained:
            raise AdmissionEvidenceError(
                "V3 plugin force-reinstall CAS differs from signed retention"
            )
        evidence = contract._load_canonical_json(
            raw, _EVIDENCE, "V3 plugin force reinstall"
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
            f"invalid V3 plugin force-reinstall evidence: {exc}"
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
            "aragorn/admission-protected-final-combined-v3-plugin-force-"
            "reinstall-route-coverage/v1"
        ),
        "assurance": (
            "ONE_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V3_NATIVE_PLUGIN_INSTALL_"
            "POLICY_BLOCK_ONLY"
        ),
        "bindings": {
            "configuration": dict(_CONTRACT_FILES["config"]),
            "image": _IMAGE,
            "plugin_force_reinstall_observation": {
                **_EVIDENCE,
                "retention": {
                    **_RETENTION,
                    "signing_key": contract._SIGNATURE["key"],
                },
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_SOURCE,
                    "signature": dict(contract._SIGNATURE),
                },
            },
            "profile": dict(_CONTRACT_FILES["profile"]),
            "runtime_lock": dict(_CONTRACT_FILES["runtime_lock"]),
            "source_artifacts": {
                name: {key: value[key] for key in ("bytes", "digest", "path")}
                for name, value in _SOURCE_ARTIFACTS.items()
            },
            "verifier_base": dict(_BASE),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V3_ROUTE_COVERAGE",
            **{key: False for key in contract._ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ONE_EXACT_DYNAMIC_PLUGIN_FORCE_REINSTALL_ROUTE_ONLY",
            "TWENTY_OTHER_V3_ROUTES_NOT_TESTED",
            "SQLITE_MAIN_FILE_UNCHANGED_BUT_WAL_AND_SHM_BYTES_CHANGED",
            "NO_TABLE_LEVEL_SQLITE_DIFF_OR_LOGICAL_TRANSACTION_ATTESTATION",
            "WAL_SHM_DELTA_NOT_ATTRIBUTABLE_TO_FORCE_COMMAND",
            "NO_PRE_EFFECT_NO_WRITE_TRANSIENT_WRITE_ROLLBACK_CLEANUP_OR_FULL_STATE_STORE_EQUIVALENCE_CLAIM",
            "INERT_NO_DEPENDENCY_NO_HOOK_LOCAL_PLUGIN_FIXTURE_ONLY",
            "ONE_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURE_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "SOURCE_TO_BINARY_BUILD_NOT_INDEPENDENTLY_ATTESTED_OR_REPRODUCED",
            "PUBLIC_NETWORK_DENIED",
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "profile": {
            "counts": {"NOT_TESTED": 20, "PASS": 1},
            "name": _PROFILE,
            "routes": routes,
        },
        "route_semantics": {
            "dynamically_exercised_routes": [_ROUTE],
            "pass_basis": (
                "PASS_EXACT_NATIVE_INSTALL_POLICY_BLOCK_OBSERVED_FOR_SAME_ID_"
                "LOCAL_DIRECTORY_FORCE_REINSTALL_WITH_EXACT_EQUAL_PROTECTED_"
                "ARTIFACT_BEFORE_AFTER_SNAPSHOTS_AND_DISCLOSED_SQLITE_WAL_SHM_DELTA"
            ),
            "protected_artifact_snapshot_equality": {
                "configuration": True,
                "discovery_roots": True,
                "gateway_process": True,
                "install_policy_command": True,
                "plugin_inspection": True,
                "skills_status": True,
                "target_plugin": True,
            },
            "sqlite_snapshot_observation": {
                "main_file_equal": True,
                "shm_changed": True,
                "wal_byte_delta": 32_960,
                "wal_changed": True,
            },
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(profile["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_dependencies() -> None:
    path = Path(parent.__file__).resolve(strict=True)
    expected = (Path(__file__).resolve(strict=True).parent / path.name).resolve(
        strict=True
    )
    if (
        path != expected
        or path.name != Path(_BASE["path"]).name
        or _digest(path.read_bytes()) != _BASE["digest"]
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall verifier base changed")
    parent._verify_dependencies()


def _verify_retained_evidence() -> bytes:
    root = Path(__file__).resolve(strict=True).parents[2]
    git = parent.config.base.legacy._git
    if (
        Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve(
            strict=True
        )
        != root
        or git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall repository changed")
    parent.config.base._verify_commit(_SOURCE)
    parent.config.base._verify_commit(_RETENTION)
    entry = git(
        ["ls-tree", "-z", "--full-name", _RETENTION["commit"], "--", _EVIDENCE["path"]]
    )
    expected = f"100644 blob {_RETENTION_BLOB}\t{_EVIDENCE['path']}".encode() + b"\0"
    if entry != expected:
        raise AdmissionEvidenceError(
            "V3 plugin force-reinstall signed tree entry changed"
        )
    raw = git(["cat-file", "blob", _RETENTION_BLOB], maximum=640 * 1024)
    oid = hashlib.sha1(
        f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
    ).hexdigest()
    if (
        oid != _RETENTION_BLOB
        or len(raw) != _EVIDENCE["bytes"]
        or _digest(raw) != _EVIDENCE["digest"]
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall signed blob changed")
    return raw


def _verify_evidence(evidence: Mapping[str, Any]) -> Mapping[str, Any]:
    parent.parent._verify_scalar_types(evidence)
    parent.config._verify_no_positive_eligibility(evidence)
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
            "source_artifacts",
        }
        or evidence["schema"]
        != "aragorn/runtime-action-worker-final-combined-v3-plugin-force-reinstall-systemd-observation/v1"
        or evidence["recorded_at"] != "2026-08-28T16:40:08.034278Z"
        or evidence["route_id"] != _ROUTE
        or evidence["authority"]
        != (
            "BOUND_FINAL_COMBINED_V3_RAW_PLUGIN_FORCE_REINSTALL_OBSERVATION_ONLY_"
            "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or evidence["decision"] != _OUTER_DECISION
        or canonical_digest(evidence["composition"]) != _DIGESTS["composition"]
        or canonical_digest(evidence["source_artifacts"])
        != _DIGESTS["source_artifacts"]
        or canonical_digest(evidence["harness"]) != _DIGESTS["harness"]
        or canonical_digest(evidence["route_observation"])
        != _DIGESTS["route_observation"]
    ):
        raise AdmissionEvidenceError(
            "V3 plugin force-reinstall outer observation changed"
        )
    _verify_sources(evidence["source_artifacts"])
    profile = _verify_composition(evidence["composition"])
    if evidence["harness"] != evidence["composition"]["action"]["harness"]:
        raise AdmissionEvidenceError("V3 plugin force-reinstall harness copies differ")
    _verify_harness(evidence["harness"])
    if (
        evidence["route_observation"]["bundle"]
        != evidence["source_artifacts"]["probe_bundle"]
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall route bundle changed")
    _verify_route_observation(evidence["route_observation"], evidence["recorded_at"])
    return profile


def _verify_sources(value: Mapping[str, Any]) -> None:
    if set(value) != {*_SOURCE_ARTIFACTS, "probe_bundle"}:
        raise AdmissionEvidenceError(
            "V3 plugin force-reinstall source inventory changed"
        )
    git = parent.config.base.legacy._git
    for name, expected in _SOURCE_ARTIFACTS.items():
        item = value[name]
        stat = item["stat"]
        if (
            {key: item[key] for key in ("bytes", "digest")}
            != {key: expected[key] for key in ("bytes", "digest")}
            or item["path"] != f"/src/{expected['path']}"
            or stat["uid"] != 0
            or stat["gid"] != 0
            or stat["mode"] != expected["mode"]
            or stat["nlink"] != 1
            or stat["size"] != expected["bytes"]
            or stat["type"] != "file"
        ):
            raise AdmissionEvidenceError(
                f"V3 plugin force-reinstall {name} source changed"
            )
        _verify_signed_bytes(git, expected)
    bundle = value["probe_bundle"]
    if [item["name"] for item in bundle] != list(_BUNDLE_PATHS):
        raise AdmissionEvidenceError("V3 plugin force-reinstall probe bundle changed")
    for item in bundle:
        expected = {**item, "path": _BUNDLE_PATHS[item["name"]]}
        expected_role = (
            "probe"
            if item["name"] == "protected-plugin-force-reinstall-v3-probe.py"
            else "fixture"
        )
        if item["role"] != expected_role:
            raise AdmissionEvidenceError(
                "V3 plugin force-reinstall bundle role changed"
            )
        _verify_signed_bytes(git, expected)


def _verify_signed_bytes(git: Any, expected: Mapping[str, Any]) -> None:
    raw = git(
        ["show", f"{_SOURCE['commit']}:{expected['path']}"],
        maximum=expected["bytes"],
    )
    if len(raw) != expected["bytes"] or _digest(raw) != expected["digest"]:
        raise AdmissionEvidenceError("V3 plugin force-reinstall signed source changed")


def _verify_composition(composition: Mapping[str, Any]) -> Mapping[str, Any]:
    action = composition["action"]
    artifact = action["artifacts"]["final_combined_v3_plugin_force_reinstall"]
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
        != "aragorn/runtime-action-worker-final-combined-v3-plugin-force-reinstall-systemd-observation/v1"
        or composition["authority"]
        != (
            "BOUND_FINAL_COMBINED_V3_RAW_PLUGIN_FORCE_REINSTALL_OBSERVATION_ONLY_"
            "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or composition["recorded_at"] != "2026-08-28T16:40:08.034237Z"
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
            "status": "FINAL_COMBINED_V3_ACTION_OBSERVED_PROFILE_NOT_TESTED",
        }
        or canonical_digest(artifact) != _DIGESTS["v3_artifact"]
    ):
        raise AdmissionEvidenceError(
            "V3 plugin force-reinstall artifact binding changed"
        )
    _verify_contract_artifacts(artifact)
    profile = artifact["profile"]["document"]
    if (
        composition["profile"]["before"] != composition["profile"]["after"]
        or composition["profile"]["before"]["document"] != profile
        or composition["profile"]["before"]["outcomes"]
        != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or profile["name"] != _PROFILE
        or len(profile["routes"]) != 21
        or len({route["id"] for route in profile["routes"]}) != 21
        or {route["outcome"] for route in profile["routes"]} != {"NOT_TESTED"}
        or sum(route["id"] == _ROUTE for route in profile["routes"]) != 1
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall profile changed")
    return profile


def _verify_contract_artifacts(artifact: Mapping[str, Any]) -> None:
    git = parent.config.base.legacy._git
    for name, expected in _CONTRACT_FILES.items():
        bound = artifact[name]
        source = bound["file"]["source"]
        stat = source["stat"]
        if (
            source["path"] != f"/src/{expected['path']}"
            or source["bytes"] != expected["bytes"]
            or source["digest"] != expected["digest"]
            or stat["uid"] != 0
            or stat["gid"] != 0
            or stat["mode"] != "0444"
            or stat["nlink"] != 1
            or stat["size"] != expected["bytes"]
            or stat["type"] != "file"
            or bound["file"]["canonical_bytes"] != expected["canonical_bytes"]
            or bound["file"]["canonical_digest"] != expected["canonical_digest"]
            or canonical_digest(bound["document"]) != expected["canonical_digest"]
        ):
            raise AdmissionEvidenceError(f"V3 plugin force-reinstall {name} changed")
        raw = git(
            ["show", f"{_SOURCE['commit']}:{expected['path']}"],
            maximum=expected["bytes"],
        )
        if (
            len(raw) != expected["bytes"]
            or _digest(raw) != expected["digest"]
            or raw != canonical_json(bound["document"]) + b"\n"
        ):
            raise AdmissionEvidenceError(
                f"V3 plugin force-reinstall signed {name} changed"
            )
    config = artifact["config"]["document"]
    policy_command = artifact["policy_command"]
    stat = policy_command["stat"]
    if (
        config["security"]["installPolicy"] != _POLICY
        or policy_command["path"] != "/usr/bin/printf"
        or policy_command["bytes"] != 68_480
        or policy_command["digest"]
        != "sha256:2c7b0151ee3c1ba4e829209f2ff4336de9d97143e22bf87c7448539112139957"
        or stat["uid"] != 0
        or stat["gid"] != 0
        or stat["mode"] != "0755"
        or stat["nlink"] != 1
        or stat["size"] != 68_480
        or stat["type"] != "file"
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall install policy changed")


def _verify_harness(value: Mapping[str, Any]) -> None:
    document = value["document"]
    file = value["file"]
    runtime_mount = document["openclaw_runtime_mount"]
    route_mount = document["route_input_mount"]
    raw = base64.b64decode(file["base64"], validate=True)
    if (
        set(value) != {"digest", "document", "file"}
        or value["digest"] != file["digest"]
        or value["digest"]
        != "sha256:5aa669737c0dc9ec8a59066e85f9bcdd2bc2d6788ae10275ef75d11b9d26e0ce"
        or canonical_digest(document) != value["digest"]
        or raw != canonical_json(document)
        or len(raw) != 20_120
        or _digest(raw) != file["digest"]
        or file["bytes"] != 20_120
        or file["path"] != "/run/aragorn-harness.json"
        or file["stat"]["uid"] != 0
        or file["stat"]["gid"] != 0
        or file["stat"]["mode"] != "0600"
        or file["stat"]["nlink"] != 1
        or file["stat"]["size"] != 20_120
        or file["stat"]["type"] != "file"
        or document["source_commit"] != _SOURCE["commit"]
        or document["run_image_reference"] != _IMAGE
        or document["parent_image_id"] != _PARENT_IMAGE
        or document["host_config"]["network_mode"] != "none"
        or document["host_config"]["privileged"] is not True
        or runtime_mount["rw"] is not False
        or runtime_mount["mode"] != "ro"
        or route_mount["rw"] is not False
        or route_mount["mode"] != "ro"
        or document["profile_label"]
        != "phase3-final-combined-v3-plugin-force-reinstall"
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall harness changed")


def _verify_route_observation(value: Mapping[str, Any], recorded_at: str) -> None:
    gateway = value["gateway_pid_binding"]
    if (
        set(value)
        != {
            "bundle",
            "document",
            "execution",
            "gateway_pid_binding",
            "raw",
            "route",
            "stack_before",
        }
        or canonical_digest(value["execution"]) != _DIGESTS["execution"]
        or canonical_digest(value["gateway_pid_binding"]) != _DIGESTS["gateway"]
        or canonical_digest(value["stack_before"]) != _DIGESTS["stack"]
        or gateway
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": "/proc/2768/ns/mnt",
            "pid": 2768,
            "unit": "aragorn-agent-gateway.service",
        }
        or value["execution"]["argv"][2] != str(gateway["pid"])
        or value["stack_before"]["pids"][gateway["unit"]] != gateway["pid"]
        or value["route"]
        != {
            "action_id": "plugin-force-reinstall",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall route envelope changed")
    _verify_execution(value["execution"])
    document = _verify_document_raw(value["raw"], value["document"])
    _verify_document(document, recorded_at)
    commands = document["action"]["commands"]
    if not (
        _time(value["execution"]["started_at"])
        <= _time(commands[0]["started_at"])
        <= _time(commands[-1]["completed_at"])
        <= _time(document["recorded_at"])
        <= _time(value["execution"]["completed_at"])
        <= _time(recorded_at)
    ):
        raise AdmissionEvidenceError(
            "V3 plugin force-reinstall outer execution time changed"
        )


def _verify_execution(value: Mapping[str, Any]) -> None:
    expected_argv = [
        "nsenter",
        "--target",
        "2768",
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
        "/usr/local/bin/python3.12",
        "/route-input/plugin-force-reinstall/protected-plugin-force-reinstall-v3-probe.py",
    ]
    if (
        set(value)
        != {
            "argv",
            "completed_at",
            "effective_identity",
            "environment_names",
            "exit_code",
            "started_at",
            "stderr",
        }
        or value["argv"] != expected_argv
        or value["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or value["environment_names"]
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
        or value["exit_code"] != 0
        or type(value["exit_code"]) is not int
        or value["stderr"]
        != {
            "bytes": 0,
            "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "excerpt": "",
        }
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall execution changed")


def _verify_document_raw(
    raw_value: Mapping[str, Any], document: Mapping[str, Any]
) -> Mapping[str, Any]:
    raw = base64.b64decode(raw_value["base64"], validate=True)
    if (
        {key: raw_value[key] for key in ("bytes", "canonical_digest", "digest")}
        != _ROUTE_RAW
        or raw_value["raw_is_canonical_json_lf"] is not True
        or len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or raw != canonical_json(document) + b"\n"
        or canonical_digest(document) != _DIGESTS["document"]
        or json.loads(raw) != document
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall raw document changed")
    return document


def _verify_document(document: Mapping[str, Any], outer_recorded_at: str) -> None:
    action = document["action"]
    if (
        set(document)
        != {
            "action",
            "assurance",
            "implementation_digest",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
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
        or set(action["prerequisites"])
        != {
            "boundary_before",
            "plugin_before",
            "skills_status_before",
            "system_info_before",
            "version",
        }
        or set(action["observations"])
        != {
            "boundary_after",
            "native_force_reinstall",
            "plugin_after",
            "post_write_containment",
            "skills_status_after",
            "state_invariants",
            "system_info_after",
        }
        or document["schema"]
        != "aragorn/openclaw-protected-plugin-force-reinstall-v3-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["implementation_digest"]
        != _SOURCE_ARTIFACTS["force_probe"]["digest"]
        or document["runtime_binding"]
        != {
            "commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188",
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "version": "2026.7.1",
        }
        or len(document["run_nonce"]) != 32
        or int(document["run_nonce"], 16) < 0
        or document["route"]
        != {
            "action_id": "plugin-force-reinstall",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or canonical_digest(action) != _DIGESTS["action"]
        or action["id"] != "plugin-force-reinstall"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall document changed")
    _verify_commands(action, document["recorded_at"], outer_recorded_at)
    _verify_semantics(action)


def _verify_commands(
    action: Mapping[str, Any], document_recorded_at: str, outer_recorded_at: str
) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    aliases = [
        before["version"],
        before["system_info_before"]["command"],
        before["skills_status_before"]["command"],
        before["plugin_before"]["command"],
        after["native_force_reinstall"]["command"],
        after["plugin_after"]["command"],
        after["skills_status_after"]["command"],
        after["system_info_after"]["command"],
    ]
    commands = action["commands"]
    if commands != aliases or len(commands) != 8:
        raise AdmissionEvidenceError(
            "V3 plugin force-reinstall command aliases changed"
        )
    _verify_nonforce_commands(before, after)
    pids = [command["pid"] for command in commands]
    if len(set(pids)) != len(pids) or any(
        type(pid) is not int or pid <= 0 or pid == 2768 for pid in pids
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall command PIDs changed")
    for command in commands:
        if _time(command["started_at"]) > _time(command["completed_at"]):
            raise AdmissionEvidenceError(
                "V3 plugin force-reinstall command time changed"
            )
    for left, right in pairwise(commands):
        if _time(left["completed_at"]) > _time(right["started_at"]):
            raise AdmissionEvidenceError(
                "V3 plugin force-reinstall commands overlapped"
            )
    if not (
        _time(commands[-1]["completed_at"])
        <= _time(document_recorded_at)
        <= _time(outer_recorded_at)
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall recording time changed")


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise AdmissionEvidenceError("V3 plugin force-reinstall timestamp changed")
    return parsed


def _verify_nonforce_commands(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> None:
    node = "/usr/local/bin/node"
    openclaw = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
    system_argv = [
        node,
        openclaw,
        "gateway",
        "call",
        "system.info",
        "--json",
        "--timeout",
        "5000",
    ]
    skills_argv = [
        node,
        openclaw,
        "gateway",
        "call",
        "skills.status",
        "--json",
        "--timeout",
        "5000",
    ]
    plugin_argv = [node, openclaw, "plugins", "inspect", _PLUGIN_ID, "--json"]
    _verify_clean_command(
        before["version"],
        [node, openclaw, "--version"],
        expected_stdout="OpenClaw 2026.7.1 (7fa98d8)\n",
    )
    for observation, argv in (
        (before["system_info_before"], system_argv),
        (before["skills_status_before"], skills_argv),
        (after["skills_status_after"], skills_argv),
        (after["system_info_after"], system_argv),
    ):
        _verify_json_command(observation, argv)
    for observation in (before["plugin_before"], after["plugin_after"]):
        excerpt = observation["command"]["stdout_excerpt"].encode()
        if (
            len(excerpt) != 2_048
            or _digest(excerpt)
            != "sha256:c94bd3a3ffed517f4d9e174dffa7cba9b48fba3457aa11181a45eb35fe4f64eb"
        ):
            raise AdmissionEvidenceError(
                "V3 plugin force-reinstall plugin output excerpt changed"
            )
        _verify_json_command(
            observation,
            plugin_argv,
            output_identity=(
                2_516,
                "sha256:743580ca707f52fbdaece81c69dc2bf0856c6f4381d73af55a202b9302eedb85",
            ),
        )


def _verify_clean_command(
    command: Mapping[str, Any],
    argv: list[str],
    *,
    expected_stdout: str | None = None,
    output_identity: tuple[int, str] | None = None,
) -> None:
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
        or command["exit_code"] != 0
        or type(command["exit_code"]) is not int
        or command["error"] is not None
        or command["signal"] is not None
        or command["stderr_bytes"] != 0
        or command["stderr_digest"]
        != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        or command["stderr_excerpt"] != ""
        or (
            output_identity is None
            and (
                command["stdout_bytes"] != len(command["stdout_excerpt"].encode())
                or command["stdout_digest"]
                != _digest(command["stdout_excerpt"].encode())
            )
        )
        or (
            output_identity is not None
            and (
                (command["stdout_bytes"], command["stdout_digest"]) != output_identity
                or len(command["stdout_excerpt"].encode()) > command["stdout_bytes"]
            )
        )
        or (
            expected_stdout is not None and command["stdout_excerpt"] != expected_stdout
        )
    ):
        raise AdmissionEvidenceError(
            "V3 plugin force-reinstall supporting command changed"
        )


def _verify_json_command(
    observation: Mapping[str, Any],
    argv: list[str],
    *,
    output_identity: tuple[int, str] | None = None,
) -> None:
    if set(observation) != {"command", "response"}:
        raise AdmissionEvidenceError(
            "V3 plugin force-reinstall supporting observation changed"
        )
    command = observation["command"]
    response = observation["response"]
    _verify_clean_command(command, argv, output_identity=output_identity)
    if (
        set(response) != {"parsed", "value"}
        or response["parsed"] is not True
        or (
            output_identity is None
            and json.loads(
                command["stdout_excerpt"],
                object_pairs_hook=contract._reject_duplicates,
                parse_constant=contract._reject_constant,
            )
            != response["value"]
        )
    ):
        raise AdmissionEvidenceError(
            "V3 plugin force-reinstall supporting response changed"
        )


def _verify_semantics(action: Mapping[str, Any]) -> None:
    before = action["prerequisites"]["boundary_before"]
    observations = action["observations"]
    after = observations["boundary_after"]
    for name in (
        "baseline_source",
        "candidate_source",
        "config",
        "config_lock",
        "discovery_roots",
        "gateway_process",
        "install_policy_command",
        "openclaw",
        "route_input_mount",
        "target_plugin",
    ):
        if (
            before[name] != after[name]
            or canonical_digest(before[name]) != _SEMANTIC_DIGESTS[name]
        ):
            raise AdmissionEvidenceError(
                f"V3 plugin force-reinstall {name} snapshots changed"
            )
    _verify_policy_and_target(before)
    _verify_force(observations["native_force_reinstall"])
    _verify_plugin_and_catalog(action)
    _verify_state_store(before["state_store"], after["state_store"])
    if (
        canonical_digest(observations["state_invariants"])
        != _SEMANTIC_DIGESTS["state_invariants"]
        or observations["state_invariants"]
        != {
            "baseline_source": True,
            "candidate_source": True,
            "config": True,
            "config_lock": True,
            "discovery_roots": True,
            "gateway_process": True,
            "install_policy_command": True,
            "openclaw": True,
            "plugin_inspection": True,
            "route_input_mount": True,
            "skills_status": True,
            "state_store": False,
            "target_plugin": True,
        }
        or canonical_digest(observations["post_write_containment"])
        != _SEMANTIC_DIGESTS["containment"]
        or observations["post_write_containment"]["state_store_unchanged"] is not False
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall derived state changed")


def _verify_policy_and_target(before: Mapping[str, Any]) -> None:
    policy = before["install_policy_command"]
    config = before["config"]
    target = before["target_plugin"]
    if (
        policy["path"] != "/usr/bin/printf"
        or policy["digest"]
        != "sha256:2c7b0151ee3c1ba4e829209f2ff4336de9d97143e22bf87c7448539112139957"
        or policy["size"] != 68_480
        or policy["uid"] != 0
        or policy["gid"] != 0
        or policy["mode"] != "755"
        or policy["nlink"] != 1
        or policy["type"] != "file"
        or config["canonical_digest"] != _CONTRACT_FILES["config"]["canonical_digest"]
        or config["install_policy"] != _POLICY
        or config["ready"] is not True
        or config["mount"]["read_only"] is not True
        or config["plugin_policy"]["target_allowlisted"] is not False
        or config["plugin_policy"]["target_entry_present"] is not False
        or target["parent_writable"] is not True
        or target["target_writable"] is not True
        or target["exact_gateway_owned_metadata"] is not True
        or target["baseline"]["ready"] is not True
        or target["baseline"]["manifest"]["version"] != "1.0.0"
        or target["candidate"]["ready"] is not False
        or target["candidate"]["manifest"]["version"] != "1.0.0"
        or before["route_input_mount"]["read_only"] is not True
    ):
        raise AdmissionEvidenceError(
            "V3 plugin force-reinstall policy precondition changed"
        )


def _verify_force(force: Mapping[str, Any]) -> None:
    command = force["command"]
    if (
        canonical_digest(force) != _SEMANTIC_DIGESTS["force"]
        or canonical_digest(command) != _SEMANTIC_DIGESTS["force_command"]
        or force["explicit_policy_block_observed"] is not False
        or force["process_started"] is not True
        or force["same_id_existing_target"] is not True
        or force["source_path"] != _SOURCE_ROOT
        or force["target_path"] != _TARGET
        or force["target_plugin_id"] != _PLUGIN_ID
        or force["effective_update_basis"]
        != {
            "candidate_manifest_id": _PLUGIN_ID,
            "existing_target_manifest_id": _PLUGIN_ID,
            "force_requested": True,
            "target_existed_before": True,
        }
        or command["argv"] != _FORCE_ARGV
        or command["exit_code"] != 1
        or type(command["exit_code"]) is not int
        or command["error"] is not None
        or command["signal"] is not None
        or command["stderr_excerpt"] != _STDERR
        or command["stderr_bytes"] != len(_STDERR.encode())
        or command["stderr_digest"] != _digest(_STDERR.encode())
        or command["stdout_excerpt"] != _STDOUT
        or command["stdout_bytes"] != len(_STDOUT.encode())
        or command["stdout_digest"] != _digest(_STDOUT.encode())
    ):
        raise AdmissionEvidenceError(
            "V3 plugin force-reinstall native policy block changed"
        )


def _verify_plugin_and_catalog(action: Mapping[str, Any]) -> None:
    before = action["prerequisites"]
    after = action["observations"]
    plugin_before = before["plugin_before"]["response"]["value"]
    plugin_after = after["plugin_after"]["response"]["value"]
    skills_before = before["skills_status_before"]["response"]["value"]
    skills_after = after["skills_status_after"]["response"]["value"]
    plugin = plugin_after["plugin"]
    if (
        plugin_before != plugin_after
        or canonical_digest(plugin_before) != _SEMANTIC_DIGESTS["plugin"]
        or skills_before != skills_after
        or canonical_digest(skills_before) != _SEMANTIC_DIGESTS["skills"]
        or plugin["id"] != _PLUGIN_ID
        or plugin["version"] != "1.0.0"
        or plugin["enabled"] is not False
        or plugin["explicitlyEnabled"] is not False
        or plugin["activated"] is not False
        or plugin["imported"] is not False
        or plugin["status"] != "disabled"
        or plugin["error"] != "not in allowlist"
        or plugin_after["capabilityCount"] != 0
        or type(plugin_after["capabilityCount"]) is not int
        or plugin_after["capabilities"] != []
        or "install" in plugin_after
        or "installedRecord" in plugin_after
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall plugin state changed")
    system_before = before["system_info_before"]["response"]["value"]
    system_after = after["system_info_after"]["response"]["value"]
    stable = ("machineName", "hostname", "platform", "release", "arch", "pid", "port")
    if (
        {key: system_before[key] for key in stable}
        != {key: system_after[key] for key in stable}
        or system_before["pid"] != 2768
        or type(system_before["uptimeMs"]) is not int
        or type(system_after["uptimeMs"]) is not int
        or system_after["uptimeMs"] <= system_before["uptimeMs"]
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall gateway state changed")


def _verify_state_store(before: Mapping[str, Any], after: Mapping[str, Any]) -> None:
    if (
        canonical_digest(before) != _SEMANTIC_DIGESTS["state_store_before"]
        or canonical_digest(after) != _SEMANTIC_DIGESTS["state_store_after"]
        or before["root"] != after["root"]
        or [item["path"] for item in before["entries"]]
        != ["openclaw.sqlite", "openclaw.sqlite-shm", "openclaw.sqlite-wal"]
        or [item["path"] for item in after["entries"]]
        != ["openclaw.sqlite", "openclaw.sqlite-shm", "openclaw.sqlite-wal"]
    ):
        raise AdmissionEvidenceError("V3 plugin force-reinstall state store changed")
    old = {item["path"]: item for item in before["entries"]}
    new = {item["path"]: item for item in after["entries"]}
    if (
        old["openclaw.sqlite"] != new["openclaw.sqlite"]
        or old["openclaw.sqlite"]["digest"]
        != "sha256:40cf07c52bfaa52b334ef341456f970787f6dc701ffe18ad3c572cb5056dbd70"
        or old["openclaw.sqlite"]["size"] != 4_096
        or old["openclaw.sqlite-shm"]["digest"]
        != "sha256:01fe90558d45209fb38f76b86f75b200687f4c31913c462a04bbad6ae6925752"
        or new["openclaw.sqlite-shm"]["digest"]
        != "sha256:ae773d1b7d3813f5ea7189cb88719586431a3b89299cd3bea410df8a4e10c671"
        or old["openclaw.sqlite-wal"]["digest"]
        != "sha256:9044b661736d1dbe885183618c6559a61d2677753c343697a77719a6f80410da"
        or new["openclaw.sqlite-wal"]["digest"]
        != "sha256:9730e3a216a910bf416073008047a4f29488a284bddc04ba9d2dc50fd3a6e338"
        or old["openclaw.sqlite-wal"]["size"] != 3_073_552
        or new["openclaw.sqlite-wal"]["size"] != 3_106_512
    ):
        raise AdmissionEvidenceError(
            "V3 plugin force-reinstall SQLite disclosure changed"
        )


def value_route() -> dict[str, Any]:
    """Expose the exact route identifier for schema tooling."""

    return {"id": _ROUTE, "status": "PASS"}
