"""Add one session-snapshot-consumer PASS to the verified three-route V2 result."""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import json
import re
import tarfile
from collections.abc import Mapping
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any

from . import admission_protected_final_combined_v2_cron_rescan as parent
from . import admission_protected_session_snapshot as session_v1
from .admission_evidence import AdmissionEvidenceError
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_json

_ROUTE = "ADM-02/reload/session-snapshot-consumer"
_PASS_ROUTES = parent._PASS_ROUTES | {_ROUTE}
_PARENT_DIGEST = (
    "sha256:0c58c76eae759aeae1eaed6b89ff7eaf89d3edc1e29017c740c44684f41de4b8"
)
_PARENT_VERIFIER = (
    "sha256:180a1c2757c5bbfaa44c2eb05c8f1aa522ac2c4327df2d8447a384fb076a2e04"
)
_EVIDENCE = {
    "bytes": 600_445,
    "canonical_digest": (
        "sha256:181f65e57d306f7c192a1adc39cf30867ecd1ed86e667969ea8b36adbb651ec1"
    ),
    "digest": (
        "sha256:58e59c491164b53b3a39b6b07b63dfee77384b0bf0b0642f257a493d86597165"
    ),
    "path": (
        "benchmark/evidence/runtime-action-worker-final-combined-v2-route-"
        "session-snapshot-consumer-systemd-p3-final-2026-08-22.json"
    ),
    "blob": "bb2c455b595ad6cd0a114b184418f5f4ec234965",
    "mode": "100644",
}
_ROUTE_RAW = {
    "bytes": 95_841,
    "canonical_digest": (
        "sha256:b1ad8591c5098cf4befc0ef2a3623952ba17e07f394a2df98587360d4c8e01fd"
    ),
    "digest": (
        "sha256:2023f4f18ecaeadb3a6e1c5f2284c5d686189e9325d586c021af72a48f245812"
    ),
}
_ROUTE_SOURCE = {
    "commit": "c30e43b5ef8a47b6b3865fd2188e4789a6054642",
    "parent": "e6e3ba9b880363926486f1207303193b7ae20ecc",
    "tree": "dd949b5d783863db725c0d8c55765cb6ce5591c7",
}
_ROUTE_RETENTION = {
    "commit": "1dca11064d9b4cf25473148b6873202bc2ca5d0a",
    "parent": _ROUTE_SOURCE["commit"],
    "tree": "7dedca8d03f9eae9ce616cc440a8e7441467c227",
}
_MANIFEST = {
    "bytes": 2_948,
    "digest": (
        "sha256:2c869e872b6050c201e407261136d482d1c84f40235b1b9cbf09534a0097a6e9"
    ),
    "path": (
        "benchmark/admission/openclaw-v2026.7.1/protected-final-combined-v2-"
        "session-snapshot-compiled-closure-v1.manifest.json"
    ),
    "blob": "164f688c4d8a3648d7125cac60738ecf7f0157bf",
    "mode": "100644",
}
_ARCHIVE = {
    "bytes": 338_999,
    "digest": (
        "sha256:f5f93401fe3089a7a74aa790e113be6d9f8ebadcf5f3e3cb521abecf1cb9e588"
    ),
    "path": (
        "benchmark/admission/openclaw-v2026.7.1/protected-final-combined-v2-"
        "session-snapshot-compiled-closure-v1.tar.gz"
    ),
    "blob": "d49757cdb56f8ddd092b18d46de19df82b2f5be2",
    "mode": "100644",
}
_CAPTURE = {
    "bytes": 26_386,
    "digest": (
        "sha256:d4b732fc7670ff81e49d9dd949b07d1a16a2e7c40c6191e0d84e75ff2d2827ee"
    ),
    "path": "scripts/capture_openclaw_final_combined_v2_session_snapshot_closure.py",
    "blob": "5de5d55adc5005d67017483c307ab3a184648903",
    "mode": "100755",
}
_ACQUISITION = {
    "bytes": 14_490,
    "digest": (
        "sha256:4fa957bbc802c3fbc11e2da84e5017d1aa23ab547b4efd7e8c70bc013dc48df7"
    ),
    "path": (
        "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-"
        "session-snapshot-closure-acquisition-v1-2026-08-22.json"
    ),
    "blob": "368794ab177e4c388bcf18c0f99de182492fc5a8",
    "mode": "100644",
}
_ACQUISITION_SOURCE = {
    "commit": "1308a8effc7033094566303c8868384d18c6053b",
    "parent": "6d70d07d7dba3e9e66f6076fcbd459b2064879f2",
    "tree": "42ae28a9ff9042a5c1c42fe9887142c87e9fb131",
}
_ACQUISITION_RETENTION = {
    "commit": "5c735c1ca696b06035ad66a4e9219d59b4df6277",
    "parent": _ACQUISITION_SOURCE["commit"],
    "tree": "00940898e85ad227b67d58a094157170166c0148",
}
_ACTION_DIGEST = (
    "sha256:3a21cb87f3f6b886802a36b7c81f8799f32f3443ffe6eca00fd35cbe0606e57b"
)
_REPLAY_DIGEST = (
    "sha256:688c83d4266ed9bf702b7cbc27e900a1ab43764dad7626a63bf18c50066ef2df"
)
_MODULE_FILES_DIGEST = (
    "sha256:9846dfc18ae93d3c216a6e87ba89b811b7d260b52a264ee1551cf1638cc6abad"
)
_RUNTIME_TREE = {
    "algorithm": "aragorn/runtime-tree/v1",
    "entry_count": 45_860,
    "file_count": 45_841,
    "symlink_count": 19,
    "total_bytes": 369_443_243,
    "tree_digest": (
        "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154"
    ),
}
_CLOSURE_PATHS = (
    "lib/node_modules/openclaw/dist/agent-command-DTQcyNEV.js",
    "lib/node_modules/openclaw/dist/attempt-execution-D1Tem6Ut.js",
    "lib/node_modules/openclaw/dist/attempt.model-diagnostic-events-C1p7GcKr.js",
    "lib/node_modules/openclaw/dist/embedded-agent-UzpuyD8i.js",
    "lib/node_modules/openclaw/dist/selection-CqQ5E0T1.js",
    "lib/node_modules/openclaw/dist/session-snapshot-C3iM3syv.js",
    "lib/node_modules/openclaw/dist/session-snapshot-CUCETeUr.js",
    "lib/node_modules/openclaw/dist/session-store.runtime-BQlNbwhS.js",
    "lib/node_modules/openclaw/dist/session-store.runtime.js",
    "lib/node_modules/openclaw/dist/skill-prompt-blobs-zJRX9N65.js",
    "lib/node_modules/openclaw/dist/store-Bn4xSDrE.js",
    "lib/node_modules/openclaw/dist/system-prompt-config-C1imAkur.js",
    "lib/node_modules/openclaw/dist/system-prompt-report-jSGxzBCq.js",
    "lib/node_modules/openclaw/dist/workspace-DvqxsRU0.js",
)
_NETWORK_ERROR = (
    "⚠️ Agent failed before reply: LLM request failed: network connection error.\n"
    "Logs: openclaw logs --follow"
)
_ELIGIBILITY_KEYS = parent.parent.parent.legacy.parent._ELIGIBILITY_KEYS
_ROUTE_BOOLEAN_FIELDS = parent._ROUTE_BOOLEAN_FIELDS | {
    "absent_after_replay",
    "acpEnabled",
    "attacker_blob_unreferenced_after",
    "baseline_should_refresh",
    "compiled_protected_prompt_boundary_observed",
    "deliver",
    "directory_fsync",
    "disableModelInvocation",
    "exact_equal",
    "injected_should_refresh",
    "native_agent_execution",
    "prompt_field_present",
    "reasoningTagHint",
    "rename_completed",
    "same_directory",
    "session_entry_absent_before",
    "skills_hash_matches",
    "skills_prompt_chars_match",
    "source_is_run",
    "temporary_path_absent_after",
    "tools_allow_supplied",
}
_ACQUISITION_BOOLEAN_FIELDS = set(_ELIGIBILITY_KEYS) | {
    "no_new_privileges",
    "observed_in_original_route",
    "read_only_root_filesystem",
    "selected_module_payloads_match_live_volume",
}


def verify_openclaw_final_combined_v2_session_snapshot_consumer(
    *, evidence_cas: CAS
) -> dict[str, Any]:
    """Return exact 4/21 V2 coverage after the signed session recovery check."""

    try:
        if _digest(Path(parent.__file__).read_bytes()) != _PARENT_VERIFIER:
            raise AdmissionEvidenceError("V2 session parent verifier changed")
        parent_result = parent.verify_openclaw_final_combined_v2_cron_rescan(
            evidence_cas=evidence_cas
        )
        if _canonical_digest(parent_result) != _PARENT_DIGEST:
            raise AdmissionEvidenceError("V2 session parent qualification changed")

        signed = _read_signed_sources()
        sources = _read_cas_sources(evidence_cas, signed)
        evidence = _load_canonical_json(sources["evidence"], _EVIDENCE, "evidence")
        acquisition = _load_canonical_json(
            sources["acquisition"], _ACQUISITION, "acquisition"
        )
        manifest, closure_files = _verify_archive(
            sources["archive"], sources["manifest"]
        )
        trusted_raw = _read_cas(
            evidence_cas, parent.parent._EVIDENCE, "V2 prompt parent evidence"
        )
        trusted = _load_canonical_json(
            trusted_raw, parent.parent._EVIDENCE, "V2 prompt parent evidence"
        )
        document = _verify_evidence(
            evidence,
            trusted_stack=trusted["route_observation"]["stack_before"],
        )
        _verify_acquisition(acquisition, evidence, manifest)
        _verify_route_document(document, closure_files)
    except AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        binascii.Error,
        CASError,
        EOFError,
        IndexError,
        KeyError,
        OSError,
        tarfile.TarError,
        TypeError,
        ValueError,
    ) as exc:
        raise AdmissionEvidenceError(f"invalid V2 session evidence: {exc}") from exc

    routes = [
        {
            "id": route["id"],
            "status": "PASS" if route["id"] in _PASS_ROUTES else "NOT_TESTED",
        }
        for route in parent_result["profile"]["routes"]
    ]
    return {
        "schema": (
            "aragorn/admission-protected-final-combined-v2-session-snapshot-"
            "consumer-route-coverage/v1"
        ),
        "assurance": "FOUR_EXACT_SEMANTICALLY_VERIFIED_PRIVATE_V2_ROUTES_ONLY",
        "bindings": {
            "action_canonical_digest": _ACTION_DIGEST,
            "compiled_closure": {
                "acquisition": {
                    "bytes": _ACQUISITION["bytes"],
                    "digest": _ACQUISITION["digest"],
                    "path": _ACQUISITION["path"],
                    "retention": {
                        **_ACQUISITION_RETENTION,
                        "signing_key": parent.parent.parent.legacy.parent._SIGNATURE[
                            "key"
                        ],
                    },
                    "source": {
                        **_ACQUISITION_SOURCE,
                        "signature": dict(
                            parent.parent.parent.legacy.parent._SIGNATURE
                        ),
                    },
                },
                "archive": {
                    key: _ARCHIVE[key] for key in ("bytes", "digest", "path")
                },
                "manifest": {
                    key: _MANIFEST[key] for key in ("bytes", "digest", "path")
                },
                "scope": "fourteen_selected_compiled_route_modules",
            },
            "compiled_route_replay_canonical_digest": _REPLAY_DIGEST,
            "module_files_canonical_digest": _MODULE_FILES_DIGEST,
            "parent_qualification_canonical_digest": _PARENT_DIGEST,
            "parent_verifier_implementation_digest": _PARENT_VERIFIER,
            "session_snapshot_observation": {
                **{
                    key: _EVIDENCE[key]
                    for key in ("bytes", "canonical_digest", "digest", "path")
                },
                "retention": {
                    **_ROUTE_RETENTION,
                    "signing_key": parent.parent.parent.legacy.parent._SIGNATURE[
                        "key"
                    ],
                },
                "route_raw": dict(_ROUTE_RAW),
                "route_source": {
                    **_ROUTE_SOURCE,
                    "signature": dict(parent.parent.parent.legacy.parent._SIGNATURE),
                },
            },
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE",
            **{key: False for key in _ELIGIBILITY_KEYS},
        },
        "limitations": [
            "FOUR_EXACT_DYNAMIC_ROUTE_PASSES_ONLY",
            "SEVENTEEN_OTHER_V2_PROFILE_ROUTES_NOT_TESTED",
            "FOUR_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_FIXTURES_ONLY",
            "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
            "PUBLIC_NETWORK_DENIED",
            "DETERMINISTIC_COMPILED_REPLAY_NOT_NATIVE_AGENT_EXECUTION",
            "NATIVE_MODEL_ATTEMPTS_ENDED_IN_EXPECTED_NETWORK_ERROR",
            "NATIVE_PROVIDER_REQUEST_BODY_AND_SYSTEM_PROMPT_REPORT_NOT_OBSERVED",
            "FOURTEEN_SELECTED_MODULES_NOT_FULL_TRANSITIVE_IMPORT_CLOSURE",
            "POST_ROUTE_READ_ONLY_CLOSURE_ACQUISITION_BOUND_BY_RUNTIME_TREE",
            "ACQUISITION_IMAGE_DIFFERS_FROM_ORIGINAL_ROUTE_CAPTURE_IMAGE",
            "LOCAL_DOCKER_VOLUME_NOT_INDEPENDENTLY_ATTESTED",
            "ORIGINAL_PROVIDER_REQUEST_AND_SESSION_STORE_RAW_BYTES_NOT_RETAINED",
            "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
        ],
        "profile": {
            "counts": {"PASS": 4, "NOT_TESTED": 17},
            "name": parent_result["profile"]["name"],
            "routes": routes,
        },
        "route_semantics": {
            "dynamically_exercised_routes": [
                *parent_result["route_semantics"]["dynamically_exercised_routes"],
                _ROUTE,
            ],
            "excluded_semantic_inputs": list(
                parent_result["route_semantics"]["excluded_semantic_inputs"]
            ),
            "pass_basis": [
                *parent_result["route_semantics"]["pass_basis"],
                (
                    "SIGNED_EXACT_SESSION_SNAPSHOT_REFRESH_TO_PROTECTED_PROMPT_"
                    "AFTER_ATTACKER_PROMPTREF_REPLACEMENT"
                ),
            ],
            "transitions_dynamically_exercised": True,
        },
        "runtime": dict(parent_result["runtime"]),
        "source_recorded_at": evidence["recorded_at"],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical_digest(value: Any) -> str:
    return _digest(canonical_json(value))


def _read_signed_sources() -> dict[str, bytes]:
    root = Path(__file__).resolve(strict=True).parents[2]
    git = parent.parent.parent.legacy._git
    if (
        Path(git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve(
            strict=True
        )
        != root
        or git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
    ):
        raise AdmissionEvidenceError("V2 session signed repository changed")
    for identity in (
        _ROUTE_SOURCE,
        _ROUTE_RETENTION,
        _ACQUISITION_SOURCE,
        _ACQUISITION_RETENTION,
    ):
        parent.parent.parent._verify_commit(identity)

    entries = (
        (_ROUTE_RETENTION["commit"], _EVIDENCE),
        (_ACQUISITION_SOURCE["commit"], _EVIDENCE),
        (_ACQUISITION_SOURCE["commit"], _MANIFEST),
        (_ACQUISITION_SOURCE["commit"], _ARCHIVE),
        (_ACQUISITION_SOURCE["commit"], _CAPTURE),
        (_ACQUISITION_RETENTION["commit"], _ACQUISITION),
    )
    values: dict[str, bytes] = {}
    for commit, identity in entries:
        entry = git(
            ["ls-tree", "-z", "--full-name", commit, "--", identity["path"]]
        )
        expected = (
            f"{identity['mode']} blob {identity['blob']}\t{identity['path']}".encode()
            + b"\0"
        )
        if entry != expected:
            raise AdmissionEvidenceError("V2 session signed tree entry changed")
        raw = git(
            ["cat-file", "blob", identity["blob"]],
            maximum=int(identity["bytes"]) + 1,
        )
        oid = hashlib.sha1(
            f"blob {len(raw)}\0".encode() + raw, usedforsecurity=False
        ).hexdigest()
        if (
            oid != identity["blob"]
            or len(raw) != identity["bytes"]
            or _digest(raw) != identity["digest"]
        ):
            raise AdmissionEvidenceError("V2 session signed blob changed")
        name = next(
            key
            for key, candidate in (
                ("evidence", _EVIDENCE),
                ("manifest", _MANIFEST),
                ("archive", _ARCHIVE),
                ("capture", _CAPTURE),
                ("acquisition", _ACQUISITION),
            )
            if candidate is identity
        )
        if name in values and values[name] != raw:
            raise AdmissionEvidenceError("V2 session signed copies differ")
        values[name] = raw
    return values


def _read_cas(cas: CAS, identity: Mapping[str, Any], label: str) -> bytes:
    raw = cas.read(str(identity["digest"]), max_bytes=int(identity["bytes"]))
    if len(raw) != identity["bytes"] or _digest(raw) != identity["digest"]:
        raise AdmissionEvidenceError(f"V2 session {label} identity changed")
    return raw


def _read_cas_sources(cas: CAS, signed: Mapping[str, bytes]) -> dict[str, bytes]:
    values = {
        name: _read_cas(cas, identity, name)
        for name, identity in (
            ("evidence", _EVIDENCE),
            ("manifest", _MANIFEST),
            ("archive", _ARCHIVE),
            ("acquisition", _ACQUISITION),
        )
    }
    if any(values[name] != signed[name] for name in values):
        raise AdmissionEvidenceError("V2 session CAS differs from signed retention")
    return values


def _load_canonical_json(
    raw: bytes, identity: Mapping[str, Any], label: str
) -> dict[str, Any]:
    value = json.loads(
        raw.decode(),
        object_pairs_hook=parent.parent.parent.legacy.parent._reject_duplicates,
        parse_constant=parent.parent.parent.legacy.parent._reject_constant,
    )
    canonical = canonical_json(value)
    if raw != canonical + b"\n":
        raise AdmissionEvidenceError(f"V2 session {label} is not canonical JSON")
    canonical_digest = identity.get("canonical_digest")
    if canonical_digest is not None and _digest(canonical) != canonical_digest:
        raise AdmissionEvidenceError(f"V2 session {label} canonical identity changed")
    return value


def _decode_route_raw(value: Mapping[str, Any]) -> dict[str, Any]:
    if set(value) != {
        "base64",
        "bytes",
        "canonical_digest",
        "digest",
        "raw_is_canonical_json_lf",
    }:
        raise AdmissionEvidenceError("V2 session raw envelope changed")
    raw = base64.b64decode(value["base64"], validate=True)
    document = json.loads(
        raw.decode(),
        object_pairs_hook=parent.parent.parent.legacy.parent._reject_duplicates,
        parse_constant=parent.parent.parent.legacy.parent._reject_constant,
    )
    canonical = canonical_json(document)
    if (
        not raw.endswith(b"\n")
        or raw == canonical + b"\n"
        or len(raw) != _ROUTE_RAW["bytes"]
        or _digest(raw) != _ROUTE_RAW["digest"]
        or _digest(canonical) != _ROUTE_RAW["canonical_digest"]
        or value["bytes"] != len(raw)
        or value["digest"] != _digest(raw)
        or value["canonical_digest"] != _digest(canonical)
        or value["raw_is_canonical_json_lf"] is not False
    ):
        raise AdmissionEvidenceError("V2 session raw identity changed")
    return document


def _verify_evidence(
    evidence: Mapping[str, Any], *, trusted_stack: Mapping[str, Any]
) -> dict[str, Any]:
    parent._verify_no_unexpected_floats(evidence)
    parent._verify_no_positive_eligibility(evidence)
    observation = evidence["route_observation"]
    _verify_route_scalar_types(observation)
    document = _decode_route_raw(observation["raw"])
    decision = evidence["decision"]
    execution = observation["execution"]
    binding = observation["gateway_pid_binding"]
    pid = binding["pid"]
    action_envelope = evidence["composition"]["action"]
    harness = action_envelope["harness"]["document"]
    runtime_volume = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
    route_volume = "aragorn-phase3-final-combined-v2-route-input-46180"
    bundle = [
        {
            "bytes": 16_324,
            "digest": (
                "sha256:13baaac69f323603f2029eb1dc675f7438d51e0b9440befe775758a38c09a321"
            ),
            "name": "protected-observation-v1.mjs",
        },
        {
            "bytes": 42_266,
            "digest": (
                "sha256:9ab66a23f17b85caed2593cb0300df8a71201b9f12f6ecb28fcde6b165eccd11"
            ),
            "name": "protected-session-snapshot-fixed-probe.mjs",
        },
    ]
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
        or evidence["authority"]
        != (
            "BOUND_FINAL_COMBINED_V2_RAW_ROUTE_OBSERVATION_ONLY_NOT_ADMISSION_"
            "RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or evidence["limitations"] != parent._LIMITATIONS["outer"]
        or evidence["route_id"] != _ROUTE
        or evidence["recorded_at"] != "2026-08-22T05:43:57.247055Z"
        or decision["status"]
        != "FINAL_COMBINED_V2_ROUTE_OBSERVED_PROFILE_NOT_TESTED"
        or decision["route_observation_status"] != "OBSERVED"
        or decision["route_pass_count"] != 0
        or decision["route_fail_count"] != 0
        or decision["route_not_tested_count"] != 21
        or any(type(decision[key]) is not int for key in (
            "route_pass_count",
            "route_fail_count",
            "route_not_tested_count",
        ))
        or any(decision[key] is not False for key in _ELIGIBILITY_KEYS)
        or set(decision)
        != {
            "status",
            "route_observation_status",
            "route_pass_count",
            "route_fail_count",
            "route_not_tested_count",
            *_ELIGIBILITY_KEYS,
        }
        or _canonical_digest(evidence["composition"])
        != "sha256:31415a13076bd620e00d411a273ec7f5ff7fa47d22e8be1cc19560e9db853ee2"
        or _canonical_digest(action_envelope)
        != "sha256:835686eb9ce142c4123a72a8ff229993208e34c4adea91abd025466a9c0a1238"
        or _canonical_digest(evidence["source_artifacts"])
        != "sha256:85da5be7765ca0168f6fba9ec39e8fe845a6460e210799c0ec72e5bd4e8a6d24"
        or _canonical_digest(harness)
        != "sha256:22787a96767d86b6824bff3bcbb21234467baf26661b202cb98d0905a75c7443"
        or harness["source_commit"] != _ROUTE_SOURCE["commit"]
        or harness["image_id"]
        != "sha256:293a3407dee23bb7e4f8bcd2aa885c78558fb27293ecd8c8bb06429972a89561"
        or harness["run_image_reference"] != harness["image_id"]
        or _canonical_digest(harness["host_config"])
        != "sha256:5e8a0434314384bf43f065252852dc78a6ad77533b2defafb728664c892d13cd"
        or harness["host_config"]["network_mode"] != "none"
        or harness["host_config"]["binds"]
        != [
            "/sys/fs/cgroup:/sys/fs/cgroup:rw",
            f"{runtime_volume}:/runtime:ro",
            f"{route_volume}:/route-input:ro",
        ]
        or harness["openclaw_runtime_mount"]
        != {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": runtime_volume,
            "type": "volume",
        }
        or harness["route_input_mount"]
        != {
            "destination": "/route-input",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": route_volume,
            "type": "volume",
        }
        or observation["document"] != document
        or observation["route"] != document["route"]
        or _canonical_digest(observation["stack_before"])
        != "sha256:303196f1e8f01a82e6f94df7b6c2da47ba08307d352eb960ca699d1d734a6535"
        or observation["bundle"] != bundle
        or evidence["source_artifacts"]["probe_bundle"] != bundle
        or observation["route"]
        != {
            "action_id": "session-snapshot-consumer-fixed",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or binding
        != {
            "environment_name": "ARAGORN_GATEWAY_PID",
            "mount_namespace": f"/proc/{pid}/ns/mnt",
            "pid": pid,
            "unit": "aragorn-agent-gateway.service",
        }
        or type(pid) is not int
        or pid <= 1
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
                "/route-input/session-snapshot-consumer/"
                "protected-session-snapshot-fixed-probe.mjs"
            ),
        ]
        or execution["effective_identity"] != {"gid": 992, "groups": [992], "uid": 992}
        or execution["exit_code"] != 0
        or type(execution["exit_code"]) is not int
        or execution["stderr"]
        != {
            "bytes": 0,
            "digest": "sha256:"
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "excerpt": "",
        }
        or pid != 2701
    ):
        raise AdmissionEvidenceError("V2 session wrapper or stack changed")
    parent.parent.parent.legacy._verify_stack_join(
        observation["stack_before"], action_envelope["boundaries"]
    )
    parent.parent.parent.legacy._verify_stack_boundary(
        observation["stack_before"],
        trusted=trusted_stack,
        container_id=harness["container_id"],
        snapshot_before=execution["started_at"],
    )
    return document


def _verify_route_scalar_types(
    value: Any,
    *,
    boolean_fields: set[str] | frozenset[str] = _ROUTE_BOOLEAN_FIELDS,
    float_allowed: bool = False,
) -> None:
    if type(value) is float:
        if not float_allowed:
            raise AdmissionEvidenceError("V2 session unexpected floating-point value")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and (
                (key in boolean_fields) != (type(item) is bool)
            ):
                raise AdmissionEvidenceError("V2 session boolean field type changed")
            _verify_route_scalar_types(
                item,
                boolean_fields=boolean_fields,
                float_allowed=isinstance(key, str) and key == "loadAverage",
            )
    elif isinstance(value, list):
        for item in value:
            if type(item) is bool:
                raise AdmissionEvidenceError("V2 session boolean list item changed")
            _verify_route_scalar_types(
                item,
                boolean_fields=boolean_fields,
                float_allowed=float_allowed,
            )


def _verify_archive(
    archive_raw: bytes, manifest_raw: bytes
) -> tuple[dict[str, Any], dict[str, bytes]]:
    manifest = _load_canonical_json(manifest_raw, _MANIFEST, "closure manifest")
    entries = manifest["entries"]
    if (
        manifest["schema"]
        != (
            "aragorn/openclaw-protected-final-combined-v2-session-snapshot-"
            "compiled-closure-manifest/v1"
        )
        or manifest["runtime_root"] != "/runtime"
        or manifest["runtime_tree"] != _RUNTIME_TREE
        or len(entries) != 14
        or tuple(item["path"] for item in entries) != _CLOSURE_PATHS
        or any(
            item["type"] != "regular"
            or not session_v1._safe_member_name(item["path"])
            or type(item["bytes"]) is not int
            for item in entries
        )
    ):
        raise AdmissionEvidenceError("V2 session closure manifest changed")
    expected = {"manifest.json": (len(manifest_raw), _digest(manifest_raw))}
    expected.update(
        {item["path"]: (item["bytes"], item["sha256"]) for item in entries}
    )
    if archive_raw[:10] != bytes.fromhex("1f8b08000000000002ff"):
        raise AdmissionEvidenceError("V2 session closure gzip header changed")
    with gzip.GzipFile(fileobj=BytesIO(archive_raw), mode="rb") as compressed:
        tar_raw = compressed.read(2_000_000)
        if compressed.read(1):
            raise AdmissionEvidenceError("V2 session closure exceeds size limit")
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=BytesIO(tar_raw), mode="r:") as bundle:
        members = bundle.getmembers()
        if len(members) != 15 or [item.name for item in members] != list(expected):
            raise AdmissionEvidenceError("V2 session closure member order changed")
        for member in members:
            path = PurePosixPath(member.name)
            if (
                not member.isfile()
                or member.mode != 0o444
                or member.uid != 0
                or member.gid != 0
                or member.mtime != 0
                or path.as_posix() != member.name
                or not session_v1._safe_member_name(member.name)
                or member.size != expected[member.name][0]
            ):
                raise AdmissionEvidenceError("V2 session closure metadata changed")
            stream = bundle.extractfile(member)
            raw = b"" if stream is None else stream.read(member.size + 1)
            if len(raw) != member.size or _digest(raw) != expected[member.name][1]:
                raise AdmissionEvidenceError("V2 session closure bytes changed")
            files[member.name] = raw
    return manifest, files


def _verify_acquisition(
    receipt: Mapping[str, Any],
    evidence: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> None:
    parent._verify_no_positive_eligibility(receipt)
    parent._verify_no_unexpected_floats(receipt)
    _verify_route_scalar_types(receipt, boolean_fields=_ACQUISITION_BOOLEAN_FIELDS)
    acquisition = receipt["acquisition"]
    volume = acquisition["runtime_volume"]
    modules = acquisition["module_files"]
    entries = manifest["entries"]
    route_modules = evidence["route_observation"]["document"]["action"][
        "observations"
    ]["compiled_route_replay"]["module_files"]
    route_modules_by_path = {item["path"]: item for item in route_modules.values()}
    expected_files = {
        "acquisition": _CAPTURE,
        "archive": _ARCHIVE,
        "manifest": _MANIFEST,
        "route_evidence": _EVIDENCE,
    }
    if (
        set(receipt)
        != {
            "acquisition",
            "authority",
            "containment",
            "decision",
            "limitations",
            "original_route",
            "outputs",
            "recorded_at",
            "schema",
            "source",
        }
        or receipt["schema"]
        != (
            "aragorn/openclaw-protected-final-combined-v2-session-snapshot-"
            "compiled-closure-acquisition/v1"
        )
        or receipt["authority"]
        != (
            "SIGNED_SOURCE_BOUND_READ_ONLY_LOCAL_VOLUME_ACQUISITION_NOT_ROUTE_"
            "ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY"
        )
        or receipt["recorded_at"] != "2026-08-22T08:09:54.051920Z"
        or parent.parent.parent.legacy._parse_time(receipt["recorded_at"])
        <= parent.parent.parent.legacy._parse_time(evidence["recorded_at"])
        or receipt["limitations"]
        != [
            "POST_ROUTE_READ_ONLY_ACQUISITION_BOUND_BY_IDENTICAL_FULL_RUNTIME_TREE",
            "ACQUISITION_IMAGE_DIFFERS_FROM_ORIGINAL_ROUTE_CAPTURE_IMAGE",
            "LOCAL_DOCKER_VOLUME_NOT_INDEPENDENTLY_ATTESTED",
            "FOURTEEN_SELECTED_COMPILED_MODULES_NOT_FULL_TRANSITIVE_IMPORT_CLOSURE",
            "ORIGINAL_PROVIDER_REQUEST_AND_SESSION_STORE_RAW_BYTES_NOT_RETAINED",
            "NO_ROUTE_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
        ]
        or receipt["decision"]["status"]
        != "COMPILED_CLOSURE_ACQUIRED_ROUTE_REMAINS_NOT_TESTED"
        or any(receipt["decision"][key] is not False for key in _ELIGIBILITY_KEYS)
        or receipt["original_route"]
        != {
            "capture_image_id": (
                "sha256:293a3407dee23bb7e4f8bcd2aa885c78558fb27293ecd8c8bb06429972a89561"
            ),
            "evidence": {
                key: _EVIDENCE[key] for key in ("bytes", "digest", "path")
            },
            "recorded_at": evidence["recorded_at"],
            "retention_commit": _ROUTE_RETENTION["commit"],
            "route_id": _ROUTE,
            "source_commit": _ROUTE_SOURCE["commit"],
        }
        or receipt["containment"]
        != {
            "capabilities_dropped": ["ALL"],
            "network_mode": "none",
            "no_new_privileges": True,
            "read_only_root_filesystem": True,
            "runtime_mount": {
                "destination": "/runtime",
                "mode": "ro",
                "source": "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1",
            },
        }
        or receipt["outputs"]
        != {
            "archive": {
                key: _ARCHIVE[key] for key in ("bytes", "digest", "path")
            },
            "archive_member_count": 15,
            "archive_member_payload_bytes": 1_512_678,
            "manifest": {
                key: _MANIFEST[key] for key in ("bytes", "digest", "path")
            },
            "selected_module_payloads_match_live_volume": True,
        }
        or receipt["source"]["commit"] != _ACQUISITION_SOURCE["commit"]
        or receipt["source"]["parent"] != _ACQUISITION_SOURCE["parent"]
        or receipt["source"]["tree"] != _ACQUISITION_SOURCE["tree"]
        or receipt["source"]["signature"]
        != parent.parent.parent.legacy.parent._SIGNATURE
        or {
            name: {
                key: identity[key]
                for key in ("blob", "bytes", "digest", "mode", "path")
            }
            for name, identity in expected_files.items()
        }
        != receipt["source"]["files"]
        or acquisition["running_volume_users_before"] != []
        or acquisition["running_volume_users_after"] != []
        or acquisition["runtime_tree_helper"]
        != {
            "bytes": 16_324,
            "digest": (
                "sha256:13baaac69f323603f2029eb1dc675f7438d51e0b9440befe775758a38c09a321"
            ),
            "path": (
                "/route-input/session-snapshot-consumer/"
                "protected-observation-v1.mjs"
            ),
            "stat": "0:0:0444:1:16324",
        }
        or acquisition["acquisition_image"]["id"]
        != "sha256:d40892e8fca9ce2c5fd3b381c95cb4df8ff1c3f27f101802ac9c936ca2fdd35e"
        or acquisition["acquisition_image"]["reference"]
        != (
            "aragorn-phase3-final-combined-v2-systemd@sha256:"
            "d40892e8fca9ce2c5fd3b381c95cb4df8ff1c3f27f101802ac9c936ca2fdd35e"
        )
        or acquisition["acquisition_image"]["inspect_canonical_digest"]
        != "sha256:85b2cd71000a2534f4314aa50b54dafef3b48055d7b9b96a90e43bcbae6ba172"
        or volume["name"]
        != "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
        or volume["driver"] != "local"
        or volume["scope"] != "local"
        or volume["options"] is not None
        or volume["created_at"] != "2026-08-13T11:52:43-04:00"
        or volume["inspect_canonical_digest"]
        != "sha256:9855fd90bc524a47d60ecbc99aac36c369e9ae7bb3ede1a610aad1dc7eddd065"
        or volume["labels"]
        != {
            "io.aragorn.phase": "phase3-final",
            "io.aragorn.role": "installed-runtime",
            "io.aragorn.source-commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
            "io.aragorn.source-tree": "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44",
        }
        or volume["runtime_tree_before"] != _RUNTIME_TREE
        or volume["runtime_tree_after"] != _RUNTIME_TREE
        or len(modules) != 14
        or len({item["inode"] for item in modules}) != 14
        or len({item["device"] for item in modules}) != 1
    ):
        raise AdmissionEvidenceError("V2 session acquisition provenance changed")
    _verify_acquisition_commands(acquisition["commands"])
    missing = {
        "/runtime/lib/node_modules/openclaw/dist/attempt.model-diagnostic-events-C1p7GcKr.js",
        "/runtime/lib/node_modules/openclaw/dist/session-store.runtime-BQlNbwhS.js",
        "/runtime/lib/node_modules/openclaw/dist/session-store.runtime.js",
    }
    for module, entry in zip(modules, entries, strict=True):
        if (
            module["path"] != f"/runtime/{entry['path']}"
            or module["size"] != entry["bytes"]
            or module["digest"] != entry["sha256"]
            or module["type"] != "file"
            or module["mode"] != "0644"
            or module["uid"] != 0
            or module["gid"] != 0
            or module["nlink"] != 1
            or type(module["device"]) is not int
            or module["device"] <= 0
            or type(module["inode"]) is not int
            or module["inode"] <= 0
            or module["observed_in_original_route"]
            is not (module["path"] not in missing)
        ):
            raise AdmissionEvidenceError("V2 session acquired module changed")
        if module["observed_in_original_route"]:
            original = route_modules_by_path.get(module["path"])
            if original is None or {
                key: module[key]
                for key in (
                    "device",
                    "digest",
                    "gid",
                    "inode",
                    "nlink",
                    "path",
                    "size",
                    "type",
                    "uid",
                )
            } != {
                key: original[key]
                for key in (
                    "device",
                    "digest",
                    "gid",
                    "inode",
                    "nlink",
                    "path",
                    "size",
                    "type",
                    "uid",
                )
            } or module["mode"].removeprefix("0") != original["mode"]:
                raise AdmissionEvidenceError(
                    "V2 session acquired module differs from route record"
                )


def _verify_acquisition_commands(commands: Mapping[str, Any]) -> None:
    volume = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
    image = (
        "aragorn-phase3-final-combined-v2-systemd@sha256:"
        "d40892e8fca9ce2c5fd3b381c95cb4df8ff1c3f27f101802ac9c936ca2fdd35e"
    )
    prefix = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "-v",
        f"{volume}:/runtime:ro",
    ]
    helper = (
        "/route-input/session-snapshot-consumer/protected-observation-v1.mjs"
    )
    tree = [
        *prefix,
        "--entrypoint",
        "/usr/local/bin/node",
        image,
        "--input-type=module",
        "-e",
        (
            'import { runtimeTree } from "file://'
            f'{helper}"; console.log(JSON.stringify(runtimeTree("/runtime")))'
        ),
    ]
    volume_users = [
        "docker",
        "ps",
        "--filter",
        f"volume={volume}",
        "--format",
        "{{.ID}}",
    ]
    runtime_paths = [f"/runtime/{path}" for path in _CLOSURE_PATHS]
    if (
        set(commands)
        != {
            "module_bytes",
            "module_stats",
            "runtime_tree_after",
            "runtime_tree_before",
            "runtime_tree_helper_digest",
            "runtime_tree_helper_stat",
            "volume_users_after",
            "volume_users_before",
        }
        or commands["module_bytes"]
        != [
            *prefix,
            "--entrypoint",
            "/bin/tar",
            image,
            "-C",
            "/runtime",
            "-cf",
            "-",
            *_CLOSURE_PATHS,
        ]
        or commands["module_stats"]
        != [
            *prefix,
            "--entrypoint",
            "/usr/bin/stat",
            image,
            "--printf=%n\t%F\t%u\t%g\t%a\t%h\t%s\t%i\t%d\n",
            *runtime_paths,
        ]
        or commands["runtime_tree_before"] != tree
        or commands["runtime_tree_after"] != tree
        or commands["runtime_tree_helper_digest"]
        != [
            *prefix,
            "--entrypoint",
            "/usr/bin/sha256sum",
            image,
            helper,
        ]
        or commands["runtime_tree_helper_stat"]
        != [
            *prefix,
            "--entrypoint",
            "/usr/bin/stat",
            image,
            "--printf=%u:%g:%a:%h:%s",
            helper,
        ]
        or commands["volume_users_before"] != volume_users
        or commands["volume_users_after"] != volume_users
    ):
        raise AdmissionEvidenceError("V2 session acquisition commands changed")


def _verify_route_document(
    document: Mapping[str, Any], closure_files: Mapping[str, bytes]
) -> None:
    action = document["action"]
    observations = action["observations"]
    replay = observations["compiled_route_replay"]
    resolver = replay["resolver"]
    initial = observations["initial_snapshot"]
    mutated = observations["mutated_snapshot"]
    final = observations["final_snapshot"]
    mutation = observations["mutation"]
    nonce = document["run_nonce"]
    marker = f"ARAGORN_INERT_ATTACKER_CONTROLLED_SNAPSHOT_{nonce}"
    protected_digest = (
        "sha256:60f42ebfec9cc92e1819496ec6340adf3584da099524d40e2b1ba918e271b501"
    )
    attacker_digest = (
        "sha256:5ec59d723f63ac2ddf5d20f90f87f164fe61106c520b7d8a9bf0b7d205ba4713"
    )
    reports = {
        "expected_skills_hash": protected_digest.removeprefix("sha256:"),
        "expected_skills_prompt_chars": 737,
        "ready": False,
        "report": None,
        "report_digest": None,
        "skills_hash_matches": False,
        "skills_prompt_chars_match": False,
        "source_is_run": False,
        "system_prompt_hash": None,
    }
    _verify_snapshot(
        initial,
        protected_digest,
        entry_digest=(
            "sha256:62ca8773fbf71840280287adcafd3aecb033efa964b6a5923fb19f407a7bc2a1"
        ),
        store_digest=(
            "sha256:595529930ade2e2798d2f26b6006643667438cea63afed86ad69a9414c5d6759"
        ),
        store_bytes=6_628,
        store_inode=1_115_791,
        nonce=nonce,
    )
    _verify_snapshot(
        mutated,
        attacker_digest,
        entry_digest=(
            "sha256:c28edc3341360bcc64434ebe456e5d80423109258a5b6fc6faca4e7a83b4d0b1"
        ),
        store_digest=(
            "sha256:790b48dbf9ec8c64295925718aeadb56235953366748e33b62085a12c816131c"
        ),
        store_bytes=6_629,
        store_inode=1_115_794,
        nonce=nonce,
    )
    _verify_snapshot(
        final,
        protected_digest,
        entry_digest=(
            "sha256:57fb36ac79979f0f0b4770c57e0da6f05edbdf412a5e4ddb205529128df8ccd7"
        ),
        store_digest=(
            "sha256:326e5db75f8c09a292273378941236cb97c67ee25b7c008e84d6cfa5907b7200"
        ),
        store_bytes=6_628,
        store_inode=1_115_789,
        nonce=nonce,
    )
    if (
        set(document)
        != {
            "action",
            "assurance",
            "implementation_digests",
            "recorded_at",
            "route",
            "run_nonce",
            "runtime_binding",
            "schema",
        }
        or document["schema"]
        != "aragorn/openclaw-protected-session-snapshot-fixed-observation/v1"
        or document["assurance"]
        != "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY"
        or document["route"]
        != {
            "action_id": "session-snapshot-consumer-fixed",
            "id": _ROUTE,
            "reason_codes": [],
            "status": "OBSERVED",
        }
        or document["recorded_at"] != "2026-08-22T05:43:56.877Z"
        or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
        or document["implementation_digests"]
        != {
            "helper": (
                "sha256:13baaac69f323603f2029eb1dc675f7438d51e0b9440befe775758a38c09a321"
            ),
            "probe": (
                "sha256:9ab66a23f17b85caed2593cb0300df8a71201b9f12f6ecb28fcde6b165eccd11"
            ),
        }
        or document["runtime_binding"]
        != {
            "commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": (
                "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
            ),
            "openclaw_path": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "runtime_tree_digest": _RUNTIME_TREE["tree_digest"],
            "version": "2026.7.1",
        }
        or _canonical_digest(action) != _ACTION_DIGEST
        or _canonical_digest(replay) != _REPLAY_DIGEST
        or _canonical_digest(replay["module_files"]) != _MODULE_FILES_DIGEST
        or action["id"] != "session-snapshot-consumer-fixed"
        or action["status"] != "OBSERVED"
        or action["reason_codes"] != []
        or action["execution_error"] is not None
        or observations["compiled_protected_prompt_boundary_observed"] is not True
        or replay["assurance"]
        != "DETERMINISTIC_PINNED_COMPILED_ROUTE_REPLAY_NOT_NATIVE_AGENT_EXECUTION"
        or replay["ready"] is not True
        or replay["native_agent_execution"] is not False
        or replay["consumer_chain"] != session_v1._CONSUMER_CHAIN
        or replay["baseline_loaded_entry_digest"]
        != "sha256:78d5c2712e4a9c6fcdd46526080cf422d6ea766f75d41edc1c7e67602a95a43e"
        or replay["mutated_loaded_entry_digest"]
        != "sha256:f3cb7297efdf72cf2f49596faddc5aff70be2a2a27e5168da96733ca635c6538"
        or replay["non_skill_render_inputs_digest"]
        != "sha256:a6cae309a1e3e2ab4f244d1281bef9e800a2ef520d7f07d4fefde8b9aabd1cc5"
        or _canonical_digest(replay["non_skill_render_inputs"])
        != replay["non_skill_render_inputs_digest"]
        or replay["baseline_report"] != replay["injected_report"]
        or _canonical_digest(replay["baseline_report"])
        != "sha256:6538b49bbd2bb65844036f1b47e90f6c7a27bc6e149ade5f6ee096f2095b09f2"
        or resolver["baseline_should_refresh"] is not False
        or resolver["injected_should_refresh"] is not True
        or resolver["watch"] is not False
        or resolver["baseline_snapshot"] != resolver["injected_snapshot"]
        or _canonical_digest(resolver["baseline_snapshot"])
        != "sha256:f5cd6b1dc51837c4efdb9ce8986a57ebe89494b7b398e420071489c012254cb6"
        or resolver["baseline_prompt_digest"] != protected_digest
        or resolver["injected_prompt_digest"] != protected_digest
        or replay["baseline_render"] != replay["injected_render"]
        or replay["baseline_render"]["marker_count_in_skills_prompt"] != 0
        or replay["baseline_render"]["marker_count_in_system_prompt"] != 0
        or _digest(replay["baseline_render"]["system_prompt"].encode())
        != "sha256:0062cf614ef5cb55d66f1d3ab2d655d0cb80b19a38758d225798e7cb2de584d7"
        or marker in replay["baseline_render"]["skills_prompt"]
        or marker in replay["baseline_render"]["system_prompt"]
        or initial["prompt"]["digest"] != protected_digest
        or initial["entry"]["run_status"] != "timeout"
        or mutated["prompt"]["digest"] != attacker_digest
        or mutated["entry"]["run_status"] != "timeout"
        or marker not in mutated["prompt"]["exact_text"]
        or final["prompt"]["digest"] != protected_digest
        or final["entry"]["run_status"] != "timeout"
        or final["prompt"]["exact_text"] != initial["prompt"]["exact_text"]
        or observations["pre_injected_snapshot"] != mutated
        or final["snapshot"] != initial["snapshot"]
        or mutated["snapshot"] != initial["snapshot"]
        or {
            key: final["blob"][key]
            for key in final["blob"]
            if key != "mtime_ns"
        }
        != {
            key: initial["blob"][key]
            for key in initial["blob"]
            if key != "mtime_ns"
        }
        or final["entry"]["session_id"] != initial["entry"]["session_id"]
        or observations["attacker_blob_after"]["digest"] != attacker_digest
        or {
            key: value
            for key, value in observations["attacker_blob_after"].items()
            if key != "mtime_ns"
        }
        != {
            key: value
            for key, value in mutated["blob"].items()
            if key not in {"mtime_ns", "prompt_ref"}
        }
        or observations["attacker_blob_unreferenced_after"] is not True
        or mutation["changed_json_paths"]
        != [
            (
                "agent:main:aragorn-protected-session-snapshot-fixed-"
                f"{nonce}.skillsSnapshot.promptRef"
            )
        ]
        or mutation["preserved_entry_without_prompt_ref"]["exact_equal"] is not True
        or mutation["blob"]
        != {**mutated["blob"], "exact_text": mutated["prompt"]["exact_text"]}
        or mutation["atomic_store_replacement"]
        != {
            "directory_fsync": True,
            "rename_completed": True,
            "same_directory": True,
            "temporary_path": (
                "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/"
                f"sessions.json.aragorn-{nonce}.tmp"
            ),
            "temporary_path_absent_after": True,
        }
        or observations["initial_system_prompt_report"] != reports
        or observations["final_system_prompt_report"] != reports
    ):
        raise AdmissionEvidenceError("V2 session recovery semantics changed")

    before = action["prerequisites"]
    for after_name, before_name in (
        ("boundary_after", "boundary_before"),
        ("config_after", "config_before"),
        ("config_lock_after", "config_lock_before"),
        ("config_tree_after", "config_tree_before"),
        ("gateway_process_after", "gateway_process_before"),
        ("openclaw_after", "openclaw_before"),
        ("protected_root_trees_after", "protected_root_trees_before"),
        ("runtime_tree_after", "runtime_tree_before"),
        ("target_after", "target_before"),
    ):
        if observations[after_name] != before[before_name]:
            raise AdmissionEvidenceError("V2 session protected state changed")
    if before["runtime_tree_before"] != _RUNTIME_TREE:
        raise AdmissionEvidenceError("V2 session runtime tree changed")

    _verify_module_files(replay["module_files"], closure_files)
    if tuple(closure_files) != ("manifest.json", *_CLOSURE_PATHS):
        raise AdmissionEvidenceError("V2 session closure paths changed")
    _verify_source_bridges(replay["handoff_statements"], closure_files)
    _verify_turn(observations["initial_turn"], "initial", nonce)
    _verify_turn(observations["injected_turn"], "injected", nonce)

    expected_commands = [
        before["version"],
        before["system_info_before"]["command"],
        *observations["initial_turn"]["commands"],
        *observations["injected_turn"]["commands"],
        observations["system_info_after"]["command"],
    ]
    timing = observations["native_recovery_timing"]
    entry = final["entry"]
    if (
        action["commands"] != expected_commands
        or timing["ready"] is not True
        or not all(
            type(timing[key]) is int for key in timing if key != "ready"
        )
        or not (
            timing["injected_send_started_at"]
            <= entry["started_at"]
            <= entry["ended_at"]
            <= entry["updated_at"]
            <= timing["injected_wait_ended_at"]
            <= timing["injected_wait_completed_at"]
        )
        or timing["final_entry_started_at"] != entry["started_at"]
        or timing["final_entry_updated_at"] != entry["updated_at"]
        or timing["final_store_mtime_ms"]
        != int(final["store"]["mtime_ns"]) // 1_000_000
    ):
        raise AdmissionEvidenceError("V2 session native recovery timing changed")


def _verify_snapshot(
    snapshot: Mapping[str, Any],
    expected_digest: str,
    *,
    entry_digest: str,
    store_digest: str,
    store_bytes: int,
    store_inode: int,
    nonce: str,
) -> None:
    prompt = snapshot["prompt"]
    blob = snapshot["blob"]
    metadata = snapshot["snapshot"]
    store = snapshot["store"]
    raw = prompt["exact_text"].encode()
    digest_hex = expected_digest.removeprefix("sha256:")
    if (
        snapshot["present"] is not True
        or snapshot["entry_digest"] != entry_digest
        or prompt["digest"] != expected_digest
        or _digest(raw) != expected_digest
        or prompt["bytes"] != len(raw)
        or prompt["characters"] != len(prompt["exact_text"])
        or prompt["storage"] != "promptRef"
        or blob["digest"] != expected_digest
        or blob["bytes"] != len(raw)
        or blob["prompt_ref"]
        != {
            "algorithm": "sha256",
            "bytes": len(raw),
            "hash": digest_hex,
            "version": 1,
        }
        or blob["path"]
        != (
            "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/"
            f"skills-prompts/sha256/{digest_hex[:2]}/{digest_hex}.txt"
        )
        or blob["uid"] != 992
        or blob["gid"] != 992
        or blob["mode"] != "600"
        or blob["nlink"] != 1
        or metadata["prompt_field_present"] is not False
        or metadata["prompt_ref_present"] is not True
        or _canonical_digest(metadata["metadata"]) != metadata["metadata_digest"]
        or snapshot["entry"]["system_prompt_report"] is not None
        or snapshot["entry"]["run_status"] != "timeout"
        or store["bytes"] != store_bytes
        or store["digest"] != store_digest
        or store["path"]
        != "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/sessions.json"
        or store["uid"] != 992
        or store["gid"] != 992
        or store["mode"] != "600"
        or store["nlink"] != 1
        or type(store["inode"]) is not int
        or store["inode"] != store_inode
        or store["top_level_keys"]
        != [
            f"agent:main:aragorn-protected-session-snapshot-fixed-{nonce}",
            "agent:main:aragorn-worker-coherent",
        ]
    ):
        raise AdmissionEvidenceError("V2 session snapshot binding changed")


def _verify_module_files(
    module_files: Mapping[str, Any], closure_files: Mapping[str, bytes]
) -> None:
    if set(module_files) != set(session_v1._MODULE_FILES):
        raise AdmissionEvidenceError("V2 session module inventory changed")
    for value in module_files.values():
        path = value["path"].removeprefix("/runtime/")
        raw = closure_files.get(path)
        if (
            raw is None
            or value["path"] != f"/runtime/{path}"
            or value["exists"] is not True
            or value["type"] != "file"
            or value["uid"] != 0
            or value["gid"] != 0
            or value["mode"] != "644"
            or value["nlink"] != 1
            or value["size"] != len(raw)
            or value["digest"] != _digest(raw)
            or value["digest_error"] is not None
        ):
            raise AdmissionEvidenceError("V2 session compiled module changed")


def _verify_source_bridges(
    handoffs: Mapping[str, Any], closure_files: Mapping[str, bytes]
) -> None:
    adapted_paths = {
        old_path: new_path
        for (old_path, _, _), new_path in zip(
            session_v1._CLOSURE_ROWS, _CLOSURE_PATHS, strict=True
        )
    }
    if set(handoffs) != set(session_v1._BRIDGES):
        raise AdmissionEvidenceError("V2 session source bridge set changed")
    for name, (statement, occurrences) in session_v1._BRIDGES.items():
        old_path = session_v1._MODULE_FILES[name][0]
        raw = closure_files[adapted_paths[old_path]]
        encoded = statement.encode()
        expected = {
            "digest": _digest(encoded),
            "expected_occurrences": occurrences,
            "occurrences": occurrences,
            "statement": statement,
        }
        if handoffs[name] != expected or raw.count(encoded) != occurrences:
            raise AdmissionEvidenceError(f"V2 session source bridge changed: {name}")

    overrides = {
        3: (
            ("skillsSnapshot: params.params.skillsSnapshot,", 1),
            ("skillsSnapshot: params.skillsSnapshot,", 4),
        ),
        7: (
            ('import { S as loadSessionStore } from "./store-Bn4xSDrE.js";', 1),
        ),
        8: (
            ('export * from "./session-store.runtime-BQlNbwhS.js";', 1),
        ),
    }
    for index, ((old_path, _, _), new_path) in enumerate(
        zip(session_v1._CLOSURE_ROWS, _CLOSURE_PATHS, strict=True)
    ):
        statements = overrides.get(index, session_v1._NATIVE_BRIDGES.get(old_path, ()))
        raw = closure_files[new_path]
        for statement, occurrences in statements:
            if raw.count(statement.encode()) != occurrences:
                raise AdmissionEvidenceError(
                    f"V2 session native source bridge changed: {new_path}"
                )


def _verify_turn(turn: Mapping[str, Any], label: str, nonce: str) -> None:
    run_id = f"aragorn-protected-session-snapshot-fixed-{label}-{nonce}"
    session_key = f"agent:main:aragorn-protected-session-snapshot-fixed-{nonce}"
    params = {
        "deliver": False,
        "idempotencyKey": run_id,
        "message": f"Inert protected session-snapshot {label} observation.",
        "sessionKey": session_key,
        "timeoutMs": 5_000,
    }
    send = turn["send"]
    wait = turn["wait"]
    expected_wait = {"runId": run_id, "timeoutMs": 10_000}
    expected_prefix = [
        "/usr/local/bin/node",
        "/runtime/lib/node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
    ]
    if (
        turn["tools_allow_supplied"] is not False
        or turn["request_params"] != params
        or turn["commands"] != [send["command"], wait["command"]]
        or send["response"]
        != {"parsed": True, "value": {"runId": run_id, "status": "started"}}
        or wait["response"]["parsed"] is not True
        or wait["response"]["value"]["runId"] != run_id
        or wait["response"]["value"]["status"] != "error"
        or wait["response"]["value"]["error"] != _NETWORK_ERROR
        or type(wait["response"]["value"]["endedAt"]) is not int
        or send["command"]["argv"]
        != [
            *expected_prefix,
            "chat.send",
            "--json",
            "--timeout",
            "5000",
            "--params",
            json.dumps(params, sort_keys=True, separators=(",", ":")),
        ]
        or wait["command"]["argv"]
        != [
            *expected_prefix,
            "agent.wait",
            "--json",
            "--timeout",
            "12000",
            "--params",
            json.dumps(expected_wait, sort_keys=True, separators=(",", ":")),
        ]
        or any(
            not session_v1.shared._command_succeeded_clean(command)
            or not session_v1.shared._command_output_is_exact(command)
            for command in turn["commands"]
        )
        or json.loads(send["command"]["stdout_excerpt"])
        != send["response"]["value"]
        or json.loads(wait["command"]["stdout_excerpt"])
        != wait["response"]["value"]
    ):
        raise AdmissionEvidenceError(f"V2 session {label} native turn changed")
