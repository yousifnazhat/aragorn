"""Qualify five exact final-profile routes by static ADM-02 gate or deny."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any

from . import admission_evidence, cas, oci_worker_protocol

_ROUTES = (
    "ADM-02/update/archive-source-force-replacement",
    "ADM-02/update/clawhub-tracked-replacement",
    "ADM-02/update/config-entry-activation",
    "ADM-02/update/core-updater-plugin-replacement",
    "ADM-02/update/curator-restore-activation",
    "ADM-02/update/plugin-enable-activation",
    "ADM-02/update/plugin-force-reinstall",
    "ADM-02/update/plugin-package-skill-replacement",
    "ADM-02/update/workshop-proposal-apply",
    "ADM-02/reload/chat-session-snapshot-consumer",
    "ADM-02/reload/config-invalidation",
    "ADM-02/reload/cron-rescan",
    "ADM-02/reload/filesystem-watch-invalidation",
    "ADM-02/reload/fresh-session-reset",
    "ADM-02/reload/manual-plugin-invalidation",
    "ADM-02/reload/missing-prompt-blob-rebuild",
    "ADM-02/reload/plugin-skill-dir-activation",
    "ADM-02/reload/remote-eligibility-invalidation",
    "ADM-02/reload/sandbox-per-run-rescan",
    "ADM-02/reload/session-snapshot-consumer",
    "ADM-02/reload/workshop-invalidation",
)
_PASS_ROUTES = frozenset(
    {
        "ADM-02/reload/config-invalidation",
        "ADM-02/reload/filesystem-watch-invalidation",
        "ADM-02/reload/manual-plugin-invalidation",
        "ADM-02/reload/plugin-skill-dir-activation",
        "ADM-02/reload/sandbox-per-run-rescan",
    }
)
_ELIGIBILITY_KEYS = (
    "admission_profile_eligible",
    "aggregate_admission_eligible",
    "edr_eligible",
    "installer_work_eligible",
    "phase3_exit_eligible",
    "release_eligible",
    "run_01_eligible",
    "run_02_eligible",
    "run_eligible",
)
_SOURCES = {
    "composition": {
        "bytes": 347_400,
        "canonical_bytes": 347_399,
        "canonical_digest": (
            "sha256:9ab4a10500f6ec64958522c297ed88d091b4e6101cd68e0588d8779039ccfa37"
        ),
        "digest": (
            "sha256:281c2de033ed033cc8df71a2e45a4e058005eb4764dd926d8b5422280ed8a029"
        ),
    },
    "configuration": {
        "bytes": 1_812,
        "canonical_bytes": 1_811,
        "canonical_digest": (
            "sha256:ae9d44f2c347a8b10a689d55c435ed0106a2a7aec40e0c6ceaefd0ea99d2564d"
        ),
        "digest": (
            "sha256:3b7218cb95bae1f7cfa3c00b499337af39bf55e3658430bfcbae62edd388d235"
        ),
    },
    "profile": {
        "bytes": 4_768,
        "canonical_bytes": 4_767,
        "canonical_digest": (
            "sha256:47503f7af99a36635f23a0f6e8b7982b8565a7e1773a9d113d697480e95065a8"
        ),
        "digest": (
            "sha256:78d7f9c5c4264c7950001b73dc9b8508dec0bb47d33b9258069106c550240670"
        ),
    },
    "runtime_lock": {
        "bytes": 6_149,
        "canonical_bytes": 6_148,
        "canonical_digest": (
            "sha256:5fa6df1b898a21c266853c10d7086bfc4f45c5141f866219ef2e3e5ace224e96"
        ),
        "digest": (
            "sha256:495f783f0bf1f942d186ba0720cc23ff9693995ff885226a88ab5ce5e5b76c3b"
        ),
    },
    "skill": {
        "bytes": 140,
        "digest": (
            "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa"
        ),
    },
    "plugin_index": {
        "bytes": 23_860,
        "digest": (
            "sha256:71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b"
        ),
    },
    "plugin_manifest": {
        "bytes": 723,
        "canonical_bytes": 722,
        "canonical_digest": (
            "sha256:71fc23aa5039af257578777fd05fd448c233f31c008f1bdf07c169bbfe3d48f6"
        ),
        "digest": (
            "sha256:d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036"
        ),
    },
    "plugin_package": {
        "bytes": 134,
        "canonical_bytes": 133,
        "canonical_digest": (
            "sha256:99de8701204a7c8f083926a3c9d27dd54bea38f56a80647c33ffadeb0914afcc"
        ),
        "digest": (
            "sha256:0097f2e532b1a5d99e3cfc4990d4bbf83a01c10ee11d567b139bd9144a859ad2"
        ),
    },
}
_DEPENDENCY_DIGESTS = {
    "admission_evidence": (
        "sha256:9699307c3fc079e8e58d32048a875386cd4c67499111657cedc7c06db64fbf6b"
    ),
    "cas": "sha256:c5642f910ac4b2d6172a59a02105b359cb43d3a2f2e2240368229d3436ad4859",
    "oci_worker_protocol": (
        "sha256:0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b"
    ),
}
_OPENCLAW = {
    "commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
    "source_parent_commit": "805a4b152b0cee271ee78ad5608c15a4f8d1624b",
    "source_tree": "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44",
    "upstream_base_commit": "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
    "version": "2026.7.1",
}
_RUNTIME = {
    "entrypoint_digest": (
        "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
    ),
    "runtime_digest": (
        "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154"
    ),
    "runtime_volume": "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1",
    "version_output": "OpenClaw 2026.7.1 (7fa98d8)",
}
_RUNTIME_TREE = {
    "algorithm": "aragorn/runtime-tree/v1",
    "entry_count": 45_860,
    "file_count": 45_841,
    "symlink_count": 19,
    "total_bytes": 369_443_243,
    "tree_digest": _RUNTIME["runtime_digest"],
}
_SIGNATURE = {
    "key": "SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk",
    "signer": "yousif.snazhat@gmail.com",
    "status": "GOOD_LOCAL_VERIFICATION",
}
_PROFILE_NAME = "openclaw-2026.7.1-protected-final-combined"
_PLUGIN_ID = "aragorn-runtime-action-worker"
_PLUGIN_PATH = "/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker"
_PLUGIN_SOURCE = {
    "commit": "50d5506dfdc180d3a31e6747c486e686f5f5fef1",
    "commit_signature": _SIGNATURE,
    "tree": "fdc7fd01f0662a53301ddde1dfd2ed38cd6fea27",
}
_SKILL_PATH = "/opt/aragorn/runtime-profile/template-skill/SKILL.md"
_CAPTURE_SOURCE_COMMIT = "c59154968b2cd637d88a5a17d5b1100873df7563"
_RETENTION_COMMIT = "276dd537f247c0db0fcfa00df525acd4274b498c"
_CHILD_IMAGE = "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
_PARENT_IMAGE = (
    "sha256:fb4794e886c2bef6ab450d28fc59ee3347ed2c2426d116c81781dc1d4bf09847"
)
_BOUNDARIES_DIGEST = (
    "sha256:e53e842baba12bd2d2a3d7c1968083ccd4e301f00c1e63e1df3e447291496968"
)


def verify_openclaw_final_disabled_routes(*, evidence_cas: cas.CAS) -> dict[str, Any]:
    """Return five PASSes that mean only exact-profile ADM-02 gate or deny."""

    try:
        _verify_dependencies()
        raw = {
            name: _read_blob(evidence_cas, identity, name)
            for name, identity in _SOURCES.items()
        }
        documents = {
            name: _load_canonical_json(raw[name], _SOURCES[name], name)
            for name in (
                "composition",
                "configuration",
                "profile",
                "runtime_lock",
                "plugin_manifest",
                "plugin_package",
            )
        }
        _verify_configuration(
            documents["configuration"],
            documents["plugin_manifest"],
            documents["plugin_package"],
        )
        _verify_profile(documents["profile"])
        _verify_runtime_lock(documents["runtime_lock"])
        _verify_composition(
            documents["composition"],
            documents["configuration"],
            documents["profile"],
            documents["runtime_lock"],
        )
    except admission_evidence.AdmissionEvidenceError:
        raise
    except (
        AttributeError,
        binascii.Error,
        cas.CASError,
        IndexError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        raise admission_evidence.AdmissionEvidenceError(
            f"invalid final disabled-route evidence: {exc}"
        ) from exc

    return {
        "schema": "aragorn/admission-protected-final-disabled-route-coverage/v1",
        "assurance": "EXACT_STATIC_PROFILE_GATE_OR_DENY_ONLY_NOT_DYNAMIC_ROUTE_EXECUTION",
        "profile": {
            "name": _PROFILE_NAME,
            "routes": [
                {
                    "id": route,
                    "status": "PASS" if route in _PASS_ROUTES else "NOT_TESTED",
                }
                for route in _ROUTES
            ],
            "counts": {"PASS": 5, "NOT_TESTED": 16},
        },
        "runtime": dict(_OPENCLAW),
        "route_semantics": {
            "pass_basis": "GATE_OR_DENY_UNDER_ADM-02",
            "transitions_dynamically_exercised": False,
        },
        "bindings": {
            "composition": {
                **_SOURCES["composition"],
                "retained_by_signed_commit": _RETENTION_COMMIT,
                "signing_key": _SIGNATURE["key"],
            },
            "configuration": dict(_SOURCES["configuration"]),
            "profile": dict(_SOURCES["profile"]),
            "runtime_lock": dict(_SOURCES["runtime_lock"]),
            "skill": dict(_SOURCES["skill"]),
            "plugin": {
                "id": _PLUGIN_ID,
                "index": dict(_SOURCES["plugin_index"]),
                "manifest": dict(_SOURCES["plugin_manifest"]),
                "package": dict(_SOURCES["plugin_package"]),
            },
            "controls": {
                "activation_authority": "external",
                "plugin_allowlist": [_PLUGIN_ID],
                "plugin_declared_skill_directories": [],
                "sandbox": "off",
                "singleton_skill": _SKILL_PATH,
                "skill_watch": False,
            },
            "runtime": dict(_RUNTIME),
            "dependency_implementation_digests": dict(_DEPENDENCY_DIGESTS),
            "verifier_implementation_digest": _digest(Path(__file__).read_bytes()),
        },
        "decision": {
            "status": "PARTIAL_STATIC_GATE_OR_DENY_ROUTE_COVERAGE",
            **{key: False for key in _ELIGIBILITY_KEYS},
        },
        "limitations": [
            "ROUTE_TRANSITIONS_NOT_DYNAMICALLY_EXERCISED",
            "PASS_MEANS_EXACT_PROFILE_GATE_OR_DENY_UNDER_ADM_02",
            "ONLY_FIVE_EXACT_DISABLED_OR_PROTECTED_ROUTES_QUALIFIED",
            "SIXTEEN_OTHER_PROTECTED_PROFILE_ROUTES_NOT_TESTED",
            "NO_AGGREGATE_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
        ],
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_dependencies() -> None:
    modules = {
        "admission_evidence": admission_evidence,
        "cas": cas,
        "oci_worker_protocol": oci_worker_protocol,
    }
    package = Path(__file__).resolve(strict=True).parent
    if any(
        (path := Path(module.__file__).resolve(strict=True))
        != (package / f"{name}.py").resolve(strict=True)
        or _digest(path.read_bytes()) != _DEPENDENCY_DIGESTS[name]
        for name, module in modules.items()
    ):
        raise admission_evidence.AdmissionEvidenceError(
            "final disabled-route dependency implementation changed"
        )


def _read_blob(store: cas.CAS, identity: dict[str, Any], label: str) -> bytes:
    raw = store.read(identity["digest"], max_bytes=identity["bytes"])
    if len(raw) != identity["bytes"] or _digest(raw) != identity["digest"]:
        raise admission_evidence.AdmissionEvidenceError(
            f"final disabled-route {label} identity changed"
        )
    return raw


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise admission_evidence.AdmissionEvidenceError(
                f"duplicate final disabled-route key: {key}"
            )
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise admission_evidence.AdmissionEvidenceError(
        f"invalid final disabled-route JSON constant: {value}"
    )


def _load_canonical_json(
    raw: bytes, identity: dict[str, Any], label: str
) -> dict[str, Any]:
    try:
        document = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise admission_evidence.AdmissionEvidenceError(
            f"invalid final disabled-route {label} JSON: {exc}"
        ) from exc
    canonical = oci_worker_protocol.canonical_json(document)
    if (
        not isinstance(document, dict)
        or canonical + b"\n" != raw
        or len(canonical) != identity["canonical_bytes"]
        or _digest(canonical) != identity["canonical_digest"]
    ):
        raise admission_evidence.AdmissionEvidenceError(
            f"final disabled-route {label} canonical identity changed"
        )
    return document


def _verify_configuration(
    config: dict[str, Any],
    plugin_manifest: dict[str, Any],
    plugin_package: dict[str, Any],
) -> None:
    activation = config["skills"]["activation"]
    plugins = config["plugins"]
    agents = config["agents"]
    if (
        activation
        != {
            "authority": "external",
            "sources": [
                {
                    "filePath": _SKILL_PATH,
                    "name": "template-skill",
                    "sha256": _SOURCES["skill"]["digest"].removeprefix("sha256:"),
                }
            ],
        }
        or config["skills"]["load"]
        != {
            "allowSymlinkTargets": [],
            "extraDirs": [str(Path(_SKILL_PATH).parent)],
            "watch": False,
        }
        or config["skills"]["workshop"] != {"restoreAuthority": "external"}
        or agents["defaults"]["sandbox"] != {"mode": "off"}
        or len(agents["list"]) != 1
        or agents["list"][0]["id"] != "main"
        or agents["list"][0]["sandbox"] != {"mode": "off"}
        or plugins["allow"] != [_PLUGIN_ID]
        or plugins["enabled"] is not True
        or set(plugins["entries"]) != {_PLUGIN_ID}
        or plugins["entries"][_PLUGIN_ID]["enabled"] is not True
        or plugins["load"] != {"paths": [_PLUGIN_PATH]}
        or plugin_manifest["id"] != _PLUGIN_ID
        or set(plugin_manifest["contracts"]) != {"tools"}
        or plugin_manifest["contracts"]["tools"] != ["aragorn_runtime_create"]
        or any(key in plugin_manifest for key in ("skills", "hooks", "prompts"))
        or plugin_package
        != {
            "name": "@aragorn/runtime-action-worker",
            "openclaw": {"extensions": ["./index.js"]},
            "private": True,
            "type": "commonjs",
            "version": "0.1.0",
        }
    ):
        raise admission_evidence.AdmissionEvidenceError(
            "final singleton config, plugin, sandbox, or watch boundary changed"
        )


def _verify_profile(profile: dict[str, Any]) -> None:
    runtime = profile["runtime"]
    routes = profile["routes"]
    decision = profile["decision"]
    controls = profile["controls"]
    if (
        profile["schema"] != "aragorn/admission-runtime-profile/v1"
        or profile["name"] != _PROFILE_NAME
        or runtime != {"name": "openclaw-protected-final-combined", **_OPENCLAW}
        or tuple(item["id"] for item in routes) != _ROUTES
        or any(item["outcome"] != "NOT_TESTED" for item in routes)
        or decision
        != {"status": "NOT_TESTED", **{key: False for key in _ELIGIBILITY_KEYS}}
        or controls["active_skill_source"]
        != "exact-singleton-allowlisted-root-owned-bytes"
        or controls["configuration"] != "read-only"
        or controls["plugins"] != "exact-pinned-aragorn-runtime-action-worker-only"
        or controls["sandbox"] != "disabled"
        or controls["skill_watch"] != "disabled"
    ):
        raise admission_evidence.AdmissionEvidenceError(
            "final protected profile boundary changed"
        )


def _verify_runtime_lock(lock: dict[str, Any]) -> None:
    deployment = lock["deployment_bindings"]
    installed = lock["installed_runtime"]
    source = lock["source"]
    configuration = deployment["configuration"]
    skill = deployment["skill_source"]
    plugin = deployment["aragorn_plugin"]
    expected_plugin_files = [
        {
            "digest": _SOURCES[f"plugin_{name}"]["digest"],
            "path": f"{_PLUGIN_PATH}/{path}",
        }
        for name, path in (
            ("index", "index.js"),
            ("manifest", "openclaw.plugin.json"),
            ("package", "package.json"),
        )
    ]
    if (
        source
        != {
            "branch": "codex/session-snapshot-protected-origin",
            "commit": _OPENCLAW["commit"],
            "commit_signature": _SIGNATURE,
            "fork_url": "https://github.com/yousifnazhat/openclaw",
            "package_json_digest": (
                "sha256:0005244d0c40e00c6fbc1e2809e78f4d138d22633d6e5eabbe971cb70d2be04e"
            ),
            "parent_commit": _OPENCLAW["source_parent_commit"],
            "repository_url": "https://github.com/openclaw/openclaw",
            "tree": _OPENCLAW["source_tree"],
            "upstream_base_commit": _OPENCLAW["upstream_base_commit"],
        }
        or installed["runtime_tree"] != _RUNTIME_TREE
        or installed["openclaw_digest"] != _RUNTIME["entrypoint_digest"]
        or installed["volume"] != _RUNTIME["runtime_volume"]
        or installed["version_output"] != _RUNTIME["version_output"]
        or installed["writable_regular_files_or_directories_for_group_or_other"] != 0
        or configuration
        != {
            "bytes": _SOURCES["configuration"]["bytes"],
            "canonical_bytes": _SOURCES["configuration"]["canonical_bytes"],
            "canonical_digest": _SOURCES["configuration"]["canonical_digest"],
            "deployment_materialization": "canonical_json(config)_without_trailing_lf",
            "digest": _SOURCES["configuration"]["digest"],
            "path": (
                "benchmark/admission/openclaw-v2026.7.1/"
                "protected-final-combined-config-v1.json"
            ),
        }
        or skill
        != {
            "activation_authority": "external",
            "digest": _SOURCES["skill"]["digest"],
            "file": {
                "gid": 0,
                "mode": "0444",
                "nlink": 1,
                "path": _SKILL_PATH,
                "uid": 0,
            },
            "name": "template-skill",
            "parent_directories": (
                "root-mode-0755-and-opt-ancestry-root-owned-mode-0555"
            ),
            "singleton_catalog": True,
            "watch": False,
        }
        or plugin
        != {
            "files": expected_plugin_files,
            "id": _PLUGIN_ID,
            "source": _PLUGIN_SOURCE,
        }
        or deployment["sandbox"] != "off"
        or deployment["network"] != "none"
        or deployment["sessions"] != "fresh-only"
        or lock["decision"]
        != {
            "status": "BUILD_LOCKED_NOT_QUALIFIED",
            **{key: False for key in _ELIGIBILITY_KEYS},
        }
    ):
        raise admission_evidence.AdmissionEvidenceError(
            "final source, runtime, skill, plugin, sandbox, or watch lock changed"
        )


def _verify_composition(
    composition: dict[str, Any],
    config: dict[str, Any],
    profile: dict[str, Any],
    lock: dict[str, Any],
) -> None:
    final = composition["action"]["artifacts"]["final_combined"]
    action = composition["action"]
    decision = composition["decision"]
    harness = action["harness"]
    harness_document = harness["document"]
    unit = action["boundaries"]["units"]["aragorn-agent-gateway.service"]
    if (
        composition["schema"]
        != "aragorn/runtime-action-worker-final-combined-systemd-observation/v1"
        or composition["profile"]["before"] != composition["profile"]["after"]
        or composition["profile"]["before"] != final["profile"]
        or final["config"]["document"] != config
        or final["profile"]["document"] != profile
        or final["runtime_lock"]["document"] != lock
        or action["inputs"]["gateway_config"] != config
        or final["profile"]["outcomes"] != {"FAIL": 0, "NOT_TESTED": 21, "PASS": 0}
        or composition["bindings"]
        != {
            "config_materialization": "canonical_json_without_trailing_lf",
            "network": "none",
            "openclaw_test_fast": "absent",
            "runtime_digest": _RUNTIME["runtime_digest"],
            "runtime_volume": _RUNTIME["runtime_volume"],
            "sandbox": "off",
            "sessions": "fresh-only",
            "skill_digest": _SOURCES["skill"]["digest"],
        }
        or decision
        != {
            "status": "FINAL_COMBINED_ACTION_OBSERVED_PROFILE_NOT_TESTED",
            "p3_7c_activation_action_observed": True,
            "route_pass_count": 0,
            "route_fail_count": 0,
            "route_not_tested_count": 21,
            **{key: False for key in _ELIGIBILITY_KEYS},
        }
        or action["decision"]["verifier_status"] != "NOT_TESTED"
        or action["runtime"]
        != {
            "entrypoint": "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "entrypoint_digest": _RUNTIME["entrypoint_digest"],
            "expected_version": _RUNTIME["version_output"],
            "root": "/runtime",
            "tree": _RUNTIME_TREE,
            "version_output": _RUNTIME["version_output"],
        }
        or harness_document["source_commit"] != _CAPTURE_SOURCE_COMMIT
        or harness_document["image_id"] != _CHILD_IMAGE
        or harness_document["run_image_reference"] != _CHILD_IMAGE
        or harness_document["parent_image_id"] != _PARENT_IMAGE
        or harness_document["openclaw_runtime_volume"] != _RUNTIME["runtime_volume"]
        or harness_document["image_lineage"]["child"]["id"] != _CHILD_IMAGE
        or harness_document["image_lineage"]["parent"]["id"] != _PARENT_IMAGE
        or oci_worker_protocol.canonical_digest(action["boundaries"])
        != _BOUNDARIES_DIGEST
        or unit["LoadCredential"]
        != 'a(ss) 1 "openclaw-config" "/etc/aragorn/agent-gateway/openclaw.json"'
        or unit["ProtectSystem"] != "strict"
        or unit["ReadWritePaths"] != "/var/lib/aragorn-agent-gateway"
        or "/runtime" not in unit["ReadOnlyPaths"].split()
        or _PLUGIN_PATH not in unit["ReadOnlyPaths"].split()
        or "-/opt/aragorn/runtime-profile" not in unit["ReadOnlyPaths"].split()
    ):
        raise admission_evidence.AdmissionEvidenceError(
            "final composition profile or runtime join changed"
        )
    _verify_embedded_sources(final)
    if oci_worker_protocol.canonical_digest(harness_document) != harness["digest"]:
        raise admission_evidence.AdmissionEvidenceError(
            "final composition harness digest changed"
        )
    if _decode_retained(harness["file"], "harness", file_record=True) != (
        oci_worker_protocol.canonical_json(harness_document)
    ):
        raise admission_evidence.AdmissionEvidenceError(
            "final composition harness bytes changed"
        )
    verification = harness_document["source_commit_verification"]
    commit_raw = _decode_retained(verification["commit_object"], "commit object")
    stderr = _decode_retained(verification["stderr"], "signature stderr")
    stdout = _decode_retained(verification["stdout"], "signature stdout")
    commit_id = hashlib.sha1(
        f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
    ).hexdigest()
    expected_stderr = (
        f'Good "git" signature for {_SIGNATURE["signer"]} with ED25519 key '
        f"{_SIGNATURE['key']}\n"
    ).encode("ascii")
    if (
        verification["command"]
        != ["git", "verify-commit", "--raw", _CAPTURE_SOURCE_COMMIT]
        or verification["exit_code"] != 0
        or commit_id != _CAPTURE_SOURCE_COMMIT
        or b"\ngpgsig " not in commit_raw
        or stdout != b""
        or stderr != expected_stderr
    ):
        raise admission_evidence.AdmissionEvidenceError(
            "final composition signed source binding changed"
        )


def _verify_embedded_sources(final: dict[str, Any]) -> None:
    for name, source_name in (
        ("config", "configuration"),
        ("profile", "profile"),
        ("runtime_lock", "runtime_lock"),
    ):
        identity = _SOURCES[source_name]
        retained = final[name]["file"]
        source = retained["source"]
        if (
            retained["canonical_bytes"] != identity["canonical_bytes"]
            or retained["canonical_digest"] != identity["canonical_digest"]
            or source["bytes"] != identity["bytes"]
            or source["digest"] != identity["digest"]
            or source["stat"]["uid"] != 0
            or source["stat"]["gid"] != 0
            or source["stat"]["mode"] != "0444"
            or source["stat"]["nlink"] != 1
            or source["stat"]["type"] != "file"
        ):
            raise admission_evidence.AdmissionEvidenceError(
                f"final composition {source_name} source changed"
            )
    skill = final["skill"]
    if (
        skill["file"]["bytes"] != _SOURCES["skill"]["bytes"]
        or skill["file"]["digest"] != _SOURCES["skill"]["digest"]
        or skill["file"]["path"] != _SKILL_PATH
        or skill["file"]["stat"]["uid"] != 0
        or skill["file"]["stat"]["gid"] != 0
        or skill["file"]["stat"]["mode"] != "0444"
        or skill["file"]["stat"]["nlink"] != 1
        or [item["mode"] for item in skill["parents"]]
        != ["0755", "0555", "0555", "0555", "0555"]
        or any(item["uid"] != 0 or item["gid"] != 0 for item in skill["parents"])
    ):
        raise admission_evidence.AdmissionEvidenceError(
            "final composition singleton skill custody changed"
        )
    for source_name, filename in (
        ("plugin_index", "index.js"),
        ("plugin_manifest", "openclaw.plugin.json"),
        ("plugin_package", "package.json"),
    ):
        item = final["plugin"][filename]
        stat = item["stat"]
        if (
            set(item) != {"bytes", "digest", "path", "stat"}
            or set(stat)
            != {"device", "gid", "inode", "mode", "nlink", "size", "type", "uid"}
            or item["bytes"] != _SOURCES[source_name]["bytes"]
            or item["digest"] != _SOURCES[source_name]["digest"]
            or item["path"] != f"{_PLUGIN_PATH}/{filename}"
            or stat["type"] != "file"
            or stat["size"] != item["bytes"]
            or stat["uid"] != 0
            or stat["gid"] != 0
            or stat["mode"] != "0644"
            or stat["nlink"] != 1
        ):
            raise admission_evidence.AdmissionEvidenceError(
                f"final composition plugin {filename} changed"
            )


def _decode_retained(
    value: dict[str, Any], label: str, *, file_record: bool = False
) -> bytes:
    expected = {"base64", "bytes", "digest"}
    if file_record:
        expected |= {"path", "stat"}
    if set(value) != expected:
        raise admission_evidence.AdmissionEvidenceError(
            f"final composition {label} retained shape changed"
        )
    raw = base64.b64decode(value["base64"], validate=True)
    if len(raw) != value["bytes"] or _digest(raw) != value["digest"]:
        raise admission_evidence.AdmissionEvidenceError(
            f"final composition {label} retained identity changed"
        )
    return raw
