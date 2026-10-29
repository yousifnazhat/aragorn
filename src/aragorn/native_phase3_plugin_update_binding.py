"""Read-only binding/replay of one native marketplace-update observation.

Identity artifacts are canonical objects with exactly ``schema``, ``dimension``
and ``identity``. The schema is ``aragorn/native-phase3-report-identity/v1``.
``identity`` is the dimension-specific projection returned by
``native_plugin_update_identity_artifacts``: runtime binds the exact runtime-tree
measurement, fixture image, volume and build-record digest; adapter binds the
four probe sources; configuration binds its digest; worker binds module bytes,
digest and worker binding; OS profile binds image, stage schema and complete
staged-file inventory digest; policy binds its canonical digest; Aragorn binds
the reported source commit and canonical source-record digest. No extra keys or
alternative projections are accepted. Every artifact is joined, not just read.

These are *reported* deployment identities, not live attestation. This consumer
recomputes command denial, selected state equality, SQLite physical custody and
cleanup joins from retained records. It does not execute/import the probes,
verify source signatures, prove raw file contents or database semantics, or
provide a Phase 3 semantic PASS. Caller-held pins are essential trust inputs.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any

from .cas import CAS, CASError
from .oci_worker_protocol import canonical_json
from .phase3_deployment import BINDING_DIMENSIONS, resolve_phase3_deployment_identity

ROUTE = "ADM-02/update/plugin-package-skill-replacement"
BRANCH = "TRACKED_LOCAL_MARKETPLACE_DIRECTORY_UPDATE"
_PLUGIN = "aragorn-plugin-skill-replacement-fixture"
_ROOT = "/route-input/plugin-package-skill-replacement"
_NODE = ["/usr/local/bin/node", "/runtime/lib/node_modules/openclaw/openclaw.mjs"]
_DOCKER = ["docker", "--context", "colima-aragorn-bakeoff"]
_RUNTIME = {
    "algorithm": "aragorn/runtime-tree/v1",
    "entry_count": 31988,
    "file_count": 31970,
    "symlink_count": 18,
    "total_bytes": 289776316,
    "tree_digest": "sha256:4e6e94cf4fb8a2527ec1cd789b20a7ddf6c84f03973b3579ded64ef8e2ef96c3",
}
_IMAGE = "sha256:1c75f0c37070aa5b702e134e6e6c830690f596891ce0f4fa389ea7515300ea17"
_VOLUME = "aragorn-native-cache-runtime-79ed6eb-v1"
_BUILD = "sha256:a1d302431804f760299e1bcbd16aa269214ce0f35e2b8996c9f0cd3d03658877"
_SOURCES = {
    "protected-plugin-force-reinstall-v3-probe.py": (
        30362,
        "sha256:58ba8c44ef474588dd48c8afaca01681c26d8a0b45c153994463c87e719f115a",
    ),
    "protected-plugin-marketplace-update-probe.py": (
        15068,
        "sha256:c00a1fd7b4071e7f6c621d78151323e3ee5be95d88ba7c3a93d736463fa95860",
    ),
    "protected-plugin-package-skill-replacement-probe.py": (
        26494,
        "sha256:d4e7c4bc2408045aab6702a8e2877916241ad372d917aaf8d5e62a289caf5a4e",
    ),
    "seed-plugin-marketplace-update-record.mjs": (
        2260,
        "sha256:8c7fc9c1dae8be9ad7688252408905ed223a8200f0a9373994afaa0906db2840",
    ),
}
_BOUNDARY = {
    "baseline_source",
    "candidate_source",
    "config",
    "config_lock",
    "discovery_roots",
    "gateway_process",
    "install_policy_command",
    "openclaw",
    "route_input_mount",
    "state_store",
    "target_plugin",
}
_DOCUMENT_LIMITS = [
    "LOCAL_MARKETPLACE_BRANCH_ONLY_NOT_NPM_GIT_OR_CLAWHUB",
    "PRE_EFFECT_DENIAL_NOT_REPLACEMENT_OR_RELOAD",
    "NO_LOGICAL_WHOLE_DATABASE_EQUALITY",
    "NOT_PHASE3_OR_FROZEN_V3_QUALIFICATION",
]
LIMITATIONS = (
    "RETAINED_REPORT_REPLAY_NOT_FRESH_CAMPAIGN_EXECUTION",
    "SEVEN_REPORTED_IDENTITY_JOINS_NOT_LIVE_DEPLOYMENT_ATTESTATION",
    "CALLER_PINNED_CAPTURE_AND_SOURCE_NOT_SIGNATURE_OR_HOST_ATTESTATION",
    "LOCAL_MARKETPLACE_BRANCH_ONLY_NOT_COMPLETE_ROUTE_SEMANTICS",
    "REPORTED_FILE_DIGESTS_NOT_INDEPENDENT_FILE_BYTE_READBACK",
    "SQLITE_PHYSICAL_CUSTODY_AND_WAL_SHAPE_NOT_LOGICAL_EQUALITY_OR_CAUSATION",
    "NO_INDEPENDENT_POLICY_CORRECTNESS_OR_PHASE3_SEMANTIC_PASS",
)
_FLAGS = (
    "phase3_eligible",
    "run_conformance_eligible",
    "production_activation_eligible",
    "route_qualified",
)


class NativePluginUpdateBindingError(ValueError):
    """The retained observation cannot support the bounded binding statement."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NativePluginUpdateBindingError(message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pin(value: object) -> str:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "invalid caller or evidence digest",
    )
    return value


def _pairs(items):
    result = dict(items)
    _require(len(result) == len(items), "duplicate JSON key")
    return result


def _constant(_):
    raise NativePluginUpdateBindingError("non-finite JSON value")


def _parse(raw: bytes, *, newline: bool = False, limit: int = 2 * 1024 * 1024) -> dict:
    _require(type(raw) is bytes and 0 < len(raw) <= limit, "unbounded evidence bytes")
    value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
    _require(
        type(value) is dict
        and canonical_json(value) + (b"\n" if newline else b"") == raw,
        "noncanonical evidence document",
    )
    return value


def _false(value: dict, names) -> None:
    _require(all(value[name] is False for name in names), "understated proof limits")


def _command_output(command: dict, channel: str, expected: bytes) -> None:
    _require(
        command[channel + "_excerpt"] == expected.decode("ascii")
        and type(command[channel + "_bytes"]) is int
        and command[channel + "_bytes"] == len(expected)
        and command[channel + "_digest"] == _digest(expected),
        "command bytes do not match retained digest",
    )


def _commands(document: dict, observation: dict) -> None:
    action = document["action"]
    _require(action["operation"] == "plugins update", "not an update lifecycle")

    def gateway(name):
        return ["gateway", "call", name, "--json", "--timeout", "5000"]

    inspect = ["plugins", "inspect", _PLUGIN, "--json"]
    suffixes = [
        ["--version"],
        gateway("system.info"),
        gateway("skills.status"),
        inspect,
        ["plugins", "update", _PLUGIN],
        inspect,
        gateway("skills.status"),
        gateway("system.info"),
    ]
    commands = action["commands"]
    _require(type(commands) is list and len(commands) == 8, "command inventory changed")
    previous = None
    for index, (command, suffix) in enumerate(zip(commands, suffixes, strict=True)):
        _require(
            command["argv"] == _NODE + suffix
            and type(command["exit_code"]) is int
            and command["exit_code"] == (1 if index == 4 else 0)
            and type(command["pid"]) is int
            and command["pid"] > 0
            and command["signal"] is None
            and command["error"] is None,
            "command execution identity changed",
        )
        start, end = (
            datetime.fromisoformat(command[key])
            for key in ("started_at", "completed_at")
        )
        _require(
            start.tzinfo is not None
            and end.tzinfo is not None
            and start <= end
            and (previous is None or previous <= start),
            "command chronology changed",
        )
        previous = end
        _command_output(command, "stderr", b"")
    expected = (
        f"Install policy target=plugin:{_PLUGIN} request=plugin-dir/update origin=plugin-package "
        "pathKind=directory source=local-path/user: blocked by install policy: plugin installs disabled by Aragorn protected profile\n"
        f"Failed to update {_PLUGIN}: blocked by install policy: plugin installs disabled by Aragorn protected profile "
        f"(marketplace plugin {_PLUGIN} from {_ROOT}/marketplace.json).\n"
    ).encode("ascii")
    _command_output(commands[0], "stdout", b"OpenClaw 2026.7.1\n")
    _command_output(commands[4], "stdout", expected)
    for before, after, indexes in ((action["before"], action["after"], (1, 7)),):
        for state, index in zip((before, after), indexes, strict=True):
            for field, command_index in (
                ("info", index),
                ("skills", 2 if index == 1 else 6),
                ("plugin", 3 if index == 1 else 5),
            ):
                _require(
                    state[field]["command"] == commands[command_index],
                    "state/command join changed",
                )
                _require(
                    state[field]["response"]["parsed"] is True,
                    "state response was not parsed",
                )
            info_raw = commands[index]["stdout_excerpt"].encode("ascii")
            _command_output(commands[index], "stdout", info_raw)
            info = json.loads(
                info_raw, object_pairs_hook=_pairs, parse_constant=_constant
            )
            _require(
                info == state["info"]["response"]["value"]
                and info["pid"]
                == observation["processes"]["gateway"]["process"]["pid"],
                "gateway response identity changed",
            )
    execution = observation["plugin_update"]["execution"]
    raw = canonical_json(document) + b"\n"
    _require(
        execution["exit_code"] == 0
        and execution["stderr_bytes"] == 0
        and execution["stdout_bytes"] == len(raw)
        and execution["stdout_digest"] == _digest(raw),
        "probe output binding changed",
    )
    pid = observation["processes"]["gateway"]["process"]["pid"]
    _require(
        execution["effective_identity"] == {"uid": 992, "gid": 992, "groups": [992]}
        and execution["argv"]
        == [
            "/usr/bin/nsenter",
            "--target",
            str(pid),
            "--mount",
            "--",
            "/usr/bin/setpriv",
            "--reuid=992",
            "--regid=992",
            "--groups=992",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            _ROOT + "/adapter/protected-plugin-marketplace-update-probe.py",
        ],
        "probe namespace or identity changed",
    )


def _sqlite(before: dict, after: dict, reported: dict) -> None:
    names = ["openclaw.sqlite", "openclaw.sqlite-shm", "openclaw.sqlite-wal"]
    file_keys = {
        "device",
        "digest",
        "digest_error",
        "exists",
        "gid",
        "inode",
        "mode",
        "nlink",
        "path",
        "size",
        "type",
        "uid",
    }
    for state in (before, after):
        _require(
            set(state) == {"entries", "root", "ready", "tree_digest"}
            and state["ready"] is True
            and len(state["entries"]) == 3
            and [item["path"] for item in state["entries"]] == names
            and state["tree_digest"] == _digest(canonical_json(state["entries"])),
            "SQLite inventory or entry digest changed",
        )
        root = state["root"]
        _require(
            set(root) == file_keys - {"digest", "digest_error"}
            and root["path"] == "/var/lib/aragorn-agent-gateway/state/state"
            and root["type"] == "directory"
            and root["mode"] == "700"
            and root["uid"] == root["gid"] == 992
            and root["exists"] is True,
            "SQLite directory custody changed",
        )
        for item in state["entries"]:
            _require(
                set(item) == file_keys
                and item["exists"] is True
                and item["type"] == "file"
                and item["mode"] == "600"
                and item["uid"] == item["gid"] == 992
                and item["nlink"] == 1
                and item["digest_error"] is None
                and type(item["size"]) is int
                and item["size"] >= 0,
                "SQLite file custody changed",
            )
            _pin(item["digest"])
        _require(
            all(
                type(item[key]) is int and item[key] > 0
                for item in [root, *state["entries"]]
                for key in ("device", "inode", "nlink")
            ),
            "SQLite identity is malformed",
        )
        _require(
            len({(item["device"], item["inode"]) for item in [root, *state["entries"]]})
            == 4,
            "SQLite file identities alias",
        )
    _require(before["root"] == after["root"], "SQLite root changed")
    for left, right in zip(before["entries"], after["entries"], strict=True):
        _require(
            {k: v for k, v in left.items() if k not in {"digest", "size"}}
            == {k: v for k, v in right.items() if k not in {"digest", "size"}},
            "SQLite inode custody changed",
        )
    db, shm, wal = before["entries"]
    new_db, new_shm, new_wal = after["entries"]
    _require(
        db == new_db
        and db["size"] >= 4096
        and db["size"] % 4096 == 0
        and shm["size"] == new_shm["size"] == 32768
        and all(
            item["size"] > 32 and (item["size"] - 32) % 4120 == 0
            for item in (wal, new_wal)
        )
        and shm["digest"] != new_shm["digest"]
        and wal["digest"] != new_wal["digest"]
        and new_wal["size"] > wal["size"],
        "SQLite delta is not bounded WAL growth",
    )
    _require(
        reported["before"] == before
        and reported["after"] == after
        and reported["schema"] == "aragorn/plugin-denial-sqlite-file-delta/v1"
        and reported["authority"]
        == "PHYSICAL_CUSTODY_AND_WAL_SHAPE_ONLY_NOT_LOGICAL_STATE_OR_CAUSATION_PROOF"
        and reported["status"] == "OBSERVED"
        and reported["delta_kind"] == "ESTABLISHED_WAL_GROWTH_SHAPE"
        and reported["main_database_bytes"] == db["size"]
        and reported["wal_frame_bytes"] == 4120
        and reported["wal_size_increase_bytes"] == new_wal["size"] - wal["size"],
        "SQLite summary disagrees with retained records",
    )
    _false(
        reported,
        (
            "entire_state_store_byte_identical",
            "logical_database_unchanged_verified",
            "housekeeping_causation_verified",
            "qualification_eligible",
        ),
    )


def _protected(document: dict, observation: dict) -> None:
    action = document["action"]
    left, right = action["before"], action["after"]
    _require(
        set(left["boundary"]) == set(right["boundary"]) == _BOUNDARY,
        "protected boundary inventory changed",
    )
    computed = {
        key: left["boundary"][key] == right["boundary"][key] for key in _BOUNDARY
    }
    for key, name in (("plugin_inspection", "plugin"), ("skills_status", "skills")):
        computed[key] = left[name]["response"] == right[name]["response"]
    _require(
        computed == action["state_invariants"]
        and all(value for key, value in computed.items() if key != "state_store"),
        "protected boundary changed",
    )
    for state in (left, right):
        plugin = state["plugin"]["response"]["value"]["plugin"]
        _require(
            plugin["id"] == _PLUGIN
            and plugin["version"] == "1.0.0"
            and plugin["status"] == "disabled"
            and all(
                plugin[key] is False
                for key in ("enabled", "explicitlyEnabled", "activated", "imported")
            ),
            "plugin became active or changed version",
        )
        boundary = state["boundary"]
        target = boundary["target_plugin"]["baseline"]["tree"]
        baseline = boundary["baseline_source"]["tree"]
        _require(
            {item["path"]: (item["size"], item["digest"]) for item in target["entries"]}
            == {
                item["path"]: (item["size"], item["digest"])
                for item in baseline["entries"]
            }
            and target["tree_digest"] == _digest(canonical_json(target["entries"]))
            and all(
                boundary[key]["manifest"]["skills"] == ["."]
                for key in ("baseline_source", "candidate_source")
            ),
            "protected plugin bytes differ from baseline records",
        )
        _require(
            boundary["config"]["canonical_digest"]
            == observation["setup"]["configuration_digest"],
            "configuration binding changed",
        )
    denial = document["explicit_policy_denial_observation"]
    record = {
        _PLUGIN: {
            "installPath": "/var/lib/aragorn-agent-gateway/state/extensions/" + _PLUGIN,
            "marketplacePlugin": _PLUGIN,
            "marketplaceSource": _ROOT + "/marketplace.json",
            "source": "marketplace",
            "version": "1.0.0",
        }
    }
    _require(
        denial["tracked_records_before"] == denial["tracked_records_after"] == record,
        "tracked marketplace record changed",
    )
    _false(denial, ("logical_database_unchanged_verified", "qualification_eligible"))
    _sqlite(
        left["boundary"]["state_store"],
        right["boundary"]["state_store"],
        denial["sqlite_file_delta"],
    )
    _require(
        observation["empty_receipt_store_after"] == observation["setup"]["empty_store"],
        "idle receipt store changed",
    )


def _cleanup(capture: dict) -> None:
    cleanup, container = capture["cleanup"], capture["fixture_container"]
    name, owner = cleanup["name"], cleanup["owner"]
    _require(
        re.fullmatch(r"aragorn-native-plugin-package-[0-9a-f]{16}", name) is not None
        and re.fullmatch(r"[0-9a-f]{64}", owner) is not None
        and cleanup["removed_id"] == container
        and cleanup["image"] == _IMAGE,
        "owned cleanup identity changed",
    )
    commands = cleanup["commands"]
    listing = ["container", "ls", "--all", "--no-trunc", "--filter"]
    by_name = [*listing, "name=^/" + name + "$", "--format", "{{.ID}}"]
    expected = [
        by_name,
        ["container", "inspect", container],
        ["container", "rm", "--force", container],
        ["info", "--format", "{{.ServerVersion}}"],
        by_name,
        [*listing, "id=" + container, "--format", "{{.ID}}"],
    ]
    _require(
        len(commands) == len(expected)
        and all(
            command["argv"] == _DOCKER + argv and command["exit_code"] == 0
            for command, argv in zip(commands, expected, strict=True)
        ),
        "cleanup command evidence changed",
    )
    _require(
        commands[0]["stdout"] == commands[2]["stdout"] == container + "\n"
        and commands[4]["stdout"] == commands[5]["stdout"] == "",
        "owned container removal was not observed",
    )
    inspected = json.loads(
        commands[1]["stdout"], object_pairs_hook=_pairs, parse_constant=_constant
    )
    _require(
        type(inspected) is list and len(inspected) == 1,
        "cleanup inspect inventory changed",
    )
    item = inspected[0]
    _require(
        item["Id"] == container
        and item["Image"] == _IMAGE
        and item["Name"] == "/" + name
        and item["Config"]["Labels"]["dev.aragorn.snapshot-owner"] == owner
        and item["Config"]["Labels"]["dev.aragorn.source-commit"]
        == capture["source"]["commit"],
        "cleanup ownership report mismatch",
    )
    for unit, state in capture["observation"]["fixture_stack_cleanup"].items():
        _require(
            state["Id"] == unit
            and state["ActiveState"] == "inactive"
            and state["MainPID"] == state["ControlPID"] == "0",
            "guest stack cleanup was not inactive",
        )
    _require(
        set(capture["observation"]["fixture_stack_cleanup"])
        == {
            "aragorn-agent-gateway.service",
            "aragorn-runtime-action-worker.service",
            "aragorn-runtime-lineage-capability-action-broker.service",
            "aragorn-runtime-lineage-capability-observation-publisher.service",
        },
        "guest cleanup inventory changed",
    )


def _capture(
    raw: bytes, capture_digest: str, source_digest: str, source_commit: str
) -> dict:
    _require(_digest(raw) == _pin(capture_digest), "capture differs from caller pin")
    value = _parse(raw, newline=True)
    _require(
        type(source_commit) is str
        and re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None
        and value["source"]["commit"] == source_commit
        and _digest(canonical_json(value["source"])) == _pin(source_digest),
        "source differs from caller pins",
    )
    observation = value["observation"]
    document = observation["plugin_update"]["document"]
    for obj, schema, authority in (
        (
            value,
            "aragorn/runtime-native-plugin-update-capture/v1",
            "LOCAL_TRACKED_MARKETPLACE_UPDATE_BRANCH_NOT_ADMISSION_OR_PHASE3_QUALIFICATION",
        ),
        (
            observation,
            "aragorn/runtime-native-plugin-update-observation/v1",
            "OWNED_LOCAL_MARKETPLACE_UPDATE_DENIAL_NOT_ROUTE_OR_RUN_QUALIFICATION",
        ),
        (
            document,
            "aragorn/native-plugin-marketplace-update-denial/v1",
            "FIXED_OWNED_UPDATE_BRANCH_OBSERVATION_NOT_ROUTE_OR_PHASE3_QUALIFICATION",
        ),
    ):
        _require(
            obj["schema"] == schema
            and obj["authority"] == authority
            and obj["status"] == "OBSERVED"
            and obj["branch"] == BRANCH
            and obj["route_id"] == ROUTE,
            "wrong observation kind or branch",
        )
    for obj in (value, observation):
        _false(obj, _FLAGS)
    _false(document, ("route_qualified", "inventory_route_coverage"))
    _require(
        document["limitations"] == _DOCUMENT_LIMITS
        and set(document["decision"])
        == {
            "admission_profile_eligible",
            "aggregate_admission_eligible",
            "edr_eligible",
            "installer_work_eligible",
            "phase3_exit_eligible",
            "release_eligible",
            "run_01_eligible",
            "run_02_eligible",
            "run_eligible",
        }
        and all(item is False for item in document["decision"].values()),
        "document proof ceiling changed",
    )
    container = value["fixture_container"]
    _require(
        re.fullmatch(r"[0-9a-f]{64}", container) is not None
        and observation["fixture_container"] == container
        and value["container_inspect"]["Id"] == container
        and value["container_inspect"]["Image"]
        == value["fixture_image"]["Id"]
        == _IMAGE,
        "native fixture identity changed",
    )
    _require(
        value["build_observation"]["digest"] == _BUILD
        and observation["setup"]["runtime_digest"] == _RUNTIME["tree_digest"]
        and value["staged_profile"]["required_runtime_not_included"]["tree"]
        == _RUNTIME,
        "native runtime/build binding changed",
    )
    for side in ("runtime_before", "runtime_after"):
        runtime = value[side]
        _require(
            runtime["content"]["runtime_tree_before"]
            == runtime["content"]["runtime_tree_after"]
            == _RUNTIME
            and runtime["volume_inspect"]["Name"] == _VOLUME
            and runtime["running_users_before"] == runtime["running_users_after"] == [],
            "runtime snapshot binding changed",
        )
        mount = runtime["content"]["mount"]
        _require(
            mount["path"] == "/runtime"
            and mount["error"] is None
            and len(mount["records"]) == 1
            and mount["records"][0]["root"] == f"/docker/volumes/{_VOLUME}/_data"
            and "ro" in mount["records"][0]["mount_options"]
            and "rw" not in mount["records"][0]["mount_options"],
            "runtime was not reported read-only",
        )
    _require(
        value["runtime_before"]["volume_inspect"]
        == value["runtime_after"]["volume_inspect"],
        "runtime volume custody changed",
    )
    prefix = "benchmark/admission/openclaw-v2026.7.1/"
    source_pins = value["source"]["plugin_fixture_sources"]
    bundle = {item["name"]: item for item in value["input_bundle"]["files"]}
    _require(
        set(source_pins) == {prefix + name for name in _SOURCES} and len(bundle) == 13,
        "probe source inventory changed",
    )
    for name, expected in _SOURCES.items():
        item = source_pins[prefix + name]
        _require(
            item["path"] == prefix + name
            and item["mode"] == "100644"
            and (item["bytes"], item["digest"]) == expected
            and (
                bundle["adapter/" + name]["bytes"],
                bundle["adapter/" + name]["digest"],
            )
            == expected,
            "source probe pin changed",
        )
    _require(
        document["implementation_digest"]
        == _SOURCES["protected-plugin-marketplace-update-probe.py"][1],
        "adapter implementation pin changed",
    )
    helper_size, helper_digest = _SOURCES[
        "protected-plugin-package-skill-replacement-probe.py"
    ]
    _require(
        document["helper_binding"]
        == {
            "name": "protected-plugin-package-skill-replacement-probe.py",
            "bytes": helper_size,
            "digest": helper_digest,
            "legacy_main_executed": False,
            "legacy_run_observation_executed": False,
        },
        "legacy helper binding changed",
    )
    version = document["native_version_binding"]
    _require(
        version["expected_stdout"] == "OpenClaw 2026.7.1\n"
        and version["retained_build_digest"] == _BUILD
        and version["retained_build_bytes"] == 40591,
        "native version/build binding changed",
    )
    upstream = document["native_update_source_binding"]
    _require(
        upstream["commit"] == "7fa98d8e21b6d5937f25a7f19445ff683bb980bf"
        and upstream["upstream_archive_digest"]
        == "sha256:ce65a9dcb876c0c507be4cc89a5c45566ac2d1b1abe1dc6813d52a359ba11623"
        and upstream["policy_failure_channel"] == "stdout",
        "upstream update source binding changed",
    )
    _commands(document, observation)
    _protected(document, observation)
    _cleanup(value)
    return value


def _identity_artifacts(capture: dict, source_digest: str) -> dict[str, bytes]:
    observation, profile = capture["observation"], capture["staged_profile"]
    worker = observation["installed_sources"][
        "/usr/lib/aragorn/aragorn/runtime_action_worker.py"
    ]
    _require(
        profile["schema"] == "aragorn/runtime-native-startup-staged-profile/v1"
        and len(profile["files"]) == 70
        and len({item["path"] for item in profile["files"]}) == 70,
        "not the native 70-file startup profile",
    )
    projections = {
        "runtime_commit_or_image": {
            "runtime_tree": _RUNTIME,
            "fixture_image": _IMAGE,
            "runtime_volume": _VOLUME,
            "build_record_digest": _BUILD,
        },
        "adapter": {
            "route_id": ROUTE,
            "branch": BRANCH,
            "probe_sources": {
                name: {"bytes": pair[0], "digest": pair[1]}
                for name, pair in _SOURCES.items()
            },
        },
        "configuration": {
            "configuration_digest": _pin(observation["setup"]["configuration_digest"])
        },
        "worker": {
            "bytes": worker["bytes"],
            "digest": _pin(worker["digest"]),
            "binding": observation["setup"]["worker_binding"],
        },
        "os_profile": {
            "fixture_image": _IMAGE,
            "staged_schema": profile["schema"],
            "staged_files_digest": _digest(canonical_json(profile["files"])),
        },
        "policy": {
            "policy_digest": _digest(canonical_json(observation["setup"]["policy"]))
        },
        "aragorn_version": {
            "source_commit": capture["source"]["commit"],
            "source_record_digest": source_digest,
        },
    }
    return {
        name: canonical_json(
            {
                "schema": "aragorn/native-phase3-report-identity/v1",
                "dimension": name,
                "identity": projections[name],
            }
        )
        for name in BINDING_DIMENSIONS
    }


def native_plugin_update_identity_artifacts(
    capture_raw: bytes,
    *,
    expected_capture_digest: str,
    expected_source_digest: str,
    expected_source_commit: str,
) -> dict[str, bytes]:
    """Project validated reported identities; no CAS write or attestation occurs."""
    try:
        capture = _capture(
            capture_raw,
            expected_capture_digest,
            expected_source_digest,
            expected_source_commit,
        )
        return _identity_artifacts(capture, expected_source_digest)
    except NativePluginUpdateBindingError:
        raise
    except (KeyError, TypeError, ValueError, IndexError, OverflowError) as exc:
        raise NativePluginUpdateBindingError(
            "retained observation is incomplete or malformed"
        ) from exc


def verify_native_plugin_update_binding(
    capture_raw: bytes,
    *,
    expected_capture_digest: str,
    expected_source_digest: str,
    expected_source_commit: str,
    deployment_raw: bytes,
    expected_deployment_digest: str,
    evidence_cas: CAS,
) -> dict[str, Any]:
    """Bind seven caller-held artifacts to a bounded retained-report replay."""
    _require(
        type(evidence_cas) is CAS and evidence_cas.read_only is True,
        "a read-only CAS is required",
    )
    artifacts = native_plugin_update_identity_artifacts(
        capture_raw,
        expected_capture_digest=expected_capture_digest,
        expected_source_digest=expected_source_digest,
        expected_source_commit=expected_source_commit,
    )
    try:
        deployment = resolve_phase3_deployment_identity(
            deployment_raw,
            expected_digest=expected_deployment_digest,
            evidence_cas=evidence_cas,
        )
        for name, expected_raw in artifacts.items():
            pinned = deployment["bindings"][name]
            _require(
                _digest(expected_raw) == pinned
                and evidence_cas.read(pinned, max_bytes=1024 * 1024) == expected_raw,
                "deployment dimension does not match retained observation: " + name,
            )
    except NativePluginUpdateBindingError:
        raise
    except (CASError, OSError, ValueError) as exc:
        raise NativePluginUpdateBindingError("deployment cannot be resolved") from exc
    return {
        "schema": "aragorn/native-phase3-plugin-update-binding/v1",
        "status": "BOUNDED_OBSERVATION_VERIFIED",
        "authority": "READ_ONLY_RETAINED_REPORT_BINDING_NOT_FRESH_ROUTE_OR_PHASE3_QUALIFICATION",
        "context": {
            "route_id": ROUTE,
            "branch": BRANCH,
            "capture_digest": expected_capture_digest,
            "source_record_digest": expected_source_digest,
            "source_commit": expected_source_commit,
            "deployment_identity_digest": expected_deployment_digest,
        },
        "reported_deployment_dimensions_verified": list(BINDING_DIMENSIONS),
        "live_deployment_dimensions_verified": [],
        "common_deployment_fully_verified": False,
        "limitations": list(LIMITATIONS),
        "fresh_campaign_execution": False,
        "independent_policy_semantics_verified": False,
        "logical_database_equality_verified": False,
        **dict.fromkeys(_FLAGS, False),
    }
