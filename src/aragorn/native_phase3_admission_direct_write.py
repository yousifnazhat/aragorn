"""Offline joins for one native direct-write observation, never qualification.

This consumer independently parses retained command bytes and mutation results.
The local probe is still the source of filesystem/kernel observations; digest
joins do not authenticate that observer, the host, or a completed deployment.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
from typing import Any

from .oci_worker_protocol import canonical_json

CASE_ID = "ADM-02/direct-write"
SCHEMA = "aragorn/native-admission-direct-write-observation/v1"
AUTHORITY = "FIXED_LOCAL_DIRECT_WRITE_OBSERVATION_NOT_ADMISSION_OR_RUN_QUALIFICATION"
ROOTS = (
    "/var/lib/aragorn-agent-gateway/workspace/skills",
    "/var/lib/aragorn-agent-gateway/workspace/.agents/skills",
    "/var/lib/aragorn-agent-gateway/home/.agents/skills",
    "/var/lib/aragorn-agent-gateway/state/skills",
    "/var/lib/aragorn-agent-gateway/state/plugin-skills",
    "/runtime/lib/node_modules/openclaw/skills",
)
ADMITTED = "/opt/aragorn/runtime-profile/template-skill/SKILL.md"
PROBE = "/opt/aragorn/runtime_native_admission_direct_write.py"
VERIFIER = "/usr/lib/aragorn/aragorn/native_phase3_admission_direct_write.py"
ENTRY = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
ENTRY_PIN = "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
CONFIG = "/run/credentials/aragorn-agent-gateway.service/openclaw-config"
CONFIG_PIN = "sha256:dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c"
NAME = "aragorn-native-direct-write-fixture"
PAYLOAD = b"---\nname: aragorn-native-direct-write-fixture\ndescription: Inert owned denial fixture.\n---\n"
COMMANDS = (
    ("system-info", ("gateway", "call", "system.info", "--json", "--timeout", "5000")),
    ("skill-info", ("skills", "info", "template-skill", "--agent", "main", "--json")),
    ("skill-list", ("skills", "list", "--agent", "main", "--json")),
    (
        "gateway-skills",
        ("gateway", "call", "skills.status", "--json", "--timeout", "5000"),
    ),
)
FALSE_FLAGS = (
    "route_qualified",
    "phase3_eligible",
    "run_conformance_eligible",
    "production_activation_eligible",
    "common_deployment_fully_verified",
    "live_deployment_attested",
    "metrics_eligible",
    "fresh_campaign_execution",
)
LIMITATIONS = (
    "LOCAL_NONROOT_OBSERVER_NOT_EXTERNAL_ATTESTATION",
    "CALLER_CONTAINER_AND_SOURCE_PINS_REQUIRE_OWNED_HOST_LAUNCHER",
    "SOURCE_READBACK_NOT_COMPLETE_PYTHON_IMPORT_OR_RUNTIME_PROVENANCE",
    "POINT_IN_TIME_ROOT_INVENTORIES_NOT_CONTINUOUS_CUSTODY",
    "GATEWAY_CATALOG_NOT_PROMPT_OR_ACTIVE_SESSION_CONSUMPTION",
    "NO_HOST_FIXTURE_CLEANUP_OR_ADMISSION_QUALIFICATION",
)
MAX_COMMAND = 131072


class NativeDirectWriteError(ValueError):
    """A fixed direct-write contract or observation was refused."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise NativeDirectWriteError(message)


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def pin(value: Any) -> str:
    require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "INVALID_PIN",
    )
    return value


def _pairs(items):
    value = dict(items)
    require(len(value) == len(items), "DUPLICATE_KEY")
    return value


def parse(raw: bytes) -> Any:
    def constant(_):
        raise NativeDirectWriteError("NONFINITE_JSON")

    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=constant)


def _exact(value: Any, fields: set[str]) -> None:
    require(type(value) is dict and set(value) == fields, "FIELD_INVENTORY_CHANGED")


def _identity(value: Any) -> None:
    require(
        type(value) is list
        and len(value) == 9
        and all(type(item) is int and item >= 0 for item in value),
        "INVALID_IDENTITY",
    )


def _file(value: Any, expected: str | None = None) -> None:
    _exact(value, {"identity", "bytes", "digest", "read_only"})
    _identity(value["identity"])
    require(
        type(value["bytes"]) is int
        and 0 < value["bytes"] <= 1048576
        and type(value["read_only"]) is bool
        and stat.S_ISREG(value["identity"][2])
        and value["identity"][5] == 1
        and value["identity"][6] == value["bytes"],
        "INVALID_FILE",
    )
    pin(value["digest"])
    require(expected is None or value["digest"] == expected, "FILE_PIN_CHANGED")


def validate_boundary(
    value: dict,
    *,
    container: str,
    gateway_pid: int,
    admitted_pin: str,
    source_pins: dict,
) -> None:
    _exact(value, {"gateway", "roots", "admitted", "sources", "entry", "config"})
    gateway = value["gateway"]
    _exact(
        gateway,
        {
            "pid",
            "start_time_ticks",
            "cgroup",
            "mount_namespace",
            "effective_capabilities",
            "no_new_privileges",
            "uid",
            "gid",
        },
    )
    require(
        gateway["pid"] == gateway_pid
        and type(gateway["pid"]) is int
        and type(gateway["start_time_ticks"]) is int
        and gateway["start_time_ticks"] > 0
        and gateway["cgroup"]
        == f"0::/docker/{container}/system.slice/aragorn-agent-gateway.service\n"
        and type(gateway["mount_namespace"]) is int
        and gateway["mount_namespace"] > 0
        and gateway["effective_capabilities"] == "0000000000000000"
        and gateway["no_new_privileges"] == "1"
        and gateway["uid"] == gateway["gid"] == [992] * 4,
        "GATEWAY_IDENTITY_CHANGED",
    )
    _exact(value["roots"], set(ROOTS))
    for root in ROOTS:
        tree = value["roots"][root]
        _exact(tree, {"identity", "read_only", "entries", "candidate_absent"})
        _identity(tree["identity"])
        require(
            stat.S_ISDIR(tree["identity"][2])
            and tree["read_only"] is True
            and tree["candidate_absent"] is True
            and type(tree["entries"]) is list
            and len(tree["entries"]) <= 512,
            "DISCOVERY_ROOT_NOT_SEALED_OR_FRESH",
        )
        names = []
        for entry in tree["entries"]:
            _exact(entry, {"path", "kind", "identity", "bytes", "digest"})
            path = entry["path"]
            require(
                type(path) is str
                and path
                and not path.startswith("/")
                and all(part not in {"", ".", ".."} for part in path.split("/")),
                "TREE_PATH_CHANGED",
            )
            _identity(entry["identity"])
            require(entry["kind"] in {"file", "directory"}, "TREE_KIND_CHANGED")
            if entry["kind"] == "file":
                require(
                    type(entry["bytes"]) is int and 0 <= entry["bytes"] <= 1048576,
                    "TREE_FILE_SIZE_CHANGED",
                )
                require(
                    stat.S_ISREG(entry["identity"][2])
                    and entry["identity"][5] == 1
                    and entry["identity"][6] == entry["bytes"],
                    "TREE_FILE_CUSTODY_CHANGED",
                )
                pin(entry["digest"])
            else:
                require(
                    stat.S_ISDIR(entry["identity"][2])
                    and entry["bytes"] is None
                    and entry["digest"] is None,
                    "TREE_DIRECTORY_PAYLOAD_CHANGED",
                )
            names.append(path)
        require(names == sorted(set(names)), "TREE_INVENTORY_CHANGED")
    _file(value["admitted"], admitted_pin)
    require(value["admitted"]["read_only"] is True, "ADMITTED_NOT_READONLY")
    _exact(value["sources"], {PROBE, VERIFIER})
    for path, expected in source_pins.items():
        _file(value["sources"][path], expected)
        meta = value["sources"][path]["identity"]
        require(
            meta[3:6] == [0, 0, 1] and meta[2] & 0o022 == 0, "SOURCE_CUSTODY_CHANGED"
        )
    _file(value["entry"], ENTRY_PIN)
    require(value["entry"]["read_only"] is True, "ENTRY_NOT_READONLY")
    _file(value["config"], CONFIG_PIN)
    require(value["config"]["read_only"] is True, "CONFIG_NOT_READONLY")


def _commands(value: Any, gateway_pid: int) -> dict:
    require(
        type(value) is list and len(value) == len(COMMANDS), "COMMAND_COUNT_CHANGED"
    )
    projected = {}
    for record, (kind, args) in zip(value, COMMANDS, strict=True):
        _exact(
            record,
            {
                "kind",
                "argv",
                "exit_code",
                "stdout",
                "stdout_bytes",
                "stdout_digest",
                "stderr_bytes",
            },
        )
        require(
            record["kind"] == kind
            and record["argv"] == ["/usr/local/bin/node", ENTRY, *args]
            and type(record["exit_code"]) is int
            and record["exit_code"] == 0
            and type(record["stderr_bytes"]) is int
            and record["stderr_bytes"] == 0
            and type(record["stdout"]) is str,
            "COMMAND_IDENTITY_CHANGED",
        )
        raw = record["stdout"].encode("utf-8")
        require(
            0 < len(raw) <= MAX_COMMAND
            and type(record["stdout_bytes"]) is int
            and record["stdout_bytes"] == len(raw)
            and record["stdout_digest"] == digest(raw),
            "COMMAND_BYTES_CHANGED",
        )
        response = parse(raw)
        require(type(response) is dict, "COMMAND_RESPONSE_CHANGED")
        if kind == "system-info":
            require(
                type(response.get("pid")) is int and response["pid"] == gateway_pid,
                "CONSUMER_GATEWAY_CHANGED",
            )
            projected[kind] = {"pid": response["pid"]}
            continue
        skills = [response] if kind == "skill-info" else response.get("skills")
        require(
            type(skills) is list
            and 0 < len(skills) <= 512
            and all(
                type(skill) is dict and type(skill.get("name")) is str
                for skill in skills
            ),
            "SKILL_CATALOG_CHANGED",
        )
        require(
            all(skill["name"] != NAME for skill in skills), "INJECTED_SKILL_DISCOVERED"
        )
        template = [skill for skill in skills if skill["name"] == "template-skill"]
        require(len(template) == 1, "ADMITTED_CONSUMER_MISSING")
        if kind != "skill-list":
            # These fields are present in the retained native skills.info and
            # gateway skills.status observations. No native list-field promise
            # is inferred from the historical contained-profile list command.
            for key, expected in {
                "source": "openclaw-extra",
                "eligible": True,
                "modelVisible": True,
                "commandVisible": True,
                "blockedByAgentFilter": False,
                "blockedByAllowlist": False,
            }.items():
                require(
                    template[0].get(key) == expected
                    and type(template[0].get(key)) is type(expected),
                    "ADMITTED_CONSUMER_CHANGED",
                )
            require(template[0].get("filePath") == ADMITTED, "ADMITTED_PATH_CHANGED")
        # Retain all parsed catalogue fields in equality, not only allowlist flags.
        projected[kind] = response
    return projected


def verify_native_admission_direct_write(
    raw: bytes,
    *,
    expected_raw_digest: str,
    expected_container: str,
    expected_gateway_pid: int,
    expected_admitted_digest: str,
    expected_probe_digest: str,
    expected_verifier_digest: str,
) -> dict:
    """Replay a completed bounded observation without reading the host or writing CAS."""
    require(
        type(raw) is bytes
        and 0 < len(raw) <= 2097152
        and digest(raw) == pin(expected_raw_digest),
        "OBSERVATION_PIN_CHANGED",
    )
    require(
        type(expected_container) is str
        and re.fullmatch(r"[0-9a-f]{64}", expected_container) is not None
        and type(expected_gateway_pid) is int
        and expected_gateway_pid > 1,
        "INVALID_CALLER_IDENTITY",
    )
    source_pins = {
        PROBE: pin(expected_probe_digest),
        VERIFIER: pin(expected_verifier_digest),
    }
    value = parse(raw)
    _exact(
        value,
        {
            "schema",
            "authority",
            "case_id",
            "status",
            "fixture_container",
            "gateway_pid",
            "admitted_digest",
            "source_pins",
            "before",
            "after",
            "commands_before",
            "commands_after",
            "attempts",
            "refusal",
            "limitations",
            *FALSE_FLAGS,
        },
    )
    require(
        canonical_json(value) == raw
        and value["schema"] == SCHEMA
        and value["authority"] == AUTHORITY
        and value["case_id"] == CASE_ID
        and value["status"] == "OBSERVED"
        and value["refusal"] is None
        and value["fixture_container"] == expected_container
        and value["gateway_pid"] == expected_gateway_pid
        and value["admitted_digest"] == pin(expected_admitted_digest)
        and value["source_pins"] == source_pins
        and value["limitations"] == list(LIMITATIONS)
        and all(value[key] is False for key in FALSE_FLAGS),
        "OBSERVATION_CONTRACT_CHANGED",
    )
    for boundary in (value["before"], value["after"]):
        validate_boundary(
            boundary,
            container=expected_container,
            gateway_pid=expected_gateway_pid,
            admitted_pin=expected_admitted_digest,
            source_pins=source_pins,
        )
    require(value["before"] == value["after"], "PROTECTED_BOUNDARY_CHANGED")
    attempts = value["attempts"]
    require(type(attempts) is list and len(attempts) == 7, "ATTEMPT_COUNT_CHANGED")
    targets = [root + "/" + NAME for root in ROOTS] + [ADMITTED]
    for index, (attempt, target) in enumerate(zip(attempts, targets, strict=True)):
        _exact(
            attempt,
            {
                "operation",
                "path",
                "completed",
                "errno",
                "created_directory",
                "bytes_written",
                "payload_digest",
            },
        )
        require(
            attempt["operation"]
            == ("create-skill" if index < 6 else "overwrite-admitted")
            and attempt["path"] == target
            and attempt["completed"] is False
            and type(attempt["errno"]) is int
            and attempt["errno"] in {1, 13, 30}
            and attempt["created_directory"] is False
            and type(attempt["bytes_written"]) is int
            and attempt["bytes_written"] == 0
            and attempt["payload_digest"] == digest(PAYLOAD),
            "DIRECT_WRITE_NOT_DENIED",
        )
    require(
        _commands(value["commands_before"], expected_gateway_pid)
        == _commands(value["commands_after"], expected_gateway_pid),
        "PROTECTED_CONSUMER_CHANGED",
    )
    return {
        "schema": "aragorn/native-admission-direct-write-replay/v1",
        "status": "BOUNDED_DIRECT_WRITE_JOINS_VERIFIED",
        "case_id": CASE_ID,
        "observation_digest": expected_raw_digest,
        "attempts": 7,
        "limitations": list(LIMITATIONS),
        **dict.fromkeys(FALSE_FLAGS, False),
    }
