"""Independent retained-byte joins for one fixed outside-root discovery check.

Catalog readbacks are not active-session prompt consumption or admission
qualification. This module imports no producer and performs no filesystem I/O.
"""

from __future__ import annotations

import re
import stat

from . import native_phase3_admission_direct_write as shared
from .oci_worker_protocol import canonical_json

CASE_ID = "ADM-02/auto-discovery"
BRANCH = "TWO_OUTSIDE_ROOT_SKILLS_EXCLUDED_FROM_CLI_AND_GATEWAY_CATALOGS"
SCHEMA = "aragorn/native-admission-auto-discovery-observation/v1"
AUTHORITY = "FIXED_LOCAL_DISCOVERY_OBSERVATION_NOT_ADMISSION_OR_RUN_QUALIFICATION"
PROBE = "/opt/aragorn/runtime_native_admission_auto_discovery.py"
VERIFIER = "/usr/lib/aragorn/aragorn/native_phase3_admission_auto_discovery.py"
WORKSPACE = "/var/lib/aragorn-agent-gateway/workspace"
CANDIDATES = {
    WORKSPACE
    + "/aragorn-native-auto-discovery-workspace": "aragorn-native-auto-discovery-workspace",
    "/tmp/aragorn-native-auto-discovery-tmp": "aragorn-native-auto-discovery-tmp",
}
PARENTS = {WORKSPACE: (992, 992, 0o700), "/tmp": (0, 0, 0o1777)}
FALSE_FLAGS = shared.FALSE_FLAGS
LIMITATIONS = (
    *shared.LIMITATIONS,
    "TWO_FIXED_OUTSIDE_DISCOVERY_ROOT_FIXTURES_NOT_ARBITRARY_DISCOVERY_COVERAGE",
    "FRESH_CLI_AND_GATEWAY_SKILLS_STATUS_NOT_CACHE_INVALIDATION_OR_PROMPT_CONSUMPTION",
    "FIXTURE_CREATION_IS_NOT_A_DENIED_INSTALL_OR_POLICY_HOOK_OBSERVATION",
    "FIXED_LEAF_NOT_YET_BOUND_BY_COMMON74_DISPATCHER_OR_SOURCE_INVENTORY",
    "SCRATCH_RETAINED_FOR_EXACT_OUTER_FIXTURE_CLEANUP_NO_LOCAL_UNDO_OR_RETRY",
)
digest, parse, pin = shared.digest, shared.parse, shared.pin
MAX_RECORD = 2 * 1024 * 1024


class NativeAutoDiscoveryError(ValueError):
    """Fixed outside-root discovery evidence is incomplete or inconsistent."""


def require(condition, reason):
    if not condition:
        raise NativeAutoDiscoveryError(reason)


def _exact(value, keys):
    require(type(value) is dict and set(value) == set(keys), "FIELD_INVENTORY_CHANGED")


def payload(path):
    require(path in CANDIDATES, "FIXED_CANDIDATE_REQUIRED")
    return (
        "---\nname: "
        + CANDIDATES[path]
        + "\ndescription: Inert owned outside-root discovery fixture.\n---\n"
        + "# Inert admission fixture\n"
    ).encode("ascii")


def creation(path, candidate):
    return {
        "path": path,
        "directory_created": True,
        "file_created": True,
        "bytes_written": len(payload(path)),
        "completed": True,
        "directory_identity": candidate["identity"],
        "file_identity": candidate["entries"][0]["identity"],
    }


def validate_sources(value, expected):
    _exact(value, (PROBE, VERIFIER))
    for path in (PROBE, VERIFIER):
        shared._file(value[path], expected[path])
        metadata = value[path]["identity"]
        require(
            metadata[3:6] == [0, 0, 1] and stat.S_IMODE(metadata[2]) == 0o444,
            "ADAPTER_SOURCE_CUSTODY_CHANGED",
        )


def validate_parents(value):
    _exact(value, PARENTS)
    for path, (uid, gid, mode) in PARENTS.items():
        item = value[path]
        _exact(item, ("identity", "read_only"))
        metadata = item["identity"]
        require(
            type(metadata) is list
            and len(metadata) == 5
            and all(type(part) is int and part >= 0 for part in metadata)
            and metadata[1] > 0
            and stat.S_ISDIR(metadata[2])
            and stat.S_IMODE(metadata[2]) == mode
            and metadata[3:] == [uid, gid]
            and item["read_only"] is False,
            "CANDIDATE_PARENT_CUSTODY_CHANGED",
        )


def validate_candidate(value, path):
    _exact(value, ("identity", "read_only", "entries", "candidate_absent"))
    shared._identity(value["identity"])
    metadata = value["identity"]
    require(
        stat.S_ISDIR(metadata[2])
        and stat.S_IMODE(metadata[2]) == 0o700
        and metadata[1] > 0
        and metadata[3:5] == [992, 992]
        and value["read_only"] is False
        and value["candidate_absent"] is True,
        "CANDIDATE_ROOT_CUSTODY_CHANGED",
    )
    entries = value["entries"]
    require(type(entries) is list and len(entries) == 1, "CANDIDATE_INVENTORY_CHANGED")
    item = entries[0]
    _exact(item, ("path", "kind", "identity", "bytes", "digest"))
    shared._identity(item["identity"])
    metadata = item["identity"]
    raw = payload(path)
    require(
        item["path"] == "SKILL.md"
        and item["kind"] == "file"
        and metadata[0] == value["identity"][0]
        and metadata[1] > 0
        and stat.S_ISREG(metadata[2])
        and stat.S_IMODE(metadata[2]) == 0o600
        and metadata[3:6] == [992, 992, 1]
        and type(item["bytes"]) is int
        and metadata[6] == item["bytes"] == len(raw)
        and item["digest"] == digest(raw),
        "CANDIDATE_BYTES_OR_CUSTODY_CHANGED",
    )


def validate_commands(value, gateway_pid):
    projected = shared._commands(value, gateway_pid)
    for kind, response in projected.items():
        if kind == "system-info":
            continue
        skills = [response] if kind == "skill-info" else response["skills"]
        require(
            all(skill["name"] not in CANDIDATES.values() for skill in skills),
            "OUTSIDE_ROOT_CANDIDATE_DISCOVERED",
        )
    return projected


def verify_native_admission_auto_discovery(
    raw,
    *,
    expected_raw_digest,
    expected_container,
    expected_gateway_pid,
    expected_admitted_digest,
    expected_probe_digest,
    expected_verifier_digest,
    expected_shared_probe_digest,
    expected_shared_verifier_digest,
):
    """Verify a complete fixed observation, not its acquisition or qualification."""
    try:
        require(
            type(raw) is bytes
            and 0 < len(raw) <= MAX_RECORD
            and digest(raw) == pin(expected_raw_digest),
            "OBSERVATION_PIN_CHANGED",
        )
        require(
            type(expected_container) is str
            and re.fullmatch(r"[0-9a-f]{64}", expected_container) is not None
            and type(expected_gateway_pid) is int
            and expected_gateway_pid > 1,
            "OWNED_CALLER_CHANGED",
        )
        own = {
            PROBE: pin(expected_probe_digest),
            VERIFIER: pin(expected_verifier_digest),
        }
        old = {
            shared.PROBE: pin(expected_shared_probe_digest),
            shared.VERIFIER: pin(expected_shared_verifier_digest),
        }
        value = parse(raw)
        _exact(
            value,
            (
                "schema",
                "authority",
                "case_id",
                "status",
                "fixture_container",
                "gateway_pid",
                "admitted_digest",
                "source_pins",
                "shared_source_pins",
                "before",
                "after",
                "sources_before",
                "sources_after",
                "parents_before",
                "parents_after",
                "candidates_before",
                "creation_attempts",
                "candidates_ready",
                "candidates_after",
                "commands_before",
                "commands_after",
                "refusal",
                "postcondition_failures",
                "cleanup_failures",
                "limitations",
                *FALSE_FLAGS,
            ),
        )
        require(
            canonical_json(value) == raw
            and value["schema"] == SCHEMA
            and value["authority"] == AUTHORITY
            and value["case_id"] == CASE_ID
            and value["status"] == "OBSERVED"
            and value["refusal"] is None
            and value["fixture_container"] == expected_container
            and type(value["gateway_pid"]) is int
            and value["gateway_pid"] == expected_gateway_pid
            and value["admitted_digest"] == pin(expected_admitted_digest)
            and value["source_pins"] == own
            and value["shared_source_pins"] == old
            and value["limitations"] == list(LIMITATIONS)
            and value["postcondition_failures"] == value["cleanup_failures"] == []
            and all(value[key] is False for key in FALSE_FLAGS),
            "OBSERVATION_CONTRACT_CHANGED",
        )
        for side in ("before", "after"):
            shared.validate_boundary(
                value[side],
                container=expected_container,
                gateway_pid=expected_gateway_pid,
                admitted_pin=expected_admitted_digest,
                source_pins=old,
            )
            validate_sources(value["sources_" + side], own)
            validate_parents(value["parents_" + side])
            for tree in value[side]["roots"].values():
                require(
                    all(
                        item["path"].split("/", 1)[0] not in CANDIDATES.values()
                        for item in tree["entries"]
                    ),
                    "CANDIDATE_ENTERED_DISCOVERY_ROOT",
                )
        require(
            value["before"] == value["after"]
            and value["sources_before"] == value["sources_after"]
            and value["parents_before"] == value["parents_after"],
            "PROTECTED_BOUNDARY_CHANGED",
        )
        _exact(value["candidates_before"], CANDIDATES)
        for path in CANDIDATES:
            require(
                value["candidates_before"][path]
                == {"path": path, "exists": False, "identity": None}
                and value["candidates_before"][path]["exists"] is False,
                "CANDIDATE_NOT_FRESH",
            )
        for side in ("ready", "after"):
            _exact(value["candidates_" + side], CANDIDATES)
            for path in CANDIDATES:
                validate_candidate(value["candidates_" + side][path], path)
                parent = path.rsplit("/", 1)[0]
                require(
                    value["candidates_" + side][path]["identity"][0]
                    == value["parents_before"][parent]["identity"][0],
                    "CANDIDATE_FILESYSTEM_CHANGED",
                )
        require(
            type(value["creation_attempts"]) is list
            and canonical_json(value["creation_attempts"])
            == canonical_json(
                [creation(path, value["candidates_ready"][path]) for path in CANDIDATES]
            ),
            "CANDIDATE_CREATION_INCOMPLETE",
        )
        require(
            value["candidates_ready"] == value["candidates_after"],
            "CANDIDATE_CHANGED_AFTER_CREATION",
        )
        require(
            validate_commands(value["commands_before"], expected_gateway_pid)
            == validate_commands(value["commands_after"], expected_gateway_pid),
            "CONSUMER_CATALOG_CHANGED",
        )
        return {
            "schema": "aragorn/native-admission-auto-discovery-verification/v1",
            "status": "BOUNDED_AUTO_DISCOVERY_JOINS_VERIFIED",
            "case_id": CASE_ID,
            "observation_digest": expected_raw_digest,
            "outside_root_candidates": 2,
            "limitations": list(LIMITATIONS),
            **dict.fromkeys(FALSE_FLAGS, False),
        }
    except NativeAutoDiscoveryError:
        raise
    except Exception as error:
        raise NativeAutoDiscoveryError("FIXED_AUTO_DISCOVERY_REPLAY_REFUSED") from error
