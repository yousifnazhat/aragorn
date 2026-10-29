"""Offline joins for two fixed path-mutation leaves; never qualification."""

from __future__ import annotations

import errno
import re
import stat

from . import native_phase3_admission_direct_write as shared
from .oci_worker_protocol import canonical_json

CASES = ("ADM-02/rename", "ADM-02/symlink")
CASE_BRANCHES = {
    CASES[0]: "RENAME_SIX_ROOT_INSERTIONS_AND_FIVE_MOUNT_RETARGETS",
    CASES[1]: "SYMLINK_SIX_ROOT_INSERTIONS",
}
SCHEMA = "aragorn/native-admission-path-mutation-observation/v1"
AUTHORITY = "FIXED_LOCAL_PATH_MUTATION_OBSERVATION_NOT_ADMISSION_OR_RUN_QUALIFICATION"
PROBE = "/opt/aragorn/runtime_native_admission_path_mutation.py"
VERIFIER = "/usr/lib/aragorn/aragorn/native_phase3_admission_path_mutation.py"
WORKSPACE = "/var/lib/aragorn-agent-gateway/workspace"
NAMES = {
    CASES[0]: "aragorn-native-rename-fixture",
    CASES[1]: "aragorn-native-symlink-fixture",
}
SCRATCH = {case: WORKSPACE + "/." + name for case, name in NAMES.items()}
RETARGET_ROOTS = (
    shared.ROOTS[0],
    WORKSPACE + "/.agents",
    "/var/lib/aragorn-agent-gateway/home/.agents",
    shared.ROOTS[3],
    shared.ROOTS[4],
)
FALSE_FLAGS = shared.FALSE_FLAGS
LIMITATIONS = (
    *shared.LIMITATIONS,
    "EXDEV_AND_EBUSY_ARE_STRUCTURAL_OUTCOMES_NOT_POLICY_OR_PERMISSION_DENIAL",
    "SCRATCH_RETAINED_FOR_OUTER_OWNED_FIXTURE_DESTRUCTION_NO_LOCAL_UNDO",
)
digest, parse, pin = shared.digest, shared.parse, shared.pin


class NativePathMutationError(ValueError):
    """A fixed path-mutation contract was refused."""


def require(condition, reason):
    if not condition:
        raise NativePathMutationError(reason)


def payload(case_id):
    require(case_id in CASES, "FIXED_CASE_REQUIRED")
    return (
        "---\nname: "
        + NAMES[case_id]
        + "\ndescription: Inert owned path-mutation fixture.\n---\n"
    ).encode("ascii")


def sources(case_id):
    require(case_id in CASES, "FIXED_CASE_REQUIRED")
    return tuple(
        SCRATCH[case_id] + "/source-" + str(i)
        for i in range(6 if case_id == CASES[0] else 1)
    )


def operations(case_id):
    source_paths = sources(case_id)
    items = [
        {
            "operation": "rename-into-root"
            if case_id == CASES[0]
            else "symlink-into-root",
            "source": source_paths[index if case_id == CASES[0] else 0],
            "destination": root + "/" + NAMES[case_id],
        }
        for index, root in enumerate(shared.ROOTS)
    ]
    if case_id == CASES[0]:
        items.extend(
            {
                "operation": "retarget-mount",
                "source": root,
                "destination": root + "-aragorn-native-retarget",
            }
            for root in RETARGET_ROOTS
        )
    return items


def outcome(operation, completed, error):
    if completed:
        return "UNEXPECTED_SUCCESS"
    if error in (errno.EPERM, errno.EACCES, errno.EROFS):
        return "PERMISSION_OR_READONLY_DENIAL"
    if operation == "rename-into-root" and error == errno.EXDEV:
        return "CROSS_MOUNT_RENAME_REFUSED"
    if operation == "retarget-mount" and error == errno.EBUSY:
        return "MOUNTPOINT_BUSY"
    return "UNEXPECTED_ERROR"


def _exact(value, keys):
    require(type(value) is dict and set(value) == set(keys), "FIELD_INVENTORY_CHANGED")


def _entry(value, path, *, exists):
    _exact(value, ("path", "exists", "identity", "link_target"))
    require(
        value["path"] == path and value["exists"] is exists, "ENTRY_EXISTENCE_CHANGED"
    )
    if not exists:
        require(
            value["identity"] is value["link_target"] is None, "ABSENT_ENTRY_CHANGED"
        )
    else:
        shared._identity(value["identity"])
        require(
            stat.S_ISDIR(value["identity"][2]) and value["link_target"] is None,
            "SOURCE_NOT_DIRECTORY",
        )


def preparation(case_id):
    created = [{"path": SCRATCH[case_id], "kind": "directory", "bytes_written": 0}]
    for source in sources(case_id):
        created.extend(
            (
                {"path": source, "kind": "directory", "bytes_written": 0},
                {
                    "path": source + "/SKILL.md",
                    "kind": "file",
                    "bytes_written": len(payload(case_id)),
                },
            )
        )
    return {"root": SCRATCH[case_id], "created": created, "completed": True}


def validate_mutation_boundary(value, *, case_id, source_pins):
    _exact(value, ("scratch", "destinations", "retargets", "adapter_sources"))
    tree = value["scratch"]
    _exact(tree, ("identity", "read_only", "entries", "candidate_absent"))
    shared._identity(tree["identity"])
    require(
        stat.S_ISDIR(tree["identity"][2])
        and stat.S_IMODE(tree["identity"][2]) == 0o700
        and tree["identity"][3:5] == [992, 992]
        and tree["read_only"] is False
        and tree["candidate_absent"] is True,
        "SCRATCH_CUSTODY_CHANGED",
    )
    expected = {}
    for index, _ in enumerate(sources(case_id)):
        expected["source-" + str(index)] = "directory"
        expected["source-" + str(index) + "/SKILL.md"] = "file"
    entries = tree["entries"]
    require(
        type(entries) is list and [row["path"] for row in entries] == sorted(expected),
        "SCRATCH_INVENTORY_CHANGED",
    )
    for row in entries:
        _exact(row, ("path", "kind", "identity", "bytes", "digest"))
        shared._identity(row["identity"])
        directory = expected[row["path"]] == "directory"
        metadata = row["identity"]
        require(
            row["kind"] == expected[row["path"]]
            and (stat.S_ISDIR(metadata[2]) if directory else stat.S_ISREG(metadata[2]))
            and stat.S_IMODE(metadata[2]) == (0o700 if directory else 0o600)
            and metadata[3:5] == [992, 992],
            "SCRATCH_ENTRY_CUSTODY_CHANGED",
        )
        require(
            (row["bytes"] is row["digest"] is None)
            if directory
            else (
                row["bytes"] == metadata[6] == len(payload(case_id))
                and metadata[5] == 1
                and row["digest"] == digest(payload(case_id))
            ),
            "SCRATCH_BYTES_CHANGED",
        )
    _exact(value["destinations"], {row["destination"] for row in operations(case_id)})
    for path, record in value["destinations"].items():
        _entry(record, path, exists=False)
    _exact(value["retargets"], RETARGET_ROOTS if case_id == CASES[0] else ())
    for path, record in value["retargets"].items():
        _exact(record, ("path", "identity", "read_only"))
        shared._identity(record["identity"])
        require(
            record["path"] == path
            and record["read_only"] is True
            and stat.S_ISDIR(record["identity"][2]),
            "RETARGET_ROOT_NOT_SEALED",
        )
    _exact(value["adapter_sources"], (PROBE, VERIFIER))
    for path, record in value["adapter_sources"].items():
        shared._file(record, source_pins[path])
        metadata = record["identity"]
        require(
            metadata[3:6] == [0, 0, 1] and metadata[2] & 0o022 == 0,
            "ADAPTER_SOURCE_CUSTODY_CHANGED",
        )


def source_entry(boundary, case_id, path):
    if path in RETARGET_ROOTS:
        metadata = boundary["retargets"][path]["identity"]
    else:
        relative = path.removeprefix(SCRATCH[case_id] + "/")
        metadata = next(
            row["identity"]
            for row in boundary["scratch"]["entries"]
            if row["path"] == relative
        )
    return {"path": path, "exists": True, "identity": metadata, "link_target": None}


def validate_commands(value, *, case_id, gateway_pid):
    """Reuse all shared command joins and additionally exclude this case's name."""
    require(case_id in CASES, "FIXED_CASE_REQUIRED")
    projected = shared._commands(value, gateway_pid)
    for kind, response in projected.items():
        if kind == "system-info":
            continue
        skills = [response] if kind == "skill-info" else response["skills"]
        require(
            all(skill["name"] != NAMES[case_id] for skill in skills),
            "PATH_MUTATION_CANDIDATE_DISCOVERED",
        )
    return projected


def verify_native_admission_path_mutation(
    raw,
    *,
    expected_raw_digest,
    expected_case_id,
    expected_container,
    expected_gateway_pid,
    expected_admitted_digest,
    expected_probe_digest,
    expected_verifier_digest,
    expected_shared_probe_digest,
    expected_shared_verifier_digest,
):
    """Consume retained bytes only; no source execution or qualification claim."""
    try:
        require(
            expected_case_id in CASES
            and type(raw) is bytes
            and 0 < len(raw) <= 2097152
            and digest(raw) == pin(expected_raw_digest),
            "OBSERVATION_PIN_OR_CASE_CHANGED",
        )
        require(
            type(expected_container) is str
            and re.fullmatch(r"[0-9a-f]{64}", expected_container) is not None,
            "INVALID_CONTAINER",
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
                "commands_before",
                "commands_after",
                "scratch_preparation",
                "mutation_before",
                "mutation_after",
                "attempts",
                "postcondition_failures",
                "refusal",
                "limitations",
                *FALSE_FLAGS,
            ),
        )
        require(
            canonical_json(value) == raw
            and value["schema"] == SCHEMA
            and value["authority"] == AUTHORITY
            and value["case_id"] == expected_case_id
            and value["status"] == "OBSERVED"
            and value["refusal"] is None
            and value["fixture_container"] == expected_container
            and type(expected_gateway_pid) is int
            and expected_gateway_pid > 1
            and value["gateway_pid"] == expected_gateway_pid
            and value["admitted_digest"] == pin(expected_admitted_digest)
            and value["source_pins"] == own
            and value["shared_source_pins"] == old
            and value["limitations"] == list(LIMITATIONS)
            and value["postcondition_failures"] == []
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
            validate_mutation_boundary(
                value["mutation_" + side], case_id=expected_case_id, source_pins=own
            )
            for path, record in value["mutation_" + side]["retargets"].items():
                if path in shared.ROOTS:
                    require(
                        record["identity"] == value[side]["roots"][path]["identity"],
                        "RETARGET_SHARED_ROOT_JOIN_CHANGED",
                    )
        require(
            value["before"] == value["after"]
            and value["mutation_before"] == value["mutation_after"],
            "PROTECTED_OR_SOURCE_BOUNDARY_CHANGED",
        )
        require(
            canonical_json(value["scratch_preparation"])
            == canonical_json(preparation(expected_case_id)),
            "SCRATCH_PREPARATION_INCOMPLETE",
        )
        require(
            validate_commands(
                value["commands_before"],
                case_id=expected_case_id,
                gateway_pid=expected_gateway_pid,
            )
            == validate_commands(
                value["commands_after"],
                case_id=expected_case_id,
                gateway_pid=expected_gateway_pid,
            ),
            "CONSUMER_CHANGED",
        )
        plan = operations(expected_case_id)
        require(
            type(value["attempts"]) is list and len(value["attempts"]) == len(plan),
            "ATTEMPT_COUNT_CHANGED",
        )
        for attempt, operation in zip(value["attempts"], plan, strict=True):
            _exact(
                attempt,
                (
                    *operation,
                    "attempted",
                    "completed",
                    "errno",
                    "outcome",
                    "source_before",
                    "source_after",
                    "destination_before",
                    "destination_after",
                    "readback_failures",
                ),
            )
            require(
                all(attempt[key] == item for key, item in operation.items())
                and attempt["attempted"] is True
                and attempt["completed"] is False
                and type(attempt["errno"]) is int
                and attempt["readback_failures"] == [],
                "ATTEMPT_CHANGED",
            )
            classification = outcome(operation["operation"], False, attempt["errno"])
            require(
                classification not in ("UNEXPECTED_SUCCESS", "UNEXPECTED_ERROR")
                and attempt["outcome"] == classification,
                "MUTATION_NOT_REFUSED",
            )
            source = source_entry(
                value["mutation_before"], expected_case_id, operation["source"]
            )
            destination = value["mutation_before"]["destinations"][
                operation["destination"]
            ]
            require(
                attempt["source_before"] == attempt["source_after"] == source
                and attempt["destination_before"]
                == attempt["destination_after"]
                == destination,
                "OPERAND_READBACK_CHANGED",
            )
        return {
            "schema": "aragorn/native-admission-path-mutation-replay/v1",
            "status": "BOUNDED_PATH_MUTATION_JOINS_VERIFIED",
            "case_id": expected_case_id,
            "observation_digest": expected_raw_digest,
            "attempts": len(plan),
            "outcomes": [row["outcome"] for row in value["attempts"]],
            "limitations": list(LIMITATIONS),
            **dict.fromkeys(FALSE_FLAGS, False),
        }
    except NativePathMutationError:
        raise
    except (
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        StopIteration,
        OverflowError,
    ) as error:
        raise NativePathMutationError("PATH_MUTATION_REPLAY_REFUSED") from error
