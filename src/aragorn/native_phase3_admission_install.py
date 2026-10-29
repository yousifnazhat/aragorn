"""Independent native upload-install denial joins, not full INSTALL coverage.

Reuse the native sealed-root and catalog contracts. The caller must retain the
actual command bytes and bind the owning fixture; no producer is imported here.
"""

from __future__ import annotations

import re

from . import native_phase3_admission_direct_write as shared
from .oci_worker_protocol import canonical_json

CASE_ID = "ADM-02/install"
BRANCH = "UPLOADED_ARCHIVE_DISABLED_BEFORE_INGESTION"
SCHEMA = "aragorn/native-admission-install-observation/v1"
AUTHORITY = "FIXED_UPLOAD_INSTALL_DENIAL_NOT_ADMISSION_OR_RUN_QUALIFICATION"
NAME = "aragorn-native-install-fixture"
PARAMS = {
    "agentId": "main",
    "force": False,
    "sha256": "a" * 64,
    "slug": NAME,
    "source": "upload",
    "uploadId": "a" * 32,
}
ARGV = (
    "/usr/local/bin/node", shared.ENTRY, "gateway", "call", "skills.install",
    "--json", "--timeout", "5000", "--params", canonical_json(PARAMS).decode(),
)
DENIAL = {
    "error": {
        "code": "UNAVAILABLE",
        "message": "Uploaded skill archive installs are disabled by "
        "skills.install.allowUploadedArchives",
        "retryable": False,
        "type": "gateway_request_error",
    },
    "ok": False,
}
LIMITATIONS = (
    *shared.LIMITATIONS,
    "UPLOAD_DISABLED_BRANCH_ONLY_NOT_LOCAL_PATH_CLAWHUB_OR_DEPENDENCY_INSTALL",
    "FIXED_UPLOAD_IDENTIFIER_NOT_ARCHIVE_INGESTION_OR_POLICY_HOOK_EXECUTION",
    "POINT_IN_TIME_CATALOG_JOINS_NOT_INSTALL_REQUEST_CAUSAL_ATTRIBUTION",
    "CONSUMER_ONLY_NATIVE_PRODUCER_AND_COMMON_DISPATCH_BINDING_PENDING",
)


class NativeInstallError(ValueError):
    """The fixed install denial observation cannot support bounded replay."""


def require(condition, reason):
    if not condition:
        raise NativeInstallError(reason)


def _command(value):
    shared._exact(value, {
        "argv", "exit_code", "stdout", "stdout_bytes", "stdout_digest",
        "stderr_bytes",
    })
    require(
        value["argv"] == list(ARGV)
        and type(value["exit_code"]) is int and value["exit_code"] == 1
        and type(value["stderr_bytes"]) is int and value["stderr_bytes"] == 0
        and type(value["stdout"]) is str,
        "INSTALL_COMMAND_CHANGED",
    )
    raw = value["stdout"].encode("utf-8")
    require(
        0 < len(raw) <= shared.MAX_COMMAND
        and type(value["stdout_bytes"]) is int
        and value["stdout_bytes"] == len(raw)
        and value["stdout_digest"] == shared.digest(raw),
        "INSTALL_COMMAND_BYTES_CHANGED",
    )
    require(
        canonical_json(shared.parse(raw)) == canonical_json(DENIAL),
        "UPLOAD_DISABLED_DENIAL_NOT_ESTABLISHED",
    )


def _snapshot(boundary, commands, bindings):
    shared.validate_boundary(
        boundary, container=bindings["expected_container"],
        gateway_pid=bindings["expected_gateway_pid"],
        admitted_pin=bindings["expected_admitted_digest"],
        source_pins={
            shared.PROBE: bindings["expected_shared_probe_digest"],
            shared.VERIFIER: bindings["expected_shared_verifier_digest"],
        },
    )
    for tree in boundary["roots"].values():
        require(all(entry["path"].split("/", 1)[0] != NAME
                    for entry in tree["entries"]), "INSTALL_TARGET_PRESENT")
    catalog = shared._commands(commands, bindings["expected_gateway_pid"])
    for kind, response in catalog.items():
        if kind != "system-info":
            skills = [response] if kind == "skill-info" else response["skills"]
            require(all(skill["name"] != NAME for skill in skills),
                    "INSTALL_TARGET_DISCOVERED")
    return catalog


def record_native_admission_install(*, read_boundary, run_command,
                                    expected_container, expected_gateway_pid,
                                    expected_admitted_digest,
                                    expected_shared_probe_digest,
                                    expected_shared_verifier_digest):
    """Record one attempt using caller-owned readers, without launching processes.

    read_boundary() supplies the existing native boundary record. run_command(argv)
    supplies a CompletedProcess with byte streams; its owner must enforce bounded
    execution, source custody and gateway identity. This helper grants no launcher
    authority. Failed observations retain metadata, never arbitrary diagnostics.
    """
    bindings = dict(
        expected_container=expected_container, expected_gateway_pid=expected_gateway_pid,
        expected_admitted_digest=expected_admitted_digest,
        expected_shared_probe_digest=expected_shared_probe_digest,
        expected_shared_verifier_digest=expected_shared_verifier_digest,
    )
    result = {
        "schema": SCHEMA, "authority": AUTHORITY, "case_id": CASE_ID,
        "branch": BRANCH, "status": "REFUSED", "refusal": None,
        "fixture_container": expected_container, "gateway_pid": expected_gateway_pid,
        "admitted_digest": expected_admitted_digest,
        "shared_source_pins": {
            shared.PROBE: expected_shared_probe_digest,
            shared.VERIFIER: expected_shared_verifier_digest,
        },
        "before": None, "after": None, "commands_before": [], "commands_after": [],
        "install_command": None, "limitations": list(LIMITATIONS),
        **dict.fromkeys(shared.FALSE_FLAGS, False),
    }
    phase, interruption = "PREREQUISITES", None

    def refuse(error):
        nonlocal interruption
        result["status"] = "REFUSED"
        if result["refusal"] is None:
            result["refusal"] = {"phase": phase, "reason": "FIXED_INSTALL_RECORDING_REFUSED"}
        if not isinstance(error, Exception) and interruption is None:
            interruption = error

    def command(argv, row):
        completed = run_command(list(argv))
        require(completed.args == list(argv)
                and type(completed.returncode) is int
                and type(completed.stdout) is bytes and type(completed.stderr) is bytes,
                "COMMAND_RESULT_CHANGED")
        row.update(exit_code=completed.returncode, stdout_bytes=len(completed.stdout),
                   stdout_digest=shared.digest(completed.stdout),
                   stderr_bytes=len(completed.stderr))
        require(0 < len(completed.stdout) <= shared.MAX_COMMAND
                and not completed.stderr, "COMMAND_OUTPUT_REFUSED")
        candidate = {**row, "stdout": completed.stdout.decode("utf-8")}
        return candidate

    def catalogs(target):
        rows = []
        for kind, args in shared.COMMANDS:
            argv = ["/usr/local/bin/node", shared.ENTRY, *args]
            row = command(argv, {"kind": kind, "argv": argv})
            rows.append(row)
        shared._commands(rows, expected_gateway_pid)
        target.extend(rows)

    try:
        require(type(expected_container) is str
                and re.fullmatch(r"[0-9a-f]{64}", expected_container) is not None
                and type(expected_gateway_pid) is int and expected_gateway_pid > 1,
                "OWNED_CALLER_CHANGED")
        for name, value in bindings.items():
            if name.endswith("digest"):
                shared.pin(value)
        phase = "BEFORE"
        result["before"] = shared.parse(canonical_json(read_boundary()))
        catalogs(result["commands_before"])
        _snapshot(result["before"], result["commands_before"], bindings)
        require(canonical_json(read_boundary()) == canonical_json(result["before"]),
                "PRE_ATTEMPT_BOUNDARY_CHANGED")
        phase = "INSTALL"
        result["install_command"] = {
            "argv": list(ARGV), "exit_code": None, "stdout": None,
            "stdout_bytes": None, "stdout_digest": None, "stderr_bytes": None,
        }
        try:
            row = command(ARGV, result["install_command"])
            _command(row)
            result["install_command"] = row
        except BaseException as error:
            refuse(error)
        finally:
            phase = "AFTER"
            try:
                result["after"] = shared.parse(canonical_json(read_boundary()))
            except BaseException as error:
                refuse(error)
            try:
                catalogs(result["commands_after"])
            except BaseException as error:
                refuse(error)
        if result["refusal"] is None:
            phase = "REPLAY"
            result["status"] = "OBSERVED"
            raw = canonical_json(result)
            verify_native_admission_install(
                raw, expected_raw_digest=shared.digest(raw), **bindings,
            )
    except BaseException as error:
        refuse(error)
    if interruption is not None:
        interruption._native_install_observation = result
        raise interruption
    return result


def verify_native_admission_install(
    raw, *, expected_raw_digest, expected_container, expected_gateway_pid,
    expected_admitted_digest, expected_shared_probe_digest,
    expected_shared_verifier_digest,
):
    """Replay retained bytes only; never execute an install or grant a route PASS."""
    try:
        require(
            type(raw) is bytes and 0 < len(raw) <= 2 * 1024 * 1024
            and shared.digest(raw) == shared.pin(expected_raw_digest),
            "OBSERVATION_PIN_CHANGED",
        )
        require(
            type(expected_container) is str
            and re.fullmatch(r"[0-9a-f]{64}", expected_container) is not None
            and type(expected_gateway_pid) is int and expected_gateway_pid > 1,
            "OWNED_CALLER_CHANGED",
        )
        pins = {
            shared.PROBE: shared.pin(expected_shared_probe_digest),
            shared.VERIFIER: shared.pin(expected_shared_verifier_digest),
        }
        value = shared.parse(raw)
        shared._exact(value, {
            "schema", "authority", "case_id", "branch", "status",
            "fixture_container", "gateway_pid", "admitted_digest",
            "shared_source_pins", "before", "after", "install_command",
            "commands_before", "commands_after", "refusal", "limitations",
            *shared.FALSE_FLAGS,
        })
        require(
            canonical_json(value) == raw
            and value["schema"] == SCHEMA and value["authority"] == AUTHORITY
            and value["case_id"] == CASE_ID and value["branch"] == BRANCH
            and value["status"] == "OBSERVED" and value["refusal"] is None
            and value["fixture_container"] == expected_container
            and type(value["gateway_pid"]) is int
            and value["gateway_pid"] == expected_gateway_pid
            and value["admitted_digest"] == shared.pin(expected_admitted_digest)
            and value["shared_source_pins"] == pins
            and value["limitations"] == list(LIMITATIONS)
            and all(value[key] is False for key in shared.FALSE_FLAGS),
            "OBSERVATION_CONTRACT_CHANGED",
        )
        catalogs = []
        for side in ("before", "after"):
            catalogs.append(_snapshot(value[side], value["commands_" + side], {
                "expected_container": expected_container,
                "expected_gateway_pid": expected_gateway_pid,
                "expected_admitted_digest": expected_admitted_digest,
                "expected_shared_probe_digest": expected_shared_probe_digest,
                "expected_shared_verifier_digest": expected_shared_verifier_digest,
            }))
        require(canonical_json(value["before"]) == canonical_json(value["after"]),
                "PROTECTED_BOUNDARY_CHANGED")
        require(canonical_json(catalogs[0]) == canonical_json(catalogs[1]),
                "CONSUMER_CATALOG_CHANGED")
        _command(value["install_command"])
        return {
            "schema": "aragorn/native-admission-install-verification/v1",
            "status": "BOUNDED_UPLOAD_INSTALL_DENIAL_JOINS_VERIFIED",
            "case_id": CASE_ID, "branch": BRANCH,
            "observation_digest": expected_raw_digest,
            "limitations": list(LIMITATIONS),
            **dict.fromkeys(shared.FALSE_FLAGS, False),
        }
    except NativeInstallError:
        raise
    except Exception as error:
        raise NativeInstallError("FIXED_INSTALL_REPLAY_REFUSED") from error
