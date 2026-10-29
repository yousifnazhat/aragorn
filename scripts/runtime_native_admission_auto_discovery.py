"""One fixed nonroot discovery leaf; no activation, install, retry or local undo.

The caller must enter an owned gateway mount namespace and drop to 992 with no
capabilities. This leaf is not yet wired into the common74 capture dispatcher.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import re
import select
import stat
import sys

if __package__:
    from scripts import runtime_native_admission_direct_write as readers
else:
    sys.path[:0] = ["/usr/lib/aragorn", "/opt/aragorn"]
    import runtime_native_admission_direct_write as readers

from aragorn import native_phase3_admission_auto_discovery as contract
from aragorn.oci_worker_protocol import canonical_json


def _guard(arguments):
    contract.require(
        sys.platform == "linux"
        and os.getresuid() == (992, 992, 992)
        and os.getresgid() == (992, 992, 992)
        and os.getgroups() == [992],
        "FIXED_NONROOT_IDENTITY_REQUIRED",
    )
    container, pid = arguments["expected_container"], arguments["expected_gateway_pid"]
    contract.require(
        type(container) is str
        and re.fullmatch(r"[0-9a-f]{64}", container) is not None
        and type(pid) is int
        and pid > 1,
        "INVALID_OWNED_CALLER",
    )
    for name, value in arguments.items():
        if name.endswith("digest"):
            contract.pin(value)
    contract.require(
        str(Path(__file__)) == contract.PROBE
        and str(Path(contract.__file__)) == contract.VERIFIER
        and str(Path(readers.__file__)) == contract.shared.PROBE
        and str(Path(contract.shared.__file__)) == contract.shared.VERIFIER,
        "FIXED_SOURCE_LOCATION_REQUIRED",
    )
    own = readers._status("self")
    contract.require(
        all(
            own.get(key, "").strip() == "0000000000000000"
            for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        )
        and own.get("NoNewPrivs", "").strip() == "1",
        "PRIVILEGE_DROP_REQUIRED",
    )
    contract.require(
        re.fullmatch(
            r"0::/docker/" + container + r"(?:/[^\n]*)?\n",
            readers._read_proc("/proc/self/cgroup").decode("ascii"),
        )
        is not None,
        "OWNED_CONTAINER_MISMATCH",
    )
    token = os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")
    contract.require(
        re.fullmatch(r"[0-9a-f]{64}", token) is not None, "FIXTURE_TOKEN_REQUIRED"
    )
    return token


def _parent(fd, path):
    metadata = os.fstat(fd)
    named = os.stat(path, follow_symlinks=False)
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
    identity = [getattr(metadata, field) for field in fields]
    contract.require(
        identity == [getattr(named, field) for field in fields],
        "CANDIDATE_PARENT_REPLACED",
    )
    item = {
        "identity": identity,
        "read_only": bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY),
    }
    uid, gid, mode = contract.PARENTS[path]
    contract.require(
        stat.S_ISDIR(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) == mode
        and (metadata.st_uid, metadata.st_gid) == (uid, gid)
        and item["read_only"] is False,
        "CANDIDATE_PARENT_CUSTODY_REFUSED",
    )
    return item


def _absent(parent, path):
    try:
        metadata = os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return {"path": path, "exists": False, "identity": None}
    return {"path": path, "exists": True, "identity": readers._identity(metadata)}


def _close(fd, failures):
    primary = sys.exception()
    try:
        os.close(fd)
    except BaseException as error:
        failures.append("OWNED_DESCRIPTOR_CLOSE_REFUSED")
        if primary is None or (
            isinstance(primary, Exception) and not isinstance(error, Exception)
        ):
            raise


def _create(parent, path, expected_parent, record, cleanup_failures):
    """Create this candidate once; a short write is retained and never retried."""
    contract.require(path in contract.CANDIDATES, "FIXED_CANDIDATE_REQUIRED")
    raw = contract.payload(path)
    parent_path = str(Path(path).parent)
    contract.require(
        _parent(parent, parent_path) == expected_parent,
        "PARENT_CHANGED_BEFORE_CREATION",
    )
    contract.require(
        _absent(parent, path)["exists"] is False, "CANDIDATE_ALREADY_EXISTS"
    )
    descriptors = []
    try:
        # Once an operation has started, an exception does not establish that
        # it had no effect. Keep unknown outcomes until the syscall returns.
        record["directory_created"] = None
        os.mkdir(Path(path).name, 0o700, dir_fd=parent)
        record["directory_created"] = True
        fd = os.open(
            Path(path).name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        descriptors.append(fd)
        before = os.fstat(fd)
        record["directory_identity"] = readers._identity(before)
        contract.require(
            readers._identity(before)
            == readers._identity(
                os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)
            )
            and stat.S_ISDIR(before.st_mode)
            and stat.S_IMODE(before.st_mode) == 0o700
            and (before.st_uid, before.st_gid) == (992, 992),
            "NEW_CANDIDATE_CUSTODY_REFUSED",
        )
        record["file_created"] = None
        file_fd = os.open(
            "SKILL.md",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=fd,
        )
        descriptors.append(file_fd)
        record["file_created"] = True
        metadata = os.fstat(file_fd)
        record["file_identity"] = readers._identity(metadata)
        contract.require(
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
            and stat.S_IMODE(metadata.st_mode) == 0o600
            and (metadata.st_uid, metadata.st_gid) == (992, 992),
            "NEW_SKILL_CUSTODY_REFUSED",
        )
        record["bytes_written"] = None
        record["bytes_written"] = os.write(file_fd, raw)
        contract.require(
            type(record["bytes_written"]) is int
            and record["bytes_written"] == len(raw),
            "CANDIDATE_WRITE_INCOMPLETE",
        )
        os.fsync(file_fd)
        os.fsync(fd)
        os.fsync(parent)
        record["directory_identity"] = readers._identity(os.fstat(fd))
        record["file_identity"] = readers._identity(os.fstat(file_fd))
        contract.require(
            record["directory_identity"][:6] == readers._identity(before)[:6]
            and record["file_identity"][:6] == readers._identity(metadata)[:6],
            "CREATED_OBJECT_CUSTODY_CHANGED",
        )
        contract.require(
            record["file_identity"]
            == readers._identity(os.stat("SKILL.md", dir_fd=fd, follow_symlinks=False)),
            "NEW_SKILL_REPLACED",
        )
        contract.require(
            record["directory_identity"]
            == readers._identity(
                os.stat(Path(path).name, dir_fd=parent, follow_symlinks=False)
            ),
            "NEW_CANDIDATE_REPLACED",
        )
        contract.require(
            _parent(parent, parent_path) == expected_parent,
            "PARENT_CHANGED_AFTER_CREATION",
        )
        record["completed"] = True
    finally:
        primary = sys.exception()
        close_error = None
        close_interrupt = None
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except BaseException as error:
                cleanup_failures.append("CANDIDATE_DESCRIPTOR_CLOSE_REFUSED")
                close_error = close_error or error
                if not isinstance(error, Exception):
                    close_interrupt = close_interrupt or error
        if close_interrupt is not None and (
            primary is None or isinstance(primary, Exception)
        ):
            raise close_interrupt
        if primary is None and close_error is not None:
            raise close_error


def _candidate(path):
    with ExitStack() as held:
        return readers._tree(path, held)


def run_auto_discovery_probe(
    *,
    expected_container,
    expected_gateway_pid,
    expected_admitted_digest,
    expected_probe_digest,
    expected_verifier_digest,
    expected_shared_probe_digest,
    expected_shared_verifier_digest,
):
    arguments = dict(
        expected_container=expected_container,
        expected_gateway_pid=expected_gateway_pid,
        expected_admitted_digest=expected_admitted_digest,
        expected_probe_digest=expected_probe_digest,
        expected_verifier_digest=expected_verifier_digest,
        expected_shared_probe_digest=expected_shared_probe_digest,
        expected_shared_verifier_digest=expected_shared_verifier_digest,
    )
    result = {
        "schema": contract.SCHEMA,
        "authority": contract.AUTHORITY,
        "case_id": contract.CASE_ID,
        "status": "REFUSED",
        "fixture_container": expected_container,
        "gateway_pid": expected_gateway_pid,
        "admitted_digest": expected_admitted_digest,
        "source_pins": {
            contract.PROBE: expected_probe_digest,
            contract.VERIFIER: expected_verifier_digest,
        },
        "shared_source_pins": {
            contract.shared.PROBE: expected_shared_probe_digest,
            contract.shared.VERIFIER: expected_shared_verifier_digest,
        },
        "before": None,
        "after": None,
        "sources_before": {},
        "sources_after": {},
        "parents_before": {},
        "parents_after": {},
        "candidates_before": {},
        "creation_attempts": [],
        "candidates_ready": {},
        "candidates_after": {},
        "commands_before": [],
        "commands_after": [],
        "refusal": None,
        "postcondition_failures": [],
        "cleanup_failures": [],
        "limitations": list(contract.LIMITATIONS),
        **dict.fromkeys(contract.FALSE_FLAGS, False),
    }
    phase, interrupts = "PREREQUISITES", []

    def refused(error):
        result["status"] = "REFUSED"
        if not isinstance(error, Exception) and not interrupts:
            interrupts.append(error)
        if result["refusal"] is None:
            result["refusal"] = {
                "phase": phase,
                "reason": "FIXED_AUTO_DISCOVERY_REFUSED",
            }

    def boundary():
        return readers._boundary(expected_container, expected_gateway_pid)

    try:
        token = _guard(arguments)
        with ExitStack() as held:
            pidfd = os.pidfd_open(expected_gateway_pid, 0)
            held.callback(_close, pidfd, result["cleanup_failures"])
            poller = select.poll()
            poller.register(pidfd, select.POLLIN)

            def alive():
                contract.require(not poller.poll(0), "GATEWAY_EXITED")

            alive()
            phase = "BEFORE"
            result["before"] = boundary()
            contract.shared.validate_boundary(
                result["before"],
                container=expected_container,
                gateway_pid=expected_gateway_pid,
                admitted_pin=expected_admitted_digest,
                source_pins=result["shared_source_pins"],
            )
            for path in result["source_pins"]:
                result["sources_before"][path] = readers._file(path, held)
            contract.validate_sources(result["sources_before"], result["source_pins"])
            parents = {
                path: readers._open(path, held, directory=True)
                for path in contract.PARENTS
            }
            for path, fd in parents.items():
                result["parents_before"][path] = _parent(fd, path)
            for path in contract.CANDIDATES:
                result["candidates_before"][path] = _absent(
                    parents[str(Path(path).parent)], path
                )
                contract.require(
                    result["candidates_before"][path]["exists"] is False,
                    "CANDIDATE_NOT_FRESH",
                )
            try:
                phase = "CATALOG_BEFORE"
                for kind, args in contract.shared.COMMANDS:
                    result["commands_before"].append(
                        readers._command(kind, args, token)
                    )
                contract.validate_commands(
                    result["commands_before"], expected_gateway_pid
                )
                alive()
                contract.require(
                    boundary() == result["before"], "PRE_CREATION_BOUNDARY_CHANGED"
                )
                phase = "CANDIDATE_CREATION"
                for path in contract.CANDIDATES:
                    alive()
                    row = {
                        "path": path,
                        "directory_created": False,
                        "file_created": False,
                        "bytes_written": 0,
                        "completed": False,
                        "directory_identity": None,
                        "file_identity": None,
                    }
                    result["creation_attempts"].append(row)
                    parent_path = str(Path(path).parent)
                    _create(
                        parents[parent_path],
                        path,
                        result["parents_before"][parent_path],
                        row,
                        result["cleanup_failures"],
                    )
                phase = "CANDIDATE_READY"
                for path in contract.CANDIDATES:
                    result["candidates_ready"][path] = _candidate(path)
                    contract.validate_candidate(result["candidates_ready"][path], path)
            except BaseException as error:
                refused(error)
            finally:
                # Each source/fixture/catalog read is independent and once-only.
                phase = "POSTCONDITIONS"
                for kind, args in contract.shared.COMMANDS:
                    try:
                        result["commands_after"].append(
                            readers._command(kind, args, token)
                        )
                    except BaseException as error:
                        refused(error)
                        result["postcondition_failures"].append("COMMAND_AFTER_" + kind)
                for path in contract.CANDIDATES:
                    try:
                        result["candidates_after"][path] = _candidate(path)
                    except BaseException as error:
                        refused(error)
                        result["postcondition_failures"].append(
                            "CANDIDATE_AFTER_" + contract.CANDIDATES[path]
                        )
                for path in result["source_pins"]:
                    try:
                        with ExitStack() as read_held:
                            result["sources_after"][path] = readers._file(
                                path, read_held
                            )
                    except BaseException as error:
                        refused(error)
                        result["postcondition_failures"].append(
                            "SOURCE_AFTER_"
                            + ("PROBE" if path == contract.PROBE else "VERIFIER")
                        )
                for path, fd in parents.items():
                    try:
                        result["parents_after"][path] = _parent(fd, path)
                    except BaseException as error:
                        refused(error)
                        result["postcondition_failures"].append(
                            "PARENT_AFTER_"
                            + ("WORKSPACE" if path == contract.WORKSPACE else "TMP")
                        )
                try:
                    result["after"] = boundary()
                except BaseException as error:
                    refused(error)
                    result["postcondition_failures"].append("SHARED_BOUNDARY_AFTER")
                try:
                    alive()
                except BaseException as error:
                    refused(error)
                    result["postcondition_failures"].append("GATEWAY_LIVENESS_AFTER")
        if result["refusal"] is None and not result["cleanup_failures"]:
            phase = "SEMANTIC_REPLAY"
            result["status"] = "OBSERVED"
            raw = canonical_json(result)
            contract.verify_native_admission_auto_discovery(
                raw, expected_raw_digest=contract.digest(raw), **arguments
            )
    except BaseException as error:
        refused(error)
    if interrupts:
        interrupts[0]._native_auto_discovery_observation = result
        raise interrupts[0]
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--container", required=True)
    parser.add_argument("--gateway-pid", type=int, required=True)
    for name in ("admitted", "probe", "verifier", "shared-probe", "shared-verifier"):
        parser.add_argument("--" + name + "-digest", required=True)
    args = parser.parse_args(argv)
    interrupted = False
    try:
        result = run_auto_discovery_probe(
            **{"expected_" + name: item for name, item in vars(args).items()}
        )
    except BaseException as error:
        result = getattr(error, "_native_auto_discovery_observation", None)
        if result is None:
            raise
        interrupted = True
    raw = canonical_json(result)
    contract.require(len(raw) <= contract.MAX_RECORD, "OUTPUT_BOUND_EXCEEDED")
    sys.stdout.buffer.write(raw + b"\n")
    return 130 if interrupted else (0 if result["status"] == "OBSERVED" else 126)


if __name__ == "__main__":
    raise SystemExit(main())
