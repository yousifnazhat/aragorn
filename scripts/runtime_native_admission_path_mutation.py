"""Two fixed native leaves; no activation, retries, undo or fixture cleanup.

The owned controller enters the pinned gateway mount namespace and drops all
privileges to 992. Scratch and unexpected effects remain for fixture destruction.
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
    # Python -I omits the script directory; both import roots are fixed by the
    # owned controller and the four installed source pins checked below.
    sys.path[:0] = ["/usr/lib/aragorn", "/opt/aragorn"]
    import runtime_native_admission_direct_write as readers

from aragorn import native_phase3_admission_path_mutation as contract
from aragorn.oci_worker_protocol import canonical_json


def _entry(parent, name, path):
    try:
        metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return {"path": path, "exists": False, "identity": None, "link_target": None}
    target = (
        os.readlink(name, dir_fd=parent) if stat.S_ISLNK(metadata.st_mode) else None
    )
    contract.require(
        readers._identity(metadata)
        == readers._identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
        "ENTRY_CHANGED_DURING_READ",
    )
    return {
        "path": path,
        "exists": True,
        "identity": readers._identity(metadata),
        "link_target": target,
    }


def _destinations(case_id):
    result = {}
    with ExitStack() as held:
        for operation in contract.operations(case_id):
            path = operation["destination"]
            parent = readers._open(str(Path(path).parent), held, directory=True)
            result[path] = _entry(parent, Path(path).name, path)
    return result


def _retargets(case_id):
    result = {}
    with ExitStack() as held:
        for path in contract.RETARGET_ROOTS if case_id == contract.CASES[0] else ():
            fd = readers._open(path, held, directory=True)
            identity = readers._identity(os.fstat(fd))
            contract.require(
                identity == readers._identity(os.stat(path, follow_symlinks=False)),
                "RETARGET_REPLACED",
            )
            result[path] = {
                "path": path,
                "identity": identity,
                "read_only": bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY),
            }
    return result


def _sources():
    with ExitStack() as held:
        return {
            path: readers._file(path, held)
            for path in (contract.PROBE, contract.VERIFIER)
        }


def _scratch(case_id):
    with ExitStack() as held:
        return readers._tree(contract.SCRATCH[case_id], held)


def _prepare_scratch(case_id, record):
    """Exclusive, fixed 992-owned source creation; never repair existing state."""
    raw = contract.payload(case_id)
    root = contract.SCRATCH[case_id]
    with ExitStack() as held:
        workspace = readers._open(contract.WORKSPACE, held, directory=True)
        info = os.fstat(workspace)
        contract.require(
            stat.S_IMODE(info.st_mode) == 0o700
            and (info.st_uid, info.st_gid) == (992, 992)
            and not os.fstatvfs(workspace).f_flag & os.ST_RDONLY,
            "WRITABLE_OWNED_WORKSPACE_REQUIRED",
        )
        name = Path(root).name
        contract.require(
            _entry(workspace, name, root)["exists"] is False, "SCRATCH_NOT_FRESH"
        )
        os.mkdir(name, mode=0o700, dir_fd=workspace)
        record["created"].append(
            {"path": root, "kind": "directory", "bytes_written": 0}
        )
        root_fd = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=workspace,
        )
        held.callback(os.close, root_fd)
        for source in contract.sources(case_id):
            child = Path(source).name
            os.mkdir(child, mode=0o700, dir_fd=root_fd)
            record["created"].append(
                {"path": source, "kind": "directory", "bytes_written": 0}
            )
            child_fd = os.open(
                child,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
            held.callback(os.close, child_fd)
            fd = os.open(
                "SKILL.md",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=child_fd,
            )
            held.callback(os.close, fd)
            item = {"path": source + "/SKILL.md", "kind": "file", "bytes_written": 0}
            record["created"].append(item)
            item["bytes_written"] = os.write(fd, raw)
            contract.require(
                item["bytes_written"] == len(raw), "SCRATCH_WRITE_INCOMPLETE"
            )
            os.fsync(fd)
    record["completed"] = True


def _attempt(operation, expected_source, expected_destination):
    """One syscall; retain its result even if either subsequent readback fails."""
    result = {
        **operation,
        "attempted": False,
        "completed": False,
        "errno": None,
        "outcome": "UNEXPECTED_ERROR",
        "source_before": None,
        "source_after": None,
        "destination_before": None,
        "destination_after": None,
        "readback_failures": [],
    }
    with ExitStack() as held:
        source, destination = operation["source"], operation["destination"]
        try:
            source_parent = readers._open(
                str(Path(source).parent), held, directory=True
            )
            destination_parent = readers._open(
                str(Path(destination).parent), held, directory=True
            )
            result["source_before"] = _entry(source_parent, Path(source).name, source)
            result["destination_before"] = _entry(
                destination_parent, Path(destination).name, destination
            )
            contract.require(
                result["source_before"] == expected_source
                and result["destination_before"] == expected_destination
                and expected_source["exists"] is True
                and expected_destination["exists"] is False,
                "OPERAND_CHANGED_BEFORE_MUTATION",
            )
        except Exception:
            result["readback_failures"].append("PRE_MUTATION_OPERANDS")
            return result
        result["attempted"] = True
        try:
            if operation["operation"] == "symlink-into-root":
                os.symlink(source, Path(destination).name, dir_fd=destination_parent)
            else:
                os.rename(
                    Path(source).name,
                    Path(destination).name,
                    src_dir_fd=source_parent,
                    dst_dir_fd=destination_parent,
                )
            result["completed"] = True
        except OSError as error:
            result["errno"] = error.errno
        except Exception:
            result["readback_failures"].append("SYSCALL_REFUSED")
        result["outcome"] = contract.outcome(
            operation["operation"], result["completed"], result["errno"]
        )
        for name, parent, path in (
            ("source_after", source_parent, source),
            ("destination_after", destination_parent, destination),
        ):
            try:
                result[name] = _entry(parent, Path(path).name, path)
            except Exception:
                result["readback_failures"].append(name)
    return result


def _guard(arguments):
    contract.require(
        sys.platform == "linux"
        and os.getresuid() == (992, 992, 992)
        and os.getresgid() == (992, 992, 992)
        and os.getgroups() == [992],
        "FIXED_NONROOT_IDENTITY_REQUIRED",
    )
    case_id, container, pid = (
        arguments["expected_case_id"],
        arguments["expected_container"],
        arguments["expected_gateway_pid"],
    )
    contract.require(
        case_id in contract.CASES
        and type(container) is str
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
    cgroup = readers._read_proc("/proc/self/cgroup").decode("ascii")
    contract.require(
        re.fullmatch(r"0::/docker/" + container + r"(?:/[^\n]*)?\n", cgroup)
        is not None,
        "OWNED_CONTAINER_MISMATCH",
    )
    token = os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")
    contract.require(
        re.fullmatch(r"[0-9a-f]{64}", token) is not None, "FIXTURE_TOKEN_REQUIRED"
    )
    return token


def run_path_mutation_probe(
    *,
    expected_case_id,
    expected_container,
    expected_gateway_pid,
    expected_admitted_digest,
    expected_probe_digest,
    expected_verifier_digest,
    expected_shared_probe_digest,
    expected_shared_verifier_digest,
):
    arguments = dict(
        expected_case_id=expected_case_id,
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
        "case_id": expected_case_id,
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
        "commands_before": [],
        "commands_after": [],
        "scratch_preparation": {
            "root": contract.SCRATCH.get(expected_case_id),
            "created": [],
            "completed": False,
        },
        "mutation_before": {},
        "mutation_after": {},
        "attempts": [],
        "postcondition_failures": [],
        "refusal": None,
        "limitations": list(contract.LIMITATIONS),
        **dict.fromkeys(contract.FALSE_FLAGS, False),
    }
    phase, original = "PREREQUISITES", None
    try:
        token = _guard(arguments)
        case_id = expected_case_id
        with ExitStack() as held:
            pidfd = os.pidfd_open(expected_gateway_pid, 0)
            held.callback(os.close, pidfd)
            poller = select.poll()
            poller.register(pidfd, select.POLLIN)

            def alive():
                contract.require(not poller.poll(0), "GATEWAY_EXITED")

            def shared_boundary():
                return readers._boundary(expected_container, expected_gateway_pid)

            def validate_shared(value):
                contract.shared.validate_boundary(
                    value,
                    container=expected_container,
                    gateway_pid=expected_gateway_pid,
                    admitted_pin=expected_admitted_digest,
                    source_pins=result["shared_source_pins"],
                )

            alive()
            phase = "BEFORE"
            result["before"] = shared_boundary()
            validate_shared(result["before"])
            own_sources = _sources()
            for path, record in own_sources.items():
                contract.shared._file(record, result["source_pins"][path])
                metadata = record["identity"]
                contract.require(
                    metadata[3:6] == [0, 0, 1] and metadata[2] & 0o022 == 0,
                    "ADAPTER_SOURCE_CUSTODY_CHANGED",
                )
            # Only after fixture, PIDFD, namespace and all four source pins pass
            # may this leaf create its exact source fixture.
            try:
                phase = "SCRATCH_PREPARATION"
                _prepare_scratch(case_id, result["scratch_preparation"])
                phase = "PRE_MUTATION_READBACKS"
                result["mutation_before"] = {
                    "scratch": _scratch(case_id),
                    "destinations": _destinations(case_id),
                    "retargets": _retargets(case_id),
                    "adapter_sources": _sources(),
                }
                contract.validate_mutation_boundary(
                    result["mutation_before"],
                    case_id=case_id,
                    source_pins=result["source_pins"],
                )
                for kind, args in contract.shared.COMMANDS:
                    result["commands_before"].append(
                        readers._command(kind, args, token)
                    )
                contract.validate_commands(
                    result["commands_before"],
                    case_id=case_id,
                    gateway_pid=expected_gateway_pid,
                )
                alive()
                contract.require(
                    shared_boundary() == result["before"],
                    "PRE_MUTATION_BOUNDARY_CHANGED",
                )
                phase = "MUTATION"
                for operation in contract.operations(case_id):
                    alive()
                    attempt = _attempt(
                        operation,
                        contract.source_entry(
                            result["mutation_before"], case_id, operation["source"]
                        ),
                        result["mutation_before"]["destinations"][
                            operation["destination"]
                        ],
                    )
                    result["attempts"].append(attempt)
                    if (
                        attempt["outcome"] in ("UNEXPECTED_SUCCESS", "UNEXPECTED_ERROR")
                        or attempt["readback_failures"]
                        or attempt["source_after"] != attempt["source_before"]
                        or attempt["destination_after"] != attempt["destination_before"]
                    ):
                        break
            except Exception as error:
                original = {
                    "phase": phase,
                    "reason": str(error)
                    if type(error) is contract.NativePathMutationError
                    else "FIXED_PATH_MUTATION_REFUSED",
                }
            finally:
                # Independent once-only reads retain whatever remains observable.
                for name, observe in (
                    ("scratch", lambda: _scratch(case_id)),
                    ("destinations", lambda: _destinations(case_id)),
                    ("retargets", lambda: _retargets(case_id)),
                    ("adapter_sources", _sources),
                ):
                    try:
                        result["mutation_after"][name] = observe()
                    except Exception:
                        result["postcondition_failures"].append(
                            "MUTATION_" + name.upper()
                        )
                try:
                    result["after"] = shared_boundary()
                except Exception:
                    result["postcondition_failures"].append("SHARED_BOUNDARY")
                for kind, args in contract.shared.COMMANDS:
                    try:
                        result["commands_after"].append(
                            readers._command(kind, args, token)
                        )
                    except Exception:
                        result["postcondition_failures"].append("COMMAND_" + kind)
                try:
                    alive()
                except Exception:
                    result["postcondition_failures"].append("GATEWAY_LIVENESS")
        if original is not None:
            result["refusal"] = original
            return result
        phase = "SEMANTIC_REPLAY"
        result["status"] = "OBSERVED"
        raw = canonical_json(result)
        contract.verify_native_admission_path_mutation(
            raw, expected_raw_digest=contract.digest(raw), **arguments
        )
    except Exception as error:
        result["status"] = "REFUSED"
        result["refusal"] = {
            "phase": phase,
            "reason": str(error)
            if type(error) is contract.NativePathMutationError
            else "FIXED_PATH_MUTATION_REFUSED",
        }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--case-id", choices=contract.CASES, required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--gateway-pid", type=int, required=True)
    for name in ("admitted", "probe", "verifier", "shared-probe", "shared-verifier"):
        parser.add_argument("--" + name + "-digest", required=True)
    args = parser.parse_args(argv)
    value = run_path_mutation_probe(
        **{"expected_" + name: item for name, item in vars(args).items()}
    )
    sys.stdout.buffer.write(canonical_json(value) + b"\n")
    return 0 if value["status"] == "OBSERVED" else 126


if __name__ == "__main__":
    raise SystemExit(main())
