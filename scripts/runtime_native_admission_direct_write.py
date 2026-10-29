"""One fixed native direct-write leaf, invoked by an owned fixture controller.

No VM, provisioning, activation, retry or cleanup is performed here. The root
controller must enter the verified gateway mount namespace, then drop to 992
with no capabilities before this command. The leaf refuses unsealed roots.
Unexpected successful mutations are retained, not undone or retried; the outer
controller must stop and destroy its exact disposable fixture on every outcome.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import re
import select
import selectors
import signal
import stat
import subprocess
import sys
import time

if not __package__:
    sys.path.insert(0, "/usr/lib/aragorn")

from aragorn import native_phase3_admission_direct_write as contract
from aragorn.oci_worker_protocol import canonical_json

_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_uid",
    "st_gid",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)
_ROOT = "/var/lib/aragorn-agent-gateway"


def _identity(value):
    return [getattr(value, field) for field in _FIELDS]


def _open(path: str, stack: ExitStack, *, directory: bool = False) -> int:
    """Hold every nofollow ancestor; no caller-selected write path is accepted."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open("/", flags | os.O_DIRECTORY)
    stack.callback(os.close, fd)
    parts = Path(path).parts[1:]
    for index, part in enumerate(parts):
        fd = os.open(
            part,
            flags | (os.O_DIRECTORY if index < len(parts) - 1 or directory else 0),
            dir_fd=fd,
        )
        stack.callback(os.close, fd)
    return fd


def _file(path: str, stack: ExitStack) -> dict:
    fd = _open(path, stack)
    before = os.fstat(fd)
    contract.require(
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1
        and 0 <= before.st_size <= 1048576,
        "FILE_CUSTODY_REFUSED",
    )
    raw = b""
    while len(raw) <= 1048576:
        piece = os.read(fd, min(65536, 1048577 - len(raw)))
        if not piece:
            break
        raw += piece
    contract.require(
        len(raw) == before.st_size
        and _identity(before)
        == _identity(os.fstat(fd))
        == _identity(os.stat(path, follow_symlinks=False)),
        "FILE_CHANGED_DURING_READ",
    )
    return {
        "identity": _identity(before),
        "bytes": len(raw),
        "digest": contract.digest(raw),
        "read_only": bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY),
    }


def _read_proc(path: str, limit: int = 65536) -> bytes:
    with open(path, "rb") as stream:
        raw = stream.read(limit + 1)
    contract.require(len(raw) <= limit, "PROC_READ_BOUND_EXCEEDED")
    return raw


def _status(pid: str) -> dict:
    return dict(
        row.split(":", 1)
        for row in _read_proc(f"/proc/{pid}/status").decode("ascii").splitlines()
        if ":" in row
    )


def _gateway(container: str, pid: int) -> dict:
    status = _status(str(pid))
    raw_stat = _read_proc(f"/proc/{pid}/stat").decode("ascii")
    end = raw_stat.rfind(")")
    fields = raw_stat[end + 2 :].split()
    contract.require(
        end > 0
        and len(fields) >= 20
        and [part for part in _read_proc(f"/proc/{pid}/cmdline").split(b"\x00") if part]
        == [b"openclaw-gateway"],
        "GATEWAY_PROCESS_REFUSED",
    )
    namespace = os.stat(f"/proc/{pid}/ns/mnt").st_ino
    contract.require(
        namespace == os.stat("/proc/self/ns/mnt").st_ino,
        "GATEWAY_MOUNT_NAMESPACE_MISMATCH",
    )
    result = {
        "pid": pid,
        "start_time_ticks": int(fields[19]),
        "cgroup": _read_proc(f"/proc/{pid}/cgroup").decode("ascii"),
        "mount_namespace": namespace,
        "effective_capabilities": status.get("CapEff", "").strip(),
        "no_new_privileges": status.get("NoNewPrivs", "").strip(),
        "uid": [int(item) for item in status.get("Uid", "").split()],
        "gid": [int(item) for item in status.get("Gid", "").split()],
    }
    contract.require(
        result["cgroup"]
        == f"0::/docker/{container}/system.slice/aragorn-agent-gateway.service\n",
        "GATEWAY_CONTAINER_MISMATCH",
    )
    return result


def _tree(path: str, stack: ExitStack) -> dict:
    root_fd = _open(path, stack, directory=True)
    before = os.fstat(root_fd)
    entries, total_bytes = [], 0

    def walk(fd: int, prefix: str = "", depth: int = 0):
        nonlocal total_bytes
        contract.require(depth <= 8, "TREE_DEPTH_EXCEEDED")
        names = sorted(os.listdir(fd))
        for name in names:
            contract.require(len(entries) < 512, "TREE_INVENTORY_EXCEEDED")
            relative = prefix + name
            metadata = os.stat(name, dir_fd=fd, follow_symlinks=False)
            directory = stat.S_ISDIR(metadata.st_mode)
            contract.require(
                directory or stat.S_ISREG(metadata.st_mode),
                "TREE_SPECIAL_ENTRY_REFUSED",
            )
            child = os.open(
                name,
                os.O_RDONLY
                | os.O_NOFOLLOW
                | os.O_CLOEXEC
                | os.O_NONBLOCK
                | (os.O_DIRECTORY if directory else 0),
                dir_fd=fd,
            )
            try:
                contract.require(
                    _identity(metadata) == _identity(os.fstat(child)),
                    "TREE_ENTRY_REPLACED",
                )
                record = {
                    "path": relative,
                    "kind": "directory" if directory else "file",
                    "identity": _identity(metadata),
                    "bytes": None,
                    "digest": None,
                }
                entries.append(record)
                if directory:
                    walk(child, relative + "/", depth + 1)
                else:
                    contract.require(
                        metadata.st_nlink == 1 and metadata.st_size <= 1048576,
                        "TREE_FILE_REFUSED",
                    )
                    raw = b""
                    while len(raw) <= 1048576:
                        piece = os.read(child, min(65536, 1048577 - len(raw)))
                        if not piece:
                            break
                        raw += piece
                    total_bytes += len(raw)
                    contract.require(
                        len(raw) == metadata.st_size and total_bytes <= 8388608,
                        "TREE_BYTES_EXCEEDED",
                    )
                    record.update(bytes=len(raw), digest=contract.digest(raw))
                contract.require(
                    _identity(metadata)
                    == _identity(os.fstat(child))
                    == _identity(os.stat(name, dir_fd=fd, follow_symlinks=False)),
                    "TREE_CHANGED_DURING_READ",
                )
            finally:
                os.close(child)
        contract.require(sorted(os.listdir(fd)) == names, "TREE_NAMES_CHANGED")

    walk(root_fd)
    try:
        os.stat(contract.NAME, dir_fd=root_fd, follow_symlinks=False)
        absent = False
    except FileNotFoundError:
        absent = True
    contract.require(
        _identity(before)
        == _identity(os.fstat(root_fd))
        == _identity(os.stat(path, follow_symlinks=False)),
        "ROOT_CHANGED_DURING_READ",
    )
    return {
        "identity": _identity(before),
        "read_only": bool(os.fstatvfs(root_fd).f_flag & os.ST_RDONLY),
        "entries": sorted(entries, key=lambda item: item["path"]),
        "candidate_absent": absent,
    }


def _boundary(container: str, pid: int) -> dict:
    with ExitStack() as held:
        return {
            "gateway": _gateway(container, pid),
            "roots": {path: _tree(path, held) for path in contract.ROOTS},
            "admitted": _file(contract.ADMITTED, held),
            "sources": {
                path: _file(path, held) for path in (contract.PROBE, contract.VERIFIER)
            },
            "entry": _file(contract.ENTRY, held),
            "config": _file(contract.CONFIG, held),
        }


def _command(kind: str, args: tuple, token: str) -> dict:
    argv = ["/usr/local/bin/node", contract.ENTRY, *args]
    env = {
        "HOME": _ROOT + "/home",
        "OPENCLAW_STATE_DIR": _ROOT + "/state",
        "OPENCLAW_CONFIG_PATH": contract.CONFIG,
        "OPENCLAW_GATEWAY_TOKEN": token,
        "OPENCLAW_NO_RESPAWN": "1",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "TZ": "UTC",
        "NO_PROXY": "127.0.0.1,localhost",
    }
    process = subprocess.Popen(
        argv,
        cwd=_ROOT + "/workspace",
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    completed = False
    streams = {"stdout": b"", "stderr": b""}
    try:
        with selectors.DefaultSelector() as reader:
            reader.register(process.stdout, selectors.EVENT_READ, "stdout")
            reader.register(process.stderr, selectors.EVENT_READ, "stderr")
            deadline = time.monotonic() + 15
            while reader.get_map():
                remaining = deadline - time.monotonic()
                contract.require(remaining > 0, "COMMAND_DEADLINE_EXCEEDED")
                for key, _ in reader.select(min(remaining, 0.25)):
                    raw = os.read(key.fileobj.fileno(), 65536)
                    if not raw:
                        reader.unregister(key.fileobj)
                    else:
                        streams[key.data] += raw
                        contract.require(
                            len(streams[key.data]) <= contract.MAX_COMMAND,
                            "COMMAND_OUTPUT_EXCEEDED",
                        )
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            completed = True
    finally:
        if not completed:
            # This owned unreaped leader's process group only; never retry an effect.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()
    raw = streams["stdout"]
    contract.require(
        code == 0
        and not streams["stderr"]
        and raw
        and token.encode("ascii") not in raw,
        "COMMAND_REFUSED",
    )
    return {
        "kind": kind,
        "argv": argv,
        "exit_code": code,
        "stdout": raw.decode("utf-8"),
        "stdout_bytes": len(raw),
        "stdout_digest": contract.digest(raw),
        "stderr_bytes": 0,
    }


def _attempt(path: str, *, create: bool) -> dict:
    result = {
        "operation": "create-skill" if create else "overwrite-admitted",
        "path": path,
        "completed": False,
        "errno": None,
        "created_directory": False,
        "bytes_written": 0,
        "payload_digest": contract.digest(contract.PAYLOAD),
    }
    try:
        with ExitStack() as held:
            parent = _open(str(Path(path).parent), held, directory=True)
            name = Path(path).name
            if create:
                os.mkdir(name, mode=0o700, dir_fd=parent)
                result["created_directory"] = True
                parent = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=parent,
                )
                held.callback(os.close, parent)
                name = "SKILL.md"
            fd = os.open(
                name,
                os.O_WRONLY
                | os.O_NOFOLLOW
                | os.O_CLOEXEC
                | os.O_NONBLOCK
                | (os.O_CREAT | os.O_EXCL if create else os.O_TRUNC),
                0o600,
                dir_fd=parent,
            )
            held.callback(os.close, fd)
            result["bytes_written"] = os.write(fd, contract.PAYLOAD)
            result["completed"] = result["bytes_written"] == len(contract.PAYLOAD)
    except OSError as error:
        result["errno"] = error.errno
    return result


def run_direct_write_probe(
    *,
    expected_container: str,
    expected_gateway_pid: int,
    expected_admitted_digest: str,
    expected_probe_digest: str,
    expected_verifier_digest: str,
) -> dict:
    """Attempt exactly this case; failures preserve observations, never clean up writes."""
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
        "before": None,
        "after": None,
        "commands_before": [],
        "commands_after": [],
        "attempts": [],
        "refusal": None,
        "limitations": list(contract.LIMITATIONS),
        **dict.fromkeys(contract.FALSE_FLAGS, False),
    }
    phase = "PREREQUISITES"
    try:
        contract.require(
            sys.platform == "linux"
            and os.getresuid() == (992, 992, 992)
            and os.getresgid() == (992, 992, 992)
            and os.getgroups() == [992],
            "FIXED_NONROOT_IDENTITY_REQUIRED",
        )
        contract.require(
            type(expected_container) is str
            and re.fullmatch(r"[0-9a-f]{64}", expected_container) is not None
            and type(expected_gateway_pid) is int
            and expected_gateway_pid > 1,
            "INVALID_OWNED_CALLER",
        )
        for expected in (
            expected_admitted_digest,
            expected_probe_digest,
            expected_verifier_digest,
        ):
            contract.pin(expected)
        contract.require(
            str(Path(__file__)) == contract.PROBE
            and str(Path(contract.__file__)) == contract.VERIFIER,
            "FIXED_SOURCE_LOCATION_REQUIRED",
        )
        own = _status("self")
        contract.require(
            all(
                own.get(key, "").strip() == "0000000000000000"
                for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
            )
            and own.get("NoNewPrivs", "").strip() == "1",
            "PRIVILEGE_DROP_REQUIRED",
        )
        cgroup = _read_proc("/proc/self/cgroup").decode("ascii")
        contract.require(
            re.fullmatch(
                r"0::/docker/" + expected_container + r"(?:/[^\n]*)?\n", cgroup
            )
            is not None,
            "OWNED_CONTAINER_MISMATCH",
        )
        token = os.environ.get("OPENCLAW_GATEWAY_TOKEN", "")
        contract.require(
            re.fullmatch(r"[0-9a-f]{64}", token) is not None, "FIXTURE_TOKEN_REQUIRED"
        )
        with ExitStack() as held:
            pidfd = os.pidfd_open(expected_gateway_pid, 0)
            held.callback(os.close, pidfd)
            poller = select.poll()
            poller.register(pidfd, select.POLLIN)

            def alive():
                contract.require(not poller.poll(0), "GATEWAY_EXITED")

            alive()
            phase = "BEFORE"
            result["before"] = _boundary(expected_container, expected_gateway_pid)
            contract.validate_boundary(
                result["before"],
                container=expected_container,
                gateway_pid=expected_gateway_pid,
                admitted_pin=expected_admitted_digest,
                source_pins=result["source_pins"],
            )
            for kind, args in contract.COMMANDS:
                result["commands_before"].append(_command(kind, args, token))
            contract._commands(result["commands_before"], expected_gateway_pid)
            alive()
            contract.require(
                _boundary(expected_container, expected_gateway_pid) == result["before"],
                "PRE_MUTATION_BOUNDARY_CHANGED",
            )
            phase = "MUTATION"
            for root in contract.ROOTS:
                alive()
                outcome = _attempt(root + "/" + contract.NAME, create=True)
                result["attempts"].append(outcome)
                if (
                    outcome["created_directory"]
                    or outcome["completed"]
                    or outcome["errno"] not in {errno.EPERM, errno.EACCES, errno.EROFS}
                ):
                    break
            if len(result["attempts"]) == 6 and all(
                item["errno"] in {errno.EPERM, errno.EACCES, errno.EROFS}
                and not item["created_directory"]
                for item in result["attempts"]
            ):
                alive()
                result["attempts"].append(_attempt(contract.ADMITTED, create=False))
            phase = "AFTER"
            alive()
            result["after"] = _boundary(expected_container, expected_gateway_pid)
            for kind, args in contract.COMMANDS:
                result["commands_after"].append(_command(kind, args, token))
            alive()
            contract.require(
                _boundary(expected_container, expected_gateway_pid) == result["after"],
                "POST_MUTATION_BOUNDARY_CHANGED",
            )
        phase = "SEMANTIC_REPLAY"
        result["status"] = "OBSERVED"
        raw = canonical_json(result)
        contract.verify_native_admission_direct_write(
            raw,
            expected_raw_digest=contract.digest(raw),
            expected_container=expected_container,
            expected_gateway_pid=expected_gateway_pid,
            expected_admitted_digest=expected_admitted_digest,
            expected_probe_digest=expected_probe_digest,
            expected_verifier_digest=expected_verifier_digest,
        )
    except Exception as error:
        result["status"] = "REFUSED"
        result["refusal"] = {
            "phase": phase,
            "reason": str(error)
            if type(error) is contract.NativeDirectWriteError
            else "FIXED_LEAF_REFUSED",
        }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--gateway-pid", type=int, required=True)
    parser.add_argument("--admitted-digest", required=True)
    parser.add_argument("--probe-digest", required=True)
    parser.add_argument("--verifier-digest", required=True)
    args = parser.parse_args(argv)
    result = run_direct_write_probe(
        expected_container=args.container,
        expected_gateway_pid=args.gateway_pid,
        expected_admitted_digest=args.admitted_digest,
        expected_probe_digest=args.probe_digest,
        expected_verifier_digest=args.verifier_digest,
    )
    sys.stdout.buffer.write(canonical_json(result) + b"\n")
    return 0 if result["status"] == "OBSERVED" else 126


if __name__ == "__main__":
    raise SystemExit(main())
