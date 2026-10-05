"""Local explicit-input verification cache; never acceptance or qualification.

Only reviewed offline unittest modules from the fixed repository registry run.
Test code is trusted, not sandboxed. Inputs are explicit: this runner does not
discover or attest a complete Python/native/environment dependency closure.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import select
import selectors
import signal
import stat
import subprocess
import sys
import sysconfig
import time
from pathlib import Path

REGISTRY = "benchmark/phase3-pipeline-v1.json"
RUNNER = "scripts/phase3_pipeline.py"
_LIMIT = 32 * 1024 * 1024
_LOG_LIMIT = 4 * 1024 * 1024
_PREFLIGHT_CODE = "import time; time.sleep(1)"
_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_LIMITATIONS = [
    "DEVELOPER_SCHEDULING_CACHE_NOT_QUALIFICATION",
    "EXPLICIT_INPUTS_ONLY_NOT_COMPLETE_DEPENDENCY_DISCOVERY",
    "TRUSTED_REGISTERED_TESTS_NOT_A_SANDBOX",
    "NO_LIVE_CAPTURE_OR_FINAL_ACCEPTANCE_AUTOMATION",
]


class PipelineError(RuntimeError):
    """Unsafe inputs or unresolved prior work prohibit execution."""


def _require(value, message):
    if not value:
        raise PipelineError(message)


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pairs(pairs):
    result = dict(pairs)
    _require(len(result) == len(pairs), "duplicate JSON key")
    return result


def _parse(raw, *, canonical=False):
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
        _require(not canonical or _canonical(value) == raw, "noncanonical local state")
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise PipelineError("invalid JSON") from exc


def _relative(path):
    _require(type(path) is str and 0 < len(path) <= 1024, "invalid input path")
    pieces = path.split("/")
    _require(
        all(part not in ("", ".", "..") for part in pieces), "non-relative input path"
    )
    _require(
        not path.startswith((".git/", ".aragorn/")),
        "state is not a declared source input",
    )
    return pieces


def _identity(info):
    return tuple(
        getattr(info, key)
        for key in (
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
    )


def _read_at(parent, name, *, private=False, limit=_LIMIT):
    fd = os.open(name, _FLAGS | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = os.fstat(fd)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and 0 <= before.st_size <= limit,
            "input is not a bounded single-link regular file",
        )
        if private:
            _require(
                before.st_uid == os.geteuid() and stat.S_IMODE(before.st_mode) == 0o400,
                "unsafe immutable state file",
            )
        chunks = []
        size = 0
        while chunk := os.read(fd, min(65536, limit + 1 - size)):
            chunks.append(chunk)
            size += len(chunk)
            _require(size <= limit, "input exceeded byte bound")
        _require(
            size == before.st_size
            and _identity(before)
            == _identity(os.fstat(fd))
            == _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
            "input changed while reading",
        )
        return b"".join(chunks)
    finally:
        os.close(fd)


def _read_repo(root, path):
    parts = _relative(path)
    held = [os.open(root, _FLAGS | os.O_DIRECTORY)]
    try:
        for part in parts[:-1]:
            held.append(os.open(part, _FLAGS | os.O_DIRECTORY, dir_fd=held[-1]))
        return _read_at(held[-1], parts[-1])
    finally:
        for fd in reversed(held):
            os.close(fd)


def load_registry(root):
    value = _parse(_read_repo(root, REGISTRY))
    _require(
        type(value) is dict
        and set(value) == {"schema", "stages"}
        and value["schema"] == "aragorn/phase3-pipeline/v1",
        "unknown registry contract",
    )
    stages = value["stages"]
    _require(type(stages) is list and 0 < len(stages) <= 64, "invalid stage inventory")
    index = {}
    for row in stages:
        _require(
            type(row) is dict
            and set(row)
            == {"id", "description", "tests", "inputs", "needs", "timeout_seconds"},
            "unknown stage fields",
        )
        name = row["id"]
        _require(
            type(name) is str
            and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name)
            and name not in index,
            "invalid/duplicate stage ID",
        )
        _require(
            type(row["description"]) is str and 0 < len(row["description"]) <= 1024,
            "invalid description",
        )
        for field in ("tests", "inputs", "needs"):
            items = row[field]
            _require(
                type(items) is list
                and len(items) <= 512
                and all(type(item) is str for item in items)
                and len(set(items)) == len(items),
                "invalid stage list",
            )
        _require(
            row["tests"]
            and row["inputs"]
            and all(re.fullmatch(r"test_[a-zA-Z0-9_]+", item) for item in row["tests"]),
            "explicit test module names required",
        )
        _require(
            all("tests/" + module + ".py" in row["inputs"] for module in row["tests"]),
            "test source must be a declared input",
        )
        for path in row["inputs"]:
            _relative(path)
            _read_repo(root, path)
        _require(
            type(row["timeout_seconds"]) is int and 1 <= row["timeout_seconds"] <= 1800,
            "invalid timeout",
        )
        index[name] = row
    ordered, visiting = [], set()

    def visit(name):
        _require(name in index, "unknown dependency")
        _require(name not in visiting, "dependency cycle")
        if name in ordered:
            return
        visiting.add(name)
        for dependency in index[name]["needs"]:
            visit(dependency)
        visiting.remove(name)
        ordered.append(name)

    for name in index:
        visit(name)
    return index, ordered


def _environment(root):
    return {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join(
            str(root / item) for item in ("src", ".", "tests")
        ),
    }


def fingerprint(root, stage, dependency_pins):
    executable = Path(sys.executable).resolve(strict=True)
    # -S excludes site packages. Standard-library/toolchain identity is recorded,
    # not claimed to be a complete attestation of every interpreter dependency.
    toolchain = {
        "executable": str(executable),
        "executable_digest": _digest(executable.read_bytes()),
        "version": sys.version,
        "cache_tag": sys.implementation.cache_tag,
        "stdlib": sysconfig.get_path("stdlib"),
        # os.uname is a direct system query. platform.uname lazily launches
        # an untracked `uname -p` child on macOS when its tuple is materialized.
        "platform": list(os.uname()),
    }
    argv = [str(executable), "-S", "-B", "-m", "unittest", *stage["tests"], "-v"]
    paths = sorted(set(stage["inputs"]) | {RUNNER, "requirements-worker.lock"})
    contract = {
        "stage_id": stage["id"],
        "argv": argv,
        "timeout_seconds": stage["timeout_seconds"],
        "inputs": {path: _digest(_read_repo(root, path)) for path in paths},
        "dependencies": {name: dependency_pins[name] for name in stage["needs"]},
        "toolchain": toolchain,
        "environment": _environment(root),
    }
    return _digest(_canonical(contract)), contract


def _directory(parent, name, *, create=False, private=True):
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
    fd = os.open(name, _FLAGS | os.O_DIRECTORY, dir_fd=parent)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & (
        0o077 if private else 0o022
    ):
        os.close(fd)
        raise PipelineError("unsafe local state directory")
    return fd


def _write_all(fd, raw):
    view = memoryview(raw)
    while view:
        count = os.write(fd, view)
        _require(count > 0, "short state write")
        view = view[count:]


def _publish(parent, name, value):
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=parent,
    )
    try:
        _write_all(fd, _canonical(value))
        os.fchmod(fd, 0o400)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent)


def _cached(fd, stage, pin):
    names = set(os.listdir(fd))
    _require(
        names
        <= {
            "preflight-started.json",
            "preflight.json",
            "started.json",
            "result.json",
            "stdout.log",
            "stderr.log",
        },
        "unknown attempt state",
    )
    if not names:
        return "NEW"
    _require("preflight-started.json" in names, "attempt lacks cleanup preflight")
    preflight_start = _read_at(fd, "preflight-started.json", private=True)
    _require(
        _parse(preflight_start, canonical=True)
        == {
            "schema": "aragorn/phase3-pipeline-preflight-start/v1",
            "stage_id": stage,
            "fingerprint": pin,
            "helper_argv": _preflight_argv(),
        },
        "invalid cleanup preflight identity",
    )
    if "preflight.json" not in names:
        return "BLOCKED_PREFLIGHT_INTERRUPTED"
    preflight = _parse(_read_at(fd, "preflight.json", private=True), canonical=True)
    _require(
        type(preflight) is dict
        and set(preflight) == {"schema", "start_digest", "status", "error"}
        and preflight["schema"] == "aragorn/phase3-pipeline-preflight-result/v1"
        and preflight["start_digest"] == _digest(preflight_start)
        and preflight["status"] in {"PASS", "REFUSED"}
        and (
            preflight["error"] is None
            if preflight["status"] == "PASS"
            else type(preflight["error"]) is str
        ),
        "invalid cleanup preflight result",
    )
    if preflight["status"] == "REFUSED":
        return "BLOCKED_PREFLIGHT"
    if "started.json" not in names:
        return "BLOCKED_PREFLIGHT_INTERRUPTED"
    _require("started.json" in names, "attempt state lacks started marker")
    started = _parse(_read_at(fd, "started.json", private=True), canonical=True)
    _require(
        type(started) is dict
        and set(started) == {"schema", "stage_id", "fingerprint", "started_at_ns"}
        and started["schema"] == "aragorn/phase3-pipeline-start/v1"
        and started["stage_id"] == stage
        and started["fingerprint"] == pin
        and type(started["started_at_ns"]) is int,
        "invalid started marker",
    )
    if "result.json" not in names:
        return "BLOCKED_INTERRUPTED"
    _require(
        names
        == {
            "preflight-started.json",
            "preflight.json",
            "started.json",
            "result.json",
            "stdout.log",
            "stderr.log",
        },
        "completed attempt lacks logs",
    )
    result = _parse(_read_at(fd, "result.json", private=True), canonical=True)
    _require(
        type(result) is dict
        and set(result)
        == {
            "schema",
            "stage_id",
            "fingerprint",
            "post_fingerprint",
            "status",
            "exit_code",
            "started_at_ns",
            "finished_at_ns",
            "logs",
            "limitations",
        },
        "invalid result keys",
    )
    _require(
        result["schema"] == "aragorn/phase3-pipeline-result/v1"
        and result["stage_id"] == stage
        and result["fingerprint"] == pin
        and result["started_at_ns"] == started["started_at_ns"]
        and type(result["finished_at_ns"]) is int
        and result["finished_at_ns"] >= started["started_at_ns"]
        and result["limitations"] == _LIMITATIONS
        and result["status"]
        in {
            "PASS",
            "FAIL",
            "TIMEOUT",
            "INTERRUPTED",
            "INPUT_CHANGED",
            "ERROR",
            "OUTPUT_LIMIT",
        },
        "invalid result identity/status",
    )
    _require(
        type(result["logs"]) is dict
        and set(result["logs"]) == {"stdout.log", "stderr.log"},
        "invalid log inventory",
    )
    for name, expected in result["logs"].items():
        raw = _read_at(fd, name, private=True, limit=_LOG_LIMIT)
        _require(
            expected == {"digest": _digest(raw), "bytes": len(raw)},
            "retained log changed",
        )
    if result["status"] == "PASS":
        _require(
            type(result["exit_code"]) is int
            and result["exit_code"] == 0
            and result["post_fingerprint"] == pin,
            "invalid PASS",
        )
        return "SKIP_PASS"
    return "BLOCKED_" + result["status"]


def _stop_group(process):
    # The caller has not polled/waited: the unreaped child pins its PID/PGID
    # while we clean up our own group, avoiding signals to a recycled PGID.
    denied = None
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            break
        except PermissionError as exc:
            # macOS can report EPERM for a zombie-only process group. Keep
            # the original error until bounded reaping and absence proof.
            denied = exc
            break
        if sig == signal.SIGTERM:
            time.sleep(0.1)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        if denied is not None:
            raise denied from exc
        raise
    # Never send a signal after reaping; PID/PGID reuse is now possible.
    # Signal 0 is read-only. Only ESRCH establishes that no group remains.
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return
    except OSError as exc:
        if denied is not None:
            raise denied from exc
        raise
    if denied is not None:
        raise denied
    raise PipelineError("owned process group still exists after cleanup")


def _preflight_argv():
    return [
        str(Path(sys.executable).resolve(strict=True)),
        "-S",
        "-B",
        "-c",
        _PREFLIGHT_CODE,
    ]


def _process_group_prerequisite(root, fd, stage, pin, contract):
    # A fixed one-second inert helper exercises real own-group cleanup. This
    # is only a prerequisite, not an attestation that future cleanup must work.
    start = {
        "schema": "aragorn/phase3-pipeline-preflight-start/v1",
        "stage_id": stage["id"],
        "fingerprint": pin,
        "helper_argv": _preflight_argv(),
    }
    _publish(fd, "preflight-started.json", start)
    child, failure = None, None
    try:
        child = subprocess.Popen(
            start["helper_argv"],
            cwd=root,
            env=contract["environment"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        # Do not swallow ESRCH here: an already-gone helper would not exercise
        # the needed permission. The unreaped child still pins its PID/PGID.
        os.killpg(child.pid, signal.SIGTERM)
        _stop_group(child)
    except (OSError, ValueError, PipelineError, subprocess.SubprocessError) as exc:
        failure = str(exc)
        if child is not None and child.returncode is None:
            # Cleanup of this single known inert child is not permission to
            # run product tests without process-group control.
            try:
                child.terminate()
            except OSError as cleanup:
                failure += "; direct helper termination: " + str(cleanup)
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    child.kill()
                    child.wait(timeout=2)
                except (OSError, subprocess.SubprocessError) as cleanup:
                    failure += "; helper cleanup: " + str(cleanup)
            except (OSError, subprocess.SubprocessError) as cleanup:
                failure += "; helper wait: " + str(cleanup)
    _publish(
        fd,
        "preflight.json",
        {
            "schema": "aragorn/phase3-pipeline-preflight-result/v1",
            "start_digest": _digest(_canonical(start)),
            "status": "PASS" if failure is None else "REFUSED",
            "error": failure,
        },
    )
    if failure is not None:
        raise PipelineError(
            "process-group control prerequisite refused before test launch: " + failure
        )


def _exit_watcher(process):
    if hasattr(os, "waitid"):
        return (
            lambda: (
                os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                is not None
            ),
            None,
        )
    _require(hasattr(select, "kqueue"), "non-reaping child observation unavailable")
    watcher = select.kqueue()
    try:
        watcher.control(
            [
                select.kevent(
                    process.pid,
                    filter=select.KQ_FILTER_PROC,
                    flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                    fflags=select.KQ_NOTE_EXIT,
                )
            ],
            0,
            0,
        )
    except ProcessLookupError:
        # Already exited but not reaped: PID reuse is still impossible.
        return lambda: True, watcher
    except Exception:
        watcher.close()
        raise
    ended = False

    def exited():
        nonlocal ended
        ended = ended or bool(watcher.control([], 1, 0))
        return ended

    return exited, watcher


def _execute(root, fd, stage, pin, contract, recheck):
    _process_group_prerequisite(root, fd, stage, pin, contract)
    started = time.time_ns()
    _publish(
        fd,
        "started.json",
        {
            "schema": "aragorn/phase3-pipeline-start/v1",
            "stage_id": stage["id"],
            "fingerprint": pin,
            "started_at_ns": started,
        },
    )
    logs, process, selector = {}, None, selectors.DefaultSelector()
    watcher = None
    status, exit_code, post = "ERROR", None, None
    try:
        for name in ("stdout.log", "stderr.log"):
            logs[name] = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=fd,
            )
        process = subprocess.Popen(
            contract["argv"],
            cwd=root,
            env=contract["environment"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        exited, watcher = _exit_watcher(process)
        for stream, name in (
            (process.stdout, "stdout.log"),
            (process.stderr, "stderr.log"),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        sizes = dict.fromkeys(logs, 0)
        deadline = time.monotonic() + stage["timeout_seconds"]
        status = "PASS"
        while selector.get_map() or not exited():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = "TIMEOUT"
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                raw = os.read(key.fileobj.fileno(), 65536)
                if not raw:
                    selector.unregister(key.fileobj)
                    continue
                available = _LOG_LIMIT - sizes[key.data]
                _write_all(logs[key.data], raw[:available])
                sizes[key.data] += min(available, len(raw))
                if len(raw) > available:
                    status = "OUTPUT_LIMIT"
                    break
            if status == "OUTPUT_LIMIT":
                break
    except (KeyboardInterrupt, InterruptedError):
        status = "INTERRUPTED"
    except (OSError, ValueError, PipelineError, subprocess.SubprocessError):
        status = "ERROR"
    finally:
        cleanup_error = None
        try:
            if process is not None:
                _stop_group(process)
                exit_code = process.returncode
                if status == "PASS" and exit_code != 0:
                    status = "FAIL"
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            cleanup_error = exc
        finally:
            try:
                if watcher is not None:
                    watcher.close()
                selector.close()
                if process is not None:
                    process.stdout.close()
                    process.stderr.close()
                for log_fd in logs.values():
                    os.fchmod(log_fd, 0o400)
                    os.fsync(log_fd)
                    os.close(log_fd)
                os.fsync(fd)
            except (OSError, ValueError) as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        if cleanup_error is not None:
            child = "none" if process is None else str(process.pid)
            raise PipelineError(
                "cleanup failed for owned child "
                + child
                + ": "
                + str(cleanup_error)
                + "; started record retained without a final result; no retry"
            ) from cleanup_error
    try:
        post = recheck()
    except (OSError, ValueError, KeyError, PipelineError):
        post = None
    if post != pin:
        status = "INPUT_CHANGED"
    _require(len(logs) == 2, "incomplete logs; started marker requires investigation")
    log_records = {}
    for name in logs:
        raw = _read_at(fd, name, private=True, limit=_LOG_LIMIT)
        log_records[name] = {"digest": _digest(raw), "bytes": len(raw)}
    _publish(
        fd,
        "result.json",
        {
            "schema": "aragorn/phase3-pipeline-result/v1",
            "stage_id": stage["id"],
            "fingerprint": pin,
            "post_fingerprint": post,
            "status": status,
            "exit_code": exit_code,
            "started_at_ns": started,
            "finished_at_ns": max(started, time.time_ns()),
            "logs": log_records,
            "limitations": _LIMITATIONS,
        },
    )
    return status


def pipeline(root: Path, *, run=False, selected=()):
    root = root.absolute()
    _require(root.resolve(strict=True) == root, "repository path must be direct")
    index, ordered = load_registry(root)
    wanted = set(selected) or set(index)
    _require(wanted <= set(index), "unknown selected stage")
    for name in reversed(ordered):
        if name in wanted:
            wanted.update(index[name]["needs"])
    _require(
        b".aragorn/" in _read_repo(root, ".gitignore").splitlines(),
        "local state must be ignored",
    )
    held, state, lock = [], None, None
    try:
        held.append(os.open(root, _FLAGS | os.O_DIRECTORY))
        try:
            held.append(_directory(held[-1], ".aragorn", create=run, private=False))
            held.append(_directory(held[-1], "phase3-pipeline", create=run))
            state = held[-1]
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
            lock = os.open(
                "lock", flags | (os.O_CREAT if run else 0), 0o600, dir_fd=state
            )
            info = os.fstat(lock)
            _require(
                stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600,
                "unsafe pipeline lock",
            )
            fcntl.flock(lock, (fcntl.LOCK_EX if run else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except FileNotFoundError:
            _require(not run, "state creation failed")
            _require(state is None, "existing pipeline state lacks its lock")
        pins, results = {}, {}

        def current_pin(name):
            current, _ = load_registry(root)
            memo = {}

            def calculate(key):
                if key not in memo:
                    memo[key] = fingerprint(
                        root,
                        current[key],
                        {dep: calculate(dep) for dep in current[key]["needs"]},
                    )[0]
                return memo[key]

            return calculate(name)

        for name in ordered:
            pin, contract = fingerprint(root, index[name], pins)
            pins[name] = pin
            if name not in wanted:
                continue
            dependency_ok = all(
                results[dep]["status"] in {"PASS", "SKIP_PASS"}
                for dep in index[name]["needs"]
            )
            status, attempt = "NEW", None
            owned = []
            try:
                if state is not None:
                    try:
                        owned.append(
                            _directory(state, name, create=run and dependency_ok)
                        )
                        owned.append(
                            _directory(owned[-1], pin[7:], create=run and dependency_ok)
                        )
                        attempt = owned[-1]
                        status = _cached(attempt, name, pin)
                    except FileNotFoundError:
                        pass
                if not dependency_ok:
                    status = "BLOCKED_DEPENDENCY"
                elif run and status == "NEW":
                    _require(
                        attempt is not None and current_pin(name) == pin,
                        "inputs changed before launch",
                    )
                    status = _execute(
                        root,
                        attempt,
                        index[name],
                        pin,
                        contract,
                        lambda name=name: current_pin(name),
                    )
                results[name] = {
                    "fingerprint": pin,
                    "status": status,
                    "argv": contract["argv"],
                }
            finally:
                for handle in reversed(owned):
                    os.close(handle)
        return {
            "schema": "aragorn/phase3-pipeline-report/v1",
            "stages": results,
            "limitations": _LIMITATIONS,
        }
    finally:
        if lock is not None:
            os.close(lock)
        for handle in reversed(held):
            os.close(handle)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("status", "run"))
    parser.add_argument("stages", nargs="*")
    args = parser.parse_args(argv)

    def interrupted(signum, frame):
        raise InterruptedError("pipeline interrupted")

    old = signal.signal(signal.SIGTERM, interrupted)
    try:
        report = pipeline(
            Path(__file__).resolve().parents[1],
            run=args.action == "run",
            selected=args.stages,
        )
        print(_canonical(report).decode())
        return (
            0
            if all(
                row["status"] in {"PASS", "SKIP_PASS", "NEW"}
                for row in report["stages"].values()
            )
            else 2
        )
    except (OSError, ValueError, PipelineError) as exc:
        print("phase3 pipeline refused: " + str(exc), file=sys.stderr)
        return 2
    finally:
        signal.signal(signal.SIGTERM, old)


if __name__ == "__main__":
    raise SystemExit(main())
