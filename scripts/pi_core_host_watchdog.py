"""One direct child, one fixed B44 budget. No CLI, VM discovery, launch policy or retry.

The trusted single-threaded coordinator supplies a direct Popen factory (no shell,
preexec_fn, other waiters, or work after Popen returns). Its only argument is the
inherited read end of the stop channel. The child must not start a VM before
external ownership is established. This is not a guardian against host death.
"""
import os
from pathlib import Path
import queue
import signal
import stat
import subprocess
import threading
import time
import uuid

from scripts.build_pi_core_linux import canonical


_NS = 1_000_000_000
BUDGET_NS = (180 * _NS, 15 * _NS, 15 * _NS)
_IO_WAIT = 3.0   # receipt I/O only; never extends a VM control window
_REAP_WAIT = 0.5  # bookkeeping after host kill, not another VM grace period
_SCHEMA = "aragorn/b46-owned-host-watchdog/v1"


def _raw():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)


class _Journal:
    """Fixed number of exclusive, fsynced receipts. Slow storage cannot delay G/F/kill."""

    def __init__(self, path):
        self.jobs = queue.SimpleQueue()
        self.failure = threading.Event()
        self.error = None
        threading.Thread(target=self._write, args=(path,), daemon=True).start()

    def _write(self, path):
        dfd = None
        try:
            if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
                raise ValueError("expected canonical private evidence directory")
            dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            st = os.fstat(dfd)
            if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
                raise ValueError("expected owned 0700 evidence directory")
            # An orphaned terminal record is not permission for another attempt.
            try:
                os.stat(path.name, dir_fd=dfd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError("watchdog terminal record already exists")
            while True:
                job = self.jobs.get()
                if job is None:
                    break
                suffix, raw, done = job
                fd = os.open(path.name + suffix, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                             0o400, dir_fd=dfd)
                with os.fdopen(fd, "wb") as f:
                    os.fchmod(fd, 0o400)
                    f.write(raw)
                    f.flush()
                    os.fsync(f.fileno())
                os.fsync(dfd)
                done.set()
        except Exception as exc:
            self.error = exc
            self.failure.set()
        finally:
            if dfd is not None:
                os.close(dfd)

    def put(self, suffix, value, wait=False):
        done = threading.Event()
        self.jobs.put((suffix, canonical(value), done))
        if wait:
            until = time.monotonic() + _IO_WAIT
            while not done.is_set():
                if self.failure.is_set():
                    raise RuntimeError("watchdog evidence not durable; retain attempt") from self.error
                remaining = until - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("watchdog evidence I/O unresolved; retain attempt")
                done.wait(min(0.02, remaining))
        return done  # Optional B47 arm decision may only be used after async fsync completes.


def _request(fd, which, when):
    message = {"requested_raw_ns": when, "delivery": "indeterminate"}
    try:
        if os.write(fd, which) == 1:
            message["delivery"] = "queued-to-control-pipe"
    except OSError as exc:
        message["errno"] = exc.errno
    message["completed_raw_ns"] = _raw()
    return message


def supervise(spawn, *, record: Path, attempt_uuid: str, _owner=None):
    """Return the durable terminal host receipt. Never interpret it as VM stop proof.

    The coordinator supplies the same canonical UUID to this call and the child's
    attempt. Inherit the FD via pass_fds; use DEVNULL or already-open owned files
    for stdio, never an undrained PIPE. Do not retry a refusal or a partial receipt.
    Run on the main thread of a dedicated CLI process; SIGINT/TERM request bounded
    shutdown and produce an interrupted (never successful) terminal record.
    """
    uid = uuid.UUID(attempt_uuid)
    if (str(uid) != attempt_uuid or not uid.int or
            threading.current_thread() is not threading.main_thread() or
            signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
        raise ValueError("expected canonical UUID and exclusive main-thread child ownership")
    rid = {"schema": _SCHEMA, "attempt_uuid": attempt_uuid, "clock": "CLOCK_MONOTONIC_RAW"}
    journal = _Journal(Path(record))
    child = None
    fds = []
    saved = {}
    pending = []
    row = dict(rid, outcome="not-started", child_pid=None, child_reaped=False, child_returncode=None,
               interrupted=False, interrupt_signal=None, host_kill_requested=False, host_kill_raw_ns=None,
               graceful=None, force=None, start_raw_ns=None, run_deadline_raw_ns=None,
               graceful_deadline_raw_ns=None, force_deadline_raw_ns=None, exit_observed_raw_ns=None,
               vm_stopped_verified=False)
    if _owner is not None:
        row["owner_arm"] = _owner.state

    def interrupt(signum, _frame):
        if not pending:
            pending.append(signum)  # no I/O or raising across Popen/fd ownership transfer

    def observe():
        code = child.poll()
        if code is not None:
            row.update(child_returncode=code, child_reaped=True, exit_observed_raw_ns=_raw())
            return True
        return False

    def host_kill():
        # No process groups/pidfiles/ps. An exclusive direct child cannot have its PID
        # reused before it has been reaped. kill() also polls the same Popen first.
        if child is None or row["child_reaped"] or row["host_kill_requested"] or observe():
            return
        row.update(host_kill_requested=True, host_kill_raw_ns=_raw())
        try:
            child.kill()
        except OSError as exc:
            row["host_kill_errno"] = exc.errno
        journal.put(".kill", dict(rid, requested_raw_ns=row["host_kill_raw_ns"],
                                  kind="host-child-kill", errno=row.get("host_kill_errno")))
        try:
            child.wait(timeout=_REAP_WAIT)
        except subprocess.TimeoutExpired:
            pass
        observe()

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            saved[sig] = signal.signal(sig, interrupt)
        journal.put(".started", dict(rid, disposition="reserved-before-spawn", reserved_raw_ns=_raw()), wait=True)
        if not pending:
            read_fd, write_fd = os.pipe()
            fds.extend((read_fd, write_fd))
            os.set_blocking(write_fd, False)
            start = _raw()
            run, grace, force = BUDGET_NS
            deadlines = [start + run, start + run + grace, start + run + grace + force]
            row.update(start_raw_ns=start, run_deadline_raw_ns=deadlines[0],
                       graceful_deadline_raw_ns=deadlines[1], force_deadline_raw_ns=deadlines[2])
            try:
                child = spawn(read_fd)
                if not isinstance(child, subprocess.Popen):
                    child = None
                    raise ValueError("expected newly owned Popen")
                row["child_pid"] = child.pid
                if any(stream is not None for stream in (child.stdin, child.stdout, child.stderr)):
                    raise ValueError("Popen stdio PIPE is not allowed")
                os.close(fds.pop(0))
                while True:
                    now = _raw()
                    if pending and not row["interrupted"]:
                        row.update(interrupted=True, interrupt_signal=pending[0])
                        # Cancellation may shorten the clock; it can never reset it.
                        deadlines[0] = min(deadlines[0], now)
                        deadlines[1] = min(deadlines[1], deadlines[0] + grace)
                        deadlines[2] = min(deadlines[2], deadlines[1] + force)
                    if observe():
                        row["outcome"] = ("child-exited" if row["exit_observed_raw_ns"] < deadlines[0]
                                          else "child-exited-after-deadline")
                        break
                    now = _raw()
                    if journal.failure.is_set():
                        row["outcome"] = "evidence-failed"
                        break
                    if now >= deadlines[2]:
                        row["outcome"] = "host-deadline"
                        break
                    if now >= deadlines[0]:
                        if row["graceful"] is None:
                            # A delayed scheduler can miss the graceful interval. Send
                            # G then F in protocol order, but grant no additional time.
                            row["graceful"] = _request(write_fd, b"G", now)
                            row["graceful"]["window_missed"] = now >= deadlines[1]
                            journal.put(".graceful", dict(rid, kind="vm-graceful-request", **row["graceful"]))
                        now = _raw()
                        if deadlines[1] <= now < deadlines[2] and row["force"] is None:
                            row["force"] = _request(write_fd, b"F", now)
                            journal.put(".force", dict(rid, kind="vm-force-request", **row["force"]))
                        next_time = deadlines[2] if now >= deadlines[1] else deadlines[1]
                    else:
                        next_time = deadlines[0]
                        if _owner is not None:
                            _owner.tick(child, row, journal, lambda: not pending and not journal.failure.is_set()
                                        and child.poll() is None and _raw() < deadlines[0])
                    time.sleep(max(0, min(0.02, (next_time - _raw()) / _NS)))
            except (Exception, KeyboardInterrupt, SystemExit) as exc:
                row.update(outcome="host-error", error_type=type(exc).__name__)
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    row["interrupted"] = True
            finally:
                host_kill()
                row["effective_deadlines_raw_ns"] = deadlines
        if pending or row["interrupted"]:
            row.update(interrupted=True, interrupt_signal=pending[0] if pending else None, outcome="interrupted")
        journal.put("", row, wait=True)
        return row
    finally:
        for fd in fds:
            os.close(fd)
        journal.jobs.put(None)
        for sig, handler in saved.items():
            signal.signal(sig, handler)
