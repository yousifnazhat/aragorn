"""B47: arm exactly one direct child over a private inherited Unix stream; no VM entry point."""
import socket

from scripts import pi_core_host_watchdog as watch


class _Arm:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""
        self.durable = None
        self.state = {"status": "not-granted", "ready_raw_ns": None, "queued_raw_ns": None}

    def refuse(self, reason):
        self.state["status"] = reason
        raise ValueError("watchdog refused owner readiness: " + reason)

    def tick(self, child, row, journal, allowed):
        # Called only after Popen ownership/stdio verification, on the watchdog thread.
        if self.state["status"] in ("queued", "peer-eof") or not allowed():
            return
        uid, pid, limit = row["attempt_uuid"], child.pid, row["run_deadline_raw_ns"]
        expected = f"READY {uid} {pid}\n".encode("ascii")
        try:
            data = self.sock.recv(len(expected) + 1 - len(self.buffer))
        except BlockingIOError:
            data = None
        if data == b"" and not self.buffer:
            # A held release can decline before READY. Drain its exit without racing a host kill.
            self.state["status"] = "peer-eof"
            return
        if data == b"":
            self.refuse("partial-ready-eof")
        if data:
            self.buffer += data
            if not expected.startswith(self.buffer):
                self.refuse("invalid-ready-frame")
        if self.buffer != expected:
            return
        if self.durable is None:
            self.state.update(status="awaiting-durability", ready_raw_ns=watch._raw())
            self.durable = journal.put(".owner-arm", {
                "schema": "aragorn/b47-owned-child-arm-decision/v1", "attempt_uuid": uid, "child_pid": pid,
                "clock": "CLOCK_MONOTONIC_RAW", "run_deadline_raw_ns": limit,
                "ready_raw_ns": self.state["ready_raw_ns"], "disposition": "decision-not-delivery",
            })
            return
        if not self.durable.is_set():
            return
        reply = f"ARM {uid} {pid} {limit}\n".encode("ascii")
        if not allowed():
            return
        self.state["status"] = "delivery-indeterminate"
        # Never retry a partial write, even after EAGAIN. The native reader rejects
        # truncation and rechecks this same RAW deadline at its queue's start site.
        if self.sock.send(reply) != len(reply):
            self.refuse("partial-arm")
        when = watch._raw()
        self.state["queued_raw_ns"] = when
        if when >= limit:
            self.refuse("deadline-crossed-during-send")
        self.state["status"] = "queued"


def supervise_owner(spawn, *, record, attempt_uuid):
    """The trusted factory passes only the two supplied FDs to its direct Popen.

    The native owner must keep the private stream open and report READY only
    from its armed recorder/observer. Neither ARM nor child exit proves a start.
    """
    parent, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with parent, peer:
        parent.setblocking(False)
        def create(stop_fd):
            try:
                return spawn(stop_fd, peer.fileno())
            finally:
                peer.close()
        return watch.supervise(create, record=record, attempt_uuid=attempt_uuid, _owner=_Arm(parent))
