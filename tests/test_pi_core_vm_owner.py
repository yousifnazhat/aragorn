"""Actual B45 recorder + B46 observer + B47 owner around an inert NSObject, never a VM."""
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time
import unittest
import uuid

from scripts.pi_core_host_owner_supervision import supervise_owner


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "packaging/pi-core"
B45, B46, B47 = [PACK / f"immutable-host-b{n}" for n in (45, 46, 47)]
PAYLOAD = b"inert-owner\0\xff\n"


def raw_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)


class VMOwner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.tmp = Path(tmp.name).resolve()
        cls.binary = cls.tmp / "inert-machine"
        compiler = Path("/Library/Developer/CommandLineTools/usr/bin/clang")
        with compiler.open("rb") as f:
            if hashlib.file_digest(f, "sha256").hexdigest() != "1220c0afafa12a6ae599d097ee7cf8b87c6b4d8e3fbb9783cee6b319a80683ba":
                raise ValueError("unreviewed compiler")
        cls.env = {"PATH": "/usr/bin:/bin", "HOME": str(cls.tmp), "TMPDIR": str(cls.tmp)}
        subprocess.run([compiler, "-isysroot", "/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk",
                        "-arch", "arm64", "-mmacosx-version-min=26.0", "-fobjc-arc", "-fno-modules", "-Werror",
                        "-DB47_INERT_MACHINE=1", "-framework", "Foundation", "-framework", "Virtualization",
                        "-I", B45, "-I", B46, "-I", B47, ROOT / "tests/b47-vm-owner-fixture.m",
                        B45 / "serial-recorder.m", B46 / "vm-stop.m", B47 / "vm-owner.m", "-o", cls.binary],
                       cwd=cls.tmp, env=cls.env, stdin=subprocess.DEVNULL, timeout=45, check=True)

    @contextmanager
    def fixture(self, mode="normal", *, occupied=False):
        with ExitStack() as stack:
            work = Path(stack.enter_context(tempfile.TemporaryDirectory(dir=self.tmp)))
            self.uid = str(uuid.uuid4())
            self.attempt = work / self.uid
            self.attempt.mkdir(mode=0o700)
            if occupied:
                (self.attempt / "serial.raw").write_bytes(b"earlier-attempt")
            directory = os.open(self.attempt, os.O_RDONLY | os.O_DIRECTORY)
            stack.callback(os.close, directory)
            trace, peer = socket.socketpair()
            self.marker, notify = stack.enter_context(trace).fileno(), stack.enter_context(peer).fileno()
            out = stack.enter_context((work / "stdout").open("w+b"))
            err = stack.enter_context((work / "stderr").open("w+b"))
            self.out, self.err = out, err
            def spawn(stop, session):
                self.child = subprocess.Popen([self.binary, mode, self.uid, str(directory), str(stop),
                                               str(session), str(notify)], env=self.env, cwd=work,
                        stdin=subprocess.DEVNULL, stdout=out, stderr=err, pass_fds=(directory, stop, session, notify))
                def finish():
                    if self.child.poll() is None:
                        self.child.kill()
                    self.child.wait(timeout=3)
                stack.callback(finish)
                return self.child
            yield spawn, work

    @contextmanager
    def manual(self, mode="normal", *, occupied=False, invalid_control=False):
        with self.fixture(mode, occupied=occupied) as (spawn, _), ExitStack() as stack:
            self.sock, peer = socket.socketpair()
            stack.enter_context(self.sock)
            rd, wr = os.pipe()
            self.control = stack.enter_context(os.fdopen(wr, "wb", buffering=0))
            try:
                spawn(wr if invalid_control else rd, peer.fileno())
            finally:
                os.close(rd)
                peer.close()
            self.sock.settimeout(4)
            yield

    def ready(self):
        want = f"READY {self.uid} {self.child.pid}\n".encode()
        with self.sock.makefile("rb") as f:
            self.assertEqual(f.readline(128), want)
        self.assertTrue((self.attempt / "serial.raw").is_file())
        self.assertEqual([event["event"] for event in self.journal()], ["armed", "recorder-armed"])
        self.assertEqual(select.select([self.marker], [], [], 0)[0], [], "fake start before supervisor grant")

    def journal(self):
        return [json.loads(line) for line in (self.attempt / "owner-events.jsonl").read_bytes().splitlines()]

    def wait_event(self, name):
        until = time.monotonic() + 3
        while json.dumps(name).encode() not in (self.attempt / "owner-events.jsonl").read_bytes():
            self.assertLess(time.monotonic(), until, f"{name} was not recorded")
            time.sleep(.01)

    def grant(self, *, uid=None, pid=None, until=None):
        return f"ARM {uid or self.uid} {pid or self.child.pid} {raw_ns()+3_000_000_000 if until is None else until}\n".encode()

    def finish(self):
        self.child.wait(timeout=5)
        self.err.seek(0)
        self.assertEqual(self.child.returncode, 0, self.err.read(4096))
        self.out.seek(0)
        return json.loads(self.out.read(65537))

    def never_started(self):
        got = self.finish()
        self.assertEqual(got["fixture_starts"], 0)
        self.assertIs(got["owner"]["start_issued"], False)
        self.assertEqual(select.select([self.marker], [], [], 0)[0], [])

    def test_real_external_watchdog_releases_one_start_with_joined_observer_and_raw_recorder(self):
        with self.fixture() as (spawn, work):
            row = supervise_owner(spawn, record=work / "watchdog.json", attempt_uuid=self.uid)
            out = self.finish()
            self.assertEqual(row["owner_arm"]["status"], "queued")
            self.assertEqual((row["child_pid"], row["child_returncode"], out["fixture_starts"]),
                             (self.child.pid, 0, 1))
            self.assertLessEqual(row["owner_arm"]["ready_raw_ns"], out["fixture_start_ns"])
            self.assertLess(out["fixture_start_ns"], row["run_deadline_raw_ns"])
            ack = json.loads((work / "watchdog.json.owner-arm").read_bytes())
            self.assertEqual((ack["attempt_uuid"], ack["child_pid"], ack["ready_raw_ns"]),
                             (self.uid, self.child.pid, row["owner_arm"]["ready_raw_ns"]))
            owner = out["owner"]
            self.assertTrue(owner["start_issued"] and owner["stopped_observed"])
            self.assertIs(owner["complete"], True)
            self.assertTrue(owner["journal_sealed"])
            events = self.journal()
            self.assertEqual(events, owner["events"])
            stamps = {e["event"]: e["monotonic_ns"] for e in events}
            self.assertLessEqual(stamps["armed"], stamps["recorder-armed"])
            self.assertLessEqual(stamps["recorder-armed"], ack["ready_raw_ns"])
            self.assertLessEqual(ack["ready_raw_ns"], stamps["start-issued"])
            self.assertLessEqual(stamps["start-issued"], out["fixture_start_ns"])
            self.assertLessEqual(stamps["active-observed"], stamps["stopped-observed"])
            self.assertEqual((self.attempt / "serial.raw").read_bytes(), PAYLOAD)
            self.assertEqual(owner["capture"]["capture_sha256"], hashlib.sha256(PAYLOAD).hexdigest())
            self.assertTrue(owner["capture"]["sync_verified"] and owner["capture"]["pipe_eof"])
            self.assertIs(row["vm_stopped_verified"], False)

    def test_withheld_authority_eof_refuses_without_calling_start(self):
        with self.manual():
            self.ready()
            self.sock.shutdown(socket.SHUT_WR)
            self.never_started()

    def test_foreign_expired_or_duplicated_grant_cannot_call_start(self):
        for case in ("uuid", "pid", "expired", "duplicate"):
            with self.subTest(case=case), self.manual():
                self.ready()
                line = dict(uuid=self.grant(uid=str(uuid.uuid4())), pid=self.grant(pid=self.child.pid+1),
                            expired=self.grant(until=raw_ns()-1), duplicate=self.grant()*2)[case]
                self.sock.sendall(line)
                self.never_started()

    def test_recorder_reservation_or_graph_or_control_failure_prevents_readiness(self):
        for mode, occupied, invalid in (("normal", True, False), ("other-pipe", False, False),
                                        ("normal", False, True)):
            with self.subTest(mode=mode, occupied=occupied, invalid=invalid), self.manual(
                    mode, occupied=occupied, invalid_control=invalid):
                self.never_started()
                self.assertEqual(self.sock.recv(128), b"")
                if occupied:
                    self.assertEqual((self.attempt / "serial.raw").read_bytes(), b"earlier-attempt")

    def test_stop_ordered_before_arm_vetoes_start(self):
        with self.manual():
            self.ready()
            self.control.write(b"G")
            try:
                self.sock.sendall(self.grant())
            except BrokenPipeError:
                pass
            self.never_started()

    def test_force_completion_and_later_same_machine_stop_are_distinct(self):
        with self.manual("hold"):
            self.ready()
            self.sock.sendall(self.grant())
            self.assertTrue(select.select([self.marker], [], [], 4)[0])
            self.assertEqual(os.read(self.marker, 1), b"S")
            self.control.write(b"GF")
            result = self.finish()
            self.assertEqual((result["fixture_starts"], result["fixture_graceful"], result["fixture_forced"]),
                             (1, 1, 1))
            names = [e["event"] for e in result["owner"]["events"]]
            self.assertLess(names.index("force-completion-returned"), names.index("stopped-observed"))
            self.assertIs(result["owner"]["stopped_observed"], True)

    def test_supervisor_lost_after_start_does_not_suppress_stop_or_claim_completion(self):
        with self.manual("hold"):
            self.ready()
            self.sock.sendall(self.grant())
            self.assertTrue(select.select([self.marker], [], [], 4)[0])
            self.assertEqual(os.read(self.marker, 1), b"S")
            self.sock.shutdown(socket.SHUT_RDWR)
            # Wait for the actual journal event while the stand-in stays running, not an estimated delay.
            self.wait_event("supervision-lost")
            self.control.write(b"GF")
            out = self.finish()
            self.assertEqual((out["fixture_starts"], out["fixture_graceful"], out["fixture_forced"]), (1, 1, 1))
            owner = out["owner"]
            self.assertIs(owner["stopped_observed"], True)
            self.assertIs(owner["complete"], False)
            self.assertIs(owner["supervision_lost"], True)
            events = [e["event"] for e in self.journal()]
            self.assertLess(events.index("supervision-lost"), events.index("graceful-accepted"))
            self.assertLess(events.index("graceful-accepted"), events.index("stopped-observed"))

    def test_stop_channel_eof_alone_invalidates_completion_even_if_arm_channel_stays_open(self):
        with self.manual("wait-fixture-stop"):
            self.ready()
            self.sock.sendall(self.grant())
            self.assertTrue(select.select([self.marker], [], [], 4)[0])
            self.assertEqual(os.read(self.marker, 1), b"S")
            self.control.close()
            self.wait_event("control-eof")
            os.write(self.marker, b"Q")  # Only the test stand-in accepts this external stop notification.
            owner = self.finish()["owner"]
            self.assertIs(owner["stopped_observed"], True)
            self.assertIs(owner["supervision_lost"], True)
            self.assertIs(owner["complete"], False)
