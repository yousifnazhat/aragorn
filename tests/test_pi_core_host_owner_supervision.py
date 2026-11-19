"""B47: real direct, inert subprocesses over private inherited FDs; no VM or external operation."""
import json
import os
from pathlib import Path
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch

from scripts import pi_core_host_owner_supervision as owner
from scripts import pi_core_host_watchdog as watch


PRELUDE = """
import json, os, select, socket, sys, time
from pathlib import Path
stop, session = map(int, sys.argv[1:3])
uid, record = sys.argv[3:5]
sock = socket.socket(fileno=session)
sock.settimeout(2)
ready = f'READY {uid} {os.getpid()}\\n'.encode('ascii')
"""


class OwnerSupervision(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.uid = str(uuid.uuid4())
        self.record = self.base / "watchdog.json"

    def spawn(self, stop, session, code, extra=()):
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", PRELUDE + code, str(stop), str(session),
             self.uid, str(self.record), *map(str, extra)], pass_fds=(stop, session, *extra),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def retire():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
        self.addCleanup(retire)
        return child

    def supervise(self, factory):
        return owner.supervise_owner(factory, record=self.record, attempt_uuid=self.uid)

    def test_fragmented_ready_granted_only_after_durable_exact_decision(self):
        row = self.supervise(lambda *fds: self.spawn(*fds, """
assert not select.select([sock], [], [], 0.05)[0]
sock.sendall(ready[:-1])
assert not select.select([sock], [], [], 0.06)[0]
sock.sendall(ready[-1:])
reply = sock.makefile('rb').readline(128)
d = json.loads(Path(record + '.owner-arm').read_bytes())
assert d['disposition'] == 'decision-not-delivery'
assert (d['attempt_uuid'], d['child_pid']) == (uid, os.getpid())
assert reply == f"ARM {uid} {os.getpid()} {d['run_deadline_raw_ns']}\\n".encode('ascii')
assert time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW) < d['run_deadline_raw_ns']
sock.sendall(ready)
assert not select.select([sock], [], [], 0.08)[0]
"""))
        self.assertEqual((row["outcome"], row["child_returncode"]), ("child-exited", 0))
        self.assertEqual(row["owner_arm"]["status"], "queued")
        self.assertLess(row["owner_arm"]["ready_raw_ns"], row["owner_arm"]["queued_raw_ns"])
        self.assertLess(row["owner_arm"]["queued_raw_ns"], row["run_deadline_raw_ns"])
        self.assertFalse(row["vm_stopped_verified"])
        self.assertEqual(stat.S_IMODE(Path(str(self.record) + ".owner-arm").stat().st_mode), 0o400)
        self.assertEqual(row, json.loads(self.record.read_bytes()))

    def test_ready_buffered_during_spawn_does_not_release_before_popen_ownership(self):
        r, w = os.pipe()
        try:
            def factory(stop, session):
                p = self.spawn(stop, session, """
sock.sendall(ready)
assert not select.select([sock], [], [], 0.10)[0]
os.write(int(sys.argv[5]), b'N')
assert sock.makefile('rb').readline(128).startswith(f'ARM {uid} {os.getpid()} '.encode())
""", (w,))
                self.assertTrue(select.select([r], [], [], 2)[0])
                self.assertEqual(os.read(r, 1), b"N")
                self.assertFalse(Path(str(self.record) + ".owner-arm").exists())
                return p
            row = self.supervise(factory)
            self.assertEqual((row["owner_arm"]["status"], row["child_returncode"]), ("queued", 0))
        finally:
            os.close(r)
            os.close(w)

    def test_wrong_attempt_pid_extra_data_and_truncated_eof_refused(self):
        for n, payload in enumerate((
            'ready.replace(uid.encode(), b"0"*36)', 'ready.replace(str(os.getpid()).encode(), b"1")',
            'ready + b"X"', 'ready[:-2]',
        )):
            with self.subTest(payload=payload):
                self.record = self.base / str(n)
                code = ("sock.sendall(" + payload + ")\n" +
                        ("sock.shutdown(socket.SHUT_WR)\n" if n == 3 else "") + "time.sleep(5)\n")
                row = self.supervise(lambda *fds: self.spawn(*fds, code))
                self.assertEqual(row["outcome"], "host-error")
                self.assertEqual(row["owner_arm"]["status"], "partial-ready-eof" if n == 3 else "invalid-ready-frame")
                self.assertIsNone(row["owner_arm"]["queued_raw_ns"])
                self.assertFalse(Path(str(self.record) + ".owner-arm").exists())
                self.assertIs(row["child_reaped"], True)

    def test_late_ready_after_deadline_cannot_receive_arm(self):
        with patch.object(watch, "BUDGET_NS", (100_000_000, 500_000_000, 500_000_000)):
            row = self.supervise(lambda *fds: self.spawn(*fds, """
assert os.read(stop, 1) == b'G'
sock.sendall(ready)
assert not select.select([sock], [], [], 0.07)[0]
"""))
        self.assertEqual((row["outcome"], row["child_returncode"]), ("child-exited-after-deadline", 0))
        self.assertEqual(row["owner_arm"]["status"], "not-granted")
        self.assertFalse(Path(str(self.record) + ".owner-arm").exists())

    def test_interrupt_is_not_supervisory_authority(self):
        def factory(*fds):
            p = self.spawn(*fds, """
sock.sendall(ready)
assert os.read(stop, 1) == b'G'
assert not select.select([sock], [], [], 0.05)[0]
""")
            signal.raise_signal(signal.SIGTERM)
            return p
        row = self.supervise(factory)
        self.assertEqual((row["outcome"], row["child_returncode"]), ("interrupted", 0))
        self.assertIsNone(row["owner_arm"]["queued_raw_ns"])

    def test_slow_arm_fsync_does_not_delay_stop_or_grant_late(self):
        receipt = Path(str(self.record) + ".owner-arm")
        sent_stop = threading.Event()
        sync, request = os.fsync, watch._request
        def slow(fd):
            if receipt.exists() and os.path.samestat(os.fstat(fd), receipt.stat()):
                if not sent_stop.wait(2):
                    raise AssertionError("watchdog waited for storage on its control thread")
            sync(fd)
        def send(fd, byte, now):
            result = request(fd, byte, now)
            if byte == b"G":
                sent_stop.set()
            return result
        with (patch.object(watch, "BUDGET_NS", (600_000_000, 500_000_000, 500_000_000)),
              patch.object(os, "fsync", slow), patch.object(watch, "_request", send)):
            row = self.supervise(lambda *fds: self.spawn(*fds, """
sock.sendall(ready)
assert os.read(stop, 1) == b'G'
assert not select.select([sock], [], [], 0.07)[0]
"""))
        self.assertEqual((row["owner_arm"]["status"], row["child_returncode"]), ("awaiting-durability", 0))
        self.assertTrue(sent_stop.is_set() and receipt.is_file())
        self.assertFalse(row["vm_stopped_verified"])

    def test_existing_arm_decision_is_never_overwritten_or_used(self):
        receipt = Path(str(self.record) + ".owner-arm")
        receipt.write_bytes(b"retained")
        with self.assertRaisesRegex(RuntimeError, "not durable"):
            self.supervise(lambda *fds: self.spawn(*fds, "sock.sendall(ready)\ntime.sleep(5)\n"))
        self.assertEqual(receipt.read_bytes(), b"retained")
        self.assertFalse(self.record.exists())
