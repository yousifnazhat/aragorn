"""B46 external host supervision: direct inert children only, no VM/firmware/network."""
import errno
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch

from scripts import pi_core_host_watchdog as watch


class HostWatchdogTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        self.record = self.dir / "watchdog.json"
        self.uid = str(uuid.uuid4())

    def factory(self, f, code, *, pipe=False):
        proc = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", "import os,sys,time; fd=int(sys.argv[1]);" + code, str(f)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE if pipe else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, pass_fds=(f,))

        def retire():
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)
            if proc.stdout is not None:
                proc.stdout.close()

        self.addCleanup(retire)
        return proc

    def watch(self, factory):
        return watch.supervise(factory, record=self.record, attempt_uuid=self.uid)

    def receipt(self, suffix=""):
        p = self.dir / (self.record.name + suffix)
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o400)
        return json.loads(p.read_bytes())

    def test_clean_exit_durable_unchanged_b44_budget_no_vm_claim(self):
        row = self.watch(lambda f: self.factory(f, "os.write(1, b'z' * 1000000)"))
        self.assertEqual(row, self.receipt())
        self.assertEqual(self.receipt(".started")["attempt_uuid"], self.uid)
        self.assertEqual(row["schema"], "aragorn/b46-owned-host-watchdog/v1")
        self.assertEqual((row["outcome"], row["child_reaped"], row["child_returncode"]),
                         ("child-exited", True, 0))
        self.assertEqual(row["attempt_uuid"], self.uid)
        self.assertEqual(row["clock"], "CLOCK_MONOTONIC_RAW")
        self.assertEqual([d - row["start_raw_ns"] for d in row["effective_deadlines_raw_ns"]],
                         [n * 10**9 for n in (180, 195, 210)])
        self.assertLess(row["exit_observed_raw_ns"], row["run_deadline_raw_ns"])
        self.assertFalse(any((row["graceful"], row["force"], row["host_kill_requested"],
                              row["interrupted"], row["vm_stopped_verified"])))

    def test_owned_child_receives_distinct_controls_and_reaped_exit_is_not_vm_stop(self):
        with patch.object(watch, "BUDGET_NS", (150_000_000, 150_000_000, 1_000_000_000)):
            row = self.watch(lambda f: self.factory(f, "assert os.read(fd,1)==b'G' and os.read(fd,1)==b'F'"))
        self.assertEqual((row["outcome"], row["child_returncode"], row["child_reaped"]),
                         ("child-exited-after-deadline", 0, True))
        for name, cutoff in (("graceful", "run_deadline_raw_ns"), ("force", "graceful_deadline_raw_ns")):
            event = self.receipt("." + name)
            self.assertEqual(event["delivery"], "queued-to-control-pipe")
            self.assertEqual(row[name]["requested_raw_ns"], event["requested_raw_ns"])
            self.assertLessEqual(row[cutoff], event["requested_raw_ns"])
            self.assertLessEqual(event["requested_raw_ns"], event["completed_raw_ns"])
        self.assertLessEqual(row["force"]["completed_raw_ns"], row["exit_observed_raw_ns"])
        self.assertFalse(row["host_kill_requested"] or row["vm_stopped_verified"])

    def test_blocked_child_only_is_killed_after_absolute_force_cutoff(self):
        bystander = subprocess.Popen([sys.executable, "-I", "-S", "-c", "import time;time.sleep(60)"],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            with patch.object(watch, "BUDGET_NS", (100_000_000,) * 3):
                row = self.watch(lambda f: self.factory(f, "time.sleep(60)"))
            self.assertIsNone(bystander.poll())
            self.assertEqual(self.receipt(".kill")["requested_raw_ns"], row["host_kill_raw_ns"])
            self.assertGreaterEqual(row["host_kill_raw_ns"], row["force_deadline_raw_ns"])
            self.assertEqual((row["outcome"], row["host_kill_requested"], row["child_returncode"],
                              row["child_reaped"], row["vm_stopped_verified"]),
                             ("host-deadline", True, -signal.SIGKILL, True, False))
        finally:
            bystander.kill()
            bystander.wait(timeout=2)

    def test_interruption_shortens_never_restarts_clock_and_restores_signal_handler(self):
        previous = signal.getsignal(signal.SIGTERM)

        def interrupt(f):
            child = self.factory(f, "assert os.read(fd,1)==b'G' and os.read(fd,1)==b'F'")
            signal.raise_signal(signal.SIGTERM)
            return child

        with patch.object(watch, "BUDGET_NS", (30_000_000_000, 150_000_000, 1_000_000_000)):
            row = self.watch(interrupt)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
        self.assertEqual((row["outcome"], row["interrupted"], row["interrupt_signal"], row["child_returncode"]),
                         ("interrupted", True, signal.SIGTERM, 0))
        effective = row["effective_deadlines_raw_ns"]
        self.assertLess(effective[0], row["run_deadline_raw_ns"])
        self.assertEqual((effective[1] - effective[0], effective[2] - effective[1]),
                         (150_000_000, 1_000_000_000))
        self.assertFalse(row["vm_stopped_verified"] or row["host_kill_requested"])

    def test_closed_control_reports_pipe_error_not_vm_acknowledgment(self):
        # No inheritance here: the child's stdin/out/err cannot accidentally carry a stop.
        def spawn(_fd):
            return subprocess.Popen([sys.executable, "-I", "-S", "-c", "import time;time.sleep(60)"],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with patch.object(watch, "BUDGET_NS", (100_000_000,) * 3):
            row = self.watch(spawn)
        for name in ("graceful", "force"):
            self.assertEqual((row[name]["delivery"], row[name]["errno"]), ("indeterminate", errno.EPIPE))
        self.assertFalse(row["vm_stopped_verified"])

    def test_misconfigured_stdio_pipe_cannot_deadlock_or_return_success(self):
        row = self.watch(lambda f: self.factory(f, "os.write(1,b'x'*1000000);time.sleep(60)", pipe=True))
        self.assertEqual((row["outcome"], row["error_type"]), ("host-error", "ValueError"))
        self.assertTrue(row["host_kill_requested"] and row["child_reaped"])
        self.assertFalse(row["vm_stopped_verified"])

    def test_existing_marker_or_terminal_refuses_without_spawning_or_overwriting(self):
        started = self.dir / (self.record.name + ".started")
        for path in (started, self.record):
            with self.subTest(path=path):
                path.write_bytes(b"retained")
                with self.assertRaises(RuntimeError):
                    self.watch(lambda _: self.fail("must not spawn"))
                self.assertEqual(path.read_bytes(), b"retained")
                path.unlink()

    def test_unowned_or_alias_evidence_directory_refuses_before_spawn(self):
        private = self.dir / "private"
        private.mkdir(mode=0o755)
        alias = self.dir / "alias"
        alias.symlink_to(self.dir, target_is_directory=True)
        for directory in (private, alias):
            with self.subTest(directory=directory), self.assertRaises(RuntimeError):
                private.chmod(0o755)
                watch.supervise(lambda _: self.fail("must not spawn"), record=directory / "receipt",
                                attempt_uuid=self.uid)

    def test_wedged_reservation_is_bounded_and_launch_never_occurs(self):
        release = threading.Event()
        finished = threading.Event()
        fsync = os.fsync

        def wedged(fd):
            release.wait(2)
            fsync(fd)
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                finished.set()

        try:
            with patch.object(watch, "_IO_WAIT", 0.15), patch.object(os, "fsync", wedged):
                with self.assertRaises(TimeoutError):
                    self.watch(lambda _: self.fail("must not spawn"))
                release.set()
                self.assertTrue(finished.wait(2))
        finally:
            release.set()
        self.assertFalse(self.record.exists())

    def test_scheduler_stall_does_not_replay_missed_control_windows(self):
        raw = watch._raw
        offset = [0]

        def spawn(f):
            child = self.factory(f, "time.sleep(60)")
            offset[0] = 211_000_000_000
            return child

        with patch.object(watch, "_raw", lambda: raw() + offset[0]):
            row = self.watch(spawn)
        self.assertEqual((row["outcome"], row["graceful"], row["force"], row["host_kill_requested"]),
                         ("host-deadline", None, None, True))
        self.assertFalse(row["vm_stopped_verified"])

    def test_late_grace_window_gets_ordered_controls_but_no_extra_time(self):
        raw = watch._raw
        offset = [0]

        def spawn(f):
            child = self.factory(f, "assert os.read(fd,1)==b'G' and os.read(fd,1)==b'F'")
            offset[0] = 196_000_000_000
            return child

        with patch.object(watch, "_raw", lambda: raw() + offset[0]):
            row = self.watch(spawn)
        self.assertTrue(row["graceful"]["window_missed"])
        self.assertLessEqual(row["graceful"]["completed_raw_ns"], row["force"]["requested_raw_ns"])
        self.assertEqual(row["child_returncode"], 0)
        self.assertEqual(row["effective_deadlines_raw_ns"][-1] - row["start_raw_ns"], 210 * 10**9)
        self.assertFalse(row["vm_stopped_verified"])

    def test_nil_or_noncanonical_uuid_is_never_reserved_or_launched(self):
        for value in (str(uuid.UUID(int=0)), self.uid.replace("-", "")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                watch.supervise(lambda _: self.fail("must not spawn"), record=self.record, attempt_uuid=value)
        self.assertEqual(list(self.dir.iterdir()), [])
