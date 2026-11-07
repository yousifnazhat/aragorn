"""Inert kernel/proc fixtures only: no ptrace, subprocess, activation or files."""

import ctypes
import copy
import hashlib
import itertools
from pathlib import Path
import signal
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn import pi_core_source_observer as observer


PID = 71
PIN = "sha256:" + "a" * 64
SOURCE = "/opt/aragorn/pi-runtime/pi-core/entrypoint.js"
META = dict(device=1, inode=3, mode=stat.S_IFREG | 0o444, nlink=1,
            uid=0, gid=0, size=3, mtime_ns=11, ctime_ns=12)
ROW = dict(path=SOURCE, digest="sha256:" + hashlib.sha256(b"abc").hexdigest(), identity=META)


def stopped(event=0, sig=signal.SIGTRAP | 0x80):
    return (event << 16) | (sig << 8) | 0x7f


def metadata(**changes):
    values = dict(st_dev=1, st_ino=3, st_mode=stat.S_IFREG | 0o444, st_nlink=1,
                  st_uid=0, st_gid=0, st_size=3, st_mtime_ns=11, st_ctime_ns=12)
    values.update(changes)
    return SimpleNamespace(**values)


class SourceAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.stack = []
        self.mock("time.monotonic", return_value=1.0)
        self.mock("_tick", side_effect=itertools.count(1000))
        # These records encode Linux wait status, even on the macOS test host.
        # Darwin WSTOPSIG does not mask Linux's high ptrace-event bits.
        self.mock("os.WSTOPSIG", side_effect=lambda status: (status >> 8) & 255)
        self.mock("os.WIFSTOPPED", side_effect=lambda status: status & 255 == 127)
        self.value = observer.PiSourceObserver(observer._SEAL)
        self.value._deadline = 10.0
        self.value._worker = dict(pid=PID, start_ticks=21, uid=1001, gid=1001,
                                  cgroup="/system.slice/owned.service", unit="owned.service", invocation_id="abc")
        self.value._bindings = {name: PIN for name in observer._BINDINGS}
        self.value._clock = dict(clock_id="CLOCK_BOOTTIME", boot_id="00000000-0000-0000-0000-000000000001", time_namespace_inode=8)
        self.value._kernel = Mock()
        self.value._kernel.duplicate.return_value = 19
        self.value._kernel.message.return_value = PID
        self.value._attached = self.value._stopped = True
        self.value._pidfd = 17
        self.value._fds = [17, 18]
        self.value._sources = [ROW]
        self.value._source_fds = {SOURCE: 18}
        self.value._ranges = {SOURCE: []}
        self.value._guard = Mock()
        self.mock("os.listdir", return_value=[str(PID)])
        self.mock("_protected_file", return_value=META)
        self.mock("_hash", return_value=(ROW["digest"], META))
        self.mock("process._executable_digest", return_value=PIN)

    def mock(self, name, **kwargs):
        item = patch.object(observer, name, **kwargs) if "." not in name else patch(
            "aragorn.pi_core_source_observer." + name, **kwargs)
        self.stack.append(item)
        return item.start()

    def tearDown(self):
        for item in reversed(self.stack):
            item.stop()

    def step(self, op="NONE", nr=None, args=None, result=None, error=None, event=0):
        self.value._kernel.info.return_value = (op, nr, args, result, error)
        sig = signal.SIGTRAP if event else signal.SIGTRAP | 0x80
        with patch.object(observer.os, "waitpid", return_value=(PID, stopped(event, sig))):
            self.value.advance(deadline=2)

    def entry(self, number, args=None):
        self.step("ENTRY", number, args or [0] * 6)

    def exit(self, result=0, error=False):
        self.step("EXIT", result=result, error=error)

    def execute(self):
        self.entry(221)
        self.step(event=4)
        self.exit()

    def read_enter(self, number=67, offset=0, count=3):
        self.entry(number, [8, 4096, count, offset, 0, 0])

    def test_factory_seal_required(self):
        with self.assertRaisesRegex(observer.PiSourceObserverError, "FACTORY"):
            observer.PiSourceObserver(object())

    def test_factory_refuses_non_linux_before_kernel_or_proc(self):
        with patch.object(observer.platform, "system", return_value="Darwin"), \
             patch.object(observer, "_Kernel") as kernel:
            with self.assertRaises(observer.PiSourceObserverError) as raised:
                observer.arm_pi_source_observer(None, gate_path=observer.GATE_PATH, gate_digest=PIN,
                    node_path=observer.NODE_PATH, node_digest=PIN, sources=[], bindings={}, deadline=2)
            self.assertEqual(raised.exception.observer._state, "REFUSED")
            kernel.assert_not_called()

    def test_current_env_to_node_plan_cannot_arm_after_the_fact(self):
        owned = self.native_guard_fixture()
        object.__setattr__(owned.plan, "systemd_run_argv", ("systemd-run", "--", "/usr/bin/env", "-i",
            "HOME=/nonexistent", "PATH=/opt/aragorn/pi-runtime/node/bin", str(observer.NODE_PATH), observer.ENTRY_PATH))
        with patch.object(observer.platform, "system", return_value="Linux"), \
             patch.object(observer.platform, "machine", return_value="aarch64"), \
             patch.object(observer.os, "getuid", return_value=0), patch.object(observer.os, "geteuid", return_value=0), \
             patch.object(observer.os, "getgid", return_value=0), patch.object(observer.os, "getegid", return_value=0), \
             patch.object(observer, "_Kernel") as kernel:
            with self.assertRaisesRegex(observer.PiSourceObserverError, "GATE_ARGV_REQUIRED"):
                observer.arm_pi_source_observer(owned, gate_path=observer.GATE_PATH, gate_digest=PIN,
                    node_path=observer.NODE_PATH, node_digest=PIN, sources=[], bindings=self.value._bindings, deadline=2)
        kernel.assert_not_called()

    def test_initial_stop_is_acquired_not_assumed(self):
        with patch.object(observer.os, "waitpid", return_value=(PID, stopped(128, 19))) as wait:
            self.value._wait(2, initial=True)
        wait.assert_called_once_with(PID, observer.os.WNOHANG | 0x40000000)
        self.assertEqual(self.value._events[-1]["kind"], "STOP")
        self.assertEqual(self.value._stops, 1)

    def test_initial_wrong_stop_refused(self):
        with patch.object(observer.os, "waitpid", return_value=(PID, stopped(4, signal.SIGTRAP))):
            with self.assertRaisesRegex(observer.PiSourceObserverError, "PREEXEC_STOP"):
                self.value._wait(2, initial=True)

    def test_exec_keeps_ordinary_syscall_exit_pair(self):
        self.entry(221)
        self.step(event=4)
        self.assertEqual(self.value._syscall, 221)
        self.exit()
        self.assertIsNone(self.value._syscall)
        self.assertTrue(self.value._executed)

    def test_missing_exec_exit_refuses_next_entry(self):
        self.entry(221)
        self.step(event=4)
        with self.assertRaisesRegex(observer.PiSourceObserverError, "UNPAIRED"):
            self.entry(56)
        self.assertEqual(self.value._state, "REFUSED")

    def test_preexec_other_syscall_refused(self):
        with self.assertRaisesRegex(observer.PiSourceObserverError, "PREEXEC_ONLY"):
            self.entry(56)

    def test_unexpected_exec_without_entry_refused(self):
        with self.assertRaisesRegex(observer.PiSourceObserverError, "EXEC_TRANSITION"):
            self.step(event=4)

    def test_changed_node_exec_refused(self):
        self.entry(221)
        with patch.object(observer.process, "_executable_digest", return_value="sha256:" + "b" * 64):
            with self.assertRaisesRegex(observer.PiSourceObserverError, "NODE_EXEC_DIGEST"):
                self.step(event=4)

    def test_pread_completes_exact_source_range(self):
        self.execute()
        self.read_enter()
        self.exit(3)
        self.assertEqual(self.value._ranges[SOURCE], [(0, 3)])
        self.assertTrue(self.value._complete())
        self.assertEqual(self.value.observation["accounting"]["bytes_read"], 3)
        self.assertIn(19, self.value._fds)

    def test_read_uses_held_open_description_offset(self):
        self.execute()
        with patch.object(observer.os, "lseek", side_effect=[0, 3]) as seek:
            self.read_enter(number=63)
            self.exit(3)
        self.assertEqual(seek.call_count, 2)
        self.value._kernel.duplicate.assert_called_once_with(17, 8)

    def test_read_offset_race_refused(self):
        self.execute()
        with patch.object(observer.os, "lseek", side_effect=[0, 2]):
            self.read_enter(number=63)
            with self.assertRaisesRegex(observer.PiSourceObserverError, "OFFSET_CHANGED"):
                self.exit(3)
        self.assertIn(19, self.value._fds)
        self.assertEqual(self.value._ranges[SOURCE], [])

    def test_failed_read_is_retained_not_positive_coverage(self):
        self.execute()
        self.read_enter()
        self.exit(-13, True)
        self.assertFalse(self.value._complete())
        self.assertEqual(self.value.observation["accounting"]["bytes_read"], 0)
        self.assertEqual(self.value.observation["accounting"]["reads_exited"], 1)

    def test_eof_does_not_invent_source_bytes(self):
        self.execute()
        self.read_enter()
        self.exit(0)
        self.assertFalse(self.value._complete())

    def test_empty_source_still_requires_completed_read(self):
        self.value._sources = [dict(ROW, identity=dict(META, size=0))]
        self.assertFalse(self.value._complete())
        self.value._read_paths.add(SOURCE)
        self.assertTrue(self.value._complete())

    def test_partial_ranges_must_cover_all_bytes(self):
        self.execute()
        self.read_enter(count=1)
        self.exit(1)
        self.assertFalse(self.value._complete())
        self.read_enter(offset=1, count=2)
        self.exit(2)
        self.assertTrue(self.value._complete())

    def test_noninventory_descriptor_refused(self):
        self.execute()
        with patch.object(observer, "_protected_file", return_value=dict(META, inode=900)):
            with self.assertRaisesRegex(observer.PiSourceObserverError, "UNCLASSIFIED_READ"):
                self.read_enter()

    def test_read_result_beyond_requested_count_refused(self):
        self.execute()
        self.read_enter(count=1)
        with self.assertRaisesRegex(observer.PiSourceObserverError, "RETURN_BOUNDS"):
            self.exit(2)

    def test_changed_source_at_read_exit_refused(self):
        self.execute()
        self.read_enter()
        with patch.object(observer, "_hash", return_value=(PIN, META)):
            with self.assertRaisesRegex(observer.PiSourceObserverError, "SOURCE_CHANGED"):
                self.exit(3)

    def test_thread_inventory_expansion_refused(self):
        self.execute()
        with patch.object(observer.os, "listdir", return_value=[str(PID), "72"]):
            with self.assertRaisesRegex(observer.PiSourceObserverError, "THREAD_INVENTORY"):
                self.read_enter()

    def test_clone_event_retains_owned_custody(self):
        with self.assertRaises(observer.PiSourceObserverError) as raised:
            self.step(event=3)
        self.assertIs(raised.exception.observer, self.value)
        self.assertTrue(self.value._attached)
        self.assertEqual(self.value._fds, [17, 18])

    def test_unclassified_aio_is_refused(self):
        self.execute()
        with self.assertRaisesRegex(observer.PiSourceObserverError, "UNCLASSIFIED_SYSCALL"):
            self.entry(2)  # io_submit, not silently classified as ordinary.

    def test_io_uring_is_refused(self):
        self.execute()
        with self.assertRaisesRegex(observer.PiSourceObserverError, "UNSUPPORTED_SYSCALL"):
            self.entry(425)

    def test_file_backed_mapping_is_refused(self):
        self.execute()
        with self.assertRaisesRegex(observer.PiSourceObserverError, "FILE_MAPPING"):
            self.entry(222, [0, 4096, 1, 2, 8, 0])

    def test_anonymous_mapping_pairs_without_source_claim(self):
        self.execute()
        self.entry(222, [0, 4096, 1, 0x22, 2**64 - 1, 0])
        self.exit(4096)
        self.assertFalse(self.value._complete())

    def test_duplicate_exit_is_refused(self):
        self.execute()
        with self.assertRaisesRegex(observer.PiSourceObserverError, "UNPAIRED_SYSCALL_EXIT"):
            self.exit()

    def challenge(self, nonce="a" * 64, event=128, op="NONE", nr=None):
        self.value._kernel.info.return_value = (op, nr, [0] * 6 if nr else None, None, None)
        with patch.object(observer.os, "waitpid", return_value=(PID, stopped(event, signal.SIGTRAP if event else signal.SIGTRAP | 0x80))):
            issued = max(999, self.value._last_tick + 1)
            return self.value.challenge(nonce=nonce, issued_ns=issued, deadline_ns=issued + observer.CHALLENGE_NS)

    def test_challenge_acquires_fresh_interrupt_wait(self):
        self.execute()
        before = self.value._stops
        raw = self.challenge()
        self.assertEqual(raw["events"][-1]["kind"], "CHALLENGE")
        self.assertEqual(raw["events"][-2]["event"], 128)
        self.assertEqual(raw["events"][-1]["stops_after"], before + 1)
        self.assertEqual(raw["architecture"], "linux-arm64")
        calls = [row.args[0] for row in self.value._kernel.ptrace.call_args_list]
        self.assertEqual(calls[-2:], [observer._SYSCALL, observer._INTERRUPT])

    def test_challenge_entry_race_is_permanent_refusal_not_retry(self):
        self.execute()
        with self.assertRaisesRegex(observer.PiSourceObserverError, "CHALLENGE_PENDING"):
            self.challenge(event=0, op="ENTRY", nr=56)
        self.assertEqual(self.value._state, "REFUSED")

    def test_challenge_cannot_reuse_any_historical_nonce(self):
        self.execute()
        self.challenge("a" * 64)
        self.challenge("b" * 64)
        with self.assertRaisesRegex(observer.PiSourceObserverError, "FRESHNESS"):
            self.challenge("a" * 64)

    def test_challenge_deadline_cannot_expand(self):
        with self.assertRaisesRegex(observer.PiSourceObserverError, "FRESHNESS"):
            self.value.challenge(nonce="a" * 64, issued_ns=999, deadline_ns=999 + observer.CHALLENGE_NS + 1)

    def test_challenge_requires_no_pending_syscall(self):
        self.execute()
        self.entry(56)
        with self.assertRaisesRegex(observer.PiSourceObserverError, "QUIESCENT"):
            self.challenge()

    def test_owned_cleanup_does_not_close_live_tracee_handles(self):
        with patch.object(observer.native, "_exited", return_value=False), patch.object(observer.os, "close") as close:
            with self.assertRaisesRegex(observer.PiSourceObserverError, "REQUIRES_EXIT"):
                self.value.close_after_exit()
        close.assert_not_called()
        self.assertEqual(self.value._fds, [17, 18])

    def test_cleanup_after_exit_closes_only_owned_handles(self):
        with patch.object(observer.native, "_exited", return_value=True), patch.object(observer.os, "close") as close:
            self.value.close_after_exit()
        self.assertEqual([row.args[0] for row in close.call_args_list], [17, 18])
        self.assertEqual(self.value._state, "CLOSED")
        self.assertEqual(self.value._events[-1]["kind"], "CLEANUP")

    def test_cleanup_will_not_resume_ordinary_stop(self):
        self.value._last_stop_event = 0
        with self.assertRaisesRegex(observer.PiSourceObserverError, "EXIT_STOP"):
            self.value.drain_owned_exit(deadline=2)
        self.value._kernel.ptrace.assert_not_called()

    def test_cleanup_releases_only_actual_exit_event(self):
        self.value._last_stop_event = 6
        with patch.object(observer.os, "waitpid", return_value=(PID, 0)), \
             patch.object(observer.native, "_exited", return_value=True):
            self.value.drain_owned_exit(deadline=2)
        self.value._kernel.ptrace.assert_called_once_with(7, PID)
        self.assertEqual(self.value._fds, [17, 18])

    def test_ambiguous_close_cannot_retry_recycled_descriptor(self):
        with patch.object(observer.native, "_exited", return_value=True), \
             patch.object(observer.os, "close", side_effect=OSError("interrupted close")) as close:
            with self.assertRaisesRegex(observer.PiSourceObserverError, "AMBIGUOUS_NO_RETRY"):
                self.value.close_after_exit()
            attempted = close.call_count
            with self.assertRaisesRegex(observer.PiSourceObserverError, "ALREADY_ATTEMPTED"):
                self.value.close_after_exit()
            self.assertEqual(close.call_count, attempted)
        self.assertEqual(self.value._events[-1]["kind"], "REFUSED")

    def test_cleanup_retains_terminal_wait_before_handle_close(self):
        self.value._stopped = False
        with patch.object(observer.os, "waitpid", return_value=(PID, signal.SIGKILL)), \
             patch.object(observer.native, "_exited", return_value=True):
            self.value.drain_owned_exit(deadline=2)
        self.assertEqual(self.value._events[-1]["kind"], "STOP")
        self.assertEqual(self.value._events[-1]["status"], signal.SIGKILL)
        self.assertEqual(self.value._stops, 1)

    def test_acquisition_event_bound_reserves_owned_cleanup_records(self):
        self.value._events = [dict(seq=index + 1, boottime_ns=1, kind="STOP")
                              for index in range(observer.MAX_EVENTS - 8)]
        with self.assertRaisesRegex(observer.PiSourceObserverError, "EVENT_LIMIT"):
            self.value._event("STOP")
        with self.assertRaises(observer.PiSourceObserverError):
            self.value._fail(observer.PiSourceObserverError("EVENT_LIMIT"))
        self.value._last_stop_event = 6
        with patch.object(observer.os, "waitpid", return_value=(PID, 0)), \
             patch.object(observer.native, "_exited", return_value=True), patch.object(observer.os, "close"):
            self.value.drain_owned_exit(deadline=2)
            self.value.close_after_exit()
        self.assertEqual([event["kind"] for event in self.value._events[-3:]], ["REFUSED", "STOP", "CLEANUP"])
        self.assertLessEqual(len(self.value._events), observer.MAX_EVENTS)

    def native_guard_fixture(self):
        prepared = object.__new__(observer.bundle.PreparedPiBundle)
        for key, value in dict(_lease=observer.bundle._Lease(), expires_at_monotonic_ns=10**30,
                               runtime_digest=PIN, deployment_digest=PIN, executable_digest=PIN,
                               activation_id="a" * 32, manifest_digest=PIN).items():
            object.__setattr__(prepared, key, value)
        plan = object.__new__(observer.confined.PiConfinedLaunchPlan)
        for key, value in dict(prepared=prepared, _lease=observer.confined._PlanLease(),
                               profile=SimpleNamespace(runtime_digest=PIN, executable_digest=PIN),
                               runtime_inventory_digest=PIN, unit_name="owned.service", deadline=10.0,
                               activation_path=Path("/run/owned-activation.json")).items():
            object.__setattr__(plan, key, value)
        owned = observer.native._Owned(plan=plan, started=True, start_attempted=True, pid=PID,
                                       pidfd=17, start_ticks=21, invocation="abc", immutable_digest=PIN)
        self.value._owned = owned
        self.value._pins = (plan, PID, 17, 21, "abc", PIN, owned.cgroup_fd, owned.cgroup_identity,
                            plan._lease, prepared, prepared._lease)
        return owned

    def test_withdrawn_launch_lease_refuses_before_kernel_access(self):
        owned = self.native_guard_fixture()
        owned.plan._lease.active = False
        with self.assertRaisesRegex(observer.PiSourceObserverError, "WITHDRAWN_NATIVE"):
            observer.PiSourceObserver._guard(self.value, 2)

    def test_withdrawn_bundle_lease_refuses_before_kernel_access(self):
        owned = self.native_guard_fixture()
        owned.plan.prepared._lease.active = False
        with self.assertRaisesRegex(observer.PiSourceObserverError, "WITHDRAWN_NATIVE"):
            observer.PiSourceObserver._guard(self.value, 2)

    def test_original_pidfd_substitution_is_refused(self):
        owned = self.native_guard_fixture()
        owned.pidfd = 29
        with self.assertRaisesRegex(observer.PiSourceObserverError, "ORIGINAL_NATIVE"):
            observer.PiSourceObserver._guard(self.value, 2)

    def test_equal_but_replaced_plan_is_refused(self):
        owned = self.native_guard_fixture()
        original = owned.plan
        replacement = object.__new__(observer.confined.PiConfinedLaunchPlan)
        # This intentionally partial inert plan does not populate unrelated
        # dataclass slots; copy.copy would read those missing slots itself.
        for name in ("prepared", "_lease", "profile", "runtime_inventory_digest",
                     "unit_name", "deadline", "activation_path"):
            object.__setattr__(replacement, name, getattr(original, name))
        owned.plan = replacement
        with self.assertRaisesRegex(observer.PiSourceObserverError, "ORIGINAL_NATIVE"):
            observer.PiSourceObserver._guard(self.value, 2)

    def health_fixture(self):
        self.execute()
        self.read_enter()
        self.exit(3)
        owned = self.native_guard_fixture()
        self.value._producer_fd, self.value._producer_identity = 42, META
        self.value._executable_identities = {"gate": META, "node": META}
        self.value._guard = observer.PiSourceObserver._guard.__get__(self.value)
        self.mock("process.require_live_pidfd")
        self.mock("process._process_start_time", return_value=21)
        self.mock("process._require_process_status")
        self.mock("process._mount_namespace", return_value={"device": 1, "inode": 9})
        self.mock("native._unit_state", return_value={})
        self.mock("native._same_generation")
        # Proc-only fake metadata must not break unittest's traceback renderer
        # if the behavior under test fails. Keep diagnostic formatting inert.
        for name, result in (("linecache.checkcache", None), ("linecache.getlines", [])):
            item = patch(name, return_value=result)
            self.stack.append(item)
            item.start()
        self.mock("os.stat", side_effect=lambda path: SimpleNamespace(st_ino=8) if str(path).endswith("ns/time") else metadata())
        self.mock("os.waitpid", return_value=(PID, stopped(128, 5)))
        activation = dict(schema=observer.identity.ACTIVATION_SCHEMA, authority=observer.identity.ACTIVATION_AUTHORITY,
            activation_id="a" * 32, session_id="a" * 32, run_id="a" * 32, pid=PID, uid=1001, gid=1001,
            start_time_ticks=21, mount_namespace={"device": 1, "inode": 9},
            cgroup=self.value._worker["cgroup"], boot_id=self.value._clock["boot_id"], expires_at_monotonic_ns=2**62,
            **{key: PIN for key in observer.identity._PINS})
        owned.activation_raw = observer.canonical_json(activation)
        self.mock("identity.read_activation", return_value=copy.deepcopy(activation))
        return activation

    def test_health_guard_joins_real_local_custody_and_acquisition(self):
        activation = self.health_fixture()
        self.value.guard_source_health(activation=activation, deadline=2)
        self.assertEqual(self.value._events[-1]["kind"], "CHALLENGE")
        self.assertEqual(self.value._state, "HELD")
        self.assertEqual(self.value._deadline, 10.0)

    def test_health_guard_rejects_unowned_activation_bytes(self):
        activation = self.health_fixture()
        activation["pid"] += 1
        with self.assertRaisesRegex(observer.PiSourceObserverError, "OWNED_ACTIVATION_CHANGED"):
            self.value.guard_source_health(activation=activation, deadline=2)
        self.assertEqual(self.value._state, "REFUSED")

    def test_health_guard_missing_coverage_never_challenges(self):
        activation = self.health_fixture()
        self.value._read_paths.clear()
        before = self.value._stops
        with self.assertRaisesRegex(observer.PiSourceObserverError, "SOURCE_COVERAGE"):
            self.value.guard_source_health(activation=activation, deadline=2)
        self.assertEqual(self.value._stops, before)

    def test_health_guard_does_not_extend_original_launch_deadline(self):
        activation = self.health_fixture()
        object.__setattr__(self.value._owned.plan, "deadline", 9.0)
        with self.assertRaisesRegex(observer.PiSourceObserverError, "WITHDRAWN_NATIVE"):
            self.value.guard_source_health(activation=activation, deadline=2)


class SourcePrimitiveTests(unittest.TestCase):
    def test_fifo_leaf_is_nonblocking_and_closed_without_read(self):
        ancestor = metadata(st_mode=stat.S_IFDIR | 0o755)
        leaf = metadata(st_mode=stat.S_IFIFO | 0o444)
        with patch.object(observer.os, "open", side_effect=[10, 11]) as opened, \
             patch.object(observer.os, "fstat", side_effect=[ancestor, leaf]), \
             patch.object(observer.os, "close") as closed:
            with self.assertRaisesRegex(observer.PiSourceObserverError, "NOT_REGULAR"):
                observer._open_view(PID, Path("/source"))
        self.assertTrue(opened.call_args_list[-1].args[1] & observer.os.O_NONBLOCK)
        self.assertEqual([row.args[0] for row in closed.call_args_list], [11, 10])

    def test_metadata_refuses_writable_or_nonroot_or_hardlinked_sources(self):
        for changes in ({"st_mode": stat.S_IFREG | 0o644}, {"st_uid": 2}, {"st_gid": 2},
                        {"st_nlink": 2}, {"st_size": observer.MAX_FILE + 1}):
            with self.subTest(changes=changes), patch.object(observer.os, "fstat", return_value=metadata(**changes)):
                with self.assertRaises(observer.PiSourceObserverError):
                    observer._protected_file(9)

    def test_hash_uses_pread_without_shared_offset_changes(self):
        with patch.object(observer.os, "fstat", return_value=metadata()), \
             patch.object(observer.os, "pread", return_value=b"abc") as read, \
             patch.object(observer.time, "monotonic", return_value=1):
            self.assertEqual(observer._hash(9, 2), (ROW["digest"], META))
        read.assert_called_once_with(9, 3, 0)

    def test_hash_changed_identity_is_refused(self):
        with patch.object(observer.os, "fstat", side_effect=[metadata(), metadata(st_ctime_ns=13)]), \
             patch.object(observer.os, "pread", return_value=b"abc"), \
             patch.object(observer.time, "monotonic", return_value=1):
            with self.assertRaisesRegex(observer.PiSourceObserverError, "CHANGED_WHILE_HASHED"):
                observer._hash(9, 2)

    def test_kernel_entry_and_exit_abi_sizes_are_exact(self):
        kernel = object.__new__(observer._Kernel)  # Never construct CDLL.
        for operation, size in ((1, 80), (2, 33)):
            def fill(request, pid, length, pointer):
                value = ctypes.cast(pointer, ctypes.POINTER(observer._SyscallInfo)).contents
                value.op, value.arch = operation, observer._ARM64
                if operation == 1:
                    value.payload.entry.nr = 67
                return size
            kernel.ptrace = Mock(side_effect=fill)
            self.assertEqual(kernel.info(PID)[0], "ENTRY" if operation == 1 else "EXIT")

    def test_kernel_wrong_architecture_refused(self):
        kernel = object.__new__(observer._Kernel)
        def fill(request, pid, length, pointer):
            value = ctypes.cast(pointer, ctypes.POINTER(observer._SyscallInfo)).contents
            value.op, value.arch = 1, 0xC000003E
            return 80
        kernel.ptrace = Mock(side_effect=fill)
        with self.assertRaisesRegex(observer.PiSourceObserverError, "SYSCALL_ABI"):
            kernel.info(PID)

    def test_closed_or_foreign_owner_custody_refused(self):
        value = observer.PiSourceObserver(observer._SEAL)
        value._deadline, value._state = 10, "CLOSED"
        with self.assertRaisesRegex(observer.PiSourceObserverError, "CUSTODY"):
            value._budget(2)


def build_inert_source_capture():
    """Synthetic cross-lane wiring fixture; kernel/proc guards are all inert.

    Expected pins and identities are supplied before acquisition, independently
    of the resulting capture. This helper never constitutes runtime evidence.
    """
    fixture = SourceAcquisitionTests()
    fixture.setUp()
    try:
        value = fixture.value
        clock = dict(clock_id="CLOCK_BOOTTIME", boot_id="00000000-0000-0000-0000-000000000001", time_namespace_inode=8)
        inventory = observer.canonical_json(dict(schema=observer.INVENTORY_SCHEMA, sources=[ROW]))
        bindings = dict(value._bindings, source_inventory_digest="sha256:" + hashlib.sha256(inventory).hexdigest())
        worker, gate = dict(value._worker), dict(META, inode=6, mode=stat.S_IFREG | 0o555)
        value._clock, value._bindings = dict(clock), dict(bindings)
        value._event("ARMED", tasks=[PID], options=observer.OPTIONS, gate_identity=gate)
        with patch.object(observer.os, "waitpid", return_value=(PID, stopped(128, 19))):
            value._wait(2, initial=True)
        fixture.execute()
        fixture.read_enter()
        fixture.exit(3)
        issued = value._last_tick + 1
        challenge = dict(nonce="a" * 64, issued_ns=issued, deadline_ns=issued + observer.CHALLENGE_NS)
        with patch.object(observer.os, "waitpid", return_value=(PID, stopped(128, 5))):
            capture = value.challenge(**challenge)
        return dict(capture=capture, expected_bindings=bindings, expected_worker=worker, expected_clock=clock,
                    expected_gate_identity=gate, expected_challenge=challenge, boundary_boottime_ns=2000,
                    source_inventory_raw=inventory, sources={ROW["digest"]: b"abc"})
    finally:
        fixture.tearDown()


if __name__ == "__main__":
    unittest.main()
