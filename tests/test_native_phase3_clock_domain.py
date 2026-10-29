"""Inert external-observer doubles; no Linux process or clock is inspected."""

from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aragorn import native_phase3_clock_domain as subject


BOOT = "00000000-1111-2222-3333-444444444444"
WORKER = {"pid": 20, "start_time_ticks": 200, "uid": 997, "gid": 997}
BROKER = {"pid": 30, "start_time_ticks": 300, "uid": 993, "gid": 997}


class NativeClockDomainTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.records = {
            10: {"pid": 10, "start_time_ticks": 100, "uid": 0, "gid": 0},
            20: deepcopy(WORKER),
            30: deepcopy(BROKER),
        }
        self.namespaces = {10: (7, 1000), 20: (7, 1000), 30: (7, 1000)}
        self.paths = []
        self.boot = (BOOT + "\n").encode()
        self.status_override = {}
        self.fdinfo_override = {}

        def replace(owner, name, **kwargs):
            return self.stack.enter_context(patch.object(owner, name, **kwargs))

        replace(subject.sys, "platform", new="linux")
        replace(subject.os, "getpid", return_value=10)
        replace(subject.os, "geteuid", return_value=0)
        replace(subject.os, "getegid", return_value=0)
        replace(subject.threading, "get_native_id", return_value=10)
        replace(subject.time, "CLOCK_BOOTTIME", new=7, create=True)
        self.clock = replace(subject.time, "clock_gettime_ns", side_effect=[1000, 2000])
        self.pidfd = replace(
            subject.os,
            "pidfd_open",
            create=True,
            side_effect=lambda pid, flags: pid + 100,
        )
        self.open = replace(
            subject.os,
            "open",
            side_effect=lambda path, flags: int(path.split("/")[2]) + 200,
        )
        self.close = replace(subject.os, "close")
        self.liveness = replace(subject.process, "require_live_pidfd")
        self.start = replace(
            subject.process,
            "_process_start_time",
            side_effect=lambda pid: self.records[pid]["start_time_ticks"],
        )
        self.read = replace(
            subject.process, "_read_virtual_file", side_effect=self._read
        )
        self.fstat = replace(
            subject.os, "fstat", side_effect=lambda fd: self._metadata(fd - 200)
        )
        self.stat = replace(
            subject.os,
            "stat",
            side_effect=lambda path: self._metadata(int(path.split("/")[2])),
        )
        self.readlink = replace(
            subject.os,
            "readlink",
            side_effect=lambda path: (
                f"time:[{self.namespaces[int(path.split('/')[2])][1]}]"
            ),
        )

    def _metadata(self, pid):
        device, inode = self.namespaces[pid]
        return SimpleNamespace(
            st_dev=device, st_ino=inode, st_mode=stat.S_IFREG | 0o444
        )

    def _read(self, path, maximum):
        path = str(path)
        self.paths.append((path, maximum))
        if path == "/proc/sys/kernel/random/boot_id":
            return self.boot
        if path.startswith("/proc/self/fdinfo/"):
            descriptor = int(path.rsplit("/", 1)[1])
            return self.fdinfo_override.get(
                descriptor, f"Pid:\t{descriptor - 100}\n".encode()
            )
        if path.endswith("/status"):
            pid = int(path.split("/")[2])
            record = self.records[pid]
            return self.status_override.get(
                pid,
                (
                    "Name:\tinert-fixture\nUid:\t"
                    + "\t".join([str(record["uid"])] * 4)
                    + "\nGid:\t"
                    + "\t".join([str(record["gid"])] * 4)
                    + "\n"
                ).encode(),
            )
        raise AssertionError("unexpected external read: " + path)

    def observe(self, **overrides):
        return subject.observe_native_common_clock_domain(
            **{
                "expected_worker": deepcopy(WORKER),
                "expected_broker": deepcopy(BROKER),
                **overrides,
            }
        )

    def test_exact_external_record_holds_all_descriptors_and_keeps_flags_false(self):
        before = deepcopy((WORKER, BROKER))
        result = self.observe()
        self.assertEqual(result["schema"], subject.SCHEMA)
        self.assertEqual(result["authority"], subject.AUTHORITY)
        self.assertEqual(result["clock_id"], "CLOCK_BOOTTIME")
        self.assertEqual(result["boot_id"], BOOT)
        self.assertEqual(
            (result["read_started_boottime_ns"], result["read_finished_boottime_ns"]),
            (1000, 2000),
        )
        self.assertEqual(
            result["processes"],
            {
                role: self.records[pid]
                | {"time_namespace": {"device": 7, "inode": 1000}}
                for role, pid in (("collector", 10), ("worker", 20), ("broker", 30))
            },
        )
        self.assertEqual(
            set(result),
            {
                "schema",
                "authority",
                "clock_id",
                "boot_id",
                "read_started_boottime_ns",
                "read_finished_boottime_ns",
                "processes",
                "limitations",
                *subject.FALSE_FLAGS,
            },
        )
        self.assertTrue(all(result[name] is False for name in subject.FALSE_FLAGS))
        self.assertEqual(result["limitations"], list(subject.LIMITATIONS))
        self.assertEqual((WORKER, BROKER), before)
        self.assertEqual(
            [call.args[0] for call in self.close.call_args_list],
            [230, 130, 220, 120, 210, 110],
        )
        self.assertEqual(self.liveness.call_count, 9)
        self.assertEqual(self.clock.call_count, 2)
        self.assertTrue(all(call.args == (7,) for call in self.clock.call_args_list))
        self.assertFalse(
            any(
                "timens_offsets" in path or "time_for_children" in path
                for path, _ in self.paths
            )
        )
        for call in self.open.call_args_list:
            self.assertTrue(call.args[0].endswith("/ns/time"))
            self.assertEqual(call.args[1] & subject.os.O_NOFOLLOW, 0)

    def test_producer_preserves_independently_unequal_active_namespaces(self):
        self.namespaces[30] = (8, 2000)
        result = self.observe()
        self.assertNotEqual(
            result["processes"]["worker"]["time_namespace"],
            result["processes"]["broker"]["time_namespace"],
        )

    def test_invalid_expected_records_refuse_before_clock_or_descriptor_open(self):
        for key, value in (
            ("pid", True),
            ("start_time_ticks", 0),
            ("uid", 0),
            ("gid", -1),
            ("pid", 2**63),
        ):
            with (
                self.subTest(key=key, value=value),
                self.assertRaises(subject.NativeClockDomainError),
            ):
                self.observe(expected_worker=WORKER | {key: value})
        for value in (WORKER | {"extra": 1}, {"pid": 20}, None):
            with (
                self.subTest(value=value),
                self.assertRaises(subject.NativeClockDomainError),
            ):
                self.observe(expected_worker=value)
        for value in (WORKER | {"pid": 10}, WORKER | {"pid": 30}):
            with self.assertRaises(subject.NativeClockDomainError):
                self.observe(expected_worker=value)
        self.clock.assert_not_called()
        self.pidfd.assert_not_called()

    def test_linux_root_main_thread_requirements_have_no_fallback(self):
        for owner, name, value in (
            (subject.sys, "platform", "darwin"),
            (subject.os, "geteuid", 1000),
            (subject.os, "getegid", 1000),
            (subject.threading, "get_native_id", 11),
        ):
            kwargs = {"new": value} if name == "platform" else {"return_value": value}
            with (
                self.subTest(name=name),
                patch.object(owner, name, **kwargs),
                self.assertRaises(subject.NativeClockDomainError),
            ):
                self.observe()
        self.clock.assert_not_called()
        self.pidfd.assert_not_called()

    def test_all_four_account_ids_and_fdinfo_must_match(self):
        for raw in (
            b"Uid:\t997 997 997 0\nGid:\t997 997 997 997\n",
            b"Uid:\t997 997 997 997\nUid:\t997 997 997 997\nGid:\t997 997 997 997\n",
            b"Uid:\t997 997 997 997\n",
            b"Uid:\t+997 997 997 997\nGid:\t997 997 997 997\n",
        ):
            self.clock.side_effect = [1000, 2000]
            self.status_override[20] = raw
            with (
                self.subTest(raw=raw),
                self.assertRaises(subject.NativeClockDomainError),
            ):
                self.observe()
        self.status_override.clear()
        self.clock.side_effect = [1000, 2000]
        self.fdinfo_override[120] = b"Pid:\t30\n"
        with self.assertRaises(subject.NativeClockDomainError):
            self.observe()

    def test_epoch_boot_and_liveness_changes_refuse_and_close(self):
        original_snapshot = subject._snapshot
        calls = {}

        def changed_snapshot(pid):
            result = original_snapshot(pid)
            calls[pid] = calls.get(pid, 0) + 1
            if pid == 20 and calls[pid] == 2:
                result["start_time_ticks"] += 1
            return result

        with (
            patch.object(subject, "_snapshot", side_effect=changed_snapshot),
            self.assertRaises(subject.NativeClockDomainError),
        ):
            self.observe()
        self.assertEqual(self.close.call_count, 6)
        self.clock.side_effect = [1000, 2000]
        with (
            patch.object(subject, "_boot", side_effect=[BOOT, "f" * 36]),
            self.assertRaises(subject.NativeClockDomainError),
        ):
            self.observe()
        self.clock.side_effect = [1000, 2000]
        self.liveness.side_effect = RuntimeError("inert exited PIDFD")
        with self.assertRaises(subject.NativeClockDomainError):
            self.observe()

    def test_held_named_and_magic_link_namespace_joins_are_required(self):
        for fault in ("named", "magic", "change", "inode", "device", "type"):
            self.clock.side_effect = [1000, 2000]
            with self.subTest(fault=fault), ExitStack() as local:
                if fault == "named":
                    local.enter_context(
                        patch.object(
                            subject.os,
                            "stat",
                            return_value=SimpleNamespace(
                                st_dev=7, st_ino=9999, st_mode=stat.S_IFREG
                            ),
                        )
                    )
                elif fault == "magic":
                    local.enter_context(
                        patch.object(subject.os, "readlink", return_value="mnt:[1000]")
                    )
                elif fault == "change":
                    original = subject._namespace
                    count = [0]

                    def changed(pid, fd):
                        value = original(pid, fd)
                        count[0] += 1
                        if count[0] > 3:
                            value["inode"] += 1
                        return value

                    local.enter_context(
                        patch.object(subject, "_namespace", side_effect=changed)
                    )
                else:
                    info = {"st_dev": 7, "st_ino": 1000, "st_mode": stat.S_IFREG}
                    info[
                        {"inode": "st_ino", "device": "st_dev", "type": "st_mode"}[
                            fault
                        ]
                    ] = {"inode": True, "device": -1, "type": stat.S_IFDIR}[fault]
                    local.enter_context(
                        patch.object(
                            subject.os, "fstat", return_value=SimpleNamespace(**info)
                        )
                    )
                with self.assertRaises(subject.NativeClockDomainError):
                    self.observe()

    def test_clock_values_are_exact_bounded_and_strictly_increasing(self):
        for values in (
            [True, 2000],
            [-1, 2000],
            [2**63, 2000],
            [1000, 1000],
            [1000, 999],
            [1000, 2**63],
        ):
            self.clock.side_effect = values
            with (
                self.subTest(values=values),
                self.assertRaises(subject.NativeClockDomainError),
            ):
                self.observe()

    def test_clock_samples_have_held_collector_domain_readbacks_on_both_sides(self):
        for changed_at in (1, 2):
            self.namespaces[10] = (7, 1000)
            self.pidfd.reset_mock()
            self.open.reset_mock()
            calls = [0]

            def changed_clock(clock_id):
                calls[0] += 1
                self.assertEqual(self.pidfd.call_count, 3)
                self.assertEqual(self.open.call_count, 3)
                self.assertEqual(clock_id, 7)
                if calls[0] == changed_at:
                    self.namespaces[10] = (7, 9999)
                return calls[0] * 1000

            self.clock.side_effect = changed_clock
            with (
                self.subTest(changed_at=changed_at),
                self.assertRaises(subject.NativeClockDomainError),
            ):
                self.observe()

    def test_all_descriptors_close_on_interrupt_and_close_failure(self):
        original_namespace = subject._namespace
        count = [0]

        def interrupt(pid, fd):
            count[0] += 1
            if count[0] == 4:
                raise KeyboardInterrupt("inert interruption")
            return original_namespace(pid, fd)

        with (
            patch.object(subject, "_namespace", side_effect=interrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            self.observe()
        self.assertEqual(self.close.call_count, 6)
        self.close.reset_mock()
        self.clock.side_effect = [1000, 2000]
        self.close.side_effect = [
            OSError("inert first close failure"),
            None,
            None,
            None,
            None,
            None,
        ]
        with self.assertRaises(subject.NativeClockDomainError):
            self.observe()
        self.assertEqual(self.close.call_count, 6)


if __name__ == "__main__":
    unittest.main()
