"""Inert held-sink syscall doubles, not live denial or filesystem evidence."""

from contextlib import ExitStack
from copy import deepcopy
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aragorn import native_phase3_denied_create_sink as subject


CONTAINER = "c" * 64
ACCOUNTS = {"broker_uid": 993, "broker_gid": 993, "runtime_gid": 997}
SOURCE = b"inert fixed sink source"
SOURCE_PIN = subject.protected._digest(SOURCE)
DESCRIPTOR = {
    "schema": "aragorn/runtime-protected-path/v1",
    "root_device": 7,
    "root_inode": 114,
    "target_name": "runtime-worker-qualified.txt",
}


def metadata(fd, *, mode=0o755, uid=0, gid=0):
    return SimpleNamespace(
        st_dev=7,
        st_ino=fd + 100,
        st_mode=stat.S_IFDIR | mode,
        st_uid=uid,
        st_gid=gid,
        st_nlink=2,
        st_size=4096,
        st_mtime_ns=1000,
        st_ctime_ns=1000,
    )


class _Entries:
    def __init__(self, owner, fd):
        self.owner, self.fd, self.reads = owner, fd, 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.owner.scan_exits.append(self.fd)

    def __iter__(self):
        return self

    def __next__(self):
        self.reads += 1
        self.owner.scan_reads.append((self.fd, self.reads))
        if self.owner.nonempty[self.owner.scan_roots[self.fd]]:
            return SimpleNamespace(name="PRIVATE_NAME_MUST_NOT_BE_RETAINED")
        raise StopIteration


class NativeDeniedCreateSinkTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.meta = {fd: metadata(fd) for fd in range(10, 16)}
        self.meta[14] = metadata(14, mode=0o710, uid=993, gid=997)
        self.meta[15] = metadata(15, mode=0o700, uid=993, gid=993)
        self.names = {
            (10, "."): 10,
            (10, "var"): 11,
            (11, "lib"): 12,
            (12, "aragorn-runtime-action"): 13,
            (13, "protected"): 14,
            (13, "staging"): 15,
        }
        self.nonempty = {14: False, 15: False}
        self.target = None
        self.scan_roots, self.scan_exits, self.scan_reads = {}, [], []
        self.next_scan = 100
        self.source_metadata = {
            "bytes": len(SOURCE),
            "digest": SOURCE_PIN,
            "identity": [
                7,
                300,
                stat.S_IFREG | 0o444,
                0,
                0,
                1,
                len(SOURCE),
                1000,
                1000,
            ],
        }

        def replace(owner, name, **kwargs):
            return self.stack.enter_context(patch.object(owner, name, **kwargs))

        replace(subject.sys, "platform", new="linux")
        replace(subject.os, "getpid", return_value=123)
        replace(subject.os, "geteuid", return_value=0)
        replace(subject.os, "getegid", return_value=0)
        replace(subject.threading, "get_native_id", return_value=123)
        self.accounts = replace(subject, "_accounts", return_value=deepcopy(ACCOUNTS))
        self.proc = replace(
            subject.process,
            "_read_virtual_file",
            return_value=f"0::/docker/{CONTAINER}/init.scope\n".encode(),
        )
        self.epoch = replace(subject.process, "_process_start_time", return_value=100)
        self.live = replace(subject.process, "require_live_pidfd")
        self.pidfd = replace(subject.os, "pidfd_open", return_value=9, create=True)
        self.open = replace(subject.os, "open", side_effect=self._open)
        self.stat = replace(subject.os, "stat", side_effect=self._stat)
        self.fstat = replace(
            subject.os,
            "fstat",
            side_effect=lambda fd: self.meta[self.scan_roots.get(fd, fd)],
        )
        self.close = replace(subject.os, "close")
        self.scandir = replace(
            subject.os, "scandir", side_effect=lambda fd: _Entries(self, fd)
        )
        self.source_read = replace(
            subject.protected,
            "_read_at",
            side_effect=lambda *_a, **_k: (SOURCE, deepcopy(self.source_metadata)),
        )

    def _open(self, path, flags, *, dir_fd=None):
        self.assertEqual(flags, subject._FLAGS)
        if path == "/":
            self.assertIsNone(dir_fd)
            return 10
        if path == ".":
            self.assertIn(dir_fd, (14, 15))
            self.next_scan += 1
            self.scan_roots[self.next_scan] = dir_fd
            return self.next_scan
        return self.names[(dir_fd, path)]

    def _stat(self, name, *, dir_fd, follow_symlinks):
        self.assertFalse(follow_symlinks)
        if name == subject.TARGET_NAME:
            self.assertEqual(dir_fd, 14)
            if self.target is None:
                raise FileNotFoundError
            return self.target
        if name == ".":
            return self.meta[dir_fd]
        return self.meta[self.names[(dir_fd, name)]]

    def hold(self, **changes):
        return subject.hold_native_denied_create_sink(
            **{
                "expected_container_id": CONTAINER,
                "expected_path_descriptor": deepcopy(DESCRIPTOR),
                "expected_source_digest": SOURCE_PIN,
                "expected_accounts": deepcopy(ACCOUNTS),
                **changes,
            }
        )

    def test_fixed_pair_holds_descriptors_and_uses_fresh_streams(self):
        with self.hold() as session:
            before = deepcopy(session.before)
            self.assertEqual(self.close.call_count, 2)  # only temporary scan FDs
            after = session.after()
            self.assertEqual(self.close.call_count, 4)
        self.assertEqual(before["phase"], "BEFORE")
        self.assertEqual(after["phase"], "AFTER")
        self.assertEqual(before | {"phase": "AFTER"}, after)
        self.assertEqual(before["path_descriptor"], DESCRIPTOR)
        self.assertEqual(before["observer_source"], self.source_metadata)
        self.assertEqual(
            before["target"],
            {"name": subject.TARGET_NAME, "status": "ABSENT", "identity": None},
        )
        self.assertEqual(
            before["directories"]["protected"]["identity"],
            [7, 114, stat.S_IFDIR | 0o710, 993, 997],
        )
        self.assertEqual(
            before["directories"]["staging"]["identity"],
            [7, 115, stat.S_IFDIR | 0o700, 993, 993],
        )
        self.assertTrue(
            all(
                before[key] is False and after[key] is False
                for key in subject.FALSE_FLAGS
            )
        )
        self.assertEqual(before["limitations"], list(subject.LIMITATIONS))
        self.assertEqual(self.scan_roots, {101: 14, 102: 15, 103: 14, 104: 15})
        self.assertEqual(self.scan_exits, [101, 102, 103, 104])
        self.assertEqual(self.scan_reads, [(101, 1), (102, 1), (103, 1), (104, 1)])
        self.assertEqual(
            [call.args[0] for call in self.close.call_args_list][-7:],
            [15, 14, 13, 12, 11, 10, 9],
        )
        self.pidfd.assert_called_once_with(1, 0)
        self.assertEqual(self.source_read.call_count, 5)

    def test_context_attempts_after_once_on_primary_driver_failure(self):
        with self.assertRaisesRegex(RuntimeError, "primary workload failure"):
            with self.hold() as session:
                raise RuntimeError("primary workload failure")
        self.assertEqual(session.after_observation["phase"], "AFTER")
        self.assertEqual(session.failures, [])
        self.assertEqual(self.scandir.call_count, 4)

    def test_nonempty_after_and_dangling_target_are_observations_not_absence(self):
        with self.hold() as session:
            self.nonempty[14] = self.nonempty[15] = True
            self.target = metadata(88, mode=0o777, uid=993, gid=997)
            self.target.st_mode = stat.S_IFLNK | 0o777
            after = session.after()
        for row in after["directories"].values():
            self.assertFalse(row["empty"])
            self.assertFalse(row["scan_complete"])
            self.assertEqual(row["entry_count_lower_bound"], 1)
        self.assertEqual(after["target"]["status"], "PRESENT")
        self.assertTrue(stat.S_ISLNK(after["target"]["identity"][2]))
        self.assertNotIn(b"PRIVATE_NAME", subject.canonical_json(after))
        self.assertTrue(all(reads == 1 for _, reads in self.scan_reads))

    def test_existing_sink_before_refuses_without_yield_or_repair(self):
        self.nonempty[15] = True
        entered = False
        with self.assertRaisesRegex(
            subject.NativeDeniedCreateSinkError, "FIXED_SINK_NOT_FRESH"
        ):
            with self.hold():
                entered = True
        self.assertFalse(entered)
        self.assertEqual(
            [call.args[0] for call in self.close.call_args_list][-7:],
            [15, 14, 13, 12, 11, 10, 9],
        )

    def test_after_cannot_retry_or_run_after_close(self):
        with self.hold() as session:
            session.after()
            with self.assertRaisesRegex(
                subject.NativeDeniedCreateSinkError, "SINK_AFTER_NOT_ONCE"
            ):
                session.after()
        with self.assertRaises(subject.NativeDeniedCreateSinkError):
            session.after()
        self.assertEqual(self.scandir.call_count, 4)

    def test_named_directory_replacement_is_refused_and_every_fd_closed(self):
        with self.assertRaises(subject.NativeDeniedCreateSinkError):
            with self.hold() as session:
                self.meta[99] = metadata(99, mode=0o710, uid=993, gid=997)
                self.names[(13, "protected")] = 99
                session.after()
        self.assertIn("SINK_AFTER_REFUSED", session.failures)
        self.assertIn("SINK_FINAL_CUSTODY_REFUSED", session.failures)
        self.assertEqual(self.scandir.call_count, 2)
        self.assertEqual(
            [call.args[0] for call in self.close.call_args_list][-7:],
            [15, 14, 13, 12, 11, 10, 9],
        )

    def test_descriptor_account_permission_and_environment_refusals(self):
        for changed in (
            {"expected_path_descriptor": DESCRIPTOR | {"root_inode": 999}},
            {"expected_path_descriptor": DESCRIPTOR | {"target_name": "arbitrary.txt"}},
            {"expected_path_descriptor": DESCRIPTOR | {"root_inode": True}},
            {"expected_accounts": ACCOUNTS | {"broker_uid": True}},
            {"expected_container_id": "../other"},
        ):
            with (
                self.subTest(changed=changed),
                self.assertRaises(subject.NativeDeniedCreateSinkError),
            ):
                with self.hold(**changed):
                    self.fail("invalid session yielded")
        self.meta[15].st_mode = stat.S_IFDIR | 0o710
        with self.assertRaises(subject.NativeDeniedCreateSinkError):
            with self.hold():
                self.fail("unsafe staging yielded")
        self.meta[15].st_mode = stat.S_IFDIR | 0o700
        self.proc.return_value = b"0::/init.scope\n"
        with self.assertRaises(subject.NativeDeniedCreateSinkError):
            with self.hold():
                self.fail("unowned session yielded")

    def test_source_identity_change_is_not_hidden_by_mutating_public_before(self):
        with self.assertRaises(subject.NativeDeniedCreateSinkError):
            with self.hold() as session:
                self.source_metadata["identity"][1] += 1
                session.before["observer_source"] = deepcopy(self.source_metadata)
                session.after()
        self.assertIn("SINK_AFTER_REFUSED", session.failures)
        self.assertIn("SINK_FINAL_SOURCE_REFUSED", session.failures)

    def test_all_closes_attempted_and_cleanup_preserves_primary(self):
        def close(fd):
            if fd in (9, 12, 15):
                raise OSError("private cleanup detail")

        self.close.side_effect = close
        with self.assertRaisesRegex(RuntimeError, "PRIMARY") as caught:
            with self.hold() as session:
                raise RuntimeError("PRIMARY")
        self.assertEqual(session.after_observation["phase"], "AFTER")
        self.assertIn("SINK_DESCRIPTOR_CLOSE_REFUSED", session.failures)
        self.assertEqual(
            caught.exception._native_sink_failures,
            ("SINK_DESCRIPTOR_CLOSE_REFUSED",) * 3,
        )
        self.assertEqual(
            [call.args[0] for call in self.close.call_args_list][-7:],
            [15, 14, 13, 12, 11, 10, 9],
        )

    def test_fresh_scan_close_failure_refuses_and_closes_outer_descriptors(self):
        self.close.side_effect = lambda fd: (
            (_ for _ in ()).throw(OSError("private")) if fd == 101 else None
        )
        with self.assertRaisesRegex(
            subject.NativeDeniedCreateSinkError, "SINK_SCAN_CLOSE_REFUSED"
        ):
            with self.hold():
                self.fail("failed scan yielded")
        self.assertEqual(self.scan_reads, [(101, 1)])
        self.assertEqual(self.scan_exits, [101])
        self.assertEqual(
            [call.args[0] for call in self.close.call_args_list][-7:],
            [15, 14, 13, 12, 11, 10, 9],
        )

    def test_nested_scan_and_outer_close_failures_are_both_retained(self):
        self.scandir.side_effect = RuntimeError("INNER_PRIMARY")

        def close(fd):
            if fd in (101, 12):
                raise OSError("private cleanup detail")

        self.close.side_effect = close
        with self.assertRaisesRegex(RuntimeError, "INNER_PRIMARY") as caught:
            with self.hold():
                self.fail("failed scan yielded")
        self.assertEqual(
            caught.exception._native_sink_failures,
            ("SINK_DESCRIPTOR_CLOSE_REFUSED",) * 2,
        )
        self.assertEqual(
            [call.args[0] for call in self.close.call_args_list],
            [101, 15, 14, 13, 12, 11, 10, 9],
        )


if __name__ == "__main__":
    unittest.main()
