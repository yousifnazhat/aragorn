"""Inert acquisition fixtures; no ptrace, tasks, services, sockets or live files."""

import copy
import hashlib
import itertools
import queue
import stat
import struct
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from contextlib import ExitStack

from aragorn import pi_core_source_observer as base
from aragorn import pi_core_node_source_observer as node


PIN = "sha256:" + "a" * 64
PATH = "/opt/aragorn/pi-runtime/pi-core/entrypoint.js"
LOADER = "/usr/lib/libc.so.6"


def profile():
    return dict(schema=node.PROFILE_SCHEMA, pins={key: PIN for key in node._PINS},
                sources=[dict(path=PATH, digest=PIN)], required_sources=[PATH],
                loader_files=[dict(path=LOADER, digest=PIN)])


def metadata(**changes):
    value = dict(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o644, st_nlink=1,
                 st_uid=0, st_gid=0, st_size=3, st_mtime_ns=4, st_ctime_ns=5, st_rdev=0)
    value.update(changes)
    return SimpleNamespace(**value)


def task(**changes):
    value = dict(start_ticks=11, stopped=True, joined=True, call=None, stop_seq=1, stop_event=128)
    value.update(changes)
    return value


def build_inert_node_source_capture():
    """Use producer transitions with an inert kernel, never a live tracee.

    The caller stores blobs in its own CAS and supplies that CAS to the separate
    consumer. No PASS record is constructed or accepted as acquisition proof.
    """
    source_bytes, loader_bytes = b"abc", b"\x7fELF"
    digest = lambda raw: "sha256:" + hashlib.sha256(raw).hexdigest()
    source_meta = base._file_identity(metadata(st_mode=stat.S_IFREG | 0o444))
    loader_meta = base._file_identity(metadata(st_ino=3, st_size=4, st_mode=stat.S_IFREG | 0o555))
    gate_meta = base._file_identity(metadata(st_ino=4, st_size=1, st_mode=stat.S_IFREG | 0o555))
    node_meta = base._file_identity(metadata(st_ino=5, st_size=1, st_mode=stat.S_IFREG | 0o555))
    source = dict(path=PATH, digest=digest(source_bytes), identity=source_meta, readonly_view=True)
    loader = dict(path=LOADER, digest=digest(loader_bytes), identity=loader_meta, readonly_view=True)
    source_raw = base.canonical_json(dict(schema=node.SOURCE_SCHEMA, sources=[source]))
    loader_raw = base.canonical_json(dict(schema=node.LOADER_SCHEMA, loaders=[loader]))
    selected = profile()
    selected["sources"][0]["digest"] = source["digest"]
    selected["loader_files"][0]["digest"] = loader["digest"]
    selected["pins"].update(source_inventory_digest=digest(source_raw), loader_inventory_digest=digest(loader_raw))
    profile_raw = base.canonical_json(selected)
    owned = SimpleNamespace(pid=71, listener=None)
    session = node._NodeSession(owned, selected, 10.0, 15.0)
    value = session.observer
    value._deadline, value._pidfd = 10.0, 17
    value._kernel = Mock()
    value._kernel.duplicate.return_value = 19
    value._kernel.message.return_value = 71
    value._sources, value._ranges = [source], {PATH: []}
    value._bindings = {**selected["pins"], "profile_digest": digest(profile_raw),
                       "runtime_digest": PIN, "deployment_digest": PIN}
    value._worker = dict(pid=71, start_ticks=11, uid=1001, gid=1002,
                        cgroup="/owned.scope", unit="owned.scope", invocation_id="a" * 32)
    value._clock = dict(boot_id="00000000-0000-0000-0000-000000000001", clock_id="CLOCK_BOOTTIME",
                       time_namespace_inode=22)
    value._executable_identities = {"gate": gate_meta, "node": node_meta}
    session.loaders = [loader]
    session.tasks = {71: task(stopped=False, stop_seq=None)}
    session._inventory = Mock(return_value=[71])
    pending = []

    def kernel_wait(tid, options):
        op, number, arguments, result, error, event, sig = pending.pop(0)
        value._kernel.info.return_value = (op, number, arguments, result, error)
        return tid, (event << 16) | (sig << 8) | 127

    def acquire(op="NONE", number=None, arguments=None, result=None, error=None, event=0, initial=False):
        if not initial:
            session._resume(71)
        pending.append((op, number, arguments, result, error, event, 5 if event else 133))
        session._wait_one(71)
        session._handle(session.pending_events.pop(0), 2.0)

    with ExitStack() as stack:
        stack.enter_context(patch.object(node.time, "monotonic", return_value=1.0))
        stack.enter_context(patch.object(base, "_tick", side_effect=itertools.count(100)))
        stack.enter_context(patch.object(node.os, "WIFSTOPPED", side_effect=lambda status: status & 255 == 127))
        stack.enter_context(patch.object(node.os, "waitpid", side_effect=kernel_wait))
        stack.enter_context(patch.object(node.os, "fstat", return_value=metadata(st_mode=stat.S_IFREG | 0o444)))
        stack.enter_context(patch.object(node.os, "stat", return_value=metadata(st_ino=5, st_size=1, st_mode=stat.S_IFREG | 0o555)))
        stack.enter_context(patch.object(node.os, "close"))
        stack.enter_context(patch.object(node, "_readonly", return_value=source_meta))
        stack.enter_context(patch.object(node, "_hash_readonly", return_value=(source["digest"], source_meta)))
        stack.enter_context(patch.object(base.process, "_executable_digest", return_value=PIN))
        session._event("ARMED", tasks=[71], options=base.OPTIONS, gate_identity=gate_meta)
        acquire(event=128, initial=True)
        session._barrier(2.0)
        stdio = dict(device=2, inode=6, mode=stat.S_IFCHR | 0o666)
        session._event("STDIO", descriptors=[dict(fd=fd, identity=stdio, rdev=259) for fd in range(3)], epoch=session.epoch)
        acquire(op="EXIT", result=0, error=False)
        acquire(op="ENTRY", number=221, arguments=[0] * 6)
        acquire(event=4)
        acquire(op="EXIT", result=0, error=False)
        # _handle performs the real producer's focus-only read interval and
        # consumes this queued actual EXIT through _exclusive_exit/_wait_one.
        session._resume(71)
        pending.extend([
            ("ENTRY", 67, [8, 4096, 3, 0, 0, 0], None, None, 0, 133),
            ("EXIT", None, None, 3, False, 0, 133),
        ])
        session._wait_one(71)
        session._handle(session.pending_events.pop(0), 2.0)
        issued = base._tick()
        challenge = dict(nonce="c" * 64, issued_ns=issued, deadline_ns=issued + base.CHALLENGE_NS)
        pending.append(("NONE", None, None, None, None, 128, 5))
        session._challenge(**challenge)
        record = session._snapshot()
    arguments = dict(expected_bindings=copy.deepcopy(value._bindings), expected_worker=copy.deepcopy(value._worker),
                     expected_clock=copy.deepcopy(value._clock), expected_gate_identity=gate_meta,
                     expected_profile_raw=profile_raw, source_inventory_raw=source_raw, loader_inventory_raw=loader_raw,
                     expected_root_peer=(9000, 0, 0), expected_root_endpoints=("/run/aragorn/request.sock",),
                     expected_challenge=challenge, boundary_boottime_ns=record["events"][-1]["boottime_ns"] + 1)
    return dict(record=record, arguments=arguments,
                blobs=[source_bytes, loader_bytes, source_raw, loader_raw, profile_raw])


class NodeAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(node.time, "monotonic", return_value=1.0).start()
        patch.object(base, "_tick", side_effect=itertools.count(100)).start()
        patch.object(node.os, "WIFSTOPPED", side_effect=lambda value: value & 255 == 127).start()
        self.owned = SimpleNamespace(pid=71, listener=None,
            plan=SimpleNamespace(worker_uid=1001, worker_gid=1002, profile=SimpleNamespace(cgroup="/owned")))
        self.session = node._NodeSession(self.owned, profile(), 10.0, 15.0)
        self.value = self.session.observer
        self.value._deadline = 10.0
        self.value._kernel = Mock()
        self.value._pidfd = 17
        self.value._kernel.duplicate.return_value = 19
        self.value._executed = True
        self.session.tasks = {71: task()}
        self.session._inventory = Mock(return_value=[71])
        self.session._barrier = Mock(return_value=[dict(pid=71, start_ticks=11)])
        self.session._budget = Mock(return_value=10.0)
        self.meta = base._file_identity(metadata())
        self.row = dict(path=PATH, digest=PIN, identity=self.meta, readonly_view=True)
        self.value._sources = [self.row]
        self.value._ranges = {PATH: []}

    def entry(self, nr, args=None, pid=71):
        row = dict(pid=pid, seq=7, event=0, status=(133 << 8) | 127,
                   op="ENTRY", syscall=nr, args=args or [0] * 6, result=None, is_error=None)
        self.session._handle(row, 2.0)
        return row

    def exit(self, result=0, error=False, pid=71):
        row = dict(pid=pid, seq=8, event=0, status=(133 << 8) | 127,
                   op="EXIT", syscall=None, args=None, result=result, is_error=error)
        self.session._handle(row, 2.0)
        return row

    def test_profile_is_canonical_copy(self):
        original = profile()
        result = node.validate_node_profile(original)
        original["required_sources"].append("/other")
        self.assertEqual(result["required_sources"], [PATH])

    def test_profile_rejects_deployment_cycle_pin(self):
        value = profile(); value["pins"]["deployment_digest"] = PIN
        with self.assertRaisesRegex(base.PiSourceObserverError, "NODE_PROFILE"):
            node.validate_node_profile(value)

    def test_profile_rejects_unlisted_required_source(self):
        value = profile(); value["required_sources"] = ["/other"]
        with self.assertRaisesRegex(base.PiSourceObserverError, "REQUIRED"):
            node.validate_node_profile(value)

    def test_profile_rejects_source_loader_path_alias(self):
        value = profile(); value["loader_files"][0]["path"] = PATH
        with self.assertRaisesRegex(base.PiSourceObserverError, "ALIAS"):
            node.validate_node_profile(value)

    def test_profile_rejects_duplicate_inventory(self):
        value = profile(); value["sources"] *= 2
        with self.assertRaisesRegex(base.PiSourceObserverError, "DUPLICATE"):
            node.validate_node_profile(value)

    def test_factory_profile_cannot_change_required_subset_of_held_plan(self):
        selected = profile()
        self.owned.plan.source_observation = copy.deepcopy(selected)
        self.owned.plan.source_observation_digest = base.canonical_digest(selected)
        selected["required_sources"] = []
        with self.assertRaisesRegex(base.PiSourceObserverError, "HELD_PROFILE"):
            node._profile_binding(self.owned, selected, base.canonical_digest(selected))

    def test_root_write_bit_requires_actual_readonly_view(self):
        with patch.object(node.os, "fstat", return_value=metadata()), \
             patch.object(node.os, "fstatvfs", return_value=SimpleNamespace(f_flag=0)):
            with self.assertRaisesRegex(base.PiSourceObserverError, "READONLY"):
                node._readonly(19)

    def test_root_write_bit_allowed_only_on_readonly_view(self):
        with patch.object(node.os, "fstat", return_value=metadata()), \
             patch.object(node.os, "fstatvfs", return_value=SimpleNamespace(f_flag=node.os.ST_RDONLY)):
            self.assertEqual(node._readonly(19), self.meta)

    def test_group_write_refused_even_on_readonly_view(self):
        with patch.object(node.os, "fstat", return_value=metadata(st_mode=stat.S_IFREG | 0o664)), \
             patch.object(node.os, "fstatvfs", return_value=SimpleNamespace(f_flag=node.os.ST_RDONLY)):
            with self.assertRaisesRegex(base.PiSourceObserverError, "READONLY"):
                node._readonly(19)

    def test_source_file_size_bound_is_not_loader_bound(self):
        info = metadata(st_size=base.MAX_FILE + 1)
        with patch.object(node.os, "fstat", return_value=info), \
             patch.object(node.os, "fstatvfs", return_value=SimpleNamespace(f_flag=node.os.ST_RDONLY)):
            with self.assertRaises(base.PiSourceObserverError): node._readonly(19)
            self.assertEqual(node._readonly(19, base.process._MAX_EXECUTABLE_BYTES)["size"], info.st_size)

    def test_tracer_identity_uses_owner_thread_not_process(self):
        self.value._thread = 99
        raw = b"Tgid:\t71\nPid:\t71\nTracerPid:\t99\nUid:\t1001 1001 1001 1001\nGid:\t1002 1002 1002 1002\n"
        with patch.object(base.process, "_read_virtual_file", return_value=raw), \
             patch.object(base.process, "_process_cgroup", return_value="/owned"), \
             patch.object(base.process, "_mount_namespace", return_value="mnt:3"), \
             patch.object(base.process, "_process_start_time", return_value=11), \
             patch.object(node.os, "getpid", return_value=90):
            self.assertEqual(self.session._tid_identity(71), 11)

    def test_different_saved_worker_uid_refused(self):
        self.value._thread = 99
        raw = b"Tgid:\t71\nPid:\t71\nTracerPid:\t99\nUid:\t1001 1001 0 1001\nGid:\t1002 1002 1002 1002\n"
        with patch.object(base.process, "_read_virtual_file", return_value=raw):
            with self.assertRaisesRegex(base.PiSourceObserverError, "CREDENTIALS"):
                self.session._tid_identity(71)

    def test_readv_uses_observed_iovec_total(self):
        raw = struct.pack("<QQQQ", 4096, 2, 8192, 3)
        self.session._peek = Mock(return_value=raw)
        self.assertEqual(self.session._read_arguments(71, dict(nr=65, args=[8, 2048, 2, 0, 0, 0])), (8, 5, raw.hex()))
        self.session._peek.assert_called_once_with(71, 2048, 32)

    def test_readv_bound_refuses_before_memory_acquisition(self):
        self.session._peek = Mock()
        with self.assertRaisesRegex(base.PiSourceObserverError, "IOV"):
            self.session._read_arguments(71, dict(nr=65, args=[8, 2048, 129, 0, 0, 0]))
        self.session._peek.assert_not_called()

    def test_preadv_high_offset_refused(self):
        self.session._peek = Mock(return_value=struct.pack("<QQ", 4096, 3))
        with self.assertRaisesRegex(base.PiSourceObserverError, "OFFSET_HIGH"):
            self.session._read_arguments(71, dict(nr=69, args=[8, 2048, 1, 0, 1, 0]))

    def test_memory_peek_requires_all_threads_held(self):
        self.session.tasks[72] = task(stopped=False)
        with self.assertRaisesRegex(base.PiSourceObserverError, "MEMORY_CUSTODY"):
            self.session._peek(71, 4096, 16)
        self.value._kernel.ptrace.assert_not_called()

    def test_successful_source_read_completes_required_delivery(self):
        self.session._exclusive_exit = Mock(return_value=dict(result=3, is_error=False))
        with patch.object(node.os, "fstat", return_value=metadata()), \
             patch.object(node, "_readonly", return_value=self.meta), \
             patch.object(node, "_hash_readonly", return_value=(PIN, self.meta)), \
             patch.object(node.os, "close"):
            self.session._file_read(71, dict(nr=67, args=[8, 4096, 3, 0, 0, 0], seq=7), 2.0)
        self.assertTrue(self.session._complete())
        self.assertEqual([row["kind"] for row in self.value._events], ["READ_ENTER", "READ_EXIT"])

    def test_failed_zero_length_read_does_not_complete_empty_source(self):
        self.meta["size"] = 0
        self.session._exclusive_exit = Mock(return_value=dict(result=-4, is_error=True))
        with patch.object(node.os, "fstat", return_value=metadata(st_size=0)), \
             patch.object(node, "_readonly", return_value=self.meta), \
             patch.object(node, "_hash_readonly", return_value=(PIN, self.meta)), \
             patch.object(node.os, "close"):
            self.session._file_read(71, dict(nr=67, args=[8, 4096, 0, 0, 0, 0], seq=7), 2.0)
        self.assertFalse(self.session._complete())

    def test_large_loader_read_never_counts_as_source(self):
        self.meta["size"] = base.MAX_FILE + 1
        self.value._sources = []
        self.session.loaders = [dict(self.row, path=LOADER)]
        self.session._exclusive_exit = Mock(return_value=dict(result=3, is_error=False))
        with patch.object(node.os, "fstat", return_value=metadata(st_size=self.meta["size"])), \
             patch.object(node, "_readonly", return_value=self.meta) as readonly, \
             patch.object(node, "_hash_readonly", return_value=(PIN, self.meta)), \
             patch.object(node.os, "close"):
            self.session._file_read(71, dict(nr=67, args=[8, 4096, 3, 0, 0, 0], seq=7), 2.0)
        readonly.assert_called_once_with(19, base.process._MAX_EXECUTABLE_BYTES)
        self.assertEqual(self.value._read_paths, set())
        self.assertEqual([row["kind"] for row in self.value._events], ["LOADER_READ_ENTER", "LOADER_READ_EXIT"])

    def test_internal_created_pipe_objects_remain_held(self):
        self.session._peek = Mock(return_value=struct.pack("<ii", 5, 6))
        self.value._kernel.duplicate.side_effect = [19, 20]
        with patch.object(node.os, "fstat", return_value=metadata(st_mode=stat.S_IFIFO | 0o600)):
            self.session._created(71, dict(nr=59, args=[4096, 0, 0, 0], seq=7), 0, False, 2.0)
        self.assertEqual(self.value._fds, [19, 20])
        self.assertEqual(self.value._events[-1]["kind"], "FD_CREATE")
        self.assertEqual(self.value._events[-1]["kind_name"], "pipe")

    def test_unknown_pipe_input_refused(self):
        with patch.object(node.os, "fstat", return_value=metadata(st_mode=stat.S_IFIFO | 0o600)):
            with self.assertRaisesRegex(base.PiSourceObserverError, "UNCLASSIFIED_INPUT"):
                self.session._channel(5, 19)

    def test_internal_anon_inode_alias_uses_exact_held_description(self):
        identity = dict(device=0, inode=1, mode=0o600)
        self.session.internal_fds[tuple(identity.values())] = [
            ({"kind": "eventfd", "created_by": 7}, 19),
            ({"kind": "eventfd", "created_by": 12}, 20),
        ]
        self.session._same_description = Mock(side_effect=[False, True])
        with patch.object(node, "_fd_identity", return_value=identity):
            channel, actual = self.session._channel(8, 21)
        self.assertEqual(channel, {"kind": "eventfd", "created_by": 12})
        self.assertEqual(actual, identity)
        self.assertEqual([call.args for call in self.session._same_description.call_args_list], [(21, 19), (21, 20)])

    def test_same_anon_inode_without_description_match_is_refused(self):
        identity = dict(device=0, inode=1, mode=0o600)
        self.session.internal_fds[tuple(identity.values())] = [({"kind": "eventfd", "created_by": 7}, 19)]
        self.session._same_description = Mock(return_value=False)
        with patch.object(node, "_fd_identity", return_value=identity):
            with self.assertRaisesRegex(base.PiSourceObserverError, "OBJECT_CHANGED"):
                self.session._channel(8, 21)

    def test_kcmp_uses_two_held_fds_in_same_tracer_process(self):
        self.value._fds = [19, 20]
        self.value._kernel.libc.syscall.return_value = 0
        with patch.object(node.os, "getpid", return_value=9000):
            self.assertTrue(self.session._same_description(19, 20))
        self.assertEqual([arg.value for arg in self.value._kernel.libc.syscall.call_args.args],
                         [272, 9000, 9000, 0, 19, 20])

    def test_kcmp_requires_stopped_tasks_and_retained_descriptors(self):
        self.value._fds = [19]
        with self.assertRaisesRegex(base.PiSourceObserverError, "CUSTODY"):
            self.session._same_description(19, 20)
        self.value._fds.append(20)
        self.session.tasks[71]["stopped"] = False
        with self.assertRaisesRegex(base.PiSourceObserverError, "CUSTODY"):
            self.session._same_description(19, 20)
        self.value._kernel.libc.syscall.assert_not_called()

    def test_kcmp_failure_is_not_a_metadata_fallback(self):
        self.value._fds = [19, 20]
        self.value._kernel.libc.syscall.return_value = -1
        with patch.object(node.ctypes, "get_errno", return_value=1):
            with self.assertRaisesRegex(OSError, "comparison failed"):
                self.session._same_description(19, 20)

    def test_ambiguous_temporary_close_retains_custody_and_disables_retry(self):
        self.value._fds = [19]
        with patch.object(node.os, "close", side_effect=OSError(5, "inert ambiguous close")) as close:
            with self.assertRaisesRegex(base.PiSourceObserverError, "AMBIGUOUS") as caught:
                self.session._close_duplicate(19)
            self.assertIs(caught.exception.observer, self.value)
            self.assertEqual(self.value._fds, [19])
            self.assertTrue(self.value._close_attempted)
            with self.assertRaisesRegex(base.PiSourceObserverError, "ALREADY_ATTEMPTED"):
                self.value.close_after_exit()
        close.assert_called_once_with(19)

    def test_successful_temporary_close_drops_record_only_after_close(self):
        self.value._fds = [19]
        def close(fd):
            self.assertEqual(fd, 19)
            self.assertEqual(self.value._fds, [19])
        with patch.object(node.os, "close", side_effect=close) as closed:
            self.session._close_duplicate(19)
        closed.assert_called_once_with(19)
        self.assertEqual(self.value._fds, [])
        self.assertFalse(self.value._close_attempted)

    def test_gate_release_only_before_first_entry(self):
        self.value._executed = False
        self.exit()
        self.assertEqual(self.value._events[-1]["kind"], "GATE_RELEASE")
        with self.assertRaisesRegex(base.PiSourceObserverError, "ORPHAN"):
            self.exit()

    def test_failed_gate_release_refused(self):
        self.value._executed = False
        with self.assertRaisesRegex(base.PiSourceObserverError, "GATE_RELEASE"):
            self.exit(-1, True)

    def test_thread_birth_exit_is_bound_to_clone(self):
        self.session.tasks[72] = task(clone_seq=4, birth_exit=False, entry_seen=False)
        self.exit(pid=72)
        self.assertEqual(self.value._events[-1], dict(seq=1, boottime_ns=100, kind="THREAD_START",
                                                     pid=72, stop_seq=8, clone_call_seq=4))
        with self.assertRaisesRegex(base.PiSourceObserverError, "ORPHAN"):
            self.exit(pid=72)

    def test_clone_requires_shared_thread_filesystem_and_vm(self):
        with self.assertRaisesRegex(base.PiSourceObserverError, "NONTHREAD"):
            self.session._clone(71, dict(nr=220, args=[0x10000, 4096, 0, 0, 0, 0], seq=7), 2.0)
        self.value._kernel.ptrace.assert_not_called()

    def test_clone3_pointer_is_read_not_used_as_flags(self):
        self.session._peek = Mock(return_value=struct.pack("<8Q", 17, 0, 0, 0, 0, 4096, 4096, 0))
        with self.assertRaisesRegex(base.PiSourceObserverError, "NONTHREAD"):
            self.session._clone(71, dict(nr=435, args=[8192, 64, 0, 0, 0, 0], seq=7), 2.0)
        self.session._peek.assert_called_once_with(71, 8192, 64)

    def test_sendmsg_and_recvmsg_are_not_ordinary(self):
        for nr in (211, 212):
            self.session.tasks[71]["call"] = None
            with self.assertRaisesRegex(base.PiSourceObserverError, "UNSUPPORTED"):
                self.entry(nr)

    def test_process_vm_and_io_uring_are_not_ordinary(self):
        for nr in (270, 271, 425, 426, 427):
            self.session.tasks[71]["call"] = None
            with self.assertRaisesRegex(base.PiSourceObserverError, "UNSUPPORTED"):
                self.entry(nr)

    def test_write_open_refused_at_entry(self):
        with self.assertRaisesRegex(base.PiSourceObserverError, "WRITE_OPEN"):
            self.entry(56, [0, 4096, 0x241, 0, 0, 0])

    def test_nonstdio_ioctl_refused(self):
        with self.assertRaisesRegex(base.PiSourceObserverError, "IOCTL"):
            self.entry(29, [8, 0x5401, 4096, 0, 0, 0])

    def test_cleanup_does_not_resume_ordinary_stop(self):
        self.session.stopping = True
        self.session.pending_events = [dict(pid=71, event=0)]
        self.session._wait_one = Mock(return_value=False)
        self.session._drain(12.0)
        self.value._kernel.ptrace.assert_not_called()
        self.session._wait_one.assert_called_once_with(71)

    def test_cleanup_releases_only_captured_exit_stop(self):
        self.session.stopping = True
        self.session.pending_events = [dict(pid=71, event=6)]
        self.session._wait_one = Mock(return_value=False)
        self.session._drain(12.0)
        self.value._kernel.ptrace.assert_called_once_with(7, 71)
        self.assertEqual(self.value._events[-1]["request"], "CONT")

    def test_cleanup_reserve_scales_with_bounded_thread_inventory(self):
        self.value._events = [{}] * (base.MAX_EVENTS - (64 * 4 + 8))
        with self.assertRaisesRegex(base.PiSourceObserverError, "RESERVE"):
            self.session._event("EXEC", pid=71, digest=PIN)

    def test_factory_timeout_retains_facade_without_running_thread(self):
        fake = Mock()
        fake.ready.wait.return_value = False
        fake.observer = self.value
        with patch.object(node, "_NodeSession", return_value=fake):
            with self.assertRaisesRegex(base.PiSourceObserverError, "ARM_TIMEOUT") as caught:
                node.start_node_observer(self.owned, profile(), operation_deadline=10.0, cleanup_deadline=15.0)
        self.assertIs(caught.exception.observer, self.value)
        fake.thread.start.assert_called_once()

    def test_owner_arm_failure_still_handles_close_command(self):
        self.session.tasks = {}
        self.value.close_after_exit = Mock()
        stop_done, close_done = threading.Event(), threading.Event()
        commands = queue.Queue()
        commands.put(("stop", None, 12.0, stop_done, []))
        commands.put(("close", None, 12.0, close_done, []))
        self.session.commands = commands
        with patch.object(node, "_arm", side_effect=RuntimeError("inert arm failure")):
            self.session._main()
        self.assertTrue(stop_done.is_set() and close_done.is_set())
        self.value.close_after_exit.assert_called_once()
        self.assertTrue(self.session.closed.is_set())

    def test_facade_health_is_sent_to_dedicated_owner(self):
        self.value._thread = -1
        self.session.command = Mock(return_value={"snapshot": True})
        self.assertEqual(self.value.guard_source_health(activation={"held": True}, deadline=2.0), {"snapshot": True})
        self.session.command.assert_called_once_with("health", {"held": True}, 2.0)

    def test_shutdown_requires_owner_thread_join(self):
        self.session.command = Mock()
        self.session.thread = Mock()
        self.session.thread.is_alive.return_value = True
        with self.assertRaisesRegex(base.PiSourceObserverError, "NOT_JOINED"):
            self.value.shutdown_after_owned_stop(12.0)
        self.session.thread.join.assert_called_once_with(11.0)

    def test_no_health_snapshot_before_actual_boundary(self):
        self.assertIsNone(self.value.health_observation)
        legacy = base.PiSourceObserver(base._SEAL)
        self.assertIsNone(legacy.health_observation)

    def test_retained_health_snapshot_has_copy_isolation(self):
        self.session.latest_health_observation = {"state": "HELD", "events": [{"kind": "CHALLENGE"}]}
        first = self.value.health_observation
        first["events"].clear()
        self.assertEqual(self.value.health_observation["events"], [{"kind": "CHALLENGE"}])

    def test_failed_health_does_not_replace_previous_actual_snapshot(self):
        self.session.tasks = {}
        self.value.close_after_exit = Mock()
        self.value.guard_source_health = Mock(side_effect=[None, RuntimeError("inert health refusal")])
        actual = {"state": "HELD", "events": [{"kind": "CHALLENGE"}]}
        self.session._snapshot = Mock(return_value=actual)
        commands = queue.Queue()
        results = []
        for kind in ("health", "health", "stop", "close"):
            result = []
            results.append(result)
            commands.put((kind, {}, 12.0, threading.Event(), result))
        self.session.commands = commands
        with patch.object(node, "_arm"):
            self.session._main()
        self.assertEqual(self.value.health_observation, actual)
        self.assertIsInstance(results[1][0], base.PiSourceObserverError)
        results[0][0]["events"].clear()
        self.assertEqual(self.value.health_observation, actual)
        self.assertTrue(any(row["kind"] == "REFUSED" for row in self.value._events))


if __name__ == "__main__":
    unittest.main()
