"""Fabricated in-memory syscalls only: no protected path, socket or live proc."""

from contextlib import ExitStack
import errno
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn import native_phase3_run_reader_acquisition as acquisition
from aragorn import native_phase3_run_reader_response as leaf
from aragorn import native_phase3_run_reader_store as store


PIN = "sha256:" + "a" * 64
ROOT = "/var/lib/aragorn-phase3-reader"


def epoch_fixture():
    process = {"boot_id": "11111111-2222-3333-4444-555555555555", "reader_pid": 101,
               "reader_start_ticks": 12, "sensor_pid": 102, "sensor_start_ticks": 13,
               "reader_uid": 997, "reader_gid": 997, "sensor_uid": 996, "sensor_gid": 996,
               "reader_source_digest": PIN, "sensor_source_digest": PIN,
               "stream_digest": PIN, "program_map_digest": PIN}
    epoch = {"process": process, "clock": {"boot_id": process["boot_id"], "clock_id": "CLOCK_BOOTTIME",
                                          "time_namespace_inode": 400}, "loss_scope": [PIN],
             "policy": {"timeout_ns": 1000, "max_age_ns": 500}, "deployment_digest": PIN}
    return leaf._canonical(epoch)


def claim_fixture(connection_epoch="e" * 64):
    challenge = {"epoch_digest": PIN, "request_digest": PIN, "boundary": "BEFORE_FIRST_EFFECT",
                 "nonce": "f" * 64, "issued_ns": 100, "deadline_ns": 1100, "sequence_before": 1}
    return leaf._canonical({"schema": "aragorn/native-phase3-run-reader-claim/v1",
                            "connection_epoch": connection_epoch, "challenge": challenge})


class MemoryFS:
    def __init__(self):
        self.nodes, self.handles, self.calls = {}, {}, []
        self.next_inode, self.next_fd, self.sync_count = 1, 100, 0
        self.write_script, self.sync_fail_at, self.close_fail = [], None, set()
        for path in ("/", "/var", "/var/lib", ROOT):
            self.add(path, stat.S_IFDIR | (0o700 if path == ROOT else 0o755))

    def add(self, path, mode, raw=b"", **changes):
        node = SimpleNamespace(st_dev=1, st_ino=self.next_inode, st_mode=mode, st_uid=0, st_gid=0,
                               st_nlink=1, st_size=len(raw), st_mtime_ns=1, st_ctime_ns=1, raw=raw, path=path)
        self.next_inode += 1
        for key, value in changes.items():
            setattr(node, key, value)
        self.nodes[path] = node
        return node

    def path(self, name, parent):
        return name if name.startswith("/") else self.handles[parent].path.rstrip("/") + "/" + name

    def open(self, name, flags, mode=0o777, *, dir_fd=None):
        path = self.path(name, dir_fd)
        self.calls.append(("open", path, flags, mode))
        if flags & os.O_EXCL:
            if path in self.nodes:
                raise FileExistsError(errno.EEXIST, "fabricated duplicate", path)
            node = self.add(path, stat.S_IFREG | mode)
            parent = self.handles[dir_fd]
            parent.st_mtime_ns += 1
            parent.st_ctime_ns += 1
        else:
            node = self.nodes[path]
            if stat.S_ISLNK(node.st_mode) and flags & os.O_NOFOLLOW:
                raise OSError(errno.ELOOP, "fabricated nofollow")
        fd = self.next_fd
        self.next_fd += 1
        self.handles[fd] = node
        return fd

    def fstat(self, fd):
        return SimpleNamespace(**vars(self.handles[fd]))

    def named_stat(self, name, *, dir_fd=None, follow_symlinks=True):
        if follow_symlinks:
            raise AssertionError("named lookup must not follow links")
        return SimpleNamespace(**vars(self.nodes[self.path(name, dir_fd)]))

    def write(self, fd, raw):
        action = self.write_script.pop(0) if self.write_script else len(raw)
        if isinstance(action, BaseException):
            raise action
        node = self.handles[fd]
        node.raw += bytes(raw[:action])
        node.st_size = len(node.raw)
        node.st_mtime_ns += 1
        node.st_ctime_ns += 1
        self.calls.append(("write", fd, action))
        return action

    def pread(self, fd, count, offset):
        self.calls.append(("pread", fd))
        return self.handles[fd].raw[offset:offset + count]

    def fsync(self, fd):
        self.sync_count += 1
        self.calls.append(("fsync", fd))
        if self.sync_count == self.sync_fail_at:
            raise OSError("fabricated sync failure")

    def close(self, fd):
        self.calls.append(("close", fd))
        self.handles.pop(fd)
        if fd in self.close_fail:
            raise OSError("fabricated close ambiguity")

    def patches(self):
        stack = ExitStack()
        stack.enter_context(patch.object(store.sys, "platform", "linux"))
        stack.enter_context(patch.object(store.os, "getresuid", return_value=(0, 0, 0), create=True))
        stack.enter_context(patch.object(store.os, "getresgid", return_value=(0, 0, 0), create=True))
        stack.enter_context(patch.object(store.os, "getpid", return_value=900))
        stack.enter_context(patch.object(store.threading, "get_native_id", return_value=900))
        for name, method in (("open", self.open), ("fstat", self.fstat), ("stat", self.named_stat),
                             ("write", self.write), ("pread", self.pread), ("fsync", self.fsync), ("close", self.close)):
            stack.enter_context(patch.object(store.os, name, side_effect=method))
        return stack


class ReaderStoreTests(unittest.TestCase):
    def test_durable_exact_claim_and_evidence_with_timestamp_changing_parent(self):
        fs, raw = MemoryFS(), claim_fixture()
        evidence = b'{"status":"REFUSED"}'
        with fs.patches():
            held = store.ReaderStore(raw)

            def assert_durable_before_ack(calls):
                fd, parent = held._files[-1][1], held._directories[-1][2]
                file_sync = calls.index(("fsync", fd))
                directory_sync = calls.index(("fsync", parent))
                final_read = max(index for index, call in enumerate(calls) if call == ("pread", fd))
                self.assertLess(file_sync, directory_sync)
                self.assertLess(directory_sync, final_read)

            self.assertEqual(held.consume_once(raw), raw)
            assert_durable_before_ack(fs.calls)
            start = len(fs.calls)
            self.assertEqual(held.retain(evidence, expected_digest=leaf._raw_digest(evidence)),
                             {"digest": leaf._raw_digest(evidence), "bytes": len(evidence)})
            assert_durable_before_ack(fs.calls[start:])
            held.final_readback()
            self.assertEqual(fs.sync_count, 4)
            self.assertTrue(all(node.st_mode == stat.S_IFREG | 0o400 for path, node in fs.nodes.items()
                                if path.endswith(".json")))
            held.close()
            self.assertFalse(fs.handles)
            self.assertEqual(len([row for row in fs.calls if row[0] == "close"]), 6)

    def test_duplicate_claim_is_global_across_connection_epochs_and_never_removed(self):
        fs, raw = MemoryFS(), claim_fixture()
        with fs.patches():
            first = store.ReaderStore(raw)
            first.consume_once(raw)
            claim_name = first._claim_name
            first.close()
            second_raw = claim_fixture("d" * 64)
            second = store.ReaderStore(second_raw)
            self.assertEqual(second._claim_name, claim_name)
            with self.assertRaises(FileExistsError):
                second.consume_once(second_raw)
            second.retain(b'{"status":"REFUSED"}', expected_digest=leaf._raw_digest(b'{"status":"REFUSED"}'))
            self.assertEqual(fs.nodes[ROOT + "/" + claim_name].raw, raw)
            second.close()

    def test_any_existing_final_name_refuses_including_partial_symlink_or_directory(self):
        for mode, raw in ((stat.S_IFREG | 0o400, b"{"), (stat.S_IFLNK | 0o777, b"elsewhere"),
                          (stat.S_IFDIR | 0o700, b"")):
            with self.subTest(mode=mode):
                fs = MemoryFS()
                with fs.patches():
                    held = store.ReaderStore(claim_fixture())
                    original = fs.add(ROOT + "/" + held._claim_name, mode, raw)
                    with self.assertRaises(FileExistsError):
                        held.consume_once(claim_fixture())
                    self.assertIs(fs.nodes[ROOT + "/" + held._claim_name], original)
                    held.close()

    def test_partial_write_and_sync_failure_preserve_residue_and_poison_callbacks(self):
        for mode in ("write", "file_sync", "directory_sync"):
            with self.subTest(mode=mode):
                fs = MemoryFS()
                if mode == "write":
                    fs.write_script = [2, OSError("fabricated partial write")]
                else:
                    fs.sync_fail_at = 1 if mode == "file_sync" else 2
                with fs.patches():
                    held = store.ReaderStore(claim_fixture())
                    with self.assertRaises(OSError):
                        held.consume_once(claim_fixture())
                    residue = fs.nodes[ROOT + "/" + held._claim_name].raw
                    self.assertEqual(residue, claim_fixture()[:2] if mode == "write" else claim_fixture())
                    with self.assertRaises(ValueError):
                        held.retain(b"{}", expected_digest=leaf._raw_digest(b"{}"))
                    held.close()
                    self.assertEqual(fs.nodes[ROOT + "/" + held._claim_name].raw, residue)

    def test_evidence_duplicate_and_partial_write_remain_permanent_refusals(self):
        raw = b'{"status":"REFUSED"}'
        digest = leaf._raw_digest(raw)
        for mode in ("duplicate", "partial"):
            with self.subTest(mode=mode):
                fs = MemoryFS()
                with fs.patches():
                    held = store.ReaderStore(claim_fixture())
                    name = ROOT + "/evidence-" + digest[7:] + ".json"
                    if mode == "duplicate":
                        fs.add(name, stat.S_IFREG | 0o400, raw)
                    else:
                        fs.write_script = [3, OSError("fabricated partial evidence")]
                    with self.assertRaises(OSError):
                        held.retain(raw, expected_digest=digest)
                    expected = raw if mode == "duplicate" else raw[:3]
                    self.assertEqual(fs.nodes[name].raw, expected)
                    with self.assertRaises(ValueError):
                        held.retain(raw, expected_digest=digest)
                    held.close()
                    self.assertEqual(fs.nodes[name].raw, expected)

    def test_directory_substitution_and_ancestry_owner_mode_or_symlink_refuse(self):
        for field, value in (("st_ino", 999), ("st_uid", 1), ("st_gid", 1),
                             ("st_mode", stat.S_IFDIR | 0o777), ("st_mode", stat.S_IFLNK | 0o700)):
            with self.subTest(field=field, value=value):
                fs = MemoryFS()
                with fs.patches():
                    held = store.ReaderStore(claim_fixture())
                    setattr(fs.nodes["/var/lib"], field, value)
                    with self.assertRaises(ValueError):
                        held.consume_once(claim_fixture())
                    self.assertFalse(any(path.endswith(".json") for path in fs.nodes))
                    held.close()
        fs = MemoryFS()
        fs.nodes[ROOT].st_mode = stat.S_IFDIR | 0o750
        with fs.patches(), self.assertRaises(store.ReaderStoreError):
            store.ReaderStore(claim_fixture())
        self.assertFalse(fs.handles)

    def test_file_substitution_hardlink_identity_and_readback_mismatch_poison(self):
        for field, value in (("st_ino", 999), ("st_uid", 1), ("st_gid", 1), ("st_nlink", 2),
                             ("st_mode", stat.S_IFREG | 0o600), ("st_size", 1), ("raw", b"corrupt")):
            with self.subTest(field=field, value=value):
                fs = MemoryFS()
                with fs.patches():
                    held = store.ReaderStore(claim_fixture())
                    held.consume_once(claim_fixture())
                    setattr(fs.nodes[ROOT + "/" + held._claim_name], field, value)
                    with self.assertRaises(ValueError):
                        held.final_readback()
                    with self.assertRaises(ValueError):
                        held.retain(b"{}", expected_digest=leaf._raw_digest(b"{}"))
                    held.close()

    def test_named_directory_and_file_swap_are_checked_independently_of_held_descriptor(self):
        for role in ("directory", "file", "during_read"):
            with self.subTest(role=role):
                fs = MemoryFS()
                with fs.patches():
                    held = store.ReaderStore(claim_fixture())
                    held.consume_once(claim_fixture())
                    if role == "directory":
                        fs.add(ROOT, stat.S_IFDIR | 0o700)
                    elif role == "file":
                        fs.add(ROOT + "/" + held._claim_name, stat.S_IFREG | 0o400, claim_fixture())
                    else:
                        def swapped_pread(fd, count, offset):
                            raw = fs.pread(fd, count, offset)
                            fs.add(ROOT, stat.S_IFDIR | 0o700)
                            return raw
                        store.os.pread.side_effect = swapped_pread
                    with self.assertRaises(ValueError):
                        held.final_readback()
                    held.close()

    def test_callback_bounds_exact_claim_digest_and_one_shot_failure(self):
        invalid = [(b"{}\n", leaf._raw_digest(b"{}\n")), (b"{}", PIN),
                   (b'{"bad":NaN}', leaf._raw_digest(b'{"bad":NaN}')),
                   (b"x" * 131073, PIN)]
        for raw, digest in invalid:
            with self.subTest(raw_length=len(raw)):
                fs = MemoryFS()
                with fs.patches():
                    held = store.ReaderStore(claim_fixture())
                    with self.assertRaises(ValueError):
                        held.retain(raw, expected_digest=digest)
                    with self.assertRaises(ValueError):
                        held.retain(b"{}", expected_digest=leaf._raw_digest(b"{}"))
                    self.assertFalse(any(path.endswith(".json") for path in fs.nodes))
                    held.close()
        fs = MemoryFS()
        with fs.patches():
            held = store.ReaderStore(claim_fixture())
            with self.assertRaises(ValueError):
                held.consume_once(claim_fixture("d" * 64))
            with self.assertRaises(ValueError):
                held.consume_once(claim_fixture())
            held.close()

    def test_fork_thread_identity_and_closed_reuse_refuse(self):
        for target, value in (("getpid", 901), ("getresuid", (0, 1, 0)), ("getresgid", (0, 0, 1))):
            with self.subTest(target=target):
                fs = MemoryFS()
                with fs.patches():
                    held = store.ReaderStore(claim_fixture())
                    with patch.object(store.os, target, return_value=value):
                        with self.assertRaises(ValueError):
                            held.consume_once(claim_fixture())
                    held.close()
        fs = MemoryFS()
        with fs.patches():
            held = store.ReaderStore(claim_fixture())
            with patch.object(store.threading, "get_native_id", return_value=901):
                with self.assertRaises(ValueError):
                    held.final_readback()
            held.close()
            with self.assertRaises(ValueError):
                held.final_readback()
            with self.assertRaises(ValueError):
                held.close()

    def test_constructor_and_final_cleanup_preserve_failures_without_close_retry(self):
        fs = MemoryFS()
        fs.nodes[ROOT].st_uid = 1
        fs.close_fail = {100, 103}
        with fs.patches(), self.assertRaises(store.ReaderStoreError) as caught:
            store.ReaderStore(claim_fixture())
        self.assertIsInstance(caught.exception.original_failure, ValueError)
        self.assertEqual(len(caught.exception.cleanup_failures), 2)
        self.assertEqual(len([row for row in fs.calls if row[0] == "close"]), 4)
        fs = MemoryFS()
        with fs.patches():
            held = store.ReaderStore(claim_fixture())
            fs.close_fail = {100, 102}
            with self.assertRaises(store.ReaderStoreError) as caught:
                held.close()
            self.assertEqual(len(caught.exception.cleanup_failures), 2)
            with self.assertRaises(ValueError):
                held.close()
            self.assertEqual(len([row for row in fs.calls if row[0] == "close"]), 4)


class OwnedReaderAcquisitionTests(unittest.TestCase):
    def call(self, connection, **changes):
        raw = epoch_fixture()
        options = {"epoch_raw": raw, "expected_epoch_digest": leaf._raw_digest(raw),
                   "request_digest": PIN, "sequence_before": 1}
        options.update(changes)
        return acquisition.acquire_owned_reader_response(connection, **options)

    def successful_leaf(self, connection, **kwargs):
        self.assertIsNotNone(connection)
        epoch, challenge = leaf._inputs(kwargs["epoch_raw"], kwargs["challenge_raw"], kwargs["bindings"],
                                         kwargs["connection_epoch"])
        raw = leaf._canonical({"schema": "aragorn/native-phase3-run-reader-claim/v1",
                               "connection_epoch": kwargs["connection_epoch"], "challenge": challenge})
        self.assertEqual(kwargs["consume_once"](raw), raw)
        evidence = leaf._canonical({"status": "ACK", "challenge": kwargs["bindings"]["challenge"]})
        self.assertEqual(kwargs["retain"](evidence, expected_digest=leaf._raw_digest(evidence)),
                         {"digest": leaf._raw_digest(evidence), "bytes": len(evidence)})
        return {"status": "ACK"}

    def test_fresh_issuance_real_store_callbacks_and_cleanup_before_return(self):
        fs = MemoryFS()
        connections = [Mock(), Mock()]
        entropy = [bytes([number]) * 32 for number in (1, 2, 3, 4)]
        with fs.patches(), patch.object(acquisition.os, "urandom", side_effect=entropy), \
                patch.object(leaf.clock, "_stamp", return_value=100), \
                patch.object(leaf, "acquire_reader_response", side_effect=self.successful_leaf) as acquired:
            first, second = [self.call(connection) for connection in connections]
        self.assertNotEqual(first["challenge_raw"], second["challenge_raw"])
        self.assertNotEqual(first["connection_epoch"], second["connection_epoch"])
        self.assertIn(b'"status":"ACK"', first["evidence_raw"])
        self.assertEqual(first["evidence_digest"], leaf._raw_digest(first["evidence_raw"]))
        self.assertEqual(acquired.call_count, 2)
        for connection in connections:
            connection.close.assert_called_once_with()
        self.assertFalse(fs.handles)
        self.assertFalse(first["sensor_health_verified"] or first["effect_authorized"] or first["phase3_qualified"])

    def test_expected_pin_malformed_epoch_entropy_and_clock_failures_close_connection(self):
        cases = [("pin", {"expected_epoch_digest": PIN}), ("oversize", {"epoch_raw": b"x" * 32769}),
                 ("sequence", {"sequence_before": True}), ("entropy", {}), ("clock", {})]
        for mode, changes in cases:
            with self.subTest(mode=mode):
                connection = Mock()
                with patch.object(acquisition.os, "urandom", side_effect=OSError("entropy") if mode == "entropy"
                                  else [b"a" * 32, b"b" * 32]) as random, \
                        patch.object(leaf.clock, "_stamp", side_effect=OSError("clock") if mode == "clock" else None,
                                     return_value=100), \
                        patch.object(acquisition, "ReaderStore") as opened, \
                        self.assertRaises(acquisition.OwnedReaderResponseError) as caught:
                    self.call(connection, **changes)
                connection.close.assert_called_once_with()
                opened.assert_not_called()
                self.assertIsNone(caught.exception.observed["challenge_raw"])
                self.assertIsNone(caught.exception.partial_evidence)
                if mode in ("pin", "oversize", "sequence"):
                    random.assert_not_called()

    def test_actual_leaf_refusal_retains_partial_evidence_and_closes_owned_connection(self):
        fs, connection = MemoryFS(), Mock()
        original = ValueError("fabricated accepted transport mismatch")
        with fs.patches(), patch.object(acquisition.os, "urandom", side_effect=[b"a" * 32, b"b" * 32]), \
                patch.object(leaf.clock, "_stamp", return_value=100), \
                patch.object(leaf, "_peer", side_effect=original), \
                self.assertRaises(acquisition.OwnedReaderResponseError) as caught:
            self.call(connection)
        self.assertIs(caught.exception.original_failure.original_failure, original)
        self.assertIn(b'"status":"REFUSED"', caught.exception.partial_evidence)
        self.assertIsNotNone(caught.exception.observed["claim_raw"])
        self.assertEqual(len([path for path in fs.nodes if "/evidence-" in path]), 1)
        self.assertIsNone(caught.exception.retention_failure)
        connection.close.assert_called_once_with()
        self.assertFalse(fs.handles)

    def test_retention_and_original_cleanup_failures_keep_observed_bytes(self):
        fs, connection = MemoryFS(), Mock()
        original, cleanup = ValueError("peer refused"), OSError("connection close ambiguity")
        connection.close.side_effect = cleanup
        fs.sync_fail_at = 1
        fs.close_fail = {100}
        with fs.patches(), patch.object(acquisition.os, "urandom", side_effect=[b"a" * 32, b"b" * 32]), \
                patch.object(leaf.clock, "_stamp", return_value=100), patch.object(leaf, "_peer", side_effect=original), \
                self.assertRaises(acquisition.OwnedReaderResponseError) as caught:
            self.call(connection)
        error = caught.exception
        self.assertIs(error.original_failure.original_failure, original)
        self.assertIsNotNone(error.retention_failure)
        self.assertEqual(len(error.cleanup_failures), 2)
        self.assertIs(error.cleanup_failures[1], cleanup)
        self.assertIsNotNone(error.partial_evidence)
        self.assertEqual(len([path for path in fs.nodes if "/evidence-" in path]), 1)
        connection.close.assert_called_once_with()

    def test_connection_close_failure_prohibits_success_and_interruption_is_preserved(self):
        fs, connection = MemoryFS(), Mock()
        connection.close.side_effect = OSError("close ambiguity")
        with fs.patches(), patch.object(acquisition.os, "urandom", side_effect=[b"a" * 32, b"b" * 32]), \
                patch.object(leaf.clock, "_stamp", return_value=100), \
                patch.object(leaf, "acquire_reader_response", side_effect=self.successful_leaf), \
                self.assertRaises(acquisition.OwnedReaderResponseError) as caught:
            self.call(connection)
        self.assertIsNotNone(caught.exception.partial_evidence)
        self.assertIsNone(caught.exception.observed["reader"])
        connection.close.assert_called_once_with()
        connection = Mock()
        with patch.object(acquisition.os, "urandom", side_effect=KeyboardInterrupt), \
                self.assertRaises(acquisition.OwnedReaderResponseError) as caught:
            self.call(connection)
        self.assertIsInstance(caught.exception.original_failure, KeyboardInterrupt)
        connection.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
