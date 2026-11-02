"""Checkpoint ownership exercised with local, fabricated syscalls and bytes only."""

from contextlib import ExitStack
import copy
import errno
import hashlib
import json
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aragorn import native_phase3_run_reader_checkpoint_acquisition as subject


SOURCE = "/var/lib/aragorn-phase3-reader-events"
ARCHIVE = "/var/lib/aragorn-phase3-reader-checkpoints"
ROOT_PID, READER_PID = 701, 702
READER_UID, READER_GID = 901, 902
BASE = 1_000_000_000
BOOT = "11111111-2222-3333-4444-555555555555"
FLAGS = ("acquisition_authenticity_verified", "sensor_health_verified",
         "effect_authorized", "run_qualified", "phase3_qualified")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def pin(label):
    return digest(label.encode("ascii"))


class Fixture:
    """An independently authored future-writer record, not a producer fixture."""

    def __init__(self, *, phase="CHALLENGE", batch=b'{"event":1}\n'):
        self.batch = batch
        self.phase = phase
        refresh = phase == "REFRESH"
        self.clock = {"boot_id": BOOT, "clock_id": "CLOCK_BOOTTIME",
                      "time_namespace": {"device": 18, "inode": 600}}
        self.provision = {
            "schema": "aragorn/native-phase3-reader-checkpoint-provision/v1",
            "epoch_digest": pin("epoch"), "session_id": "a" * 64,
            "reader": {"pid": READER_PID, "start_time_ticks": 42,
                       "uid": READER_UID, "gid": READER_GID},
            "observer": {"pid": ROOT_PID, "start_time_ticks": 41, "uid": 0, "gid": 0},
            "clock": copy.deepcopy(self.clock), "stream_digest": pin("stream"),
            "source_inventory_digest": pin("source inventory"),
            "access_inventory_digest": pin("access inventory"),
            "directories": [], "session_deadline_ns": BASE + 500_000_000,
        }
        for index, path in enumerate(("/", "/var", "/var/lib", SOURCE, ARCHIVE)):
            self.provision["directories"].append({
                "path": path, "device": 17, "inode": 100 + index,
                "mode": stat.S_IFDIR | (0o700 if path in (SOURCE, ARCHIVE) else 0o755),
                "uid": READER_UID if path == SOURCE else 0,
                "gid": READER_GID if path == SOURCE else 0,
            })
        self.expectation = {
            "schema": "aragorn/native-phase3-reader-checkpoint-expectation/v1",
            "provision_digest": digest(canonical(self.provision)), "phase": phase,
            "epoch_digest": pin("epoch"), "request_digest": pin("request"),
            "challenge_digest": pin("challenge"),
            "trigger_digest": pin("refresh command" if refresh else "challenge"),
            "trigger_issued_ns": BASE + (100_000_000 if refresh else 0),
            "trigger_deadline_ns": BASE + (200_000_000 if refresh else 100_000_000),
            "deadline_ns": BASE + 250_000_000,
            "previous_checkpoint_digest": pin("previous acquisition") if refresh else None,
            "sequence_before": 1 if refresh else 0, "sequence_after": 2 if refresh else 1,
            "offset_before": 48 if refresh else 0, "records_before": 3 if refresh else 0,
            "reader_evidence_digest": pin("original reader evidence"),
            "reader_summary_digest": pin("original reader summary"),
            "reader_connection_epoch": "c" * 64, "reader_ack_ns": BASE + 80_000_000,
            "loss_scope_digest": pin("loss scope"),
        }
        shift = 100_000_000 if refresh else 0
        offset = self.expectation["offset_before"]
        reads = []
        if batch:
            reads.append({"started_ns": BASE + shift + 10_000_000,
                          "finished_ns": BASE + shift + 11_000_000,
                          "offset": offset, "bytes": len(batch), "outcome": "DATA"})
        reads.append({"started_ns": BASE + shift + 20_000_000,
                      "finished_ns": BASE + shift + 21_000_000,
                      "offset": offset + len(batch), "bytes": 0, "outcome": "EAGAIN"})
        self.manifest = {
            "schema": "aragorn/native-phase3-reader-checkpoint/v1",
            "provision_digest": digest(canonical(self.provision)),
            **{key: self.provision[key] for key in ("epoch_digest", "session_id", "stream_digest")},
            **{key: self.expectation[key] for key in (
                "phase", "request_digest", "challenge_digest", "trigger_digest",
                "previous_checkpoint_digest", "sequence_before", "sequence_after", "offset_before",
                "records_before", "loss_scope_digest")},
            "offset_after": offset + len(batch),
            "records_after": self.expectation["records_before"] + batch.count(b"\n"),
            "clock": copy.deepcopy(self.clock), "trigger_received_ns": BASE + shift + 5_000_000,
            "reads": reads, "drain_finished_ns": BASE + shift + 22_000_000,
            "raw_digest": digest(batch), "raw_bytes": len(batch), "raw_records": batch.count(b"\n"),
            "raw_publish_started_ns": BASE + shift + 23_000_000,
            "raw_readback_finished_ns": BASE + shift + 24_000_000,
            "manifest_prepared_ns": BASE + shift + 25_000_000,
            "loss_evidence_digest": None, "upstream_loss_state": "UNKNOWN",
        }
        self.publication = {
            "schema": "aragorn/native-phase3-reader-checkpoint-publication/v1",
            "manifest_digest": digest(canonical(self.manifest)), "raw_digest": digest(batch),
            "sequence_after": self.expectation["sequence_after"],
            "manifest_publish_started_ns": BASE + shift + 26_000_000,
            "manifest_readback_finished_ns": BASE + shift + 27_000_000,
            "receipt_prepared_ns": BASE + shift + 28_000_000,
        }

    def source_records(self):
        manifest = canonical(self.manifest)
        self.publication["manifest_digest"] = digest(manifest)
        trigger_hex = self.expectation["trigger_digest"][7:]
        return {
            SOURCE + "/" + self.phase.lower() + "-" + trigger_hex + ".json": manifest,
            SOURCE + "/batch-" + self.provision["session_id"] + "-" + str(self.manifest["sequence_after"]) + ".ndjson": self.batch,
            SOURCE + "/receipt-" + digest(manifest)[7:] + ".json": canonical(self.publication),
        }

    def arguments(self):
        provision, expectation = canonical(self.provision), canonical(self.expectation)
        return {"provision_raw": provision, "expected_provision_digest": digest(provision),
                "expectation_raw": expectation, "expected_expectation_digest": digest(expectation)}

    def archive_path(self, suffix):
        return ARCHIVE + "/checkpoint-" + self.expectation["trigger_digest"][7:] + "-" + suffix


class FakeKernel:
    """Named nodes, distinct open descriptions, proc bytes and a deterministic clock."""

    def __init__(self, fixture):
        self.nodes, self.handles, self.calls = {}, {}, []
        self.next_fd, self.next_inode = 1000, 1000
        self.now = BASE + (160_000_000 if fixture.phase == "REFRESH" else 110_000_000)
        self.pid, self.thread = ROOT_PID, ROOT_PID
        self.uids, self.gids = (0, 0, 0), (0, 0, 0)
        self.dead = False
        self.read_limit, self.write_limit = None, None
        self.write_actions, self.close_failures = [], set()
        self.on_read = lambda _path, _offset, raw: raw
        self.on_sync = lambda _fd: None
        self.on_open = lambda _path, _flags: None
        self.on_created = lambda _node: None
        self.clock_values = []
        for item in fixture.provision["directories"]:
            self.add(item["path"], mode=item["mode"], uid=item["uid"], gid=item["gid"],
                     st_dev=item["device"], st_ino=item["inode"])
        for path, raw in fixture.source_records().items():
            self.add(path, raw, uid=READER_UID, gid=READER_GID)
        for pid, start, uid, gid in ((ROOT_PID, 41, 0, 0), (READER_PID, 42, READER_UID, READER_GID)):
            fields = ["S", *(["0"] * 18), str(start), *(["0"] * 4)]
            self.add(f"/proc/{pid}/stat", (f"{pid} (fabricated reader) " + " ".join(fields) + "\n").encode())
            status = "Uid:\t" + "\t".join([str(uid)] * 4) + "\nGid:\t" + "\t".join([str(gid)] * 4) + "\n"
            status += "".join(key + ":\t0000000000000000\n" for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            status += "NoNewPrivs:\t1\n"
            self.add(f"/proc/{pid}/status", status.encode())
            self.add(f"/proc/{pid}/ns/time", mode=stat.S_IFREG | 0o444, st_dev=18, st_ino=600)
        self.add("/proc/sys/kernel/random/boot_id", (BOOT + "\n").encode())

    def add(self, path, raw=b"", *, mode=stat.S_IFREG | 0o400, uid=0, gid=0, **changes):
        node = SimpleNamespace(path=path, raw=raw, st_dev=17, st_ino=self.next_inode,
                               st_mode=mode, st_uid=uid, st_gid=gid, st_nlink=1,
                               st_size=len(raw), st_mtime_ns=1, st_ctime_ns=1)
        self.next_inode += 1
        for key, value in changes.items():
            setattr(node, key, value)
        self.nodes[path] = node
        return node

    def resolve(self, name, dir_fd=None):
        path = os.fspath(name)
        if path.startswith("/"):
            return path
        if dir_fd is None:
            raise AssertionError("relative path without held parent")
        return self.handles[dir_fd].node.path.rstrip("/") + "/" + path

    def open(self, name, flags, mode=0o777, *, dir_fd=None):
        path = self.resolve(name, dir_fd)
        self.on_open(path, flags)
        if flags & os.O_CREAT:
            if path in self.nodes and flags & os.O_EXCL:
                raise FileExistsError(errno.EEXIST, "fabricated exclusive collision", path)
            if path not in self.nodes:
                self.on_created(self.add(path, mode=stat.S_IFREG | mode))
        if path not in self.nodes:
            raise FileNotFoundError(errno.ENOENT, "fabricated missing source", path)
        node = self.nodes[path]
        if flags & os.O_NOFOLLOW and stat.S_ISLNK(node.st_mode):
            raise OSError(errno.ELOOP, "fabricated symlink")
        if flags & os.O_DIRECTORY and not stat.S_ISDIR(node.st_mode):
            raise NotADirectoryError(path)
        if stat.S_ISFIFO(node.st_mode) and not flags & os.O_NONBLOCK:
            raise AssertionError("FIFO would block before held type validation")
        fd = self.next_fd; self.next_fd += 1
        self.handles[fd] = SimpleNamespace(node=node, flags=flags, position=0)
        self.calls.append(("open", path, flags, mode, fd))
        return fd

    def fstat(self, fd):
        self.calls.append(("fstat", fd))
        return copy.copy(self.handles[fd].node)

    def stat(self, name, *, dir_fd=None, follow_symlinks=True):
        path = self.resolve(name, dir_fd)
        self.calls.append(("stat", path, follow_symlinks))
        if path not in self.nodes:
            raise FileNotFoundError(path)
        return copy.copy(self.nodes[path])

    def read_bytes(self, fd, size, offset):
        handle = self.handles[fd]
        self.calls.append(("read", handle.node.path, fd, size, offset))
        if self.read_limit is not None:
            size = min(size, self.read_limit)
        raw = handle.node.raw[offset:offset + size]
        return self.on_read(handle.node.path, offset, raw)

    def read(self, fd, size):
        raw = self.read_bytes(fd, size, self.handles[fd].position)
        self.handles[fd].position += len(raw)
        return raw

    def pread(self, fd, size, offset):
        return self.read_bytes(fd, size, offset)

    def write(self, fd, data):
        handle = self.handles[fd]
        raw = bytes(data)
        action = self.write_actions.pop(0) if self.write_actions else None
        if isinstance(action, BaseException):
            raise action
        count = min(len(raw), action) if type(action) is int else len(raw)
        if self.write_limit is not None:
            count = min(count, self.write_limit)
        before = handle.node.raw
        position = handle.position
        handle.node.raw = before[:position] + raw[:count] + before[position + count:]
        handle.position += count
        handle.node.st_size = len(handle.node.raw)
        handle.node.st_mtime_ns += 1; handle.node.st_ctime_ns += 1
        self.calls.append(("write", handle.node.path, fd, count))
        return count

    def fsync(self, fd):
        self.calls.append(("fsync", self.handles[fd].node.path, fd))
        self.on_sync(fd)

    def close(self, fd):
        handle = self.handles.pop(fd)
        self.calls.append(("close", fd, handle.node.path))
        if fd in self.close_failures:
            raise OSError(errno.EIO, "fabricated ambiguous close")

    def pidfd_open(self, pid, flags=0):
        if pid != READER_PID or flags != 0:
            raise AssertionError("unexpected pidfd identity")
        path = "/fake/pidfd"
        self.add(path)
        fd = self.open(path, os.O_RDONLY | os.O_CLOEXEC)
        self.add(f"/proc/self/fdinfo/{fd}", f"pos:\t0\nflags:\t02000000\nPid:\t{pid}\n".encode())
        return fd

    def readlink(self, name, *, dir_fd=None):
        node = self.nodes[self.resolve(name, dir_fd)]
        return "time:[" + str(node.st_ino) + "]"

    def tick(self, _clock):
        if self.clock_values:
            self.now = self.clock_values.pop(0)
        self.calls.append(("clock", self.now))
        return self.now

    def poll(self):
        kernel = self
        class Poll:
            def __init__(self):
                self.fds = []
            def register(self, fd, _events):
                self.fds.append(fd)
            def poll(self, timeout):
                if timeout != 0:
                    raise AssertionError("acquisition must not wait or retry")
                return [(self.fds[0], 1)] if kernel.dead else []
        return Poll()

    def os_api(self):
        api = {name: getattr(os, name) for name in dir(os) if name.startswith("O_")}
        api.update(open=self.open, read=self.read, pread=self.pread, write=self.write,
                   fsync=self.fsync, fstat=self.fstat, stat=self.stat, close=self.close,
                   lstat=lambda name, **kw: self.stat(name, follow_symlinks=False, **kw),
                   readlink=self.readlink, pidfd_open=self.pidfd_open,
                   getpid=lambda: self.pid, getuid=lambda: self.uids[0], geteuid=lambda: self.uids[1],
                   getgid=lambda: self.gids[0], getegid=lambda: self.gids[1],
                   getresuid=lambda: self.uids, getresgid=lambda: self.gids,
                   get_inheritable=lambda fd: not bool(self.handles[fd].flags & os.O_CLOEXEC),
                   get_blocking=lambda fd: not bool(self.handles[fd].flags & os.O_NONBLOCK),
                   fspath=os.fspath)
        return SimpleNamespace(**api)

    def patches(self):
        stack = ExitStack()
        stack.enter_context(patch.object(subject, "os", self.os_api()))
        stack.enter_context(patch.object(subject, "_ORIGINAL_PID", ROOT_PID))
        stack.enter_context(patch.object(subject.sys, "platform", "linux"))
        stack.enter_context(patch.object(subject.threading, "get_native_id", lambda: self.thread))
        stack.enter_context(patch.object(subject.time, "clock_gettime_ns", self.tick))
        stack.enter_context(patch.object(subject.time, "CLOCK_BOOTTIME", 7, create=True))
        stack.enter_context(patch.object(subject.select, "poll", self.poll))
        return stack


class ReaderCheckpointAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()
        self.kernel = FakeKernel(self.fixture)

    def acquire(self, **changes):
        arguments = self.fixture.arguments()
        arguments.update(changes)
        with self.kernel.patches():
            return subject.acquire_reader_checkpoint(**arguments)

    def failure(self, **changes):
        with self.assertRaises(subject.ReaderCheckpointAcquisitionError) as caught:
            self.acquire(**changes)
        return caught.exception

    def assert_closed_once(self):
        opened = [item[-1] for item in self.kernel.calls if item[0] == "open"]
        closed = [item[1] for item in self.kernel.calls if item[0] == "close"]
        self.assertCountEqual(opened, closed)
        self.assertEqual(len(closed), len(set(closed)))
        self.assertEqual(self.kernel.handles, {})

    def test_completed_archive_exact_bytes_order_and_claim_ceiling(self):
        result = self.acquire()
        self.assertEqual(set(result), {"acquisition_raw", "acquisition_digest", "manifest_raw",
                                      "publication_raw", "batch_raw"})
        self.assertEqual(result["manifest_raw"], canonical(self.fixture.manifest))
        self.assertEqual(result["publication_raw"], canonical(self.fixture.publication))
        self.assertEqual(result["batch_raw"], self.fixture.batch)
        self.assertEqual(result["acquisition_digest"], digest(result["acquisition_raw"]))
        acquisition = json.loads(result["acquisition_raw"])
        self.assertTrue(all(acquisition[key] is False for key in FLAGS))
        self.assertGreater(acquisition["started_ns"], self.fixture.expectation["trigger_deadline_ns"])
        self.assertEqual([item["role"] for item in acquisition["source_files"]],
                         ["BATCH", "MANIFEST", "PUBLICATION"])
        identities = acquisition["source_files"] + acquisition["retained_files"]
        self.assertEqual(len({(item["device"], item["inode"]) for item in identities}), 6)
        suffixes = ("claim.json", "batch.ndjson", "manifest.json", "publication.json", "acquisition.json")
        creations = [item for item in self.kernel.calls if item[0] == "open" and item[2] & os.O_CREAT]
        self.assertEqual([item[1] for item in creations], [self.fixture.archive_path(s) for s in suffixes])
        for index, opened in enumerate(creations):
            path, flags, mode, fd = opened[1:]
            self.assertEqual(mode, 0o400)
            required = os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            self.assertEqual(flags & required, required)
            start = self.kernel.calls.index(opened)
            stop = self.kernel.calls.index(creations[index + 1]) if index + 1 < len(creations) else len(self.kernel.calls)
            window = self.kernel.calls[start:stop]
            file_sync = next(i for i, item in enumerate(window) if item[:3] == ("fsync", path, fd))
            parent_sync = next(i for i, item in enumerate(window) if item[:2] == ("fsync", ARCHIVE))
            readback = next(i for i, item in enumerate(window) if item[0] == "read" and item[1] == path)
            self.assertLess(file_sync, parent_sync)
            self.assertLess(parent_sync, readback)
        claim = json.loads(self.kernel.nodes[self.fixture.archive_path("claim.json")].raw)
        self.assertEqual(claim, {"schema": "aragorn/native-phase3-reader-checkpoint-claim/v1",
                               "expectation_digest": digest(canonical(self.fixture.expectation)),
                               "manifest_digest": digest(result["manifest_raw"]),
                               "trigger_digest": self.fixture.expectation["trigger_digest"]})
        self.assertEqual(self.kernel.nodes[self.fixture.archive_path("acquisition.json")].raw,
                         result["acquisition_raw"])
        self.assert_closed_once()

    def test_empty_idle_batch_and_refresh_retain_original_ack(self):
        for phase, batch in (("CHALLENGE", b""), ("REFRESH", b'{"event":2}\n')):
            with self.subTest(phase=phase):
                self.fixture = Fixture(phase=phase, batch=batch)
                self.kernel = FakeKernel(self.fixture)
                before = copy.deepcopy(self.fixture.arguments())
                result = self.acquire()
                self.assertEqual(result["batch_raw"], batch)
                self.assertEqual(self.fixture.arguments(), before)
                self.assertEqual(json.loads(result["manifest_raw"])["sequence_after"],
                                 2 if phase == "REFRESH" else 1)
                self.assertEqual(self.fixture.expectation["reader_ack_ns"], BASE + 80_000_000)
                self.assert_closed_once()

    def test_external_pins_and_malformed_inputs_refuse_before_claim(self):
        arguments = self.fixture.arguments()
        variants = ({"expected_provision_digest": pin("other provision")},
                    {"expected_expectation_digest": pin("other expectation")},
                    {"provision_raw": arguments["provision_raw"] + b"\n"},
                    {"expectation_raw": b'{"x":1,"x":2}'},
                    {"expectation_raw": b'{"x":NaN}'},
                    {"expectation_raw": b"x" * 8193})
        for change in variants:
            with self.subTest(change=list(change)):
                self.kernel = FakeKernel(self.fixture)
                error = self.failure(**change)
                self.assertIs(error.observed["claim_attempted"], False)
                self.assertFalse(any(item[0] == "open" and item[2] & os.O_CREAT for item in self.kernel.calls))
                self.assert_closed_once()

    def test_manifest_joins_sequence_reads_and_unknown_loss_are_enforced(self):
        mutations = (
            lambda m: m.update(sequence_after=3), lambda m: m.update(offset_after=m["offset_after"] + 1),
            lambda m: m.update(previous_checkpoint_digest=pin("invented previous")),
            lambda m: m.update(stream_digest=pin("other stream")),
            lambda m: m.update(raw_records=2), lambda m: m.update(upstream_loss_state="ZERO"),
            lambda m: m.update(loss_evidence_digest=pin("unreleased loss")),
            lambda m: m["reads"][-1].update(outcome="EOF"),
            lambda m: m["reads"][-1].update(started_ns=BASE + 10_500_000),
            lambda m: m["reads"][-1].update(offset=0),
            lambda m: m.update(manifest_readback_finished_ns=BASE + 30_000_000),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.fixture = Fixture(); mutation(self.fixture.manifest)
                self.kernel = FakeKernel(self.fixture)
                error = self.failure()
                self.assertIs(error.observed["claim_attempted"], False)
                self.assert_closed_once()

    def test_raw_framing_and_declared_byte_bounds_refuse_without_archiving(self):
        for batch in (b"unterminated", b"\n", b'{"event":1}\r\n', b"x" * 65536 + b"\n"):
            with self.subTest(batch_length=len(batch)):
                self.fixture = Fixture(batch=batch)
                if len(batch) > 65536:
                    first, last = self.fixture.manifest["reads"]
                    first["bytes"] = 65536
                    second = {"started_ns": BASE + 12_000_000, "finished_ns": BASE + 13_000_000,
                              "offset": 65536, "bytes": len(batch) - 65536, "outcome": "DATA"}
                    self.fixture.manifest["reads"] = [first, second, last]
                self.kernel = FakeKernel(self.fixture)
                self.assertIs(self.failure().observed["claim_attempted"], False)
                self.assert_closed_once()
        self.fixture = Fixture(); self.kernel = FakeKernel(self.fixture)
        path = next(path for path in self.kernel.nodes if path.startswith(SOURCE + "/challenge-"))
        self.kernel.nodes[path].st_size = 16385
        self.assertIs(self.failure().observed["claim_attempted"], False)
        self.assertFalse(any(item[0] == "read" and item[1] == path for item in self.kernel.calls))
        self.assert_closed_once()

    def test_refresh_needs_prior_checkpoint_and_receipt_cannot_follow_readback(self):
        self.fixture = Fixture(phase="REFRESH")
        self.fixture.expectation.update(previous_checkpoint_digest=None, sequence_before=0,
                                        sequence_after=1, offset_before=0, records_before=0)
        self.kernel = FakeKernel(self.fixture)
        self.assertIs(self.failure().observed["claim_attempted"], False)
        self.assert_closed_once()
        self.fixture = Fixture(phase="REFRESH")
        self.fixture.publication["receipt_prepared_ns"] = BASE + 180_000_000
        self.kernel = FakeKernel(self.fixture)
        error = self.failure()
        self.assertIn("future", str(error.original_failure))
        self.assertIs(error.observed["claim_attempted"], False)
        self.assert_closed_once()

    def test_trigger_deadline_outer_deadline_ack_age_and_clock_rollback(self):
        self.fixture.expectation["reader_ack_ns"] = self.fixture.expectation["trigger_deadline_ns"]
        self.assertIs(self.failure().observed["claim_attempted"], False)
        for kind in ("outer", "age", "rollback"):
            with self.subTest(kind=kind):
                self.fixture = Fixture()
                if kind == "age":
                    self.fixture.expectation["deadline_ns"] = BASE + 400_000_000
                self.kernel = FakeKernel(self.fixture)
                if kind == "outer":
                    self.kernel.now = self.fixture.expectation["deadline_ns"]
                elif kind == "age":
                    self.kernel.now = self.fixture.expectation["reader_ack_ns"] + 200_000_000
                else:
                    self.kernel.clock_values = [self.kernel.now, self.kernel.now - 1]
                self.assertIs(self.failure().observed["claim_attempted"], False)
                self.assert_closed_once()

    def test_source_fifo_and_symlink_never_block_or_get_read(self):
        for mode in (stat.S_IFIFO | 0o400, stat.S_IFLNK | 0o400):
            with self.subTest(mode=mode):
                self.kernel = FakeKernel(self.fixture)
                path = next(path for path in self.kernel.nodes if path.startswith(SOURCE + "/challenge-"))
                self.kernel.nodes[path].st_mode = mode
                error = self.failure()
                self.assertNotIsInstance(error.original_failure, AssertionError)
                self.assertFalse(any(item[0] == "read" and item[1] == path for item in self.kernel.calls))
                for item in self.kernel.calls:
                    if item[0] == "open" and item[1] == path:
                        self.assertEqual(item[2] & (os.O_NONBLOCK | os.O_NOFOLLOW), os.O_NONBLOCK | os.O_NOFOLLOW)
                self.assert_closed_once()

    def test_source_owner_mode_links_and_directory_identity_are_guarded(self):
        for key, value in (("st_uid", 0), ("st_gid", 0), ("st_mode", stat.S_IFREG | 0o600), ("st_nlink", 2)):
            with self.subTest(key=key):
                self.kernel = FakeKernel(self.fixture)
                path = next(path for path in self.kernel.nodes if path.startswith(SOURCE + "/challenge-"))
                setattr(self.kernel.nodes[path], key, value)
                self.assertIs(self.failure().observed["claim_attempted"], False)
                self.assert_closed_once()
        self.kernel = FakeKernel(self.fixture)
        self.kernel.nodes["/var"].st_ino += 1
        self.assertIs(self.failure().observed["claim_attempted"], False)
        self.assert_closed_once()

    def test_source_name_substitution_during_read_preserves_observed_bytes(self):
        changed = []
        def replace(path, offset, raw):
            if path.startswith(SOURCE + "/challenge-") and offset == 0 and not changed:
                changed.append(path)
                self.kernel.add(path, raw, uid=READER_UID, gid=READER_GID)
            return raw
        self.kernel.on_read = replace
        error = self.failure()
        self.assertEqual(error.observed["manifest_raw"], canonical(self.fixture.manifest))
        self.assertIs(error.observed["claim_attempted"], False)
        self.assertTrue(changed)
        self.assert_closed_once()

    def test_source_partial_read_error_retains_only_the_actual_prefix(self):
        self.kernel.read_limit = 11
        def fail_read(path, offset, raw):
            if path.startswith(SOURCE + "/challenge-") and offset >= 11:
                raise OSError(errno.EIO, "fabricated partial manifest read")
            return raw
        self.kernel.on_read = fail_read
        error = self.failure()
        self.assertEqual(error.observed["manifest_raw"], canonical(self.fixture.manifest)[:11])
        self.assertIsNone(error.observed["batch_raw"])
        self.assertIsNone(error.observed["publication_raw"])
        self.assertIs(error.observed["claim_attempted"], False)
        self.assert_closed_once()

    def test_source_and_retained_artifact_identity_aliases_refuse(self):
        for kind in ("source", "retained"):
            with self.subTest(kind=kind):
                self.kernel = FakeKernel(self.fixture)
                manifest = next(node for path, node in self.kernel.nodes.items() if path.startswith(SOURCE + "/challenge-"))
                if kind == "source":
                    publication = next(node for path, node in self.kernel.nodes.items() if path.startswith(SOURCE + "/receipt-"))
                    publication.st_ino = manifest.st_ino
                else:
                    def alias(node):
                        if node.path == self.fixture.archive_path("batch.ndjson"):
                            node.st_ino = manifest.st_ino
                    self.kernel.on_created = alias
                error = self.failure()
                self.assertIn("alias", str(error.original_failure))
                self.assertIs(error.observed["claim_attempted"], kind == "retained")
                self.assert_closed_once()

    def test_reader_process_capabilities_boot_namespace_and_pidfd_are_rechecked(self):
        for kind in ("accounts", "capability", "nnp", "boot", "namespace", "dead", "fdinfo"):
            with self.subTest(kind=kind):
                self.kernel = FakeKernel(self.fixture)
                status = self.kernel.nodes[f"/proc/{READER_PID}/status"]
                if kind == "accounts":
                    status.raw = status.raw.replace(b"Uid:\t901\t901\t901\t901", b"Uid:\t901\t0\t901\t901")
                elif kind == "capability":
                    status.raw = status.raw.replace(b"CapEff:\t0000000000000000", b"CapEff:\t0000000000000001")
                elif kind == "nnp":
                    status.raw = status.raw.replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0")
                elif kind == "boot":
                    self.kernel.nodes["/proc/sys/kernel/random/boot_id"].raw = ("0" * 36 + "\n").encode()
                elif kind == "namespace":
                    self.kernel.nodes[f"/proc/{READER_PID}/ns/time"].st_ino += 1
                elif kind == "dead":
                    self.kernel.dead = True
                else:
                    self.kernel.on_read = lambda path, _offset, raw: raw.replace(b"Pid:\t702", b"Pid:\t703") if "/fdinfo/" in path else raw
                self.assertIs(self.failure().observed["claim_attempted"], False)
                self.assert_closed_once()

    def test_original_root_thread_saved_accounts_and_pinned_ancestor_group(self):
        for name, value in (("pid", ROOT_PID + 1), ("thread", ROOT_PID + 1),
                            ("uids", (0, 0, 1)), ("gids", (0, 0, 1))):
            with self.subTest(name=name):
                self.kernel = FakeKernel(self.fixture); setattr(self.kernel, name, value)
                self.assertIs(self.failure().observed["claim_attempted"], False)
                self.assert_closed_once()
        self.fixture = Fixture()
        self.fixture.provision["directories"][1]["gid"] = 12
        self.fixture.expectation["provision_digest"] = digest(canonical(self.fixture.provision))
        self.fixture.manifest["provision_digest"] = self.fixture.expectation["provision_digest"]
        self.kernel = FakeKernel(self.fixture)
        self.assertEqual(self.acquire()["batch_raw"], self.fixture.batch)
        self.assert_closed_once()

    def test_existing_claim_residue_is_never_overwritten_or_retried(self):
        for mode in (stat.S_IFREG | 0o400, stat.S_IFDIR | 0o700, stat.S_IFLNK | 0o400):
            with self.subTest(mode=mode):
                self.kernel = FakeKernel(self.fixture)
                path = self.fixture.archive_path("claim.json")
                node = self.kernel.add(path, b"partial permanent claim", mode=mode)
                error = self.failure()
                self.assertIs(error.observed["claim_attempted"], True)
                self.assertIs(self.kernel.nodes[path], node)
                self.assertEqual(node.raw, b"partial permanent claim")
                self.assertFalse(any(item[0] == "write" for item in self.kernel.calls))
                self.assert_closed_once()

    def test_short_reads_and_writes_complete_without_reissuing_attempt(self):
        self.kernel.read_limit = 31
        self.kernel.write_limit = 17
        result = self.acquire()
        self.assertEqual(result["batch_raw"], self.fixture.batch)
        creations = [item[1] for item in self.kernel.calls if item[0] == "open" and item[2] & os.O_CREAT]
        self.assertEqual(len(creations), len(set(creations)))
        self.assertEqual(len(creations), 5)
        self.assert_closed_once()

    def test_partial_claim_write_and_zero_progress_preserve_residue(self):
        for second in (0, OSError(errno.ENOSPC, "fabricated full archive")):
            with self.subTest(second=second):
                self.kernel = FakeKernel(self.fixture)
                self.kernel.write_actions = [9, second]
                error = self.failure()
                self.assertIs(error.observed["claim_attempted"], True)
                self.assertEqual(len(self.kernel.nodes[self.fixture.archive_path("claim.json")].raw), 9)
                self.assertEqual(error.observed["retained_files"], [])
                self.assert_closed_once()

    def test_fsync_failure_leaves_actual_batch_and_no_usable_success(self):
        def fail(fd):
            if self.kernel.handles[fd].node.path == self.fixture.archive_path("batch.ndjson"):
                raise OSError(errno.EIO, "fabricated batch fsync failure")
        self.kernel.on_sync = fail
        error = self.failure()
        self.assertIs(error.observed["claim_attempted"], True)
        self.assertEqual(self.kernel.nodes[self.fixture.archive_path("batch.ndjson")].raw, self.fixture.batch)
        self.assertEqual(error.observed["batch_raw"], self.fixture.batch)
        self.assertEqual(error.observed["retained_files"], [])
        self.assertNotIn(self.fixture.archive_path("acquisition.json"), self.kernel.nodes)
        self.assert_closed_once()

    def test_final_readback_detects_source_change_after_acquisition_publication(self):
        changed = []
        def mutate(fd):
            if self.kernel.handles[fd].node.path == self.fixture.archive_path("acquisition.json") and not changed:
                path = next(path for path in self.kernel.nodes if path.startswith(SOURCE + "/batch-"))
                node = self.kernel.nodes[path]
                node.raw = node.raw.replace(b"1", b"2")
                node.st_ctime_ns += 1
                changed.append(path)
        self.kernel.on_sync = mutate
        error = self.failure()
        self.assertTrue(changed)
        self.assertIsNotNone(error.observed["acquisition_raw"])
        self.assertIn(self.fixture.archive_path("acquisition.json"), self.kernel.nodes)
        self.assert_closed_once()

    def test_late_completion_and_ambiguous_close_never_return_success(self):
        for kind in ("deadline", "close"):
            with self.subTest(kind=kind):
                self.kernel = FakeKernel(self.fixture)
                def finish(fd):
                    if self.kernel.handles[fd].node.path == self.fixture.archive_path("acquisition.json"):
                        if kind == "deadline":
                            self.kernel.now = self.fixture.expectation["deadline_ns"]
                        else:
                            owned = next(handle for handle, value in self.kernel.handles.items() if value.node.path == ARCHIVE)
                            self.kernel.close_failures.add(owned)
                self.kernel.on_sync = finish
                error = self.failure()
                self.assertIn(self.fixture.archive_path("acquisition.json"), self.kernel.nodes)
                if kind == "close":
                    self.assertTrue(error.cleanup_failures)
                self.assert_closed_once()

    def test_foreign_reused_descriptor_is_reported_and_never_closed(self):
        replaced = []
        def substitute(fd):
            if self.kernel.handles[fd].node.path == self.fixture.archive_path("acquisition.json") and not replaced:
                target = next(handle for handle, value in self.kernel.handles.items() if value.node.path == SOURCE)
                foreign = self.kernel.add("/foreign/descriptor", mode=stat.S_IFDIR | 0o700)
                self.kernel.handles[target].node = foreign
                replaced.append(target)
        self.kernel.on_sync = substitute
        error = self.failure()
        self.assertTrue(error.cleanup_failures)
        self.assertEqual(len(replaced), 1)
        foreign_fd = replaced[0]
        self.assertEqual(set(self.kernel.handles), {foreign_fd})
        self.assertFalse(any(item[0] == "close" and item[1] == foreign_fd for item in self.kernel.calls))
        closed = [item[1] for item in self.kernel.calls if item[0] == "close"]
        self.assertEqual(len(closed), len(set(closed)))

    def test_actual_proc_reader_bounds_error_and_close_failure_stay_offline(self):
        for kind in ("oversize", "read", "close"):
            with self.subTest(kind=kind):
                self.kernel = FakeKernel(self.fixture)
                path = f"/proc/{READER_PID}/status"
                if kind == "oversize":
                    self.kernel.nodes[path].raw = b"x" * 16385
                elif kind == "read":
                    def fail_read(name, _offset, raw):
                        if name == path:
                            raise OSError(errno.EIO, "fabricated proc read error")
                        return raw
                    self.kernel.on_read = fail_read
                else:
                    def close_error(name, _offset, raw):
                        if name == path:
                            self.kernel.close_failures.update(fd for fd, handle in self.kernel.handles.items() if handle.node.path == path)
                        return raw
                    self.kernel.on_read = close_error
                error = self.failure()
                self.assertIs(error.observed["claim_attempted"], False)
                self.assertIsNone(error.observed["manifest_raw"])
                if kind == "close":
                    self.assertTrue(error.cleanup_failures)
                self.assert_closed_once()


if __name__ == "__main__":
    unittest.main()

