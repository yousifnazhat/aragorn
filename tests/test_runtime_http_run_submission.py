"""New broker journal checks with fabricated bytes and intercepted syscalls only."""

from contextlib import ExitStack
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aragorn import runtime_http_run_submission as subject


CONTROL = "/var/lib/aragorn-runtime-action/control"
LOCK = CONTROL + "/broker.lock"
PID, UID, GID, START = 701, 901, 902, 33
CONTROL_FD, LOCK_FD = 40, 41
BOOT = "11111111-2222-3333-4444-555555555555"
DEVICE = os.makedev(8, 1)
FALSE_FLAGS = (
    "acquisition_authenticity_verified", "sensor_health_verified",
    "effect_authorized", "run_qualified", "phase3_qualified",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def pin(label):
    return digest(label.encode("ascii"))


def artifact(raw):
    return {"base64": base64.b64encode(raw).decode("ascii"),
            "bytes": len(raw), "digest": digest(raw)}


def context_record():
    return {
        "schema": "aragorn/native-phase3-broker-reader-context/v1",
        **{name + "_digest": pin(name) for name in
           ("request", "effect", "grant", "deployment", "epoch")},
        "broker": {"pid": PID, "start_time_ticks": START, "uid": UID, "gid": GID},
        "provider": {"pid": 702, "start_time_ticks": 34, "uid": 0, "gid": 0},
        "clock": {"boot_id": BOOT, "clock_id": "CLOCK_BOOTTIME",
                  "time_namespace": {"device": DEVICE, "inode": 600}},
        "exchange_id": "e" * 64,
        "accepted_boottime_ns": 999_999_990,
        "deadline_boottime_ns": 1_500_000_000,
        "clock_bracket": {"boottime_before_ns": 1_000_000_000,
                          "monotonic_ns": 2_000_000_000,
                          "boottime_after_ns": 1_000_000_010,
                          "original_monotonic_deadline_ns": 2_500_000_000},
    }


def packet_pair(context, phase="BEFORE_CONNECT", previous=None):
    request = {
        "schema": "aragorn/native-phase3-broker-reader-request/v1",
        "context_digest": digest(canonical(context)),
        **{key: context[key] for key in
           ("exchange_id", "epoch_digest", "request_digest", "effect_digest",
            "deadline_boottime_ns")},
        "phase": phase, "previous_response_digest": previous,
    }
    payload = phase == "BEFORE_PAYLOAD_SEND"
    received = 1_150_000_000 if payload else 1_100_000_000
    finished = 1_160_000_000 if payload else 1_120_000_000
    bindings = {key: pin(key) for key in
                ("epoch", "challenge", "request", "process", "clock", "loss_scope", "policy")}
    loss = {
        "epoch_digest": bindings["epoch"], "challenge_digest": bindings["challenge"],
        "request_digest": bindings["request"], "scope_digest": bindings["loss_scope"],
        "before": {"start_ns": 1_000_000_025, "end_ns": 1_000_000_050,
                   "counters": [4, 0]},
        "after": {"start_ns": received + 5, "end_ns": received + 10,
                  "counters": [4, 0]},
    }
    evidence = artifact(b'{"fixture":"reader-bytes-not-health"}')
    response = {
        "schema": "aragorn/native-phase3-broker-reader-response/v1",
        "request_packet_digest": digest(canonical(request)),
        **{key: request[key] for key in ("exchange_id", "phase", "context_digest",
                                       "epoch_digest", "request_digest", "effect_digest")},
        "received_ns": received, "finished_ns": finished,
        "status": "EVIDENCE", "error_codes": [],
        "reader_connection_epoch": "c" * 64, "bindings": bindings,
        "reader_evidence": evidence,
        "reader_summary": artifact(b'{"status":"ACK","unverified_fixture":true}'),
        "reader_retention": {"bytes": evidence["bytes"], "digest": evidence["digest"]},
        "loss_record": artifact(canonical(loss)),
        "checkpoint_record": artifact(canonical({"fixture": phase})),
        **dict.fromkeys(FALSE_FLAGS, False),
    }
    return request, response


class MemoryJournal:
    """Separate named nodes and held handles expose substitution and partial writes."""

    def __init__(self):
        self.nodes, self.handles, self.calls = {}, {}, []
        self.next_inode, self.next_fd = 100, 1000
        self.now, self.monotonic = 1_000_000_020, 2_000_000_020
        self.pid, self.thread = PID, PID
        self.uids, self.gids = (UID,) * 3, (GID,) * 3
        self.write_actions, self.close_failures = [], set()
        self.sync_count, self.fail_sync = 0, None
        self.on_sync = lambda _fd: None
        self.boot_reads = []
        self.read_chunk_limit = None
        self.fdinfo_transform = lambda raw: raw
        self.read_transform = lambda _fd, raw: raw
        self.mount = 9
        for path in ("/", "/var", "/var/lib", "/var/lib/aragorn-runtime-action", "/run"):
            self.add(path, stat.S_IFDIR | 0o755, uid=0, gid=0)
        control = self.add(CONTROL, stat.S_IFDIR | 0o700)
        lock = self.add(LOCK, stat.S_IFREG | 0o600)
        self.borrow(CONTROL_FD, control, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        self.borrow(LOCK_FD, lock, os.O_RDWR | os.O_CLOEXEC)
        self.add(f"/proc/{PID}/ns/time", stat.S_IFREG | 0o444, uid=0, gid=0,
                 st_ino=600)
        self.add("/run/aragorn-broker-boot-id", stat.S_IFREG | 0o444,
                 (BOOT + "\n").encode(), uid=0, gid=0)

    def add(self, path, mode, raw=b"", *, uid=UID, gid=GID, **changes):
        node = SimpleNamespace(path=path, raw=raw, st_mode=mode, st_uid=uid, st_gid=gid,
                               st_dev=DEVICE, st_ino=self.next_inode, st_nlink=1,
                               st_size=len(raw), st_mtime_ns=1, st_ctime_ns=1)
        self.next_inode += 1
        for name, value in changes.items():
            setattr(node, name, value)
        self.nodes[path] = node
        return node

    def borrow(self, fd, node, flags):
        self.handles[fd] = SimpleNamespace(node=node, flags=flags, position=0)

    def resolve(self, name, dir_fd=None):
        name = os.fspath(name)
        if name.startswith("/"):
            return name
        if dir_fd is None:
            raise AssertionError("unexpected relative I/O without a held parent")
        return self.handles[dir_fd].node.path.rstrip("/") + "/" + name

    def open(self, name, flags, mode=0o777, *, dir_fd=None):
        path = self.resolve(name, dir_fd)
        self.calls.append(("open", path, flags, mode))
        if flags & os.O_CREAT:
            if not flags & os.O_EXCL:
                raise AssertionError("journal creation must be exclusive")
            if path in self.nodes:
                raise FileExistsError(errno.EEXIST, "fabricated existing name")
            node = self.add(path, stat.S_IFREG | mode)
            parent = self.handles[dir_fd].node
            parent.st_mtime_ns += 1
            parent.st_ctime_ns += 1
        else:
            if path not in self.nodes:
                raise AssertionError("unmodeled open: " + path)
            node = self.nodes[path]
            if stat.S_ISLNK(node.st_mode) and flags & os.O_NOFOLLOW:
                raise OSError(errno.ELOOP, "fabricated link")
        fd = self.next_fd
        self.next_fd += 1
        self.borrow(fd, node, flags)
        return fd

    def fstat(self, fd):
        return SimpleNamespace(**vars(self.handles[fd].node))

    def named_stat(self, name, *, dir_fd=None, follow_symlinks=True):
        path = self.resolve(name, dir_fd)
        self.calls.append(("stat", path, follow_symlinks))
        if follow_symlinks and "/ns/" not in path:
            raise AssertionError("non-namespace lookup followed a link")
        return SimpleNamespace(**vars(self.nodes[path]))

    def write_all(self, fd, raw):
        remaining = memoryview(raw)
        while remaining:
            action = self.write_actions.pop(0) if self.write_actions else len(remaining)
            if isinstance(action, BaseException):
                raise action
            if not 0 < action <= len(remaining):
                raise AssertionError("invalid fabricated write script")
            node = self.handles[fd].node
            node.raw += bytes(remaining[:action])
            node.st_size = len(node.raw)
            node.st_mtime_ns += 1
            node.st_ctime_ns += 1
            self.calls.append(("write", fd, action))
            remaining = remaining[action:]

    def pread(self, fd, count, offset):
        self.calls.append(("pread", fd, count, offset))
        raw = self.handles[fd].node.raw[offset:offset + count]
        return self.read_transform(fd, raw)

    def read(self, fd, count):
        handle = self.handles[fd]
        if self.read_chunk_limit is not None:
            count = min(count, self.read_chunk_limit)
        raw = self.pread(fd, count, handle.position)
        handle.position += len(raw)
        return raw

    def fsync(self, fd):
        self.calls.append(("fsync", fd))
        self.sync_count += 1
        if self.sync_count == self.fail_sync:
            raise OSError("fabricated fsync failure")
        self.on_sync(fd)

    def close(self, fd):
        self.calls.append(("close", fd))
        if fd in (CONTROL_FD, LOCK_FD):
            raise AssertionError("borrowed broker descriptor was closed")
        self.handles.pop(fd)
        if fd in self.close_failures:
            raise OSError("fabricated ambiguous close")

    def fcntl(self, fd, command):
        handle = self.handles[fd]
        if command == subject.fcntl.F_GETFL:
            return handle.flags & ~os.O_CLOEXEC
        if command == subject.fcntl.F_GETFD:
            return subject.fcntl.FD_CLOEXEC if handle.flags & os.O_CLOEXEC else 0
        raise AssertionError("unexpected descriptor mutation")

    def fdinfo(self):
        lock = self.handles[LOCK_FD].node
        return (f"pos:\t0\nflags:\t{self.handles[LOCK_FD].flags:o}\n"
                f"mnt_id:\t{self.mount}\nino:\t{lock.st_ino}\n"
                f"lock:\t1: FLOCK ADVISORY WRITE {PID} "
                f"{os.major(lock.st_dev):x}:{os.minor(lock.st_dev):x}:{lock.st_ino} 0 EOF\n").encode()

    def virtual(self, path, maximum):
        self.calls.append(("virtual", path, maximum))
        if path == f"/proc/self/fdinfo/{LOCK_FD}":
            raw = self.fdinfo_transform(self.fdinfo())
        elif path == f"/proc/{PID}/stat":
            raw = (f"{PID} (broker) worker) " + " ".join(
                ["S"] + ["0"] * 18 + [str(START)] + ["0"] * 4) + "\n").encode()
        else:
            raise AssertionError("unmodeled virtual source: " + path)
        if len(raw) > maximum:
            raise ValueError("fabricated bounded proc read")
        return raw

    def clock(self, clock_id):
        if clock_id == subject.time.CLOCK_BOOTTIME:
            return self.boot_reads.pop(0) if self.boot_reads else self.now
        if clock_id == subject.time.CLOCK_MONOTONIC:
            return self.monotonic
        raise AssertionError("unexpected clock domain")

    def advance(self, now):
        self.now, self.monotonic = now, now + 1_000_000_000

    def patches(self):
        # A strict replacement prevents an unmodeled call reaching live proc/files.
        allowed = {name: getattr(os, name) for name in dir(os) if name.isupper()}
        allowed.update(open=self.open, fstat=self.fstat, stat=self.named_stat,
                       pread=self.pread, read=self.read, fsync=self.fsync, close=self.close,
                       getpid=lambda: self.pid, getresuid=lambda: self.uids,
                       getresgid=lambda: self.gids, getuid=lambda: self.uids[0],
                       geteuid=lambda: self.uids[1], getgid=lambda: self.gids[0],
                       getegid=lambda: self.gids[1], major=os.major, minor=os.minor,
                       readlink=lambda path: f"time:[{self.nodes[path].st_ino}]",
                       get_inheritable=lambda fd: not bool(self.handles[fd].flags & os.O_CLOEXEC))
        native_fcntl = subject.fcntl
        stack = ExitStack()
        stack.enter_context(patch.object(subject, "os", SimpleNamespace(**allowed)))
        stack.enter_context(patch.object(subject, "sys", SimpleNamespace(platform="linux")))
        stack.enter_context(patch.object(subject, "threading", SimpleNamespace(get_native_id=lambda: self.thread)))
        stack.enter_context(patch.object(subject, "time", SimpleNamespace(
            CLOCK_BOOTTIME=7, CLOCK_MONOTONIC=1, clock_gettime_ns=self.clock)))
        stack.enter_context(patch.object(subject, "fcntl", SimpleNamespace(
            F_GETFL=native_fcntl.F_GETFL, F_GETFD=native_fcntl.F_GETFD,
            FD_CLOEXEC=native_fcntl.FD_CLOEXEC, fcntl=self.fcntl)))
        stack.enter_context(patch.object(subject, "_ORIGINAL_PID", PID))
        stack.enter_context(patch.object(subject, "write_all", side_effect=self.write_all))
        stack.enter_context(patch.object(subject.SubmissionJournal, "_read_virtual",
                                         lambda _journal, path, maximum: self.virtual(path, maximum)))
        return stack

    def journal_files(self):
        return {path: node.raw for path, node in self.nodes.items()
                if path.startswith(CONTROL + "/run-reader-")}

    def events(self):
        return [json.loads(raw) for path, raw in sorted(self.journal_files().items())
                if "-event-" in path]


class HttpRunSubmissionTests(unittest.TestCase):
    def begin(self, fs, context=None):
        context = context_record() if context is None else context
        raw = canonical(context)
        config = SimpleNamespace(control_root=Path(CONTROL), lock_path=Path(LOCK),
                                 expected_broker_uid=UID, expected_runtime_uid=903,
                                 expected_runtime_gid=904)
        return subject.begin_http_submission_locked(
            CONTROL_FD, LOCK_FD, config, context_raw=raw,
            expected_context_digest=digest(raw))

    def first_check(self, fs, journal, *, change=None):
        request, response = packet_pair(context_record())
        if change is not None:
            change(request, response)
        fs.advance(1_130_000_000)
        journal.record_check("BEFORE_CONNECT", request_raw=canonical(request),
                             response_raw=canonical(response))
        return request, response

    def first_intent(self, fs, journal):
        pair = self.first_check(fs, journal)
        fs.advance(1_140_000_000)
        journal.record_connect_intent()
        return pair

    def payload_check(self, fs, journal, first_response, *, change=None):
        request, response = packet_pair(context_record(), "BEFORE_PAYLOAD_SEND",
                                         digest(canonical(first_response)))
        if change is not None:
            change(request, response)
        fs.advance(1_170_000_000)
        journal.record_check("BEFORE_PAYLOAD_SEND", request_raw=canonical(request),
                             response_raw=canonical(response))
        return request, response

    def assert_borrowed_only(self, fs):
        self.assertEqual(set(fs.handles), {CONTROL_FD, LOCK_FD})
        self.assertNotIn(("close", CONTROL_FD), fs.calls)
        self.assertNotIn(("close", LOCK_FD), fs.calls)

    def test_full_lifecycle_publishes_original_packets_and_monotonic_intent(self):
        fs = MemoryJournal()
        with fs.patches():
            journal = self.begin(fs)
            request1, response1 = self.first_check(fs, journal)
            pre = json.loads(journal.submission_snapshot())
            self.assertEqual(set(pre), {"epoch_digest", "challenge_digest", "request_digest",
                                       "checked_ns", "custody", "intent", "effect_possible"})
            self.assertEqual((pre["custody"], pre["intent"], pre["effect_possible"]),
                             ("EXCLUSIVE", False, False))
            fs.advance(1_140_000_000)
            journal.record_connect_intent()
            request2, response2 = self.payload_check(fs, journal, response1)
            self.assertTrue(json.loads(journal.submission_snapshot())["intent"])
            fs.advance(1_180_000_000)
            journal.record_payload_intent()
            transport = b'{"connect_attempted":false,"status":"NOT_PERFORMED"}'
            journal.finish(transport_raw=transport, failure_code=None)
            self.assertIsNone(journal.final_readback())
            rows = fs.events()
            self.assertEqual([row["phase"] for row in rows],
                             ["BOUND", "CONNECT_CHECKED", "CONNECT_INTENT", "PAYLOAD_CHECKED",
                              "PAYLOAD_INTENT", "TERMINAL"])
            self.assertEqual([row["sequence"] for row in rows], list(range(6)))
            self.assertIsNone(rows[0]["previous_digest"])
            for previous, row in zip(rows, rows[1:]):
                self.assertEqual(row["previous_digest"], digest(canonical(previous)))
            self.assertEqual([(row["intent"], row["effect_possible"]) for row in rows],
                             [(False, False)] * 2 + [(True, True)] * 4)
            packets = {raw for path, raw in fs.journal_files().items() if "-packet-" in path}
            self.assertEqual(packets, {canonical(request1), canonical(response1), canonical(request2),
                                       canonical(response2), transport})
            self.assertTrue(all(node.st_mode == stat.S_IFREG | 0o400 and node.st_nlink == 1
                                for path, node in fs.nodes.items() if "run-reader-" in path))
            journal.close()
            self.assert_borrowed_only(fs)

    def test_preintent_terminal_stays_unknown_despite_opaque_not_performed(self):
        fs = MemoryJournal()
        with fs.patches():
            journal = self.begin(fs)
            journal.finish(transport_raw=b'{"status":"NOT_PERFORMED"}', failure_code="POLICY_REFUSED")
            terminal = fs.events()[-1]
            self.assertEqual(terminal["phase"], "TERMINAL")
            self.assertIs(terminal["intent"], False)
            self.assertIsNone(terminal["effect_possible"])
            journal.final_readback()
            journal.close()
            self.assert_borrowed_only(fs)

    def test_snapshot_requires_reader_binding_and_bad_transition_poison_is_sticky(self):
        for operation in ("submission_snapshot", "record_connect_intent", "record_payload_intent"):
            with self.subTest(operation=operation):
                fs = MemoryJournal()
                with fs.patches():
                    journal = self.begin(fs)
                    with self.assertRaises(subject.SubmissionJournalError):
                        getattr(journal, operation)()
                    with self.assertRaises(subject.SubmissionJournalError):
                        self.first_check(fs, journal)
                    self.assertEqual([row["phase"] for row in fs.events()], ["BOUND"])
                    with self.assertRaises(subject.SubmissionJournalError):
                        journal.close()
                    self.assert_borrowed_only(fs)

    def test_each_publication_is_exclusive_synced_and_read_back_before_next_record(self):
        fs = MemoryJournal()
        with fs.patches():
            journal = self.begin(fs)
            self.first_check(fs, journal)
            calls = list(fs.calls)
            creates = [(index, row) for index, row in enumerate(calls)
                       if row[0] == "open" and row[2] & os.O_CREAT]
            self.assertEqual(len(creates), 5)  # context, BOUND, two packets, CHECKED
            for position, (index, row) in enumerate(creates):
                end = creates[position + 1][0] if position + 1 < len(creates) else len(calls)
                window = calls[index:end]
                self.assertEqual(row[2] & (os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC),
                                 os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC)
                self.assertEqual(row[3], 0o400)
                write = next(event for event in window if event[0] == "write")
                fd = write[1]
                file_sync = window.index(("fsync", fd))
                parent_sync = window.index(("fsync", CONTROL_FD))
                rereads = [i for i, event in enumerate(window)
                           if event[0] == "pread" and event[1] == fd]
                self.assertLess(window.index(write), file_sync)
                self.assertLess(file_sync, parent_sync)
                self.assertTrue(rereads)
                self.assertLess(parent_sync, min(rereads))
                self.assertTrue(any(event[0] == "virtual" and "fdinfo" in event[1]
                                    for event in window[parent_sync + 1:]))
            self.assertLess(next(index for index, row in creates if "-packet-" in row[1]),
                            next(index for index, row in creates if "-event-1" in row[1]))
            journal.close()
            self.assert_borrowed_only(fs)

    def test_any_existing_context_refuses_and_preserves_original_node(self):
        raw = canonical(context_record())
        name = CONTROL + "/run-reader-" + pin("request")[7:] + "-context.json"
        for mode, old in ((stat.S_IFREG | 0o400, raw), (stat.S_IFREG | 0o400, b"{"),
                          (stat.S_IFLNK | 0o777, b"elsewhere"), (stat.S_IFDIR | 0o700, b"")):
            with self.subTest(mode=mode, size=len(old)):
                fs = MemoryJournal()
                original = fs.add(name, mode, old)
                with fs.patches():
                    with self.assertRaises(subject.SubmissionJournalError) as caught:
                        self.begin(fs)
                    self.assertEqual(caught.exception.original_error["type"], "FileExistsError")
                    self.assertIs(fs.nodes[name], original)
                    self.assertEqual(original.raw, old)
                    self.assertEqual(fs.events(), [])
                    self.assert_borrowed_only(fs)

    def test_partial_publication_keeps_residue_original_error_and_attempted_intent(self):
        for failure in ("partial_write", "file_sync", "parent_sync", "readback"):
            with self.subTest(failure=failure):
                fs = MemoryJournal()
                with fs.patches():
                    journal = self.begin(fs)
                    self.first_check(fs, journal)
                    fs.advance(1_140_000_000)
                    if failure == "partial_write":
                        fs.write_actions = [7, OSError("fabricated partial intent")]
                    elif failure in ("file_sync", "parent_sync"):
                        fs.fail_sync = fs.sync_count + (1 if failure == "file_sync" else 2)
                    else:
                        def corrupt_intent(fd, raw):
                            return b"x" + raw[1:] if fs.handles[fd].node.path.endswith("-event-2.json") and raw else raw
                        fs.read_transform = corrupt_intent
                    with self.assertRaises(subject.SubmissionJournalError) as caught:
                        journal.record_connect_intent()
                    error = caught.exception
                    self.assertTrue(error.intent_attempted)
                    self.assertFalse(error.known_intent)
                    self.assertIs(error.effect_possible, True)
                    self.assertEqual(json.loads(error.last_completed_event)["phase"], "CONNECT_CHECKED")
                    self.assertIsInstance(error.partial_bytes, bytes)
                    residue = {path: raw for path, raw in fs.journal_files().items()
                               if path.endswith("-event-2.json")}
                    self.assertEqual(len(residue), 1)
                    if failure == "partial_write":
                        self.assertEqual(next(iter(residue.values())), error.partial_bytes[:7])
                    count = len(fs.calls)
                    with self.assertRaises(subject.SubmissionJournalError):
                        journal.record_connect_intent()
                    self.assertFalse(any(call[0] == "open" for call in fs.calls[count:]))
                    with self.assertRaises(subject.SubmissionJournalError) as closed:
                        journal.close()
                    self.assertEqual(closed.exception.original_error, error.original_error)
                    self.assertTrue(all(fs.nodes[path].raw == raw for path, raw in residue.items()))
                    self.assert_borrowed_only(fs)

    def test_root_ancestors_and_named_held_process_namespace_lock_custody(self):
        for variant in ("root_owner", "root_write", "control_swap", "lock_swap", "file_swap",
                        "file_links", "mount", "pid", "thread", "saved_uid", "saved_gid",
                        "namespace_swap", "boot_swap"):
            with self.subTest(variant=variant):
                fs = MemoryJournal()
                if variant.startswith("root_"):
                    if variant == "root_owner":
                        fs.nodes["/var"].st_uid = UID
                    else:
                        fs.nodes["/var"].st_mode = stat.S_IFDIR | 0o775
                    with fs.patches():
                        with self.assertRaises(subject.SubmissionJournalError):
                            self.begin(fs)
                        self.assertEqual(fs.journal_files(), {})
                        self.assert_borrowed_only(fs)
                    continue
                with fs.patches():
                    journal = self.begin(fs)
                    self.first_intent(fs, journal)
                    if variant == "control_swap":
                        fs.add(CONTROL, stat.S_IFDIR | 0o700)
                    elif variant == "lock_swap":
                        fs.add(LOCK, stat.S_IFREG | 0o600)
                    elif variant in ("file_swap", "file_links"):
                        path = next(path for path in fs.journal_files() if path.endswith("-context.json"))
                        if variant == "file_swap":
                            fs.add(path, stat.S_IFREG | 0o400, fs.nodes[path].raw)
                        else:
                            fs.nodes[path].st_nlink = 2
                    elif variant == "mount":
                        fs.mount += 1
                    elif variant == "pid":
                        fs.pid += 1
                    elif variant == "thread":
                        fs.thread += 1
                    elif variant == "saved_uid":
                        fs.uids = (UID, UID, UID + 1)
                    elif variant == "saved_gid":
                        fs.gids = (GID, GID, GID + 1)
                    elif variant == "namespace_swap":
                        fs.add(f"/proc/{PID}/ns/time", stat.S_IFREG | 0o444, uid=0, gid=0)
                    else:
                        fs.add("/run/aragorn-broker-boot-id", stat.S_IFREG | 0o444,
                               (BOOT + "\n").encode(), uid=0, gid=0)
                    with self.assertRaises(subject.SubmissionJournalError) as caught:
                        journal.submission_snapshot()
                    self.assertTrue(caught.exception.known_intent)
                    with self.assertRaises(subject.SubmissionJournalError):
                        journal.close()
                    self.assert_borrowed_only(fs)

    def test_readback_rechecks_process_ancestry_and_lock_after_journal_or_boot_read(self):
        for source in ("journal", "boot"):
            for changed in ("process", "ancestor", "lock"):
                with self.subTest(source=source, changed=changed):
                    fs = MemoryJournal()
                    with fs.patches():
                        journal = self.begin(fs)
                        self.first_check(fs, journal)
                        fired = []
                        def change_during_read(fd, raw):
                            path = fs.handles[fd].node.path
                            target = path.endswith("-context.json") if source == "journal" else path == "/run/aragorn-broker-boot-id"
                            if target and not fired:
                                fired.append(True)
                                if changed == "process":
                                    fs.pid += 1
                                elif changed == "ancestor":
                                    fs.add("/var", stat.S_IFDIR | 0o755, uid=0, gid=0)
                                else:
                                    fs.fdinfo_transform = lambda value: value.replace(b" WRITE ", b" READ ")
                            return raw
                        fs.read_transform = change_during_read
                        with self.assertRaises(subject.SubmissionJournalError):
                            journal.submission_snapshot()
                        self.assertEqual(fired, [True])
                        with self.assertRaises(subject.SubmissionJournalError):
                            journal.close()
                        self.assert_borrowed_only(fs)

    def test_closing_boottime_sample_catches_suspend_before_intent_attempt(self):
        fs = MemoryJournal()
        with fs.patches():
            journal = self.begin(fs)
            self.first_check(fs, journal)
            fs.advance(1_140_000_000)
            fs.boot_reads = [1_140_000_000, 1_500_000_000]
            before = set(fs.journal_files())
            with self.assertRaises(subject.SubmissionJournalError) as caught:
                journal.record_connect_intent()
            self.assertFalse(caught.exception.intent_attempted)
            self.assertFalse(caught.exception.known_intent)
            self.assertEqual(set(fs.journal_files()), before)
            with self.assertRaises(subject.SubmissionJournalError):
                journal.close()
            self.assert_borrowed_only(fs)

    def test_checked_event_uses_its_exact_timestamp_not_an_earlier_guard(self):
        fs = MemoryJournal()
        with fs.patches():
            journal = self.begin(fs)
            original_event = journal._event
            def delay_event(phase, **kwargs):
                if phase == "CONNECT_CHECKED":
                    fs.advance(1_320_000_000)  # Exactly 200ms after response.finished_ns.
                return original_event(phase, **kwargs)
            with patch.object(journal, "_event", side_effect=delay_event):
                with self.assertRaises(subject.SubmissionJournalError) as caught:
                    self.first_check(fs, journal)
            self.assertFalse(caught.exception.known_intent)
            self.assertEqual([row["phase"] for row in fs.events()], ["BOUND"])
            self.assertEqual(len([path for path in fs.journal_files() if "-packet-" in path]), 2)
            with self.assertRaises(subject.SubmissionJournalError):
                journal.close()
            self.assert_borrowed_only(fs)

    def test_postpublication_staleness_retains_durable_intent_and_no_retry(self):
        fs = MemoryJournal()
        with fs.patches():
            journal = self.begin(fs)
            self.first_check(fs, journal)
            fs.advance(1_140_000_000)
            def stale_after_sync(fd):
                if fs.handles[fd].node.path.endswith("-event-2.json"):
                    fs.advance(1_320_000_000)
            fs.on_sync = stale_after_sync
            with self.assertRaises(subject.SubmissionJournalError) as caught:
                journal.record_connect_intent()
            self.assertTrue(caught.exception.intent_attempted)
            self.assertTrue(caught.exception.effect_possible)
            self.assertTrue(fs.events()[-1]["intent"])
            names = set(fs.journal_files())
            with self.assertRaises(subject.SubmissionJournalError):
                journal.record_connect_intent()
            self.assertEqual(set(fs.journal_files()), names)
            with self.assertRaises(subject.SubmissionJournalError):
                journal.close()
            self.assert_borrowed_only(fs)

    def test_cleanup_keeps_original_failure_and_never_retries_ambiguous_close(self):
        fs = MemoryJournal()
        with fs.patches():
            journal = self.begin(fs)
            self.first_intent(fs, journal)
            failing_fd = max(fs.handles)
            fs.close_failures.add(failing_fd)
            fs.thread += 1
            with self.assertRaises(subject.SubmissionJournalError) as primary:
                journal.submission_snapshot()
            with self.assertRaises(subject.SubmissionJournalError) as cleanup:
                journal.close()
            self.assertEqual(cleanup.exception.original_error, primary.exception.original_error)
            self.assertTrue(cleanup.exception.known_intent)
            self.assertEqual(len(cleanup.exception.cleanup_failures), 1)
            self.assertEqual(fs.calls.count(("close", failing_fd)), 1)
            count = len(fs.calls)
            with self.assertRaises(subject.SubmissionJournalError):
                journal.close()
            self.assertEqual(len(fs.calls), count)
            self.assert_borrowed_only(fs)

    def test_cleanup_never_closes_a_reused_foreign_owned_descriptor(self):
        fs = MemoryJournal()
        with fs.patches():
            journal = self.begin(fs)
            fd = next(fd for fd, handle in fs.handles.items() if handle.node.path == "/var")
            foreign = fs.add("/foreign-fabricated", stat.S_IFREG | 0o400, b"foreign", uid=77, gid=78)
            fs.handles[fd].node = foreign
            with self.assertRaises(subject.SubmissionJournalError) as caught:
                journal.close()
            self.assertTrue(caught.exception.cleanup_failures)
            self.assertNotIn(("close", fd), fs.calls)
            self.assertIs(fs.handles[fd].node, foreign)
            self.assertEqual(set(fs.handles), {CONTROL_FD, LOCK_FD, fd})
            count = len(fs.calls)
            with self.assertRaises(subject.SubmissionJournalError):
                journal.close()
            self.assertEqual(len(fs.calls), count)

    def test_context_chronology_scalar_clocks_and_terminal_expiry(self):
        for variant in ("accepted", "bracket", "budget", "clock_bool", "clock_rollback", "mono_expired"):
            with self.subTest(variant=variant):
                fs, context = MemoryJournal(), context_record()
                if variant == "accepted":
                    context["accepted_boottime_ns"] = 1_000_000_001
                elif variant == "bracket":
                    context["clock_bracket"]["boottime_after_ns"] = 999_999_999
                elif variant == "budget":
                    context["deadline_boottime_ns"] += 1
                elif variant == "clock_bool":
                    fs.now = True
                elif variant == "clock_rollback":
                    fs.now = 1_000_000_009
                else:
                    fs.monotonic = 2_500_000_000
                with fs.patches():
                    with self.assertRaises(subject.SubmissionJournalError):
                        self.begin(fs, context)
                    self.assertEqual(fs.journal_files(), {})
                    self.assert_borrowed_only(fs)
        fs = MemoryJournal()
        with fs.patches():
            journal = self.begin(fs)
            self.first_intent(fs, journal)
            fs.advance(1_600_000_000)
            journal.finish(transport_raw=None, failure_code="TRANSPORT_INDETERMINATE")
            self.assertEqual(fs.events()[-1]["checked_ns"], 1_600_000_000)
            self.assertTrue(fs.events()[-1]["intent"])
            journal.final_readback()
            journal.close()
            with self.assertRaises(subject.SubmissionJournalError):
                journal.submission_snapshot()
            self.assert_borrowed_only(fs)

    def test_refused_ack_looking_or_missing_reset_increased_loss_never_allows_intent(self):
        for variant in ("refused_ack", "unknown", "reset", "increase", "missing_before", "missing_after"):
            with self.subTest(variant=variant):
                fs = MemoryJournal()
                with fs.patches():
                    journal = self.begin(fs)
                    def change(_request, response):
                        if variant == "refused_ack":
                            response.update(status="REFUSED", error_codes=["RETENTION_FAILED"],
                                            reader_retention=None)
                        else:
                            loss = json.loads(base64.b64decode(response["loss_record"]["base64"]))
                            if variant.startswith("missing_"):
                                loss[variant.removeprefix("missing_")] = None
                            else:
                                loss["after"]["counters"][0] = {"unknown": None, "reset": 3, "increase": 5}[variant]
                            response["loss_record"] = artifact(canonical(loss))
                    _, response = self.first_check(fs, journal, change=change)
                    with self.assertRaises(subject.SubmissionJournalError):
                        journal.record_connect_intent()
                    self.assertIn(canonical(response), fs.journal_files().values())
                    self.assertFalse(any(row["intent"] for row in fs.events()))
                    with self.assertRaises(subject.SubmissionJournalError):
                        journal.close()
                    self.assert_borrowed_only(fs)

    def test_second_check_requires_original_reader_fresh_loss_and_postconnect_receipt(self):
        for variant in ("previous", "reader", "summary", "connection", "baseline", "old_after",
                        "before_connect", "late_after"):
            with self.subTest(variant=variant):
                fs = MemoryJournal()
                with fs.patches():
                    journal = self.begin(fs)
                    _, first = self.first_intent(fs, journal)
                    def change(request, response):
                        if variant == "previous":
                            request["previous_response_digest"] = pin("wrong-predecessor")
                            response["request_packet_digest"] = digest(canonical(request))
                        elif variant in ("reader", "summary"):
                            name = "reader_evidence" if variant == "reader" else "reader_summary"
                            response[name] = artifact(b'{"changed":true}')
                            if variant == "reader":
                                response["reader_retention"] = {
                                    key: response[name][key] for key in ("bytes", "digest")}
                        elif variant == "connection":
                            response["reader_connection_epoch"] = "d" * 64
                        else:
                            loss = json.loads(base64.b64decode(response["loss_record"]["base64"]))
                            if variant == "baseline":
                                loss["before"]["start_ns"] += 1
                            elif variant == "old_after":
                                loss["after"] = json.loads(base64.b64decode(first["loss_record"]["base64"]))["after"]
                            elif variant == "late_after":
                                loss["after"]["end_ns"] = response["finished_ns"] + 1
                            else:
                                response["received_ns"] = 1_139_999_999
                            response["loss_record"] = artifact(canonical(loss))
                    with self.assertRaises(subject.SubmissionJournalError) as caught:
                        self.payload_check(fs, journal, first, change=change)
                    self.assertTrue(caught.exception.known_intent)
                    self.assertEqual(json.loads(caught.exception.last_completed_event)["phase"], "CONNECT_INTENT")
                    self.assertFalse(any(row["phase"] == "PAYLOAD_CHECKED" for row in fs.events()))
                    with self.assertRaises(subject.SubmissionJournalError):
                        journal.close()
                    self.assert_borrowed_only(fs)

    def test_fdinfo_requires_exact_exclusive_original_owner_and_flags(self):
        variants = {
            "missing_lock": lambda raw: b"\n".join(raw.splitlines()[:-1]) + b"\n",
            "duplicate": lambda raw: raw + b"pos:\t0\n",
            "unknown": lambda raw: raw + b"other:\t0\n",
            "foreign": lambda raw: raw.replace(b"WRITE 701 ", b"WRITE 702 "),
            "read": lambda raw: raw.replace(b" WRITE ", b" READ "),
            "posix": lambda raw: raw.replace(b" FLOCK ", b" POSIX "),
            "blocked": lambda raw: raw.replace(b"1: FLOCK", b"1: -> FLOCK"),
            "flags": lambda raw: raw.replace(f"flags:\t{os.O_RDWR | os.O_CLOEXEC:o}".encode(), b"flags:\t0"),
            "inode": lambda raw: raw.replace(b"ino:\t106", b"ino:\t999"),
            "nonascii": lambda raw: raw + b"\xff",
        }
        for name, transform in variants.items():
            with self.subTest(name=name):
                fs = MemoryJournal()
                if name == "inode":
                    inode = fs.handles[LOCK_FD].node.st_ino
                    transform = lambda raw: raw.replace(f"ino:\t{inode}".encode(), b"ino:\t999")
                fs.fdinfo_transform = transform
                with fs.patches():
                    with self.assertRaises(subject.SubmissionJournalError) as caught:
                        self.begin(fs)
                    self.assertEqual(fs.journal_files(), {})
                    self.assertEqual(caught.exception.custody_observations["latest"], transform(fs.fdinfo()))
                    self.assert_borrowed_only(fs)

    def test_actual_virtual_reader_bounds_partial_reads_and_closes_owned_proc_fd(self):
        real_reader = subject.SubmissionJournal._read_virtual
        path = f"/proc/self/fdinfo/{LOCK_FD}"
        for variant in ("multiple_reads", "oversize", "read_error", "close_error"):
            with self.subTest(variant=variant):
                fs = MemoryJournal()
                with fs.patches():
                    journal = self.begin(fs)
                    raw = fs.fdinfo() if variant != "oversize" else b"x" * 4097
                    fs.add(path, stat.S_IFREG | 0o444, raw)
                    fd = fs.next_fd
                    fs.read_chunk_limit = 7
                    if variant == "read_error":
                        def fail_second_read(descriptor, value):
                            if descriptor == fd and fs.handles[descriptor].position >= 7:
                                raise OSError("fabricated interrupted proc read")
                            return value
                        fs.read_transform = fail_second_read
                    elif variant == "close_error":
                        fs.close_failures.add(fd)
                    with patch.object(subject.SubmissionJournal, "_read_virtual", real_reader):
                        if variant == "multiple_reads":
                            self.assertEqual(journal._read_virtual(path, 4096), raw)
                        else:
                            expected = ValueError if variant == "oversize" else OSError
                            with self.assertRaises(expected):
                                journal._read_virtual(path, 4096)
                    self.assertNotIn(fd, fs.handles)
                    self.assertEqual(fs.calls.count(("close", fd)), 1)
                    self.assertGreater(len([row for row in fs.calls
                                            if row[0] == "pread" and row[1] == fd]), 1)
                    retained = raw[:7] if variant == "read_error" else raw[:4096]
                    self.assertEqual(journal._fdinfo_latest, retained)
                    opened = next(row for row in fs.calls if row[0] == "open" and row[1] == path)
                    self.assertEqual(opened[2] & (os.O_NOFOLLOW | os.O_CLOEXEC),
                                     os.O_NOFOLLOW | os.O_CLOEXEC)
                    fs.read_transform = lambda _fd, value: value
                    if variant == "close_error":
                        with self.assertRaises(subject.SubmissionJournalError) as caught:
                            journal.close()
                        self.assertEqual(len(caught.exception.cleanup_failures), 1)
                    else:
                        journal.close()
                    self.assert_borrowed_only(fs)
