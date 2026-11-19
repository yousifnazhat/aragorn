"""Exercise the same recorder on anonymous test pipes, never a VM or EFI store."""
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time
import unittest


SRC = Path(__file__).resolve().parents[1] / "packaging/pi-core/immutable-host-b45"
CAP = 8 << 20
# Only this test harness accepts inherited arbitrary fds/clock offsets; not linked into the runner.
DRIVER = r'''
#import "serial-recorder.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>
int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc != 5 && argc != 6) return 70;
        if (atoi(argv[4])) {
            struct rlimit lim = {4, 4};
            if (signal(SIGXFSZ, SIG_IGN) == SIG_ERR || setrlimit(RLIMIT_FSIZE, &lim)) return 71;
        }
        uint64_t start = B45MonotonicNow() - strtoull(argv[3], NULL, 10);
        NSDictionary *report;
        if (argc == 6) {
            int notify = atoi(argv[5]);
            dispatch_semaphore_t armed = dispatch_semaphore_create(0);
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
                if (dispatch_semaphore_wait(armed, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)) == 0)
                    (void)write(notify, "A", 1);
            });
            report = B45RecordSerialArmed(atoi(argv[1]), atoi(argv[2]), start, armed);
        } else {
            report = B45RecordSerial(atoi(argv[1]), atoi(argv[2]), start);
        }
        if (!report) return 2;
        NSData *data = [NSJSONSerialization dataWithJSONObject:report options:0 error:NULL];
        return !data || fwrite(data.bytes, 1, data.length, stdout) != data.length;
    }
}
'''


class BoundedSerialRecorder(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.tmp = Path(tmp.name).resolve()
        cls.runner = cls.tmp / "test-recorder"
        source = cls.tmp / "fixture.m"
        source.write_text(DRIVER)
        cc = Path("/Library/Developer/CommandLineTools/usr/bin/clang")
        with cc.open("rb") as f:
            if hashlib.file_digest(f, "sha256").hexdigest() != "1220c0afafa12a6ae599d097ee7cf8b87c6b4d8e3fbb9783cee6b319a80683ba":
                raise ValueError("unreviewed local compiler")
        cls.env = {"PATH": "/usr/bin:/bin", "HOME": str(cls.tmp), "TMPDIR": str(cls.tmp)}
        subprocess.run([cc, "-isysroot", "/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk",
            "-arch", "arm64", "-mmacosx-version-min=14", "-fobjc-arc", "-fno-modules", "-Werror",
            "-framework", "Foundation", "-I", SRC, source, SRC / "serial-recorder.m", "-o", cls.runner],
            env=cls.env, cwd=cls.tmp, stdin=subprocess.DEVNULL, check=True, timeout=45)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=self.tmp)
        self.addCleanup(tmp.cleanup)
        self.attempt = Path(tmp.name)
        self.directory = os.open(self.attempt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.directory)
        self.raw = self.attempt / "serial.raw"

    def spawn(self, source, *, elapsed=0, fail_write=False, notify=None):
        profile = ('(version 1)(allow default)(deny network*)(deny file-write*)'
                   '(allow file-write* (subpath ' + json.dumps(str(self.attempt)) + '))')
        return subprocess.Popen(["/usr/bin/sandbox-exec", "-p", profile, self.runner, str(source),
            str(self.directory), str(elapsed), str(int(fail_write)), *([] if notify is None else [str(notify)])],
            pass_fds=(source, self.directory) if notify is None else (source, self.directory, notify),
            env=self.env, cwd=self.tmp, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def feed(self, data, **kwargs):
        r, w = os.pipe()
        try:
            proc = self.spawn(r, **kwargs)
        finally:
            os.close(r)
        with proc:
            with os.fdopen(w, "wb") as f:
                if data:
                    f.write(data)
            stdout, stderr = proc.communicate(timeout=10)
            self.assertEqual(proc.returncode, 0, stderr)
            return json.loads(stdout)

    def check_saved(self, result, data, status, eof):
        self.assertEqual(self.raw.read_bytes(), data)
        self.assertEqual(self.raw.stat().st_mode & 0o7777, 0o400)
        self.assertEqual(result["capture_bytes"], len(data))
        self.assertEqual(result["capture_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["status"], status)
        self.assertIs(result["pipe_eof"], eof)
        self.assertIs(result["sync_verified"], True)
        self.assertIs(result["boot_observed"], False)
        self.assertIs(result["phase3_exit_eligible"], False)
        self.assertLessEqual(result["attempt_start_ns"], result["record_start_ns"])
        self.assertLessEqual(result["record_start_ns"], result["record_end_ns"])

    def test_binary_stream_is_not_decoded_or_reconstructed(self):
        data = bytes(range(256)) * 190 + b"\r\n\0"
        self.check_saved(self.feed(data), data, "eof", True)

    def test_armed_is_observable_before_first_byte_or_pipe_retirement(self):
        r, w = os.pipe()
        notice, notify = os.pipe()
        try:
            proc = self.spawn(r, notify=notify)
        finally:
            os.close(r); os.close(notify)
        with proc, os.fdopen(notice, "rb", buffering=0) as event:
            with os.fdopen(w, "wb", buffering=0) as writer:
                self.assertTrue(select.select([event], [], [], 3)[0], "recorder did not arm before first byte")
                self.assertEqual(event.read(1), b"A")
                self.assertEqual(self.raw.read_bytes(), b"")
                self.assertIsNone(proc.poll())
                writer.write(b"after-arm")
            stdout, stderr = proc.communicate(timeout=3)
        self.assertEqual(proc.returncode, 0, stderr)
        self.check_saved(json.loads(stdout), b"after-arm", "eof", True)

    def test_empty_pipe_eof_is_not_an_observation(self):
        self.check_saved(self.feed(b""), b"", "empty", True)

    def test_exactly_the_cap_is_indeterminate_even_at_eof(self):
        data = b"z" * CAP
        self.check_saved(self.feed(data), data, "limit", False)

    def test_monotonic_deadline_preserves_partial_stream_while_writer_remains_open(self):
        r, w = os.pipe()
        try:
            os.write(w, b"head")
            proc = self.spawn(r, elapsed=179_700_000_000)
        finally:
            os.close(r)
        with proc, os.fdopen(w, "wb", buffering=0) as writer:
            sent = bytearray(b"head")
            end = time.monotonic() + 2
            while time.monotonic() < end and proc.poll() is None:
                try:
                    writer.write(b".")
                    sent += b"."
                except BrokenPipeError:
                    break
                time.sleep(0.01)
            out, err = proc.communicate(timeout=2)
        self.assertEqual(proc.returncode, 0, err)
        result = json.loads(out)
        partial = self.raw.read_bytes()
        self.assertTrue(partial.startswith(b"head") and sent.startswith(partial))
        self.assertGreaterEqual(result["record_end_ns"] - result["attempt_start_ns"], 180_000_000_000)
        self.check_saved(result, partial, "deadline", False)

    def test_short_disk_write_retains_only_persisted_prefix(self):
        r, w = os.pipe()
        try:
            os.write(w, b"abcd")
            proc = self.spawn(r, fail_write=True)
        finally:
            os.close(r)
        with proc, os.fdopen(w, "wb", buffering=0) as writer:
            end = time.monotonic() + 3
            while time.monotonic() < end and not (self.raw.exists() and self.raw.stat().st_size == 4):
                time.sleep(0.01)
            self.assertEqual(self.raw.read_bytes(), b"abcd")
            writer.write(b"efgh")
            stdout, stderr = proc.communicate(timeout=3)
        self.assertEqual(proc.returncode, 0, stderr)
        self.check_saved(json.loads(stdout), b"abcd", "write-error", False)

    def test_existing_capture_or_symlink_is_never_overwritten(self):
        original = self.attempt / "prior"
        original.write_bytes(b"prior")
        for symlink in (False, True):
            if symlink:
                self.raw.symlink_to(original)
            else:
                self.raw.write_bytes(b"existing")
            r, w = os.pipe()
            try:
                with self.spawn(r) as proc:
                    out, _ = proc.communicate(timeout=3)
                    self.assertEqual((proc.returncode, out), (2, b""))
            finally:
                os.close(r); os.close(w)
            self.assertEqual(self.raw.read_bytes(), b"prior" if symlink else b"existing")
            self.raw.unlink()
        self.assertEqual(original.read_bytes(), b"prior")

    def test_arbitrary_regular_input_or_shared_directory_refused_before_reservation(self):
        other = self.attempt / "not-pipe"
        other.write_bytes(b"regular")
        with other.open("rb") as f, self.spawn(f.fileno()) as proc:
            out, _ = proc.communicate(timeout=3)
            self.assertEqual((proc.returncode, out), (2, b""))
        self.attempt.chmod(0o755)
        r, w = os.pipe()
        try:
            with self.spawn(r) as proc:
                out, _ = proc.communicate(timeout=3)
                self.assertEqual((proc.returncode, out), (2, b""))
        finally:
            os.close(r); os.close(w)
        self.assertFalse(self.raw.exists())
