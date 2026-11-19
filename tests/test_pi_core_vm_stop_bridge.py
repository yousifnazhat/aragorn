"""No VZ machine, store or VM allocation. Drive the compiled bridge via its inherited pipe."""
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import unittest

from scripts.pi_core_host_watchdog import _raw, _request


SRC = Path(__file__).resolve().parents[1] / "packaging/pi-core/immutable-host-b46"
SESSION = "a2345678-1234-4000-9000-123456789abc"
DRIVER = r'''
#import "vm-stop.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const char queueKey = 0;
static void output(NSDictionary *object) {
    NSMutableData *d = [[NSJSONSerialization dataWithJSONObject:object options:0 error:NULL] mutableCopy];
    [d appendBytes:"\n" length:1];
    if (write(STDOUT_FILENO, d.bytes, d.length) != (ssize_t)d.length) _exit(82);
}
// An ordinary NSObject implementing only selectors consumed by the bridge.
// All operational selectors assert exact dispatch-queue affinity.
@interface InertTarget : NSObject
@property (strong) dispatch_queue_t queue;
@property VZVirtualMachineState value;
@property BOOL deny;
@property unsigned gracefulCalls, forcedCalls;
@property (copy) void (^completion)(NSError *);
@end
@implementation InertTarget
- (void)check { if (dispatch_get_specific(&queueKey) != (__bridge void *)self) _exit(80); }
- (VZVirtualMachineState)state { [self check]; return self.value; }
- (BOOL)canRequestStop { [self check]; return !self.deny; }
- (BOOL)canStop { [self check]; return !self.deny; }
- (BOOL)requestStopWithError:(NSError **)err { [self check]; self.gracefulCalls++; return YES; }
- (void)stopWithCompletionHandler:(void (^)(NSError *))block {
    [self check]; self.forcedCalls++; self.completion = block;
}
@end
int main(int argc, char **argv) { @autoreleasepool {
    if (argc != 3) return 70;
    int fd = atoi(argv[1]);
    NSString *mode = @(argv[2]);
    InertTarget *m = [InertTarget new];
    m.queue = dispatch_queue_create("fixture.one-held-target", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_set_specific(m.queue, &queueKey, (__bridge void *)m, NULL);
    m.deny = [mode isEqual:@"deny"];
    m.value = [mode isEqual:@"stopped"] ? VZVirtualMachineStateStopped : VZVirtualMachineStateRunning;
    NSUUID *s = [[NSUUID alloc] initWithUUIDString:@"A2345678-1234-4000-9000-123456789ABC"];
    VZVirtualMachine *target = (VZVirtualMachine *)(id)m; // stand-in; no framework initializer
    B46VMStopBridge *b = [B46VMStopBridge armMachine:target sessionID:s controlReadFD:fd
                                    observer:^(NSDictionary *event) { [m check]; output(event); }];
    if (!b) { output(@{@"fixture": @"arm-refused"}); return 0; }
    BOOL duplicate = [B46VMStopBridge armMachine:target sessionID:[NSUUID UUID] controlReadFD:fd
                                        observer:^(NSDictionary *unused) {}] != nil;
    close(fd);
    if (duplicate) return 71;
    for (int c; (c = getchar()) != EOF; ) {
        if (c == 'q') break;
        dispatch_sync(m.queue, ^{
            if (c == 's' || c == 'u') m.value = VZVirtualMachineStateStopped;
            if (c == 'a') m.value = VZVirtualMachineStateRunning;
            if (c == 'e') m.value = VZVirtualMachineStateError;
            if (c == 'C' || c == 'E') {
                void (^done)(NSError *) = m.completion;
                if (done) done(c == 'E' ? [NSError errorWithDomain:@"fixture" code:1 userInfo:nil] : nil);
                m.completion = nil;
            }
            if (c == 'u') [b sampleStateForMachine:(VZVirtualMachine *)(id)[NSObject new]];
            if (c == 's' || c == 'e' || c == 'a') [b sampleStateForMachine:target];
            if (c == 't') [b retire];
        });
        dispatch_sync(m.queue, ^{
            output(@{@"fixture": @"ack", @"command": @(c), @"graceful": @(m.gracefulCalls),
                     @"forced": @(m.forcedCalls)});
        });
    }
    return 0;
} }
'''


class VMStopBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.tmp = Path(tmp.name).resolve()
        cls.binary = cls.tmp / "inert-stop-fixture"
        fixture = cls.tmp / "fixture.m"
        fixture.write_text(DRIVER)
        compiler = Path("/Library/Developer/CommandLineTools/usr/bin/clang")
        with compiler.open("rb") as f:
            if hashlib.file_digest(f, "sha256").hexdigest() != "1220c0afafa12a6ae599d097ee7cf8b87c6b4d8e3fbb9783cee6b319a80683ba":
                raise ValueError("unreviewed compiler")
        cls.env = {"PATH": "/usr/bin:/bin", "HOME": str(cls.tmp), "TMPDIR": str(cls.tmp)}
        subprocess.run([compiler, "-isysroot", "/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk",
                        "-arch", "arm64", "-mmacosx-version-min=26.0", "-fobjc-arc", "-fno-modules", "-Werror",
                        "-framework", "Foundation", "-framework", "Virtualization", "-I", SRC,
                        fixture, SRC / "vm-stop.m", "-o", cls.binary], env=cls.env, cwd=cls.tmp,
                       stdin=subprocess.DEVNULL, check=True, timeout=45)

    def start(self, mode="running", *, bad_fd=False, buffered=b""):
        r, w = os.pipe()
        self.writer = os.fdopen(w, "wb", buffering=0)
        self.addCleanup(self.writer.close)
        if buffered:
            self.writer.write(buffered)
        fd = w if bad_fd else r
        try:
            self.proc = subprocess.Popen(["/usr/bin/sandbox-exec", "-p",
                    "(version 1)(allow default)(deny network*)(deny file-write*)",
                    self.binary, str(fd), mode], pass_fds=(fd,), stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.env, cwd=self.tmp, bufsize=0)
        finally:
            os.close(r)
        self.addCleanup(self.finish)
        self.events = []
        if not bad_fd:
            self.event("armed")
            if mode != "stopped":
                self.event("active-observed")

    def finish(self):
        if self.proc.poll() is None:
            try:
                self.proc.communicate(b"q", timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.communicate()
                self.fail("inert fixture did not exit")
        else:
            self.proc.communicate()
        self.assertEqual(self.proc.returncode, 0)

    def read(self):
        self.assertTrue(select.select([self.proc.stdout], [], [], 3)[0], "bounded event wait expired")
        line = self.proc.stdout.readline()
        self.assertTrue(line, "unexpected fixture exit")
        return json.loads(line)

    def event(self, kind):
        item = self.read()
        self.assertEqual(item["event"], kind)
        self.assertEqual(item["attempt_uuid"], SESSION)
        self.assertEqual(item["clock"], "CLOCK_MONOTONIC_RAW")
        self.assertEqual(item["sequence"], len(self.events) + 1)
        self.assertGreaterEqual(item["monotonic_ns"], self.events[-1]["monotonic_ns"] if self.events else 1)
        self.events.append(item)

    def command(self, key, events=(), counts=(0, 0)):
        self.proc.stdin.write(key.encode())
        for kind in events:
            self.event(kind)
        self.assertEqual(self.read(), {"fixture": "ack", "command": ord(key),
                                       "graceful": counts[0], "forced": counts[1]})

    def test_both_buffered_commands_run_once_but_callback_is_not_terminal_state(self):
        self.start(buffered=b"GF")
        self.event("graceful-accepted")
        self.event("force-issued")
        self.command("C", ["force-completion-returned"], (1, 1))
        self.command("e", counts=(1, 1))
        self.command("s", ["stopped-observed"], (1, 1))
        self.command("t", ["retired"], (1, 1))

    def test_terminal_state_is_bound_to_same_previously_active_target(self):
        self.start("stopped")
        self.command("s")
        self.command("a", ["active-observed"])
        self.command("u")
        self.command("s", ["stopped-observed"])
        self.command("s")

    def test_superseded_callback_cannot_assert_stopped_after_retirement(self):
        self.start()
        graceful = _request(self.writer.fileno(), b"G", _raw())
        self.assertEqual(graceful["delivery"], "queued-to-control-pipe")
        self.event("graceful-accepted")
        self.assertLessEqual(graceful["requested_raw_ns"], self.events[-1]["monotonic_ns"])
        force = _request(self.writer.fileno(), b"F", _raw())
        self.assertEqual(force["delivery"], "queued-to-control-pipe")
        self.event("force-issued")
        self.assertLessEqual(force["requested_raw_ns"], self.events[-1]["monotonic_ns"])
        self.command("t", ["retired"], (1, 1))
        self.command("E", counts=(1, 1))
        self.command("s", counts=(1, 1))

    def test_capability_refusal_and_duplicate_force_do_not_retry(self):
        self.start("deny")
        self.writer.write(b"G")
        self.event("graceful-refused")
        self.writer.write(b"F")
        self.event("force-refused")
        self.writer.write(b"F")
        self.event("control-refused")
        self.command("t", ["retired"])

    def test_channel_eof_never_stops_or_proves_target_exit(self):
        self.start()
        self.writer.close()
        self.event("control-eof")
        self.command("t", ["retired"])

    def test_out_of_order_force_and_write_end_are_refused(self):
        self.start(buffered=b"F")
        self.event("control-refused")
        self.command("t", ["retired"])
        self.doCleanups()
        self.start(bad_fd=True)
        self.assertEqual(self.read(), {"fixture": "arm-refused"})
