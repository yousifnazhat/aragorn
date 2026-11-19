#import "serial-recorder.h"
#import <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const size_t cap = 8 * 1024 * 1024;
static const uint64_t window = UINT64_C(180000000000);

uint64_t B45MonotonicNow(void) { return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW); }

NSDictionary *B45RecordSerial(int source, int dir, uint64_t start) {
    return B45RecordSerialArmed(source, dir, start, NULL);
}

NSDictionary *B45RecordSerialArmed(int source, int dir, uint64_t start, dispatch_semaphore_t armed) {
    uint64_t entered = B45MonotonicNow();
    struct stat pipeStat, ds, created, named;
    int flags = fcntl(source, F_GETFL);
    if (!start || start > entered || start > UINT64_MAX - window || source <= 2 || dir <= 2 ||
        flags < 0 || (flags & O_ACCMODE) != O_RDONLY || fstat(source, &pipeStat) || !S_ISFIFO(pipeStat.st_mode) ||
        fstat(dir, &ds) || !S_ISDIR(ds.st_mode) || ds.st_uid != geteuid() || (ds.st_mode & 07777) != 0700)
        return nil;
    const char name[] = "serial.raw";
    int out = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (out < 0) return nil;

    NSString *status = @"read-error";
    BOOL eof = NO, nonblocking = (fcntl(source, F_SETFL, flags | O_NONBLOCK) == 0);
    size_t saved = 0;
    uint8_t bytes[16384], digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_CTX sha;
    CC_SHA256_Init(&sha);
    if (armed && nonblocking && B45MonotonicNow() < start + window) dispatch_semaphore_signal(armed);
    while (nonblocking) {
        uint64_t now = B45MonotonicNow(), deadline = start + window;
        if (now >= deadline) { status = @"deadline"; break; }
        struct pollfd watch = {.fd = source, .events = POLLIN};
        int ready = poll(&watch, 1, (int)((deadline - now + 999999) / 1000000));
        if (ready < 0 && errno == EINTR) continue;  // Interrupted waits never renew the deadline.
        if (ready < 0 || (watch.revents & (POLLERR | POLLNVAL))) break;
        if (B45MonotonicNow() >= deadline) { status = @"deadline"; break; }
        if (!ready) continue;
        ssize_t got = read(source, bytes, MIN(sizeof bytes, cap - saved));
        if (got < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (got < 0) break;
        if (!got) { eof = YES; status = saved ? @"eof" : @"empty"; break; }
        ssize_t put = write(out, bytes, (size_t)got);
        if (put > 0) { CC_SHA256_Update(&sha, bytes, (CC_LONG)put); saved += (size_t)put; }
        if (put != got) { status = @"write-error"; break; }
        if (saved == cap) { status = @"limit"; break; }  // Equality is indeterminate, even if no byte follows.
    }
    uint64_t ended = B45MonotonicNow();
    if (eof && ended >= start + window) status = @"deadline";
    if (nonblocking && fcntl(source, F_SETFL, flags) != 0) status = @"read-error";
    CC_SHA256_Final(digest, &sha);
    char hex[2 * CC_SHA256_DIGEST_LENGTH + 1] = {0};
    for (size_t i = 0; i < sizeof digest; ++i) {
        hex[2*i] = "0123456789abcdef"[digest[i] >> 4];
        hex[2*i + 1] = "0123456789abcdef"[digest[i] & 15];
    }
    // Retain partial evidence, including the empty file; never unlink or truncate on failure.
    BOOL sync = fchmod(out, 0400) == 0 && fsync(out) == 0 && fsync(dir) == 0 &&
        fstat(out, &created) == 0 && fstatat(dir, name, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISREG(created.st_mode) && (created.st_mode & 07777) == 0400 && created.st_nlink == 1 &&
        created.st_uid == geteuid() && created.st_size == (off_t)saved &&
        created.st_dev == named.st_dev && created.st_ino == named.st_ino;
    if (close(out)) sync = NO;
    return @{@"schema": @"aragorn/bounded-host-serial/v1", @"status": sync ? status : @"retain-error",
             @"stream_termination": status, @"clock": @"CLOCK_MONOTONIC_RAW", @"attempt_start_ns": @(start),
             @"record_start_ns": @(entered), @"record_end_ns": @(ended), @"raw_file": @"serial.raw",
             @"capture_bytes": @(saved), @"capture_sha256": [NSString stringWithUTF8String:hex],
             @"sync_verified": @(sync), @"pipe_eof": @(eof), @"boot_observed": @NO, @"phase3_exit_eligible": @NO};
}
