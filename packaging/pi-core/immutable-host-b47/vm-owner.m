#import "vm-owner.h"
#import "serial-recorder.h"
#import "vm-stop.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static const uint64_t runWindow = 180ULL * NSEC_PER_SEC;
static const uint64_t stopWindow = 30ULL * NSEC_PER_SEC;

#ifdef B47_INERT_MACHINE
// Test artifact only. The pinned executable links the framework constructor.
extern VZVirtualMachine *B47InertMachine(VZVirtualMachineConfiguration *, dispatch_queue_t);
#endif

@interface B47Delegate : NSObject <VZVirtualMachineDelegate>
@property (weak) VZVirtualMachine *machine;
@property (weak) B46VMStopBridge *bridge;
@property (copy) void (^note)(NSString *);
@property (atomic) BOOL logFailed;
@property BOOL stopError;
@end
@implementation B47Delegate
- (void)guestDidStopVirtualMachine:(VZVirtualMachine *)machine {
    if (machine == self.machine) { self.note(@"delegate-guest-stop"); [self.bridge sampleStateForMachine:machine]; }
}
- (void)virtualMachine:(VZVirtualMachine *)machine didStopWithError:(NSError *)error {
    if (machine == self.machine) {
        self.stopError=YES; self.note(@"delegate-stop-error"); [self.bridge sampleStateForMachine:machine];
    }
}
@end

static BOOL quietFD(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    return poll(&p, 1, 0) == 0;
}

static BOOL privateDir(int fd, NSString *uid) {
    struct stat s, named;
    char buf[PATH_MAX];
    return fd > 2 && !fstat(fd, &s) && S_ISDIR(s.st_mode) && s.st_uid == geteuid() &&
        (s.st_mode & 07777) == 0700 && !fcntl(fd, F_GETPATH, buf) && !lstat(buf, &named) &&
        s.st_dev == named.st_dev && s.st_ino == named.st_ino &&
        [[[NSString stringWithUTF8String:buf] lastPathComponent] isEqualToString:uid];
}

static BOOL channels(VZVirtualMachineConfiguration *cfg, NSPipe *pipe, int ctl, int arm) {
    VZFileHandleSerialPortAttachment *a = (id)cfg.serialPorts.firstObject.attachment;
    if (!pipe || cfg.serialPorts.count != 1 || ![a isKindOfClass:VZFileHandleSerialPortAttachment.class] ||
        a.fileHandleForReading || a.fileHandleForWriting != pipe.fileHandleForWriting) return NO;
    int r = pipe.fileHandleForReading.fileDescriptor, w = pipe.fileHandleForWriting.fileDescriptor;
    struct stat cs, rs, ws;
    struct sockaddr_storage peer;
    socklen_t len = sizeof(peer), typeLen = sizeof(int);
    int type, noSig = 1;
    return ctl > 2 && arm > 2 && r > 2 && w > 2 && r != ctl && w != ctl &&
        !fstat(ctl, &cs) && S_ISFIFO(cs.st_mode) && (fcntl(ctl, F_GETFL) & O_ACCMODE) == O_RDONLY &&
        !fstat(r, &rs) && S_ISFIFO(rs.st_mode) && !fstat(w, &ws) && S_ISFIFO(ws.st_mode) &&
        (fcntl(r, F_GETFL) & O_ACCMODE) == O_RDONLY && (fcntl(w, F_GETFL) & O_ACCMODE) == O_WRONLY &&
        !getsockopt(arm, SOL_SOCKET, SO_TYPE, &type, &typeLen) && type == SOCK_STREAM &&
        !getpeername(arm, (struct sockaddr *)&peer, &len) && peer.ss_family == AF_UNIX &&
        !setsockopt(arm, SOL_SOCKET, SO_NOSIGPIPE, &noSig, sizeof(noSig)) && quietFD(ctl) && quietFD(arm);
}

static uint64_t grant(int fd, int ctl, NSString *uid, uint64_t limit, BOOL (^alive)(void)) {
    NSString *identity = [NSString stringWithFormat:@"%@ %d", uid, getpid()];
    NSData *ready = [[NSString stringWithFormat:@"READY %@\n", identity] dataUsingEncoding:NSASCIIStringEncoding];
    if (!alive() || !quietFD(ctl) || !quietFD(fd) ||
        send(fd, ready.bytes, ready.length, MSG_DONTWAIT) != (ssize_t)ready.length) return 0;
    char frame[128];
    size_t used = 0;
    while (B45MonotonicNow() < limit && alive() && quietFD(ctl) && used < sizeof(frame)) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        int n = poll(&p, 1, 20);
        if (n == 0 || (n < 0 && errno == EINTR)) continue;
        if (n < 0 || p.revents != POLLIN) return 0;
        ssize_t got = recv(fd, frame + used, sizeof(frame) - used, MSG_DONTWAIT);
        if (got <= 0) return 0;
        used += got;
        if (!memchr(frame, '\n', used)) continue;
        NSData *data = [NSData dataWithBytes:frame length:used];
        NSString *wire = [[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding];
        NSString *prefix = [NSString stringWithFormat:@"ARM %@ ", identity];
        if (![wire hasPrefix:prefix] || ![wire hasSuffix:@"\n"] || wire.length <= prefix.length + 1) return 0;
        NSString *value = [wire substringWithRange:NSMakeRange(prefix.length, wire.length-prefix.length-1)];
        uint64_t deadline = strtoull(value.UTF8String, NULL, 10);
        if (![[NSString stringWithFormat:@"%llu", (unsigned long long)deadline] isEqual:value] ||
            !quietFD(fd)) return 0;
        return deadline;
    }
    return 0;
}

NSDictionary *B47OwnMachine(VZVirtualMachineConfiguration *cfg, NSPipe *serial,
                            int dir, NSUUID *attempt, int ctl, int arm, uint64_t start) {
    NSString *uid = attempt.UUIDString.lowercaseString;
    NSDictionary *refused = @{@"schema":@"aragorn/pi-core-vm-owner/v1", @"attempt_uuid":uid ?: @"",
        @"status":@"refused", @"start_issued":@NO, @"stopped_observed":@NO, @"events":@[],
        @"complete":@NO, @"boot_observed":@NO, @"phase3_exit_eligible":@NO};
    uint64_t now = B45MonotonicNow();
    if (!uid || [uid isEqual:@"00000000-0000-0000-0000-000000000000"] || !start || start > now ||
        start > UINT64_MAX-runWindow-stopWindow || now >= start+runWindow || !privateDir(dir,uid) ||
        !channels(cfg,serial,ctl,arm)) return refused;
    int logfd = openat(dir,"owner-events.jsonl",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (logfd < 0) return refused;
    NSFileHandle *log = [[NSFileHandle alloc] initWithFileDescriptor:logfd closeOnDealloc:YES];
    dispatch_queue_t io = dispatch_queue_create("aragorn.b47.owner-journal", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_t q = dispatch_queue_create("aragorn.b47.machine-owner", DISPATCH_QUEUE_SERIAL);
    B47Delegate *delegate = [B47Delegate new];
    __weak B47Delegate *logState=delegate;
    NSMutableArray *events = [NSMutableArray array];
    // Machine queue only. Never stall the stop bridge on file IO. Preserve partial journals.
    void (^append)(NSDictionary *) = ^(NSDictionary *e) {
        if (events.count >= 48) { logState.logFailed=YES; return; }
        [events addObject:e];
        dispatch_async(io, ^{
            NSData *json = [NSJSONSerialization dataWithJSONObject:e options:NSJSONWritingSortedKeys error:NULL];
            NSMutableData *line = [json mutableCopy]; [line appendBytes:"\n" length:1];
            if (!json || line.length>2048 || write(log.fileDescriptor,line.bytes,line.length)!=(ssize_t)line.length ||
                fsync(log.fileDescriptor)) logState.logFailed=YES;
        });
    };
    delegate.note = ^(NSString *name) {
        append(@{@"schema":@"aragorn/b47-owner-event/v1", @"attempt_uuid":uid, @"event":name,
                 @"monotonic_ns":@(B45MonotonicNow()), @"clock":@"CLOCK_MONOTONIC_RAW"});
    };
    __block VZVirtualMachine *machine;
    dispatch_sync(q, ^{
#ifdef B47_INERT_MACHINE
        machine = B47InertMachine(cfg,q);
#else
        machine = [[VZVirtualMachine alloc] initWithConfiguration:cfg queue:q];
#endif
        delegate.machine=machine; machine.delegate=delegate;
    });
    __block BOOL seenArm=NO, veto=NO, issued=NO, stopped=NO, startFailed=NO, retired=NO;
    __block BOOL startReturned=NO, lostOwner=NO;
    B46VMStopBridge *bridge = machine.queue == q ?
        [B46VMStopBridge armMachine:machine sessionID:attempt controlReadFD:ctl observer:^(NSDictionary *e) {
            append(e);
            if ([e[@"event"] isEqual:@"armed"]) seenArm=YES;
            else if (!issued) veto=YES;
            if (issued && !stopped && ([e[@"event"] isEqual:@"control-eof"] ||
                [e[@"event"] isEqual:@"control-refused"])) lostOwner=YES;
            if ([e[@"event"] isEqual:@"stopped-observed"]) stopped=YES;
        }] : nil;
    delegate.bridge=bridge;
    dispatch_group_t reader = dispatch_group_create();
    dispatch_semaphore_t armed = dispatch_semaphore_create(0);
    __block NSDictionary *capture=nil;
    int readerDir=bridge ? fcntl(dir,F_DUPFD_CLOEXEC,3) : -1;
    if (readerDir>=0) {
        dispatch_group_async(reader,dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{
            @autoreleasepool {
                capture=B45RecordSerialArmed(serial.fileHandleForReading.fileDescriptor,readerDir,start,armed);
                close(readerDir);
            }
        });
    }
    BOOL (^readerAlive)(void) = ^BOOL { return dispatch_group_wait(reader,DISPATCH_TIME_NOW)!=0; };
    uint64_t startupCutoff=MIN(start+runWindow,now+5*NSEC_PER_SEC);
    BOOL ready=NO;
    while (bridge && readerAlive() && B45MonotonicNow()<startupCutoff) {
        if (!dispatch_semaphore_wait(armed,dispatch_time(DISPATCH_TIME_NOW,10*NSEC_PER_MSEC))) {ready=YES;break;}
    }
    __block BOOL canAsk=NO;
    dispatch_sync(q,^{
        canAsk=ready && seenArm && !veto && machine.state==VZVirtualMachineStateStopped;
        if (canAsk) delegate.note(@"recorder-armed");
    });
    dispatch_sync(io,^{ if (fsync(dir)) delegate.logFailed=YES; }); // Never block the VM queue on journal I/O.
    uint64_t deadline=canAsk && !delegate.logFailed ? grant(arm,ctl,uid,startupCutoff,readerAlive) : 0;
    dispatch_sync(q,^{
        uint64_t t=B45MonotonicNow();
        if (!canAsk || !seenArm || veto || !readerAlive() || delegate.logFailed || !quietFD(arm) ||
            !quietFD(ctl) || !privateDir(dir,uid) || !deadline || t>=deadline || t>=startupCutoff ||
            deadline>start+runWindow || machine.state!=VZVirtualMachineStateStopped || !machine.canStart) return;
        issued=YES; delegate.note(@"start-issued");
        [machine startWithCompletionHandler:^(NSError *error) {
            if (retired) return;
            startReturned=YES;
            startFailed=(error!=nil);
            delegate.note(error ? @"start-completion-error" : @"start-completion-returned");
            [bridge sampleStateForMachine:machine];
        }];
    });
    if (issued) {
        while (B45MonotonicNow() < deadline+stopWindow) {
            __block BOOL terminal=NO;
            dispatch_sync(q,^{
                if (!lostOwner && !quietFD(arm)) {
                    lostOwner=YES; delegate.note(@"supervision-lost");
                }
                terminal=stopped || (startFailed && machine.state==VZVirtualMachineStateStopped);
            });
            if (terminal) break;
            usleep(10000);
        }
    }
    [bridge retire];
    dispatch_sync(q,^{ retired=YES; machine.delegate=nil; delegate.bridge=nil; machine=nil; });
    BOOL closed=[serial.fileHandleForWriting closeAndReturnError:NULL];
    BOOL joined=dispatch_group_wait(reader,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC))==0;
    dispatch_sync(io,^{});
    struct stat s,n;
    BOOL sealed=fchmod(logfd,0400)==0 && fsync(logfd)==0 && fsync(dir)==0 && !delegate.logFailed &&
        !fstat(logfd,&s) && !fstatat(dir,"owner-events.jsonl",&n,AT_SYMLINK_NOFOLLOW) &&
        s.st_dev==n.st_dev && s.st_ino==n.st_ino && s.st_nlink==1 && s.st_size>0;
    sealed=[log closeAndReturnError:NULL] && sealed;
    delegate.note=nil;
    BOOL complete=issued && stopped && startReturned && !startFailed && !delegate.stopError && !lostOwner &&
        closed && joined && sealed && [capture[@"status"] isEqual:@"eof"] &&
        [capture[@"capture_bytes"] unsignedLongLongValue]>0 && [capture[@"sync_verified"] boolValue] &&
        [capture[@"pipe_eof"] boolValue];
    return @{@"schema":@"aragorn/pi-core-vm-owner/v1", @"attempt_uuid":uid,
             @"status":issued ? (complete ? @"stopped-observed" : @"indeterminate") : @"start-refused",
             @"start_issued":@(issued), @"stopped_observed":@(stopped), @"events":[events copy],
             @"complete":@(complete), @"supervision_lost":@(lostOwner), @"journal_sealed":@(sealed), @"recorder_joined":@(joined),
             @"capture":joined && capture ? capture : NSNull.null,
             @"boot_observed":@NO, @"phase3_exit_eligible":@NO};
}
