#import "vm-stop.h"
#import <objc/runtime.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char claimedMachine = 0;

@implementation B46VMStopBridge {
    VZVirtualMachine *_machine;
    dispatch_queue_t _queue;
    dispatch_source_t _source;
    NSString *_session;
    void (^_observer)(NSDictionary *);
    BOOL _retired, _activeSeen, _stoppedSeen, _gracefulSeen, _forcedSeen;
    unsigned _sequence;
}

- (instancetype)initPrivate { return [super init]; }

+ (instancetype)armMachine:(VZVirtualMachine *)machine sessionID:(NSUUID *)session
             controlReadFD:(int)fd observer:(void (^)(NSDictionary *))observer {
    struct stat st;
    if (!machine || ![session isKindOfClass:NSUUID.class] ||
        [session.UUIDString isEqualToString:@"00000000-0000-0000-0000-000000000000"] || !observer || fd < 3 ||
        fstat(fd, &st) || !S_ISFIFO(st.st_mode)) return nil;
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY) return nil;
    dispatch_queue_t queue = machine.queue; // SDK explicitly permits off-queue access to this property
    if (!queue) return nil;
    B46VMStopBridge *b = [[self alloc] initPrivate];
    @synchronized (machine) {
        if (objc_getAssociatedObject(machine, &claimedMachine)) return nil;
        int owned = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (owned < 0) return nil;
        if (fcntl(owned, F_SETFL, flags | O_NONBLOCK) < 0) { close(owned); return nil; }
        dispatch_source_t src = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, owned, 0, queue);
        if (!src) { close(owned); return nil; }
        b->_machine = machine; b->_queue = queue; b->_source = src;
        b->_session = session.UUIDString.lowercaseString; b->_observer = [observer copy];
        // One lifetime per instance. Re-arming even after retirement could replay an effect.
        objc_setAssociatedObject(machine, &claimedMachine, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        __weak B46VMStopBridge *weak = b;
        dispatch_source_set_event_handler(src, ^{ [weak consume:owned]; });
        dispatch_source_set_cancel_handler(src, ^{ close(owned); });
        dispatch_async(queue, ^{ [b emit:@"armed"]; [b observeState]; });
        dispatch_activate(src);
    }
    return b;
}

- (void)emit:(NSString *)kind {
    _observer(@{@"schema": @"pi-core-vz-stop-event/v1", @"attempt_uuid": _session,
                @"sequence": @(++_sequence), @"event": kind,
                @"clock": @"CLOCK_MONOTONIC_RAW",
                @"monotonic_ns": @(clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW))});
}

- (void)closeControl {
    if (_source) { dispatch_source_cancel(_source); _source = nil; }
}

- (void)observeState {
    if (_retired || _stoppedSeen) return;
    VZVirtualMachineState state = _machine.state;
    if (state == VZVirtualMachineStateRunning || state == VZVirtualMachineStatePaused) {
        if (!_activeSeen) { _activeSeen = YES; [self emit:@"active-observed"]; }
    } else if (state == VZVirtualMachineStateStopped && _activeSeen) {
        _stoppedSeen = YES;
        [self emit:@"stopped-observed"]; // Not a clean-shutdown, serial EOF or release claim.
        [self closeControl];
    }
}

- (void)consume:(int)fd {
    if (_retired || !_source) return;
    uint8_t byte;
    // Stream boundaries are not message boundaries. The external watchdog
    // keeps the deadlines; a delayed machine queue may see both commands buffered.
    ssize_t n = read(fd, &byte, 1);
    if (n < 0 && (errno == EAGAIN || errno == EINTR)) return;
    if (n == 0) { [self emit:@"control-eof"]; [self closeControl]; return; }
    if (n != 1 || !((byte == 'G' && !_gracefulSeen) ||
                    (byte == 'F' && _gracefulSeen && !_forcedSeen))) {
        [self emit:@"control-refused"]; [self closeControl]; return;
    }
    [self observeState];
    if (_stoppedSeen) return;
    if (byte == 'G') {
        _gracefulSeen = YES;
        NSError *err = nil;
        BOOL ok = _machine.canRequestStop && [_machine requestStopWithError:&err];
        [self emit:ok && !err ? @"graceful-accepted" : @"graceful-refused"];
    } else {
        _forcedSeen = YES;
        if (!_machine.canStop) { [self emit:@"force-refused"]; return; }
        [self emit:@"force-issued"];
        __weak B46VMStopBridge *weak = self;
        [_machine stopWithCompletionHandler:^(NSError *error) {
            // SDK guarantees delivery on the machine queue.
            B46VMStopBridge *b = weak;
            if (!b || b->_retired) return;
            [b emit:error ? @"force-completion-error" : @"force-completion-returned"];
            [b observeState]; // Callback result is never proof of a terminal state.
        }];
    }
}

- (void)sampleStateForMachine:(VZVirtualMachine *)machine {
    if (machine != _machine) return;
    dispatch_async(_queue, ^{ [self observeState]; });
}

- (void)retire {
    dispatch_async(_queue, ^{
        if (self->_retired) return;
        [self observeState];
        self->_retired = YES;
        [self closeControl];
        [self emit:@"retired"];
        self->_observer = nil;
    });
}

- (void)dealloc { if (_source) dispatch_source_cancel(_source); }
@end
