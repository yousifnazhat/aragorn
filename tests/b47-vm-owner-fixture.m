// Link this file only with the B47_INERT_MACHINE test variant.
#import "vm-owner.h"
#import "serial-recorder.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static const char qkey = 0;
static NSString *scenario;
static int events;
static unsigned starts, graceful, forced;
static uint64_t firstStart;

@interface InertOwnerTarget : NSObject
@property (strong) dispatch_queue_t queue;
@property (weak) id<VZVirtualMachineDelegate> delegate;
@property (strong) NSFileHandle *serial;
@property VZVirtualMachineState value;
@end

@implementation InertOwnerTarget
- (void)check { if (dispatch_get_specific(&qkey) != (__bridge void *)self) _exit(70); }
- (VZVirtualMachineState)state { [self check]; return self.value; }
- (BOOL)canStart { [self check]; return self.value == VZVirtualMachineStateStopped; }
- (BOOL)canRequestStop { [self check]; return self.value == VZVirtualMachineStateRunning; }
- (BOOL)canStop { return self.canRequestStop; }
- (void)reportStop {
    self.value = VZVirtualMachineStateStopped;
    [self.delegate guestDidStopVirtualMachine:(VZVirtualMachine *)(id)self];
}
- (void)startWithCompletionHandler:(void (^)(NSError *))completion {
    [self check];
    if (++starts != 1) _exit(71);
    firstStart = B45MonotonicNow();
    if (write(events, "S", 1) != 1) _exit(72);
    if ([scenario isEqual:@"start-error"]) {
        completion([NSError errorWithDomain:@"inert-fixture" code:1 userInfo:nil]);
        return;
    }
    const char bytes[] = "inert-owner\0\xff\n";
    if (write(self.serial.fileDescriptor, bytes, sizeof(bytes)-1) != sizeof(bytes)-1) _exit(73);
    self.value = VZVirtualMachineStateRunning;
    completion(nil);
    if ([scenario isEqual:@"wait-fixture-stop"]) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            char c;
            if (read(events, &c, 1) != 1 || c != 'Q') _exit(76);
            dispatch_async(self.queue, ^{ [self reportStop]; });
        });
    } else if (![scenario isEqual:@"hold"]) {
        // Process the bridge's enqueued state sample before the later delegate notification.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 60*NSEC_PER_MSEC), self.queue, ^{ [self reportStop]; });
    }
}
- (BOOL)requestStopWithError:(NSError **)error {
    [self check]; graceful++;
    return YES; // Remains running; confirmation must be a separate observed state transition.
}
- (void)stopWithCompletionHandler:(void (^)(NSError *))completion {
    [self check]; forced++;
    completion(nil);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 60*NSEC_PER_MSEC), self.queue, ^{ [self reportStop]; });
}
@end

VZVirtualMachine *B47InertMachine(VZVirtualMachineConfiguration *cfg, dispatch_queue_t queue) {
    InertOwnerTarget *m = [InertOwnerTarget new];
    m.queue = queue;
    m.value = VZVirtualMachineStateStopped;
    m.serial = ((VZFileHandleSerialPortAttachment *)cfg.serialPorts.firstObject.attachment).fileHandleForWriting;
    dispatch_queue_set_specific(queue, &qkey, (__bridge void *)m, NULL);
    return (VZVirtualMachine *)(id)m;
}

int main(int argc, const char **argv) { @autoreleasepool {
    if (argc != 7) return 74;
    scenario = @(argv[1]);
    NSUUID *attempt = [[NSUUID alloc] initWithUUIDString:@(argv[2])];
    int dir = atoi(argv[3]), stop = atoi(argv[4]), arm = atoi(argv[5]); events = atoi(argv[6]);
    NSPipe *serial = [NSPipe pipe];
    NSPipe *attachment = [scenario isEqual:@"other-pipe"] ? [NSPipe pipe] : serial;
    VZVirtioConsoleDeviceSerialPortConfiguration *port = [[VZVirtioConsoleDeviceSerialPortConfiguration alloc] init];
    port.attachment = [[VZFileHandleSerialPortAttachment alloc] initWithFileHandleForReading:nil
                                                                       fileHandleForWriting:attachment.fileHandleForWriting];
    VZVirtualMachineConfiguration *cfg = [VZVirtualMachineConfiguration new];
    cfg.serialPorts = @[port];  // No VM, boot loader, firmware store, disks or network.
    NSDictionary *row = B47OwnMachine(cfg, serial, dir, attempt, stop, arm, B45MonotonicNow());
    NSDictionary *out = @{@"owner": row, @"fixture_starts": @(starts), @"fixture_start_ns": @(firstStart),
                          @"fixture_graceful": @(graceful), @"fixture_forced": @(forced)};
    NSData *data = [NSJSONSerialization dataWithJSONObject:out options:0 error:NULL];
    return data && fwrite(data.bytes, 1, data.length, stdout) == data.length ? 0 : 75;
} }
