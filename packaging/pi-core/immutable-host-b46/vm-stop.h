#import <Foundation/Foundation.h>
#import <Virtualization/Virtualization.h>

// No discovery, creation, start or stop on arm. The trusted owner supplies one
// exact machine and a fresh, exclusively owned inherited FIFO read end. Close
// the caller's copy after successful arm (its file description becomes
// nonblocking). The watchdog is the sole writer and owns the grace deadline.
// Keep the bridge alive through final state readback. The event sink runs on
// machine.queue; it must be bounded/nonblocking and must not call back inline.
@interface B46VMStopBridge : NSObject
+ (instancetype)armMachine:(VZVirtualMachine *)machine
                 sessionID:(NSUUID *)session
             controlReadFD:(int)fd
                  observer:(void (^)(NSDictionary *event))observer;
// The existing owner forwards launch/state/delegate notifications without
// replacing any delegate. Each is only a hint to resample the exact machine.
- (void)sampleStateForMachine:(VZVirtualMachine *)machine;
// Revoke further commands/callbacks. Asynchronous on the same machine queue.
- (void)retire;
- (instancetype)init NS_UNAVAILABLE;
+ (instancetype)new NS_UNAVAILABLE;
@end
