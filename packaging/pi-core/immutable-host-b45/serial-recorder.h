#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>
#include <stdint.h>

// Same clock domain at attempt reservation, recorder entry and termination.
uint64_t B45MonotonicNow(void);
// Borrow the runner's sole, output-only VZ pipe reader and private attempt directory.
// nil means no new raw file was reserved. Never substitutes stdin or opens a serial path.
NSDictionary *B45RecordSerial(int pipeReadFD, int attemptDirFD, uint64_t attemptStartNS);
// Signals once, before reading, only after the private raw file and pipe are armed within the watchdog.
NSDictionary *B45RecordSerialArmed(int pipeReadFD, int attemptDirFD, uint64_t attemptStartNS, dispatch_semaphore_t armed);
