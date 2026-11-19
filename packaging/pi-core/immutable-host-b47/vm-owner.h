#import <Foundation/Foundation.h>
#import <Virtualization/Virtualization.h>

// Called once by the dedicated runner, off the VM queue, after admission of the
// complete disk/store/graph. Consumes the serial writer; borrows dir and channel
// FDs for this call. The parent keeps the arm socket and stop writer exclusively.
NSDictionary *B47OwnMachine(VZVirtualMachineConfiguration *cfg, NSPipe *serial,
                            int attemptDirFD, NSUUID *attempt, int stopReadFD,
                            int authoritySocketFD, uint64_t startRawNS);
