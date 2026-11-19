// Host-side descriptor inspection only. There is no VM, firmware or variable store here.
#import <Foundation/Foundation.h>
#import <Virtualization/VZDiskImageStorageDeviceAttachment.h>
#import <Virtualization/VZNVMExpressControllerDeviceConfiguration.h>

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2) return 2;
        NSURL *url = [NSURL fileURLWithFileSystemRepresentation:argv[1] isDirectory:NO relativeToURL:nil];
        NSError *error = nil;
        VZDiskImageStorageDeviceAttachment *disk =
            [[VZDiskImageStorageDeviceAttachment alloc] initWithURL:url readOnly:YES error:&error];
        if (!disk) {
            fprintf(stderr, "attachment refused: %s (%ld)\n",
                    error.domain.UTF8String, (long)error.code);
            return 1;
        }
        VZNVMExpressControllerDeviceConfiguration *controller =
            [[VZNVMExpressControllerDeviceConfiguration alloc] initWithAttachment:disk];
        if (!controller || controller.attachment != disk || !disk.isReadOnly || ![disk.URL isEqual:url])
            return 1;
        puts("host: raw read-only attachment accepted by NVMe descriptor; guest: not observed");
        return 0;
    }
}
