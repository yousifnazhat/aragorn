// Host-only descriptor readback. No EFI store, VM instance, persisted configuration or guest execution.
#import <Foundation/Foundation.h>
#import <Virtualization/VZDiskImageStorageDeviceAttachment.h>
#import <Virtualization/VZEFIBootLoader.h>
#import <Virtualization/VZEFIVariableStore.h>
#import <Virtualization/VZFileHandleSerialPortAttachment.h>
#import <Virtualization/VZGenericPlatformConfiguration.h>
#import <Virtualization/VZNVMExpressControllerDeviceConfiguration.h>
#import <Virtualization/VZVirtioConsoleDeviceSerialPortConfiguration.h>
#import <Virtualization/VZVirtualMachineConfiguration.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static BOOL sameFile(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_uid == b->st_uid &&
        a->st_mode == b->st_mode && a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}

// Protect this cooperating user's private B41 artifact. Not a hostile-host or cryptographic custody check.
static int openCandidate(const char *arg, struct stat *st) {
    char canonical[PATH_MAX];
    NSString *path = [NSString stringWithUTF8String:arg];
    if (!path || ![path hasSuffix:@"/.aragorn/host-preflight/build-b41/media-v1/aragorn-arm64.raw"] ||
        arg[0] != '/' || !realpath(arg, canonical) || strcmp(canonical, arg)) return -1;
    for (int i = 0; i < 3; i++) { // media-v1, build-b41, host-preflight
        struct stat dir;
        path = path.stringByDeletingLastPathComponent;
        if (lstat(path.fileSystemRepresentation, &dir) || !S_ISDIR(dir.st_mode) ||
            dir.st_uid != getuid() || (dir.st_mode & 077)) return -1;
    }
    int fd = open(arg, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, st) || !S_ISREG(st->st_mode) || st->st_uid != getuid() || st->st_nlink != 1 ||
        (st->st_mode & 07777) != 0400 || st->st_size != 3542227456LL) {
        close(fd);
        return -1;
    }
    return fd;
}

static NSDictionary *preview(NSURL *url) API_AVAILABLE(macos(14.0));
static NSDictionary *preview(NSURL *url) {
    VZDiskImageStorageDeviceAttachment *disk =
        [[VZDiskImageStorageDeviceAttachment alloc] initWithURL:url readOnly:YES error:NULL];
    if (!disk || !disk.isReadOnly || ![disk.URL isEqual:url]) return nil;
    VZNVMExpressControllerDeviceConfiguration *nvme =
        [[VZNVMExpressControllerDeviceConfiguration alloc] initWithAttachment:disk];
    VZGenericPlatformConfiguration *platform = [[VZGenericPlatformConfiguration alloc] init];
    VZEFIBootLoader *efi = [[VZEFIBootLoader alloc] init];
    NSPipe *pipe = [NSPipe pipe];
    NSFileHandle *writer = pipe.fileHandleForWriting;
    VZFileHandleSerialPortAttachment *serial =
        [[VZFileHandleSerialPortAttachment alloc] initWithFileHandleForReading:nil fileHandleForWriting:writer];
    VZVirtioConsoleDeviceSerialPortConfiguration *port = [[VZVirtioConsoleDeviceSerialPortConfiguration alloc] init];
    port.attachment = serial;
    VZVirtualMachineConfiguration *config = [VZVirtualMachineConfiguration new];
    config.platform = platform;
    config.bootLoader = efi;
    config.CPUCount = 2;
    config.memorySize = 4ULL << 30;
    config.storageDevices = @[nvme];
    config.serialPorts = @[port];
    config.audioDevices = @[];
    config.consoleDevices = @[];
    config.directorySharingDevices = @[];
    config.entropyDevices = @[];
    config.graphicsDevices = @[];
    config.keyboards = @[];
    config.memoryBalloonDevices = @[];
    config.networkDevices = @[];
    config.pointingDevices = @[];
    config.socketDevices = @[];
    NSUInteger usbCount = 0, customCount = 0;
    if (@available(macOS 15.0, *)) {
        config.usbControllers = @[];
        usbCount = config.usbControllers.count;
        if (platform.nestedVirtualizationEnabled) return nil;
    }
    NSInteger major = NSProcessInfo.processInfo.operatingSystemVersion.majorVersion;
    // macOS 27 getter; query the public read-only view, without sending a setter or building any custom device.
    BOOL customAPI = [config respondsToSelector:NSSelectorFromString(@"customVirtioDevices")];
    if (major >= 27 && !customAPI) return nil;
    if (customAPI) {
        id devices = [config valueForKey:@"customVirtioDevices"];
        if (![devices isKindOfClass:[NSArray class]]) return nil;
        customCount = [(NSArray *)devices count];
    }
    NSDictionary *empty = @{@"audio": @(config.audioDevices.count), @"console": @(config.consoleDevices.count),
        @"shares": @(config.directorySharingDevices.count), @"entropy": @(config.entropyDevices.count),
        @"graphics": @(config.graphicsDevices.count), @"keyboards": @(config.keyboards.count),
        @"balloon": @(config.memoryBalloonDevices.count), @"network": @(config.networkDevices.count),
        @"pointing": @(config.pointingDevices.count), @"sockets": @(config.socketDevices.count),
        @"usb": @(usbCount), @"custom_virtio": @(customCount)};
    for (NSNumber *count in empty.allValues) if (count.unsignedIntegerValue != 0) return nil;
    struct stat out, in;
    NSFileHandle *reader = pipe.fileHandleForReading;
    if (!reader || !writer || fstat(reader.fileDescriptor, &in) || !S_ISFIFO(in.st_mode) ||
        (fcntl(reader.fileDescriptor, F_GETFL) & O_ACCMODE) != O_RDONLY ||
        fstat(writer.fileDescriptor, &out) || !S_ISFIFO(out.st_mode) ||
        (fcntl(writer.fileDescriptor, F_GETFL) & O_ACCMODE) != O_WRONLY ||
        !platform || config.platform != platform || !efi || config.bootLoader != efi || efi.variableStore != nil ||
        config.CPUCount != 2 || config.memorySize != (4ULL << 30) ||
        config.storageDevices.count != 1 || config.storageDevices[0] != nvme || nvme.attachment != disk ||
        config.serialPorts.count != 1 || config.serialPorts[0] != port || port.attachment != serial ||
        serial.fileHandleForReading != nil || serial.fileHandleForWriting != writer) return nil;
    // Apple's documented Objective-C selectors. Report availability only; never call on a variable store.
    Class store = [VZEFIVariableStore class];
    NSDictionary *methods = @{
        @"get_enabled": @([store instancesRespondToSelector:NSSelectorFromString(@"getSecureBootEnabled:error:")]),
        @"get_databases": @([store instancesRespondToSelector:NSSelectorFromString(@"getEnrolledSecureBootSignaturesWithError:")]),
        @"enroll": @([store instancesRespondToSelector:NSSelectorFromString(@"enrollSecureBootSignatures:error:")]),
        @"enable_default_pk": @([store instancesRespondToSelector:NSSelectorFromString(@"enableSecureBootUsingDefaultPlatformKeyWithError:")])};
    return @{@"schema": @"aragorn/pi-core-boot-config-preview/v1", @"host_os_major": @(major),
        @"cpu_count": @(config.CPUCount), @"memory_bytes": @(config.memorySize),
        @"storage_devices": @(config.storageDevices.count), @"nvme_read_only": @(disk.isReadOnly),
        @"serial_ports": @(config.serialPorts.count), @"serial_input": @((BOOL)(serial.fileHandleForReading != nil)),
        @"serial_output_pipe": @YES, @"efi_without_store": @((BOOL)(efi.variableStore == nil)), @"empty_devices": empty,
        @"trust_selectors": methods, @"custom_virtio_api": @(customAPI), @"variable_store_opened": @NO,
        @"vm_created": @NO, @"trust_proven": @NO, @"boot_observed": @NO, @"guest_nvme_observed": @NO};
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
#if defined(__arm64__)
        if (argc == 2) {
            if (@available(macOS 14.0, *)) {
                struct stat before, after;
                int fd = openCandidate(argv[1], &before);
                if (fd < 0) return 2;
                NSURL *url = [NSURL fileURLWithFileSystemRepresentation:argv[1] isDirectory:NO relativeToURL:nil];
                NSDictionary *result = preview(url);
                BOOL stable = !fstat(fd, &after) && sameFile(&before, &after) &&
                    !lstat(argv[1], &after) && sameFile(&before, &after);
                close(fd);
                if (!stable || !result) return 1;
                NSData *data = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingSortedKeys error:NULL];
                if (!data || data.length > 2048 || fwrite(data.bytes, 1, data.length, stdout) != data.length ||
                    fputc('\n', stdout) == EOF) return 1;
                return 0;
            }
        }
#endif
        return 2;
    }
}
