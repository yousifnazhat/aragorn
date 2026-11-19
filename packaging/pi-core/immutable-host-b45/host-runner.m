// Bind and inspect host objects only. No VM instance, store creation, enrollment or guest entry.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Virtualization/Virtualization.h>
#import <CommonCrypto/CommonDigest.h>
#import <objc/message.h>
#import "serial-recorder.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static NSString *const mediaSuffix = @"/.aragorn/host-preflight/build-b44/build-39510067d1c70d3327b6225cc51ea0b75632092c6422cb0d97e1403b25f32648/aragorn-arm64.raw";
static NSString *const imageHash = @"fa2ccca39b781d7e20baad88944bf0a52c5b578034d49b6839dd79f4040a22fa";
static void need(BOOL ok, const char *why) { if (!ok) { fprintf(stderr, "B45 refused: %s\n", why); exit(2); } }
static NSString *hex(const unsigned char *v, NSUInteger n) {
    static const char digits[] = "0123456789abcdef"; char buf[65];
    need(v && n && n <= 32, "digest length");
    for (NSUInteger i = 0; i < n; i++) { buf[i*2] = digits[v[i] >> 4]; buf[i*2+1] = digits[v[i] & 15]; }
    buf[n * 2] = 0; return @(buf);
}
static NSString *digest(NSData *d) {
    need(d && d.length <= (1u << 22), "bounded object");
    unsigned char v[32]; CC_SHA256(d.bytes, (CC_LONG)d.length, v); return hex(v, sizeof v);
}
static BOOL shaString(NSString *s) {
    return s.length == 64 && [s rangeOfCharacterFromSet:
        [NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"].invertedSet].location == NSNotFound;
}
static NSData *json(id d) {
    NSData *raw = [NSJSONSerialization dataWithJSONObject:d options:NSJSONWritingSortedKeys error:NULL];
    need(raw && raw.length <= 32768, "bounded JSON"); return raw;
}
static BOOL canonical(NSString *p) {
    char buf[PATH_MAX];
    return p.isAbsolutePath && realpath(p.fileSystemRepresentation, buf) &&
        strcmp(p.fileSystemRepresentation, buf) == 0;
}
static NSDictionary *identity(struct stat s) {
    return @{@"dev": @((uint64_t)s.st_dev), @"ino": @((uint64_t)s.st_ino)};
}
static BOOL sameNode(struct stat a, struct stat b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid && a.st_mode == b.st_mode;
}
static BOOL sameFile(struct stat a, struct stat b) {
    return sameNode(a, b) && a.st_nlink == b.st_nlink && a.st_size == b.st_size &&
        a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec;
}
static BOOL dirAt(int fd, NSString *p, struct stat *s) {
    struct stat name;
    return canonical(p) && fstat(fd,s) == 0 && lstat(p.fileSystemRepresentation,&name) == 0 &&
        sameNode(*s,name) && S_ISDIR(s->st_mode) && (s->st_mode & 07777) == 0700 && s->st_uid == getuid();
}
typedef struct { int fd; struct stat st; } Held;
static BOOL stable(Held f, NSString *p) {
    struct stat fd, name;
    return canonical(p) && !fstat(f.fd, &fd) && !lstat(p.fileSystemRepresentation, &name) &&
        sameFile(f.st,fd) && sameFile(f.st,name);
}
static Held hold(NSString *path, off_t min, off_t max, BOOL raw) {
    need(canonical(path), "canonical existing file required");
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    Held h = {.fd=fd}; need(fd >= 0 && fstat(fd,&h.st) == 0, "open file read-only");
    mode_t m = h.st.st_mode & 07777;
    need(S_ISREG(h.st.st_mode) && h.st.st_uid == getuid() && h.st.st_nlink == 1 &&
         h.st.st_size >= min && h.st.st_size <= max && (!raw || m == 0400) && stable(h,path), "file custody");
    return h;
}
static NSString *fileHash(Held h) {
    unsigned char buf[65536], out[32]; CC_SHA256_CTX ctx; CC_SHA256_Init(&ctx);
    off_t pos = 0;
    while (pos < h.st.st_size) {
        size_t want = (size_t)MIN((off_t)sizeof(buf), h.st.st_size-pos);
        ssize_t got = pread(h.fd,buf,want,pos); need(got > 0, "file read");
        CC_SHA256_Update(&ctx,buf,(CC_LONG)got); pos += got;
    }
    CC_SHA256_Final(out,&ctx); return hex(out,sizeof out);
}
static NSDictionary *runnerIdentity(void) {
    SecCodeRef code = NULL; SecStaticCodeRef binary = NULL;
    CFDictionaryRef details = NULL; CFURLRef location = NULL;
    need(SecCodeCopySelf(kSecCSDefaultFlags,&code) == errSecSuccess &&
        SecCodeCopyStaticCode(code,kSecCSDefaultFlags,&binary) == errSecSuccess &&
        SecCodeCheckValidity(code,kSecCSDefaultFlags,NULL) == errSecSuccess &&
        SecStaticCodeCheckValidity(binary,kSecCSStrictValidate,NULL) == errSecSuccess &&
        SecCodeCopySigningInformation(binary,kSecCSSigningInformation,&details) == errSecSuccess &&
        SecCodeCopyPath(binary,kSecCSDefaultFlags,&location) == errSecSuccess, "runner code signature");
    NSDictionary *info = CFBridgingRelease(details); NSURL *url = CFBridgingRelease(location);
    NSData *cd = info[(__bridge id)kSecCodeInfoUnique];
    need(cd.length == 20 && [info[(__bridge id)kSecCodeInfoIdentifier] isEqual:@"org.aragorn.pi-core.b45.host-runner"] &&
         ([info[(__bridge id)kSecCodeInfoFlags] unsignedLongValue] & kSecCodeSignatureRuntime) &&
         [info[(__bridge id)kSecCodeInfoEntitlementsDict] isEqual:@{@"com.apple.security.virtualization": @YES}],
         "runner identifier, hardened runtime or entitlement");
    Held h = hold(url.path,1,16<<20,NO); NSString *sha = fileHash(h);
    need(stable(h,url.path), "runner changed"); close(h.fd); CFRelease(code); CFRelease(binary);
    return @{@"runner_sha256":sha,@"runner_cdhash":hex(cd.bytes,cd.length)};
}

// Public macOS 27 readback methods, looked up only on the pinned target OS (build SDK is 26.5).
static id getter(id o, NSString *name) {
    SEL s = NSSelectorFromString(name); need(o && [o respondsToSelector:s],"firmware getter unavailable");
    return ((id (*)(id,SEL))objc_msgSend)(o,s);
}
static NSString *policyHash(VZEFIVariableStore *store) {
    SEL getEnabled = NSSelectorFromString(@"getSecureBootEnabled:error:");
    SEL getDB = NSSelectorFromString(@"getEnrolledSecureBootSignaturesWithError:");
    need([store respondsToSelector:getEnabled] && [store respondsToSelector:getDB],"firmware readback unavailable");
    BOOL enabled = NO; NSError *err = nil;
    need(((BOOL (*)(id,SEL,BOOL *,NSError **))objc_msgSend)(store,getEnabled,&enabled,&err) && enabled && !err,
         "secure boot not enabled");
    id db = ((id (*)(id,SEL,NSError **))objc_msgSend)(store,getDB,&err);
    need(db && !err,"firmware database readback");
    NSMutableSet<NSString *> *rows = [NSMutableSet set];
    for (NSArray *field in @[@[@"kek",@"keyExchangeKeys"],@[@"db",@"dbSignatures"],@[@"dbx",@"dbxSignatures"]]) {
        NSArray *lists = getter(db,field[1]); NSUInteger count = 0;
        need([lists isKindOfClass:NSArray.class] && lists.count && lists.count <= 4096,"firmware database lists");
        for (id list in lists) {
            NSArray *sigs = getter(list,@"signatures");
            need([sigs isKindOfClass:NSArray.class] && sigs.count && sigs.count <= 16384-rows.count,"firmware signatures");
            for (id sig in sigs) {
                NSString *kind=nil, *value=nil;
                if ([sig isKindOfClass:NSClassFromString(@"VZEFISignatureSHA256Hash")]) {
                    NSData *data = getter(sig,@"data");
                    need([data isKindOfClass:NSData.class] && data.length == 32,"firmware SHA-256");
                    kind=@"sha256"; value=hex(data.bytes,data.length);
                } else if ([sig isKindOfClass:NSClassFromString(@"VZEFISignatureX509Certificate")]) {
                    SEL certSel=NSSelectorFromString(@"certificate"); need([sig respondsToSelector:certSel],"firmware certificate getter");
                    SecCertificateRef cert=((SecCertificateRef (*)(id,SEL))objc_msgSend)(sig,certSel);
                    need(cert && CFGetTypeID(cert) == SecCertificateGetTypeID(),"firmware certificate");
                    NSData *der=CFBridgingRelease(SecCertificateCopyData(cert));
                    need(der.length > 0 && der.length <= (1<<20),"firmware DER length");
                    kind=@"x509-sha256"; value=digest(der);
                } else need(NO,"unknown firmware signature type");
                BOOL image = [kind isEqual:@"sha256"] && [value isEqual:imageHash];
                need(![field[0] isEqual:@"db"] || image, "unexpected firmware allow entry");
                need(![field[0] isEqual:@"dbx"] || !image, "revoked image");
                NSString *row=[NSString stringWithFormat:@"%@:%@:%@\n",field[0],kind,value];
                need(![rows containsObject:row],"duplicate firmware entry"); [rows addObject:row]; count++;
            }
        }
        need(![field[0] isEqual:@"db"] || count == 1, "firmware allow set");
    }
    NSString *bytes = [[[rows allObjects] sortedArrayUsingSelector:@selector(compare:)] componentsJoinedByString:@""];
    return digest([bytes dataUsingEncoding:NSUTF8StringEncoding]);
}

static NSDictionary *deviceGraph(NSURL *diskURL, VZEFIVariableStore *store, NSPipe *pipe,
                                 VZVirtualMachineConfiguration **held) {
    VZDiskImageStorageDeviceAttachment *disk = [[VZDiskImageStorageDeviceAttachment alloc] initWithURL:diskURL readOnly:YES error:NULL];
    need(disk && disk.isReadOnly && [disk.URL isEqual:diskURL],"read-only disk attachment");
    VZNVMExpressControllerDeviceConfiguration *nvme=[[VZNVMExpressControllerDeviceConfiguration alloc] initWithAttachment:disk];
    VZGenericPlatformConfiguration *p=[[VZGenericPlatformConfiguration alloc] init];
    VZEFIBootLoader *efi=[[VZEFIBootLoader alloc] init]; efi.variableStore=store;
    VZFileHandleSerialPortAttachment *serial=[[VZFileHandleSerialPortAttachment alloc]
        initWithFileHandleForReading:nil fileHandleForWriting:pipe.fileHandleForWriting];
    VZVirtioConsoleDeviceSerialPortConfiguration *port=[[VZVirtioConsoleDeviceSerialPortConfiguration alloc] init];
    port.attachment=serial;
    VZVirtualMachineConfiguration *cfg=[VZVirtualMachineConfiguration new];
    cfg.platform=p; cfg.bootLoader=efi; cfg.CPUCount=2; cfg.memorySize=4ULL<<30;
    cfg.storageDevices=@[nvme]; cfg.serialPorts=@[port];
    cfg.audioDevices=@[]; cfg.consoleDevices=@[]; cfg.directorySharingDevices=@[]; cfg.entropyDevices=@[];
    cfg.graphicsDevices=@[]; cfg.keyboards=@[]; cfg.memoryBalloonDevices=@[]; cfg.networkDevices=@[];
    cfg.pointingDevices=@[]; cfg.socketDevices=@[];
    NSUInteger other=cfg.audioDevices.count+cfg.consoleDevices.count+cfg.directorySharingDevices.count+
        cfg.entropyDevices.count+cfg.graphicsDevices.count+cfg.keyboards.count+cfg.memoryBalloonDevices.count+
        cfg.networkDevices.count+cfg.pointingDevices.count+cfg.socketDevices.count;
    if (@available(macOS 15.0,*)) {
        cfg.usbControllers=@[]; other+=cfg.usbControllers.count;
        need(!p.nestedVirtualizationEnabled,"nested virtualization");
    }
    if ([cfg respondsToSelector:NSSelectorFromString(@"customVirtioDevices")]) {
        NSArray *v=getter(cfg,@"customVirtioDevices"); need([v isKindOfClass:NSArray.class],"custom virtio readback"); other+=v.count;
    } else need(NSProcessInfo.processInfo.operatingSystemVersion.majorVersion < 27,"custom virtio API missing");
    struct stat rd,wr; int r=pipe.fileHandleForReading.fileDescriptor, w=pipe.fileHandleForWriting.fileDescriptor;
    need(!other && cfg.CPUCount==2 && cfg.memorySize==(4ULL<<30) && p && cfg.platform==p &&
         efi && cfg.bootLoader==efi && efi.variableStore==store &&
         cfg.storageDevices.count==1 && cfg.storageDevices[0]==nvme && nvme.attachment==disk &&
         cfg.serialPorts.count==1 && cfg.serialPorts[0]==port && port.attachment==serial &&
         !serial.fileHandleForReading && serial.fileHandleForWriting==pipe.fileHandleForWriting &&
         fstat(r,&rd)==0 && fstat(w,&wr)==0 && S_ISFIFO(rd.st_mode) && S_ISFIFO(wr.st_mode) &&
         (fcntl(r,F_GETFL)&O_ACCMODE)==O_RDONLY && (fcntl(w,F_GETFL)&O_ACCMODE)==O_WRONLY,
         "isolated device graph readback");
    if (store) need([cfg validateWithError:NULL],"target configuration validation");
    *held=cfg;
    return @{@"platform":@"generic-arm64-efi", @"cpu_count":@(cfg.CPUCount), @"memory_bytes":@(cfg.memorySize),
      @"nvme_controllers":@(cfg.storageDevices.count), @"raw_disks":@1, @"attachment_read_only":@(disk.isReadOnly),
      @"serial_output_only":@(cfg.serialPorts.count), @"guest_serial_input":@NO, @"other_devices":@(other),
      @"variable_store_bound":@((BOOL)(store!=nil))};
}

static void retainReceipt(int dir, const char *name, NSData *receipt) {
    int out=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0400);
    need(out>=0 && write(out,receipt.bytes,receipt.length)==(ssize_t)receipt.length &&
         fsync(out)==0 && close(out)==0 && fsync(dir)==0,"durable exclusive binding receipt");
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        need(argc == 5 || argc == 7,"preview DISK FIXTURE_ROOT ATTEMPT_UUID | bind-existing DISK FIXTURE_ROOT ATTEMPT_UUID STORE_SHA256 POLICY_SHA256");
        BOOL bind=argc==7;
        need(strcmp(argv[1],bind?"bind-existing":"preview")==0,"unsupported operation");
        NSOperatingSystemVersion os=NSProcessInfo.processInfo.operatingSystemVersion;
        need(!bind || (os.majorVersion==27 && os.minorVersion==2 && os.patchVersion==1),"target macOS 27.2.1 required");
        NSString *diskPath=@(argv[2]), *root=@(argv[3]), *uuid=@(argv[4]);
        NSUUID *parsed=[[NSUUID alloc] initWithUUIDString:uuid];
        need(parsed && [parsed.UUIDString.lowercaseString isEqual:uuid] && ![uuid isEqual:@"00000000-0000-0000-0000-000000000000"],"canonical attempt UUID required");
        NSString *expectedStore=bind?@(argv[5]):nil, *expectedPolicy=bind?@(argv[6]):nil;
        need(!bind || (shaString(expectedStore) && shaString(expectedPolicy)),"external store and policy digests required");
        need(canonical(root) && (bind ? [diskPath isEqual:[root stringByAppendingPathComponent:@"aragorn-arm64.raw"]]
                                      : [diskPath hasSuffix:mediaSuffix]), "fixture or B44 disk location");
        int rootFD=open(root.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_DIRECTORY|O_CLOEXEC);
        struct stat rootStat; need(rootFD>=0 && dirAt(rootFD,root,&rootStat) && !flock(rootFD,LOCK_EX|LOCK_NB),"private exclusive fixture root");
        if (!bind) {
            NSString *dir=diskPath;
            for (int i=0;i<3;i++) { dir=dir.stringByDeletingLastPathComponent;
                struct stat mode; need(!lstat(dir.fileSystemRepresentation,&mode) && S_ISDIR(mode.st_mode) &&
                    mode.st_uid==getuid() && (mode.st_mode&07777)==0700,"private retained disk directory"); }
        }
        NSDictionary *signer=runnerIdentity(); uint64_t start=B45MonotonicNow();
        Held disk=hold(diskPath,3542227456LL,3542227456LL,YES);
        need([fileHash(disk) isEqual:@(B45_DISK_SHA256)] && stable(disk,diskPath),"B44 raw disk digest");
        NSString *storePath=[root stringByAppendingPathComponent:@"efi-vars.fd"]; Held sf={.fd=-1};
        VZEFIVariableStore *store=nil; id storeInfo=NSNull.null;
        if (bind) {
            sf=hold(storePath,1,64LL<<20,NO); mode_t mode=sf.st.st_mode&07777;
            need((mode==0400 || mode==0600) && [fileHash(sf) isEqual:expectedStore] && stable(sf,storePath),"private pinned store");
            NSURL *url=[NSURL fileURLWithPath:storePath isDirectory:NO];
            store=[[VZEFIVariableStore alloc] initWithURL:url];
            need(store && [store.URL isEqual:url] && [policyHash(store) isEqual:expectedPolicy],"bound firmware policy");
            storeInfo=@{@"identity":identity(sf.st),@"sha256":expectedStore,@"policy_sha256":expectedPolicy,@"secure_boot_enabled":@YES};
        }
        need(!mkdirat(rootFD,uuid.UTF8String,0700),"attempt already exists or cannot be reserved");
        int attempt=openat(rootFD,uuid.UTF8String,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_DIRECTORY);
        NSString *attemptPath=[root stringByAppendingPathComponent:uuid]; struct stat attemptStat;
        need(attempt>=0 && dirAt(attempt,attemptPath,&attemptStat) && fsync(rootFD)==0,"one-shot attempt directory");
        NSPipe *pipe=[NSPipe pipe]; NSDictionary *graph=nil; BOOL armedWithGraph=NO, custodyOK=NO;
        dispatch_group_t worker=dispatch_group_create();
        dispatch_semaphore_t armed=dispatch_semaphore_create(0);
        dispatch_queue_t queue=dispatch_queue_create("org.aragorn.b45.serial",DISPATCH_QUEUE_SERIAL);
        __block NSDictionary *capture=nil;
        @autoreleasepool {
            __attribute__((objc_precise_lifetime)) VZVirtualMachineConfiguration *cfg=nil;
            graph=deviceGraph([NSURL fileURLWithPath:diskPath isDirectory:NO],store,pipe,&cfg);
            need(stable(disk,diskPath) && (!bind || (stable(sf,storePath) &&
                [fileHash(sf) isEqual:expectedStore] && stable(sf,storePath))),"substitution while binding");
            int readFD=pipe.fileHandleForReading.fileDescriptor;
            dispatch_group_async(worker,queue,^{ @autoreleasepool {
                capture=B45RecordSerialArmed(readFD,attempt,start,armed);
            } });
            BOOL ready=dispatch_semaphore_wait(armed,dispatch_time(DISPATCH_TIME_NOW,5LL*NSEC_PER_SEC))==0;
            armedWithGraph=ready && [cfg.serialPorts.firstObject.attachment isKindOfClass:VZFileHandleSerialPortAttachment.class] &&
                ((VZFileHandleSerialPortAttachment *)cfg.serialPorts.firstObject.attachment).fileHandleForWriting==pipe.fileHandleForWriting &&
                ((VZEFIBootLoader *)cfg.bootLoader).variableStore==store;
            custodyOK=stable(disk,diskPath) && (!bind || stable(sf,storePath));
        } // No VM exists. Retire the graph while still retaining the exact pipe, then close its writer.
        uint64_t retired=B45MonotonicNow();
        BOOL closed=[pipe.fileHandleForWriting closeAndReturnError:NULL];
        // This dry graph cannot produce data. The extra two seconds are for sealing metadata, not capture.
        BOOL joined=dispatch_group_wait(worker,dispatch_time(DISPATCH_TIME_NOW,2LL*NSEC_PER_SEC))==0;
        if (!armedWithGraph || !custodyOK || !closed || !joined || !capture ||
            ![capture[@"status"] isEqual:@"empty"] || ![capture[@"sync_verified"] boolValue] ||
            ![capture[@"pipe_eof"] boolValue] || ![capture[@"capture_bytes"] isEqual:@0] ||
            [capture[@"record_start_ns"] unsignedLongLongValue]>retired ||
            retired>[capture[@"record_end_ns"] unsignedLongLongValue]) {
            id terminal=joined && capture ? (id)capture : NSNull.null;
            retainReceipt(attempt,"binding-failure.json",json(@{@"schema":@"aragorn/b44-host-binding-failure/v1",
              @"attempt_uuid":uuid,@"recorder_armed_with_graph":@(armedWithGraph),@"graph_retired_ns":@(retired),
              @"custody_stable":@(custodyOK),@"writer_closed":@(closed),@"recorder_joined":@(joined),
              @"capture":terminal,@"boot_observed":@NO,@"phase3_exit_eligible":@NO}));
            need(NO,"capture handoff incomplete; retained attempt, no retry");
        }
        struct stat now;
        need(dirAt(rootFD,root,&now) && sameNode(now,rootStat) && dirAt(attempt,attemptPath,&now) &&
             sameNode(now,attemptStat) && stable(disk,diskPath) && (!bind || stable(sf,storePath)),"custody changed");
        NSMutableDictionary *result=[@{@"schema":@"aragorn/b44-host-binding/v1",@"mode":@(argv[1]),
            @"attempt_uuid":uuid,@"request_sha256":@(B45_REQUEST_SHA256),@"media_pins_sha256":@(B45_MEDIA_PINS_SHA256),
            @"disk_sha256":@(B45_DISK_SHA256),@"disk_bytes":@(disk.st.st_size),@"disk_identity":identity(disk.st),
            @"fixture_identity":identity(rootStat),@"store":storeInfo,@"graph":graph,@"graph_sha256":digest(json(graph)),
            @"uki_sha256":@"bc5ce331a61b4a35350adfbf4d6a4acb4061754d94078a94f558a009449f6a27",
            @"authenticode_sha256":imageHash,@"esl_sha256":@"ef48fe74972ba8f7343ea74fcd44544bcf8c467521c750031f02cfe11b5fbb30",
            @"capture":capture,@"recorder_armed_with_graph":@(armedWithGraph),@"graph_retired_ns":@(retired),
            @"vm_created":@NO,@"boot_observed":@NO,@"phase3_exit_eligible":@NO} mutableCopy];
        [result addEntriesFromDictionary:signer];
        NSMutableData *receipt=[json(result) mutableCopy]; [receipt appendBytes:"\n" length:1];
        retainReceipt(attempt,"binding.json",receipt);
        need(fwrite(receipt.bytes,1,receipt.length,stdout)==receipt.length && fflush(stdout)==0,"report binding");
        close(disk.fd); if (bind) close(sf.fd); close(attempt); close(rootFD); return 0;
    }
}
