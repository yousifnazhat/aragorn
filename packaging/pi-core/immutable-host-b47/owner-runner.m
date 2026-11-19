// b45-binding.inc is generated from the pinned B45 binding helpers, without its main.
#import "b45-binding.inc"
#import "vm-owner.h"
#include <errno.h>
#include <limits.h>

static int inheritedFD(const char *s) {
    char *end; errno=0;
    long n=strtol(s,&end,10);
    need(!errno && *s>='1' && *s<='9' && *end=='\0' && n>=3 && n<=INT_MAX &&
         fcntl((int)n,F_GETFD)>=0, "invalid inherited descriptor");
    return (int)n;
}

static NSDictionary *releaseFor(NSString *attempt) {
    // Embedded in the signed executable. This build accepts only an EMPTY release inventory.
    // No command-line flag, environment variable or caller-supplied approval is consulted.
    NSData *data=[NSData dataWithBytes:B47_RELEASE length:sizeof(B47_RELEASE)-1];
    NSDictionary *manifest=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    need([manifest[@"schema"] isEqual:@"aragorn/b47-host-release/v1"], "release schema");
    for (NSDictionary *entry in manifest[@"approved_attempts"])
        if ([entry[@"attempt_uuid"] isEqual:attempt]) return entry;
    return nil;
}

static int runBoundTarget(NSDictionary *entry, NSString *root, NSUUID *session, int stopFD, int armFD) {
    NSOperatingSystemVersion os=NSProcessInfo.processInfo.operatingSystemVersion;
    need(os.majorVersion==27 && os.minorVersion==2 && os.patchVersion==1, "target OS mismatch");
    NSString *uuid=session.UUIDString.lowercaseString;
    need(stopFD!=armFD && [entry[@"fixture"] isEqual:root] && canonical(root) &&
         shaString(entry[@"store_sha256"]) && shaString(entry[@"policy_sha256"]), "target binding");
    NSDictionary *signer=runnerIdentity();
    int rootFD=open(root.fileSystemRepresentation,O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_RDONLY);
    struct stat rootStat,attemptStat;
    need(rootFD>=0 && dirAt(rootFD,root,&rootStat) && !flock(rootFD,LOCK_EX|LOCK_NB),"private owned fixture");
    NSString *diskPath=[root stringByAppendingPathComponent:@"aragorn-arm64.raw"];
    NSString *storePath=[root stringByAppendingPathComponent:@"efi-vars.fd"];
    Held disk=hold(diskPath,3542227456LL,3542227456LL,YES), sf=hold(storePath,1,64LL<<20,NO);
    need(((sf.st.st_mode&07777)==0400 || (sf.st.st_mode&07777)==0600) &&
         [fileHash(disk) isEqual:@(B45_DISK_SHA256)] && [fileHash(sf) isEqual:entry[@"store_sha256"]] &&
         stable(disk,diskPath) && stable(sf,storePath), "sealed disk or enrolled store mismatch");
    NSURL *url=[NSURL fileURLWithPath:storePath isDirectory:NO];
    VZEFIVariableStore *store=[[VZEFIVariableStore alloc] initWithURL:url];
    need(store && [store.URL isEqual:url] && [policyHash(store) isEqual:entry[@"policy_sha256"]], "EFI policy mismatch");
    need(!mkdirat(rootFD,uuid.UTF8String,0700), "attempt already reserved");
    int attempt=openat(rootFD,uuid.UTF8String,O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_RDONLY);
    NSString *path=[root stringByAppendingPathComponent:uuid];
    need(attempt>=0 && dirAt(attempt,path,&attemptStat) && !fsync(rootFD), "attempt reservation");
    uint64_t began=B45MonotonicNow();
    NSPipe *serial=[NSPipe pipe];
    VZVirtualMachineConfiguration *cfg=nil;
    NSDictionary *graph=deviceGraph([NSURL fileURLWithPath:diskPath isDirectory:NO],store,serial,&cfg);
    need(stable(disk,diskPath) && [fileHash(sf) isEqual:entry[@"store_sha256"]] && stable(sf,storePath),
         "substitution during binding");
    NSDictionary *owned=B47OwnMachine(cfg,serial,attempt,session,stopFD,armFD,began);
    NSDictionary *terminal=@{@"schema":@"aragorn/b47-bound-owner-terminal/v1", @"attempt_uuid":uuid,
        @"runner":signer, @"fixture_identity":identity(rootStat), @"attempt_identity":identity(attemptStat),
        @"disk_identity":identity(disk.st), @"disk_sha256":@(B45_DISK_SHA256),
        @"store_identity":identity(sf.st), @"store_sha256_before":entry[@"store_sha256"],
        @"policy_sha256_before":entry[@"policy_sha256"], @"graph":graph,
        @"owner":owned ?: (id)NSNull.null, @"phase3_exit_eligible":@NO};
    retainReceipt(attempt,"owner-terminal.json",json(terminal));
    close(attempt); close(disk.fd); close(sf.fd); close(rootFD);
    // A durable terminal report (even a positive stop) is not approval for cleanup.
    return [owned[@"complete"] isEqual:@YES] ? 0 : 2;
}

int main(int argc,const char **argv) { @autoreleasepool {
    need(argc==6 && !strcmp(argv[1],"own"),"own FIXTURE UUID STOP_FD ARM_FD");
    NSString *uuid=@(argv[3]);
    NSUUID *session=[[NSUUID alloc] initWithUUIDString:uuid];
    need(session && [session.UUIDString.lowercaseString isEqual:uuid] &&
         ![uuid isEqual:@"00000000-0000-0000-0000-000000000000"], "attempt UUID");
    NSDictionary *entry=releaseFor(uuid);
    if (!entry) { fputs("B47 held: no approved boot attempt\n",stderr); return 78; }
    return runBoundTarget(entry,@(argv[2]),session,inheritedFD(argv[4]),inheritedFD(argv[5]));
} }
