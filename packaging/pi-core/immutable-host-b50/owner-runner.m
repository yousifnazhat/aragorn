#import "b45-binding.inc"
#import "vm-owner.h"
#import "single-use.h"
#include "b50-embedded-release.h"
#include <gethostuuid.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <uuid/uuid.h>

static NSDictionary *bound;
static NSString *observedHost;
static uint64_t sampledRaw, latestRaw;
static int64_t sampledUTC;

static NSString *hostDigest(void) {
    uuid_t bytes;
    struct timespec timeout={.tv_sec=1};
    if (gethostuuid(bytes,&timeout) || uuid_is_null(bytes)) return nil;
    NSUUID *uid=[[NSUUID alloc] initWithUUIDBytes:bytes];
    return digest([uid.UUIDString.lowercaseString dataUsingEncoding:NSASCIIStringEncoding]);
}

// The B47 gate calls this on its sole machine queue AFTER its checks and ARM, immediately before issue.
BOOL B50PreStart(void) {
    uint64_t raw=B45MonotonicNow();
    struct timespec utc;
    if (!raw || raw>=latestRaw || clock_gettime(CLOCK_REALTIME,&utc) || !B50Window(bound,utc.tv_sec)) return NO;
    sampledRaw=raw; sampledUTC=utc.tv_sec;
    return YES;
}

static int inheritedFD(const char *s) {
    char *end; errno=0; long n=strtol(s,&end,10);
    need(!errno && *s>='1' && *s<='9' && *end=='\0' && n>=3 && n<=INT_MAX && fcntl((int)n,F_GETFD)>=0,
         "invalid inherited descriptor");
    return (int)n;
}

int main(int argc,const char **argv) { @autoreleasepool {
    need(argc==6 && !strcmp(argv[1],"own"),"own FIXTURE UUID STOP_FD ARM_FD");
    NSString *uid=@(argv[3]);
    NSUUID *session=[[NSUUID alloc] initWithUUIDString:uid];
    need(session && [uid isEqual:session.UUIDString.lowercaseString] &&
         ![uid isEqual:@"00000000-0000-0000-0000-000000000000"],"invalid attempt UUID");
    NSData *manifest=[NSData dataWithBytes:B50ReleaseBytes length:sizeof(B50ReleaseBytes)];
    need([digest(manifest) isEqual:@(B50_RELEASE_SHA256)],"release digest");
    bound=B50Select([NSJSONSerialization JSONObjectWithData:manifest options:0 error:NULL],uid);
    if (!bound) { fputs("B50 held: no approved boot attempt\n",stderr); return 78; }

    NSOperatingSystemVersion os=NSProcessInfo.processInfo.operatingSystemVersion;
    need(os.majorVersion==27 && os.minorVersion==2 && os.patchVersion==1,"target OS mismatch");
    uint64_t anchor=B45MonotonicNow(); struct timespec utc;
    need(anchor && !clock_gettime(CLOCK_REALTIME,&utc) && B50Window(bound,utc.tv_sec),"outside boot window");
    // Never extend the original expiry if the wall clock steps backwards.
    uint64_t remaining=MIN(211ULL,(uint64_t)([bound[@"expires_utc"] longLongValue]-utc.tv_sec))*NSEC_PER_SEC;
    need(anchor<=UINT64_MAX-remaining,"invalid clock"); latestRaw=anchor+remaining-(uint64_t)utc.tv_nsec;
    observedHost=hostDigest();
    NSString *root=@(argv[2]);
    need(observedHost && [observedHost isEqual:bound[@"host_identity_sha256"]] &&
         [bound[@"fixture"] isEqual:root] && canonical(root) &&
         [bound[@"disk_sha256"] isEqual:@(B45_DISK_SHA256)],"wrong host, fixture or disk pin");
    int stop=inheritedFD(argv[4]), arm=inheritedFD(argv[5]);
    need(stop!=arm,"aliased supervision channels");
    NSDictionary *signer=runnerIdentity();
    int r=open(root.fileSystemRepresentation,O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC|O_RDONLY);
    struct stat rs,as;
    need(r>=0 && dirAt(r,root,&rs) && [identity(rs) isEqual:bound[@"fixture_identity"]] &&
         !flock(r,LOCK_EX|LOCK_NB),"private nominated fixture");
    int a=B50Consume(r,session);
    need(a>=0 && dirAt(a,[root stringByAppendingPathComponent:uid],&as),"attempt unavailable or already consumed");
    NSString *dp=[root stringByAppendingPathComponent:@"aragorn-arm64.raw"], *sp=[root stringByAppendingPathComponent:@"efi-vars.fd"];
    Held d=hold(dp,3542227456LL,3542227456LL,YES), s=hold(sp,1,64LL<<20,NO);
    need(B50Matches(bound,observedHost,identity(rs),identity(d.st),identity(s.st)) &&
         ((s.st.st_mode&07777)==0400 || (s.st.st_mode&07777)==0600) &&
         [fileHash(d) isEqual:@(B45_DISK_SHA256)] && [fileHash(s) isEqual:bound[@"store_sha256"]] &&
         stable(d,dp) && stable(s,sp),"changed nominated media");
    NSURL *url=[NSURL fileURLWithPath:sp isDirectory:NO];
    VZEFIVariableStore *store=[[VZEFIVariableStore alloc] initWithURL:url];
    need(store && [store.URL isEqual:url] && [policyHash(store) isEqual:bound[@"policy_sha256"]],"store policy");
    uint64_t began=B45MonotonicNow(); NSPipe *serial=[NSPipe pipe]; VZVirtualMachineConfiguration *cfg=nil;
    NSDictionary *graph=deviceGraph([NSURL fileURLWithPath:dp isDirectory:NO],store,serial,&cfg);
    need(stable(d,dp) && [fileHash(s) isEqual:bound[@"store_sha256"]] && stable(s,sp),"media changed");
    NSDictionary *owned=B47OwnMachine(cfg,serial,a,session,stop,arm,began);
    NSDictionary *inner=@{@"schema":@"aragorn/b47-bound-owner-terminal/v1",@"attempt_uuid":uid,
      @"runner":signer,@"fixture_identity":identity(rs),@"attempt_identity":identity(as),
      @"disk_identity":identity(d.st),@"disk_sha256":@(B45_DISK_SHA256),@"store_identity":identity(s.st),
      @"store_sha256_before":bound[@"store_sha256"],@"policy_sha256_before":bound[@"policy_sha256"],
      @"graph":graph,@"owner":owned ?: (id)NSNull.null,@"phase3_exit_eligible":@NO};
    retainReceipt(a,"owner-terminal.json",json(@{@"schema":@"aragorn/b50-owner-terminal/v1",
        @"release_sha256":@(B50_RELEASE_SHA256),@"host_identity_sha256":observedHost,
        @"consumed_identity":identity(as),@"start_check_utc_s":@(sampledUTC),@"start_check_raw_ns":@(sampledRaw),@"terminal":inner}));
    close(a); close(s.fd); close(d.fd); close(r);
    return [owned[@"complete"] isEqual:@YES] ? 0 : 2;
} }
