#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// Only the canonical, build-time-validated release bytes are passed here.
static NSDictionary *B50Select(NSDictionary *release, NSString *uid) {
    if (![release isKindOfClass:NSDictionary.class] || release.count!=2 ||
        ![release[@"schema"] isEqual:@"aragorn/b50-single-use-release/v1"]) return nil;
    NSArray *slots=release[@"approved_attempts"];
    if (![slots isKindOfClass:NSArray.class] || slots.count!=1) return nil;
    NSDictionary *slot=slots[0];
    if (![slot isKindOfClass:NSDictionary.class] || ![slot[@"attempt_uuid"] isEqual:uid]) return nil;
    NSArray *names=@[@"nomination_sha256",@"enrollment_sha256",@"boot_approval_sha256"];
    NSMutableSet *receipts=[NSMutableSet set];
    for (NSString *name in names) {
        id h=slot[name];
        if (![h isKindOfClass:NSString.class] || [h length]!=64 ||
            [h rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"].invertedSet].location!=NSNotFound ||
            ![[h stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"0"]] length]) return nil;
        [receipts addObject:h];
    }
    return receipts.count==names.count ? slot : nil;
}

static BOOL B50Matches(NSDictionary *slot, NSString *host, NSDictionary *fixture,
                       NSDictionary *disk, NSDictionary *store) {
    return host && [host isEqual:slot[@"host_identity_sha256"]] &&
        [fixture isEqual:slot[@"fixture_identity"]] && [disk isEqual:slot[@"disk_identity"]] &&
        [store isEqual:slot[@"store_identity"]];
}

static BOOL B50Window(NSDictionary *slot, int64_t utc) {
    return utc>0 && [slot[@"not_before_utc"] longLongValue]<=utc && utc<[slot[@"expires_utc"] longLongValue];
}

// Never remove the reservation, even after an error. An already present UUID is spent.
static int B50Consume(int root, NSUUID *session) {
    const char *name=session.UUIDString.lowercaseString.UTF8String;
    if (!name || mkdirat(root,name,0700) || fsync(root)) return -1;
    return openat(root,name,O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);
}
