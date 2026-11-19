// No firmware store, file, EFI enrollment or VZ configuration. Feed the production
// policy checker inert Objective-C values on a host without the macOS 27 classes.
#import <Foundation/Foundation.h>
#import <Virtualization/Virtualization.h>
#import <Security/Security.h>
@interface FixtureHash : NSObject
@property(nonatomic,copy) NSData *data;
@end
@implementation FixtureHash
@end
static Class fixtureClass(NSString *s) {
    return [s isEqual:@"VZEFISignatureSHA256Hash"] ? FixtureHash.class : Nil;
}
#define NSClassFromString(s) fixtureClass(s)
#define main unusedHostMain
#define B45_REQUEST_SHA256 ""
#define B45_MEDIA_PINS_SHA256 ""
#define B45_DISK_SHA256 ""
#import "host-runner.m"
#undef main

@interface Fixture : NSObject
@property(nonatomic,copy) NSArray *keyExchangeKeys;
@property(nonatomic,copy) NSArray *dbSignatures;
@property(nonatomic,copy) NSArray *dbxSignatures;
@property(nonatomic,copy) NSArray *signatures;
@property(nonatomic) BOOL enabled;
@end
@implementation Fixture
- (BOOL)getSecureBootEnabled:(BOOL *)value error:(NSError **)error { *value=self.enabled; return YES; }
- (id)getEnrolledSecureBootSignaturesWithError:(NSError **)error { return self; }
@end
static Fixture *group(NSArray *values) { Fixture *f=[Fixture new]; f.signatures=values; return f; }
static FixtureHash *h(NSData *data) { FixtureHash *f=[FixtureHash new]; f.data=data; return f; }
int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc!=2) return 3;
        NSString *mode=@(argv[1]);
        unsigned char img[32], ones[32]; memset(ones,1,32);
        for (NSUInteger i=0;i<32;i++) {
            NSString *pair=[imageHash substringWithRange:NSMakeRange(2*i,2)];
            img[i]=(unsigned char)strtoul(pair.UTF8String,NULL,16);
        }
        id image=h([NSData dataWithBytes:img length:32]), kek=h([NSMutableData dataWithLength:32]);
        id revoked=h([NSData dataWithBytes:ones length:32]);
        Fixture *db=[Fixture new]; db.enabled=![mode isEqual:@"disabled"];
        db.keyExchangeKeys=@[group(@[kek])]; db.dbxSignatures=@[group(@[revoked])]; db.dbSignatures=@[group(@[image])];
        if ([mode isEqual:@"revoked"]) db.dbxSignatures=@[group(@[image])];
        if ([mode isEqual:@"extra"]) db.dbSignatures=@[group(@[image,kek])];
        if ([mode isEqual:@"duplicate"]) db.dbSignatures=@[group(@[image,image])];
        if ([mode isEqual:@"unknown"]) db.dbxSignatures=@[group(@[[NSObject new]])];
        if ([mode isEqual:@"empty"]) db.keyExchangeKeys=@[];
        puts(policyHash((VZEFIVariableStore *)(id)db).UTF8String);
        return 0;
    }
}
