"""B50 changed gate only, using Foundation and a private temporary directory; never instantiate a VM."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import prepare_pi_core_single_use_owner as prep
from scripts.build_pi_core_linux import BuildError, canonical, sha256


# No VZ or host-identity APIs in this test program; the release input is inert data, not a compiled grant.
FIXTURE = r'''
#import "single-use.h"
int main(int argc,const char **argv) { @autoreleasepool {
    NSUUID *session=NSUUID.UUID;
    NSString *uid=session.UUIDString.lowercaseString;
    if (argc!=3) return 1;
    if (!strcmp(argv[1],"consume")) {
        int root=open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
        int first=B50Consume(root,session);
        if (first<0) return 2;
        struct stat expected, retained;
        if (fstat(first,&expected) || close(first) || close(root)) return 3;
        root=open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
        if (B50Consume(root,session)>=0 || fstatat(root,uid.UTF8String,&retained,AT_SYMLINK_NOFOLLOW)) return 4;
        return !(expected.st_ino==retained.st_ino && expected.st_dev==retained.st_dev && (retained.st_mode&07777)==0700);
    }
    NSDictionary *f=@{@"dev":@1,@"ino":@10}, *d=@{@"dev":@1,@"ino":@11}, *s=@{@"dev":@1,@"ino":@12};
    NSString *(^hash)(NSString *)=^NSString *(NSString *s){ return [s stringByPaddingToLength:64 withString:s startingAtIndex:0]; };
    NSDictionary *slot=@{@"attempt_uuid":uid,@"not_before_utc":@10,@"expires_utc":@20,
        @"nomination_sha256":hash(@"1"),@"enrollment_sha256":hash(@"2"),@"boot_approval_sha256":hash(@"3"),
        @"host_identity_sha256":@"fake",@"fixture_identity":f,@"disk_identity":d,@"store_identity":s};
    NSDictionary *(^release)(NSArray *)=^NSDictionary *(NSArray *slots) {
        return @{@"schema":@"aragorn/b50-single-use-release/v1",@"approved_attempts":slots};
    };
    if (!strcmp(argv[1],"select")) {
        NSMutableDictionary *missing=[slot mutableCopy]; [missing removeObjectForKey:@"nomination_sha256"];
        if (B50Select(release(@[missing]),uid) || B50Select(release(@[]),uid) || B50Select(release(@[slot,slot]),uid) ||
            B50Select(release(@[slot]),@"other") || B50Select(@{@"schema":@"wrong",@"approved_attempts":@[slot]},uid) ||
            ![B50Select(release(@[slot]),uid) isEqual:slot]) return 5;
        return !(B50Window(slot,10) && B50Window(slot,19) && !B50Window(slot,9) && !B50Window(slot,20));
    }
    if (strcmp(argv[1],"match")) return 6;
    return !(B50Matches(slot,@"fake",f,d,s) && !B50Matches(slot,@"wrong",f,d,s) &&
       !B50Matches(slot,nil,f,d,s) && !B50Matches(slot,@"fake",d,d,s) &&
       !B50Matches(slot,@"fake",f,s,s) && !B50Matches(slot,@"fake",f,d,d));
} }
'''


class SingleUseNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = Path(cls.tmp.name).resolve()
        cls.exe = cls.root / "inert"
        source = cls.root / "inert.m"
        source.write_text(FIXTURE)
        prep.b45.run(cls.root,[prep.b45.CC,"-isysroot",prep.b45.SDK,"-arch","arm64","-Werror","-fobjc-arc",
                     "-fno-modules","-I",prep.PACK,"-framework","Foundation",source,"-o",cls.exe],writable=True)

    def test_native_exact_slot_and_expiration(self):
        prep.b45.run(self.root,[self.exe,"select",self.root])

    def test_native_host_and_all_three_node_identities(self):
        prep.b45.run(self.root,[self.exe,"match",self.root])

    def test_durable_uuid_is_spent_even_after_closing_handles(self):
        prep.b45.run(self.root,[self.exe,"consume",self.root],writable=True)

    def test_pinned_artifact_closure_and_changed_preissue_guard(self):
        pin = json.loads(prep.PIN.read_bytes())
        exe = prep.verified_binary(pin)
        _, files, closure = prep.snapshots()
        self.assertEqual(sha256(canonical(closure)), pin["inputs_sha256"])
        self.assertEqual((exe.parent/"inputs.json").read_bytes(), canonical(closure))
        self.assertEqual(json.loads((exe.parent/"receipt.json").read_bytes()), pin)
        for name,data in files.items():
            self.assertEqual((exe.parent/name).read_bytes(),data)
        issued = files["supervised-owner.m"]
        self.assertIn(b"!machine.canStart || !B50PreStart()) return;\n        issued=YES;",issued)
        symbols = subprocess.run(["/usr/bin/nm","-j",exe],check=True,capture_output=True,timeout=10).stdout.splitlines()
        for sym in (b"_B47OwnMachine",b"_B50PreStart",b"_B45RecordSerialArmed",b"_OBJC_CLASS_$_VZVirtualMachine"):
            self.assertIn(sym,symbols)
        self.assertNotIn(b"_B47InertMachine",symbols)

    def test_artifact_rejects_mutable_or_wrong_release(self):
        pin = json.loads(prep.PIN.read_bytes())
        for change in ({"boot_authorized":True},{"release_sha256":"b"*64},{"runner_sha256":"a"*64}):
            with self.subTest(change=change), self.assertRaises(BuildError):
                prep.verified_binary(dict(pin, **change))
        # An otherwise accepted singleton is still refused before build output or target access.
        with patch.object(prep.contract,"parse_release",return_value={"approved_attempts":[{}]}), self.assertRaises(BuildError):
            prep.snapshots()
