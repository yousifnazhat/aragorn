"""Prepare or statically verify the B112-bound B113 owner. No start or private-release operation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess

from scripts import prepare_pi_core_bound_host_runner as host
from scripts.build_pi_core_linux import ROOT, canonical, require, sha256
from scripts.prepare_pi_core_guest_disk import opened, put
from scripts.verify_pi_core_host_binding import identity, retained, signed_pin, unique


BASE = ROOT / "packaging/pi-core"
PACK = BASE / "immutable-host-b113"
PIN = PACK / "runner-output.json"
WORK = Path.home() / "Library/Application Support/Aragorn-B113-Offline"
ID = "org.aragorn.pi-core.b113.host-owner"
SCHEMA = "aragorn/b113-held-owner/v1"
HELD = {"schema": "aragorn/b113-single-use-release/v1", "approved_attempts": []}
RELEASE = canonical(HELD)
MEDIA_PIN = "fac725f23b8a1d694ba89054859710786649693c53d23a9c19a01794938877f7"
REQUEST_PIN = "b765a437ea55e54c18e2418c7e084f0bd195361b9fc7537cf755a812087c436a"
PROPOSAL_PIN = "af7197021a39f2dc7d96ecaa5a47f0c346a0fa6e0d0eb56e413d7b4b3b760d9c"
SOURCES = {
    (50, "owner-runner.m"): "503aef831e8d4df64e84045f134c6a6d6fbe9a5136629ffa74ad185bd0ccb471",
    (50, "single-use.h"): "6350583b6bc9d42fa8667bc3a46321d8dddacbc7e206c970dc9c0b25161e9ad1",
    (47, "vm-owner.m"): "6fb3fedb6a685680b0318921f46ed3e6551af0903a43f7013931b1559a17ed2a",
    (47, "vm-owner.h"): "1474f2c372728bdc13136eb13c8dac22e0356faadc30b65cf53cda3389c39e64",
    (46, "vm-stop.m"): "ff8fbb12990fb1ee0bd455b3cf560496f7f79d107985b3323597afc5bd2dfc75",
    (46, "vm-stop.h"): "123d30e5542bf4ee513d767874cdbdd3a19c9727605bf56059933754d8475d6f",
    (45, "host-runner.m"): "8c1f179efc8b224cda14219d7524af06543a5bd239ace523ef16eb46ef4f4084",
    (45, "serial-recorder.h"): "6c0fa55ae202ca711d0063b97b4ffeced3712f87c1f7bfa9eef3b611e3a0e0d4",
    (45, "serial-recorder.m"): "210561eb3c0718fe3e7b46db804ce844ab5d4229b6833ad7cb6a54ace7f5533b",
    (45, "runner.entitlements.plist"): "5c1c6753b84cc1a1349de2a465074f166b5a47bade536b231683c22f53072259",
}


def pinned(path, digest):
    data = host.source_bytes(path)
    require(sha256(data) == digest, "wrong B113 source: " + path.name)
    return data


def held(raw):
    require(raw == RELEASE + b"\n", "B113 is held; private, predecessor or nonempty releases are not build inputs")
    return RELEASE


def profile():
    media = json.loads(pinned(BASE/"immutable-host-b112/media-output.json", MEDIA_PIN))
    req = json.loads(pinned(PACK/"boot-request.json", REQUEST_PIN))
    prop = json.loads(pinned(PACK/"firmware-proposal.json", PROPOSAL_PIN))
    fields = ("disk_bytes", "disk_sha256", "uki_sha256", "authenticode_sha256", "esl_sha256")
    require(all(media[k] == prop[k] for k in fields) and (req["guest"]["disk_sha256"], req["guest"]["disk_bytes"])
            == (media["disk_sha256"], media["disk_bytes"]) and all(x is False for x in req["authority_now"].values())
            and prop["media_catalog_sha256"] == MEDIA_PIN and prop["boot_request_sha256"] == REQUEST_PIN
            and prop["boot_authorized"] is False, "media, public request or held proposal disagree")
    return {**{k: media[k] for k in fields}, "media_pins_sha256": MEDIA_PIN, "request_sha256": REQUEST_PIN,
            "firmware_proposal_sha256": PROPOSAL_PIN, "serial_recorder_sha256": SOURCES[45, "serial-recorder.m"]}


def once(data, old, new):
    require(data.count(old) == 1, "ambiguous pinned native transformation")
    return data.replace(old, new, 1)


def arrays(name, data):
    return (f"static const unsigned char {name}[]={{" + ",".join(map(str, data)) + "};\n").encode("ascii")


def snapshots():
    media = profile()
    hold = held(host.source_bytes(PACK / "owner-release.json"))
    files = {n: pinned(BASE / f"immutable-host-b{b}" / n, digest) for (b,n), digest in SOURCES.items()}
    prefix, marker, _ = files.pop("host-runner.m").partition(b"\nint main(")
    require(marker and prefix.count(b"static NSString *const mediaSuffix") == 1, "missing frozen B45 binding helpers")
    # The obsolete preview route/path isn't compiled into the B113 owner.
    prefix = b"\n".join(line for line in prefix.split(b"\n") if not line.startswith(b"static NSString *const mediaSuffix"))
    prefix = once(prefix, host.IDENTIFIER.encode(), ID.encode())
    files["b45-binding.inc"] = once(prefix, b"fa2ccca39b781d7e20baad88944bf0a52c5b578034d49b6839dd79f4040a22fa",
                                    media["authenticode_sha256"].encode())
    gate = b"|| !machine.canStart) return;\n        issued=YES;"
    files["supervised-owner.m"] = (b'#import <Foundation/Foundation.h>\nextern BOOL B50PreStart(void);\n' +
        once(files.pop("vm-owner.m"), gate, gate.replace(b"!machine.canStart)", b"!machine.canStart || !B50PreStart())")))
    files["single-use.h"] = once(files["single-use.h"], b"aragorn/b50-single-use-release/v1",
                                 HELD["schema"].encode())
    src = once(files["owner-runner.m"], b"B50 held: no approved boot attempt", b"B113 held: no approved boot attempt")
    src = once(src, b"3542227456LL,3542227456LL", b"B113_DISK_BYTES,B113_DISK_BYTES")
    src = once(src, b"    NSData *manifest=", b"""    NSData *pins=[NSData dataWithBytes:B113Media length:sizeof(B113Media)];
    need([digest(pins) isEqual:@(B113_MEDIA_SHA256)],"media digest");
    NSDictionary *media=[NSJSONSerialization JSONObjectWithData:pins options:0 error:NULL];
    need([media[@"disk_sha256"] isEqual:@(B45_DISK_SHA256)] &&
         [media[@"disk_bytes"] isEqual:@(B113_DISK_BYTES)] &&
         [media[@"authenticode_sha256"] isEqual:imageHash],"media constants");
    NSData *manifest=""")
    files["owner-runner.m"] = once(src, b'@"aragorn/b50-owner-terminal/v1",',
                                   b'@"aragorn/b113-owner-terminal/v1",@"media":media,')
    files["b50-embedded-release.h"] = arrays("B50ReleaseBytes", hold) + arrays("B113Media", canonical(media))
    ingredients = dict(files={k: sha256(v) for k,v in files.items()}, tools={str(k): v for k,v in host.TOOLS.items()},
                       recipe_sha256=sha256(host.source_bytes(Path(__file__).resolve())), identifier=ID, media=media,
                       release_sha256=sha256(hold))
    return files, ingredients


def properties(exe, media):
    with opened(exe) as f:
        st = os.fstat(f.fileno())
        require(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o500 and 32 < st.st_size <= 8 << 20,
                "unsealed B113 runner")
        raw = f.read(st.st_size)
        require(raw.count(canonical(media)) == 1 and raw.count(RELEASE) == 1, "missing/duplicate compiled B113 bindings")
        host.run(exe.parent, [host.SIGN, "--verify", "--strict", "--all-architectures", exe])
        desc = host.run(exe.parent, [host.SIGN, "--display", "--verbose=4", exe]).stderr.decode()
        fields = dict(line.split("=",1) for line in desc.splitlines() if "=" in line)
        ent = plistlib.loads(host.run(exe.parent, [host.SIGN,"--display","--entitlements","-","--xml",exe]).stdout)
        require(fields.get("Identifier") == ID and fields.get("Signature") == "adhoc" and
                fields.get("TeamIdentifier") == "not set" and re.fullmatch("[0-9a-f]{40}", fields.get("CDHash","")) and
                "runtime" in fields.get("CodeDirectory v","").partition("flags=")[2].partition(")")[0]
                and ent.keys() == {host.ENTITLEMENT} and ent[host.ENTITLEMENT] is True, "unexpected B113 signature")
        return dict(runner_sha256=sha256(raw), runner_bytes=len(raw), identifier=ID, cdhash=fields["CDHash"],
                    macho_uuid_hex=host.macho_uuid(raw), signing="ad-hoc-local-integrity", entitlements=ent)


def receipt(key, props, media):
    return dict(schema=SCHEMA, directory="build-"+key, inputs_sha256=key, approval_commit=None,
                release_sha256=sha256(RELEASE), boot_authorized=False, **media, **props)


def build():
    files, inputs = snapshots()
    for path, pin in host.TOOLS.items():
        actual = path.resolve(strict=True)
        require(actual == path or actual.is_relative_to(host.SDK), "unexpected tool path")
        with actual.open("rb") as f:
            require(host.fstat_trusted(os.fstat(f.fileno())) and hashlib.file_digest(f,"sha256").hexdigest() == pin,
                    "host tool or SDK differs: "+path.name)
    host.private_dir(WORK)
    key = sha256(canonical(inputs))
    dst = WORK/("build-"+key)
    dst.mkdir(mode=0o700)  # do not replace prepared/failed artifacts
    put(dst/"inputs.json", canonical(inputs))
    for n, raw in files.items():
        put(dst/n, raw)
    media = inputs["media"]
    exe = dst/"vm-owner"
    defines = [f'-DB45_DISK_SHA256="{media["disk_sha256"]}"', f'-DB113_DISK_BYTES={media["disk_bytes"]}LL',
               f'-DB113_MEDIA_SHA256="{sha256(canonical(media))}"', f'-DB50_RELEASE_SHA256="{sha256(RELEASE)}"']
    host.run(dst, [host.CC,"-arch","arm64","-isysroot",host.SDK,"--ld-path="+str(host.LD),"-mmacosx-version-min=26",
             "-fobjc-arc","-fno-modules","-Werror","-Os",*defines,"owner-runner.m","supervised-owner.m",
             "vm-stop.m","serial-recorder.m","-framework","Foundation","-framework","Virtualization","-framework",
             "Security","-o",exe], writable=True)
    host.run(dst,[host.SIGN,"--force","--sign","-","--identifier",ID,"--options","runtime","--timestamp=none",
                  "--entitlements",dst/"runner.entitlements.plist",exe],writable=True)
    exe.chmod(0o500)
    row = receipt(key, properties(exe,media), media)
    put(dst/"receipt.json",canonical(row)+b"\n")
    return row


def verified_binary(pin):
    files, inputs = snapshots()
    key = sha256(canonical(inputs))
    dst = WORK / ("build-"+key)
    require(pin.get("inputs_sha256") == key and pin.get("boot_authorized") is False and
            pin.get("directory") == dst.name and pin.get("schema") == SCHEMA, "foreign or authorized owner pin")
    identity(WORK, True)
    identity(dst, True)
    require(retained(dst/"inputs.json", 1 << 20) == canonical(inputs) and
            all(retained(dst/n, 1 << 20) == data for n,data in files.items()), "retained owner inputs differ")
    exe = dst / "vm-owner"
    expected = canonical(receipt(key, properties(exe,inputs["media"]), inputs["media"]))
    require(expected == canonical(pin) and retained(dst/"receipt.json",8192) == expected+b"\n",
            "owner differs from published pin")
    return exe


def authenticated_pin(commit, signer):
    signed_pin(commit, signer)  # authenticate the exact commit and externally assigned signer first
    spec = commit + ":" + PIN.relative_to(ROOT).as_posix()
    def git(op):
        return subprocess.run(["/usr/bin/git","--no-replace-objects","cat-file",op,spec],cwd=ROOT,timeout=15,
            check=True,env={"HOME":str(Path.home()),"PATH":"/usr/bin:/bin","LC_ALL":"C"},
            stdin=subprocess.DEVNULL,capture_output=True).stdout
    require(0 < int(git("-s")) <= 8192, "oversized signed B113 owner pin")
    return json.loads(git("blob"), object_pairs_hook=unique)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action",required=True)
    commands.add_parser("build")
    v = commands.add_parser("verify")
    v.add_argument("commit")
    v.add_argument("signer")
    args = parser.parse_args()
    if args.action == "build":
        os.umask(0o077)
        print(json.dumps(build(), sort_keys=True))
    else:
        print(verified_binary(authenticated_pin(args.commit, args.signer)))
