"""Build the default held B50 owner, or a successor from an exact previously signed seal. Never start it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess

from scripts import prepare_pi_core_bound_host_runner as b45
from scripts import prepare_pi_core_vm_owner as b47
from scripts import pi_core_single_use_release as contract
from scripts import pi_core_boot_build_seal as seal
from scripts.build_pi_core_linux import ROOT, canonical, require, sha256
from scripts.prepare_pi_core_guest_disk import opened, put
from scripts import verify_pi_core_host_binding as binding


PACK = b47.PACK.parent / "immutable-host-b50"
PIN = PACK / "runner-output.json"
WORK = Path.home() / "Library/Application Support/Aragorn-B50-Offline"
SCHEMA = "aragorn/b50-single-use-owner/v1"
ID = "org.aragorn.pi-core.b50.host-owner"
SOURCES = (PACK/"owner-release.json", PACK/"owner-runner.m", PACK/"single-use.h",
           b47.PACK/"vm-owner.m", b47.PACK/"vm-owner.h", b47.B46/"vm-stop.m", b47.B46/"vm-stop.h",
           *(b45.PACK/n for n in b45.SOURCES))


def snapshots(reviewed=None):
    raw = {p:b45.source_bytes(p) for p in seal.REVIEWED_SOURCES}
    files = {p.name:raw[p] for p in SOURCES}
    hold = contract.parse_release(files["owner-release.json"])
    require(hold["approved_attempts"] == [], "tracked B50 default must stay held")
    source_digests = {p:sha256(data) for p,data in raw.items()}
    seal_file_sha = sha256(raw[PACK/"build-seal.json"])
    if reviewed is None:
        require(json.loads(raw[seal.SEAL], object_pairs_hook=binding.unique) == seal.HELD,
                "default build requires the unapproved seal")
        release, seal_sha, approval_commit = hold, seal_file_sha, None
    else:
        approval_commit, signer, private_path = reviewed
        release, seal_sha = seal.reviewed_release(approval_commit,signer,private_path,source_digests)
        require(len(release["approved_attempts"]) == 1 and seal_sha == seal_file_sha,
                "reviewed build must bind the same signed seal and one private grant")
    # The manifest can contain private host and fixture facts. Never put it in argv, Git, or diagnostic output.
    octets = ",".join(map(str,canonical(release)))
    files["b50-embedded-release.h"] = ("static const unsigned char B50ReleaseBytes[]={"+octets+"};\n").encode()
    prefix, marker, _ = files["host-runner.m"].partition(b"\nint main(")
    require(sha256(files["host-runner.m"]) == "8c1f179efc8b224cda14219d7524af06543a5bd239ace523ef16eb46ef4f4084" and
            marker and prefix.count(b45.IDENTIFIER.encode()) == 1, "review B45 static helpers")
    files["b45-binding.inc"] = prefix.replace(b45.IDENTIFIER.encode(), ID.encode())
    owner = files["vm-owner.m"]
    guard = b"|| !machine.canStart) return;\n        issued=YES;"
    require(sha256(owner) == "6fb3fedb6a685680b0318921f46ed3e6551af0903a43f7013931b1559a17ed2a" and
            owner.count(guard) == 1 and owner.count(b"[machine startWithCompletionHandler:") == 1,
            "review the sole B47 issue gate")
    files["supervised-owner.m"] = (b'#import <Foundation/Foundation.h>\nextern BOOL B50PreStart(void);\n' +
                                   owner.replace(guard, guard.replace(b"!machine.canStart)", b"!machine.canStart || !B50PreStart())")))
    req, media = (raw[b45.B44/n] for n in ("boot-request.json","media-output.json"))
    require(json.loads(req)["guest"]["disk_sha256"] == json.loads(media)["disk_sha256"] == contract.DISK_SHA256,
            "B44 disk mismatch")
    ingredients = {"files":{k:sha256(v) for k,v in files.items()}, "tools":{str(k):v for k,v in b45.TOOLS.items()},
                   "source_digests":{p.relative_to(ROOT).as_posix():h for p,h in source_digests.items()},
                   "approval_commit":approval_commit,"build_seal_sha256":seal_sha,
                   "request_sha256":sha256(req),"media_pins_sha256":sha256(media),"disk_sha256":contract.DISK_SHA256,
                   "release_sha256":contract.release_digest(release)}
    return release, files, ingredients


def properties(path):
    with opened(path) as f:
        s = os.fstat(f.fileno())
        require(s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o500 and 32 <= s.st_size <= 8 << 20,
                "unsealed owner artifact")
        raw = f.read(s.st_size)
        b45.run(path.parent,[b45.SIGN,"--verify","--strict","--all-architectures",path])
        desc = b45.run(path.parent,[b45.SIGN,"--display","--verbose=4",path]).stderr.decode()
        fields = dict(line.split("=",1) for line in desc.splitlines() if "=" in line)
        ent = plistlib.loads(b45.run(path.parent,[b45.SIGN,"--display","--entitlements","-","--xml",path]).stdout)
        require(fields.get("Identifier") == ID and fields.get("Signature") == "adhoc" and
                fields.get("TeamIdentifier") == "not set" and re.fullmatch("[a-f0-9]{40}",fields.get("CDHash","")) and
                "runtime" in fields.get("CodeDirectory v","").partition("flags=")[2].partition(")")[0] and
                set(ent) == {b45.ENTITLEMENT} and ent[b45.ENTITLEMENT] is True, "wrong owner signature")
        return {"runner_sha256":sha256(raw),"runner_bytes":len(raw),"macho_uuid_hex":b45.macho_uuid(raw),
                "cdhash":fields["CDHash"],"identifier":ID,"entitlements":ent,"signing":"ad-hoc-local-integrity"}


def build(reviewed=None):
    release, files, inputs = snapshots(reviewed)
    for p, expected in b45.TOOLS.items():
        actual = p.resolve(strict=True)
        require(actual == p or actual.is_relative_to(b45.SDK), "tool outside pinned SDK")
        with actual.open("rb") as f:
            require(b45.fstat_trusted(os.fstat(f.fileno())) and hashlib.file_digest(f,"sha256").hexdigest() == expected,
                    "host tool or SDK mismatch: " + str(p))
    b45.private_dir(WORK)
    key = sha256(canonical(inputs))
    dst = WORK / ("build-"+key)
    dst.mkdir(mode=0o700)   # never overwrite a failed or previously retained build
    put(dst/"inputs.json",canonical(inputs))
    for name, raw in files.items():
        put(dst/name,raw)
    exe = dst/"vm-owner"
    defines = [f'-DB45_{k.upper()}="{inputs[k]}"' for k in ("request_sha256","media_pins_sha256","disk_sha256")]
    b45.run(dst,[b45.CC,"-arch","arm64","-isysroot",b45.SDK,"--ld-path="+str(b45.LD),"-mmacosx-version-min=26",
                 "-fobjc-arc","-fno-modules","-Werror","-Os",*defines,
                 '-DB50_RELEASE_SHA256="'+inputs["release_sha256"]+'"',
                 "owner-runner.m","supervised-owner.m","vm-stop.m","serial-recorder.m","-framework","Foundation",
                 "-framework","Virtualization","-framework","Security","-o",exe],writable=True)
    b45.run(dst,[b45.SIGN,"--force","--sign","-","--identifier",ID,"--options","runtime","--timestamp=none",
                 "--entitlements",dst/"runner.entitlements.plist",exe],writable=True)
    exe.chmod(0o500)
    result = dict(schema=SCHEMA,directory=dst.name,inputs_sha256=key,boot_authorized=bool(release["approved_attempts"]),
                  **properties(exe), **{k:inputs[k] for k in ("release_sha256","disk_sha256","build_seal_sha256","approval_commit")})
    put(dst/"receipt.json",canonical(result)+b"\n")
    return result


def authenticated_pin(commit, signer):
    binding.signed_pin(commit, signer)
    raw = subprocess.run(["/usr/bin/git","--no-replace-objects","cat-file","blob",commit+":"+PIN.relative_to(ROOT).as_posix()],
                         cwd=ROOT,check=True,timeout=10,env={"HOME":str(Path.home()),"PATH":"/usr/bin:/bin","LC_ALL":"C"},
                         stdin=subprocess.DEVNULL,capture_output=True).stdout
    return json.loads(raw,object_pairs_hook=binding.unique)


def verified_binary(pin):
    require(pin["schema"] == SCHEMA and pin["boot_authorized"] is False and
            re.fullmatch("[a-f0-9]{64}",pin["inputs_sha256"]) and pin["directory"]=="build-"+pin["inputs_sha256"] and
            pin["disk_sha256"]==contract.DISK_SHA256 and
            pin["release_sha256"]==contract.release_digest({"schema":contract.SCHEMA,"approved_attempts":[]}),
            "not the held single-use owner")
    dst = WORK / pin["directory"]
    binding.identity(WORK,True)
    binding.identity(dst,True)
    inputs = b45.source_bytes(dst/"inputs.json")
    closure = json.loads(inputs)
    require(sha256(inputs)==pin["inputs_sha256"] and
            all(closure[k]==pin[k] for k in ("release_sha256","build_seal_sha256","approval_commit")) and
            pin["approval_commit"] is None and re.fullmatch("[a-f0-9]{64}",pin["build_seal_sha256"]),
            "retained build identity mismatch")
    exe=dst/"vm-owner"
    props=properties(exe)
    require(canonical(props)==canonical({k:pin[k] for k in props}),"runner differs from signed pin")
    return exe


if __name__=="__main__":
    ap=argparse.ArgumentParser(description=__doc__)
    cmds=ap.add_subparsers(dest="command",required=True)
    cmds.add_parser("build")
    reviewed=cmds.add_parser("build-reviewed",help="build only from a signed, matching private approval; never execute")
    reviewed.add_argument("commit")
    reviewed.add_argument("signer")
    reviewed.add_argument("private_release",type=Path)
    v=cmds.add_parser("verify")
    v.add_argument("commit")
    v.add_argument("signer")
    args=ap.parse_args()
    if args.command in ("build","build-reviewed"):
        os.umask(0o077)
        review=(args.commit,args.signer,args.private_release) if args.command=="build-reviewed" else None
        print(json.dumps(build(review),sort_keys=True))
    else:
        print(verified_binary(authenticated_pin(args.commit,args.signer)))
