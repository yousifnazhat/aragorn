"""Build/sign the held B47 owner or verify it from a signed release. Neither operation runs it."""
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
from scripts import verify_pi_core_host_binding as binding
from scripts.build_pi_core_linux import ROOT, canonical, require, sha256
from scripts.prepare_pi_core_guest_disk import opened, put


PACK = b45.PACK.parent / "immutable-host-b47"
B46 = b45.PACK.parent / "immutable-host-b46"
WORK = Path.home() / "Library/Application Support/Aragorn-B47-Offline"
PIN = PACK / "runner-output.json"
ID = "org.aragorn.pi-core.b47.host-owner"
SCHEMA = "aragorn/b47-held-vm-owner/v1"
HOLD = {"schema": "aragorn/b47-host-release/v1", "approved_attempts": []}
SOURCES = (PACK / "owner-release.json", PACK / "owner-runner.m", PACK / "vm-owner.h", PACK / "vm-owner.m",
           B46 / "vm-stop.h", B46 / "vm-stop.m", *(b45.PACK / name for name in b45.SOURCES))


def properties(path):
    with opened(path) as f:
        s = os.fstat(f.fileno())
        require(s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o500 and s.st_size <= 8 << 20,
                "unsealed owner artifact")
        raw = f.read(s.st_size)
        b45.run(path.parent, [b45.SIGN, "--verify", "--strict", "--all-architectures", path])
        desc = b45.run(path.parent, [b45.SIGN, "--display", "--verbose=4", path]).stderr.decode()
        fields = dict(line.split("=", 1) for line in desc.splitlines() if "=" in line)
        require(fields.get("Identifier") == ID and fields.get("Signature") == "adhoc"
                and fields.get("TeamIdentifier") == "not set" and re.fullmatch("[0-9a-f]{40}", fields.get("CDHash", ""))
                and "runtime" in fields["CodeDirectory v"].partition("flags=")[2].partition(")")[0],
                "unexpected owner code signature")
        ent = plistlib.loads(b45.run(path.parent, [b45.SIGN, "--display", "--entitlements", "-", "--xml", path]).stdout)
        require(set(ent) == {b45.ENTITLEMENT} and ent[b45.ENTITLEMENT] is True, "owner entitlement mismatch")
        return {"runner_sha256": sha256(raw), "runner_bytes": len(raw), "macho_uuid_hex": b45.macho_uuid(raw),
                "cdhash": fields["CDHash"], "identifier": ID, "entitlements": ent, "signing": "ad-hoc-local-integrity"}


def build():
    for p, digest in b45.TOOLS.items():
        with p.resolve(strict=True).open("rb") as f:
            require(b45.fstat_trusted(os.fstat(f.fileno())) and hashlib.file_digest(f, "sha256").hexdigest() == digest,
                    "host tool or SDK mismatch: " + str(p))
    files = {p.name: b45.source_bytes(p) for p in SOURCES}
    require(json.loads(files["owner-release.json"], object_pairs_hook=binding.unique) == HOLD, "nonempty owner release")
    # Reuse the exact B45 static custody/graph code without linking its no-boot main or modifying its pinned bytes.
    source = files["host-runner.m"]
    require(sha256(source) == "8c1f179efc8b224cda14219d7524af06543a5bd239ace523ef16eb46ef4f4084",
            "review B45 helper boundary before building a successor")
    prefix, marker, _ = source.partition(b"\nint main(")
    require(marker and prefix.count(b45.IDENTIFIER.encode()) == 1, "ambiguous native helper boundary")
    files["b45-binding.inc"] = prefix.replace(b45.IDENTIFIER.encode(), ID.encode())
    request, media = (b45.source_bytes(b45.B44 / name) for name in ("boot-request.json", "media-output.json"))
    disk = json.loads(media)["disk_sha256"]
    require(re.fullmatch("[a-f0-9]{64}", disk) and json.loads(request)["guest"]["disk_sha256"] == disk,
            "B44 request mismatch")
    inputs = {"files": {n: sha256(data) for n, data in files.items()}, "tools": {str(k): v for k,v in b45.TOOLS.items()},
              "recipe_sha256": sha256(b45.source_bytes(Path(__file__).resolve())),
              "b45_recipe_sha256": sha256(b45.source_bytes(Path(b45.__file__).resolve())),
              "request_sha256": sha256(request), "media_pins_sha256": sha256(media), "disk_sha256": disk}
    key = sha256(canonical(inputs))
    b45.private_dir(WORK)
    dst = WORK / ("build-" + key)
    dst.mkdir(mode=0o700)  # No overwriting successes or retrying a failed build.
    put(dst / "inputs.json", canonical(inputs))
    for n, data in files.items():
        put(dst / n, data)
    binary = dst / "vm-owner"
    defines = [f'-DB45_{k.upper()}="{inputs[k]}"' for k in ("request_sha256", "media_pins_sha256", "disk_sha256")]
    b45.run(dst, [b45.CC, "-arch", "arm64", "-isysroot", b45.SDK, "--ld-path=" + str(b45.LD),
                  "-mmacosx-version-min=26", "-fobjc-arc", "-fno-modules", "-Werror", "-Os", *defines,
                  "-DB47_RELEASE=" + json.dumps(canonical(HOLD).decode()), "owner-runner.m", "vm-owner.m",
                  "vm-stop.m", "serial-recorder.m", "-framework", "Foundation", "-framework", "Virtualization",
                  "-framework", "Security", "-o", binary], writable=True)
    b45.run(dst, [b45.SIGN, "--force", "--sign", "-", "--identifier", ID, "--options", "runtime",
                  "--timestamp=none", "--entitlements", dst / "runner.entitlements.plist", binary], writable=True)
    binary.chmod(0o500)
    result = {"schema": SCHEMA, "directory": dst.name, "inputs_sha256": key, **properties(binary),
              "disk_sha256": disk, "release_sha256": sha256(files["owner-release.json"]), "boot_authorized": False}
    put(dst / "receipt.json", canonical(result) + b"\n")
    return result


def authenticated_pin(commit, signer):
    # Verify this exact immutable commit using the predecessor's trust procedure, then select the new blob.
    binding.signed_pin(commit, signer)
    raw = subprocess.run(["/usr/bin/git", "--no-replace-objects", "cat-file", "blob",
                          commit + ":" + PIN.relative_to(ROOT).as_posix()], cwd=ROOT, check=True, timeout=10,
                         env={"HOME": str(Path.home()), "PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                         stdin=subprocess.DEVNULL, capture_output=True).stdout
    return json.loads(raw, object_pairs_hook=binding.unique)


def verified_binary(pin):
    require(pin["schema"] == SCHEMA and pin["boot_authorized"] is False and
            re.fullmatch("[0-9a-f]{64}", pin["inputs_sha256"]) and pin["directory"] == "build-" + pin["inputs_sha256"],
            "not the held owner release")
    dst = WORK / pin["directory"]
    binding.identity(WORK, True)
    binding.identity(dst, True)
    require(sha256(b45.source_bytes(dst / "inputs.json")) == pin["inputs_sha256"], "owner build closure changed")
    binary = dst / "vm-owner"
    props = properties(binary)
    require(canonical(props) == canonical({k:pin[k] for k in props}), "owner differs from release")
    return binary


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    cmds = ap.add_subparsers(dest="command", required=True)
    cmds.add_parser("build")
    verify = cmds.add_parser("verify")
    verify.add_argument("commit")
    verify.add_argument("signer")
    args = ap.parse_args()
    if args.command == "build":
        os.umask(0o077)
        print(json.dumps(build(), sort_keys=True))
    else:
        print(verified_binary(authenticated_pin(args.commit, args.signer)))
