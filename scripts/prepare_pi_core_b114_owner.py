"""Build an already reviewed B112 singleton privately. No grant creation, launch or retry command."""
import argparse
import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
import time

from scripts import pi_core_b114_release as seal
from scripts import prepare_pi_core_b113_owner as old
from scripts.build_pi_core_linux import BuildError, canonical, require, sha256
from scripts.prepare_pi_core_guest_disk import opened, put
from scripts.verify_pi_core_host_binding import identity, retained

host = old.host
WORK = old.WORK.with_name("Aragorn-B114-Offline")
# Merely a fixed local interface. This script never creates the nomination directory or file.
PRIVATE_RELEASE = WORK.with_name("Aragorn-B114-Private") / "release.json"
SCHEMA = "aragorn/b113-single-use-owner/v1"  # issued terminal/serial contract prepared at B113
ID = "org.aragorn.pi-core.b114.single-use-owner"
BASE_CATALOG = "bedfbfb5f8a71dd74c55ce00e5dd1e2a6f09db1a0c00e9b362cae5a552b8dbd0"


def _template(signed_sources):
    """Take the compiler inputs once. No subsequent source may be read from the checkout for assembly."""
    prior_raw = signed_sources[old.PIN]
    require(sha256(prior_raw) == BASE_CATALOG, "foreign held owner catalog")
    prior = json.loads(prior_raw)
    files, spec = old.snapshots()  # frozen B113 rendering, NOT a build or a read of the old executable
    require(sha256(canonical(spec)) == prior["inputs_sha256"] and
            spec["files"] == {n: sha256(v) for n, v in files.items()} and
            spec["tools"] == {str(p): h for p, h in host.TOOLS.items()} and
            canonical(spec["media"]) == canonical({k: prior[k] for k in spec["media"]}),
            "generated source/tool/media snapshot differs from signed B113 build")
    return files, spec["media"]


def _render(files, private_bytes):
    """Only the embedded release bytes and runtime code-signing identifier differ from B113."""
    native_id = old.once(files["b45-binding.inc"], old.ID.encode(), ID.encode())
    header = old.once(files["b50-embedded-release.h"], old.arrays("B50ReleaseBytes", old.RELEASE),
                      old.arrays("B50ReleaseBytes", private_bytes))
    return files | {"b45-binding.inc": native_id, "b50-embedded-release.h": header}


def _materials(release, seal_sha, commit, sources):
    require(re.fullmatch("[0-9a-f]{40}", commit) and set(sources) == set(seal.REVIEWED_SOURCES)
            and sha256(sources[seal.SEAL]) == seal_sha, "wrong reviewed build context")
    private = canonical(release)
    checked = seal.match_private(seal.approved_digest(sources[seal.SEAL]), private)
    require(canonical(checked) == private and len(checked["approved_attempts"]) == 1, "not one sealed release")
    files, media = _template(sources)
    files = _render(files, private)
    spec = dict(schema="aragorn/b114-reviewed-build-inputs/v1", identifier=ID, media=media,
                release_sha256=sha256(private), build_seal_sha256=seal_sha, approval_commit=commit,
                held_owner_catalog_sha256=BASE_CATALOG, files={n: sha256(v) for n, v in files.items()},
                sources={p.relative_to(old.ROOT).as_posix(): sha256(v) for p, v in sources.items()},
                tools={str(p): h for p, h in host.TOOLS.items()})
    return files, spec, private


def _tools(paths):
    for path in paths:
        actual = path.resolve(strict=True)
        require(actual == path or actual.is_relative_to(host.SDK), "unexpected host tool or SDK path")
        with actual.open("rb") as f:
            require(host.fstat_trusted(os.fstat(f.fileno())) and
                    hashlib.file_digest(f, "sha256").hexdigest() == host.TOOLS[path], "changed host tool or SDK")


def _issued_dir(release_sha):
    require(type(release_sha) is str and re.fullmatch("[0-9a-f]{64}", release_sha), "invalid release pin")
    return WORK / ("issue-" + release_sha)


def _claim_name(uid):
    require(type(uid) is str and re.fullmatch("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", uid),
            "invalid reservation identifier")
    return "attempt-" + sha256(b"aragorn/b114/build-reservation/v1\0" + uid.encode("ascii"))


def _reserve(uid, release_sha):
    dst = _issued_dir(release_sha)
    host.private_dir(WORK)
    ident = identity(WORK, True)
    fd = os.open(WORK, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY)
    try:
        st = os.fstat(fd)
        require((st.st_dev, st.st_ino) == (ident["dev"], ident["ino"]), "changed private custody root")
        # Flush the root itself before the first claim, including on a freshly provisioned filesystem.
        pfd = os.open(WORK.parent, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY)
        try:
            os.fsync(pfd)
        finally:
            os.close(pfd)
        # A differently signed/worded grant cannot reuse this attempt UUID on the same custody root.
        os.mkdir(_claim_name(uid), mode=0o700, dir_fd=fd)
        os.fsync(fd)
        os.mkdir(dst.name, mode=0o700, dir_fd=fd)
        os.fsync(fd)
        require(identity(WORK, True) == ident, "changed custody root; retain reservation")
        identity(dst, True)
    finally:
        os.close(fd)
    return dst


def _compile(dst, spec):
    m = spec["media"]
    defines = [f'-DB45_DISK_SHA256="{m["disk_sha256"]}"', f'-DB113_DISK_BYTES={m["disk_bytes"]}LL',
               f'-DB113_MEDIA_SHA256="{sha256(canonical(m))}"', f'-DB50_RELEASE_SHA256="{spec["release_sha256"]}"']
    exe = dst / "vm-owner"
    try:
        host.run(dst, [host.CC, "-arch", "arm64", "-isysroot", host.SDK, "--ld-path="+str(host.LD),
            "-mmacosx-version-min=26", "-fobjc-arc", "-fno-modules", "-Werror", "-Os", *defines,
            "owner-runner.m", "supervised-owner.m", "vm-stop.m", "serial-recorder.m", "-framework", "Foundation",
            "-framework", "Virtualization", "-framework", "Security", "-o", exe], writable=True)
        host.run(dst, [host.SIGN, "--force", "--sign", "-", "--identifier", ID, "--options", "runtime",
            "--timestamp=none", "--entitlements", dst/"runner.entitlements.plist", exe], writable=True)
    except (BuildError, OSError, subprocess.SubprocessError):
        # Normal nonzero exits leave B45's bounded failed-command.json in private custody.
        # Timeout/I/O can prevent that record; never retry the retained reservation or echo private source.
        raise BuildError("B114 private toolchain failed; retain all files and reservation, do not retry") from None
    exe.chmod(0o500)
    return exe


def _properties(exe, media, private):
    with opened(exe) as f:
        st = os.fstat(f.fileno())
        require(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o500 and 32 < st.st_size <= 8 << 20,
                "unexpected issued binary")
        raw = f.read(st.st_size)
        require(raw.count(canonical(media)) == raw.count(private) == 1 and old.RELEASE not in raw
                and sha256(raw) != "a209e62302def49a64e2f47bbc309c4f19a7a4a90bb259ee8063a8a70dac714b",
                "held or substituted compiled candidate")
        host.run(exe.parent, [host.SIGN, "--verify", "--strict", "--all-architectures", exe])
        desc = host.run(exe.parent, [host.SIGN, "--display", "--verbose=4", exe]).stderr.decode()
        fields = dict(line.split("=", 1) for line in desc.splitlines() if "=" in line)
        ent = plistlib.loads(host.run(exe.parent, [host.SIGN, "--display", "--entitlements", "-", "--xml", exe]).stdout)
        require(fields.get("Identifier") == ID and fields.get("Signature") == "adhoc" and
                fields.get("TeamIdentifier") == "not set" and re.fullmatch("[a-f0-9]{40}", fields.get("CDHash", "")) and
                "runtime" in fields.get("CodeDirectory v", "").partition("flags=")[2].partition(")")[0] and
                ent.keys() == {host.ENTITLEMENT} and ent[host.ENTITLEMENT] is True, "wrong issued runner signature")
        return dict(runner_sha256=sha256(raw), runner_bytes=len(raw), identifier=ID, cdhash=fields["CDHash"],
                    macho_uuid_hex=host.macho_uuid(raw), signing="ad-hoc-local-integrity", entitlements=ent)


def _pin(spec, props):
    return dict(schema=SCHEMA, directory=_issued_dir(spec["release_sha256"]).name, inputs_sha256=sha256(canonical(spec)),
                boot_authorized=True, **{k: spec[k] for k in ("release_sha256", "approval_commit", "build_seal_sha256")},
                **spec["media"], **props)


def build(commit, signer, private_path):
    # Do not move any tool, output-root or private-release operation ahead of the authenticated seal.
    release, seal_sha, sources = seal.authorized_material(commit, signer, private_path)
    files, spec, private = _materials(release, seal_sha, commit, sources)
    entry = release["approved_attempts"][0]
    _tools(host.TOOLS)
    require(time.time() < entry["expires_utc"], "already expired; no private build")
    dst = _reserve(entry["attempt_uuid"], spec["release_sha256"])
    put(dst/"inputs.json", canonical(spec))
    for n, data in files.items():
        put(dst/n, data)
    exe = _compile(dst, spec)
    pin = _pin(spec, _properties(exe, spec["media"], private))
    require(time.time() < entry["expires_utc"], "expired during build; hold partial result and do not retry")
    put(dst/"receipt.json", canonical(pin) + b"\n")
    return pin  # only public digests, not the slot or private host/path identities


def verify_artifact(pin, release, seal_sha, approval_commit, signed_sources):
    """Read only. Caller must independently authenticate the catalog and its approved signed ancestor first."""
    files, spec, private = _materials(release, seal_sha, approval_commit, signed_sources)
    dst = _issued_dir(spec["release_sha256"])
    require(type(pin) is dict and pin.get("directory") == dst.name and pin.get("inputs_sha256") == sha256(canonical(spec))
            and pin.get("schema") == SCHEMA and pin.get("boot_authorized") is True, "foreign B114 issue catalog")
    identity(WORK, True)
    identity(WORK / _claim_name(release["approved_attempts"][0]["attempt_uuid"]), True)
    identity(dst, True)
    require(retained(dst/"inputs.json", 1 << 20) == canonical(spec) and
            all(retained(dst/n, 1 << 20) == raw for n, raw in files.items()), "incomplete or substituted compiler inputs")
    _tools([host.SIGN])
    exe = dst / "vm-owner"
    expected = canonical(_pin(spec, _properties(exe, spec["media"], private)))
    require(expected == canonical(pin) and retained(dst/"receipt.json", 8192) == expected + b"\n",
            "issued artifact or receipt differs from signed catalog")
    return exe


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("approval_commit", help="independently nominated, full signed prebuild commit")
    ap.add_argument("signer", help="independently trusted SSH signer fingerprint")
    args = ap.parse_args()
    import sys
    try:
        os.umask(0o077)
        # Never put the private release, host tuple or private path on the command line.
        print(json.dumps(build(args.approval_commit, args.signer, PRIVATE_RELEASE), sort_keys=True))
    except (BuildError, OSError, ValueError, subprocess.SubprocessError, KeyError):
        sys.exit("B114 build refused; retain any private reservation/material. No automatic retry.")
