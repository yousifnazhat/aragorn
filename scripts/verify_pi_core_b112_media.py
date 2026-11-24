"""Inspect the sealed B112 disk as data; never mount it, enroll firmware or run the guest."""
import hashlib
import json
import mmap
import os
from pathlib import Path
import resource
import shutil
import stat
import struct
import subprocess
from tempfile import TemporaryDirectory

from scripts import inspect_pi_core_guest_disk as gpt
from scripts import prepare_pi_core_guest_disk as b41
from scripts import prepare_pi_core_guest_firmware_trust as efi
from scripts import prepare_pi_core_immutable_image as image
from scripts.build_pi_core_linux import regular_bytes, require, sha256


OUT = Path.home() / "Library/Application Support/Aragorn-B112-Offline"
CATALOG = b41.PACK.parent / "immutable-host-b112/media-output.json"
B44 = b41.PACK.parent / "immutable-host-b44/media-output.json"
B44_PIN = "0ebd47b2380dcba15e60d9dfb1dd42838f613733d62ac8128a679cd1ec19e892"
B41_INPUT_PIN = "768aa84188abbf43d85771152a01721cafcc98a72cf3d9630ceb384ef9e03325"
B111_PAYLOAD = "ea17bce82e6044ac29fef1d1e893d347272cff2054298f26ed1c10c487360fa0"
B111_OUTCOME = "e8c292f30ed8442db237749711f6ed1e64523697eb568bcfe8e44dbfc7e5b2d3"
# Independent projection of the signed B41 logical inventory overlaid by the signed B111 rows.
# This value is fixed before compression. It is not taken from producer output or readback.
LOGICAL = "6ee50fe7b8cb234b9e8a8439735f736b677bf5ee133d14851a91822cb588160c"
ROWS, XATTRS = 182229, 8
CMDLINE = b41.CMDLINE + " console=hvc0"
OSREL = b41.OSREL.replace("immutable-b41", "immutable-b112")


def _json(path, pin):
    raw = regular_bytes(path, 65536)
    require(sha256(raw) == pin, "foreign verifier input")
    return json.loads(raw)


def _receipt(raw):
    def distinct(pairs):
        obj = dict(pairs)
        require(len(obj) == len(pairs), 'ambiguous media receipt')
        return obj
    return json.loads(raw, object_pairs_hook=distinct)


def _logical(digest, count, attrs):
    require((digest, count, attrs) == (LOGICAL, ROWS, XATTRS),
            f"whole B111-over-B41 root differs: {digest}, {count} paths, {attrs} attributes")


def _profile(p, prior):
    fields = set('schema root_size root_sha256 esp_sha256 disk_bytes inventory_sha256 inventory_entries '
                 'payload_sha256 b111_outcome_sha256 base_boot_receipt_sha256 cmdline osrel sector_size '
                 'kernel_version init_sha256 manager_sha256 loader_sha256 kernel_sha256 initramfs_sha256 '
                 'uki_sha256 uki_bytes authenticode_sha256 esl_sha256 esl_bytes disk_sha256 boot_observed '
                 'secure_boot_enrollment phase3_exit_eligible'.split())
    require(type(p) is dict and p.keys() == fields and p['schema'] == 'aragorn/pi-core-b112-successor-media/v1'
            and p['base_boot_receipt_sha256'] == B44_PIN and p['kernel_version'] == prior['kernel_version']
            and all(type(p[k]) is int and p[k] > 0 for k in (
                'root_size', 'disk_bytes', 'inventory_entries', 'sector_size', 'uki_bytes', 'esl_bytes'))
            and all(p[k] is False for k in ("boot_observed", "secure_boot_enrollment", "phase3_exit_eligible"))
            and (p["payload_sha256"], p["b111_outcome_sha256"]) == (B111_PAYLOAD, B111_OUTCOME)
            and (p["cmdline"], p["osrel"], p["sector_size"]) == (CMDLINE, OSREL, 512)
            and (p["inventory_sha256"], p["inventory_entries"]) == (LOGICAL, ROWS),
            "wrong successor candidate, inventory or authorization scope")
    for key in ("kernel_sha256", "init_sha256", "loader_sha256", "manager_sha256"):
        require(p[key] == prior[key], "changed retained boot input: " + key)
    for key in ("root_sha256", "initramfs_sha256", "uki_sha256", "esp_sha256", "disk_sha256",
                "authenticode_sha256", "esl_sha256"):
        require(p[key] != prior[key], "old medium or trust proposal reused: " + key)


def _policy(p):
    return struct.pack("<8sQ32s32s32s", b"ARGBOOT1", p["root_size"], *(
        bytes.fromhex(p[k]) for k in ("root_sha256", "manager_sha256", "loader_sha256")))


def _cpio(previous, actual, old_policy, new_policy):
    # The exact predecessor archive was authenticated and its single /policy member
    # already verified at B44. No parsing of a producer-supplied member list or
    # extraction of guest paths/devices is necessary for this fixed-length change.
    require(len(old_policy) == len(new_policy) == 112 and old_policy != new_policy and
            previous.count(old_policy) == 1 and previous.replace(old_policy, new_policy, 1) == actual,
            "root policy is not the only change to the authenticated B44 initramfs")


def _boot(esp, start, p, prior):
    require(sha256(esp) == p["esp_sha256"], "wrong ESP")
    pe = gpt.fat_uki(memoryview(esp), start)
    require(len(pe) == p["uki_bytes"] and sha256(pe) == p["uki_sha256"], "wrong removable EFI file")
    s = gpt.sections(pe)
    require(sha256(s[b".linux"]) == prior["kernel_sha256"] and sha256(s[b".initrd"]) == p["initramfs_sha256"]
            and s[b".cmdline"] == CMDLINE.encode() and s[b".osrel"] == OSREL.encode()
            and s[b".uname"] == b41.LINUX_VERSION.encode() and b".profile" not in s, "wrong embedded boot policy")
    archive = b41.WORK.parent / "build-b44" / prior["directory"] / "initramfs.cpio"
    with b41.opened(archive) as f:
        original = f.read((8 << 20) + 1)
        require(len(original) <= 8 << 20 and sha256(original) == prior["initramfs_sha256"], "wrong B44 initramfs")
    _cpio(original, s[b".initrd"], _policy(prior), _policy(p))
    auth = efi.image_hash(pe)
    proposal = struct.pack("<16sIII16s32s", efi.EFI_CERT_SHA256.bytes_le, 76, 0, 48, efi.OWNER.bytes_le, auth)
    require(p["authenticode_sha256"] == auth.hex() and p["esl_bytes"] == 76 and
            sha256(proposal) == p["esl_sha256"] and
            regular_bytes(OUT / "b112-uki-sha256.esl", 76) == proposal, "wrong detached B112 trust proposal")


def _disk(f, p, prior):
    size = os.fstat(f.fileno()).st_size
    require(size == p["disk_bytes"] and (129 << 20) < size <= 9 << 30 and size % 512 == 0,
            "wrong B112 disk extent")
    whole = hashlib.sha256()
    def take(n):
        data = f.read(n)
        require(len(data) == n, "truncated disk")
        whole.update(data)
        return data

    last = size // 512 - 1
    mbr, header, table = take(512), take(512), take(32 * 512)
    require(mbr == bytes(446) + struct.pack("<B3sB3sII", 0, b"\0\x02\0", 0xee,
            b"\xff\xff\xff", 1, last) + bytes(48) + b"\x55\xaa", "wrong protective MBR")
    parts = gpt.gpt(header, table, 1, last, 2)
    (es, ee), (rs, re) = parts
    require(es == b41.ESP_START and ee + 1 == rs == b41.ROOT_START and not any(take((es-34)*512)),
            "wrong or concealed pre-partition geometry")
    _boot(take((ee-es+1)*512), es, p, prior)
    remaining = p["root_size"]
    require(96 < remaining <= (re-rs+1)*512 < remaining+512, "root size differs from GPT")
    sb = take(96)
    require(sb[:4] == b"hsqs" and int.from_bytes(sb[40:48], "little") == remaining, "wrong SquashFS extent")
    root = hashlib.sha256(sb)
    remaining -= len(sb)
    while remaining:
        chunk = take(min(4 << 20, remaining))
        root.update(chunk)
        remaining -= len(chunk)
    require(root.hexdigest() == p["root_sha256"] and not any(take(-p["root_size"] % 512)),
            "embedded root bytes or slack differ")
    mirror, backup = take(32 * 512), take(512)
    require(mirror == table and gpt.gpt(backup, mirror, last, 1, last-32) == parts
            and f.read(1) == b"" and whole.hexdigest() == p["disk_sha256"], "disk digest or backup GPT differs")
    return rs * 512


def _decode(fd, offset):
    env = image.decoder(image.WORK, _json(image.PINS, B41_INPUT_PIN))
    tool = image.WORK / "tools/unsquashfs"
    with TemporaryDirectory(prefix="aragorn-b112-read-") as scratch:
        tmp = Path(scratch).resolve(strict=True)
        require(shutil.disk_usage(tmp).free > image.BOUND, "insufficient scratch space for bounded decoder")
        out = tmp / "decoded.pseudo"
        policy = ('(version 1)(allow default)(deny network*)(deny file-write*)'
                  '(allow file-write* (literal "/dev/null") (subpath ' + json.dumps(str(tmp)) + '))')
        def bound_output():
            _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
            resource.setrlimit(resource.RLIMIT_FSIZE, (image.BOUND if hard == resource.RLIM_INFINITY else
                                                       min(image.BOUND, hard), hard))
        # Darwin's system launcher strips DYLD_* from its incoming environment. Pass the
        # authenticated dylib directory after that boundary and inherit the very FD already hashed.
        proc = subprocess.run(["/usr/bin/sandbox-exec", "-p", policy, "/usr/bin/env",
            "DYLD_LIBRARY_PATH=" + env['DYLD_LIBRARY_PATH'], str(tool), "-offset", str(offset),
            "-pf", str(out), "-strict-errors", "-no-progress", "-processors", "6", f"/dev/fd/{fd}"], cwd=tmp,
            env={"PATH": "/usr/bin:/bin", "HOME": str(tmp), "TMPDIR": str(tmp), "LC_ALL": "C", "TZ": "UTC"},
            pass_fds=(fd,), preexec_fn=bound_output, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, timeout=900)
        require(proc.returncode == 0, "root decoder refused: " + proc.stderr[:512].decode("ascii", "replace"))
        with b41.opened(out) as f:
            require(0 < os.fstat(f.fileno()).st_size <= image.BOUND, "pseudo-file exceeds readback limit")
            rows, attrs, off = image.read_pseudo(f)
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as raw:
                _logical(image.inventory(rows, attrs, raw, off, None), len(rows), sum(map(len, attrs.values())))


def verify():
    """One serialized final-medium readback. Temporary ordinary data only; no VM calls."""
    prior = _json(B44, B44_PIN)
    p = _receipt(regular_bytes(CATALOG, 65536))
    require(json.dumps(p, sort_keys=True) == json.dumps(_receipt(regular_bytes(OUT / "receipt.json", 65536)),
                                                       sort_keys=True), "private build differs from nominated media")
    _profile(p, prior)
    path = OUT / "aragorn-arm64.raw"
    with b41.opened(path) as f:
        info = os.fstat(f.fileno())
        require(stat.S_IMODE(info.st_mode) == 0o400 and info.st_uid == os.getuid(), "unsealed disk file")
        offset = _disk(f, p, prior)
        _decode(f.fileno(), offset)  # exactly one full decompression of the *on-disk* partition
    return dict(schema="aragorn/b112-offline-media-finding/v1", disk_sha256=p["disk_sha256"],
                root_sha256=p["root_sha256"], inventory_sha256=LOGICAL, inventory_entries=ROWS,
                payload_sha256=B111_PAYLOAD, boot_observed=False, secure_boot_enrollment=False, phase3_exit_eligible=False)


if __name__ == "__main__":
    print(json.dumps(verify(), sort_keys=True))
