"""Offline B41: pack a UKI and immutable root into an ordinary raw GPT file. No mounts."""
import argparse
from contextlib import contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tarfile
import uuid
import zlib

from scripts.build_pi_core_linux import ROOT, canonical, regular_bytes, require, sha256
from scripts.prepare_pi_core_host_sysroot import ZSTD, ZSTD_SHA, data_tar

WORK = ROOT / ".aragorn/host-preflight/build-b41"
PACK = ROOT / "packaging/pi-core/immutable-host-b41"
MEDIA_INPUTS = WORK / "media-inputs"
BOOT = WORK / "boot"
LINUX_VERSION = "7.0.0-14-generic"
CMDLINE = "rdinit=/init init=/aragorn-no-fallback root=/dev/aragorn-no-kernel-fallback ro panic=0"
OSREL = "ID=ubuntu\nVERSION_ID=26.04\nIMAGE_ID=aragorn-immutable-b41"
GPT = uuid.UUID("a5410041-e073-4bd4-8d70-e8cc1f372041")
PARTS = (
    ("EFI System", "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "a5410001-e073-4bd4-8d70-e8cc1f372041"),
    ("Aragorn immutable root", "b921b045-1df0-41c3-af44-4c6f280d3fae", "a5410002-e073-4bd4-8d70-e8cc1f372041"),
)
SECTOR = 512
ESP_START = 2048
ESP_LEN = 128 * 1024 * 1024 // SECTOR
ROOT_START = ESP_START + ESP_LEN
PY = Path("/opt/homebrew/Cellar/python@3.12/3.12.13_4/Frameworks/Python.framework/Versions/3.12/bin/python3.12")
PY_SHA = "1ce7aea77992ab97bb6225339a1d72a79925d5641e461cdfc2584916119a7edb"
MTOOL = "mtools--4.0.50.arm64_tahoe.bottle.tar.gz"
MTOOL_SHA = "9abaf0b9f5a39215bf8891e55783246cc1cbd306d9301662a933f6987284c872"
# Ubuntu Resolute GA signed universe/binary-arm64 index retained by B40.
DEBS = {
    "systemd-boot-efi_259.5-0ubuntu3_arm64.deb": ("1acff7a7240b29f52f8a6b00e7c5578a32bfbcaee15e7c357a2fe359a09cf039",
        {"./usr/lib/systemd/boot/efi/linuxaa64.efi.stub": "stub.efi"}),
    "systemd-ukify_259.5-0ubuntu3_all.deb": ("433ec6e00f448463bc7ca4129798ba59c61eb4be5cefba378514ee3d54342d35",
        {"./usr/bin/ukify": "ukify.py"}),
    "python3-pefile_2024.8.26-2.1_all.deb": ("75ec46b516dd136ec66552347ec43cb96fada2358a5fa953c146a9a362d6609e",
        {"./usr/lib/python3/dist-packages/" + s: s for s in (
            "pefile.py", "ordlookup/__init__.py", "ordlookup/oleaut32.py", "ordlookup/ws2_32.py", "ordlookup/wsock32.py")}),
}


def put(path, data, mode=0o400):
    with path.open("xb") as f:
        f.write(data)
        os.fchmod(f.fileno(), mode)


@contextmanager
def opened(path):
    require(path.is_absolute() and path.resolve(strict=True) == path, "linked or relative artifact")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as f:
        key = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        before = key(os.fstat(f.fileno()))
        require(stat.S_ISREG(before[2]) and before[3] == 1, "expected singly linked regular artifact")
        yield f
        require(key(os.fstat(f.fileno())) == before == key(path.lstat()), "artifact changed during read")


def stream(f, count, out=None):
    h = hashlib.sha256()
    while count:
        chunk = f.read(min(count, 4 << 20))
        require(bool(chunk), "short artifact")
        h.update(chunk)
        if out is not None:
            out.write(chunk)
        count -= len(chunk)
    return h.hexdigest()


def recipe_tools(dest):
    """Execute no maintainer scripts; only selected payloads from reviewed archives."""
    dest.mkdir(mode=0o700)
    zstd = ZSTD.resolve(strict=True)
    require(sha256(regular_bytes(zstd, 8 << 20)) == ZSTD_SHA, "zstd differs")
    require(sha256(regular_bytes(PY, 1 << 20)) == PY_SHA, "host Python differs")
    for name, (pin, picks) in DEBS.items():
        raw = regular_bytes(MEDIA_INPUTS / name, 1 << 20)
        require(sha256(raw) == pin, "Ubuntu package differs: " + name)
        with tarfile.open(fileobj=io.BytesIO(data_tar(raw, zstd)), mode="r:*") as ar:
            for member, local in picks.items():
                item = ar.getmember(member)
                require(item.isfile() and 0 < item.size <= 2 << 20, "unexpected Ubuntu tool member")
                path = dest / local
                path.parent.mkdir(mode=0o700, exist_ok=True)
                put(path, ar.extractfile(item).read())
    bottles = list((Path.home() / "Library/Caches/Homebrew/downloads").glob("*--" + MTOOL))
    require(len(bottles) == 1, "expected one pinned mtools distribution")
    raw = regular_bytes(bottles[0], 2 << 20)
    require(sha256(raw) == MTOOL_SHA, "mtools bottle differs")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as ar:
        item = ar.getmember("mtools/4.0.50/bin/mtools")
        require(item.isfile(), "invalid Darwin mtools member")
        raw = ar.extractfile(item).read()
        for name in ("mformat", "mmd", "mcopy"):
            put(dest / name, raw, 0o500)


def run(work, args, *, stdin=None):
    profile = ('(version 1)(allow default)(deny network*)(deny file-write*)'
               '(allow file-write* (literal "/dev/null") (subpath ' + json.dumps(str(work)) + '))')
    subprocess.run(["/usr/bin/sandbox-exec", "-p", profile, *map(str, args)], cwd=work,
                   env={"HOME": str(work), "TMPDIR": str(work), "PATH": "/usr/bin:/bin", "LC_ALL": "C",
                        "TZ": "UTC", "MTOOLSRC": "/dev/null", "SOURCE_DATE_EPOCH": "1776816000"},
                   stdin=subprocess.DEVNULL if stdin is None else stdin, check=True, timeout=180)


def header(here, other, table, crc, last_usable):
    h = bytearray(struct.pack("<8sIIIIQQQQ16sQIII", b"EFI PART", 0x10000, 92, 0, 0, here, other,
                              34, last_usable, GPT.bytes_le, table, 128, 128, crc))
    struct.pack_into("<I", h, 16, zlib.crc32(h))
    return bytes(h).ljust(SECTOR, b"\0")


def emit_disk(dest, esp, root, root_pin):
    with opened(root) as image, opened(esp) as fat, dest.open("xb") as disk:
        size = os.fstat(image.fileno()).st_size
        require(0 < size <= 32 << 30 and os.fstat(fat.fileno()).st_size == ESP_LEN * SECTOR, "invalid partition size")
        last_root = ROOT_START + (size + SECTOR - 1) // SECTOR - 1
        backup = last_root + 33
        entries = bytearray(128 * 128)
        for i, ((label, kind, uid), start, end, attr) in enumerate(zip(PARTS, (ESP_START, ROOT_START),
                (ROOT_START-1, last_root), (0, 1 << 60), strict=True)):
            struct.pack_into("<16s16sQQQ72s", entries, i*128, uuid.UUID(kind).bytes_le, uuid.UUID(uid).bytes_le,
                             start, end, attr, label.encode("utf-16-le"))
        crc = zlib.crc32(entries)
        mbr = bytearray(SECTOR)
        struct.pack_into("<B3sB3sII", mbr, 446, 0, b"\0\x02\0", 0xee, b"\xff\xff\xff", 1, min(backup, 0xffffffff))
        mbr[510:] = b"\x55\xaa"
        disk.write(mbr + header(1, backup, 2, crc, last_root) + entries)
        disk.seek(ESP_START * SECTOR)
        esp_pin = stream(fat, ESP_LEN*SECTOR, disk)
        require(stream(image, size, disk) == root_pin, "root changed or unapproved")
        disk.seek((backup-32) * SECTOR)
        disk.write(entries + header(backup, 1, backup-32, crc, last_root))
        os.fchmod(disk.fileno(), 0o400)
        disk.flush()
        os.fsync(disk.fileno())
    return {"root_size": size, "root_sha256": root_pin, "esp_sha256": esp_pin, "disk_bytes": (backup+1)*SECTOR}


def build(dest, image, root_pin, kernel_pin, initrd_pin):
    require(dest.parent == WORK and dest.parent.resolve(strict=True) == WORK and not os.path.lexists(dest),
            "fresh private output required")
    dest.mkdir(mode=0o700)
    kit = dest / "tools"
    recipe_tools(kit)
    kernel = BOOT / "vmlinuz"
    initrd = BOOT / "initramfs.cpio"
    for path, pin in ((kernel, kernel_pin), (initrd, initrd_pin)):
        require(path.resolve(strict=True) == path and sha256(regular_bytes(path, 256 << 20)) == pin,
                "boot input differs: " + path.name)
    uki = dest / "BOOTAA64.EFI"
    # Isolated Python, authenticated tools only. The non-directory prefix prevents stale .pyc reads.
    driver = "import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); sys.argv.pop(0); runpy.run_path(sys.argv[0],run_name='__main__')"
    run(dest, [PY, "-I", "-S", "-B", "-X", "pycache_prefix=/dev/null/pyc", "-c", driver, kit, kit/"ukify.py", "build",
               "--config=/dev/null", "--efi-arch=aa64", "--stub", kit/"stub.efi", "--linux", kernel, "--initrd", initrd,
               "--uname", LINUX_VERSION, "--cmdline", CMDLINE, "--os-release", OSREL, "--output", uki])
    esp = dest / "esp.fat"
    with esp.open("xb") as f:
        f.truncate(ESP_LEN * SECTOR)
    run(dest, [kit/"mformat", "-i", esp, "-F", "-H", str(ESP_START), "-N", "0xa5410041", "-v", "ARAGORN_EFI", "::"])
    run(dest, [kit/"mmd", "-i", esp, "::/EFI", "::/EFI/BOOT"])
    run(dest, [kit/"mcopy", "-i", esp, uki, "::/EFI/BOOT/BOOTAA64.EFI"])
    disk = dest / "aragorn-arm64.raw"
    require(image.name == "root.squashfs" and image.parent.parent == WORK/"image", "not an assembled root")
    receipt = emit_disk(disk, esp, image, root_pin)
    with opened(disk) as f:
        receipt.update(disk_sha256=stream(f, receipt["disk_bytes"]))
    receipt.update(kernel_sha256=kernel_pin, initramfs_sha256=initrd_pin, uki_sha256=sha256(regular_bytes(uki, 128 << 20)),
                   sector_size=SECTOR, cmdline=CMDLINE, kernel_version=LINUX_VERSION,
                   schema="aragorn/immutable-guest-disk/v1", boot_observed=False, secure_boot_enrollment=False,
                   phase3_exit_eligible=False)
    put(dest/"receipt.json", canonical(receipt) + b"\n")
    return receipt


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dest", type=Path)
    p.add_argument("image", type=Path)
    p.add_argument("root_sha256")
    p.add_argument("kernel_sha256")
    p.add_argument("initramfs_sha256")
    args = p.parse_args()
    print(json.dumps(build(args.dest, args.image, args.root_sha256, args.kernel_sha256, args.initramfs_sha256), sort_keys=True))
