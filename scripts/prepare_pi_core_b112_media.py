"""Pack B111 into new ordinary ARM64 media. No mounts, target execution, signing or enrollment."""
import json
import mmap
import os
from pathlib import Path
import shutil
import struct
import subprocess

from scripts import prepare_pi_core_immutable_image as image
from scripts import prepare_pi_core_observable_guest as b44
from scripts.build_pi_core_linux import canonical, require, sha256


media, boot, firmware = b44.media, b44.boot, b44.firmware
BASE = Path.home() / "Library/Application Support/Aragorn-B111-Offline"
OUT = BASE.with_name("Aragorn-B112-Offline")
OUTCOME = "e8c292f30ed8442db237749711f6ed1e64523697eb568bcfe8e44dbfc7e5b2d3"
PAYLOAD = "ea17bce82e6044ac29fef1d1e893d347272cff2054298f26ed1c10c487360fa0"
INVENTORY = "6ee50fe7b8cb234b9e8a8439735f736b677bf5ee133d14851a91822cb588160c"
B41_INPUTS = "768aa84188abbf43d85771152a01721cafcc98a72cf3d9630ceb384ef9e03325"
B44_RECEIPT = "0ebd47b2380dcba15e60d9dfb1dd42838f613733d62ac8128a679cd1ec19e892"
OSREL = b44.OSREL.replace("immutable-b44", "immutable-b112")
CMDLINE = b44.CMDLINE
_MTOOLS = "9ee3f94fca9146b6930df4f4c116d2f69e28e7404165064a70ad380d04c07a88"
_KIT = {
    "mcopy": _MTOOLS, "mmd": _MTOOLS, "mformat": _MTOOLS,
    "stub.efi": "2484474a4f3a09330478fbc6982acdd8bdf96752d1313382e5e291c5942fa072",
    "ukify.py": "6b2a43c5859abcb455f6fa8fea3fdf709547c94394b575241d4d4e726c6dd806",
    "pefile.py": "0d0eb68f0f169182613dc64b3ab50b20855508c1c1d2faafe8fccf23edb6a345",
    "ordlookup/__init__.py": "fe7e3869702abb571846d74bc34ea4966e8f75a6603530fe3f9e03c982d736a7",
    "ordlookup/oleaut32.py": "d3199a7ea2f1ef42a93cb8b20acc752de67789671cb4248584e2b43f441e5aaf",
    "ordlookup/ws2_32.py": "0879ce2fee63d738838f61332e69a149d463c177649c78935295d7f335604810",
    "ordlookup/wsock32.py": "f029bc58669eae582a7087c630fd8be8f9f5aa2df6f7cecaa13f8f1e1199ed17",
}


def _root(out, entries, lock, env):
    pseudo = out / "composed.pseudo"
    with media.opened(image.WORK / "base.pseudo") as f:
        size = os.fstat(f.fileno()).st_size
        require(0 < size <= image.BOUND and media.stream(f, size) == lock["base_pseudo_sha256"], "foreign Ubuntu base")
        f.seek(0)
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            rows, attrs, off = image.read_pseudo(f)
            data, aliases = image.project(rows, attrs, mapped, off, BASE / "root", entries)
            require((len(rows), sum(map(len, attrs.values())), len(aliases)) == (182229, 8, 21) and
                    image.inventory(rows, attrs, mapped, off, None, data) == INVENTORY,
                    "root projection differs from independently reviewed B111 overlay")
            with pseudo.open("xb") as g:
                for name, record in rows.items():
                    g.write(b" ".join(record) + b"\n")
                    g.writelines(attrs.get(name, ()))
                g.write(image.MARKER)
                shutil.copyfileobj(f, g, 8 << 20)
                for raw in data.values():
                    g.write(raw)
    pseudo.chmod(0o400)
    root = out / "root.squashfs"
    profile = ('(version 1)(allow default)(deny network*)(deny file-write*)'
               '(allow file-write* (literal "/dev/null") (subpath ' + json.dumps(str(out)) + '))')
    # Pass the verified decoder library directory *after* Darwin's SIP-protected launcher.
    argv = ["/usr/bin/sandbox-exec", "-p", profile, "/usr/bin/env", "DYLD_LIBRARY_PATH="+env["DYLD_LIBRARY_PATH"],
            str(image.WORK/"tools/mksquashfs"), "-", str(root), "-pf", str(pseudo), "-noappend",
            "-comp", "zstd", "-Xcompression-level", "5", "-nopad", "-no-progress", "-processors", "6",
            "-mem", "512M", "-exit-on-error", "-mkfs-time", str(image.EPOCH)]
    with (out / "mksquashfs.log").open("xb") as log:
        subprocess.run(argv, cwd=out, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                       timeout=900, check=True, env={"HOME": str(out), "TMPDIR": str(out), "PATH": "/usr/bin:/bin",
                                                    "TZ": "UTC", "LC_ALL": "C"})
    root.chmod(0o400)
    with media.opened(root) as f:
        size = os.fstat(f.fileno()).st_size
        header = f.read(96)
        require(96 <= size <= 8 << 30 and header[:4] == b"hsqs" and int.from_bytes(header[40:48], "little") == size,
                "unexpected SquashFS length or padding")
        f.seek(0)
        return root, size, media.stream(f, size)


def replace_policy(predecessor, old, root_size, root_pin):
    """In the exact signed-input B44 archive, substitute only its unique 112-byte policy member."""
    require(sha256(predecessor) == old["initramfs_sha256"] and old["loader_sha256"] == boot.LOADER_SHA,
            "foreign observable initramfs")
    before = boot.policy(old["root_size"], old["root_sha256"], old["manager_sha256"])
    after = boot.policy(root_size, root_pin, old["manager_sha256"])
    require(before != after and predecessor.count(before) == 1, "ambiguous or unchanged predecessor root policy")
    return predecessor.replace(before, after, 1)


def build():
    require(not os.path.lexists(OUT), "B112 output already present; no overwrite, adoption or retry")
    require(OUT.parent.resolve(strict=True) == OUT.parent and OUT.parent.stat().st_uid == os.geteuid()
            and not OUT.parent.stat().st_mode & 0o022, "unsafe private output parent")
    read = b44.pinned
    old = json.loads(read(b44.PACK / "media-output.json", B44_RECEIPT, 16384))
    prev = b44.WORK / old["directory"]
    lock = json.loads(read(image.PINS, B41_INPUTS, 65536))
    env = image.decoder(image.WORK, lock)
    outcome = json.loads(read(BASE / "outcome.json", OUTCOME, 16384))
    payload = json.loads(read(BASE / "payload.json", PAYLOAD, 2 << 20))
    require(payload["schema"] == "aragorn/pi-core-immutable-payload/v1" and outcome["payload_sha256"] == PAYLOAD
            and outcome["activation_performed"] is outcome["installed_identity_verified"] is False, "foreign B111 inputs")
    kernel = read(prev / "vmlinuz", old["kernel_sha256"], 32 << 20)
    original = read(prev / "initramfs.cpio", old["initramfs_sha256"], 8 << 20)
    kit_bytes = {k: read(prev / "tools" / k, v, 4 << 20) for k, v in _KIT.items()}
    read(media.PY, media.PY_SHA, 1 << 20)
    require(shutil.disk_usage(OUT.parent).free >= 32 << 30, "insufficient space for media and independent readback")
    OUT.mkdir(mode=0o700)
    root, size, root_pin = _root(OUT, payload["entries"], lock, env)
    initrd = replace_policy(original, old, size, root_pin)
    media.put(OUT / "initramfs.cpio", initrd)
    media.put(OUT / "vmlinuz", kernel)
    kit = OUT / "tools"
    kit.mkdir(mode=0o700)
    (kit / "ordlookup").mkdir(mode=0o700)
    for name, raw in kit_bytes.items():
        media.put(kit / name, raw, 0o500 if _KIT[name] == _MTOOLS else 0o400)
    uki, esp, disk = (OUT / name for name in ("BOOTAA64.EFI", "esp.fat", "aragorn-arm64.raw"))
    driver = "import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); sys.argv.pop(0); runpy.run_path(sys.argv[0],run_name='__main__')"
    media.run(OUT, [media.PY, "-I", "-S", "-B", "-X", "pycache_prefix=/dev/null/pyc", "-c", driver,
                    kit, kit/"ukify.py", "build", "--config=/dev/null", "--efi-arch=aa64", "--stub", kit/"stub.efi",
                    "--linux", OUT/"vmlinuz", "--initrd", OUT/"initramfs.cpio", "--uname", media.LINUX_VERSION,
                    "--cmdline", CMDLINE, "--os-release", OSREL, "--output", uki])
    uki.chmod(0o400)
    pe = b44.regular_bytes(uki, 64 << 20)
    digest = firmware.image_hash(pe)
    esl = struct.pack("<16sIII16s32s", firmware.EFI_CERT_SHA256.bytes_le, 76, 0, 48, firmware.OWNER.bytes_le, digest)
    media.put(OUT / "b112-uki-sha256.esl", esl)  # a file, never an EFI variable
    with esp.open("xb") as stream:
        stream.truncate(media.ESP_LEN * media.SECTOR)
    media.run(OUT, [kit/"mformat", "-i", esp, "-F", "-H", str(media.ESP_START), "-N", "0xa5410112", "-v", "ARAGORN_EFI", "::"])
    media.run(OUT, [kit/"mmd", "-i", esp, "::/EFI", "::/EFI/BOOT"])
    media.run(OUT, [kit/"mcopy", "-i", esp, uki, "::/EFI/BOOT/BOOTAA64.EFI"])
    esp.chmod(0o400)
    receipt = media.emit_disk(disk, esp, root, root_pin)
    with media.opened(disk) as f:
        disk_pin = media.stream(f, receipt["disk_bytes"])
    receipt.update(schema="aragorn/pi-core-b112-successor-media/v1", root_size=size,
                   inventory_sha256=INVENTORY, inventory_entries=182229, payload_sha256=PAYLOAD,
                   b111_outcome_sha256=OUTCOME, base_boot_receipt_sha256=B44_RECEIPT,
                   cmdline=CMDLINE, osrel=OSREL, sector_size=media.SECTOR, kernel_version=media.LINUX_VERSION,
                   init_sha256=old["init_sha256"], manager_sha256=old["manager_sha256"], loader_sha256=old["loader_sha256"],
                   kernel_sha256=old["kernel_sha256"], initramfs_sha256=sha256(initrd), uki_sha256=sha256(pe),
                   uki_bytes=len(pe), authenticode_sha256=digest.hex(), esl_sha256=sha256(esl), esl_bytes=len(esl),
                   disk_sha256=disk_pin, boot_observed=False, secure_boot_enrollment=False, phase3_exit_eligible=False)
    media.put(OUT / "receipt.json", canonical(receipt) + b"\n")
    return receipt


if __name__ == "__main__":
    os.umask(0o077)
    print(json.dumps(build(), sort_keys=True))
