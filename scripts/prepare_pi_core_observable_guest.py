"""Build B44 into a fresh private directory. No device access, target execution or enrollment."""
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tarfile

from scripts import inspect_pi_core_guest_disk as reader
from scripts import prepare_pi_core_guest_disk as media
from scripts import prepare_pi_core_guest_firmware_trust as firmware
from scripts import prepare_pi_core_immutable_boot as boot
from scripts.build_pi_core_linux import ROOT, canonical, regular_bytes, require, require_static_arm64_elf, sha256


PACK = media.PACK.parent / "immutable-host-b44"
WORK = media.WORK.parent / "build-b44"
CMDLINE = media.CMDLINE + " console=hvc0"
OSREL = media.OSREL.replace("immutable-b41", "immutable-b44")
BSDTAR = Path("/usr/bin/bsdtar")
BSDTAR_SHA = "f96200d5be4a3f99cdbc88892a2e26f14d501d354c72b224472462cc67fa271d"
OPTIONS = ("HVC_DRIVER", "VIRTIO_CONSOLE", "VIRTIO_PCI", "PCI_HOST_GENERIC", "DEVTMPFS", "PROC_FS", "SYSFS")


def pinned(path, digest, limit):
    with media.opened(path) as stream:
        size = os.fstat(stream.fileno()).st_size
        require(0 < size <= limit, "input length: " + path.name)
        raw = stream.read(size)
        require(len(raw) == size and sha256(raw) == digest, "input pin: " + path.name)
        return raw


def successor_cpio(original, old, new):
    """Use the authenticated B41 newc verbatim as input; only substitute the static /init."""
    require(sha256(original) == old["initramfs_sha256"], "expected B41 initramfs")
    require(sha256(regular_bytes(BSDTAR, 2 << 20)) == BSDTAR_SHA, "unexpected archive reader")
    # libarchive performs a format translation only: no installation, extraction or device creation.
    converted = subprocess.run([str(BSDTAR), "-cf", "-", "--format=ustar", "@-"], input=original,
                               capture_output=True, check=True, timeout=15, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    require(not converted.stderr, "archive reader warning")
    entries = []
    with tarfile.open(fileobj=io.BytesIO(converted.stdout), mode="r:") as tar:
        for item in tar:
            if item.isdir():
                mode, payload = stat.S_IFDIR, b""
            elif item.ischr() and (item.name, item.devmajor, item.devminor) == ("dev/console", 5, 1):
                mode, payload = stat.S_IFCHR, b""
            else:
                require(item.isfile(), "unexpected predecessor member")
                mode, payload = stat.S_IFREG, tar.extractfile(item).read()
            entries.append((item.name, mode | item.mode, payload))
    # B41's own writer must round-trip every archive byte before changing a member.
    require(boot.cpio(entries) == original, "unsupported predecessor archive metadata")
    selected = [i for i, (name, _, data) in enumerate(entries) if name == "init" and sha256(data) == old["init_sha256"]]
    require(len(selected) == 1, "expected pinned predecessor init")
    i, = selected
    entries[i] = ("init", entries[i][1], new)
    return boot.cpio(entries)


def compile_guard(dst, tool, source):
    sr = boot.sysroot.WORK / "root"
    cc, ld = (tool["tools"][name]["path"] for name in ("clang", "ld.lld"))
    media.put(dst / "boot-init.c", source)
    argv = [cc, "--target=aarch64-linux-gnu", f"--sysroot={sr}", f"--gcc-toolchain={sr}/usr",
            f"--ld-path={ld}", "-static", "-Os", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3",
            "-Wall", "-Wextra", "-Werror", "-Wl,--build-id=none,-z,noexecstack,-s",
            str(dst / "boot-init.c"), "-lnettle", "-o", str(dst / "init")]
    media.put(dst / "compile.argv.json", canonical(argv))
    profile = ('(version 1)(allow default)(deny network*)(deny file-write*)'
               '(allow file-write* (literal "/dev/null") (subpath ' + json.dumps(str(dst)) + '))')
    with (dst / "compile.log").open("xb") as log:
        subprocess.run(["/usr/bin/sandbox-exec", "-p", profile, *argv], cwd=dst, stdin=subprocess.DEVNULL,
                       stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60,
                       env={"HOME": str(dst), "TMPDIR": str(dst), "PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    raw = regular_bytes(dst / "init", 4 << 20)
    require_static_arm64_elf(raw)
    ph = struct.unpack_from("<Q", raw, 32)[0]
    size, count = struct.unpack_from("<HH", raw, 54)
    require(raw[16:18] == b"\x02\0" and all(struct.unpack_from("<I", raw, ph + n*size)[0] != 2
                                            for n in range(count)), "dynamic observer init")
    return raw


def build():
    source = regular_bytes(PACK / "boot-init.c", 128 << 10)
    pins41 = ("boot-artifacts.json", "boot-inputs.json", "media-output.json", "image-output.json")
    files = [*(media.PACK / p for p in pins41), boot.SOURCE, firmware.PIN, Path(__file__).resolve(),
             *(Path(mod.__file__).resolve() for mod in (boot, media, reader, firmware))]
    old, lock, previous, image = (json.loads(regular_bytes(media.PACK / p)) for p in pins41)
    require(previous["root_sha256"] == old["root_sha256"] == image["root_sha256"] and
            previous["root_size"] == old["root_bytes"] == image["root_bytes"] and
            previous["kernel_sha256"] == old["kernel_sha256"] == lock["kernel_sha256"] and
            previous["initramfs_sha256"] == old["initramfs_sha256"], "predecessors do not join")
    tool = boot.tools.verify_existing()
    sysroot = boot.sysroot.verify(boot.sysroot.WORK / "root")
    inputs = {"source_sha256": sha256(source), "cmdline": CMDLINE, "tool_tree": tool["sealed_sha256"],
              "tool_manifest": tool["manifest_sha256"], "sysroot_tree": sysroot["inventory_sha256"],
              "predecessors_and_recipes": {p.relative_to(ROOT).as_posix(): sha256(regular_bytes(p)) for p in files}}
    identity = sha256(canonical(inputs))
    firmware.private_dir(WORK)
    dst = WORK / ("build-" + identity)
    dst.mkdir(mode=0o700, exist_ok=False)  # preserve both successful and incomplete attempts
    media.put(dst / "inputs.json", canonical(inputs))
    cfg = "./boot/config-" + lock["release"]
    config = boot.extract(boot.WORK/"inputs/modules.deb", lock["packages"]["modules"], [cfg])[cfg]
    require(sha256(config) == lock["config_sha256"] and
            all(("CONFIG_" + k + "=y").encode() in config.splitlines() for k in OPTIONS),
            "kernel does not supply the built-in observation path")
    media.put(dst / "kernel.config", config)
    init = compile_guard(dst, tool, source)
    initrd = successor_cpio(pinned(boot.WORK / "initramfs.cpio", old["initramfs_sha256"], 8 << 20), old, init)
    media.put(dst / "initramfs.cpio", initrd)
    kernel = pinned(boot.WORK / "vmlinuz", old["kernel_sha256"], 32 << 20)
    media.put(dst / "vmlinuz", kernel)
    kit = dst / "tools"
    media.recipe_tools(kit)
    uki, esp, disk = (dst / n for n in ("BOOTAA64.EFI", "esp.fat", "aragorn-arm64.raw"))
    driver = "import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); sys.argv.pop(0); runpy.run_path(sys.argv[0],run_name='__main__')"
    media.run(dst, [media.PY, "-I", "-S", "-B", "-X", "pycache_prefix=/dev/null/pyc", "-c", driver,
                    kit, kit / "ukify.py", "build", "--config=/dev/null", "--efi-arch=aa64", "--stub", kit/"stub.efi",
                    "--linux", dst/"vmlinuz", "--initrd", dst/"initramfs.cpio", "--uname", media.LINUX_VERSION,
                    "--cmdline", CMDLINE, "--os-release", OSREL, "--output", uki])
    pe = regular_bytes(uki, 128 << 20)
    digest = firmware.image_hash(pe)
    esl = struct.pack("<16sIII16s32s", firmware.EFI_CERT_SHA256.bytes_le, 76, 0, 48, firmware.OWNER.bytes_le, digest)
    media.put(dst / "b44-uki-sha256.esl", esl)
    with esp.open("xb") as f:
        f.truncate(media.ESP_LEN * media.SECTOR)
    media.run(dst, [kit/"mformat", "-i", esp, "-F", "-H", str(media.ESP_START), "-N", "0xa5440044",
                    "-v", "ARAGORN_EFI", "::"])
    media.run(dst, [kit/"mmd", "-i", esp, "::/EFI", "::/EFI/BOOT"])
    media.run(dst, [kit/"mcopy", "-i", esp, uki, "::/EFI/BOOT/BOOTAA64.EFI"])
    root = media.WORK / "image" / image["fingerprint"] / "root.squashfs"
    receipt = media.emit_disk(disk, esp, root, old["root_sha256"])
    require(receipt["root_size"] == old["root_bytes"], "root size differs")
    with media.opened(disk) as f:
        disk_hash = media.stream(f, receipt["disk_bytes"])
    for path in (dst / "init", esp, uki):
        path.chmod(0o400)
    receipt.update(schema="aragorn/observable-guest-disk/v1", directory=dst.name, cmdline=CMDLINE, osrel=OSREL,
                   sector_size=media.SECTOR, kernel_version=media.LINUX_VERSION, kernel_config_sha256=sha256(config),
                   source_sha256=sha256(source), init_sha256=sha256(init), initramfs_sha256=sha256(initrd),
                   kernel_sha256=sha256(kernel), disk_sha256=disk_hash, uki_sha256=sha256(pe), uki_bytes=len(pe),
                   authenticode_sha256=digest.hex(), esl_sha256=sha256(esl), esl_bytes=len(esl),
                   manager_sha256=old["manager_sha256"], loader_sha256=old["loader_sha256"], boot_observed=False,
                   secure_boot_enrollment=False, phase3_exit_eligible=False)
    media.put(dst / "receipt.json", canonical(receipt) + b"\n")
    return receipt


if __name__ == "__main__":
    os.umask(0o077)
    print(json.dumps(build(), sort_keys=True))
