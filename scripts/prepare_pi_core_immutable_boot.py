"""Build, never run, the B41 kernel/initramfs for the pinned read-only NVMe root."""
import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import stat
import struct
import subprocess
import tarfile

from scripts import prepare_pi_core_host_build_tools as tools
from scripts import prepare_pi_core_host_sysroot as sysroot
from scripts.build_pi_core_linux import ROOT, canonical, regular_bytes, require, require_static_arm64_elf, sha256
from scripts.prepare_pi_core_immutable_host_layout import LOADER_SHA, _owned_directory

PACK = ROOT / "packaging/pi-core/immutable-host-b41"
WORK = ROOT / ".aragorn/host-preflight/build-b41/boot"
LOCK = PACK / "boot-inputs.json"
SOURCE = PACK / "boot-init.c"
CMDLINE = "rdinit=/init init=/aragorn-no-fallback root=/dev/aragorn-no-kernel-fallback ro panic=0"


def put(path, raw, mode=0o400):
    with path.open("xb") as out:
        out.write(raw)
        os.fchmod(out.fileno(), mode)


def indexed():
    lock = json.loads(regular_bytes(LOCK))
    idx = regular_bytes(sysroot.B38 / "Packages-arm64.xz")
    require(sha256(idx) == sysroot.MAIN, "not the B38 signed package index")
    fields = set()
    for para in lzma.decompress(idx).decode().split("\n\n"):
        row = dict(line.split(": ", 1) for line in para.splitlines() if ": " in line and not line.startswith(" "))
        if row.get("Architecture") == "arm64" and row.get("Version") == lock["version"] and "SHA256" in row:
            fields.add((row["Filename"], int(row["Size"]), row["SHA256"]))
    require(all(tuple(row) in fields for row in lock["packages"].values()), "kernel package outside signed index")
    return lock


def decompress(raw):
    exe = sysroot.ZSTD.resolve(strict=True)
    require(sha256(regular_bytes(exe, 8 << 20)) == sysroot.ZSTD_SHA, "unapproved Zstandard decoder")
    return subprocess.run([str(exe), "-qdc"], input=raw, check=True, capture_output=True, timeout=60).stdout


def extract(deb, row, wanted):
    """Skip all package scripts. Avoid buffering the 285 MB kernel-modules package."""
    require(deb.resolve(strict=True) == deb and stat.S_ISREG(deb.lstat().st_mode), "invalid archive")
    with deb.open("rb") as f:
        before = os.fstat(f.fileno())
        require(before.st_size == row[1] and hashlib.file_digest(f, "sha256").hexdigest() == row[2],
                "package bytes differ from signed index")
        f.seek(0)
        require(f.read(8) == b"!<arch>\n", "bad deb container")
        selected = {}
        found = False
        while h := f.read(60):
            require(len(h) == 60 and h[58:] == b"`\n", "bad deb header")
            length = int(h[48:58].strip())
            start = f.tell()
            require(0 <= length <= before.st_size - start, "out-of-range deb member")
            kind = h[:16].strip().rstrip(b"/")
            if kind.startswith(b"data.tar"):
                require(not found and kind in (b"data.tar", b"data.tar.zst"), "unexpected package encoding")
                found = True
                data = f if kind == b"data.tar" else io.BytesIO(decompress(f.read(length)))
                with tarfile.open(fileobj=data, mode="r|") as ar:
                    for entry in ar:
                        if entry.name in wanted:
                            require(entry.isfile() and 0 < entry.size <= 40 << 20 and entry.name not in selected,
                                    "unexpected kernel archive file")
                            selected[entry.name] = ar.extractfile(entry).read()
            f.seek(start + length + length % 2)
        after = os.fstat(f.fileno())
        require(set(selected) == set(wanted) and before.st_ctime_ns == after.st_ctime_ns,
                "missing or changing kernel inputs")
        return selected


def kernel_pe(raw):
    p = struct.unpack_from("<I", raw, 60)[0]
    opt = p + 24
    require(raw[:2] == b"MZ" and raw[p:p+6] == b"PE\0\0\x64\xaa" and
            struct.unpack_from("<H", raw, opt)[0] == 0x20b and struct.unpack_from("<H", raw, opt+68)[0] == 10,
            "not an ARM64 EFI application")
    off, size = struct.unpack_from("<II", raw, opt+112+32)
    require(size >= 8 and off + size == len(raw) and off % 8 == 0, "invalid EFI certificate table")
    cert, revision, typ = struct.unpack_from("<IHH", raw, off)
    require((cert+7)&~7 == size and (revision, typ) == (0x200, 2), "unexpected EFI certificate metadata")


def stage():
    _owned_directory(WORK)
    _owned_directory(WORK / "inputs")
    lock = indexed()
    t = tools.verify_existing()
    s = sysroot.verify(sysroot.WORK / "root")
    identity = {"source": sha256(regular_bytes(SOURCE)), "release_lock": sha256(regular_bytes(LOCK)),
                "tool_manifest": t["manifest_sha256"], "tool_tree": t["sealed_sha256"],
                "sysroot_tree": s["inventory_sha256"], "recipe": sha256(regular_bytes(Path(__file__).resolve()))}
    dst = WORK / ("build-" + sha256(canonical(identity)))
    dst.mkdir(mode=0o700, exist_ok=False)
    put(dst / "inputs.json", canonical(identity))
    rel = lock["release"]
    kp = "./boot/vmlinuz-" + rel
    kernel = extract(WORK / "inputs/kernel.deb", lock["packages"]["kernel"], [kp])[kp]
    require(sha256(kernel) == lock["kernel_sha256"], "kernel payload changed")
    kernel_pe(kernel)
    put(dst / "vmlinuz", kernel)
    prefix = "./usr/lib/modules/" + rel + "/kernel/"
    cfg = "./boot/config-" + rel
    rows = lock["modules"]
    entries = extract(WORK / "inputs/modules.deb", lock["packages"]["modules"],
                      [cfg] + [prefix + path + ".ko.zst" for path, _, _ in rows])
    config = entries[cfg]
    require(sha256(config) == lock["config_sha256"], "kernel config differs")
    for option in ("BLK_DEV_INITRD=y", "EFI_PARTITION=y", "DEVTMPFS=y", "PROC_FS=y", "MODULES=y",
                   "ACPI=y", "PCI_HOST_GENERIC=y", "BLK_DEV_NVME=m", "NVME_CORE=m", "SQUASHFS=y",
                   "SQUASHFS_ZSTD=y", "BINFMT_ELF=y", "MODULE_SIG=y"):
        require(("CONFIG_" + option).encode() in config.splitlines(), "unsupported kernel: " + option)
    module_dir = dst / "modules"
    module_dir.mkdir(mode=0o700)
    available = set()
    for path, deps, digest in rows:
        raw = decompress(entries[prefix + path + ".ko.zst"])
        n = Path(path).name
        require(sha256(raw) == digest and raw[:6] == b"\x7fELF\x02\x01" and raw[16:20] == b"\x01\0\xb7\0" and
                raw.endswith(b"~Module signature appended~\n") and b"\0vermagic=" + rel.encode() + b" " in raw and
                b"\0depends=" + deps.encode() + b"\0" in raw and (not deps or set(deps.split(",")) <= available),
                "unsigned, wrong-ABI or out-of-order module: " + n)
        put(module_dir / (n + ".ko"), raw)
        available.add(n)
    sr = sysroot.WORK / "root"
    cc, ld = (Path(t["tools"][name]["path"]) for name in ("clang", "ld.lld"))
    argv = [str(cc), "--target=aarch64-linux-gnu", f"--sysroot={sr}", f"--gcc-toolchain={sr}/usr",
            f"--ld-path={ld}", "-static", "-Os", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3",
            "-Wall", "-Wextra", "-Werror", "-Wl,--build-id=none,-z,noexecstack,-s", str(SOURCE), "-lnettle",
            "-o", str(dst/"init")]
    sandbox = "(version 1)(allow default)(deny network*)(deny file-write*)(allow file-write* (subpath " + \
              json.dumps(str(dst)) + ') (literal "/dev/null"))'
    put(dst/"compile.argv.json", canonical(argv))
    with (dst/"compile.log").open("xb") as log:
        subprocess.run(["/usr/bin/sandbox-exec", "-p", sandbox, *argv], cwd=dst,
                       env={"PATH": "/usr/bin:/bin", "TMPDIR": str(dst), "LC_ALL": "C"},
                       stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60)
    init = regular_bytes(dst/"init", 4 << 20)
    require_static_arm64_elf(init)
    ph = struct.unpack_from("<Q", init, 32)[0]
    width, count = struct.unpack_from("<HH", init, 54)
    require(init[16:18] == b"\x02\0" and all(struct.unpack_from("<I", init, ph+i*width)[0] != 2
                                              for i in range(count)), "dynamic early init")
    put(dst/"stage.json", canonical({"init_sha256": sha256(init), "kernel_sha256": sha256(kernel)}))
    return dst


def cpio(entries):
    out = bytearray()
    for inode, (name, mode, data) in enumerate([*entries, ("TRAILER!!!", 0, b"")], 1):
        raw = name.encode("ascii") + b"\0"
        major, minor = (5, 1) if name == "dev/console" else (0, 0)
        values = (inode, mode, 0, 0, 1, 0, len(data), 0, 0, major, minor, len(raw), 0)
        out.extend(b"070701" + "".join("%08x" % x for x in values).encode() + raw)
        out.extend(bytes(-len(out) % 4))
        out.extend(data)
        out.extend(bytes(-len(out) % 4))
    out.extend(bytes(-len(out) % 512))
    return bytes(out)


def policy(root_bytes, root_sha, manager_sha):
    require(type(root_bytes) is int and 4096 <= root_bytes <= 8 << 30, "unexpected root length")
    raw = [bytes.fromhex(x) for x in (root_sha, manager_sha, LOADER_SHA)]
    require(all(len(x) == 32 for x in raw), "bad boot digest")
    return struct.pack("<8sQ32s32s32s", b"ARGBOOT1", root_bytes, *raw)


def finish(dst, image, root_sha, init_sha):
    _owned_directory(dst)
    require(dst.parent == WORK and dst.name.startswith("build-") and image.resolve(strict=True) == image,
            "unexpected build or image location")
    lock = indexed()
    with image.open("rb") as f:
        info = os.fstat(f.fileno())
        require(stat.S_ISREG(info.st_mode) and 4096 <= info.st_size <= 8 << 30 and
                f.read(4) == b"hsqs", "not a bounded raw SquashFS root")
        f.seek(0)
        require(hashlib.file_digest(f, "sha256").hexdigest() == root_sha and
                info.st_ctime_ns == os.fstat(f.fileno()).st_ctime_ns, "root image not the pinned bytes")
    init = regular_bytes(dst/"init", 4 << 20)
    kernel = regular_bytes(dst/"vmlinuz", 32 << 20)
    require(sha256(init) == init_sha and sha256(kernel) == lock["kernel_sha256"], "boot build drift")
    entries = [(n, stat.S_IFDIR | 0o755, b"") for n in ("dev","proc","newroot","modules")]
    entries += [("dev/console", stat.S_IFCHR | 0o600, b""), ("init", stat.S_IFREG | 0o555, init),
                ("policy", stat.S_IFREG | 0o400, policy(info.st_size, root_sha, lock["manager_sha256"]))]
    for path, _, sha in lock["modules"]:
        name = "modules/" + Path(path).name + ".ko"
        raw = regular_bytes(dst/name, 8 << 20)
        require(sha256(raw) == sha, "changed staged module")
        entries.append((name, stat.S_IFREG | 0o400, raw))
    archive = cpio(entries)
    require(all(not os.path.lexists(WORK/n) for n in ("vmlinuz", "initramfs.cpio", "receipt.json")),
            "existing boot bundle; do not overwrite")
    put(WORK/"vmlinuz", kernel)
    put(WORK/"initramfs.cpio", archive)
    receipt = {"kernel_sha256": sha256(kernel), "initramfs_sha256": sha256(archive), "init_sha256": init_sha,
               "manager_sha256": lock["manager_sha256"], "root_sha256": root_sha, "root_bytes": info.st_size,
               "loader_sha256": LOADER_SHA, "cmdline": CMDLINE, "build": dst.name, "booted": False}
    put(WORK/"receipt.json", canonical(receipt))
    return receipt


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="op", required=True)
    sub.add_parser("stage")
    f = sub.add_parser("finish")
    for name in ("build_dir", "root_image", "root_sha256", "init_sha256"):
        f.add_argument(name)
    arg = ap.parse_args()
    os.umask(0o077)
    if arg.op == "stage":
        print(stage())
    else:
        print(json.dumps(finish(Path(arg.build_dir), Path(arg.root_image), arg.root_sha256, arg.init_sha256)))
