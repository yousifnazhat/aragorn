"""Inspect the three staged Ubuntu clients, without executing or loading a target ELF."""
import json
import os
from pathlib import Path
import stat
import struct

from scripts import check_pi_core_host_abi as abi
from scripts.build_pi_core_linux import canonical, regular_bytes, sha256
from scripts.prepare_pi_core_immutable_host_layout import LIBC_SHA, LOADER_SHA
from scripts.prepare_pi_core_os_root import elf_dependencies, require

CLIENTS = ("busctl", "systemctl", "systemd-run")
LOADER = "ld-linux-aarch64.so.1"
INTERP = "/lib/" + LOADER
# On the approved guest /lib will be a read-only bind of /usr/lib.
LIBDIRS = ("usr/lib/aarch64-linux-gnu", "usr/lib")
# src/basic/build.c advertisement in Ubuntu's signed-index libsystemd-shared
# 259.5-0ubuntu3 arm64 (deb SHA256 754ac748...203a2bdc). Not behavior proof.
FEATURES = (
    b"+PAM +AUDIT +SELINUX +APPARMOR +IMA +IPE +SMACK +SECCOMP +GCRYPT -GNUTLS +OPENSSL +ACL"
    b" +BLKID +CURL +ELFUTILS +FIDO2 +IDN2 -IDN +KMOD +LIBCRYPTSETUP +LIBCRYPTSETUP_PLUGINS"
    b" +LIBFDISK +PCRE2 +PWQUALITY +P11KIT +QRENCODE +TPM2 +BZIP2 +LZ4 +XZ +ZLIB +ZSTD"
    b" +BPF_FRAMEWORK +BTF -XKBCOMMON -UTMP +SYSVINIT +LIBARCHIVE"
)


def _vendor_features(raw):
    # elf_dependencies first validates the ELF64 program table and file ranges.
    off, = struct.unpack_from("<Q", raw, 32)
    size, count = struct.unpack_from("<HH", raw, 54)
    literal = b"\x00" + FEATURES + b"\x00"
    for i in range(count):
        kind, flags, start, _, _, length = struct.unpack_from("<IIQQQQ", raw, off + size * i)
        if kind == 1 and flags & 4 and not flags & 2 and raw.find(literal, start, start + length) >= 0:
            return True
    return False


def _library(root, name, approved_files=None):
    """Cross-sysroot absolute links must have been normalized, never followed on the host."""
    matches = {}
    for directory in LIBDIRS:
        path = root / directory / name
        if not os.path.lexists(path):
            continue
        resolved = path.resolve(strict=True)
        require(resolved.is_relative_to(root) and resolved.is_file(), "library outside pinned sysroot")
        raw = regular_bytes(resolved, 128 << 20)
        digest = sha256(raw)
        if approved_files is not None:
            require(approved_files.get(resolved.relative_to(root).as_posix()) == digest,
                    "sysroot library differs from authenticated inventory")
        matches[digest] = raw
    require(len(matches) == 1, "missing or ambiguous library: " + name)
    digest, raw = next(iter(matches.items()))
    expected = {LOADER: LOADER_SHA, "libc.so.6": LIBC_SHA}.get(name, digest)
    require(digest == expected, "immutable guest library differs: " + name)
    return raw


def _clients(stage):
    expected = {"usr", "usr/bin", *("usr/bin/" + n for n in CLIENTS)}
    require(stage.is_dir() and stage.resolve(strict=True) == stage, "stage root is linked or absent")
    found = {p.relative_to(stage).as_posix(): p for p in stage.rglob("*")}
    require(found.keys() == expected, "stage does not contain exactly the three installed clients")
    for directory in ("usr", "usr/bin"):
        require(stat.S_ISDIR(found[directory].lstat().st_mode), "invalid staged client directory")
    files = {}
    for n in CLIENTS:
        path = found["usr/bin/" + n]
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) in (0o555, 0o755), "invalid staged client mode or link")
        raw = regular_bytes(path, 128 << 20)
        require(raw[16:18] == b"\x03\x00", "client is not an ELF PIE candidate")
        files["/usr/bin/" + n] = raw
    require(len({sha256(raw) for raw in files.values()}) == len(CLIENTS), "duplicate client bytes")
    return files


def _inspect(stage: Path, sysroot: Path, expected_clients: dict, approved_files: dict) -> dict:
    """Authenticate the consumed buffers before handing them to a host ELF reader."""
    require(sysroot.is_dir() and sysroot.resolve(strict=True) == sysroot, "invalid sysroot")
    files = _clients(stage)
    require({Path(p).name: sha256(raw) for p, raw in files.items()} == expected_clients,
            "installed client bytes differ from reviewed build")
    queue = list(files)
    reports, records = {}, {}
    abi._tools()
    for name in queue:
        raw = files[name]
        elf = elf_dependencies(raw)
        client = name.startswith("/usr/bin/")
        require(elf["interpreter"] in (None, INTERP), "unreviewed ELF interpreter")
        if client:
            require(elf["interpreter"] == INTERP and elf["needed"] and elf["soname"] is None,
                    "unexpected client interpreter or dynamic contract")
            require(_vendor_features(raw), "Ubuntu client feature advertisement differs")
        else:
            require(elf["soname"] == name, "library SONAME differs: " + name)
        for dep in [*elf["needed"], *([LOADER] if elf["interpreter"] else [])]:
            require(not dep.startswith("libsystemd-shared"), "private systemd shared library")
            if dep not in files:
                require(len(queue) < 128, "client dependency bound")
                files[dep] = _library(sysroot, dep, approved_files)
                queue.append(dep)
        reports[name] = abi._readelf(raw)
        records[name] = {"sha256": sha256(raw), **elf}
    edges = []
    for name, report in sorted(reports.items()):
        if "No version information found in this file." in report.splitlines():
            require(not any(s in report for s in ("Version symbols section '", "Version needs section '",
                                                  "Version definition section '")), "ambiguous ELF version report")
            continue
        _, imports, _, refs, _ = abi._parse(report)
        for dep in sorted({lib for lib, _ in imports.values()}):
            require(dep in records[name]["needed"] and dep in refs, "unsupported symbol version edge")
            edges.append({"requester": name, **abi._edge(report, reports[dep], dep)})
    abi._tools()
    return {"scope": "STAGED_CLIENTS_STATIC_ELF_AND_VERSIONED_IMPORTS_ONLY", "files": records,
            "versioned_edges": edges, "target_executed": False, "phase3_exit_eligible": False}


def verify_attempt(attempt: Path, expected: dict) -> dict:
    """Use reviewed build-output pins, not the build's success flag, as the trust anchor."""
    from scripts import build_pi_core_host_clients as build
    from scripts import prepare_pi_core_host_sysroot as sysroot

    build.private_directory(attempt)
    require(attempt.parent == build.WORK and set(expected) == {"fingerprint", "clients"}
            and set(expected["clients"]) == set(CLIENTS) and attempt.name == expected["fingerprint"],
            "unreviewed build attempt or client set")
    inputs = regular_bytes(attempt / "inputs.json", 1 << 20)
    require(sha256(inputs) == attempt.name, "build inputs changed")
    closure = json.loads(inputs)
    tree = sysroot.verify(build.SYSROOT)
    require(closure["sysroot_tree"] == tree["inventory_sha256"]
            and closure["sysroot_packages"] == tree["package_lock_sha256"], "different build sysroot")
    rows = json.loads(regular_bytes(build.SYSROOT.parent / "sysroot.json", 2 << 20))["inventory"]
    require(sha256(canonical(rows)) == tree["inventory_sha256"], "unsigned library inventory")
    approved = {r["path"]: r["sha256"] for r in rows if r["kind"] == "file"}
    report = _inspect(attempt / "stage", build.SYSROOT, expected["clients"], approved)
    return {**report, "build_fingerprint": attempt.name, "sysroot_tree": tree["inventory_sha256"]}
