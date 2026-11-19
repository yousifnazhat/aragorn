"""Materialize a cross-linker sysroot. No package scripts, target programs or installation."""
from __future__ import annotations

import argparse
import concurrent.futures
import io
import json
import lzma
import os
import posixpath
import re
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path

from scripts.build_pi_core_linux import canonical, regular_bytes, require, sha256


BASE = Path(__file__).resolve().parents[1]
PINS = BASE / "packaging/pi-core/host-tools-b40"
B38 = BASE / ".aragorn/host-preflight/build-b38"
WORK = BASE / ".aragorn/host-preflight/build-b40/sysroot-work"
MAIN = "537715817d9ed77cc919f5123edb91a48d9ae97abf05588a8f18208cc7227e08"
UNIVERSE = "0a68c22478773d9681e098a3a1e650464aa707c4a557b4c3020678d92dfb53c0"
# Exact archive metadata authenticated and retained in B38. Never trust today's mirror by name.
SIGNED = "45f95ce276cdba3e41870516a130e03c58b8b7a79e9546b0efe9e526d255740c"
RELEASE = "596ee4cea058f74d59e2180532c89904e306d90725d42162eda82c01d4370834"
ZSTD = Path("/opt/homebrew/bin/zstd")
ZSTD_SHA = "aff8169fb421bb925fb16c44a7e0143fa2c7a941dc45cce76b15062a2ce54917"
ABI = "aarch64-linux-gnu"
POOL_RE = re.compile(r"pool/(?:main|universe)/[a-z0-9+.-]+/[a-z0-9+.-]+/[a-zA-Z0-9~+._%:-]+\.deb")
LIMIT = 256 << 20
# Resolute's UAPI includes eight different pairs at names that alias on this
# build volume. Neither spelling is referenced by the patched client sources.
# Exclude BOTH: any attempted use fails; never silently present the other ABI.
OMITTED_CASE_FOLDS = frozenset(
    ["usr/include/linux/netfilter/xt_" + s + ".h" for s in
     ("connmark", "dscp", "mark", "rateest", "tcpmss")]
    + ["usr/include/linux/netfilter_ipv4/ipt_ecn.h", "usr/include/linux/netfilter_ipv4/ipt_ttl.h",
       "usr/include/linux/netfilter_ipv6/ip6t_hl.h"])


def clean_name(raw: str) -> str:
    while raw.startswith("./"):
        raw = raw[2:]
    require(raw and not raw.startswith("/") and "\\" not in raw and
            not any(p in ("", ".", "..") for p in raw.rstrip("/").split("/")), "unsafe package member")
    return raw.rstrip("/")


def target_link(name: str, target: str) -> str:
    """Rebase guest-absolute links onto this private sysroot, never onto the build host."""
    require(target and "\\" not in target and not target.startswith("//"), "unsafe target link")
    parent = posixpath.dirname(name)
    guest = target[1:] if target.startswith("/") else posixpath.join(parent, target)
    guest = posixpath.normpath(guest)
    require(guest not in ("", ".", "..") and not guest.startswith(("../", "/")), "target link escapes sysroot")
    # /lib is a compile-time alias, not an assertion about the eventual protected guest.
    if guest == "lib" or guest.startswith("lib/"):
        guest = "usr/" + guest
    return posixpath.relpath(guest, parent or ".")


def selected(name: str) -> bool:
    # This is a header/link sysroot, not an OS root, apt install or installed guest inventory.
    if name.casefold() in OMITTED_CASE_FOLDS:
        return False
    if name.startswith(("usr/include/", "usr/share/pkgconfig/")):
        return True
    if name.startswith(f"usr/lib/gcc/{ABI}/15/"):
        return name.rsplit("/", 1)[-1] in {
            "crtbegin.o", "crtend.o", "crtbeginS.o", "crtendS.o", "crtbeginT.o",
            "libgcc.a", "libgcc_eh.a", "libgcc_s.so", "libatomic.so"}
    if name.startswith(f"usr/lib/{ABI}/"):
        base = name.rsplit("/", 1)[-1]
        return (base.endswith((".h", ".a", ".o", ".pc", ".so")) or ".so." in base)
    return name.startswith("usr/lib/pkgconfig/") or name == "usr/lib/ld-linux-aarch64.so.1"


def profile(work: Path = WORK) -> dict:
    lock = json.loads(regular_bytes(PINS / "sysroot-packages.json"))
    require(lock["schema"] == "aragorn.pi-core.cross-sysroot-packages/v1" and
            lock["indexes"] == {"main": MAIN, "universe": UNIVERSE}, "unknown sysroot package profile")
    require(sha256(regular_bytes(B38 / "InRelease")) == SIGNED and
            sha256(regular_bytes(B38 / "Release")) == RELEASE, "retained signed Ubuntu release mismatch")
    release = regular_bytes(B38 / "Release").decode("ascii").split("SHA256:\n", 1)[1].split("\nSHA", 1)[0]
    for component, index, digest in (("main", B38 / "Packages-arm64.xz", MAIN),
                                     ("universe", work / "Packages-universe-arm64.xz", UNIVERSE)):
        archive = regular_bytes(index, 32 << 20)
        require(sha256(archive) == digest and
                re.search(rf"^ {digest}\s+{len(archive)} {component}/binary-arm64/Packages\.xz$", release, re.M),
                "incorrect Ubuntu package index: " + component)
        expected = {k: v for k, v in lock["packages"].items() if v["component"] == component}
        seen = set()
        for paragraph in lzma.decompress(archive).decode().split("\n\n"):
            name = paragraph.partition("\n")[0].removeprefix("Package: ")
            if name not in expected:
                continue
            row = dict(line.split(": ", 1) for line in paragraph.splitlines() if
                       not line.startswith(" ") and ": " in line)
            pin = expected[name]
            require(name not in seen and pin["Architecture"] in ("arm64", "all") and
                    POOL_RE.fullmatch(pin["Filename"]) and pin["Filename"].startswith("pool/" + component + "/")
                    and all(pin[f] == row[f] for f in ("Version", "Architecture", "Filename", "Size", "SHA256")),
                    "package not bound to Ubuntu index: " + name)
            seen.add(name)
        require(seen == set(expected), "package absent from signed index")
    require(all(r["component"] in lock["indexes"] for r in lock["packages"].values()), "unknown package component")
    return lock


def fetch(work: Path = WORK) -> None:
    """Explicit developer acquisition; normal preparation and verification never use the network."""
    require(work.is_absolute() and work.resolve(strict=True) == work and
            work.stat().st_uid == os.geteuid() and not work.stat().st_mode & 0o022, "unsafe acquisition workspace")
    def download(dest, url, size, digest):
        temp = dest.with_name(dest.name + ".partial")
        require(not os.path.lexists(temp), "incomplete previous acquisition: " + str(temp))
        subprocess.run(["/usr/bin/curl", "--proto", "=https", "-fsS", "--max-filesize", str(size),
                        "--connect-timeout", "10", "--max-time", "90",
                        "https://ports.ubuntu.com/ubuntu-ports/" + url, "-o", str(temp)],
                       check=True, timeout=100)
        raw = regular_bytes(temp, size)
        require(len(raw) == size and sha256(raw) == digest, "incorrect download: " + str(dest))
        os.link(temp, dest)
        temp.unlink()

    universe = work / "Packages-universe-arm64.xz"
    if not os.path.lexists(universe):
        require(sha256(regular_bytes(B38 / "InRelease")) == SIGNED and
                sha256(regular_bytes(B38 / "Release")) == RELEASE, "retained signed Ubuntu release mismatch")
        download(universe, "dists/resolute/universe/binary-arm64/Packages.xz", 16202372, UNIVERSE)
    cache = work / "packages"
    cache.mkdir(mode=0o700, exist_ok=True)
    require(cache.resolve(strict=True) == cache and not cache.stat().st_mode & 0o022, "unsafe package cache")

    def acquire(row):
        filename = Path(row["Filename"]).name
        dest = cache / filename
        if not os.path.lexists(dest):
            download(dest, row["Filename"], int(row["Size"]), row["SHA256"])
        else:
            raw = regular_bytes(dest, int(row["Size"]))
            require(len(raw) == int(row["Size"]) and sha256(raw) == row["SHA256"], "cached package mismatch: " + filename)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(acquire, profile(work)["packages"].values()))


def data_tar(deb: bytes, zstd: Path) -> bytes:
    require(deb[:8] == b"!<arch>\n", "invalid deb magic")
    at = 8
    found = []
    while at < len(deb):
        header = deb[at:at + 60]
        require(len(header) == 60 and header[58:] == b"`\n", "malformed ar member")
        size = int(header[48:58].strip())
        require(0 <= size <= len(deb) - at - 60, "invalid ar member size")
        name = header[:16].decode("ascii").strip().rstrip("/")
        if name.startswith("data.tar."):
            found.append((name, deb[at + 60:at + 60 + size]))
        at += 60 + size + size % 2
    require(at == len(deb) and len(found) == 1, "ambiguous deb payload")
    name, raw = found[0]
    if name == "data.tar.zst":
        return subprocess.run([str(zstd), "-qdc"], input=raw, check=True, capture_output=True,
                              timeout=60).stdout
    require(name in ("data.tar.xz", "data.tar.gz"), "unsupported package compression")
    return raw  # Python tarfile transparently decodes these formats.


def inventory(root: Path) -> tuple[list, dict]:
    require(root.is_absolute() and root.resolve(strict=True) == root and root.is_dir(), "linked sysroot")
    rows = []
    counts = {"files": 0, "directories": 0, "symlinks": 0}
    def visit(path):
        st = path.lstat()
        row = {"path": path.relative_to(root).as_posix(), "mode": stat.S_IMODE(st.st_mode)}
        if stat.S_ISDIR(st.st_mode):
            counts["directories"] += 1
            row["kind"] = "directory"
            for child in path.iterdir():
                visit(child)
        elif stat.S_ISREG(st.st_mode):
            counts["files"] += 1
            data = regular_bytes(path, LIMIT)
            row.update(kind="file", bytes=len(data), sha256=sha256(data))
        elif stat.S_ISLNK(st.st_mode):
            target = os.readlink(path)
            require(not os.path.isabs(target) and path.resolve(strict=True).is_relative_to(root), "broken or escaping sysroot link")
            counts["symlinks"] += 1
            row.update(kind="symlink", target=target)
        else:
            raise ValueError("unsupported sysroot member: " + str(path))
        rows.append(row)
    visit(root)
    return sorted(rows, key=lambda r: r["path"]), counts


def verify(root: Path) -> dict:
    """Re-read the materialized tree; do not trust caller receipts or rerun extraction."""
    pin = json.loads(regular_bytes(PINS / "sysroot-tree.json"))
    rows, counts = inventory(root)
    result = dict(counts, inventory_sha256=sha256(canonical(rows)),
                  package_lock_sha256=sha256(regular_bytes(PINS / "sysroot-packages.json")))
    require(pin == result, "unexpected sysroot tree or package lock")
    return result


def prepare(work: Path = WORK) -> dict:
    lock = profile(work)
    require(work.is_absolute() and work.resolve(strict=True) == work and work.stat().st_uid == os.geteuid()
            and not work.stat().st_mode & 0o022, "unsafe build workspace")
    require((work / "packages").resolve(strict=True) == work / "packages", "linked package cache")
    final = work / "root"
    require(not os.path.lexists(final) and not os.path.lexists(work / "sysroot.json"), "refuse existing materialization")
    zstd = ZSTD.resolve(strict=True)
    require(sha256(regular_bytes(zstd, 8 << 20)) == ZSTD_SHA, "unapproved host zstd decoder")
    # No partial sysroot is published for the build; failed private trees are retained.
    root = Path(tempfile.mkdtemp(prefix="unpublished-", dir=work))
    links = {"lib": "usr/lib"}
    spelling = {}
    for package, pin in sorted(lock["packages"].items()):
        package_file = work / "packages" / Path(pin["Filename"]).name
        deb = regular_bytes(package_file, int(pin["Size"]))
        require(len(deb) == int(pin["Size"]) and sha256(deb) == pin["SHA256"], "incorrect package: " + package)
        with tarfile.open(fileobj=io.BytesIO(data_tar(deb, zstd)), mode="r:*") as archive:
            for item in archive:
                if item.name in (".", "./"):
                    continue
                source = clean_name(item.name)
                name = "usr/" + source if source.startswith("lib/") else source
                if item.isdir() or not selected(name):
                    continue
                for part in (Path(name), *Path(name).parents):
                    s = part.as_posix()
                    require(s.isascii() and spelling.setdefault(s.casefold(), s) == s,
                            "undeclared filesystem case collision: " + name)
                path = root / name
                if item.issym():
                    link = target_link(name, item.linkname)
                    require(name not in links or links[name] == link, "conflicting link: " + name)
                    links[name] = link
                    continue
                # Only archive-local hardlinks; never let package data select a host file.
                require(item.isfile() or item.islnk(), "unsupported target member: " + name)
                if item.islnk():
                    require(selected(clean_name(item.linkname)), "hardlink outside target namespace")
                stream = archive.extractfile(item)
                require(stream is not None, "missing package member")
                data = stream.read(LIMIT + 1)
                require(len(data) <= LIMIT, "oversized package member")
                path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                if os.path.lexists(path):
                    require(path.is_file() and regular_bytes(path, LIMIT) == data, "conflicting file: " + name)
                else:
                    with path.open("xb") as out:
                        out.write(data)
                    path.chmod(0o644)
    for name, target in sorted(links.items()):
        path = root / name
        # No untrusted ancestor symlinks during file writes or deferred link creation.
        require(not os.path.lexists(path) and path.parent.resolve(strict=False) == path.parent,
                "package file/link collision: " + name)
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        path.symlink_to(target)
        # Reproduce this Darwin-hosted cross-build independently of the caller's umask.
        os.lchmod(path, 0o755)
    for dirpath, _, _ in os.walk(root):
        os.chmod(dirpath, 0o700 if Path(dirpath) == root else 0o755)
    rows, counts = inventory(root)
    summary = dict(counts, inventory_sha256=sha256(canonical(rows)),
                   package_lock_sha256=sha256(regular_bytes(PINS / "sysroot-packages.json")))
    require(json.loads(regular_bytes(PINS / "sysroot-tree.json")) == summary,
            "unreviewed materialized sysroot; unpublished tree retained")
    root.rename(final)
    with (work / "sysroot.json").open("x") as out:
        json.dump(dict(summary, schema="aragorn.pi-core.cross-sysroot/v1", inventory=rows), out,
                  sort_keys=True, separators=(",", ":"))
    return summary


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("operation", choices=("fetch", "prepare", "verify"))
    op = ap.parse_args().operation
    if op == "fetch":
        fetch()
    else:
        print(json.dumps(prepare() if op == "prepare" else verify(WORK / "root"), sort_keys=True))
