"""Repack the authenticated Ubuntu ARM64 filesystem entirely offline, as data.

Never extract guest paths onto Darwin. SquashFS pseudo files preserve Linux
ownership, links, devices and xattrs without root, mounts or target execution.
"""
import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import subprocess

from scripts.build_pi_core_linux import canonical, regular_bytes, require, sha256
from scripts.prepare_pi_core_host_build_tools import digest


ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / ".aragorn/host-preflight/build-b41/image"
PINS = ROOT / "packaging/pi-core/immutable-host-b41/image-inputs.json"
EPOCH = 1776907354
BOUND = 12 << 30
MARKER = b"#\n# START OF DATA - DO NOT MODIFY\n#\n"
# The first field uses backslash escapes; later fields (e.g. symlink data)
# must be kept verbatim rather than subjected to shell tokenization.
ENTRY = re.compile(rb"((?:\\.|[^\\ \t\n])+)[ \t]+([a-zA-Z])[ \t]+(.*)\n")


def locked(path, expected):
    require(path.resolve(strict=True) == path and path.is_file() and
            path.stat().st_size <= BOUND and digest(path) == expected, "image input differs: " + str(path))


def decoder(work, lock):
    tools = work / "tools"
    for name, value in lock["tools"].items():
        locked(tools / name, value)
    require({p.name for p in (tools / "lib").iterdir()} ==
            {k[4:] for k in lock["tools"] if k.startswith("lib/")}, "unexpected decoder library")
    return {"DYLD_LIBRARY_PATH": str(tools / "lib"), "PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"}


def unescape(token):
    return os.fsdecode(re.sub(rb"\\(.)", rb"\1", token))


def read_pseudo(f):
    rows, attrs = {}, {}
    for index in range(220000):
        line = f.readline(32768)
        if line == b"#\n":
            require(line + f.readline(128) + f.readline(16) == MARKER, "invalid data boundary")
            require(attrs.keys() <= rows.keys(), "orphan extended attribute")
            return rows, attrs, f.tell()
        m = ENTRY.fullmatch(line)
        require(m is not None, "unsupported pseudo entry")
        token, kind, meta = m.groups()
        name = unescape(token)
        require(name == "/" or (not name.startswith("/") and
                all(n not in ("", ".", "..") for n in name.split("/"))), "unsafe pseudo path")
        if kind == b"x":
            attrs.setdefault(name, []).append(line)
        else:
            require(kind in (b"D", b"S", b"R", b"C", b"L") and name not in rows,
                    "unexpected or duplicate pseudo entry")
            rows[name] = (token, kind, meta)
    raise ValueError("excessive or incomplete pseudo inventory")


def raw_extent(meta, offset, limit):
    time, mode, uid, gid, size, start, sparse = meta.split()
    size, start = int(size), offset + int(start)
    require(size >= 0 and offset <= start <= start + size <= limit, "invalid data extent")
    return start, size


def inventory(rows, attrs, mapped, offset, out, replacements=None):
    h = hashlib.sha256()
    for name in sorted(rows):
        token, kind, meta = rows[name]
        if kind == b"L":
            fields = {"target": unescape(meta)}
            require(fields["target"] in rows and rows[fields["target"]][1] != b"L", "missing hardlink origin")
        else:
            mt, md, uid, gid, *rest = meta.split(b" ", 4)
            fields = {"mtime": int(mt), "mode": int(md, 8), "uid": int(uid), "gid": int(gid)}
            if kind == b"R":
                if replacements is not None and name in replacements:
                    raw = replacements[name]
                else:
                    start, size = raw_extent(meta, offset, len(mapped))
                    raw = memoryview(mapped)[start:start + size]
                fields.update(size=len(raw), sha256=sha256(raw), sparse=int(rest[0].split()[-1]))
            elif rest:
                fields["target" if kind == b"S" else "device"] = os.fsdecode(rest[0])
        row = canonical({"path": "/" + name.lstrip("/"), "type": kind.decode(), **fields,
                         "xattrs": [os.fsdecode(v.split(b" x ", 1)[1].rstrip(b"\n")) for v in attrs.get(name, [])]}) + b"\n"
        h.update(row)
        if out is not None:
            out.write(row)
    return h.hexdigest()


def project(rows, attrs, mapped, offset, root, entries):
    incoming, data, aliases = {}, {}, {}
    for e in entries:
        p = e["path"]
        require(re.fullmatch(r"(?:/[a-zA-Z0-9_@.+-]+)+", p) and
                all(n not in (".", "..") for n in p.split("/")) and
                p[1:] not in incoming, "unsafe or duplicate payload path")
        name = p[1:]
        require(not attrs.get(name) and e["type"] in ("file", "dir") and
                e["uid"] == e["gid"] == 0 and type(e["mode"]) is int and
                0 <= e["mode"] <= 0o755 and not e["mode"] & 0o022, "unsupported payload metadata")
        incoming[name] = e
        if e["type"] == "file":
            path = root / name
            require(path.resolve(strict=True) == path, "linked payload")
            raw = regular_bytes(path, 128 << 20)
            require(len(raw) == e["size"] and sha256(raw) == e["sha256"], "payload bytes differ")
            data[name] = raw
    require(incoming["lib"]["type"] == "dir" and rows["lib"][1:] == (b"S", b"1776674791 777 0 0 usr/lib")
            and not any(n.startswith("lib/") for n in incoming), "immutable /lib contract")
    for name in incoming:
        for parent in PurePosixPath(name).parents:
            k = str(parent)
            if k != ".":
                require((k in incoming and incoming[k]["type"] == "dir") or
                        (k not in incoming and rows.get(k, (None, None))[1] == b"D"),
                        "payload requires an absent or nonphysical parent: " + k)
        prior = rows.get(name)
        if prior and prior[1] == b"S" and name != "lib":
            require(name.startswith("usr/lib/") and name in data, "unreviewed replaced symlink: " + name)
            dest = name
            for _ in range(12):
                _, tag, meta = rows[dest]
                if tag != b"S":
                    break
                link = os.fsdecode(meta.split(b" ", 4)[4])
                require(not link.startswith("/"), "external guest library alias")
                dest = posixpath.normpath(posixpath.join(posixpath.dirname(dest), link))
                require(dest.startswith("usr/lib/") and dest in rows, "escaping guest library alias")
            require(rows[dest][1] == b"R" and dest not in incoming and dest not in aliases and
                    not attrs.get(dest), "ambiguous library alias: " + dest)
            start, sz = raw_extent(rows[dest][2], offset, len(mapped))
            require(sha256(memoryview(mapped)[start:start + sz]) == incoming[name]["sha256"],
                    "base library alias target is a different build: " + dest)
            aliases[dest] = name
        elif prior:
            require(prior[1] in (b"R", b"D", b"S") and (name == "lib" or
                    (prior[1] == b"D") == (incoming[name]["type"] == "dir")),
                    "unsupported base replacement")
    for token, kind, meta in rows.values():
        require(kind != b"L" or unescape(meta) not in (incoming.keys() | aliases.keys()),
                "replacing a hard-linked payload file")
    for dest, target in aliases.items():
        rows[dest] = (os.fsencode(dest), b"S", f"{EPOCH} 777 0 0 {posixpath.relpath(target, posixpath.dirname(dest))}".encode())
    end = len(mapped) - offset
    for name, e in incoming.items():
        meta = f"{EPOCH} {e['mode']:o} 0 0"
        if e["type"] == "dir":
            rows[name] = (os.fsencode(name), b"D", meta.encode())
        else:
            size = len(data[name])
            rows[name] = (os.fsencode(name), b"R", f"{meta} {size} {end} 0".encode())
            end += size
    return data, aliases


def assemble(work, payload, payload_sha):
    require(work == WORK and work.resolve(strict=True) == work and work.stat().st_uid == os.getuid() and
            not work.stat().st_mode & 0o077, "private image workspace required")
    lock = json.loads(regular_bytes(PINS))
    env = decoder(work, lock)
    base = work / "base.pseudo"
    locked(base, lock["base_pseudo_sha256"])
    manifest = regular_bytes(payload / "payload.json", 16 << 20)
    require(sha256(manifest) == payload_sha, "unexpected approved payload manifest")
    profile = json.loads(manifest)
    require(profile["schema"] == "aragorn/pi-core-immutable-payload/v1", "unknown payload")
    # Keep each changed recipe in a separate transaction. An occupied reservation never reruns.
    fp = sha256(canonical([digest(Path(__file__)), digest(PINS), payload_sha]))
    dst = work / fp
    dst.mkdir(mode=0o700)
    tool = work / "tools"
    image = dst / "root.squashfs"
    edited = dst / "composed.pseudo"
    readback = dst / "readback.pseudo"
    with base.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        rows, attrs, offset = read_pseudo(f)
        data, aliases = project(rows, attrs, mapped, offset, payload / "root", profile["entries"])
        expected = inventory(rows, attrs, mapped, offset, None, data)
        with edited.open("xb") as g:
            for name, record in rows.items():
                g.write(b" ".join(record) + b"\n")
                g.writelines(attrs.get(name, []))
            g.write(MARKER)
            shutil.copyfileobj(f, g, 8 << 20)
            for raw in data.values():
                g.write(raw)
    def run(name, args):
        with (dst / (name + ".log")).open("xb") as log:
            subprocess.run([str(tool / name), *map(str, args)], stdin=subprocess.DEVNULL, stdout=log,
                           stderr=subprocess.STDOUT, cwd=dst, env=env, timeout=900, check=True)
    run("mksquashfs", ["-", image, "-pf", edited, "-noappend", "-comp", "zstd", "-Xcompression-level", "5",
        "-nopad", "-no-progress", "-processors", "6", "-mem", "512M", "-exit-on-error", "-mkfs-time", str(EPOCH)])
    run("unsquashfs", ["-pf", readback, "-strict-errors", "-no-progress", "-processors", "6", image])
    with readback.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
        actual, xa, off = read_pseudo(f)
        with (dst / "inventory.jsonl").open("xb") as out:
            observed = inventory(actual, xa, mapped, off, out)
    require(observed == expected, "whole-image logical readback differs from expected inventory")
    with image.open("rb") as f:
        hdr = f.read(96)
    require(hdr[:4] == b"hsqs" and int.from_bytes(hdr[40:48], "little") == image.stat().st_size,
            "wrong SquashFS bytes/padding")
    receipt = {"schema": "aragorn/pi-core-immutable-root/v1", "fingerprint": fp, "sha256": digest(image),
               "bytes": image.stat().st_size, "inventory_sha256": observed, "entries": len(actual),
               "xattr_records": sum(map(len, xa.values())), "payload_sha256": payload_sha,
               "library_aliases_retargeted": aliases, "boot_verified": False, "phase3_exit_eligible": False}
    with (dst / "receipt.json").open("xb") as f:
        f.write(canonical(receipt) + b"\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("payload_directory", type=Path)
    parser.add_argument("approved_manifest_sha256")
    args = parser.parse_args()
    os.umask(0o077)
    print(json.dumps(assemble(WORK, args.payload_directory.resolve(strict=True), args.approved_manifest_sha256),
                     sort_keys=True))
