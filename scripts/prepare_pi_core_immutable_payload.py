"""Project the authenticated coordinator runtime into an immutable image, without loading it."""
import argparse
from functools import cache
import io
import json
import lzma
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile

from scripts import check_pi_core_host_abi as abi
from scripts import inspect_pi_core_host_clients as b40
from scripts import prepare_pi_core_host_sysroot as sysroot
from scripts import prepare_pi_core_restricted_host_sources as sources
from scripts.build_pi_core_linux import ROOT, canonical, regular_bytes, require, sha256
from scripts.prepare_pi_core_os_root import elf_dependencies

PINS = ROOT / "packaging/pi-core/immutable-host-b41/payload-pins.json"
STATE = ROOT / ".aragorn/host-preflight"
WORK = STATE / "build-b41/payload"
PKG_DIR = STATE / "build-b41/payload-packages"
EXTRAS = frozenset("libgdbm6t64 libncursesw6 libnsl2 libreadline8t64 libsqlite3-0 libtinfo6 libtirpc3t64".split())
PYROOT = "/opt/aragorn-cpython"
PYTHON = PYROOT + "/bin/python3.12"
STDLIB = PYROOT + "/lib/python3.12"
PROFILE = "/etc/aragorn/coordinator-host.json"
MULTI = "/usr/lib/aarch64-linux-gnu/"
LOADER = "/usr/lib/" + b40.LOADER
ORIGINS = "953970e9e9aa82c291672602a7ca668102dfd19bc205bc7350c650a9c01006fb"
PY_RELEASE = "c03a2cacf42161b94c730948e4d1c1dcfd58aede8d003a16312fef0663f3a46e"
CLIENT_REPORT = ROOT / "docs/phase3/coordinator/pi-core-immutable-host-clients-batch-40.static-elf.json"
CLIENT_REPORT_SHA = "fb7c5fffeb2cb351ef4017e3cce5c35a8585808eaa9ec100667819150f856249"


def read(path, digest, limit):
    require(path.resolve(strict=True) == path, "linked payload input: " + str(path))
    raw = regular_bytes(path, limit)
    require(sha256(raw) == digest, "payload input digest differs: " + str(path))
    return raw


def package_rows():
    # The signed Release and exact Packages index were authenticated in B38.
    raw = read(sysroot.B38 / "Packages-arm64.xz", sysroot.MAIN, 4 << 20)
    rows = {}
    for stanza in lzma.decompress(raw).decode("utf-8").split("\n\n"):
        head = stanza.partition("\n")[0]
        if head.removeprefix("Package: ") not in EXTRAS:
            continue
        d = dict(s.split(": ", 1) for s in stanza.splitlines() if not s.startswith(" ") and ": " in s)
        require(d["Architecture"] == "arm64" and sysroot.POOL_RE.fullmatch(d["Filename"])
                and d["Package"] not in rows, "unapproved supplemental package row")
        rows[d["Package"]] = d
    require(rows.keys() == EXTRAS, "Ubuntu runtime package missing")
    return rows


def fetch():
    PKG_DIR.mkdir(mode=0o700, exist_ok=True)
    require(PKG_DIR.resolve(strict=True) == PKG_DIR and PKG_DIR.stat().st_uid == os.getuid()
            and not PKG_DIR.stat().st_mode & 0o077, "unsafe package cache")
    for d in package_rows().values():
        dest = PKG_DIR / Path(d["Filename"]).name
        if not dest.exists():
            temp = dest.with_name(dest.name + ".partial")
            with temp.open("xb") as out:
                subprocess.run(["/usr/bin/curl", "--proto", "=https", "-fsS", "--max-filesize", d["Size"],
                                "--max-time", "60", "https://ports.ubuntu.com/ubuntu-ports/" + d["Filename"]],
                               stdout=out, stdin=subprocess.DEVNULL, timeout=65, check=True)
            read(temp, d["SHA256"], int(d["Size"]))
            os.link(temp, dest)
            temp.unlink()
        read(dest, d["SHA256"], int(d["Size"]))


def additional():
    providers = {}
    zstd = sysroot.ZSTD.resolve(strict=True)
    read(zstd, sysroot.ZSTD_SHA, 8 << 20)
    for d in package_rows().values():
        deb = read(PKG_DIR / Path(d["Filename"]).name, d["SHA256"], int(d["Size"]))
        with tarfile.open(fileobj=io.BytesIO(sysroot.data_tar(deb, zstd))) as archive:
            for m in archive:
                p = "/" + m.name.removeprefix("./")
                if not m.isfile() or str(Path(p).parent) != MULTI.rstrip("/") or ".so." not in m.name:
                    continue
                require(m.size <= 16 << 20, "supplemental library too large")
                raw = archive.extractfile(m).read()
                name = elf_dependencies(raw)["soname"]
                require(name and name not in providers, "ambiguous supplemental SONAME")
                providers[name] = raw
    return providers


def library_index():
    bdir = sysroot.WORK / "root"
    table = json.loads(regular_bytes(sysroot.WORK / "sysroot.json", 2 << 20))["inventory"]
    expect = json.loads(regular_bytes(sysroot.PINS / "sysroot-tree.json"))
    require(sha256(canonical(table)) == expect["inventory_sha256"], "unapproved B40 library inventory")
    pins = {r["path"]: r["sha256"] for r in table if r["kind"] == "file"}
    return bdir, pins


def projection():
    files = {}
    native = {}
    def insert(path, raw, mode):
        require(path not in files and mode in (0o444, 0o555), "duplicate or invalid projected file")
        files[path] = (raw, mode)
        if raw.startswith(b"\x7fELF"):
            native[path] = elf_dependencies(raw, allowed_rpath=("$ORIGIN/../lib",) if path == PYTHON else ())

    for r in sources._release(ROOT):
        path = r["path"]
        src = ROOT / ("packaging/pi-core/coordinator.py" if path == sources.WRAPPER else path.removeprefix("/opt/aragorn/"))
        insert(path, read(src, r["digest"][7:], r["size"]), 0o444)
    pyr = ROOT / ".aragorn/pi-core-build" / ("host-python-" + PY_RELEASE)
    records = json.loads(read(pyr / "host-python-origins.json", ORIGINS, 256 << 10))
    for r in records:
        path = r["path"]
        require(path.startswith(PYROOT + "/"), "unexpected Python source")
        insert(path, read(pyr / "root" / path[1:], r["digest"][7:], r["size"]), r["mode"])
    evidence = json.loads(read(CLIENT_REPORT, CLIENT_REPORT_SHA, 16 << 10))
    client = json.loads(regular_bytes(ROOT / "packaging/pi-core/host-tools-b40/clients.json"))
    require(evidence["build_fingerprint"] == client["fingerprint"], "different client build")
    stage = STATE / "build-b40/client-work" / client["fingerprint"] / "stage"
    for name in b40.CLIENTS:
        p = "/usr/bin/" + name
        require(client["clients"][name] == evidence["files"][p]["sha256"], "client evidence differs")
        insert(p, read(stage / p[1:], client["clients"][name], 16 << 20), 0o555)

    base, reviewed = library_index()
    extra = additional()
    internal = PYROOT + "/lib/libpython3.12.so.1.0"
    require(native[internal]["soname"] == Path(internal).name, "libpython SONAME mismatch")
    queue = list(native)
    for p in queue:
        elf = native[p]
        require(elf["interpreter"] in (None, b40.INTERP), "unexpected ARM64 interpreter")
        for n in elf["needed"] + ([b40.LOADER] if elf["interpreter"] else []):
            if n == Path(internal).name:
                require(p == PYTHON, "unexpected libpython consumer")
                continue
            provider = LOADER if n == b40.LOADER else MULTI + n
            if provider in files:
                continue
            if n in extra:
                raw = extra[n]
                if any(os.path.lexists(base / d / n) for d in b40.LIBDIRS):
                    require(raw == b40._library(base, n, reviewed), "conflicting package provider")
            else:
                raw = b40._library(base, n, reviewed)
            if n in evidence["files"]:
                require(sha256(raw) == evidence["files"][n]["sha256"], "different B40 library")
            insert(provider, raw, 0o555)
            require(native[provider]["soname"] == n and len(queue) < 256, "provider identity mismatch")
            queue.append(provider)
    return files, native, evidence


def logical(physical):
    # In the real guest the early read-only bind of /usr/lib supplies this path.
    return b40.INTERP if physical == LOADER else physical


def decimal_symbol_sizes(text):
    # GNU readelf switches to 0x... for large st_size (e.g. CPython's _PyRuntime).
    # B38's verifier accepts a decimal size column. Preserve its exact integer
    # and every other character; do not discard or synthesize any symbol row.
    row = r"^(\s*\d+:[ \t]+[0-9a-f]+[ \t]+)0x([0-9a-f]+)(?=[ \t]+(?:OBJECT|FUNC|NOTYPE|TLS|IFUNC)\b)"
    return re.sub(row, lambda m: m[1] + str(int(m[2], 16)), text, flags=re.M)


def abi_report():
    """Extend, do not repeat, the B40 versioned-symbol checks with the newly joined objects."""
    files, native, evidence = projection()
    profile_digest = sha256(host_profile(files))
    expected = json.loads(regular_bytes(PINS, 4096))
    require(profile_digest == expected["host_profile_sha256"], "unapproved host ABI input")
    by_soname = {elf["soname"]: p for p, elf in native.items() if elf["soname"]}
    require(len(by_soname) == sum(bool(elf["soname"]) for elf in native.values()), "ambiguous SONAME")
    @cache
    def report(path):
        return decimal_symbol_sizes(abi._readelf(files[path][0]))
    abi._tools()
    edges = []
    old = evidence["files"]
    for path, elf in sorted(native.items()):
        old_name = path if path in old else elf["soname"]
        if old_name in old:
            require(sha256(files[path][0]) == old[old_name]["sha256"], "B40 ELF input differs")
            continue
        text = report(path)
        if "No version information found in this file." in text.splitlines():
            require(not any(k in text for k in ("Version symbols section '", "Version needs section '",
                                                "Version definition section '")), "ambiguous no-version table")
            continue
        _, imports, _, refs, _ = abi._parse(text)
        for dep in sorted({lib for lib, _ in imports.values()}):
            require(dep in refs and dep in elf["needed"] and dep in by_soname, "unbound version provider")
            if path == PYTHON and dep == "libc.so.6":
                # B38 already verified this exact edge with the same unchanged checker.
                require(sha256(files[path][0]) == "7863a4d5e03fde7791c7f8c2c304cf3522f435e19745364ad18a6b7a0458af57"
                        and sha256(files[by_soname[dep]][0]) == b40.LIBC_SHA, "B38 inputs differ")
                continue
            try:
                edge = abi._edge(text, report(by_soname[dep]), dep)
            except ValueError as exc:
                raise ValueError(f"{path} -> {dep}: {exc}") from exc
            edges.append({"requester": path, "provider_file": by_soname[dep], **edge})
    abi._tools()
    return {"schema": "aragorn/pi-core-immutable-payload-abi/v1", "host_profile_sha256": profile_digest,
            "b40_report_sha256": CLIENT_REPORT_SHA, "reused_b40_edges": len(evidence["versioned_edges"]),
            "reused_b38_edges": [[PYTHON, "libc.so.6"]], "new_versioned_edges": edges,
            "runtime_verified": False, "phase3_exit_eligible": False}


def host_profile(files):
    rows = sorted(({"path": logical(p), "size": len(raw), "digest": "sha256:" + sha256(raw)}
                   for p, (raw, _) in files.items()), key=lambda r: Path(r["path"]))
    zip_path = PYROOT + "/lib/python312.zip"
    return canonical({"schema": "aragorn/pi-core-coordinator-host/v1", "target": "linux-arm64-cpython312",
                      "python_executable": PYTHON, "wrapper_path": sources.WRAPPER, "stdlib_roots": [STDLIB],
                      "sys_path": [zip_path, STDLIB, STDLIB + "/lib-dynload"], "absent_sys_path": [zip_path],
                      "files": rows})


def overlay(files, profile):
    require(PROFILE not in files and not any(p == "/lib" or p.startswith("/lib/") for p in files),
            "reserved physical payload path")
    physical = {**files, PROFILE: (profile, 0o400)}
    dirs = {"/lib"}
    rows = []
    for name, (raw, mode) in physical.items():
        dirs.update(str(d) for d in Path(name).parents if str(d) != "/")
        rows.append({"path": name, "type": "file", "mode": mode, "uid": 0, "gid": 0,
                     "size": len(raw), "sha256": sha256(raw)})
    require(not dirs.intersection(physical), "physical payload path collision")
    rows.extend({"path": d, "type": "dir", "mode": 0o755, "uid": 0, "gid": 0} for d in dirs)
    return {"schema": "aragorn/pi-core-immutable-payload/v1",
            "entries": sorted(rows, key=lambda row: row["path"])}


def pins(profile, manifest):
    return {"schema": "aragorn/pi-core-immutable-payload-pins/v1",
            "host_profile_sha256": sha256(profile), "manifest_sha256": sha256(canonical(manifest))}


def new(path, raw, mode=0o400):
    with path.open("xb") as f:
        f.write(raw)
        f.flush()
        os.fchmod(f.fileno(), mode)
        os.fsync(f.fileno())


def check_physical(root, manifest):
    require(root.resolve(strict=True) == root and root.is_dir(), "invalid staging root")
    rows = {r["path"]: r for r in manifest["entries"]}
    require(len(rows) == len(manifest["entries"]) and
            {"/" + p.relative_to(root).as_posix() for p in root.rglob("*")} == set(rows),
            "different physical payload namespace")
    for name, row in rows.items():
        p = root / name[1:]
        st = p.lstat()
        require(p.resolve(strict=True) == p and stat.S_IMODE(st.st_mode) == row["mode"]
                and row["uid"] == row["gid"] == 0, "staging mode, path or target ownership differs")
        if row["type"] == "dir":
            require(stat.S_ISDIR(st.st_mode), "not a staging directory")
        else:
            require(row["type"] == "file" and stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                    st.st_size == row["size"] and sha256(regular_bytes(p, st.st_size)) == row["sha256"],
                    "staged bytes or type differ")


def prepare():
    expected = json.loads(regular_bytes(PINS, 4096))
    files, _, _ = projection()
    profile = host_profile(files)
    manifest = overlay(files, profile)
    require(pins(profile, manifest) == expected, "source projection differs from reviewed inventory")
    require(WORK.parent.resolve(strict=True) == WORK.parent and WORK.parent.stat().st_uid == os.getuid()
            and not WORK.parent.stat().st_mode & 0o022, "unsafe private staging parent")
    WORK.mkdir(mode=0o700, exist_ok=False)
    root, export = WORK / "root", WORK / "host-export"
    export.mkdir(mode=0o700)
    root.mkdir(mode=0o700)
    for r in manifest["entries"]:
        name = r["path"]
        dest = root / name[1:]
        if r["type"] == "dir":
            dest.mkdir()
            dest.chmod(r["mode"])
            continue
        payload = profile if name == PROFILE else files[name][0]
        new(dest, payload, r["mode"])
        if name != PROFILE:
            target = export / logical(name)[1:]
            target.parent.mkdir(parents=True, exist_ok=True)
            new(target, payload, r["mode"])
    return _seal(files, profile, manifest, expected)


def seal():
    # A failed custody read never publishes a manifest. Independently rederive
    # every expected byte, inspect the complete physical tree, then authenticate
    # the separate logical export. No resume from a self-attested staging pin.
    expected = json.loads(regular_bytes(PINS, 4096))
    files, _, _ = projection()
    profile = host_profile(files)
    manifest = overlay(files, profile)
    require(pins(profile, manifest) == expected, "source projection differs from reviewed inventory")
    return _seal(files, profile, manifest, expected)


def _seal(files, profile, manifest, expected):
    require(not any(os.path.lexists(WORK / name) for name in ("payload.json", "coordinator-host.json",
                                                             "host-preparation.json")),
            "already sealed or partially sealed")
    check_physical(WORK / "root", manifest)
    # The unchanged preparer needs a separate logical export (after the future
    # bind). No symlink, hardlink, bind mount or root ownership is simulated.
    checked = sources.prepare_restricted_coordinator_host(profile,
                    expected_profile_digest="sha256:" + expected["host_profile_sha256"], retained_root=WORK / "host-export")
    require(checked.profile_raw == profile, "retained profile changed")
    new(WORK / "coordinator-host.json", profile)
    new(WORK / "host-preparation.json", checked.preparation_raw)
    new(WORK / "payload.json", canonical(manifest))
    return expected


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("fetch", "prepare", "seal", "abi"))
    action = p.parse_args().action
    if action == "abi":
        raw = canonical(abi_report())
        new(WORK / "payload-abi.json", raw)
        print(sha256(raw))
    else:
        print(json.dumps({"fetch": fetch, "prepare": prepare, "seal": seal}[action](), sort_keys=True))
