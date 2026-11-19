"""Project signed Alpine x86-64 host codegen inputs. Never run the helper or package scripts."""
import base64
import concurrent.futures
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile
import zlib

from scripts import check_pi_core_host_abi as elf_tool
from scripts.build_pi_core_linux import canonical, regular_bytes, require, sha256
from scripts.prepare_pi_core_host_sysroot import BASE, PINS, inventory

WORK = BASE / ".aragorn/host-preflight/build-b40/tools-work/alpine-host"
LOCK = PINS / "alpine-bpf-packages.json"
PIN = PINS / "alpine-bpf-tree.json"
OPENSSL = Path("/usr/bin/openssl")
OPENSSL_SHA = "f81b4fcec5048ea1eceb40fc08f4e06f1668181f0b5bacfa8be27d0da181dcb7"
BPF = "usr/sbin/bpftool"
INTERP = "lib/ld-musl-x86_64.so.1"
ALPINE_KEYS = "https://alpinelinux.org/keys/"
RELEASE = "https://dl-cdn.alpinelinux.org/alpine/v3.20/"


def fetch(work: Path = WORK) -> None:
    """Explicit acquisition from the Alpine signing-key endpoint and named TLS release archive.

    No network on prepare, verify, or in the helper. Occupied or failed pins are
    not overwritten. No apk tooling, dependency installation or maintainer scripts.
    """
    require(work.resolve(strict=True) == work and work.stat().st_uid == os.geteuid()
            and not work.stat().st_mode & 0o022, "unowned or linked Alpine cache")
    packages = work / "packages"
    packages.mkdir(mode=0o700, exist_ok=True)
    require(packages.resolve(strict=True) == packages, "linked Alpine packages")
    lock = json.loads(regular_bytes(LOCK))
    urls = [(ALPINE_KEYS + lock["key"], work / lock["key"], lock["key_sha256"], 8192)]
    urls += [(RELEASE + c + "/x86_64/APKINDEX.tar.gz", work / (c + ".index.gz"), pin, 8 << 20)
             for c, pin in lock["indexes"].items()]
    urls += [(RELEASE + c + "/x86_64/" + f, packages / f, pin, size)
             for f, (c, size, pin) in lock["packages"].items()]
    def acquire(row):
        url, path, pin, limit = row
        if not os.path.lexists(path):
            tmp = path.with_name(path.name + ".partial")
            require(not os.path.lexists(tmp), "incomplete Alpine input acquisition")
            subprocess.run(["/usr/bin/curl", "--proto", "=https", "-fsS",
                            "--connect-timeout", "10", "--max-time", "60",
                            "--max-filesize", str(limit), url, "-o", str(tmp)], check=True, timeout=65)
            require(sha256(regular_bytes(tmp, limit)) == pin, "wrong Alpine acquisition: " + path.name)
            os.link(tmp, path)
            tmp.unlink()
        else:
            require(sha256(regular_bytes(path, limit)) == pin, "wrong retained Alpine input: " + path.name)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(acquire, urls))


# APK v2 is multiple gzip members, each containing one tar segment. Signatures
# cover exact compressed control/INDEX bytes; .PKGINFO's datahash covers the compressed data segment.
def members(raw, count):
    parts = []
    while raw:
        require(len(parts) < count, "too many Alpine gzip members")
        d = zlib.decompressobj(31)
        plain = d.decompress(raw, 96 << 20)
        require(d.eof and not d.unconsumed_tail, "oversize or unterminated signed Alpine member")
        consumed = len(raw) - len(d.unused_data)
        parts.append((raw[:consumed], plain))
        raw = d.unused_data
    require(len(parts) == count, "incorrect Alpine gzip member count")
    return parts


def tar(raw):
    return tarfile.open(fileobj=io.BytesIO(raw), mode="r:")


def authenticated(raw, key, count):
    parts = members(raw, count)
    with tar(parts[0][1]) as ar:
        names = ar.getmembers()
        require(len(names) == 1 and names[0].isfile() and names[0].name == ".SIGN.RSA." + key.name,
                "Alpine archive signature/key mismatch")
        sig = ar.extractfile(names[0]).read()
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "sig"
        f.write_bytes(sig)
        p = subprocess.run([str(OPENSSL), "dgst", "-sha1", "-verify", str(key), "-signature", str(f)],
                           input=parts[1][0], capture_output=True, check=False, timeout=10)
        require(p.returncode == 0 and p.stdout.strip() == b"Verified OK", "Alpine RSA signature rejected")
    return parts[1:]


def digest(root):
    rows, counts = inventory(root)
    return {**counts, "inventory_sha256": sha256(canonical(rows)), "package_lock_sha256": sha256(regular_bytes(LOCK))}


def verify(root: Path) -> dict:
    result = digest(root)
    require(result == json.loads(regular_bytes(PIN)), "unapproved Alpine host helper tree")
    return result


def project(work: Path = WORK) -> dict:
    require(work.is_absolute() and work.resolve(strict=True) == work and work.stat().st_uid == os.geteuid()
            and not work.stat().st_mode & 0o022 and (work / "packages").resolve(strict=True) == work / "packages",
            "unowned or linked Alpine input workspace")
    require(not os.path.lexists(work / "root") and not os.path.lexists(work / "receipt.json"), "occupied Alpine output")
    raw_lock = regular_bytes(LOCK)
    lock = json.loads(raw_lock)
    require((lock["branch"], lock["architecture"]) == ("v3.20", "x86_64"), "not the selected codegen helper ABI")
    key = work / lock["key"]
    require(key.parent == work and sha256(regular_bytes(key, 8192)) == lock["key_sha256"], "Alpine official key mismatch")
    require(sha256(regular_bytes(OPENSSL, 8 << 20)) == OPENSSL_SHA, "host signature verifier differs")
    elf_tool._tools()
    indexed = {}
    for component, wanted in lock["indexes"].items():
        raw = regular_bytes(work / (component + ".index.gz"), 8 << 20)
        require(sha256(raw) == wanted, "Alpine signed index differs")
        [(_, plain)] = authenticated(raw, key, 2)
        with tar(plain) as ar:
            text = ar.extractfile("APKINDEX").read().decode()
        for stanza in text.strip().split("\n\n"):
            r = dict(row.split(":", 1) for row in stanza.splitlines())
            f = r["P"] + "-" + r["V"] + ".apk"
            if f in lock["packages"] and lock["packages"][f][0] == component:
                require(r["A"] == "x86_64" and f not in indexed, "unexpected Alpine architecture/duplicate")
                indexed[f] = r
    require(indexed.keys() == lock["packages"].keys(), "Alpine packages absent from signed indexes")
    files, links = {}, {}
    for f, (component, size, wanted) in lock["packages"].items():
        require(PurePosixPath(f).name == f and int(indexed[f]["S"]) == size, "invalid Alpine pin")
        raw = regular_bytes(work / "packages" / f, size)
        require(len(raw) == size and sha256(raw) == wanted, "Alpine archive byte mismatch: " + f)
        (control_z, ctrl), (data_z, data) = authenticated(raw, key, 3)
        require("Q1" + base64.b64encode(hashlib.sha1(control_z).digest()).decode() == indexed[f]["C"],
                "Alpine control not in signed index: " + f)
        with tar(ctrl) as ar:
            lines = ar.extractfile(".PKGINFO").read().decode().splitlines()
        require([line for line in lines if line.startswith("datahash = ")] == ["datahash = " + sha256(data_z)],
                "incorrect signed Alpine datahash")
        with tar(data) as ar:
            for item in ar:
                n = item.name
                if n != BPF and not re.fullmatch(r"(usr/)?lib/[a-zA-Z0-9_+.-]+\.so(?:\.[a-zA-Z0-9_.-]+)?", n):
                    continue
                require(n not in files and n not in links, "duplicate Alpine path")
                if item.issym():
                    require(re.fullmatch(r"[a-zA-Z0-9_.+-]+", item.linkname) and item.linkname not in (".", ".."),
                            "non-local Alpine library alias")
                    links[n] = item.linkname
                else:
                    require(item.isfile(), "not a regular Alpine ELF")
                    files[n] = ar.extractfile(item).read()
    # Resolve DT_NEEDED, not the whole package dependency set (which includes other commands).
    todo, seen, graph = [BPF, INTERP], set(), {}
    with tempfile.TemporaryDirectory() as tmp:
        specimen = Path(tmp) / "host.elf"
        while todo:
            n = todo.pop()
            if n in seen:
                continue
            seen.add(n)
            if n in links:
                todo.append(str(PurePosixPath(n).with_name(links[n])))
                continue
            data = files[n]
            require(data[:7] == b"\x7fELF\x02\x01\x01" and data[18:20] == b"\x3e\x00", "not x86-64 LE host code")
            specimen.write_bytes(data)
            p = subprocess.run([str(elf_tool.READELF), "-Wld", str(specimen)], env={"LC_ALL": "C"}, check=True,
                               capture_output=True, timeout=10)
            require(not p.stderr, "invalid build-helper ELF")
            report = p.stdout.decode()
            interps = re.findall(r"\[Requesting program interpreter: ([^\]]+)\]", report)
            # Alpine's libcap is also executable and legitimately carries the same
            # PT_INTERP. The command must name it; DSOs may name only that route.
            require(interps == ["/" + INTERP] or (n != BPF and not interps), "unexpected Alpine host interpreter: " + n)
            require(not re.search(r"\((?:RPATH|RUNPATH|AUDIT|DEPAUDIT|AUXILIARY|FILTER)\)", report), "unapproved helper library route")
            deps = re.findall(r"\(NEEDED\)\s+Shared library: \[([a-zA-Z0-9_.+-]+)\]", report)
            require(report.count("(NEEDED)") == len(deps) == len(set(deps)), "malformed Alpine dependencies")
            graph[n] = deps
            for dep in deps:
                providers = [prefix + dep for prefix in ("lib/", "usr/lib/") if prefix + dep in files or prefix + dep in links]
                require(len(providers) == 1, "missing or ambiguous Alpine provider: " + dep)
                todo.extend(providers)
    root = Path(tempfile.mkdtemp(prefix="unpublished-", dir=work))
    for n in ["dev", "proc", "SystemRoot"]:
        (root / n).mkdir()
    for n in sorted(seen, key=lambda x: (x in links, x)):
        path = root / n
        path.parent.mkdir(parents=True, exist_ok=True)
        if n in links:
            path.symlink_to(links[n])
            os.lchmod(path, 0o755)
        else:
            with path.open("xb") as out:
                out.write(files[n])
            path.chmod(0o555)
    for directory, _, _ in os.walk(root):
        os.chmod(directory, 0o700 if Path(directory) == root else 0o755)
    result = digest(root)
    require(result == json.loads(regular_bytes(PIN)), "unreviewed Alpine tree; unpublished inputs retained")
    root.rename(work / "root")
    with (work / "receipt.json").open("x") as out:
        json.dump(dict(result, signed_release="Alpine 3.20 x86_64", package_archives=len(indexed),
                       dependencies=graph, target_executed=False), out, sort_keys=True)
    return result


if __name__ == "__main__":
    require(sys.argv[1:] in (["fetch"], ["prepare"], ["verify"]), "operation must be fetch, prepare or verify")
    if sys.argv[1] == "fetch":
        fetch()
    else:
        print(json.dumps(project() if sys.argv[1] == "prepare" else verify(WORK / "root"), sort_keys=True))
