"""Bind B59's fixed helper to retained ARM64 runtime inputs; never execute guest code."""
import ast
import json
from pathlib import Path
import re

from scripts.build_pi_core_linux import canonical, regular_bytes, require, sha256
from scripts.prepare_pi_core_os_root import elf_dependencies
from scripts.prepare_pi_core_restricted_host_sources import _identity


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PAYLOAD = ROOT / ".aragorn/host-preflight/build-b41/payload"
HELPER = "aef5d0aebb0c1d98d91da4c627c51b991f902baf2c3005a473bf4fcaaf693725"
PREFIX = "/opt/aragorn-cpython"
EXE = PREFIX + "/bin/python3.12"
LIBPY = PREFIX + "/lib/libpython3.12.so.1.0"
STDLIB = PREFIX + "/lib/python3.12"
DYN = STDLIB + "/lib-dynload/"
LOADER = "/lib/ld-linux-aarch64.so.1"
LIBDIR = "/usr/lib/aarch64-linux-gnu/"
CONFIG = "_sysconfigdata__linux_aarch64-linux-gnu.py"
B41 = "immutable-host-b41/"


def _read(path, expected, limit):
    before = _identity(path)
    raw = regular_bytes(path, limit)
    require(before == _identity(path) and sha256(raw) == expected, "mask input differs: " + str(path))
    return raw


def _published(relative, digest):
    return json.loads(_read(ROOT / "packaging/pi-core" / relative, digest, 16384))


def _bound_row(path, host_rows, payload_rows):
    physical = "/usr" + path if path == LOADER else path
    row, src = host_rows.get(path), payload_rows.get(physical)
    require(type(row) is dict and row.keys() == {"path", "size", "digest"} and row["path"] == path
            and type(row["size"]) is int and 0 < row["size"] <= 128 << 20
            and type(row["digest"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", row["digest"]),
            "missing or invalid host row: " + path)
    require(type(src) is dict and src.keys() == {"path", "size", "sha256", "type", "uid", "gid", "mode"}
            and (src["path"], src["type"]) == (physical, "file")
            and all(type(src[k]) is int for k in ("uid", "gid", "mode", "size"))
            and src["uid"] == src["gid"] == 0 and src["mode"] in (0o444, 0o555)
            and src["size"] == row["size"] and src["sha256"] == row["digest"][7:],
            "missing, unsafe or different physical payload row: " + physical)
    return physical, row


def verify_guest_inputs(*, helper_source: str, payload_dir=DEFAULT_PAYLOAD):
    require(type(helper_source) is str and helper_source.isascii() and
            sha256(helper_source.encode("ascii")) == HELPER, "wrong B59 helper bytes")
    pins = _published(B41 + "payload-pins.json", "b02f6541d56985420534f9899431e90163bbfc1bed4435cbb10eb1802136d63c")
    receipts = _published(B41 + "payload-receipts.json", "931475e8d555d9b07ef377de191b377ac7250722423493d3f31d939b0c0623d6")
    image = _published(B41 + "image-output.json", "1f01764ec29cfb940cd1608ebbbb96fcafa25cf6359e6ab45d2bd2fed7cf02ca")
    media = _published("immutable-host-b44/media-output.json", "0ebd47b2380dcba15e60d9dfb1dd42838f613733d62ac8128a679cd1ec19e892")
    require(image["root_sha256"] == media["root_sha256"] and image["root_bytes"] == media["root_size"],
            "B44 root differs from authenticated B41 projection")
    base = Path(payload_dir).absolute()
    host = json.loads(_read(base / "coordinator-host.json", pins["host_profile_sha256"], 1 << 20))
    payload = json.loads(_read(base / "payload.json", pins["manifest_sha256"], 1 << 20))
    abi = json.loads(_read(base / "payload-abi.json", receipts["payload_abi_sha256"], 1 << 20))
    require(host["python_executable"] == EXE and host["target"] == "linux-arm64-cpython312" and
            host["sys_path"] == [PREFIX + "/lib/python312.zip", STDLIB, DYN[:-1]] and
            host["absent_sys_path"] == host["sys_path"][:1] and abi["host_profile_sha256"] == pins["host_profile_sha256"],
            "different CPython import profile or native ABI receipt")
    host_rows = {r["path"]: r for r in host["files"]}
    payload_rows = {r["path"]: r for r in payload["entries"]}
    require(len(host_rows) == len(host["files"]) and len(payload_rows) == len(payload["entries"]),
            "duplicate guest paths")
    selected, objects, edges = {}, {}, set()

    def read(path):
        physical, row = _bound_row(path, host_rows, payload_rows)
        data = _read(base / "root" / physical[1:], row["digest"][7:], row["size"])
        require(len(data) == row["size"], "target file size differs")
        selected[path] = row
        return data

    # CPython contains the built-in/frozen modules. Other stdlib transitives
    # remain covered by the original complete B41 import-tree pin, not a trace.
    pure = ("ctypes/__init__.py", "ctypes/_endian.py", "json/__init__.py", "json/decoder.py",
            "json/encoder.py", "json/scanner.py", "signal.py", "socket.py", "struct.py", "os.py",
            "enum.py", "selectors.py", "types.py", "encodings/__init__.py")
    for name in pure:
        read(STDLIB + "/" + name)
    config = ast.parse(read(STDLIB + "/" + CONFIG))
    require(len(config.body) == 1 and isinstance(config.body[0], ast.Assign) and
            len(config.body[0].targets) == 1 and isinstance(config.body[0].targets[0], ast.Name)
            and config.body[0].targets[0].id == "build_time_vars", "unknown CPython build record")
    flags = ast.literal_eval(config.body[0].value)
    require(all(flags.get("HAVE_" + f) == 1 for f in ("CLOCK_GETTIME", "FDOPENDIR", "CHROOT", "FCHDIR",
            "SETGROUPS", "SETITIMER", "SETNS", "SETRESGID", "SETRESUID")) and
            all(flags.get("MODULE_" + m + "_STATE") == "yes" for m in ("_CTYPES", "_SOCKET", "_STRUCT")),
            "CPython lacks a required mask-probe build feature")
    suffix = ".cpython-312-aarch64-linux-gnu.so"
    queue = [EXE, *(DYN + m + suffix for m in ("_ctypes", "_socket", "_struct", "_json", "select", "math", "array"))]
    while queue:
        path = queue.pop()
        if path in objects:
            continue
        require(len(objects) < 64, "excessive helper ELF closure")
        obj = objects[path] = elf_dependencies(read(path), allowed_rpath=("$ORIGIN/../lib",) if path == EXE else ())
        interp = obj["interpreter"]
        require(interp in (None, LOADER) and (path != EXE or interp == LOADER), "unexpected ARM64 interpreter")
        for name in obj["needed"] + ([interp] if interp else []):
            target = (LOADER if name in (LOADER, Path(LOADER).name) else
                      LIBPY if name == Path(LIBPY).name and path == EXE else LIBDIR + name)
            edges.add((path, target))
            queue.append(target)
    for _, target in edges:
        require(objects[target]["soname"] == Path(target).name, "native provider SONAME differs")
    require(LIBPY in objects and LOADER in objects and LIBDIR + "libffi.so.8" in objects,
            "missing CPython, loader or ctypes provider")
    rows = [selected[p] for p in sorted(selected)]
    return {"schema": "aragorn/pi-core-mask-guest-inputs/v1", "helper_digest": "sha256:" + HELPER,
            "interpreter_digest": selected[EXE]["digest"], "host_profile_digest": "sha256:" + pins["host_profile_sha256"],
            "payload_digest": "sha256:" + pins["manifest_sha256"], "abi_receipt_digest": "sha256:" + receipts["payload_abi_sha256"],
            "root_digest": "sha256:" + image["root_sha256"], "selected_files_digest": "sha256:" + sha256(canonical(rows)),
            "selected_files": rows, "native_edges": [list(e) for e in sorted(edges)], "guest_execution_observed": False,
            "installed_identity_verified": False, "phase3_exit_eligible": False}
