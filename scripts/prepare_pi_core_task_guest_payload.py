"""Offline preparation of the common fixed-task guest payload."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re

from scripts import prepare_pi_core_split_guest_payload as split
from scripts import prepare_pi_core_service_successor as previous
from scripts.build_pi_core_linux import ROOT, canonical, sha256
from scripts.prepare_pi_core_service_image import SOURCE_PIN_MARKER


BASE = Path.home() / "Library/Application Support/Aragorn-B111-Offline"
OUT = BASE.with_name("Aragorn-Task-Guest-v1-Offline")
BASE_PIN = "ea17bce82e6044ac29fef1d1e893d347272cff2054298f26ed1c10c487360fa0"
WORKER = ROOT / ".aragorn/pi-task-worker-v1"
ASSETS = ROOT / "packaging/pi-core"
SOURCES_PIN = "c087383fd1d0851c20da7074c2423721be7f3ffdb763ca4771a4ce9084beabfc"
CATALOG = ASSETS / "task-guest-payload-v1.json"
CATALOG_PIN = "d56253da3d0148a4da2d4afa67472ae21b7a2632ffec7d4fb3f0c2d0a590af6d"
BUILD_PIN = "b4c9e04a9076375bfdc7514a2378096f52601c6933e9f79fdf99301477ef43b1"
PREFIX = "/opt/aragorn/fixed-task/src/aragorn/"
RUNTIME = "/var/lib/aragorn/pi-task-runtime/"
WRAPPER = "/opt/aragorn/bin/pi-fixed-task.py"
UNIT = "/usr/lib/systemd/system/aragorn-pi-task.service"
PI_UNIT = "/usr/lib/systemd/system/aragorn-pi-task-worker.service"
PYTHON = "/opt/aragorn-cpython/bin/python3.12"
OLD_RUNTIME = "/var/lib/aragorn/pi-runtime/"
STATIC = {WRAPPER, UNIT, PI_UNIT, *(RUNTIME + p for p in ("pi-core/package.json","pi-core/entrypoint.js",
                                                            "observer/source-gate","node/bin/node"))}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def _mode(path):
    return 0o555 if path in (WRAPPER,RUNTIME+"observer/source-gate",RUNTIME+"node/bin/node") else 0o444


def compose(predecessor, additions):
    need(predecessor["schema"] == split.SCHEMA, "different predecessor")
    rows = split._index(predecessor["entries"])
    for p, raw in additions.items():
        need(p not in rows and (p in STATIC or p.startswith(PREFIX) and
             re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*\.py",p[len(PREFIX):])), "collision or unapproved guest path")
        need(type(raw) is bytes and len(raw) <= 128 << 20, "invalid regular bytes")
        rows[p] = dict(path=p,type="file",uid=0,gid=0,mode=_mode(p),size=len(raw),sha256=sha256(raw))
        for parent in PurePosixPath(p).parents:
            name = str(parent)
            if name == "/":
                break
            if name not in rows:
                mode = 0o555 if name.startswith("/opt/aragorn/fixed-task") else 0o755
                rows[name] = split._dir(parent,mode)
            need(rows[name]["type"] == "dir", "non-directory guest parent")
    return dict(schema=split.SCHEMA,entries=[rows[p] for p in sorted(rows)])


def _base():
    return json.loads(split.image.read(BASE/"payload.json",BASE_PIN,2 << 20))


def project():
    """Consume reviewed pins, never approve the checkout or discovery results."""
    base = _base()
    before = split._index(base["entries"])
    read = split.image.read
    lock = json.loads(read(ASSETS/"task-guest-sources-v1.json", SOURCES_PIN, 65536))
    build = json.loads(read(ASSETS/"task-worker-v1/build.json", BUILD_PIN, 4096))
    need(read(WORKER/"receipt.json", BUILD_PIN, 4096) == canonical(build) + b"\n" and
         build["target_executed"] is False, "wrong worker preparation")
    data, pins = {}, {}
    for name, digest in sorted(lock["python"].items()):
        need(re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", name), "invalid pinned Python source")
        origin = ASSETS/"task-guest-v1" if name == "pi_core_task_guest_entry" else ROOT/"src/aragorn"
        raw = read(origin/(name+".py"),digest,4 << 20)
        pins["opt/aragorn/src/aragorn/"+name+".py"] = "sha256:"+digest
        data[PREFIX+name+".py"] = raw
    wrapper = read(ASSETS/"task-guest-v1/pi-fixed-task.py",lock["wrapper_template"],65536)
    need(wrapper.count(SOURCE_PIN_MARKER)==1, "missing or ambiguous source loader")
    data[WRAPPER] = wrapper.replace(SOURCE_PIN_MARKER,b"_ARAGORN_SOURCE_DIGESTS = "+repr(pins).encode("ascii")+b"\n")
    for path, source in ((UNIT,"task-guest-v1"),(PI_UNIT,"task-worker-v1")):
        name = PurePosixPath(path).name
        data[path] = read(ASSETS/source/name,lock["units"][name],16384)
    for name in ("node/bin/node","pi-core/package.json"):
        row = before[OLD_RUNTIME+name]
        data[RUNTIME+name] = read(BASE/"root"/row["path"][1:],row["sha256"],row["size"])
    for name, inner in (("source-gate","observer/source-gate"),("entrypoint.js","pi-core/entrypoint.js")):
        row = build["outputs"][name]
        data[RUNTIME+inner] = read(WORKER/name,row["sha256"],row["bytes"])
    need(set(data) == STATIC | {PREFIX+n+".py" for n in lock["python"]}, "incomplete package")
    manifest = compose(base,data)
    additions = [r for r in manifest["entries"] if r["path"] not in before]
    service_code = dict(unit_digest="sha256:"+sha256(data[UNIT]),wrapper_digest="sha256:"+sha256(data[WRAPPER]),
                        interpreter_digest="sha256:"+before[PYTHON]["sha256"])
    result = dict(schema="aragorn/pi-core-fixed-task-package/v1",base_payload_sha256=BASE_PIN,
                  payload_sha256=sha256(canonical(manifest)),entries=len(manifest["entries"]),
                  base_entries=len(before),added_paths=len(additions),delta_sha256=sha256(canonical(additions)),
                  service_code=service_code,service_sources_sha256=sha256(canonical(pins)),
                  worker_build_sha256=BUILD_PIN,booted=False,activated=False,phase3_exit_eligible=False)
    return manifest, data, result


def prepare():
    need(not os.path.lexists(OUT), "output already exists; no overwrite or automatic retry")
    need(OUT.parent.resolve(strict=True)==OUT.parent and OUT.parent.stat().st_uid==os.getuid()
         and not OUT.parent.stat().st_mode & 0o022,"unsafe private staging parent")
    manifest, data, result = project()
    receipt = split.image.read(CATALOG, CATALOG_PIN, 8192)
    need(result == json.loads(receipt), "projection differs from reviewed complete package")
    OUT.mkdir(mode=0o700)
    split._stage(OUT/"root",manifest,lambda r: data[r["path"]] if r["path"] in data else
                 previous._retained(BASE/"root",r["path"][1:],r))
    split.image.new(OUT/"payload.json",canonical(manifest))
    split.image.new(OUT/"receipt.json",receipt)
    return result


def readback():
    receipt = split.image.read(CATALOG,CATALOG_PIN,8192)
    need(split.image.read(OUT/"receipt.json",CATALOG_PIN,8192)==receipt,"private receipt differs")
    expected = json.loads(receipt)
    manifest = json.loads(split.image.read(OUT/"payload.json", expected["payload_sha256"],2 << 20))
    before, after = split._index(_base()["entries"]), split._index(manifest["entries"])
    delta = [after[k] for k in sorted(after.keys()-before.keys())]
    need(len(after) == expected["entries"] and len(delta)==expected["added_paths"] and
         all(after.get(k)==v for k,v in before.items()) and sha256(canonical(delta))==expected["delta_sha256"],
         "foreign successor layout or predecessor edits")
    split.image.check_physical(OUT/"root",manifest)
    return expected


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=("prepare","readback"))
    print(json.dumps((prepare if parser.parse_args().command=="prepare" else readback)(), sort_keys=True))
