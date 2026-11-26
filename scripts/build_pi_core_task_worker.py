"""Offline Pi fixed-task worker compiler. Never runs the guest."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from scripts import build_pi_core_linux as assets, build_pi_core_source_gate as gate
from scripts import build_pi_core_worker_bundle as bundler

ROOT = Path(__file__).resolve().parents[1]
GATE_BASE = "90156fce7c6eb95d30426567f8182a5273d00d7a579156b2e1c01243a98b9ab0"
BUNDLE_PROFILE = "80bafd44a14cba0063ebbba005cc9b2852a4ac88fcc42ff10135d300dc49ccdf"
SOURCES = {"paired-task.mjs": "991b2cfc7a3ec3e79a318c2dc8cc66c56e9050208d2d4420bd4d8b55d164b775",
           "task-worker-v1/main.mjs": "c376a3c9a4fcf9941f6a1dabf960496474c62fc008aeb19c76ba4fda6703f7c8"}
TASKDIR = "/run/aragorn-pi-bootstrap/tasks"
ENDPOINTS = (TASKDIR + "/control.sock", TASKDIR + "/service.sock")
BUILTINS = {"node:events", "node:fs", "node:net"}


def require(ok, why):
    if not ok:
        raise ValueError(why)


def pinned(path, digest, limit):
    raw = assets.regular_bytes(path, limit)
    require(assets.sha256(raw) == digest, "unexpected pinned input: " + str(path))
    return raw


def task_gate(base):
    """Keep the proven pre-exec checks and both stops, narrow the endpoint view."""
    require(assets.sha256(base) == GATE_BASE, "different predecessor gate source")
    for old, new in (
        (b"d.mode != 0040711", b"d.mode != 0040710"),
        (b'endpoint("/run/aragorn-pi-bootstrap/requests", "/run/aragorn-pi-bootstrap/requests/request.sock")',
         f'endpoint("{TASKDIR}", "{ENDPOINTS[0]}")'.encode()),
        (b'endpoint("/run/aragorn-pi-bootstrap/provider", "/run/aragorn-pi-bootstrap/provider/provider.sock")',
         f'endpoint("{TASKDIR}", "{ENDPOINTS[1]}")'.encode()),
    ):
        require(base.count(old) == 1, "predecessor socket guard changed")
        base = base.replace(old, new)
    return base


def _elf(root, scratch):
    _, base, clang, lld = gate.load_toolchain(root, root / assets.PACKAGE / "source-gate-toolchain-v3.json", gate.VIEW_TOOLCHAIN_PIN)
    new = task_gate(base)
    gate._write(scratch / "source-gate.c", new)
    budget = time.monotonic() + 30
    for argv, phase in zip(gate.commands(clang, lld, scratch), ("compile", "link"), strict=True):
        gate._command(argv, scratch, phase, budget, budget + 5, [])
    raw = assets.regular_bytes(scratch / "source-gate", 1024 * 1024)
    literals = set(gate.VIEW_LITERALS) - {s for s in gate.VIEW_LITERALS if s.startswith("/run/")}
    gate._check_gate_image(raw, literals | {TASKDIR, *ENDPOINTS})
    require(b"/requests/request.sock" not in raw and b"/provider/provider.sock" not in raw, "old endpoint in task gate")
    return raw, assets.sha256(new)


def _js(root, retained, scratch):
    pinned(root / bundler.PINS, BUNDLE_PROFILE, 16384)
    profile = bundler.load_profile(root)
    code = scratch / "input"
    code.mkdir()
    for name, digest in SOURCES.items():
        bundler._save_exclusive(code / Path(name).name, pinned(root / assets.PACKAGE / name, digest, 1 << 16))
    deps = code / "node_modules"
    shutil.copytree(bundler._dependency_root(retained, profile), deps, symlinks=True, copy_function=shutil.copyfile)
    require(assets.sha256(assets.canonical(assets.tree_inventory(deps))) == profile["dependency_tree_sha256"],
            "different staged Pi SDK dependency tree")
    sri = profile["archive"]["integrity"]
    hashed = base64.b64decode(sri.removeprefix("sha512-"), validate=True).hex()
    archive = bundler.tool_archive(Path.home()/".npm/_cacache/content-v2/sha512"/hashed[:2]/hashed[2:4]/hashed[4:], profile)
    assets.unpack(archive, scratch / "tool", "package", {profile["binary"]["member"]})
    binary = scratch / "tool/bin/esbuild"
    pinned(binary, profile["binary"]["sha256"], 16 << 20)
    binary.chmod(0o500)
    sandbox = Path(profile["sandbox"]["path"])
    pinned(sandbox, profile["sandbox"]["sha256"], 1 << 20)
    out = scratch / "out"
    out.mkdir()
    args = ["input/main.mjs", "--bundle", "--platform=node", "--target=node24.22", "--format=esm",
            "--tree-shaking=true", "--charset=utf8", "--legal-comments=inline", "--color=false",
            "--log-level=warning", "--outfile=out/entrypoint.js", "--metafile=out/meta.json"]
    with tempfile.TemporaryFile() as diag:
        result = subprocess.run([str(sandbox), "-p", bundler._sandbox(scratch, binary), str(binary), *args],
            cwd=scratch, env={"HOME":"/nonexistent","PATH":"/nonexistent","LANG":"C","LC_ALL":"C","TZ":"UTC","GOMAXPROCS":"2"},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=diag, timeout=profile["sandbox"]["timeout_seconds"])
        if result.returncode:
            diag.seek(0)
            raise ValueError(f"pinned task bundler exited {result.returncode}: " + diag.read(2048).decode(errors="replace"))
    require({p.name for p in out.iterdir()} == {"entrypoint.js", "meta.json"}, "unexpected emitted files")
    meta = json.loads(assets.regular_bytes(out / "meta.json", 8 << 20))
    require(set(meta["outputs"]) == {"out/entrypoint.js"}, "multiple task outputs")
    info = meta["outputs"]["out/entrypoint.js"]
    require(info["entryPoint"] == "input/main.mjs" and not info["exports"] and all(info["inputs"][n]["bytesInOutput"] > 0
        for n in ("input/main.mjs", "input/paired-task.mjs", "input/node_modules/@earendil-works/pi-agent-core/dist/agent-loop.js")),
        "fixed task entry, carrier or actual Pi implementation missing")
    require(all(row["kind"] == "import-statement" and row["external"] is True for row in info["imports"])
            and {r["path"] for r in info["imports"]} == BUILTINS, "undeclared module dependency: " + str(info["imports"]))
    raw = assets.regular_bytes(out / "entrypoint.js", 8 << 20)
    require(len(raw) == info["bytes"], "emitted size mismatch")
    return raw, profile["dependency_tree_sha256"], assets.sha256(assets.canonical(meta))


def build(root, retained, output):
    root, retained = root.resolve(strict=True), retained.resolve(strict=True)
    require(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
            and output.parent == root / ".aragorn" and not output.name.startswith("."), "private developer output required")
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    with tempfile.TemporaryDirectory(prefix="aragorn-task-worker-") as name:
        scratch = Path(name).resolve(strict=True)
        elf, gate_source = _elf(root, scratch)
        js, dependencies, meta = _js(root, retained, scratch)
    outputs = {"source-gate":elf, "entrypoint.js":js}
    receipt = dict(schema="aragorn/pi-core-task-worker-preparation/v1", gate_source_sha256=gate_source,
        gate_toolchain=gate.VIEW_TOOLCHAIN_PIN, sources=SOURCES, bundle_profile_sha256=BUNDLE_PROFILE,
        dependency_tree_sha256=dependencies, metafile_sha256=meta, external_modules=sorted(BUILTINS),
        outputs={n:{"bytes":len(v),"sha256":assets.sha256(v)} for n,v in outputs.items()}, target_executed=False)
    output.mkdir(mode=0o700)
    for name, raw in outputs.items():
        bundler._save_exclusive(output / name, raw)
        (output / name).chmod(0o400)
    bundler._save_exclusive(output / "receipt.json", assets.canonical(receipt) + b"\n")
    return receipt


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--retained-repo", type=Path, required=True)
    cli.add_argument("--output", type=Path, required=True)
    arguments = cli.parse_args()
    print(json.dumps(build(ROOT, arguments.retained_repo, arguments.output), sort_keys=True))
