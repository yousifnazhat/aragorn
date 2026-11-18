"""Offline build-only compiler. Never run the generated worker or a package hook."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

if __package__:
    from . import build_pi_core_linux as previous
else:
    import build_pi_core_linux as previous

ROOT, BuildError, require = previous.ROOT, previous.BuildError, previous.require
PINS = "packaging/pi-core/worker-bundle-toolchain-v1.json"
CHECKPOINT = "packaging/pi-core/compiled-artifact-v3.json"
DYLD_SUPPORT = Path("/System/Library/Sandbox/Profiles/dyld-support.sb")
DYLD_SUPPORT_SHA256 = "06215a5d32689aefe395c29710e182eb54ba22162f50df8b4842290f8a19bf1c"
SOURCE_NAMES = frozenset(f"{previous.PACKAGE}/{name}" for name in previous.SOURCES) | {
    f"{previous.LEGACY}/index.js", f"{previous.LEGACY}/package.json"}
OPTIONS = ("input/pi-core/entrypoint.ts", "--bundle", "--platform=node", "--target=node24.22", "--format=esm",
    "--tree-shaking=true", "--charset=utf8", "--legal-comments=inline", "--tsconfig=input/pi-core/tsconfig.json",
    "--log-level=warning", "--color=false", "--outfile=out/entrypoint.js", "--metafile=out/meta.json")


def load_profile(root: Path) -> dict:
    pins = json.loads(previous.regular_bytes(root / PINS, 16384))
    require(pins["schema"] == "aragorn/pi-core-worker-bundle-toolchain/v1" and
            pins["purpose"] == "BUILD_ONLY_DARWIN_ARM64_TO_NODE24_ESM_NOT_RUNTIME_AUTHORITY" and
            pins["archive"]["package"] == "@esbuild/darwin-arm64@0.27.0" and
            pins["binary"]["member"] == "package/bin/esbuild" and pins["sandbox"]["path"] == "/usr/bin/sandbox-exec" and
            pins["sandbox"]["profile"] == "PI_PRIVATE_TREE_DEFAULT_DENY_V1" and
            pins["sandbox"]["timeout_seconds"] == 60 and pins["options"] == list(OPTIONS),
            "unreviewed compiler, sandbox or argument profile")
    return pins


def read_sources(root: Path, pins: dict) -> dict[str, bytes]:
    require(set(pins["sources"]) == SOURCE_NAMES, "incomplete or unexpected worker source pin")
    sources = {}
    for name in sorted(SOURCE_NAMES):
        raw = previous.regular_bytes(root / name, 4 << 20)
        require(previous.sha256(raw) == pins["sources"][name], f"source digest mismatch: {name}")
        sources[name] = raw
    return sources


def tool_archive(path: Path, pins: dict) -> bytes:
    spec = pins["archive"]
    raw = previous.regular_bytes(path, 8 << 20)
    require(len(raw) == spec["bytes"] and previous.sha256(raw) == spec["sha256"] and
            "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode("ascii") == spec["integrity"],
            "bundler archive digest or size mismatch")
    return raw


def _once(raw, before, after):
    require(raw.count(before) == 1, "pinned legacy bridge shape changed")
    return raw.replace(before, after, 1)


def adapt_source(path: str, raw: bytes) -> bytes:
    """Only map the known local CJS bridge; never replace upstream runtime loads."""
    if path == f"{previous.LEGACY}/index.js":
        for fields, module in ((b"createHash", b"crypto"), (b"lstatSync, realpathSync, statSync", b"fs"),
                (b"createConnection", b"net"), (b"dirname, isAbsolute", b"path"), (b"TextDecoder", b"util")):
            # Default builtin object + destructuring preserves CJS value capture,
            # including any subsequent assignments to that object's properties.
            before = b'const { ' + fields + b' } = require("node:' + module + b'");'
            after = b'import builtin_' + module + b' from "node:' + module + b'";\nconst { ' + fields + b' } = builtin_' + module + b';'
            raw = _once(raw, before, after)
        return _once(raw, b"module.exports = {", b"export default {")
    if path in {f"{previous.PACKAGE}/{name}.ts" for name in ("entrypoint", "worker", "provider")}:
        raw = _once(raw, b'import { createRequire } from "node:module";',
                    b'import legacyModule from "../openclaw/aragorn-runtime-action-worker/index.mjs";')
        raw = _once(raw, b"const require = createRequire(import.meta.url);\n", b"")
        return _once(raw, b'require("../openclaw/aragorn-runtime-action-worker/index.js").__testing',
                     b"legacyModule.__testing")
    return raw


def _dependency_root(root, pins):
    checkpoint = json.loads(previous.regular_bytes(root / CHECKPOINT, 32768))
    name = pins["predecessor_receipt"]
    require(name == checkpoint["receipt_local_path"] and Path(name).parts[:2] == (".aragorn", "pi-core-build") and
            ".." not in Path(name).parts and Path(name).name == "build-receipt.json", "unsafe retained input path")
    path = root / name
    raw = previous.regular_bytes(path, 4 << 20)
    require(previous.sha256(raw) == pins["predecessor_receipt_sha256"] == checkpoint["receipt_file_sha256"] and
            json.loads(raw)["inputs"]["runtime_dependency_tree_sha256"] == pins["dependency_tree_sha256"] ==
            checkpoint["inputs"]["runtime_dependency_tree_sha256"], "retained dependency receipt mismatch")
    return path.parent / "deployment/pi-core/node_modules"


def _scratch_inputs(scratch, root, pins, sources):
    staged = {}
    for name, original in sources.items():
        rel = "input/" + name.removeprefix("packaging/")
        if name == f"{previous.LEGACY}/index.js":
            rel = rel.removesuffix(".js") + ".mjs"
        data = adapt_source(name, original)
        if data is not original and name.endswith((".js", ".ts")):
            require(previous.sha256(original) == pins["sources"][name], "unreviewed adapter bridge input")
        path = scratch / rel
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
        staged[rel] = previous.sha256(data)
    deps = scratch / "input/pi-core/node_modules"
    # Verify the copied bytes (not just the mutable source directory); preserve
    # links for inventory validation and never let the compiler see the repo.
    shutil.copytree(_dependency_root(root, pins), deps, symlinks=True, copy_function=shutil.copyfile)
    require(previous.sha256(previous.canonical(previous.tree_inventory(deps))) == pins["dependency_tree_sha256"],
            "staged dependency tree digest mismatch")
    return staged


def _sandbox(scratch, binary):
    # libignition opens "/" and reads the sealed cryptex grafts during dyld
    # bootstrap, before the compiler's main. Inline the reviewed bytes; never
    # import system.sb or re-resolve a potentially different profile at exec.
    dyld = previous.regular_bytes(DYLD_SUPPORT, 16384)
    require(previous.sha256(dyld) == DYLD_SUPPORT_SHA256, "OS loader sandbox profile differs from pin")
    header = b"\n(version 3)\n"
    require(dyld.count(header) == 1, "unexpected OS loader sandbox header")
    loader_rules = dyld.split(header, 1)[1].decode("ascii")
    q = lambda value: json.dumps(str(value), ensure_ascii=False)
    # Only OS runtime libraries and this private input tree are readable. Permit
    # stat of specific ancestors for getcwd, never their contents or siblings.
    ancestors = " ".join("(literal " + q(p) + ")" for p in binary.parents)
    runtime = '(subpath "/usr/lib") (subpath "/System/Library")'
    return f"""(version 1)
(deny default)
{loader_rules}
(allow sysctl-read)
(allow process-info* (target self))
(allow process-exec (literal {q(binary)}))
(allow file-read-metadata {ancestors})
; esbuild resolves relative argv by enumerating its cwd. List exactly this
; private directory (input/out/tool names), never its parent or its siblings.
(allow file-read-data file-test-existence (literal {q(scratch)}))
(allow file-read* {runtime} (literal "/dev/null") (literal "/dev/urandom") (literal {q(binary)})
 (subpath {q(scratch / "input")}) (subpath {q(scratch / "out")}))
(allow file-map-executable {runtime} (literal {q(binary)}))
(allow file-write* (subpath {q(scratch / "out")}))
"""


def _save_exclusive(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)


def build(output: Path, *, root: Path = ROOT) -> dict:
    """Emit one candidate into a fresh directory. A build receipt is not verification."""
    root = root.resolve(strict=True)
    build_root = root / ".aragorn/pi-core-build"
    output = output.absolute()
    require(build_root.is_dir() and build_root.resolve(strict=True) == build_root and ".." not in output.parts and
            output.parent.is_relative_to(build_root) and output.parent.resolve(strict=True) == output.parent and
            output.parent.is_dir(), "fresh named output under the nonsymlinked owned build root required")
    require(not output.exists() and not output.is_symlink(), "output already exists")
    output.mkdir(mode=0o700)
    try:
        loaded = {"scripts/build_pi_core_worker_bundle.py": Path(__file__),
                  "scripts/build_pi_core_linux.py": Path(previous.__file__)}
        recipes = {name: previous.sha256(previous.regular_bytes(path, 1 << 20)) for name, path in loaded.items()}
        require(all(previous.sha256(previous.regular_bytes(root / name, 1 << 20)) == value
                    for name, value in recipes.items()), "build recipe differs from selected checkout")
        pins = load_profile(root)
        profile_raw = previous.regular_bytes(root / PINS, 16384)
        require(json.loads(profile_raw) == pins, "toolchain profile changed during read")
        sources = read_sources(root, pins)
        sri = pins["archive"]["integrity"]
        require(sri.startswith("sha512-"), "unsupported tool archive identity")
        digest = base64.b64decode(sri[7:], validate=True).hex()
        cache = Path.home() / ".npm/_cacache/content-v2/sha512" / digest[:2] / digest[2:4] / digest[4:]
        archive = tool_archive(cache, pins)
        sandbox = Path(pins["sandbox"]["path"])
        require(previous.sha256(previous.regular_bytes(sandbox, 1 << 20)) == pins["sandbox"]["sha256"],
                "build sandbox executable differs from pin")
        with tempfile.TemporaryDirectory(prefix="aragorn-worker-bundle-") as temp:
            scratch = Path(temp).resolve(strict=True)
            staged = _scratch_inputs(scratch, root, pins, sources)
            previous.unpack(archive, scratch / "tool", "package", {pins["binary"]["member"]})
            binary = scratch / "tool/bin/esbuild"
            tool = previous.regular_bytes(binary, 16 << 20)
            require(len(tool) == pins["binary"]["bytes"] and previous.sha256(tool) == pins["binary"]["sha256"],
                    "build binary differs from pin")
            binary.chmod(0o500)
            emitted = scratch / "out"
            emitted.mkdir(mode=0o700)
            with tempfile.TemporaryFile() as diagnostic:
                proc = subprocess.run([str(sandbox), "-p", _sandbox(scratch, binary), str(binary), *OPTIONS],
                    cwd=scratch, env={"HOME": "/nonexistent", "PATH": "/nonexistent", "LANG": "C", "LC_ALL": "C",
                                     "TZ": "UTC", "GOMAXPROCS": "2"}, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=diagnostic, timeout=pins["sandbox"]["timeout_seconds"], check=False)
                if proc.returncode:
                    diagnostic.seek(0)
                    raise BuildError(f"confined bundler exited {proc.returncode}: " +
                                     diagnostic.read(32768).decode("utf-8", "replace"))
            require({p.name for p in emitted.iterdir()} == {"entrypoint.js", "meta.json"}, "unexpected emitted files")
            outputs = {}
            for name in ("entrypoint.js", "meta.json"):
                raw = previous.regular_bytes(emitted / name, 16 << 20)
                require(bool(raw), f"empty build output: {name}")
                _save_exclusive(output / name, raw)
                outputs[name] = {"bytes": len(raw), "sha256": previous.sha256(raw)}
        receipt = {"schema": "aragorn/pi-core-worker-bundle-build/v1", "status": "EMITTED_NOT_VERIFIED_OR_DEPLOYED",
            "toolchain_sha256": previous.sha256(profile_raw), "tool_archive_sha256": previous.sha256(archive),
            "tool_binary_sha256": previous.sha256(tool), "sources": pins["sources"], "staged_sources": staged,
            "dependency_tree_sha256": pins["dependency_tree_sha256"], "recipes": recipes, "outputs": outputs,
            "target_executed": False, "phase3_exit_eligible": False}
        require(all(previous.sha256(previous.regular_bytes(root / name, 1 << 20)) == value
                    for name, value in recipes.items()), "build recipe changed during emission")
        _save_exclusive(output / "receipt.json", previous.canonical(receipt) + b"\n")
        return receipt
    except BaseException as error:
        # Keep output prefixes and bounded diagnostic. Never overwrite or retry.
        try:
            _save_exclusive(output / "refusal.json", previous.canonical({"schema": "aragorn/pi-core-worker-bundle-refusal/v1",
                "reason": str(error)[:32768], "target_executed": False, "phase3_exit_eligible": False}) + b"\n")
        except BaseException:
            pass
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    print(json.dumps(build(parser.parse_args().output), sort_keys=True))
