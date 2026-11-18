"""Independent developer build verifier. No emitted module is ever run or linked."""

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "packaging/pi-core/worker-bundle-toolchain-v1.json"
PROFILE_PIN = "80bafd44a14cba0063ebbba005cc9b2852a4ac88fcc42ff10135d300dc49ccdf"
CHECKPOINT = "packaging/pi-core/compiled-artifact-v3.json"
V3 = "1bfae9d5726f1ea61dbc70d58867c8666e4fc4318a7a92ccff160cc0c6e544fc"
TREE = "4ea4f2b7eb5408dbe64682a99c9921d42855faa69fdb4511328c444e4afed359"
ESBUILD = "734cac3a18b8b5ed6a9a0e73f227ab94321f2859d2e65d700d83d19121860ee6"
TARBALL = "58044064b395eb3f9a2aececc5518f29a8590533756a0bbcc5fcd228227af270"
NODE = Path("/opt/homebrew/Cellar/node/26.3.1/bin/node")
PARSER = Path("/opt/homebrew/lib/node_modules/vercel/node_modules/acorn/dist/acorn.js")
PARSER_TOOLS = {NODE: "56694c81b093cc8da273fa017cf91765b3653e5f64f16727976ffaa87b2b6b31",
    NODE.parents[1] / "lib/libnode.147.dylib": "7cf4fe248871a346d50de8475a03327244a304924825c5b24c474167444e5c75",
    PARSER: "b373ccd10e9deb63654289f73216eeefcaf0405d9ee24289aabf596b91b4c318"}
BUILTINS = {"node:crypto", "node:fs", "node:net", "node:path", "node:perf_hooks", "node:url", "node:util"}
ENTRY = "input/pi-core/entrypoint.ts"
BRIDGE = "input/openclaw/aragorn-runtime-action-worker/index.mjs"
CURRENT = {"packaging/pi-core/" + n for n in ("entrypoint.ts", "worker.ts", "provider.ts", "tsconfig.json",
    "package.json", "package-lock.json")} | {"packaging/openclaw/aragorn-runtime-action-worker/" + n
    for n in ("index.js", "package.json")}
RECIPES = ("scripts/build_pi_core_worker_bundle.py", "scripts/build_pi_core_linux.py")
ARTIFACTS = {"entrypoint.js", "meta.json", "receipt.json"}
ENTRY_EXPORTS = {"BOOTSTRAP_SOCKET", "MAX_BOOTSTRAP_FRAME_BYTES", "encodeBootstrapFrame", "decodeBootstrapFrame",
                 "parseStart", "runPreparedPiEntry", "runPreparedNativePiEntry", "runProtectedNativePiEntry",
                 "runBootstrapChannel"}


class BundleVerificationError(ValueError):
    pass


def _check(ok, reason):
    if not ok:
        raise BundleVerificationError(reason)


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _json(raw):
    def pairs(items):
        obj = dict(items)
        _check(len(obj) == len(items), "duplicate JSON key")
        return obj
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(BundleVerificationError("invalid JSON number")))


def _read(path, maximum=16 << 20, *, empty=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        def ident(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size,
                    value.st_ctime_ns, value.st_mtime_ns)
        before = os.fstat(fd)
        _check(stat.S_ISREG(before.st_mode) and (0 if empty else 1) <= before.st_size <= maximum,
               "invalid build input: " + str(path))
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(before.st_size + 1)
        _check(len(raw) == before.st_size and ident(before) == ident(os.fstat(fd)) == ident(path.lstat()),
               "build file changed: " + str(path))
        return raw
    finally:
        os.close(fd)


def inspect_js(raw: bytes) -> dict:
    """Parse attacker-controlled text as data; never evaluate or import it."""
    return _inspect(raw, None)


def _inspect(raw, restricted):
    _check(type(raw) is bytes and 0 < len(raw) <= 8 << 20, "invalid candidate length")
    suffix = []
    if restricted is not None:
        _check(_hash(raw) == restricted.BUNDLE_SHA256, "unreviewed restricted bundle")
        suffix = ["--", "restricted-gate-v2"]
    try:
        for path, pin in PARSER_TOOLS.items():
            _check(_hash(_read(path, 96 << 20)) == pin, "inspection tool pin mismatch: " + str(path))
        helper = _read(Path(__file__).with_name("inspect_pi_core_worker_bundle.cjs"), 64 << 10)
        proc = subprocess.run([str(NODE), "--no-addons", "--no-warnings", "--input-type=commonjs",
            "--eval", helper.decode("utf-8"), *suffix], input=raw, capture_output=True, cwd="/", env={"LC_ALL": "C"},
            check=False, timeout=25)
        _check(proc.returncode == 0 and 0 < len(proc.stdout) <= 32768, "JavaScript parse/inspection refused")
        row = _json(proc.stdout)
        keys = {"nodes", "static_builtins", "exports", "failures", "counts"}
        if restricted is not None:
            keys.add("restricted_review")
            names = row.get("restricted_review")
            _check(type(names) is list and len(names) == len(set(names)) == 32 and "CreateDynamicCheck" in names,
                   "missing restricted syntax or fallback evidence")
        _check(set(row) == keys and type(row["nodes"]) is int
               and row["nodes"] > 0 and isinstance(row["failures"], list) and isinstance(row["counts"], dict)
               and set(row["static_builtins"]) <= BUILTINS, "malformed inspection result")
        _check(not row["counts"] and not row["failures"], "emitted AST requires review: " +
               _canonical({"counts": row["counts"], "locations": row["failures"]}).decode())
        return {**row, "parser_sha256": PARSER_TOOLS[PARSER], "inspection_recipe_sha256": _hash(helper)}
    except BundleVerificationError:
        raise
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as e:
        raise BundleVerificationError("static parser unavailable or result invalid") from e


def _adapt(name, raw):
    # Independent reconstruction of the restricted bridge, never producer helper output.
    if name.endswith(".ts"):
        rows = raw.splitlines(keepends=True)
        before = b'import { createRequire } from "node:module";\n'
        binding = b'const require = createRequire(import.meta.url);\n'
        call = b'require("../openclaw/aragorn-runtime-action-worker/index.js").__testing'
        _check(rows.count(before) == rows.count(binding) == raw.count(call) == 1, "adapter source shape changed")
        rows[rows.index(before)] = b'import legacyModule from "../openclaw/aragorn-runtime-action-worker/index.mjs";\n'
        rows.remove(binding)
        return b"".join(rows).replace(call, b"legacyModule.__testing")
    if not name.endswith("/index.js"):
        return raw
    seen = set()
    result = []
    for line in raw.splitlines(keepends=True):
        match = re.fullmatch(rb'const \{ (\w+(?:, \w+)*) \} = require\("node:(\w+)"\);\n', line)
        if match:
            fields, module = match.groups()
            _check(module not in seen, "duplicate legacy builtin")
            seen.add(module)
            result.append(b'import builtin_' + module + b' from "node:' + module + b'";\n')
            line = b"const { " + fields + b" } = builtin_" + module + b";\n"
        result.append(line)
    value = b"".join(result)
    _check(seen == {b"crypto", b"fs", b"net", b"path", b"util"} and value.count(b"module.exports = {") == 1,
           "legacy bridge shape changed")
    return value.replace(b"module.exports = {", b"export default {")


def _meta(meta: dict, sizes: dict, output: bytes, external: list) -> None:
    _check(type(meta) is dict and set(meta) == {"inputs", "outputs"}, "unexpected metadata fields")
    ins, outs = meta["inputs"], meta["outputs"]
    _check(type(ins) is dict and len(ins) <= 16000 and {ENTRY, "input/pi-core/worker.ts",
           "input/pi-core/provider.ts", BRIDGE} <= set(ins) <= set(sizes), "missing or unbound compiler input")
    _check(type(outs) is dict and set(outs) == {"out/entrypoint.js"}, "unexpected compiler outputs")
    reachable, pending = set(), [ENTRY]
    for path, record in ins.items():
        _check(type(record) is dict and set(record) <= {"bytes", "format", "imports"} and
               type(record.get("bytes")) is int and record["bytes"] == sizes[path] and
               type(record.get("imports")) is list, "compiler input length or fields differ: " + path)
    while pending:
        path = pending.pop()
        if path in reachable:
            continue
        reachable.add(path)
        for edge in ins[path]["imports"]:
            _check(type(edge) is dict and type(edge.get("path")) is str and type(edge.get("kind")) is str
                   and set(edge) <= {"path", "kind", "external", "original", "with"}
                   and type(edge.get("external", False)) is bool, "malformed compiler edge")
            if edge.get("external"):
                # Discarded declarations are not evidence that the emitted ESM loads them.
                continue
            _check(edge["path"] in ins, "unbound internal compiler edge")
            pending.append(edge["path"])
    _check(reachable == set(ins), "disconnected compiler input")
    out = outs["out/entrypoint.js"]
    _check(set(out) == {"imports", "exports", "entryPoint", "inputs", "bytes"} and out["entryPoint"] == ENTRY
           and type(out["bytes"]) is int and out["bytes"] == len(output) and type(out["inputs"]) is dict and
           type(out["imports"]) is list and set(out["inputs"]) <= set(ins), "emitted entrypoint metadata differs")
    total = 0
    for row in out["inputs"].values():
        _check(set(row) == {"bytesInOutput"} and type(row["bytesInOutput"]) is int and row["bytesInOutput"] >= 0,
               "invalid emitted byte attribution")
        total += row["bytesInOutput"]
    _check(0 < total <= len(output) and all(out["inputs"].get(n, {}).get("bytesInOutput", 0) > 0
           for n in (ENTRY, "input/pi-core/worker.ts", "input/pi-core/provider.ts", BRIDGE)),
           "missing connected provider, worker or bridge implementation")
    _check(all(type(x) is dict and set(x) == {"path", "kind", "external"} and
               x["external"] is True and x["kind"] == "import-statement" and x["path"] in BUILTINS
               for x in out["imports"]), "unapproved emitted metadata external")
    _check(sorted({x["path"] for x in out["imports"]}) == sorted(external), "AST/metadata external mismatch")


def _provenance(root, receipt, compiler_inputs):
    profile_raw = _read(root / PROFILE, 32768)
    _check(_hash(profile_raw) == PROFILE_PIN, "reviewed build profile changed")
    profile = _json(profile_raw)
    checkpoint = _json(_read(root / CHECKPOINT, 32768))
    _check(receipt["toolchain_sha256"] == _hash(profile_raw) and
           receipt["tool_archive_sha256"] == profile["archive"]["sha256"] == TARBALL and
           receipt["tool_binary_sha256"] == profile["binary"]["sha256"] == ESBUILD and
           receipt["dependency_tree_sha256"] == profile["dependency_tree_sha256"] == TREE,
           "toolchain or dependency pin mismatch")
    sri = profile["archive"]["integrity"]
    _check(sri.startswith("sha512-"), "wrong build archive SRI")
    addr = base64.b64decode(sri[7:], validate=True).hex()
    archive = _read(Path.home() / ".npm/_cacache/content-v2/sha512" / addr[:2] / addr[2:4] / addr[4:], 8 << 20)
    _check(hashlib.sha512(archive).hexdigest() == addr and _hash(archive) == TARBALL, "actual builder archive changed")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        members = [x for x in tar if x.name == "package/bin/esbuild"]
        _check(len(members) == 1 and members[0].isreg() and members[0].size == profile["binary"]["bytes"] < 16 << 20,
               "unexpected compiler binary in archive")
        _check(_hash(tar.extractfile(members[0]).read()) == ESBUILD, "actual compiler binary changed")
    _check(set(profile["sources"]) == CURRENT and receipt["sources"] == profile["sources"], "changed source inventory")
    _check(receipt["recipes"] == {n: _hash(_read(root / n)) for n in RECIPES}, "build recipe changed")
    staged, sizes = {}, {}
    for name, pin in profile["sources"].items():
        raw = _read(root / name)
        _check(_hash(raw) == pin, "source bytes changed: " + name)
        rel = "input/" + name.removeprefix("packaging/")
        if name.endswith("/index.js"):
            rel = BRIDGE
        adapted = _adapt(name, raw)
        staged[rel], sizes[rel] = _hash(adapted), len(adapted)
    _check(receipt["staged_sources"] == staged, "adapted inputs do not match independently reconstructed bridge")
    path = checkpoint["receipt_local_path"]
    _check(path == ".aragorn/pi-core-build/d2-73e34727a1f04044a7b74381e5bbb32d/build-receipt.json" and
           path == profile["predecessor_receipt"], "unreviewed predecessor")
    raw = _read(root / path, 4 << 20)
    _check(_hash(raw) == V3 == checkpoint["receipt_file_sha256"] == profile["predecessor_receipt_sha256"],
           "dependency source receipt differs")
    inventory = _json(raw)["deployment_inventory"]
    prefix = "pi-core/node_modules/"
    rows = [dict(row, path=row["path"][len(prefix):]) for row in inventory if row["path"].startswith(prefix)]
    _check(_hash(_canonical(rows)) == TREE, "retained dependency inventory does not reproduce")
    dep_root = root / Path(path).parent / "deployment/pi-core/node_modules"
    for row in rows:
        if row["kind"] == "file":
            key = "input/" + prefix + row["path"]
            sizes[key] = row["bytes"]
            if key in compiler_inputs:
                member = dep_root / row["path"]
                _check(member.resolve(strict=True) == member and
                       _hash(_read(member, 16 << 20, empty=True)) == row["sha256"],
                       "compiled predecessor dependency bytes differ: " + row["path"])
    return sizes


def _verified(directory, root, restricted=None):
    _check(not directory.is_symlink() and directory.is_dir() and
           directory.resolve().is_relative_to((root / ".aragorn/pi-core-build").resolve(strict=True)),
           "output must be an owned build directory")
    _check({p.name for p in directory.iterdir()} == ARTIFACTS and
           all((directory / n).lstat().st_nlink == 1 for n in ARTIFACTS), "unexpected or linked build artifacts")
    js, meta_raw, raw = (_read(directory/n) for n in ("entrypoint.js", "meta.json", "receipt.json"))
    if restricted is not None:
        _check((_hash(js), _hash(meta_raw), _hash(raw)) == (
            restricted.BUNDLE_SHA256, restricted.META_SHA256, restricted.BUNDLE_RECEIPT_SHA256),
            "restricted retained product substitution")
    receipt, meta = _json(raw), _json(meta_raw)
    _check(type(receipt) is dict and set(receipt) == {"schema", "status", "toolchain_sha256",
           "tool_archive_sha256", "tool_binary_sha256", "sources", "staged_sources", "recipes",
           "dependency_tree_sha256", "outputs", "target_executed", "phase3_exit_eligible"} and
           raw == _canonical(receipt) + b"\n" and receipt["schema"] == "aragorn/pi-core-worker-bundle-build/v1"
           and receipt["status"] == "EMITTED_NOT_VERIFIED_OR_DEPLOYED" and receipt["target_executed"] is False
           and receipt["phase3_exit_eligible"] is False, "invalid canonical build receipt")
    outputs = {n: {"bytes": len(b), "sha256": _hash(b)} for n,b in (("entrypoint.js", js), ("meta.json", meta_raw))}
    _check(_canonical(outputs) == _canonical(receipt["outputs"]), "emitted bytes or metadata changed")
    sizes = _provenance(root.resolve(strict=True), receipt, meta["inputs"])
    parsed = inspect_js(js) if restricted is None else _inspect(js, restricted)
    _meta(meta, sizes, js, parsed["static_builtins"])
    _check(parsed["exports"] == sorted(ENTRY_EXPORTS) ==
           sorted(meta["outputs"]["out/entrypoint.js"]["exports"]), "protected entrypoint exports differ")
    return {"schema":"aragorn/pi-core-worker-bundle-verification/v1", "status": "INSPECTED_NOT_DEPLOYED",
            "outputs": outputs, "build_receipt_sha256": _hash(raw), "static_inspection": parsed,
            "claim": "STATIC_EMITTED_MODULE_SURFACE_ONLY", "build_invocation_attested_by_bytes": False,
            "source_consumption_observed": False, "runtime_behavior_verified": False,
            "target_executed": False, "phase3_exit_eligible": False}


def verify_one(first: Path, *, root=ROOT) -> dict:
    try:
        return _verified(Path(first), Path(root))
    except BundleVerificationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, tarfile.TarError) as exc:
        raise BundleVerificationError("unbound build inputs or malformed evidence: " + type(exc).__name__) from exc


def verify_restricted(directory, gate_build, node_argv, *, root=ROOT):
    """Condition the static surface review on the approved gate; not a runtime observation."""
    from aragorn import pi_core_restricted_profile as fixed

    try:
        _check(type(node_argv) in (tuple, list) and tuple(node_argv) == fixed.NODE_ARGV, "restricted Node argv differs")
        fixed.validate_gate(gate_build)
        report = _verified(Path(directory), Path(root), fixed)
        return {**report, "status": "INSPECTED_RESTRICTED_NOT_DEPLOYED",
                "claim": "STATIC_MODULE_SURFACE_CONDITIONAL_ON_RESTRICTED_LAUNCH",
                "node_argv": list(fixed.NODE_ARGV), "node_sha256": fixed.NODE_SHA256,
                "gate_receipt_digest": "sha256:" + fixed.GATE_RECEIPT_SHA256,
                "restricted_gate_elf_sha256": fixed.GATE_SHA256,
                "runtime_enforcement_observed": False, "interpreted_validator_observed": False}
    except BundleVerificationError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, tarfile.TarError) as exc:
        raise BundleVerificationError("invalid restricted launch or build evidence: " + str(exc)[:256]) from exc


def verify(first: Path, second: Path, *, root=ROOT) -> dict:
    try:
        _check(not os.path.samefile(first, second), "two distinct fresh build directories required")
    except OSError as exc:
        raise BundleVerificationError("two existing build directories required") from exc
    a, b = verify_one(first, root=root), verify_one(second, root=root)
    _check(a == b, "independent emissions are not byte-reproducible")
    return {**a, "status": "REPRODUCED_NOT_DEPLOYED", "invocation_independence_attested_by_bytes": False}
