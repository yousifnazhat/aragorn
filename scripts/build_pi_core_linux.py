"""Fixed offline Linux compiler assembly; never execute an Aragorn worker.

Consumes reviewed archives and the already prepared 89-package tree. Only the
static, pinned arm64 TypeScript compiler executes in an owned scratch container
on an already-running colima daemon. No pull, npm resolution, lifecycle script,
VM startup, service activation or OS-qualification claim is permitted here.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
PINS = "docs/design/pi-core-dependency-pins-v1.json"
PACKAGE = "packaging/pi-core"
LEGACY = "packaging/openclaw/aragorn-runtime-action-worker"
DOCKER = "/opt/homebrew/bin/docker"
CONTEXT = "colima"
LABEL = "org.aragorn.pi-core-build"
MAX_ARCHIVE = 512 * 1024 * 1024
SOURCES = ("worker.ts", "entrypoint.ts", "provider.ts", "package.json", "package-lock.json", "tsconfig.json")


class BuildError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildError(message)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def regular_bytes(path: Path, limit: int = MAX_ARCHIVE) -> bytes:
    # No path-following open at the leaf; identity comparison detects replacement
    # while reading. This is developer input custody, not a hostile-host boundary.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, f"invalid regular input: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        require(len(raw) == before.st_size and identity(before) == identity(after), f"input changed while reading: {path}")
        return raw
    finally:
        os.close(fd)


def tree_inventory(root: Path) -> list[dict]:
    require(root.is_dir() and not root.is_symlink(), "missing or linked dependency directory")
    rows: list[dict] = []

    def visit(directory: Path) -> None:
        for path in directory.iterdir():
            relative = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                target = os.readlink(path)
                require(not os.path.isabs(target), f"absolute dependency link: {relative}")
                require(path.resolve().is_relative_to(root.resolve()), f"escaping dependency link: {relative}")
                rows.append({"path": relative, "kind": "symlink", "target": target})
            elif stat.S_ISDIR(mode):
                visit(path)
            elif stat.S_ISREG(mode):
                raw = regular_bytes(path)
                rows.append({"path": relative, "kind": "file", "bytes": len(raw), "sha256": sha256(raw)})
            else:
                raise BuildError(f"unsupported dependency entry: {relative}")

    visit(root)
    require(bool(rows), "empty dependency tree")
    return sorted(rows, key=lambda row: row["path"])


def verified_archive(path: Path, integrity: str) -> bytes:
    raw = regular_bytes(path)
    algorithm, expected = integrity.split("-", 1)
    require(algorithm in ("sha256", "sha512"), "unsupported archive integrity algorithm")
    actual = hashlib.new(algorithm, raw).digest()
    expected_bytes = bytes.fromhex(expected) if algorithm == "sha256" else base64.b64decode(expected, validate=True)
    require(actual == expected_bytes, f"archive digest mismatch: {path.name}")
    return raw


def unpack(raw: bytes, destination: Path, prefix: str, selected: set[str] | None = None) -> None:
    """Validate the entire archive namespace, then manually write regular files.

    No tar extraction API, symlink creation or archive-selected permissions.
    Non-selected safe symlinks in the official Node distribution stay unextracted.
    """
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
        members = archive.getmembers()
        require(len(members) <= 100_000, "archive has too many entries")
        seen: set[str] = set()
        total = 0
        for member in members:
            name = member.name.rstrip("/")
            parts = PurePosixPath(name).parts
            require(name and not name.startswith("/") and "\\" not in name and
                    all(piece not in (".", "..") for piece in parts) and
                    "/".join(parts) == name and parts[0] == prefix,
                    f"unsafe archive path: {name}")
            require(name not in seen, f"duplicate archive entry: {name}")
            seen.add(name)
            require(member.isfile() or member.isdir() or member.issym(), f"unsupported archive entry: {name}")
            total += member.size
            require(0 <= member.size <= MAX_ARCHIVE and total <= MAX_ARCHIVE, "archive expansion limit exceeded")
            if member.issym():
                target = posixpath.normpath(posixpath.join(posixpath.dirname(name), member.linkname))
                require(not member.linkname.startswith("/") and target.startswith(prefix + "/"),
                        f"escaping archive symlink: {name}")
                require(selected is not None and name not in selected, "selected archive symlinks are prohibited")
        chosen = {member.name for member in members if member.isfile() and
                  (selected is None or member.name in selected)}
        require(selected is None or chosen == selected, "required archive payload is missing")
        for member in members:
            if member.name not in chosen:
                continue
            relative = PurePosixPath(member.name).relative_to(prefix)
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            require(not target.exists() and not target.is_symlink(), "archive output already exists")
            stream = archive.extractfile(member)
            require(stream is not None, "archive regular payload is unavailable")
            with stream, target.open("xb") as output:
                shutil.copyfileobj(stream, output)
            target.chmod(0o644)


def require_static_arm64_elf(raw: bytes) -> None:
    require(len(raw) >= 64 and raw[:6] == b"\x7fELF\x02\x01", "compiler is not little-endian ELF64")
    require(struct.unpack_from("<H", raw, 18)[0] == 183, "compiler is not arm64")
    offset = struct.unpack_from("<Q", raw, 32)[0]
    size, count = struct.unpack_from("<HH", raw, 54)
    require(size >= 56 and 0 < count <= 128 and offset + size * count <= len(raw), "invalid compiler ELF program headers")
    types = [struct.unpack_from("<I", raw, offset + size * index)[0] for index in range(count)]
    require(3 not in types and 1 in types, "compiler requires an unapproved dynamic interpreter")


def source_gate_input(root: Path, binary: Path, receipt_path: Path, receipt_digest: str) -> tuple[bytes, dict]:
    """Consume independently reviewed gate bytes; never compile or execute them."""
    require(type(receipt_digest) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", receipt_digest),
            "source gate requires an independently pinned receipt")
    raw_receipt = regular_bytes(receipt_path, 16384)
    require("sha256:" + sha256(raw_receipt) == receipt_digest, "source gate receipt pin differs")
    receipt = json.loads(raw_receipt)
    require(type(receipt) is dict and set(receipt) == {
        "schema", "target", "source_sha256", "elf_sha256", "compiler_sha256",
        "build_command_sha256", "runtime_executed"}, "source gate receipt fields differ")
    require(raw_receipt in (canonical(receipt), canonical(receipt) + b"\n") and
            receipt["schema"] == "aragorn/pi-core-source-gate-build/v1" and
            receipt["target"] == "linux-arm64-static" and receipt["runtime_executed"] is False and
            all(type(receipt[key]) is str and re.fullmatch(r"[0-9a-f]{64}", receipt[key])
                for key in ("source_sha256", "elf_sha256", "compiler_sha256", "build_command_sha256")),
            "source gate receipt is not the reviewed static build contract")
    source = regular_bytes(root / PACKAGE / "source-gate.c", 65536)
    raw = regular_bytes(binary, 1024 * 1024)
    require(sha256(source) == receipt["source_sha256"] and sha256(raw) == receipt["elf_sha256"],
            "source gate source or binary differs")
    require_static_arm64_elf(raw)
    require(struct.unpack_from("<H", raw, 16)[0] == 2, "source gate must be a fixed static executable")
    offset = struct.unpack_from("<Q", raw, 32)[0]
    size, count = struct.unpack_from("<HH", raw, 54)
    entry = struct.unpack_from("<Q", raw, 24)[0]
    executable_entry = False
    for index in range(count):
        kind, flags, file_offset, address, _physical, file_size, memory_size, _alignment = \
            struct.unpack_from("<IIQQQQQQ", raw, offset + size * index)
        require(kind not in (2, 3), "source gate cannot have a dynamic segment or interpreter")
        if kind == 1:
            require(file_size <= memory_size and file_offset + file_size <= len(raw) and
                    address + memory_size <= 2**64 and flags & 3 != 3,
                    "source gate segment bounds or permissions differ")
            executable_entry |= bool(flags & 1 and address <= entry < address + file_size)
    require(executable_entry, "source gate entrypoint is not in executable file bytes")
    return raw, {**receipt, "receipt_digest": receipt_digest}


def prepare(root: Path, output: Path, node: Path, typescript: Path, compiler: Path, *,
            source_gate: Path | None = None, source_gate_receipt: Path | None = None,
            source_gate_receipt_digest: str | None = None) -> dict:
    supplied = (source_gate, source_gate_receipt, source_gate_receipt_digest)
    require(all(value is None for value in supplied) or all(value is not None for value in supplied),
            "source gate binary, receipt and independent pin must be supplied together")
    gate = None if source_gate is None else source_gate_input(root, *supplied)
    pins_raw = regular_bytes(root / PINS)
    pins = json.loads(pins_raw)
    require(pins["target"]["os"] == "linux" and pins["target"]["architecture"] == "arm64" and
            pins["target"]["libc"] == "glibc" and pins["node"]["version"] == "24.22.2", "unreviewed target pins")
    records = {item["source_lock_path"]: item for item in pins["packages"]}
    ts_pin = records["node_modules/typescript"]
    compiler_pin = records["node_modules/@typescript/typescript-linux-arm64"]
    require(ts_pin["version"] == compiler_pin["version"] == "7.0.2", "unreviewed compiler pins")
    node_raw = verified_archive(node, "sha256-" + pins["node"]["sha256"])
    ts_raw = verified_archive(typescript, ts_pin["integrity"])
    compiler_raw = verified_archive(compiler, compiler_pin["integrity"])
    package = root / PACKAGE
    toolchain_raw = regular_bytes(package / "offline-toolchain-v1.json")
    toolchain = json.loads(toolchain_raw)
    require(toolchain["schema"] == "aragorn/pi-core-offline-toolchain/v1" and
            toolchain["preparation"]["packages"] == 89 and
            toolchain["preparation"]["scripts_executed"] is False, "unreviewed prepared dependency closure")
    sources = {name: regular_bytes(package / name) for name in SOURCES}
    require(sha256(sources["package-lock.json"]) == toolchain["preparation"]["package_lock_sha256"], "prepared lock changed")
    source_tree = tree_inventory(package / "node_modules")
    dependency_digest = sha256(canonical(source_tree))
    require(dependency_digest == toolchain["dependency_tree_sha256"], "prepared runtime tree changed")
    lock = json.loads(sources["package-lock.json"])
    require(len(lock["packages"]) - 1 == 89, "runtime package graph is not the approved 89 occurrences")
    destination = output.absolute()
    require(destination == destination.resolve(), "linked output path is prohibited")
    require("," not in str(destination) and all(ord(character) >= 32 for character in str(destination)),
            "output path contains Docker mount delimiters or control characters")
    require(destination.is_relative_to(root.resolve() / ".aragorn/pi-core-build"), "output must be inside .aragorn/pi-core-build")
    require(destination != root.resolve() / ".aragorn/pi-core-build", "choose a new named build output")
    require(not destination.exists(), "output already exists; no automatic retry or overwrite")
    destination.mkdir(parents=True, exist_ok=False)
    staged = destination / "source/pi-core"
    staged.mkdir(parents=True)
    for name, raw in sources.items():
        (staged / name).write_bytes(raw)
    shutil.copytree(package / "node_modules", staged / "node_modules", symlinks=True)
    require(tree_inventory(staged / "node_modules") == source_tree, "staged runtime closure changed during copying")
    require(tree_inventory(package / "node_modules") == source_tree, "source runtime closure changed during copying")
    unpack(ts_raw, destination / "tools/typescript", "package")
    unpack(compiler_raw, destination / "compiler", "package")
    native = destination / "compiler/lib/tsc"
    require_static_arm64_elf(regular_bytes(native))
    native.chmod(0o755)
    require((destination / "compiler/lib/lib.es2024.d.ts").is_file(), "compiler standard library is missing")
    for folder, name in (("tools/typescript", "typescript"), ("compiler", "@typescript/typescript-linux-arm64")):
        metadata = json.loads(regular_bytes(destination / folder / "package.json"))
        require(metadata["name"] == name and metadata["version"] == "7.0.2", "compiler package identity mismatch")
    unpack(node_raw, destination / "deployment/node", "node-v24.22.2-linux-arm64",
           {"node-v24.22.2-linux-arm64/bin/node", "node-v24.22.2-linux-arm64/LICENSE"})
    (destination / "deployment/node/bin/node").chmod(0o755)
    if gate is not None:
        gate_path = destination / "deployment/observer/source-gate"
        gate_path.parent.mkdir()
        with gate_path.open("xb") as stream:
            stream.write(gate[0])
        gate_path.chmod(0o555)
    legacy = destination / "deployment/openclaw/aragorn-runtime-action-worker"
    legacy.mkdir(parents=True)
    for name in ("index.js", "package.json"):
        (legacy / name).write_bytes(regular_bytes(root / LEGACY / name))
    compiled = destination / "deployment/pi-core"
    compiled.mkdir()
    (compiled / "package.json").write_bytes(sources["package.json"])
    shutil.copytree(staged / "node_modules", compiled / "node_modules", symlinks=True)
    # Import contains only the compiler package, never Node, sources or runtime.
    with tarfile.open(destination / "compiler-rootfs.tar", "w") as archive:
        archive.add(destination / "compiler", arcname="compiler", recursive=True)
    inputs = {
        "pins_sha256": sha256(pins_raw), "offline_toolchain_sha256": sha256(toolchain_raw),
        "node_archive_sha256": sha256(node_raw), "typescript_archive_sha256": sha256(ts_raw),
        "compiler_archive_sha256": sha256(compiler_raw), "compiler_binary_sha256": sha256(regular_bytes(native)),
        "runtime_dependency_tree_sha256": dependency_digest, "runtime_package_occurrences": 89,
        "sources": {name: sha256(raw) for name, raw in sources.items()},
    }
    if gate is not None:
        inputs["source_gate"] = gate[1]
    return inputs


class DockerBuild:
    """One original deadline, with its last 30 seconds reserved for cleanup."""

    def __init__(self, output: Path, *, timeout: int = 120):
        require(type(timeout) is int and 60 <= timeout <= 600, "build timeout must be 60..600 seconds")
        self.output = output
        self.deadline = time.monotonic() + timeout
        self.token = uuid.uuid4().hex
        self.name = "aragorn-pi-compiler-" + self.token
        self.image = self.name + ":owned"
        self.environment = {"PATH": "/opt/homebrew/bin:/usr/bin:/bin", "HOME": str(Path.home()),
                            "LANG": "C", "LC_ALL": "C"}
        self.commands: list[dict] = []

    def command(self, arguments: list[str], *, cleanup: bool = False) -> subprocess.CompletedProcess:
        remaining = self.deadline - time.monotonic() - (0 if cleanup else 30)
        require(remaining > 0, "original compiler deadline exhausted")
        # File-backed bounded logging avoids an unbounded communicate() buffer.
        # No shell, inherited secrets, Docker host override or automatic retries.
        argv = [DOCKER, "--context", CONTEXT, *arguments]
        end = time.monotonic() + remaining
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            child = subprocess.Popen(argv, env=self.environment, stdout=stdout, stderr=stderr)
            try:
                while True:
                    require(os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size <= 1024 * 1024,
                            "compiler command exceeded the 1 MiB output bound")
                    left = end - time.monotonic()
                    require(left > 0, "original compiler deadline exhausted")
                    try:
                        code = child.wait(timeout=min(left, 0.1))
                        break
                    except subprocess.TimeoutExpired:
                        continue
                require(os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size <= 1024 * 1024,
                        "compiler command exceeded the 1 MiB output bound")
                stdout.seek(0)
                stderr.seek(0)
                result = subprocess.CompletedProcess(argv, code, stdout.read(), stderr.read())
            except BaseException as exc:
                child.kill()
                child.wait(timeout=max(0.01, min(5, self.deadline - time.monotonic())))
                stdout.seek(0)
                stderr.seek(0)
                self.commands.append({"arguments": arguments, "failure": str(exc),
                                      "stdout": stdout.read(512 * 1024).decode("utf-8", errors="replace"),
                                      "stderr": stderr.read(512 * 1024).decode("utf-8", errors="replace")})
                raise
        self.commands.append({"arguments": arguments, "returncode": result.returncode,
                              "stdout": result.stdout.decode("utf-8", errors="replace")[:1024 * 1024],
                              "stderr": result.stderr.decode("utf-8", errors="replace")[:1024 * 1024]})
        return result

    def checked(self, arguments: list[str]) -> subprocess.CompletedProcess:
        result = self.command(arguments)
        require(result.returncode == 0, f"compiler Docker command failed: {arguments[0]}; see compiler-log.json")
        return result

    def cleanup(self, kind: str, reference: str) -> None:
        result = self.command([kind, "inspect", "--format", "{{json .Config.Labels}}", reference], cleanup=True)
        if result.returncode != 0:
            require(b"No such" in result.stderr, f"cannot determine owned {kind} cleanup state")
            return
        require(json.loads(result.stdout).get(LABEL) == self.token, f"refusing cleanup of unowned {kind}")
        remove = [kind, "rm"] + (["--force"] if kind == "container" else []) + [reference]
        result = self.command(remove, cleanup=True)
        require(result.returncode == 0, f"owned {kind} cleanup failed")
        final = self.command([kind, "inspect", reference], cleanup=True)
        require(final.returncode != 0 and b"No such" in final.stderr, f"owned {kind} remains after cleanup")

    def compile(self) -> dict:
        image_attempted = container_attempted = False
        failure: BaseException | None = None
        cleanup_errors: list[str] = []
        try:
            image_attempted = True
            self.checked(["image", "import", "--platform", "linux/arm64", "--change",
                          f"LABEL {LABEL}={self.token}", str(self.output / "compiler-rootfs.tar"), self.image])
            uid, gid = os.getuid(), os.getgid()
            require(uid != 0, "compiler build must run under a nonroot host identity")
            container_attempted = True
            self.checked(["container", "create", "--name", self.name, "--label", f"{LABEL}={self.token}",
                          "--platform", "linux/arm64", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
                          "--security-opt", "no-new-privileges:true", "--user", f"{uid}:{gid}",
                          "--pids-limit", "64", "--memory", "512m", "--cpus", "2",
                          "--mount", f"type=bind,src={self.output / 'source'},dst=/source,readonly",
                          "--mount", f"type=bind,src={self.output / 'deployment/pi-core'},dst=/out",
                          "--workdir", "/source/pi-core", "--entrypoint", "/compiler/lib/tsc", self.image,
                          "--project", "/source/pi-core/tsconfig.json", "--outDir", "/out", "--pretty", "false"])
            self.checked(["container", "start", "--attach", self.name])
            state = self.checked(["container", "inspect", "--format", "{{json .State}}", self.name])
            status = json.loads(state.stdout)
            require(status.get("Running") is False and status.get("ExitCode") == 0 and
                    status.get("OOMKilled") is False and not status.get("Error"), "compiler did not exit successfully")
            require(all((self.output / "deployment/pi-core" / name).is_file()
                        for name in ("worker.js", "entrypoint.js", "provider.js")), "compiler output is incomplete")
        except BaseException as exc:
            failure = exc
        finally:
            for attempted, kind, reference in ((container_attempted, "container", self.name),
                                                (image_attempted, "image", self.image)):
                if attempted:
                    try:
                        self.cleanup(kind, reference)
                    except BaseException as exc:
                        cleanup_errors.append(f"{kind}: {exc}")
            (self.output / "compiler-log.json").write_bytes(canonical({
                "commands": self.commands, "failure": None if failure is None else str(failure),
                "cleanup_errors": cleanup_errors, "ownership": self.token, "context": CONTEXT,
            }) + b"\n")
        if cleanup_errors:
            raise BuildError("owned compiler cleanup requires attention: " + "; ".join(cleanup_errors)) from failure
        if failure is not None:
            raise failure
        return {"context": CONTEXT, "container": self.name, "image": self.image,
                "owned_container_absent": True, "owned_image_absent": True}


def build(root: Path, output: Path, node: Path, typescript: Path, compiler: Path, *, timeout: int = 120,
          source_gate: Path | None = None, source_gate_receipt: Path | None = None,
          source_gate_receipt_digest: str | None = None) -> dict:
    # Deadline starts before input assembly, not afresh for every process.
    output = output.absolute()
    executor = DockerBuild(output, timeout=timeout)
    options = {} if source_gate is source_gate_receipt is source_gate_receipt_digest is None else {
        "source_gate": source_gate, "source_gate_receipt": source_gate_receipt,
        "source_gate_receipt_digest": source_gate_receipt_digest}
    inputs = prepare(root, output, node, typescript, compiler, **options)
    cleanup = executor.compile()
    require(sha256(canonical(tree_inventory(output / "deployment/pi-core/node_modules"))) ==
            inputs["runtime_dependency_tree_sha256"], "compiler changed the preserved runtime dependency closure")
    require(all(sha256(regular_bytes(root / PACKAGE / name)) == digest
                for name, digest in inputs["sources"].items()), "source changed during compilation")
    if "source_gate" in inputs:
        raw, pinned = source_gate_input(root, source_gate, source_gate_receipt, source_gate_receipt_digest)
        require(pinned == inputs["source_gate"] and
                regular_bytes(output / "deployment/observer/source-gate", 1024 * 1024) == raw,
                "source gate changed during compiler assembly")
    inventory = tree_inventory(output / "deployment")
    receipt = {
        "schema": "aragorn/pi-core-linux-build/v1", "status": "COMPILED_NOT_DEPLOYED_OR_OS_QUALIFIED",
        "target": "linux-arm64-glibc", "node_version": "24.22.2", "typescript_version": "7.0.2",
        "runtime_executed": False, "install_scripts_executed": False, "inputs": inputs,
        "deployment_inventory": inventory, "deployment_tree_sha256": sha256(canonical(inventory)),
        "cleanup": cleanup,
        "limitations": ["NO_OS_LIBRARY_CLOSURE_OR_LIVE_LAUNCH", "NO_PHASE3_QUALIFICATION",
                        "UPSTREAM_DECLARATIONS_SKIP_LIB_CHECK_ADAPTER_SOURCE_STRICT"],
    }
    (output / "build-receipt.json").write_bytes(canonical(receipt) + b"\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-archive", required=True, type=Path)
    parser.add_argument("--typescript-archive", required=True, type=Path)
    parser.add_argument("--compiler-archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--source-gate", type=Path)
    parser.add_argument("--source-gate-receipt", type=Path)
    parser.add_argument("--source-gate-receipt-digest")
    args = parser.parse_args()
    try:
        result = build(ROOT, args.output, args.node_archive, args.typescript_archive, args.compiler_archive,
                       timeout=args.timeout, source_gate=args.source_gate,
                       source_gate_receipt=args.source_gate_receipt,
                       source_gate_receipt_digest=args.source_gate_receipt_digest)
    except (BuildError, OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"Pi Linux build refused or failed: {exc}\n")
    print(json.dumps({"status": result["status"], "deployment_tree_sha256": result["deployment_tree_sha256"],
                      "receipt": str(args.output / "build-receipt.json")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
