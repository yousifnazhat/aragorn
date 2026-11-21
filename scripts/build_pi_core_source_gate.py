"""Build the fixed pre-Node gate without executing any Linux target code.

Developer input custody, not a hermetic or hostile-host compiler attestation.
Only separately pinned host clang and rust-lld execute, once each. The existing
gate receipt consumer remains authoritative for the resulting static ELF shape.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import time

_SPEC = importlib.util.spec_from_file_location("aragorn_pi_linux_build_shared",
    Path(__file__).with_name("build_pi_core_linux.py"))
assert _SPEC and _SPEC.loader
shared = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(shared)
BuildError, require = shared.BuildError, shared.require
canonical, sha256, regular_bytes = shared.canonical, shared.sha256, shared.regular_bytes
ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "aragorn/pi-core-source-gate-toolchain/v1"
RESTRICTED_SCHEMA = "aragorn/pi-core-source-gate-toolchain/v2"
RESTRICTED_RECEIPT = "aragorn/pi-core-source-gate-build/v2"
RESTRICTED_SOURCE = "source-gate-noeval-v2.c"
RESTRICTED_SOURCE_SHA = "29b9242f40b2a611560d2aa97170d47f07284a76a3d489b3e90287ef1c1ef491"
RESTRICTED_TOOLCHAIN_PIN = "sha256:7fdaa9b7d5f80903b5f758458bca4457f4e8b8d025c8f113aac0f6d53f13ce5f"
RESTRICTED_GATE = "/opt/aragorn/pi-runtime/observer/source-gate"
RESTRICTED_ARGV = ("/opt/aragorn/pi-runtime/node/bin/node", "--disallow-code-generation-from-strings",
                   "/opt/aragorn/pi-runtime/pi-core/entrypoint.js")
VIEW_SCHEMA = "aragorn/pi-core-source-gate-toolchain/v3"
VIEW_RECEIPT = "aragorn/pi-core-source-gate-build/v3"
VIEW_RECORD = "aragorn/pi-core-pre-exec-fixed-view/v1"  # protocol identifier, not a worker-generated report
VIEW_SOURCE = "source-gate-view-v3.c"
VIEW_SOURCE_SHA = "90156fce7c6eb95d30426567f8182a5273d00d7a579156b2e1c01243a98b9ab0"
VIEW_TOOLCHAIN_PIN = "sha256:63d0b9fd2cb3a62aab22acd262230196d300fd861abedb4fd688ccb8c407ec69"
VIEW_RECIPE_SHA = "b236b3778d938f4f0ddfe4a03891a236c010376164a22bdc4d60d61634048306"
VIEW_LITERALS = frozenset({
    "/run/aragorn-pi-bootstrap/requests", "/run/aragorn-pi-bootstrap/requests/request.sock",
    "/run/aragorn-pi-bootstrap/provider", "/run/aragorn-pi-bootstrap/provider/provider.sock",
    "/proc/self", "/proc/thread-self", "/proc/self/fd", "/dev/fd",
    "/dev/stdin", "/dev/stdout", "/dev/stderr",
})
PROFILE = "clang-rust-lld-gnu/v1"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
MAX_LOG = 1024 * 1024


def _write(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)


def _json(path, value):
    raw = canonical(value) + b"\n"
    _write(path, raw)
    return raw


def _pin(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value), "invalid source/tool byte pin")
    return value


def _tool(row, *, executable=True):
    require(type(row) is dict and set(row) == {"path", "sha256"} and type(row["path"]) is str,
            "invalid pinned tool fields")
    path = Path(row["path"])
    require(path.is_absolute() and str(path) == row["path"] and path.resolve(strict=True) == path and
            all(ord(char) >= 32 and ord(char) != 127 for char in str(path)), "tool path is not resolved absolute data")
    raw = regular_bytes(path)
    require(sha256(raw) == _pin(row["sha256"]) and
            (not executable or stat.S_IMODE(path.stat().st_mode) & 0o111),
            "pinned compiler/linker bytes or executable mode differ")
    return path


def load_toolchain(root, path, digest):
    require(type(digest) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", digest),
            "independent toolchain manifest pin is required")
    raw = regular_bytes(path, 16384)
    require("sha256:" + sha256(raw) == digest, "toolchain manifest pin differs")
    value = json.loads(raw)
    restricted = type(value) is dict and value.get("schema") == RESTRICTED_SCHEMA
    view = type(value) is dict and value.get("schema") == VIEW_SCHEMA
    fields = {"schema", "target", "command_profile", "source_sha256", "compiler", "linker", "linker_library"}
    if restricted:
        fields |= {"gate_path", "node_argv"}
        require(digest == RESTRICTED_TOOLCHAIN_PIN and value.get("gate_path") == RESTRICTED_GATE and
                value.get("node_argv") == list(RESTRICTED_ARGV) and value.get("source_sha256") == RESTRICTED_SOURCE_SHA,
                "restricted gate requires its fixed toolchain, original source and complete argv")
    if view:
        fields |= {"gate_path", "node_argv", "view_record"}
        require(digest == VIEW_TOOLCHAIN_PIN and value.get("gate_path") == RESTRICTED_GATE and
                value.get("node_argv") == list(RESTRICTED_ARGV) and value.get("source_sha256") == VIEW_SOURCE_SHA
                and value.get("view_record") == VIEW_RECORD, "fixed-view gate requires its original pinned profile")
    require(type(value) is dict and set(value) == fields and
        raw in (canonical(value), canonical(value) + b"\n") and value["schema"] in (SCHEMA, RESTRICTED_SCHEMA, VIEW_SCHEMA) and
        value["target"] == "linux-arm64-static" and value["command_profile"] == PROFILE,
        "toolchain manifest is not the fixed reviewed contract")
    compiler, linker = _tool(value["compiler"]), _tool(value["linker"])
    library = _tool(value["linker_library"], executable=False)
    require(len(linker.parents) >= 4 and linker.name == "rust-lld" and linker.parent.name == "bin" and
            linker.parents[1].name == "aarch64-apple-darwin" and linker.parents[2].name == "rustlib" and
            library == linker.parents[3] / "libLLVM.dylib", "pinned linker library is not the reviewed adjacent runtime")
    name = VIEW_SOURCE if view else RESTRICTED_SOURCE if restricted else "source-gate.c"
    source = regular_bytes(root / shared.PACKAGE / name, 65536)
    require(sha256(source) == _pin(value["source_sha256"]), "reviewed source gate bytes differ")
    return value, source, compiler, linker


def commands(compiler, linker, output):
    """No manifest-selected options, headers, libraries, driver linker or shell."""
    return (
        [str(compiler), "--no-default-config", "--target=aarch64-unknown-linux-gnu",
         "-std=c11", "-O2", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
         "-fno-pic", "-fno-pie", "-nostdinc", "-fintegrated-cc1", "-integrated-as",
         "-Wall", "-Wextra", "-Werror", "-c", str(output / "source-gate.c"),
         "-o", str(output / "gate.o")],
        [str(linker), "-flavor", "gnu", "-m", "aarch64elf", "-static", "--no-undefined",
         "--fatal-warnings", "--entry=_start", "--build-id=none", "-z", "noexecstack",
         "-o", str(output / "source-gate"), str(output / "gate.o")],
    )


def restricted_gate_input(root, binary, receipt_path, receipt_digest):
    """Offline source/ELF/argv custody, not execution or proof of V8 enforcement."""
    raw_receipt = regular_bytes(receipt_path, 16384)
    require(type(receipt_digest) is str and "sha256:" + sha256(raw_receipt) == receipt_digest,
            "restricted gate receipt pin differs")
    receipt = json.loads(raw_receipt)
    require(type(receipt) is dict and set(receipt) == {"schema", "target", "source_sha256", "elf_sha256",
            "compiler_sha256", "build_command_sha256", "runtime_executed", "node_argv"} and
            raw_receipt == canonical(receipt) + b"\n" and receipt["schema"] == RESTRICTED_RECEIPT and
            receipt["node_argv"] == list(RESTRICTED_ARGV) and receipt["target"] == "linux-arm64-static" and
            receipt["runtime_executed"] is False, "restricted gate receipt fields, target or argv differ")
    for key in ("source_sha256", "elf_sha256", "compiler_sha256", "build_command_sha256"):
        _pin(receipt[key])
    source = regular_bytes(root / shared.PACKAGE / RESTRICTED_SOURCE, 65536)
    elf = regular_bytes(binary, 1024 * 1024)
    require(sha256(source) == receipt["source_sha256"] == RESTRICTED_SOURCE_SHA and
            sha256(elf) == receipt["elf_sha256"] and
            receipt["compiler_sha256"] == "1220c0afafa12a6ae599d097ee7cf8b87c6b4d8e3fbb9783cee6b319a80683ba",
            "restricted gate source, compiler or ELF differs")
    _check_gate_image(elf)
    return elf, {**receipt, "receipt_digest": receipt_digest}


def view_gate_input(root, binary, receipt_path, receipt_digest):
    """Validate one pinned fixed-view build, not a syscall, access or launch observation."""
    raw = regular_bytes(receipt_path, 16384)
    require(type(receipt_digest) is str and "sha256:" + sha256(raw) == receipt_digest,
            "fixed-view receipt pin differs")
    receipt = json.loads(raw)
    require(type(receipt) is dict and set(receipt) == {"schema", "target", "source_sha256", "elf_sha256",
            "compiler_sha256", "build_command_sha256", "runtime_executed", "node_argv", "view_record",
            "gate_path", "toolchain_digest"} and raw == canonical(receipt) + b"\n" and
            receipt["schema"] == VIEW_RECEIPT and receipt["target"] == "linux-arm64-static" and
            receipt["runtime_executed"] is False and receipt["view_record"] == VIEW_RECORD and
            receipt["node_argv"] == list(RESTRICTED_ARGV) and receipt["gate_path"] == RESTRICTED_GATE and
            receipt["toolchain_digest"] == VIEW_TOOLCHAIN_PIN and receipt["build_command_sha256"] == VIEW_RECIPE_SHA,
            "fixed-view receipt, toolchain, recipe or immutable argv differs")
    source = regular_bytes(root / shared.PACKAGE / VIEW_SOURCE, 65536)
    elf = regular_bytes(binary, 1024 * 1024)
    require(sha256(source) == receipt["source_sha256"] == VIEW_SOURCE_SHA and sha256(elf) == receipt["elf_sha256"]
            and receipt["compiler_sha256"] == "1220c0afafa12a6ae599d097ee7cf8b87c6b4d8e3fbb9783cee6b319a80683ba",
            "fixed-view source, compiler or ELF differs")
    _check_gate_image(elf, VIEW_LITERALS)
    return elf, {**receipt, "receipt_digest": receipt_digest}


def _check_gate_image(elf, extra_literals=()):
    shared.require_static_arm64_elf(elf)
    require(struct.unpack_from("<H", elf, 16)[0] == 2, "restricted gate must be a fixed executable")
    entry, offset = struct.unpack_from("<QQ", elf, 24)
    size, count = struct.unpack_from("<HH", elf, 54)
    executable_entry, literals = False, set()
    required_literals = {RESTRICTED_GATE, *RESTRICTED_ARGV, "HOME=/nonexistent", "PATH=/opt/aragorn/pi-runtime/node/bin",
                         *extra_literals}
    for index in range(count):
        kind, flags, start, address, _, file_size, memory_size = struct.unpack_from("<IIQQQQQ", elf, offset + index * size)
        require(kind not in (2, 3), "restricted gate has a dynamic section or interpreter")
        if kind != 1:
            continue
        require(file_size <= memory_size and start + file_size <= len(elf) and address + memory_size <= 2**64 and
                flags & 3 != 3, "restricted gate segment bounds or permissions differ")
        executable_entry |= bool(flags & 1 and address <= entry < address + file_size)
        if flags & 4 and not flags & 2:
            region = elf[start:start + file_size]
            literals.update(text for text in required_literals if text.encode("ascii") + b"\0" in region)
    require(executable_entry and required_literals == literals, "restricted gate lacks executable entry or pinned literals")


def _remaining(deadline):
    left = deadline - time.monotonic()
    require(left > 0, "original gate build deadline exhausted")
    return left


def _identities(paths):
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    result = {}
    for path in paths:
        value = os.stat(path, follow_symlinks=False)
        result[str(path)] = [getattr(value, field) for field in fields]
    return result


def _command(argv, output, phase, operation_deadline, cleanup_deadline, records):
    record = {"phase": phase, "argv": argv, "status": "STARTING", "child_reaped": False}
    records.append(record)
    stdout_path, stderr_path = output / (phase + ".stdout"), output / (phase + ".stderr")
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            _remaining(operation_deadline)
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                cwd=output, env=dict(ENV), close_fds=True, shell=False)
            record.update(status="RUNNING", pid=child.pid)
            try:
                while True:
                    require(os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size <= MAX_LOG,
                            "gate compiler/linker output exceeds 1 MiB")
                    try:
                        code = child.wait(timeout=min(_remaining(operation_deadline), 0.1))
                        break
                    except subprocess.TimeoutExpired:
                        continue
                record.update(returncode=code, child_reaped=True, status="EXITED")
                require(os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size <= MAX_LOG,
                        "gate compiler/linker output exceeds 1 MiB")
            except BaseException:
                # Terminate only this captured compiler/linker child. A race
                # with natural exit still requires the same bounded reap.
                if child.poll() is None:
                    record["termination_requested"] = True
                    try:
                        child.kill()
                    except ProcessLookupError:
                        pass
                    except OSError as error:
                        record["termination_error"] = str(error)[:256]
                    try:
                        child.wait(timeout=_remaining(cleanup_deadline))
                        record["child_reaped"] = True
                    except (BuildError, OSError, subprocess.TimeoutExpired) as error:
                        record.update(status="CLEANUP_HOLD", cleanup_error=str(error)[:256])
                else:
                    record["child_reaped"] = True
                if record["status"] != "CLEANUP_HOLD":
                    record["status"] = "FAILED_CHILD_REAPED"
                raise
    finally:
        for name, path in (("stdout", stdout_path), ("stderr", stderr_path)):
            if path.exists():
                size = path.stat().st_size
                record[name] = {"path": path.name, "bytes": size, "sha256":
                    sha256(regular_bytes(path, MAX_LOG)) if size <= MAX_LOG else None}
    require(code == 0, f"gate {phase} failed; retained output must be diagnosed before another build")


def build(root, output, toolchain_manifest, toolchain_digest, *, timeout_seconds=30):
    require(type(timeout_seconds) is int and 5 <= timeout_seconds <= 60, "gate timeout must be 5..60 seconds")
    deadline = time.monotonic() + timeout_seconds
    operation_deadline = deadline - 2
    root, output = Path(root).resolve(strict=True), Path(output).absolute()
    require(output == output.resolve() and output.is_relative_to(root / ".aragorn/pi-core-build") and
            output != root / ".aragorn/pi-core-build" and not output.exists(),
            "gate build output must be a new unlinked named directory in .aragorn/pi-core-build")
    manifest, source, compiler, linker = load_toolchain(root, toolchain_manifest, toolchain_digest)
    restricted = manifest["schema"] == RESTRICTED_SCHEMA
    view = manifest["schema"] == VIEW_SCHEMA
    if restricted:
        require(output == root / ".aragorn/pi-core-build/gate-batch-36", "restricted gate output differs")
    if view:
        require(output == root / ".aragorn/pi-core-build/gate-batch-82", "fixed-view gate output differs")
    source_name = VIEW_SOURCE if view else RESTRICTED_SOURCE if restricted else "source-gate.c"
    inputs = (compiler, linker, Path(manifest["linker_library"]["path"]),
              root / shared.PACKAGE / source_name, Path(toolchain_manifest))
    identities = _identities(inputs)
    _remaining(operation_deadline)
    recipe = {"profile": PROFILE, "argv": commands(compiler, linker, output), "environment": ENV,
              "working_directory": str(output), "toolchain_digest": toolchain_digest}
    if restricted or view:
        recipe.update(source=source_name, gate_path=RESTRICTED_GATE, node_argv=list(RESTRICTED_ARGV))
    if view:
        recipe["view_record"] = VIEW_RECORD
        require(sha256(canonical(recipe)) == VIEW_RECIPE_SHA, "fixed-view build recipe differs before compilation")
    records = []
    output.mkdir(parents=True, exist_ok=False)
    try:
        _write(output / "source-gate.c", source)
        _json(output / "toolchain.json", manifest)
        _json(output / "commands.json", recipe)
        for phase, argv in zip(("compile", "link"), recipe["argv"]):
            _remaining(operation_deadline)
            _tool(manifest["compiler" if phase == "compile" else "linker"])
            _tool(manifest["linker_library"], executable=False)
            _command(argv, output, phase, operation_deadline, deadline, records)
        _remaining(operation_deadline)
        # Revalidate pinned inputs and staged source after both host tools exit.
        after, current, _, _ = load_toolchain(root, toolchain_manifest, toolchain_digest)
        require(after == manifest and current == source and _identities(inputs) == identities and
                regular_bytes(output / "source-gate.c", 65536) == source,
                "gate source/toolchain changed during build")
        obj = regular_bytes(output / "gate.o", 1024 * 1024)
        elf = regular_bytes(output / "source-gate", 1024 * 1024)
        receipt = {"schema": "aragorn/pi-core-source-gate-build/v1", "target": "linux-arm64-static",
            "source_sha256": sha256(source), "elf_sha256": sha256(elf),
            "compiler_sha256": manifest["compiler"]["sha256"], "build_command_sha256": sha256(canonical(recipe)),
            "runtime_executed": False}
        if restricted:
            receipt.update(schema=RESTRICTED_RECEIPT, node_argv=list(RESTRICTED_ARGV))
        elif view:
            receipt.update(schema=VIEW_RECEIPT, node_argv=list(RESTRICTED_ARGV), gate_path=RESTRICTED_GATE,
                           view_record=VIEW_RECORD, toolchain_digest=toolchain_digest)
        candidate = _json(output / "candidate-receipt.json", receipt)
        receipt_digest = "sha256:" + sha256(candidate)
        reader = view_gate_input if view else restricted_gate_input if restricted else shared.source_gate_input
        reader(root, output / "source-gate", output / "candidate-receipt.json", receipt_digest)
        _remaining(operation_deadline)
        (output / "source-gate").chmod(0o555)
        provenance = {"schema": ("aragorn/pi-core-source-gate-provenance/v3" if view else
            "aragorn/pi-core-source-gate-provenance/v2" if restricted else "aragorn/pi-core-source-gate-provenance/v1"),
            "status": "COMPILED_STATIC_GATE_NOT_EXECUTED", "toolchain_digest": toolchain_digest,
            "toolchain": manifest, "input_identities": identities, "recipe": recipe, "commands": records,
            "artifacts": {"gate.o": {"sha256": sha256(obj), "bytes": len(obj)},
                          "source-gate": {"sha256": sha256(elf), "bytes": len(elf)}},
            "receipt_digest": receipt_digest, "runtime_executed": False,
            "limitations": ["DEVELOPER_BUILD_CUSTODY_NOT_HOSTILE_HOST_ATTESTATION",
                "HOST_DYNAMIC_COMPILER_DEPENDENCIES_NOT_FULLY_ATTESTED", "NO_TARGET_EXECUTION_OR_LIVE_QUALIFICATION"]}
        _json(output / "provenance.json", provenance)
        _write(output / "build-receipt.json", candidate)
        return provenance
    except BaseException as error:
        _json(output / "failure.json", {"schema": "aragorn/pi-core-source-gate-build-failure/v1",
            "status": "FAILED_RETAINED_NO_RETRY", "error_type": type(error).__name__,
            "reason": str(error)[:1024], "toolchain_digest": toolchain_digest, "commands": records,
            "runtime_executed": False})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain-manifest", type=Path, required=True)
    parser.add_argument("--toolchain-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    args = parser.parse_args()
    try:
        result = build(ROOT, args.output, args.toolchain_manifest, args.toolchain_digest,
                       timeout_seconds=args.timeout_seconds)
    except (BuildError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"source gate build refused or failed: {error}\n")
    print(json.dumps({"status": result["status"], "receipt_digest": result["receipt_digest"],
                      "receipt": str(args.output / "build-receipt.json")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
