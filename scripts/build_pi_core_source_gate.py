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
    require(type(value) is dict and set(value) == {
        "schema", "target", "command_profile", "source_sha256", "compiler", "linker", "linker_library"} and
        raw in (canonical(value), canonical(value) + b"\n") and value["schema"] == SCHEMA and
        value["target"] == "linux-arm64-static" and value["command_profile"] == PROFILE,
        "toolchain manifest is not the fixed reviewed contract")
    compiler, linker = _tool(value["compiler"]), _tool(value["linker"])
    library = _tool(value["linker_library"], executable=False)
    require(len(linker.parents) >= 4 and linker.name == "rust-lld" and linker.parent.name == "bin" and
            linker.parents[1].name == "aarch64-apple-darwin" and linker.parents[2].name == "rustlib" and
            library == linker.parents[3] / "libLLVM.dylib", "pinned linker library is not the reviewed adjacent runtime")
    source = regular_bytes(root / shared.PACKAGE / "source-gate.c", 65536)
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
    inputs = (compiler, linker, Path(manifest["linker_library"]["path"]),
              root / shared.PACKAGE / "source-gate.c", Path(toolchain_manifest))
    identities = _identities(inputs)
    _remaining(operation_deadline)
    recipe = {"profile": PROFILE, "argv": commands(compiler, linker, output), "environment": ENV,
              "working_directory": str(output), "toolchain_digest": toolchain_digest}
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
        candidate = _json(output / "candidate-receipt.json", receipt)
        receipt_digest = "sha256:" + sha256(candidate)
        shared.source_gate_input(root, output / "source-gate", output / "candidate-receipt.json", receipt_digest)
        _remaining(operation_deadline)
        (output / "source-gate").chmod(0o555)
        provenance = {"schema": "aragorn/pi-core-source-gate-provenance/v1",
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
