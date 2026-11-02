"""Inert assembly/command tests; never contact Docker or execute target code."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("pi_linux_build", _ROOT / "scripts/build_pi_core_linux.py")
assert _SPEC and _SPEC.loader
build = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(build)


def archive_bytes(files: dict[str, bytes], links: dict[str, str] | None = None) -> bytes:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as archive:
        for name, raw in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
        for name, target in (links or {}).items():
            member = tarfile.TarInfo(name)
            member.type = tarfile.SYMTYPE
            member.linkname = target
            archive.addfile(member)
    return result.getvalue()


def elf(*, machine: int = 183, program_type: int = 1) -> bytes:
    raw = bytearray(120)
    raw[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", raw, 18, machine)
    struct.pack_into("<Q", raw, 32, 64)
    struct.pack_into("<HH", raw, 54, 56, 1)
    struct.pack_into("<I", raw, 64, program_type)
    return bytes(raw)


class LinuxBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="aragorn-pi-build-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        # Any accidental process activation fails before it can execute.
        self.popen = mock.patch.object(build.subprocess, "Popen", side_effect=AssertionError("live process forbidden"))
        self.popen.start()
        self.addCleanup(self.popen.stop)

    def write(self, path: Path, raw: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def fixture(self) -> tuple[Path, Path, Path, Path]:
        package = self.root / build.PACKAGE
        self.write(package / "node_modules/example/index.js", b"// inert unit fixture\n")
        lock = {"packages": {"": {}} | {f"node_modules/p{i}": {} for i in range(89)}}
        for name in build.SOURCES:
            self.write(package / name, json.dumps(lock).encode() if name == "package-lock.json" else b"{}")
        toolchain = {
            "schema": "aragorn/pi-core-offline-toolchain/v1",
            "preparation": {"packages": 89, "scripts_executed": False,
                            "package_lock_sha256": build.sha256((package / "package-lock.json").read_bytes())},
            "dependency_tree_sha256": build.sha256(build.canonical(build.tree_inventory(package / "node_modules"))),
        }
        self.write(package / "offline-toolchain-v1.json", json.dumps(toolchain).encode())
        self.write(self.root / build.LEGACY / "index.js", b"// codec fixture")
        self.write(self.root / build.LEGACY / "package.json", b'{"type":"commonjs"}')
        node_raw = archive_bytes({"node-v24.22.2-linux-arm64/bin/node": b"not executed",
                                  "node-v24.22.2-linux-arm64/LICENSE": b"license"})
        ts_raw = archive_bytes({"package/package.json": b'{"name":"typescript","version":"7.0.2"}'})
        compiler_raw = archive_bytes({
            "package/package.json": b'{"name":"@typescript/typescript-linux-arm64","version":"7.0.2"}',
            "package/lib/tsc": elf(), "package/lib/lib.es2024.d.ts": b"// declarations",
        })
        pins = {"target": {"os": "linux", "architecture": "arm64", "libc": "glibc"},
                "node": {"version": "24.22.2", "sha256": build.sha256(node_raw)}, "packages": []}
        for source, raw in (("node_modules/typescript", ts_raw),
                            ("node_modules/@typescript/typescript-linux-arm64", compiler_raw)):
            pins["packages"].append({"source_lock_path": source, "version": "7.0.2",
                                     "integrity": "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode()})
        self.write(self.root / build.PINS, json.dumps(pins).encode())
        paths = (self.root / "node.tar.xz", self.root / "typescript.tgz", self.root / "compiler.tgz")
        for path, raw in zip(paths, (node_raw, ts_raw, compiler_raw)):
            self.write(path, raw)
        return self.root / ".aragorn/pi-core-build/unit", *paths

    def executor(self) -> tuple[object, list[list[str]], set[str]]:
        output = self.root / "output"
        for name in ("worker.js", "entrypoint.js"):
            self.write(output / "deployment/pi-core" / name, b"// inert output")
        subject = build.DockerBuild(output)
        calls: list[list[str]] = []
        removed: set[str] = set()

        def command(arguments: list[str], **kwargs) -> subprocess.CompletedProcess:
            calls.append(arguments)
            if arguments[1] == "inspect":
                if arguments[0] in removed:
                    return subprocess.CompletedProcess(arguments, 1, b"", b"Error: No such object")
                value = ({"Running": False, "ExitCode": 0, "OOMKilled": False, "Error": ""}
                         if "{{json .State}}" in arguments else {build.LABEL: subject.token})
                return subprocess.CompletedProcess(arguments, 0, json.dumps(value).encode(), b"")
            if arguments[1] == "rm":
                removed.add(arguments[0])
            return subprocess.CompletedProcess(arguments, 0, b"fixture", b"")

        subject.command = mock.Mock(side_effect=command)
        return subject, calls, removed

    def test_archive_digest_matches_sha256(self):
        path = self.root / "archive"
        path.write_bytes(b"content")
        self.assertEqual(build.verified_archive(path, "sha256-" + build.sha256(b"content")), b"content")

    def test_archive_digest_matches_sha512(self):
        path = self.root / "archive"
        path.write_bytes(b"content")
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(b"content").digest()).decode()
        self.assertEqual(build.verified_archive(path, integrity), b"content")

    def test_archive_digest_mismatch_refuses(self):
        path = self.root / "archive"
        path.write_bytes(b"content")
        with self.assertRaisesRegex(build.BuildError, "digest mismatch"):
            build.verified_archive(path, "sha256-" + "0" * 64)

    def test_archive_digest_unknown_algorithm_refuses(self):
        path = self.root / "archive"
        path.write_bytes(b"content")
        with self.assertRaisesRegex(build.BuildError, "algorithm"):
            build.verified_archive(path, "md5-invalid")

    def test_regular_input_refuses_symlink(self):
        path = self.root / "original"
        path.write_bytes(b"content")
        linked = self.root / "linked"
        linked.symlink_to(path)
        with self.assertRaises(OSError):
            build.regular_bytes(linked)

    def test_regular_input_enforces_size_bound(self):
        path = self.root / "original"
        path.write_bytes(b"content")
        with self.assertRaisesRegex(build.BuildError, "regular input"):
            build.regular_bytes(path, limit=1)

    def test_inventory_hashes_sorted_entries(self):
        self.write(self.root / "tree/z", b"z")
        self.write(self.root / "tree/a", b"a")
        rows = build.tree_inventory(self.root / "tree")
        self.assertEqual([row["path"] for row in rows], ["a", "z"])
        self.assertEqual(rows[0]["sha256"], build.sha256(b"a"))

    def test_inventory_includes_internal_link_without_following(self):
        self.write(self.root / "tree/a", b"a")
        (self.root / "tree/link").symlink_to("a")
        self.assertEqual(build.tree_inventory(self.root / "tree")[1],
                         {"path": "link", "kind": "symlink", "target": "a"})

    def test_inventory_rejects_external_link(self):
        self.write(self.root / "tree/a", b"a")
        (self.root / "tree/link").symlink_to("../outside")
        with self.assertRaisesRegex(build.BuildError, "escaping"):
            build.tree_inventory(self.root / "tree")

    def test_inventory_rejects_special_entries(self):
        (self.root / "tree").mkdir()
        os.mkfifo(self.root / "tree/fifo")
        with self.assertRaisesRegex(build.BuildError, "unsupported"):
            build.tree_inventory(self.root / "tree")

    def test_inventory_rejects_empty_directory(self):
        (self.root / "tree").mkdir()
        with self.assertRaisesRegex(build.BuildError, "empty"):
            build.tree_inventory(self.root / "tree")

    def test_unpack_regular_payload_only(self):
        build.unpack(archive_bytes({"package/file": b"content"}), self.root / "out", "package")
        self.assertEqual((self.root / "out/file").read_bytes(), b"content")
        self.assertEqual((self.root / "out/file").stat().st_mode & 0o777, 0o644)

    def test_unpack_rejects_parent_path(self):
        with self.assertRaisesRegex(build.BuildError, "unsafe archive path"):
            build.unpack(archive_bytes({"package/../outside": b"bad"}), self.root / "out", "package")
        self.assertFalse((self.root / "outside").exists())

    def test_unpack_rejects_absolute_path(self):
        with self.assertRaisesRegex(build.BuildError, "unsafe archive path"):
            build.unpack(archive_bytes({"/package/file": b"bad"}), self.root / "out", "package")

    def test_unpack_rejects_unselected_escaping_link(self):
        raw = archive_bytes({"package/file": b"ok"}, {"package/link": "../../outside"})
        with self.assertRaisesRegex(build.BuildError, "escaping archive"):
            build.unpack(raw, self.root / "out", "package", {"package/file"})

    def test_unpack_leaves_safe_unselected_link_uncreated(self):
        raw = archive_bytes({"package/file": b"ok"}, {"package/link": "file"})
        build.unpack(raw, self.root / "out", "package", {"package/file"})
        self.assertFalse((self.root / "out/link").exists())

    def test_unpack_rejects_missing_required_file(self):
        with self.assertRaisesRegex(build.BuildError, "missing"):
            build.unpack(archive_bytes({"package/file": b"ok"}), self.root / "out", "package", {"package/absent"})

    def test_unpack_rejects_selected_symlink(self):
        raw = archive_bytes({"package/file": b"ok"}, {"package/link": "file"})
        with self.assertRaisesRegex(build.BuildError, "symlinks"):
            build.unpack(raw, self.root / "out", "package", {"package/link"})

    def test_static_arm64_elf_is_accepted(self):
        build.require_static_arm64_elf(elf())

    def test_non_elf_compiler_is_rejected(self):
        with self.assertRaisesRegex(build.BuildError, "ELF64"):
            build.require_static_arm64_elf(b"#!/bin/sh")

    def test_x64_elf_compiler_is_rejected(self):
        with self.assertRaisesRegex(build.BuildError, "arm64"):
            build.require_static_arm64_elf(elf(machine=62))

    def test_dynamic_compiler_is_rejected(self):
        with self.assertRaisesRegex(build.BuildError, "interpreter"):
            build.require_static_arm64_elf(elf(program_type=3))

    def test_invalid_elf_program_headers_are_rejected(self):
        with self.assertRaisesRegex(build.BuildError, "headers"):
            build.require_static_arm64_elf(elf()[:-1])

    def test_preparation_keeps_runtime_and_legacy_relative_layout(self):
        output, node, ts, compiler = self.fixture()
        inputs = build.prepare(self.root, output, node, ts, compiler)
        self.assertEqual(inputs["runtime_package_occurrences"], 89)
        self.assertTrue((output / "deployment/node/bin/node").is_file())
        self.assertTrue((output / "deployment/openclaw/aragorn-runtime-action-worker/index.js").is_file())
        self.assertEqual(build.tree_inventory(output / "source/pi-core/node_modules"),
                         build.tree_inventory(output / "deployment/pi-core/node_modules"))
        self.assertFalse((output / "build-receipt.json").exists())

    def test_preparation_refuses_output_reuse(self):
        output, node, ts, compiler = self.fixture()
        output.mkdir(parents=True)
        with self.assertRaisesRegex(build.BuildError, "already exists"):
            build.prepare(self.root, output, node, ts, compiler)

    def test_preparation_refuses_output_outside_owned_root(self):
        _, node, ts, compiler = self.fixture()
        with self.assertRaisesRegex(build.BuildError, "inside"):
            build.prepare(self.root, self.root / "unrelated", node, ts, compiler)

    def test_preparation_refuses_mutated_runtime(self):
        output, node, ts, compiler = self.fixture()
        (self.root / build.PACKAGE / "node_modules/example/index.js").write_bytes(b"changed")
        with self.assertRaisesRegex(build.BuildError, "runtime tree changed"):
            build.prepare(self.root, output, node, ts, compiler)
        self.assertFalse(output.exists())

    def test_preparation_refuses_mutated_lock(self):
        output, node, ts, compiler = self.fixture()
        (self.root / build.PACKAGE / "package-lock.json").write_bytes(b"changed")
        with self.assertRaisesRegex(build.BuildError, "lock changed"):
            build.prepare(self.root, output, node, ts, compiler)

    def test_preparation_refuses_modified_node_pin(self):
        output, node, ts, compiler = self.fixture()
        pins_path = self.root / build.PINS
        pins = json.loads(pins_path.read_bytes())
        pins["node"]["version"] = "26.3.1"
        pins_path.write_text(json.dumps(pins))
        with self.assertRaisesRegex(build.BuildError, "target pins"):
            build.prepare(self.root, output, node, ts, compiler)

    def test_compiler_command_is_networkless_nonprivileged_and_bounded(self):
        subject, calls, removed = self.executor()
        with mock.patch.object(build.os, "getuid", return_value=501), mock.patch.object(build.os, "getgid", return_value=20):
            result = subject.compile()
        create = next(command for command in calls if command[:2] == ["container", "create"])
        for option, value in (("--network", "none"), ("--cap-drop", "ALL"), ("--user", "501:20"),
                              ("--security-opt", "no-new-privileges:true"), ("--entrypoint", "/compiler/lib/tsc"),
                              ("--memory", "512m"), ("--pids-limit", "64")):
            self.assertEqual(create[create.index(option) + 1], value)
        self.assertIn("--read-only", create)
        self.assertNotIn("--privileged", create)
        self.assertIn("readonly", next(value for value in create if value.startswith("type=bind,src=") and "dst=/source" in value))
        self.assertEqual(removed, {"container", "image"})
        self.assertTrue(result["owned_container_absent"])
        self.assertTrue(result["owned_image_absent"])

    def test_compile_failure_still_cleans_owned_resources(self):
        subject, calls, removed = self.executor()
        original = subject.command.side_effect

        def command(arguments, **kwargs):
            if arguments[:2] == ["container", "start"]:
                return subprocess.CompletedProcess(arguments, 2, b"TS error", b"")
            return original(arguments, **kwargs)

        subject.command.side_effect = command
        with self.assertRaisesRegex(build.BuildError, "command failed"):
            subject.compile()
        self.assertEqual(removed, {"container", "image"})
        self.assertTrue((subject.output / "compiler-log.json").is_file())

    def test_unowned_cleanup_is_refused(self):
        subject, _, removed = self.executor()
        subject.command.return_value = subprocess.CompletedProcess([], 0, b'{"org.aragorn.pi-core-build":"someone-else"}', b"")
        subject.command.side_effect = None
        with self.assertRaisesRegex(build.BuildError, "unowned"):
            subject.cleanup("container", subject.name)
        self.assertFalse(removed)
        self.assertEqual(subject.command.call_count, 1)

    def test_cleanup_does_not_treat_daemon_failure_as_absence(self):
        subject, _, _ = self.executor()
        subject.command.return_value = subprocess.CompletedProcess([], 1, b"", b"Cannot connect to daemon")
        subject.command.side_effect = None
        with self.assertRaisesRegex(build.BuildError, "cannot determine"):
            subject.cleanup("container", subject.name)

    def test_cleanup_failure_prevents_success_receipt(self):
        subject, _, _ = self.executor()
        subject.cleanup = mock.Mock(side_effect=build.BuildError("retained resource"))
        with self.assertRaisesRegex(build.BuildError, "requires attention"):
            subject.compile()
        self.assertFalse((subject.output / "build-receipt.json").exists())

    def test_build_has_one_original_deadline(self):
        with mock.patch.object(build.time, "monotonic", return_value=100):
            subject = build.DockerBuild(self.root)
        self.assertEqual(subject.deadline, 220)
        with mock.patch.object(build.time, "monotonic", return_value=191):
            with self.assertRaisesRegex(build.BuildError, "deadline"):
                subject.command(["container", "start", subject.name])

    def test_build_timeout_is_bounded(self):
        for value in (0, 59, 601, True):
            with self.subTest(value=value), self.assertRaises(build.BuildError):
                build.DockerBuild(self.root, timeout=value)

    def test_process_uses_only_explicit_colima_context_and_clean_environment(self):
        child = mock.Mock()
        child.wait.return_value = 0
        with mock.patch.object(build.subprocess, "Popen", return_value=child) as popen:
            subject = build.DockerBuild(self.root)
            subject.command(["image", "inspect", subject.image])
        arguments, options = popen.call_args
        self.assertEqual(arguments[0][:3], [build.DOCKER, "--context", "colima"])
        self.assertEqual(set(options["env"]), {"PATH", "HOME", "LANG", "LC_ALL"})
        self.assertNotIn("shell", options)
        self.assertNotIn("aragorn-bakeoff", arguments[0])
        child.kill.assert_not_called()

    def test_process_output_overflow_is_killed_and_retained(self):
        child = mock.Mock()
        child.wait.return_value = 0

        def popen(*args, **kwargs):
            kwargs["stdout"].write(b"x" * (1024 * 1024 + 1))
            kwargs["stdout"].flush()
            return child

        subject = build.DockerBuild(self.root)
        with mock.patch.object(build.subprocess, "Popen", side_effect=popen):
            with self.assertRaisesRegex(build.BuildError, "output bound"):
                subject.command(["image", "inspect", subject.image])
        child.kill.assert_called_once()
        self.assertIn("output bound", subject.commands[0]["failure"])
        self.assertLessEqual(len(subject.commands[0]["stdout"]), 512 * 1024)

    def test_receipt_explicitly_disclaims_runtime_execution_and_qualification(self):
        output, node, ts, compiler = self.fixture()

        def compile_inert(subject):
            for name in ("worker.js", "entrypoint.js"):
                (subject.output / "deployment/pi-core" / name).write_bytes(b"// mocked compiler output")
            return {"owned_container_absent": True, "owned_image_absent": True}

        with mock.patch.object(build.DockerBuild, "compile", compile_inert):
            receipt = build.build(self.root, output, node, ts, compiler)
        self.assertEqual(receipt["status"], "COMPILED_NOT_DEPLOYED_OR_OS_QUALIFIED")
        self.assertFalse(receipt["runtime_executed"])
        self.assertFalse(receipt["install_scripts_executed"])
        self.assertEqual(receipt["deployment_tree_sha256"], build.sha256(build.canonical(receipt["deployment_inventory"])))
        self.assertEqual(json.loads((output / "build-receipt.json").read_bytes()), receipt)

    def test_post_compile_dependency_mutation_prevents_receipt(self):
        output, node, ts, compiler = self.fixture()

        def compile_inert(subject):
            (subject.output / "deployment/pi-core/node_modules/example/index.js").write_bytes(b"unexpected mutation")
            return {"owned_container_absent": True, "owned_image_absent": True}

        with mock.patch.object(build.DockerBuild, "compile", compile_inert):
            with self.assertRaisesRegex(build.BuildError, "changed the preserved"):
                build.build(self.root, output, node, ts, compiler)
        self.assertFalse((output / "build-receipt.json").exists())

    def test_compiler_config_has_only_explicit_entrypoints(self):
        config = json.loads((_ROOT / "packaging/pi-core/tsconfig.json").read_bytes())
        self.assertEqual(config["files"], ["worker.ts", "entrypoint.ts"])
        self.assertEqual(config["compilerOptions"]["target"], "ES2023")
        self.assertEqual(config["compilerOptions"]["lib"], ["ES2024"])
        self.assertEqual(config["compilerOptions"]["module"], "NodeNext")
        self.assertTrue(config["compilerOptions"]["strict"])
        self.assertTrue(config["compilerOptions"]["noEmitOnError"])


if __name__ == "__main__":
    unittest.main()
