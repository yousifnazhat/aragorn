"""B45 only: one signed local no-store preview; no VM, guest, cloud or real firmware."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from scripts import prepare_pi_core_bound_host_runner as build
from scripts import verify_pi_core_host_binding as check
from scripts.build_pi_core_linux import BuildError, sha256


class BoundHost(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pin = json.loads(check.PIN.read_bytes())
        cls.dest = build.WORK / cls.pin["directory"]
        cls.runner = cls.dest / "host-runner"
        cls.media = json.loads(check.MEDIA.read_bytes())
        cls.disk = build.B41.parent / "build-b44" / cls.media["directory"] / "aragorn-arm64.raw"
        cls.tmpdir = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmpdir.cleanup)
        cls.tmp = Path(cls.tmpdir.name).resolve()

    def test_exact_executable_signature_and_frozen_provenance(self):
        self.assertEqual(self.pin, json.loads((self.dest / "receipt.json").read_bytes()))
        props = check.match_executable(self.runner, self.pin)
        self.assertEqual(props["signing"], "ad-hoc-local-integrity")
        self.assertEqual(props["entitlements"], {"com.apple.security.virtualization": True})
        raw = (self.dest / "inputs.json").read_bytes()
        self.assertEqual(self.dest.name, "build-" + sha256(raw))
        inputs = json.loads(raw)
        self.assertEqual(inputs["sources"], {s: sha256((build.PACK / s).read_bytes()) for s in build.SOURCES})
        self.assertEqual(inputs["recipe"], self.pin["build_recipe_sha256"])
        self.assertEqual(sha256(Path(build.__file__).read_bytes()), self.pin["verification_recipe_sha256"])
        self.assertEqual(sha256((build.B44 / "boot-request.json").read_bytes()), self.pin["request_sha256"])
        self.assertEqual(sha256(check.MEDIA.read_bytes()), self.pin["media_pins_sha256"])
        self.assertEqual(self.pin["disk_sha256"], self.media["disk_sha256"])

    def test_modified_executable_does_not_verify(self):
        altered = self.tmp / "changed-runner"
        data = bytearray(self.runner.read_bytes())
        data[4096] ^= 1
        altered.write_bytes(data)
        altered.chmod(0o500)
        with self.assertRaises(BuildError):
            check.match_executable(altered, self.pin)

    def test_missing_or_zero_loader_uuid_refused_before_execution(self):
        data = self.runner.read_bytes()
        self.assertEqual(build.macho_uuid(data), self.pin["macho_uuid_hex"])
        at = 32
        for _ in range(struct.unpack_from("<I", data, 16)[0]):
            command, size = struct.unpack_from("<II", data, at)
            if command == 0x1b:
                for offset, replacement in ((at, bytes(4)), (at + 8, bytes(16))):
                    bad = bytearray(data)
                    bad[offset:offset + len(replacement)] = replacement
                    with self.assertRaises(BuildError):
                        build.macho_uuid(bad)
                return
            at += size
        self.fail("no LC_UUID in supposedly sealed executable")

    def test_physical_b44_binding_to_armed_closed_pipe_and_replay_refusals(self):
        root = self.tmp / "own-fixture"
        root.mkdir(mode=0o700)
        uid = "1ea4e2cc-32a4-4686-b109-504ac985d48e"
        # An unrelated sentinel would be denied even read access by the preview sandbox.
        sentinel = root / "efi-vars.fd"
        sentinel.write_bytes(b"NOT AN EFI STORE")
        profile = ('(version 1)(allow default)(deny network*)(deny file-write*)'
                   '(allow file-write* (subpath ' + json.dumps(str(root)) + '))'
                   '(deny file-read* file-write* (literal ' + json.dumps(str(sentinel)) + '))')
        p = subprocess.run(["/usr/bin/sandbox-exec", "-p", profile, self.runner, "preview", self.disk, root, uid],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=70,
                           env={"HOME": str(root), "TMPDIR": str(root), "PATH": "/usr/bin:/bin"})
        self.assertEqual(p.returncode, 0, p.stderr.decode(errors="replace"))
        attempt = root / uid
        receipt = attempt / "binding.json"
        raw = receipt.read_bytes()
        self.assertEqual(raw, p.stdout)
        self.assertEqual(sentinel.read_bytes(), b"NOT AN EFI STORE")
        self.assertEqual(set(os.listdir(attempt)), {"binding.json", "serial.raw"})
        got = check.replay(attempt, self.disk, sha256(p.stdout), self.pin)
        self.assertEqual(got["status"], "matched_no_boot_binding")
        self.assertIs(got["boot_observed"], False)
        # Keep the actual no-guest receipt in the private stage log; the fixture itself is disposable.
        print(raw.decode("ascii").rstrip("\n"), flush=True)
        with self.assertRaisesRegex(BuildError, "digest mismatch"):
            check.replay(attempt, self.disk, "0"*64, self.pin)
        with self.assertRaisesRegex(BuildError, "attempt or mode"):
            check.replay(attempt, self.disk, sha256(raw), self.pin, expected_store="a"*64, expected_policy="b"*64)
        # Mutate copies in test-owned directories, never original evidence or media.
        b = json.loads(raw)
        for label, mutate in (
            ("graph", lambda d: d["graph"].update(guest_serial_input=True)),
            ("signer", lambda d: d.update(runner_sha256="0"*64)),
            ("store", lambda d: d.update(store={"secure_boot_enabled": True})),
            ("capture", lambda d: d["capture"].update(capture_bytes=1)),
            ("lifetime", lambda d: d.update(graph_retired_ns=d["capture"]["attempt_start_ns"]-1)),
            ("authority", lambda d: d.update(boot_observed=True)),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory(dir=self.tmp) as alt:
                parent = Path(alt)
                forged = parent / uid
                forged.mkdir(mode=0o700)
                row = copy.deepcopy(b)
                row["fixture_identity"] = check.identity(parent, True)
                mutate(row)
                fake = (json.dumps(row) + "\n").encode()
                for name, content in (("binding.json", fake), ("serial.raw", b"")):
                    build.put(forged / name, content)
                with self.assertRaises(BuildError):
                    check.replay(forged, self.disk, sha256(fake), self.pin)

    def test_unsupported_operation_and_missing_private_custody_do_not_reserve(self):
        for mode in ("start", "preview", "bind-existing"):
            with self.subTest(mode=mode):
                absent = self.tmp / "no-fixture"
                argv = [self.runner, mode, "/nonexistent", absent, "bad-uuid"]
                if mode == "bind-existing":
                    argv += ["b"*64, "c"*64]
                proc = subprocess.run(["/usr/bin/sandbox-exec", "-p",
                    "(version 1)(allow default)(deny network*)(deny file-write*)", *argv],
                    capture_output=True, stdin=subprocess.DEVNULL, timeout=5)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIn(b"B45 refused:", proc.stderr)
                self.assertFalse(proc.stdout or absent.exists())

    def test_policy_readback_conformance_on_inert_objects_only(self):
        fixture = self.tmp / "inert-policy"
        env = {"HOME": str(self.tmp), "TMPDIR": str(self.tmp), "PATH": "/usr/bin:/bin"}
        with build.CC.open("rb") as f:
            self.assertEqual(hashlib.file_digest(f, "sha256").hexdigest(), build.TOOLS[build.CC])
        subprocess.run([build.CC, "-arch", "arm64", "-isysroot", build.SDK, "-mmacosx-version-min=14",
            "-fobjc-arc", "-fno-modules", "-Werror", "-Os", "-I", build.PACK, "-framework", "Security",
            "-framework", "Virtualization", "-framework", "Foundation",
            Path(__file__).with_name("b45-firmware-readback-fixture.m"), build.PACK / "serial-recorder.m",
            "-o", fixture], check=True, env=env, stdin=subprocess.DEVNULL, timeout=45)
        def invoke(mode):
            return subprocess.run(["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny network*)(deny file-write*)",
                fixture, mode], env=env, capture_output=True, stdin=subprocess.DEVNULL, timeout=5)
        rows = ["db:sha256:" + self.media["authenticode_sha256"], "kek:sha256:" + "00"*32,
                "dbx:sha256:" + "01"*32]
        expected = sha256(("\n".join(sorted(rows))+"\n").encode())
        result = invoke("intended")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.decode().strip(), expected)
        for mode in ("disabled", "extra", "duplicate", "revoked", "unknown", "empty"):
            with self.subTest(mode=mode):
                result = invoke(mode)
                self.assertEqual((result.returncode, result.stdout), (2, b""))
