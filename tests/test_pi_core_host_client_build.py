"""Build-boundary checks only: no compiler, VM, generator, or target invocation."""
import json
from pathlib import Path
import tempfile
import unittest

from scripts import build_pi_core_host_clients as build
from scripts.build_pi_core_linux import BuildError


class ClientBuildBoundary(unittest.TestCase):
    def test_cross_machine_cannot_run_target(self):
        m = build.target_file(Path("/owned/root"), {k: Path("/tools") / k for k in
                              ("clang", "ld.lld", "llvm-ar", "pkg-config", "python3")})
        self.assertIn("needs_exe_wrapper = true", m)
        self.assertNotIn("\nexe_wrapper =", m)
        self.assertIn("'--target=aarch64-linux-gnu', '--sysroot=/owned/root'", m)
        self.assertIn("'/owned/root/usr/lib/aarch64-linux-gnu/pkgconfig'", m)
        self.assertIn("'--ld-path=/tools/ld.lld'", m)
        self.assertIn("--wrap-mode=nofallback", build.options())
        self.assertIn("-Dbpf-framework=enabled", build.options())
        self.assertEqual(set(build.SELECTORS), {"./systemctl:executable", "./systemd-run:executable",
                                                "./busctl:executable"})

    def test_reject_ambiguous_generator_paths(self):
        with self.assertRaises(BuildError):
            build.target_file(Path("/unsafe sysroot"), {})

    def test_capability_request_cannot_supply_arguments_or_request_twice(self):
        for request in (b"gen object x y\n", b"--version\n--version\n", b"--version", b""):
            with self.subTest(request=request), self.assertRaises(BuildError):
                build.answer_query(request, None, None, None, 1)

    def test_no_repeat_of_reserved_or_failed_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            owned = Path(tmp).resolve()
            _, first = build.reserve(owned, {"source": 123})
            (first / "failure.json").write_text("retained")
            with self.assertRaises(FileExistsError):
                build.reserve(owned, {"source": 123})
            self.assertEqual((first / "failure.json").read_text(), "retained")

    def test_only_installed_targets_in_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp).resolve()
            info = scratch / "meson-info"
            info.mkdir()
            path = info / "intro-install_plan.json"
            targets = {str(scratch / t): {"tag": build.TAG, "destination": "{bindir}/" + t,
                       "subproject": None, "install_rpath": None} for t in build.TARGETS}
            plan = {"targets": targets}
            path.write_text(json.dumps(plan))
            build.audit_install_plan(scratch)
            row = targets[str(scratch / "busctl")]
            for key, value in (("install_rpath", "/untrusted"), ("destination", "/usr/bin/busctl"),
                               ("subproject", "other"), ("tag", "runtime")):
                with self.subTest(column=key):
                    original = row[key]
                    row[key] = value
                    path.write_text(json.dumps(plan))
                    with self.assertRaises(BuildError):
                        build.audit_install_plan(scratch)
                    row[key] = original
            plan["data"] = {"/other": {"tag": build.TAG}}
            path.write_text(json.dumps(plan))
            with self.assertRaises(BuildError):
                build.audit_install_plan(scratch)
