from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import stage_runtime_quarantine_profile as subject

_ROOT = Path(__file__).resolve().parents[1]
_RESPONSE_FILES = {
    "/usr/lib/aragorn/aragorn/runtime_response_service.py": (
        "src/aragorn/runtime_response_service.py",
        "0644",
    ),
    "/usr/lib/aragorn/aragorn/runtime_quarantine_response.py": (
        "src/aragorn/runtime_quarantine_response.py",
        "0644",
    ),
    "/usr/lib/aragorn/aragorn/runtime_quarantine_service.py": (
        "src/aragorn/runtime_quarantine_service.py",
        "0644",
    ),
    "/usr/libexec/aragorn/aragorn-runtime-quarantine-service.py": (
        "packaging/libexec/aragorn-runtime-quarantine-service.py",
        "0755",
    ),
}


def _copy_inputs(root):
    for name in (*subject._BASE_INPUTS, *subject.activation._DEPENDENCIES):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_ROOT / name, path)


def _sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class RuntimeQuarantineProfileStageTests(unittest.TestCase):
    def test_exact_fifty_four_file_inventory_manifest_and_non_deployment_ceiling(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output = root / "stage"
            manifest = subject.stage_runtime_quarantine_profile(output)
            self.assertEqual(
                manifest["schema"], "aragorn/runtime-quarantine-staged-profile/v1"
            )
            self.assertEqual(
                manifest["authority"],
                "CALLER_OWNED_DESTDIR_BYTES_ONLY_NOT_ROOT_DEPLOYMENT_OR_STARTUP_ENFORCEMENT",
            )
            self.assertEqual(
                set(manifest),
                {
                    "schema",
                    "authority",
                    "files",
                    "directories",
                    "base_inputs",
                    "new_dependencies",
                    "gateway_config_digest_required_not_included",
                    "root_deployment",
                    "production_activation_eligible",
                    "runtime_startup_enforcement",
                    "quarantine_response_deployed",
                    "producer_release_included",
                    "phase3_qualification",
                    "missing_inputs",
                },
            )
            for key in (
                "root_deployment",
                "production_activation_eligible",
                "runtime_startup_enforcement",
                "quarantine_response_deployed",
                "producer_release_included",
                "phase3_qualification",
            ):
                self.assertIs(manifest[key], False)
            self.assertEqual(len(manifest["files"]), 54)
            self.assertEqual(len(manifest["base_inputs"]), 47)
            self.assertEqual(len(manifest["new_dependencies"]), 9)
            self.assertEqual(len(manifest["directories"]), 12)
            self.assertEqual({p.name for p in root.iterdir()}, {"stage"})
            self.assertNotIn(str(root), json.dumps(manifest))
            self.assertEqual(
                sorted(
                    "/" + path.relative_to(output).as_posix()
                    for path in output.rglob("*")
                    if path.is_file()
                ),
                [item["path"] for item in manifest["files"]],
            )
            for item in manifest["files"]:
                path = output / item["path"].removeprefix("/")
                raw = path.read_bytes()
                self.assertEqual(len(raw), item["bytes"])
                self.assertEqual(_sha(raw), item["digest"])
                self.assertEqual(
                    stat.S_IMODE(path.stat().st_mode), int(item["mode"], 8)
                )
                self.assertEqual(path.stat().st_nlink, 1)
                self.assertEqual(path.stat().st_uid, os.geteuid())
                self.assertFalse(path.is_symlink())
            for name in manifest["directories"]:
                self.assertEqual(
                    stat.S_IMODE((output / name.removeprefix("/")).stat().st_mode),
                    0o755,
                )
            self.assertFalse((output / "etc").exists())
            self.assertFalse((output / "var").exists())
            self.assertFalse((output / "requirements-worker.lock").exists())
            items = {item["path"]: item for item in manifest["files"]}
            self.assertEqual(len(items.keys() - _RESPONSE_FILES.keys()), 50)
            for name, (source, mode) in _RESPONSE_FILES.items():
                self.assertEqual(items[name]["source_name"], source)
                self.assertEqual(items[name]["mode"], mode)
                self.assertEqual(
                    (output / name.removeprefix("/")).read_bytes(),
                    (_ROOT / source).read_bytes(),
                )
            self.assertFalse(
                any(
                    "aragorn-runtime-response-service.py" in item["path"]
                    or "runtime-health" in item["path"]
                    or "runtime_health" in item["path"]
                    or "protected-install-broker" in item["path"]
                    for item in manifest["files"]
                )
            )
            self.assertIn("response deployment", manifest["missing_inputs"][-1])
            self.assertNotIn("entrypoint", manifest["missing_inputs"][-1])
            # A second fresh destination yields the same path-independent manifest.
            again = subject.stage_runtime_quarantine_profile(root / "again")
            self.assertEqual(manifest, again)

    def test_catalog_exactly_covers_frozen_installer_inputs_and_pinned_sizes(self):
        references = {subject._INSTALLER}
        for script in subject._INSTALLERS:
            text = (_ROOT / script).read_text()
            references.update(re.findall(r'\$root/([^" ]+)', text))
        self.assertEqual(references, set(subject._BASE_INPUTS))
        self.assertEqual(len(references), 47)
        for name, (size, digest) in subject._BASE_INPUTS.items():
            raw = (_ROOT / name).read_bytes()
            self.assertEqual((len(raw), _sha(raw)), (size, digest), name)
        self.assertEqual(
            subject._BASE_INPUTS["packaging/install-runtime-capability-host.sh"],
            (
                3322,
                "sha256:6a7b4ec084b4dee8d974a0acab183f850be57e0acff30b616040687b307d28d9",
            ),
        )
        self.assertEqual(
            subject._BASE_INPUTS[subject._INSTALLER],
            (
                1240,
                "sha256:885441b628298629cc07d5c68e52b852864c6a755bc10d0e7e5de406f17b4748",
            ),
        )

    def test_installer_runs_only_from_verified_private_snapshot_and_fixed_environment(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            checkout = root / "checkout"
            checkout.mkdir()
            _copy_inputs(checkout)
            output = root / "stage"
            real_popen = subprocess.Popen
            calls = []

            def popen(argv, **kwargs):
                self.assertEqual(argv[0], "/bin/sh")
                snapshot = Path(kwargs["cwd"])
                self.assertNotEqual(snapshot, checkout)
                self.assertEqual(argv[1], str(snapshot / subject._INSTALLER))
                self.assertEqual(
                    kwargs["env"],
                    {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "DESTDIR": str(output)},
                )
                self.assertTrue(kwargs["start_new_session"])
                self.assertEqual(kwargs["umask"], 0o022)
                self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
                files = [path for path in snapshot.rglob("*") if path.is_file()]
                self.assertEqual(len(files), 47)
                for path in files:
                    name = path.relative_to(snapshot).as_posix()
                    self.assertEqual(
                        _sha(path.read_bytes()), subject._BASE_INPUTS[name][1]
                    )
                    self.assertEqual(
                        stat.S_IMODE(path.stat().st_mode),
                        0o555 if name in subject._INSTALLERS else 0o444,
                    )
                self.assertTrue(
                    all(
                        stat.S_IMODE(path.stat().st_mode) == 0o555
                        for path in (
                            snapshot,
                            *[p for p in snapshot.rglob("*") if p.is_dir()],
                        )
                    )
                )
                # The verified snapshot, not a later checkout reopening, is used.
                original = checkout / "src/aragorn/runtime_action_worker.py"
                original.write_bytes(b"changed after snapshot")
                calls.append(snapshot)
                return real_popen(argv, **kwargs)

            with (
                mock.patch.object(subject, "_ROOT", checkout),
                mock.patch.object(subject.subprocess, "Popen", side_effect=popen),
            ):
                subject.stage_runtime_quarantine_profile(output)
            self.assertEqual(len(calls), 1)
            self.assertFalse(calls[0].exists())
            self.assertEqual(
                _sha(
                    (
                        output / "usr/lib/aragorn/aragorn/runtime_action_worker.py"
                    ).read_bytes()
                ),
                subject._BASE_INPUTS["src/aragorn/runtime_action_worker.py"][1],
            )

    def test_new_absolute_destination_and_safe_parent_are_mandatory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            alias = root / "alias"
            alias.symlink_to(root, target_is_directory=True)
            dangling = root / "dangling"
            dangling.symlink_to(root / "absent")
            candidates = (
                root,
                alias,
                dangling,
                Path("relative"),
                str(root / "string"),
                alias / "stage",
                root / "missing" / "stage",
            )
            for output in candidates:
                with (
                    self.subTest(output=output),
                    mock.patch.object(subject, "_verified_payloads") as prepare,
                    self.assertRaises(subject.RuntimeQuarantineStageError),
                ):
                    subject.stage_runtime_quarantine_profile(output)
                prepare.assert_not_called()
            root.chmod(0o777)
            with self.assertRaises(subject.RuntimeQuarantineStageError):
                subject.stage_runtime_quarantine_profile(root / "unsafe")
            self.assertFalse((root / "unsafe").exists())

    def test_every_base_and_dependency_drift_refuses_before_destination_or_process(
        self,
    ):
        for name in (*subject._BASE_INPUTS, *subject.activation._DEPENDENCIES):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                _copy_inputs(root)
                path = root / name
                raw = path.read_bytes()
                path.write_bytes(b"!" + raw[1:])
                output = root / "stage"
                with (
                    mock.patch.object(subject, "_ROOT", root),
                    mock.patch.object(subject, "_run_installer") as installer,
                    self.assertRaises(subject.RuntimeQuarantineStageError),
                ):
                    subject.stage_runtime_quarantine_profile(output)
                installer.assert_not_called()
                self.assertFalse(output.exists())

    def test_source_size_digest_and_rendered_identity_each_fail_independently(self):
        for dimension in ("size", "digest", "runtime-render", "activation-render"):
            with (
                self.subTest(dimension=dimension),
                tempfile.TemporaryDirectory() as temporary,
            ):
                output = Path(temporary).resolve() / "stage"
                pins = subject._BASE_INPUTS.copy()
                size, digest = pins[subject._INSTALLER]
                if dimension in {"size", "digest"}:
                    pins[subject._INSTALLER] = (
                        (size + 1, digest)
                        if dimension == "size"
                        else (size, "sha256:" + "0" * 64)
                    )
                    failure = mock.patch.object(subject, "_BASE_INPUTS", pins)
                elif dimension == "runtime-render":
                    failure = mock.patch.object(
                        subject.services, "_transform", side_effect=lambda raw: raw
                    )
                else:
                    failure = mock.patch.object(
                        subject.activation,
                        "_render",
                        return_value={subject.activation._UNIT: b"changed"},
                    )
                with failure, self.assertRaises(subject.RuntimeQuarantineStageError):
                    subject.stage_runtime_quarantine_profile(output)
                self.assertFalse(output.exists())

    def test_fifo_symlink_and_hardlinked_inputs_fail_with_bounded_reads(self):
        for mutation in ("fifo", "symlink", "hardlink"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary).resolve()
                _copy_inputs(root)
                path = root / subject._INSTALLER
                if mutation == "hardlink":
                    os.link(path, root / "second-link")
                else:
                    path.unlink()
                    if mutation == "fifo":
                        os.mkfifo(path, 0o444)
                    else:
                        path.symlink_to(_ROOT / subject._INSTALLER)
                script = "from pathlib import Path\nimport sys\nfrom scripts import stage_runtime_quarantine_profile as s\ns._ROOT=Path(sys.argv[1])\ntry: s.stage_runtime_quarantine_profile(s._ROOT/'stage')\nexcept s.RuntimeQuarantineStageError: pass\nelse: raise SystemExit(1)\n"
                result = subprocess.run(
                    [sys.executable, "-B", "-c", script, str(root)],
                    cwd=_ROOT,
                    capture_output=True,
                    timeout=3,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertFalse((root / "stage").exists())

    def test_mutation_before_final_readback_cannot_return_a_manifest(self):
        for mutation in (
            "bytes",
            "mode",
            "hardlink",
            "symlink",
            "missing",
            "extra-file",
            "extra-dir",
            "directory-mode",
            "directory-symlink",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary).resolve()
                output = root / "stage"
                real_audit = subject._audit_tree

                def audit(
                    path, payloads, mutation=mutation, real_audit=real_audit, root=root
                ):
                    if len(payloads) == 54:
                        target = (
                            path
                            / "usr/lib/aragorn/aragorn/runtime_skill_startup_service.py"
                        )
                        if mutation == "bytes":
                            target.write_bytes(b"changed")
                        elif mutation == "mode":
                            target.chmod(0o666)
                        elif mutation == "hardlink":
                            os.link(target, root / "external-link")
                        elif mutation == "missing":
                            target.unlink()
                        elif mutation == "symlink":
                            target.unlink()
                            target.symlink_to(
                                _ROOT / "src/aragorn/runtime_skill_startup_service.py"
                            )
                        elif mutation == "extra-file":
                            (path / "extra").write_bytes(b"extra")
                        elif mutation == "extra-dir":
                            (path / "extra").mkdir()
                        elif mutation == "directory-mode":
                            (path / "usr/lib/aragorn").chmod(0o777)
                        else:
                            directory = path / "usr/lib/aragorn"
                            moved = root / "moved-aragorn"
                            directory.rename(moved)
                            directory.symlink_to(moved, target_is_directory=True)
                    return real_audit(path, payloads)

                with (
                    mock.patch.object(subject, "_audit_tree", side_effect=audit),
                    self.assertRaises(subject.RuntimeQuarantineStageError),
                ):
                    subject.stage_runtime_quarantine_profile(output)

    def test_file_changed_after_pinned_read_is_detected_by_final_metadata_join(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output = root / "stage"
            real_read = subject.overlay._read_pinned
            changed = []

            def read(name, size, digest, **kwargs):
                raw = real_read(name, size, digest, **kwargs)
                if kwargs.get("root") == output and name.endswith(
                    "runtime_skill_startup_service.py"
                ):
                    (output / name).write_bytes(b"x" * len(raw))
                    changed.append(True)
                return raw

            with (
                mock.patch.object(subject.overlay, "_read_pinned", side_effect=read),
                self.assertRaisesRegex(
                    subject.RuntimeQuarantineStageError, "after readback"
                ),
            ):
                subject.stage_runtime_quarantine_profile(output)
            self.assertEqual(changed, [True])

    def test_partial_write_installer_and_overlay_failures_never_report_success(self):
        for phase in ("snapshot-write", "installer", "overlay-write", "second-overlay"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                output = root / "stage"
                real_write = subject._write_new
                count = []

                def write(
                    path, raw, mode, phase=phase, real_write=real_write, count=count
                ):
                    if path.name.startswith(".aragorn-stage-"):
                        count.append(path)
                        if phase == "overlay-write" or (
                            phase == "second-overlay" and len(count) == 2
                        ):
                            raise OSError("overlay failure")
                    return real_write(path, raw, mode)

                if phase == "snapshot-write":
                    failure = mock.patch.object(subject.os, "write", return_value=0)
                elif phase == "installer":
                    failure = mock.patch.object(
                        subject,
                        "_run_installer",
                        side_effect=subject.RuntimeQuarantineStageError(
                            "installer failure"
                        ),
                    )
                else:
                    failure = mock.patch.object(
                        subject, "_write_new", side_effect=write
                    )
                with failure, self.assertRaises(subject.RuntimeQuarantineStageError):
                    subject.stage_runtime_quarantine_profile(output)
                self.assertFalse(
                    any(
                        path.name.startswith(".aragorn-runtime-stage-")
                        for path in root.iterdir()
                    )
                )
                self.assertEqual(output.exists(), phase != "snapshot-write")

    def test_installer_failure_and_timeout_reap_only_the_owned_process(self):
        process = mock.Mock(pid=12345, returncode=1)
        process.communicate.return_value = (b"", b"failure")
        with (
            mock.patch.object(subject.subprocess, "Popen", return_value=process),
            self.assertRaisesRegex(
                subject.RuntimeQuarantineStageError, "installer failed"
            ),
        ):
            subject._run_installer(Path("/private-snapshot"), Path("/new-destdir"))
        process = mock.Mock(pid=12345, returncode=-9)
        process.poll.return_value = None
        process.communicate.side_effect = [
            subprocess.TimeoutExpired("frozen-installer", 20),
            (b"", b""),
        ]
        with (
            mock.patch.object(subject.subprocess, "Popen", return_value=process),
            mock.patch.object(subject.os, "killpg") as kill,
            self.assertRaisesRegex(
                subject.RuntimeQuarantineStageError, "did not complete"
            ),
        ):
            subject._run_installer(Path("/private-snapshot"), Path("/new-destdir"))
        kill.assert_called_once_with(12345, subject.signal.SIGKILL)
        self.assertEqual(
            process.communicate.call_args_list,
            [mock.call(timeout=20), mock.call(timeout=5)],
        )

    def test_already_reaped_installer_is_never_signalled_on_interruption(self):
        process = mock.Mock(pid=12345, returncode=0)
        process.poll.return_value = 0
        process.communicate.side_effect = [KeyboardInterrupt, (b"", b"")]
        with (
            mock.patch.object(subject.subprocess, "Popen", return_value=process),
            mock.patch.object(subject.os, "killpg") as kill,
            self.assertRaises(subject.RuntimeQuarantineStageError),
        ):
            subject._run_installer(Path("/private-snapshot"), Path("/new-destdir"))
        kill.assert_not_called()

    def test_audit_root_rebinding_and_close_failure_fail_without_descriptor_leaks(self):
        for mutation in ("root-rebinding", "close-failure"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                base = Path(temporary).resolve()
                output = base / "stage"
                output.mkdir(mode=0o755)
                target = output / "file"
                target.write_bytes(b"fixed")
                target.chmod(0o644)
                payloads = {"file": ("source", 0o644, b"fixed")}
                root_fds = []
                real_open, real_close = os.open, os.close

                def opened(
                    path,
                    flags,
                    *args,
                    real_open=real_open,
                    mutation=mutation,
                    output=output,
                    base=base,
                    root_fds=root_fds,
                    **kwargs,
                ):
                    fd = real_open(path, flags, *args, **kwargs)
                    if path == output:
                        root_fds.append(fd)
                        if mutation == "root-rebinding":
                            output.rename(base / "old-stage")
                            output.mkdir(mode=0o755)
                            (output / "file").write_bytes(b"fixed")
                            (output / "file").chmod(0o644)
                    return fd

                def closed(
                    fd, real_close=real_close, mutation=mutation, root_fds=root_fds
                ):
                    real_close(fd)
                    if mutation == "close-failure" and fd in root_fds:
                        raise OSError("post-close failure")

                with (
                    mock.patch.object(subject.os, "open", side_effect=opened),
                    mock.patch.object(subject.os, "close", side_effect=closed),
                    self.assertRaises(subject.RuntimeQuarantineStageError),
                ):
                    subject._audit_tree(output, payloads)
                self.assertEqual(len(root_fds), 1)
                with self.assertRaises(OSError):
                    os.fstat(root_fds[0])

    def test_fresh_staged_imports_use_successors_and_shim_refuses_arguments(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "stage"
            subject.stage_runtime_quarantine_profile(output)
            package = output / "usr/lib/aragorn"
            script = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from aragorn import runtime_action_broker_v5 as broker
from aragorn import runtime_action_observation_publisher_v4 as sensor
from aragorn import runtime_lineage_capability_issuer as issuer
from aragorn import runtime_active_skill_lineage_v2 as lineage
from aragorn import runtime_skill_startup_service as startup
from aragorn import runtime_quarantine_service as quarantine_service
from aragorn import runtime_quarantine_response as quarantine
from aragorn import runtime_response_service as response
assert broker.hold_runtime_active_skill_lineage is lineage.hold_runtime_active_skill_lineage
assert sensor.verify_runtime_active_skill_lineage is lineage.verify_runtime_active_skill_lineage
assert issuer.hold_runtime_active_skill_lineage is lineage.hold_runtime_active_skill_lineage
assert quarantine_service.response is quarantine
assert quarantine.response is response
assert quarantine.startup is startup.startup
for module in (broker, sensor, issuer, lineage, startup, quarantine_service, quarantine, response):
    assert Path(module.__file__).parent == Path(sys.argv[1]) / 'aragorn'
"""
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c", script, str(package)],
                cwd="/",
                env={"PATH": "/usr/bin:/bin"},
                capture_output=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            shim = (
                output / "usr/libexec/aragorn/aragorn-runtime-skill-startup-service.py"
            )
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(shim), "--refuse"],
                cwd="/",
                env={"PATH": "/usr/bin:/bin"},
                capture_output=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 64, result.stderr.decode())
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"usage: aragorn-runtime-skill-startup", result.stderr)
            shim = output / "usr/libexec/aragorn/aragorn-runtime-quarantine-service.py"
            # Argument refusal occurs before platform/root checks or response effects.
            for arguments, status, diagnostic in (
                ([], 64, b"usage: aragorn-runtime-quarantine-service"),
                (["--refuse"], 64, b"usage: aragorn-runtime-quarantine-service"),
                (["invalid", "invalid"], 126, b"REFUSED"),
            ):
                with self.subTest(arguments=arguments):
                    result = subprocess.run(
                        [sys.executable, "-I", "-S", "-B", str(shim), *arguments],
                        cwd="/",
                        env={"PATH": "/usr/bin:/bin"},
                        capture_output=True,
                        timeout=5,
                        check=False,
                    )
                    self.assertEqual(result.returncode, status, result.stderr.decode())
                    self.assertEqual(result.stdout, b"")
                    self.assertIn(diagnostic, result.stderr)


if __name__ == "__main__":
    unittest.main()
