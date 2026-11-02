from __future__ import annotations

import io
import os
import runpy
import stat
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aragorn import runtime_skill_startup_service as subject
from aragorn.oci_worker_protocol import canonical_json
from tests.test_runtime_skill_startup import _fixture as _startup_fixture
from tests.test_runtime_skill_startup import _publish, _write

_WORKER_UID = os.geteuid() or 10001


@contextmanager
def _fixture():
    with _startup_fixture() as fixture:
        directory = fixture["root"].parent / "credentials"
        directory.mkdir(mode=0o700)
        binding = {
            "schema": subject.worker._BINDING_SCHEMA,
            **subject.startup._binding_document(fixture["binding"]),
        }
        _write(directory / "worker-binding", canonical_json(binding), 0o400)
        _write(directory / "openclaw-config", canonical_json(fixture["config"]), 0o400)
        fixture.update(directory=directory, binding_document=binding)
        with (
            mock.patch.object(subject, "_CREDENTIAL_DIRECTORY", directory),
            mock.patch.object(subject, "_EXPECTED_ROOT_UID", os.geteuid()),
            mock.patch.object(subject.sys, "platform", "linux"),
            mock.patch.object(
                subject.worker, "_service_identities", return_value=(_WORKER_UID,)
            ),
            mock.patch.object(
                subject.os,
                "fstatvfs",
                return_value=SimpleNamespace(f_flag=os.ST_RDONLY),
            ),
            mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(directory)}),
        ):
            yield fixture


def _main(arguments=()):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = subject.main(arguments)
    return status, stdout.getvalue(), stderr.getvalue()


@contextmanager
def _metadata(path, **updates):
    inode = path.lstat().st_ino
    real_stat, real_fstat = os.stat, os.fstat

    def changed(metadata):
        if metadata.st_ino != inode:
            return metadata
        fields = {
            name: getattr(metadata, name)
            for name in dir(metadata)
            if name.startswith("st_")
        }
        fields.update(updates)
        return SimpleNamespace(**fields)

    with (
        mock.patch.object(
            os, "stat", side_effect=lambda *a, **k: changed(real_stat(*a, **k))
        ),
        mock.patch.object(os, "fstat", side_effect=lambda fd: changed(real_fstat(fd))),
    ):
        yield


class RuntimeSkillStartupServiceTests(unittest.TestCase):
    def test_fixed_identity_paths_and_real_byte_verification_succeed_silently(self):
        self.assertEqual(
            subject._CREDENTIAL_DIRECTORY,
            Path("/run/credentials/aragorn-runtime-action-worker.service"),
        )
        with _fixture() as fixture:
            snapshot = subject._run()
            self.assertEqual(
                snapshot["active_skill_digest"], fixture["binding"].active_skill_digest
            )
            self.assertIn("POINT_IN_TIME", snapshot["authority"])
            self.assertEqual(_main(), (0, "", ""))
            self.assertEqual(subject.worker._service_identities.call_count, 2)

    def test_arguments_never_reach_identity_or_filesystem(self):
        for arguments in (
            ["--help"],
            ["/arbitrary/path"],
            ["worker-binding", "openclaw-config"],
        ):
            with (
                self.subTest(arguments=arguments),
                mock.patch.object(subject, "_run") as run,
            ):
                status, stdout, stderr = _main(arguments)
                self.assertEqual(status, 64)
                self.assertEqual(stdout, "")
                self.assertIn("usage:", stderr)
                run.assert_not_called()

    def test_platform_identity_root_and_interrupt_fail_closed(self):
        for mutation in ("platform", "identity", "root", "interrupt"):
            with self.subTest(mutation=mutation), _fixture():
                patch = {
                    "platform": mock.patch.object(subject.sys, "platform", "darwin"),
                    "identity": mock.patch.object(
                        subject.worker,
                        "_service_identities",
                        side_effect=ValueError("secret"),
                    ),
                    "root": mock.patch.object(
                        subject.worker, "_service_identities", return_value=(0,)
                    ),
                    "interrupt": mock.patch.object(
                        subject.worker,
                        "_service_identities",
                        side_effect=KeyboardInterrupt,
                    ),
                }[mutation]
                with patch:
                    self.assertEqual(
                        _main(),
                        (
                            126,
                            "",
                            "aragorn runtime skill startup: verification failed\n",
                        ),
                    )

    def test_environment_must_name_exact_fixed_canonical_directory(self):
        for mutation in ("absent", "relative", "slash", "dot", "other"):
            with self.subTest(mutation=mutation), _fixture() as fixture:
                directory = str(fixture["directory"])
                values = {
                    "relative": "credentials",
                    "slash": directory + "/",
                    "dot": directory + "/.",
                    "other": directory + "-other",
                }
                if mutation == "absent":
                    os.environ.pop("CREDENTIALS_DIRECTORY")
                else:
                    os.environ["CREDENTIALS_DIRECTORY"] = values[mutation]
                with mock.patch.object(
                    subject.startup, "_verify_runtime_skill_startup"
                ) as verify:
                    self.assertEqual(_main()[0], 126)
                    verify.assert_not_called()

    def test_namespace_requires_exactly_two_credentials(self):
        for mutation in ("missing-binding", "missing-config", "extra"):
            with self.subTest(mutation=mutation), _fixture() as fixture:
                directory = fixture["directory"]
                if mutation == "extra":
                    _write(directory / "extra", b"extra", 0o400)
                else:
                    (
                        directory
                        / (
                            "worker-binding"
                            if mutation == "missing-binding"
                            else "openclaw-config"
                        )
                    ).unlink()
                with mock.patch.object(
                    subject.startup, "_verify_runtime_skill_startup"
                ) as verify:
                    self.assertEqual(_main()[0], 126)
                    verify.assert_not_called()

    def test_unsafe_directory_ancestry_and_symlink_are_rejected(self):
        for mutation in (
            "directory-mode",
            "ancestor-mode",
            "directory-owner",
            "ancestor-owner",
            "symlink",
        ):
            with self.subTest(mutation=mutation), _fixture() as fixture:
                directory = fixture["directory"]
                path = (
                    directory.parent if mutation.startswith("ancestor") else directory
                )
                if mutation.endswith("mode"):
                    path.chmod(0o777)
                elif mutation == "symlink":
                    moved = directory.with_name("original-credentials")
                    directory.rename(moved)
                    directory.symlink_to(moved, target_is_directory=True)
                if mutation.endswith("owner"):
                    with _metadata(path, st_uid=os.geteuid() + 10000):
                        self.assertEqual(_main()[0], 126)
                else:
                    self.assertEqual(_main()[0], 126)

    def test_service_and_root_credential_modes_have_exact_owner_contract(self):
        for uid, gid, mode, accepted in (
            (_WORKER_UID, os.getegid(), 0o400, True),
            (_WORKER_UID, os.getegid(), 0o440, False),
            (0, 0, 0o400, True),
            (0, 0, 0o440, True),
            (0, os.getegid() or 1, 0o440, False),
            (os.geteuid() + 10000, os.getegid(), 0o400, False),
            (_WORKER_UID, os.getegid(), 0o600, False),
        ):
            with self.subTest(uid=uid, gid=gid, mode=mode), _fixture() as fixture:
                path = fixture["directory"] / "worker-binding"
                with _metadata(
                    path, st_uid=uid, st_gid=gid, st_mode=stat.S_IFREG | mode
                ):
                    self.assertEqual(_main()[0], 0 if accepted else 126)

    def test_file_type_link_and_size_denials_precede_byte_verifier(self):
        for name in subject._CREDENTIAL_NAMES:
            for mutation in ("symlink", "directory", "hardlink", "empty", "oversize"):
                with self.subTest(name=name, mutation=mutation), _fixture() as fixture:
                    path = fixture["directory"] / name
                    if mutation == "hardlink":
                        os.link(path, fixture["directory"].parent / "hardlink")
                    else:
                        path.unlink()
                        if mutation == "symlink":
                            path.symlink_to(fixture["external"])
                        elif mutation == "directory":
                            path.mkdir(mode=0o500)
                        else:
                            bound = (
                                subject._MAX_BINDING_BYTES
                                if name == "worker-binding"
                                else subject.startup._MAX_CONFIG_BYTES
                            )
                            _write(
                                path,
                                b"" if mutation == "empty" else b"x" * (bound + 1),
                                0o400,
                            )
                    with mock.patch.object(
                        subject.startup, "_verify_runtime_skill_startup"
                    ) as verify:
                        self.assertEqual(_main()[0], 126)
                        verify.assert_not_called()

    def test_fifo_substitution_uses_nonblocking_open_before_type_rejection(self):
        for name in subject._CREDENTIAL_NAMES:
            with self.subTest(name=name), _fixture() as fixture:
                path = fixture["directory"] / name
                real_open = os.open
                substituted = []

                def raced_open(
                    open_name,
                    flags,
                    *args,
                    name=name,
                    path=path,
                    real_open=real_open,
                    substituted=substituted,
                    **kwargs,
                ):
                    if open_name == name and kwargs.get("dir_fd") is not None:
                        # This assertion bounds the test even if O_NONBLOCK regresses.
                        self.assertTrue(flags & os.O_NONBLOCK)
                        path.unlink()
                        os.mkfifo(path, 0o400)
                        substituted.append(True)
                    return real_open(open_name, flags, *args, **kwargs)

                with mock.patch.object(subject.os, "open", side_effect=raced_open):
                    self.assertEqual(_main()[0], 126)
                self.assertEqual(substituted, [True])

    def test_canonical_binding_schema_digest_and_types_are_strict(self):
        for mutation in (
            "schema",
            "extra",
            "missing",
            "boolean",
            "float",
            "zero",
            "uppercase",
            "signed-hex",
            "newline",
            "duplicate",
            "nan",
        ):
            with self.subTest(mutation=mutation), _fixture() as fixture:
                document = fixture["binding_document"].copy()
                if mutation == "schema":
                    document["schema"] = "wrong"
                elif mutation == "extra":
                    document["extra"] = True
                elif mutation == "missing":
                    document.pop("runtime_digest")
                elif mutation in {"boolean", "float", "zero"}:
                    document["policy_version"] = {
                        "boolean": True,
                        "float": 1.0,
                        "zero": 0,
                    }[mutation]
                elif mutation in {"uppercase", "signed-hex"}:
                    document["runtime_digest"] = "sha256:" + (
                        "A" * 64 if mutation == "uppercase" else "+" + "a" * 63
                    )
                raw = canonical_json(document)
                if mutation == "newline":
                    raw += b"\n"
                elif mutation == "duplicate":
                    raw = b'{"schema":"duplicate",' + raw[1:]
                elif mutation == "nan":
                    raw = raw.replace(b'"policy_version":1', b'"policy_version":NaN')
                _write(fixture["directory"] / "worker-binding", raw, 0o400)
                with mock.patch.object(
                    subject.startup, "_verify_runtime_skill_startup"
                ) as verify:
                    self.assertEqual(_main()[0], 126)
                    verify.assert_not_called()

    def test_config_canonical_json_and_actual_selection_are_checked(self):
        for mutation in (
            "array",
            "invalid",
            "newline",
            "duplicate",
            "wrong-source",
            "boolean-coercion",
        ):
            with self.subTest(mutation=mutation), _fixture() as fixture:
                config = fixture["config"]
                if mutation == "wrong-source":
                    config["skills"]["activation"]["sources"][0]["filePath"] = (
                        "/arbitrary/SKILL.md"
                    )
                elif mutation == "boolean-coercion":
                    config["skills"]["load"]["watch"] = 0
                raw = canonical_json(config)
                if mutation == "array":
                    raw = b"[]"
                elif mutation == "invalid":
                    raw = b"\xff"
                elif mutation == "newline":
                    raw += b"\n"
                elif mutation == "duplicate":
                    raw = b'{"skills":{},' + raw[1:]
                _write(fixture["directory"] / "openclaw-config", raw, 0o400)
                self.assertEqual(_main()[0], 126)

    def test_real_installed_byte_mismatch_and_quarantine_deny_startup(self):
        for mutation in ("installed", "external", "quarantined"):
            with self.subTest(mutation=mutation), _fixture() as fixture:
                if mutation == "quarantined":
                    _publish(fixture)
                else:
                    _write(
                        fixture["skill" if mutation == "installed" else "external"],
                        b"changed bytes",
                    )
                self.assertEqual(_main()[0], 126)

    def test_credential_and_directory_fds_remain_open_through_guard_and_close(self):
        with _fixture() as fixture:
            real_open = os.open
            opened = []

            def tracked_open(*args, **kwargs):
                fd = real_open(*args, **kwargs)
                opened.append(fd)
                return fd

            def verify(binding, config):
                self.assertEqual(binding, fixture["binding"])
                self.assertEqual(config, fixture["config"])
                self.assertGreaterEqual(len(opened), 3)
                for fd in opened:
                    os.fstat(fd)
                return {"bounded": "snapshot"}

            with (
                mock.patch.object(subject.os, "open", side_effect=tracked_open),
                mock.patch.object(
                    subject.startup, "_verify_runtime_skill_startup", side_effect=verify
                ),
            ):
                self.assertEqual(subject._run(), {"bounded": "snapshot"})
            for fd in opened:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_post_verification_mutations_never_report_success(self):
        for mutation in (
            "binding",
            "config",
            "replace-file",
            "namespace",
            "directory",
            "ancestor",
            "environment",
            "mount",
        ):
            with self.subTest(mutation=mutation), _fixture() as fixture:
                directory = fixture["directory"]

                def verify(*_args, mutation=mutation, directory=directory):
                    if mutation in {"binding", "config"}:
                        name = (
                            "worker-binding"
                            if mutation == "binding"
                            else "openclaw-config"
                        )
                        _write(directory / name, b"changed", 0o400)
                    elif mutation == "replace-file":
                        raw = (directory / "worker-binding").read_bytes()
                        (directory / "worker-binding").unlink()
                        _write(directory / "worker-binding", raw, 0o400)
                    elif mutation == "namespace":
                        _write(directory / "extra", b"extra", 0o400)
                    elif mutation == "directory":
                        directory.rename(directory.with_name("old-credentials"))
                        directory.mkdir(mode=0o700)
                    elif mutation == "ancestor":
                        directory.parent.chmod(0o777)
                    elif mutation == "environment":
                        os.environ["CREDENTIALS_DIRECTORY"] += "-changed"
                    elif mutation == "mount":
                        subject.os.fstatvfs.return_value = SimpleNamespace(f_flag=0)
                    return {"success": True}

                with mock.patch.object(
                    subject.startup, "_verify_runtime_skill_startup", side_effect=verify
                ):
                    self.assertEqual(_main()[0:2], (126, ""))

    def test_read_only_directory_and_each_credential_mount_are_required(self):
        for kind in ("directory", "worker-binding", "openclaw-config"):
            with self.subTest(kind=kind), _fixture() as fixture:
                path = (
                    fixture["directory"]
                    if kind == "directory"
                    else fixture["directory"] / kind
                )
                inode = path.stat().st_ino

                def mount(fd, inode=inode):
                    return SimpleNamespace(
                        f_flag=0 if os.fstat(fd).st_ino == inode else os.ST_RDONLY
                    )

                with mock.patch.object(subject.os, "fstatvfs", side_effect=mount):
                    self.assertEqual(_main()[0], 126)

    def test_unrelated_ancestor_entries_do_not_break_stable_custody(self):
        with _fixture() as fixture:

            def verify(*_args):
                _write(fixture["directory"].parent / "unrelated", b"unrelated")
                return {"point-in-time": True}

            with mock.patch.object(
                subject.startup, "_verify_runtime_skill_startup", side_effect=verify
            ):
                self.assertEqual(_main(), (0, "", ""))

    def test_read_time_changes_and_premature_eof_never_reach_guard(self):
        for name in subject._CREDENTIAL_NAMES:
            for mutation in ("eof", "change", "growth"):
                with self.subTest(name=name, mutation=mutation), _fixture() as fixture:
                    path = fixture["directory"] / name
                    inode = path.stat().st_ino
                    real_read = os.read
                    changed = []

                    def read(
                        fd,
                        size,
                        inode=inode,
                        mutation=mutation,
                        path=path,
                        changed=changed,
                        real_read=real_read,
                    ):
                        if os.fstat(fd).st_ino != inode or changed:
                            return real_read(fd, size)
                        changed.append(True)
                        if mutation == "eof":
                            return b""
                        raw = real_read(fd, size)
                        _write(
                            path,
                            raw + b"x" if mutation == "growth" else b"x" * len(raw),
                            0o400,
                        )
                        return raw

                    with (
                        mock.patch.object(subject.os, "read", side_effect=read),
                        mock.patch.object(
                            subject.startup, "_verify_runtime_skill_startup"
                        ) as verify,
                    ):
                        self.assertEqual(_main()[0], 126)
                        verify.assert_not_called()
                    self.assertEqual(changed, [True])

    def test_short_reads_are_supported_and_read_failures_release_all_fds(self):
        with _fixture():
            real_read = os.read
            with mock.patch.object(
                subject.os,
                "read",
                side_effect=lambda fd, size: real_read(fd, min(size, 3)),
            ):
                self.assertEqual(_main(), (0, "", ""))
        with _fixture():
            real_open = os.open
            opened = []

            def tracked_open(*args, **kwargs):
                fd = real_open(*args, **kwargs)
                opened.append(fd)
                return fd

            with (
                mock.patch.object(subject.os, "open", side_effect=tracked_open),
                mock.patch.object(
                    subject.os, "read", side_effect=OSError("read failed")
                ),
            ):
                self.assertEqual(_main()[0], 126)
            for fd in opened:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_cleanup_failure_closes_remaining_fds_and_never_reports_success(self):
        for guard_fails in (False, True):
            with self.subTest(guard_fails=guard_fails), _fixture():
                real_close = os.close
                closed = []

                def close(fd, real_close=real_close, closed=closed):
                    real_close(fd)
                    closed.append(fd)
                    if len(closed) == 1:
                        raise OSError("post-close failure")

                with (
                    mock.patch.object(subject.os, "close", side_effect=close),
                    mock.patch.object(
                        subject.startup,
                        "_verify_runtime_skill_startup",
                        side_effect=ValueError("guard failed") if guard_fails else None,
                        return_value={},
                    ),
                ):
                    self.assertEqual(_main()[0:2], (126, ""))
                self.assertGreaterEqual(len(closed), 3)
                for fd in closed:
                    with self.assertRaises(OSError):
                        os.fstat(fd)

    def test_shim_imports_only_fixed_installed_module_and_preserves_exit_code(self):
        shim = (
            Path(__file__).resolve().parents[1]
            / "packaging/libexec/aragorn-runtime-skill-startup-service.py"
        )
        module = SimpleNamespace(main=mock.Mock(return_value=126))
        with (
            mock.patch("importlib.import_module", return_value=module) as imported,
            mock.patch.object(subject.sys, "path", list(subject.sys.path)),
            self.assertRaises(SystemExit) as raised,
        ):
            runpy.run_path(str(shim))
        self.assertEqual(raised.exception.code, 126)
        imported.assert_called_once_with("aragorn.runtime_skill_startup_service")
        module.main.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
