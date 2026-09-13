from __future__ import annotations

import ast
import copy
import io
import os
import stat
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from aragorn import runtime_action_worker as worker
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import materialize_runtime_native_gateway_credentials as subject
from tests.test_runtime_skill_startup_service import _metadata

_ROOT = subject._ROOT
_UID = os.geteuid() or 10001
_GID = os.getegid() or 10002
_WORKER_UID = _UID + 100
_WORKER_GID = _GID + 100


def _module():
    raw = subject._verified_inputs()["runtime_native_gateway_credentials.py"]
    name = "aragorn._native_gateway_credentials_test"
    result = types.ModuleType(name)
    result.__package__ = "aragorn"
    with mock.patch.dict(sys.modules, {name: result}):
        exec(compile(raw, name, "exec"), result.__dict__)  # noqa: S102 - exact pinned local source
    return result


def _write(path, raw):
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(0o400)


@contextmanager
def _fixture(module):
    # Synthetic projected credentials. No real service credentials are accessed.
    with tempfile.TemporaryDirectory(dir=Path.home().resolve()) as temporary:
        directory = Path(temporary).resolve() / "credentials"
        directory.mkdir(mode=0o700)
        config = {
            "sensitive_unselected_config": "never-output-this-value",
            "plugins": {
                "allow": ["aragorn-runtime-action-worker"],
                "enabled": True,
                "entries": {
                    "aragorn-runtime-action-worker": {
                        "enabled": True,
                        "config": {
                            "expectedGatewayGid": _GID,
                            "expectedGatewayUid": _UID,
                            "expectedWorkerUid": _WORKER_UID,
                            "workerSocketPath": "/run/aragorn-runtime-action-worker/worker.sock",
                        },
                    }
                },
                "load": {
                    "paths": ["/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker"]
                },
            },
        }
        genesis = {
            "schema": "aragorn/native-tool-receipt-genesis/v1",
            "authority": "ROOT_PROVISIONED_WORKER_RECEIPT_STREAM_NOT_RUN_AUTHORITY",
            "stream_id": "sha256:" + "a" * 64,
            "worker_uid": _WORKER_UID,
            "worker_gid": _WORKER_GID,
            "runtime_digest": "sha256:" + "b" * 64,
            "policy_digest": "sha256:" + "c" * 64,
            "policy_version": 1,
        }
        for name, value in (
            ("openclaw-config", config),
            ("native-tool-genesis", genesis),
        ):
            _write(directory / name, canonical_json(value))
        users = {
            worker._GATEWAY_PRINCIPAL: types.SimpleNamespace(pw_uid=_UID, pw_gid=_GID),
            worker._WORKER_PRINCIPAL: types.SimpleNamespace(
                pw_uid=_WORKER_UID, pw_gid=_WORKER_GID
            ),
        }
        groups = {
            worker._GATEWAY_PRINCIPAL: types.SimpleNamespace(gr_gid=_GID),
            worker._WORKER_PRINCIPAL: types.SimpleNamespace(gr_gid=_WORKER_GID),
        }
        with ExitStack() as stack:
            for target, name, value in (
                (module, "_CREDENTIAL_DIRECTORY", directory),
                (module, "_EXPECTED_ROOT_UID", os.geteuid()),
                (module.sys, "platform", "linux"),
                (module.pwd, "getpwnam", mock.Mock(side_effect=users.__getitem__)),
                (module.grp, "getgrnam", mock.Mock(side_effect=groups.__getitem__)),
                (module.os, "getuid", mock.Mock(return_value=_UID)),
                (module.os, "geteuid", mock.Mock(return_value=_UID)),
                (module.os, "getgid", mock.Mock(return_value=_GID)),
                (module.os, "getegid", mock.Mock(return_value=_GID)),
                (module.os, "getgroups", mock.Mock(return_value=[_GID])),
                (
                    module.os,
                    "fstatvfs",
                    mock.Mock(return_value=types.SimpleNamespace(f_flag=os.ST_RDONLY)),
                ),
            ):
                stack.enter_context(mock.patch.object(target, name, value))
            stack.enter_context(
                mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(directory)})
            )
            yield types.SimpleNamespace(
                directory=directory,
                config=config,
                genesis=genesis,
                users=users,
                groups=groups,
            )


def _main(module, arguments=()):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = module.main(arguments)
    return status, stdout.getvalue(), stderr.getvalue()


class NativeGatewayCredentialTests(unittest.TestCase):
    def test_exact_render_publication_custody_and_unit_delta(self):
        rendered = subject._verified_inputs()
        self.assertEqual(set(rendered), set(subject._OUTPUTS))
        old = subject.overlay._read_pinned(
            subject._HELPER, *subject._INPUTS[subject._HELPER], root=_ROOT
        ).decode()
        new = rendered["runtime_native_gateway_credentials.py"].decode()
        for name in (
            "_Held",
            "_custody",
            "_recheck",
            "_open_directory",
            "_read_credential",
        ):
            parts = []
            for source in (old, new):
                node = next(
                    node
                    for node in ast.parse(source).body
                    if getattr(node, "name", None) == name
                )
                parts.append(ast.get_source_segment(source, node))
            self.assertEqual(*parts)
        original_unit = subject.overlay._read_pinned(
            subject._UNIT, *subject._INPUTS[subject._UNIT], root=_ROOT
        )
        unit = rendered["aragorn-agent-gateway.service"]
        projection = b"LoadCredential=native-tool-genesis:/etc/aragorn/runtime-native-tool-genesis.json\n"
        self.assertEqual(unit.count(projection), 1)
        self.assertEqual(
            unit.replace(projection, b"").replace(
                b"InaccessiblePaths=/etc/aragorn/agent-gateway /etc/aragorn/runtime-native-tool-genesis.json\n",
                b"InaccessiblePaths=/etc/aragorn/agent-gateway\n",
            ),
            original_unit,
        )
        self.assertNotIn(b"ExecStartPre", unit)
        self.assertIn(
            b'"aragorn.runtime_native_gateway_credentials"',
            rendered["aragorn-runtime-native-gateway-credentials.py"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "output"
            manifest = subject.materialize_runtime_native_gateway_credentials(output)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o555)
            self.assertEqual({path.name for path in output.iterdir()}, set(rendered))
            for name, raw in rendered.items():
                self.assertEqual((output / name).read_bytes(), raw)
                self.assertEqual(stat.S_IMODE((output / name).stat().st_mode), 0o444)
                self.assertEqual(
                    (len(raw), subject.overlay._digest(raw)), subject._OUTPUTS[name]
                )
            for name in (
                "standalone_executable",
                "production_activation_eligible",
                "gateway_credential_projection_verified",
                "native_hook_reachability",
                "run_eligible",
            ):
                self.assertIs(manifest[name], False)
            output.chmod(0o700)

    def test_positive_result_is_bounded_nonsecret_and_never_opens_receipt_store(self):
        module = _module()
        self.assertEqual(
            module._CREDENTIAL_DIRECTORY,
            Path("/run/credentials/aragorn-agent-gateway.service"),
        )
        self.assertEqual(
            module._CREDENTIAL_NAMES, {"openclaw-config", "native-tool-genesis"}
        )
        with (
            _fixture(module) as fixture,
            mock.patch.object(module.receipts, "NativeToolReceiptStore") as store,
        ):
            status, stdout, stderr = _main(module)
            expected = {
                "worker_config": fixture.config["plugins"]["entries"][
                    "aragorn-runtime-action-worker"
                ]["config"],
                "genesis_digest": canonical_digest(fixture.genesis),
            }
            self.assertEqual(
                (status, stdout.encode(), stderr), (0, canonical_json(expected), "")
            )
            self.assertLessEqual(len(stdout.encode()), 1024)
            self.assertNotIn("never-output-this-value", stdout)
            self.assertNotIn("runtime_digest", stdout)
            store.assert_not_called()
            self.assertEqual(
                module.pwd.getpwnam.call_args_list,
                [
                    mock.call(worker._GATEWAY_PRINCIPAL),
                    mock.call(worker._WORKER_PRINCIPAL),
                ],
            )
            self.assertEqual(
                module.grp.getgrnam.call_args_list, module.pwd.getpwnam.call_args_list
            )
            self.assertEqual(
                expected["worker_config"]["workerSocketPath"],
                str(worker._WORKER_RUNTIME_DIRECTORY / "worker.sock"),
            )
            for arguments in (
                ["--help"],
                [str(fixture.directory)],
                ["native-tool-genesis"],
            ):
                with mock.patch.object(module, "_run") as run:
                    self.assertEqual(_main(module, arguments)[0:2], (64, ""))
                    run.assert_not_called()

    def test_platform_nss_real_effective_and_supplementary_identity_refusals(self):
        module = _module()
        for mode in (
            "platform",
            "missing-user",
            "missing-group",
            "root",
            "bool",
            "uid-overflow",
            "same-uid",
            "same-gid",
            "primary-group",
            "getuid",
            "geteuid",
            "getgid",
            "getegid",
            "supplementary",
            "interrupt",
        ):
            with (
                self.subTest(mode=mode),
                _fixture(module) as fixture,
                ExitStack() as stack,
            ):
                if mode == "platform":
                    stack.enter_context(
                        mock.patch.object(module.sys, "platform", "darwin")
                    )
                elif mode.startswith("missing") or mode == "interrupt":
                    target = (
                        module.grp.getgrnam
                        if mode == "missing-group"
                        else module.pwd.getpwnam
                    )
                    target.side_effect = (
                        KeyboardInterrupt("secret")
                        if mode == "interrupt"
                        else KeyError("secret")
                    )
                elif mode in {"root", "bool", "uid-overflow", "same-uid"}:
                    fixture.users["aragorn-agent-gateway"].pw_uid = {
                        "root": 0,
                        "bool": True,
                        "uid-overflow": 2**32,
                        "same-uid": _WORKER_UID,
                    }[mode]
                elif mode == "same-gid":
                    fixture.groups[worker._WORKER_PRINCIPAL].gr_gid = _GID
                elif mode == "primary-group":
                    fixture.users[worker._WORKER_PRINCIPAL].pw_gid += 1
                else:
                    function = (
                        module.os.getgroups
                        if mode == "supplementary"
                        else getattr(module.os, mode)
                    )
                    function.return_value = (
                        [_GID, _WORKER_GID] if mode == "supplementary" else 0
                    )
                with mock.patch.object(module, "_open_directory") as open_directory:
                    self.assertEqual(
                        _main(module),
                        (
                            126,
                            "",
                            "aragorn native gateway credentials: verification failed\n",
                        ),
                    )
                    open_directory.assert_not_called()

    def test_exact_genesis_and_selected_plugin_fields_fail_closed(self):
        module = _module()
        changes = [
            ("genesis", "schema", "wrong"),
            ("genesis", "authority", "wrong"),
            ("genesis", "extra", 1),
            ("genesis", "worker_uid", _WORKER_UID + 1),
            ("genesis", "worker_gid", _WORKER_GID + 1),
            *[
                ("genesis", name, value)
                for name in ("stream_id", "runtime_digest", "policy_digest")
                for value in (None, "sha256:" + "A" * 64, "sha256:" + "b" * 63, True)
            ],
            *[
                ("genesis", name, value)
                for name in ("policy_version", "worker_uid", "worker_gid")
                for value in (True, 0, -1, 1.0, 2**53)
            ],
            *[
                ("worker", name, value)
                for name, value in (
                    ("extra", 1),
                    ("expectedGatewayUid", True),
                    ("expectedGatewayGid", _GID + 1),
                    ("expectedWorkerUid", _UID),
                    ("workerSocketPath", "/tmp/worker.sock"),
                )
            ],
            *[
                ("plugins", name, value)
                for name, value in (
                    ("allow", []),
                    ("enabled", 1),
                    ("extra", True),
                    ("load", {"paths": ["/tmp/plugin"]}),
                )
            ],
        ]
        for kind, name, value in changes:
            with (
                self.subTest(kind=kind, name=name, value=value),
                _fixture(module) as fixture,
            ):
                target = (
                    fixture.genesis
                    if kind == "genesis"
                    else fixture.config["plugins"]
                    if kind == "plugins"
                    else fixture.config["plugins"]["entries"][
                        "aragorn-runtime-action-worker"
                    ]["config"]
                )
                target[name] = value
                path = fixture.directory / (
                    "native-tool-genesis" if kind == "genesis" else "openclaw-config"
                )
                _write(
                    path,
                    canonical_json(
                        fixture.genesis if kind == "genesis" else fixture.config
                    ),
                )
                self.assertEqual(_main(module)[0:2], (126, ""))
        for name in module._CREDENTIAL_NAMES:
            for mutation in (
                "newline",
                "duplicate",
                "noncanonical",
                "array",
                "invalid-utf8",
                "empty",
                "oversize",
                "missing-key",
            ):
                with (
                    self.subTest(name=name, mutation=mutation),
                    _fixture(module) as fixture,
                ):
                    document = (
                        fixture.genesis
                        if name == "native-tool-genesis"
                        else fixture.config
                    )
                    raw = canonical_json(document)
                    if mutation == "missing-key":
                        document.pop(
                            "stream_id" if name == "native-tool-genesis" else "plugins"
                        )
                        raw = canonical_json(document)
                    raw = {
                        "newline": raw + b"\n",
                        "duplicate": b'{"duplicate":1,"duplicate":2,' + raw[1:],
                        "noncanonical": b" " + raw,
                        "array": b"[]",
                        "invalid-utf8": b"\xff",
                        "empty": b"",
                        "oversize": b"x"
                        * ((4096 if name == "native-tool-genesis" else 64 * 1024) + 1),
                    }.get(mutation, raw)
                    _write(fixture.directory / name, raw)
                    self.assertEqual(_main(module)[0:2], (126, ""))

    def test_custody_namespace_readonly_and_post_read_changes_are_refused(self):
        module = _module()
        for uid, gid, mode, links, accepted in (
            (0, 0, 0o400, 1, True),
            (0, 0, 0o440, 1, True),
            (0, _GID, 0o440, 1, False),
            (_UID, _GID, 0o400, 1, True),
            (_UID, _GID, 0o440, 1, False),
            (_WORKER_UID, _GID, 0o400, 1, False),
            (_UID, _GID, 0o400, 0, False),
            (_UID, _GID, 0o400, 2, False),
        ):
            with (
                self.subTest(uid=uid, gid=gid, mode=mode, links=links),
                _fixture(module) as fixture,
                _metadata(
                    fixture.directory / "native-tool-genesis",
                    st_uid=uid,
                    st_gid=gid,
                    st_mode=stat.S_IFREG | mode,
                    st_nlink=links,
                ),
            ):
                self.assertEqual(_main(module)[0], 0 if accepted else 126)
        for mutation in (
            "environment",
            "missing",
            "extra",
            "directory-mode",
            "file-mode",
            "file-link",
            "symlink",
            "directory-instead",
            "mount",
            "file-bind-writable",
            "after-read-bytes",
            "after-read-replace",
            "after-read-namespace",
        ):
            with self.subTest(mutation=mutation), _fixture(module) as fixture:
                path = fixture.directory / "native-tool-genesis"
                if mutation == "environment":
                    os.environ["CREDENTIALS_DIRECTORY"] += "/."
                elif mutation == "missing":
                    path.unlink()
                elif mutation == "extra":
                    _write(fixture.directory / "extra", b"x")
                elif mutation == "directory-mode":
                    fixture.directory.chmod(0o777)
                elif mutation == "file-mode":
                    path.chmod(0o600)
                elif mutation == "file-link":
                    os.link(path, fixture.directory.parent / "alias")
                elif mutation in {"symlink", "directory-instead"}:
                    path.unlink()
                    path.symlink_to(
                        "openclaw-config"
                    ) if mutation == "symlink" else path.mkdir(mode=0o500)
                elif mutation == "mount":
                    module.os.fstatvfs.return_value = types.SimpleNamespace(f_flag=0)
                elif mutation == "file-bind-writable":
                    inode = path.stat().st_ino
                    module.os.fstatvfs.side_effect = lambda fd, inode=inode: (
                        types.SimpleNamespace(
                            f_flag=0 if os.fstat(fd).st_ino == inode else os.ST_RDONLY
                        )
                    )
                real_genesis = module._genesis

                def changed(
                    value,
                    identities,
                    mutation=mutation,
                    path=path,
                    fixture=fixture,
                    real_genesis=real_genesis,
                ):
                    result = real_genesis(value, identities)
                    if mutation == "after-read-bytes":
                        _write(path, b"changed")
                    elif mutation == "after-read-replace":
                        raw = path.read_bytes()
                        path.unlink()
                        _write(path, raw)
                    elif mutation == "after-read-namespace":
                        _write(fixture.directory / "extra", b"x")
                    return result

                with mock.patch.object(module, "_genesis", side_effect=changed):
                    self.assertEqual(_main(module)[0:2], (126, ""))

    def test_all_held_fds_rechecked_closed_and_cleanup_output_failures_refuse(self):
        module = _module()
        for failure in (None, OSError("secret"), KeyboardInterrupt("secret")):
            with self.subTest(failure=type(failure).__name__), _fixture(module):
                opened = []
                real_open, real_close, real_genesis = os.open, os.close, module._genesis

                def tracked_open(*args, real_open=real_open, opened=opened, **kwargs):
                    fd = real_open(*args, **kwargs)
                    opened.append(fd)
                    return fd

                def verify(*args, opened=opened, real_genesis=real_genesis):
                    self.assertGreaterEqual(len(opened), 4)
                    for fd in opened:
                        os.fstat(fd)
                    return real_genesis(*args)

                def close(fd, real_close=real_close, failure=failure):
                    real_close(fd)
                    if failure is not None:
                        raise failure

                with (
                    mock.patch.object(module.os, "open", side_effect=tracked_open),
                    mock.patch.object(module.os, "close", side_effect=close),
                    mock.patch.object(module, "_genesis", side_effect=verify),
                ):
                    status, stdout, _stderr = _main(module)
                    self.assertEqual(status, 0 if failure is None else 126)
                    if failure is not None:
                        self.assertEqual(stdout, "")
                for fd in opened:
                    with self.assertRaises(OSError):
                        os.fstat(fd)
        with (
            _fixture(module),
            mock.patch.object(module.sys, "stdout") as stdout,
            redirect_stderr(io.StringIO()),
        ):
            stdout.write.return_value = 0
            self.assertEqual(module.main([]), 126)

    def test_pin_anchor_destination_and_partial_publication_refusals(self):
        inputs = {
            name: subject.overlay._read_pinned(name, *pin, root=_ROOT)
            for name, pin in subject._INPUTS.items()
        }
        for name in inputs:
            altered = dict(inputs)
            altered[name] += b"\n"
            with self.assertRaises(subject.NativeGatewayCredentialOverlayError):
                subject._render(altered)
        with self.assertRaises(subject.NativeGatewayCredentialOverlayError):
            subject._render_helper(
                inputs[subject._HELPER].replace(b"\ndef _binding(", b"\ndef _changed(")
            )
        for collection in ("_DEPENDENCIES", "_INPUTS", "_OUTPUTS"):
            changed = copy.deepcopy(getattr(subject, collection))
            first = next(iter(changed))
            changed[first] = (changed[first][0], "sha256:" + "0" * 64)
            with (
                mock.patch.object(subject, collection, changed),
                self.assertRaises(ValueError),
            ):
                subject._verified_inputs()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for value in ("string", Path("relative"), root):
                with (
                    mock.patch.object(subject, "_verified_inputs") as verify,
                    self.assertRaises(ValueError),
                ):
                    subject.materialize_runtime_native_gateway_credentials(value)
                verify.assert_not_called()
            output = root / "partial"

            def partial(path, rendered, _parts):
                path.mkdir()
                (path / next(iter(rendered))).write_bytes(b"partial")
                raise OSError("partial")

            with (
                mock.patch.object(
                    subject.overlay, "_write_overlay", side_effect=partial
                ),
                self.assertRaises(subject.NativeGatewayCredentialOverlayError),
            ):
                subject.materialize_runtime_native_gateway_credentials(output)
            self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main()
