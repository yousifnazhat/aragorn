from __future__ import annotations

import copy
import os
import stat
import tempfile
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aragorn import runtime_native_tool_provisioning as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_D = "sha256:" + "1" * 64


class Fixture:
    """Inert, caller-owned files: root/systemd/identity boundaries are mocked.

    The actual caller UID/GID owns every temporary file and plays both provisioner
    and worker for ownership operations; no process privilege changes take place.
    Unprivileged core acceptance below does not mock core identity/custody checks.
    """

    def __init__(self, root):
        self.root = root
        self.var = root / "var-lib"
        self.etc = root / "etc-aragorn"
        self.control = root / "control"
        for directory in (self.var, self.etc, self.control):
            directory.mkdir(mode=0o700)
        self.store = self.var / "aragorn-runtime-tool-receipts"
        self.source = self.etc / "runtime-native-tool-genesis.json"
        self.binding_path = self.etc / "runtime-action-worker.json"
        self.policy_path = self.control / "policy.json"
        self.socket = root / "worker.sock"
        self.policy = {
            "schema": "aragorn/runtime-action-policy/v1",
            "id": "native-receipts",
            "version": 1,
            "default": "BLOCK",
            "sensor_digest": _D,
            "revocation_source_digest": _D,
            "allow": [],
        }
        self.binding = {
            "schema": "aragorn/runtime-action-worker-binding/v1",
            "runtime_digest": _D,
            "active_skill_digest": _D,
            "policy_digest": canonical_digest(self.policy),
            "policy_version": 1,
        }
        self.write(self.binding_path, canonical_json(self.binding))
        self.write(self.policy_path, canonical_json(self.policy))
        self.identities = (
            os.geteuid(),
            os.geteuid(),
            os.getegid(),
            os.geteuid() + 1,
            os.getegid() + 1,
            os.geteuid() + 2,
            os.getegid() + 2,
        )
        self.events = []
        self.unlock_error = None
        self.closed_fds = []

    def write(self, path, raw, mode=0o400):
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(mode)

    @contextmanager
    def activation(self):
        self.events.append("activation-lock")
        try:
            yield
        finally:
            self.events.append("activation-release")

    @contextmanager
    def broker(self, _config):
        self.events.append("broker-lock")
        fd = os.open(self.control, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)
            self.events.append("broker-release")
            if self.unlock_error is not None:
                raise self.unlock_error

    @contextmanager
    def patched(self):
        original_close = subject._close

        def close_all(held):
            self.closed_fds.extend(entry.fd for entry in held)
            return original_close(held)

        def stopped(unit):
            self.events.append("stopped:" + unit)
            return {
                "ActiveState": "inactive",
                "SubState": "dead",
                "MainPID": "0",
                "ControlPID": "0",
                "ControlGroup": "",
            }

        with ExitStack() as stack:
            for name, value in {
                "_ROOT_UID": os.geteuid(),
                "_ROOT_GID": os.getegid(),
                "_STORE": self.store,
                "_GENESIS_SOURCE": self.source,
                "_WORKER_BINDING": self.binding_path,
                "_WORKER_SOCKET": self.socket,
                "_require_root": mock.Mock(),
                "_close": close_all,
            }.items():
                stack.enter_context(mock.patch.object(subject, name, value))
            for name, value in {
                "_activation_guard": self.activation,
                "_broker_guard": self.broker,
                "_identities": mock.Mock(return_value=self.identities),
                "_broker_config": mock.Mock(
                    return_value=SimpleNamespace(policy_path=self.policy_path)
                ),
                "_unit_state": stopped,
                "_service_cgroup": lambda unit: "/system.slice/" + unit,
                "_cgroup_empty": mock.Mock(return_value={"status": "ABSENT"}),
                "_command": mock.Mock(
                    side_effect=AssertionError("no systemd command is allowed in tests")
                ),
            }.items():
                stack.enter_context(mock.patch.object(subject.response, name, value))
            yield

    def run(self):
        with self.patched():
            return subject.provision_runtime_native_tool_receipts()

    def snapshot(self):
        result = {}
        for root in (self.var, self.etc, self.control):
            for path in (root, *root.rglob("*")):
                info = path.lstat()
                raw = (
                    os.readlink(path)
                    if path.is_symlink()
                    else path.read_bytes()
                    if path.is_file()
                    else None
                )
                result[str(path)] = (
                    stat.S_IFMT(info.st_mode),
                    stat.S_IMODE(info.st_mode),
                    info.st_uid,
                    info.st_gid,
                    info.st_ino,
                    info.st_nlink,
                    raw,
                )
        return result


@unittest.skipIf(
    os.geteuid() == 0 or os.getegid() == 0,
    "inert fixture and actual receipt-core acceptance require a non-root UID/GID",
)
class NativeToolProvisioningTests(unittest.TestCase):
    def test_complete_inert_provisioning_and_unprivileged_core_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary).resolve())
            handoffs = []
            original_chown = os.fchown

            def chown(fd, uid, gid):
                handoffs.append((os.fstat(fd).st_ino, uid, gid))
                original_chown(fd, uid, gid)

            original_create = subject._create_document

            def create(parent, name, raw, held):
                if name == fixture.source.name:
                    self.assertEqual(len(handoffs), 7)
                    self.assertEqual(handoffs[-1][0], fixture.store.stat().st_ino)
                    self.assertIn("broker-lock", fixture.events)
                    self.assertNotIn("broker-release", fixture.events)
                    self.assertFalse(fixture.source.exists())
                return original_create(parent, name, raw, held)

            with (
                fixture.patched(),
                mock.patch.object(subject, "_create_document", side_effect=create),
                mock.patch.object(subject.os, "fchown", side_effect=chown),
            ):
                report = subject.provision_runtime_native_tool_receipts()
            source = fixture.source.read_bytes()
            self.assertEqual(source, (fixture.store / "genesis.json").read_bytes())
            self.assertEqual(
                report["genesis_digest"],
                subject.broker._parse_canonical_document(
                    (fixture.store / "state.json").read_bytes(), "test state"
                )["genesis_digest"],
            )
            self.assertEqual(report["worker_uid"], os.geteuid())
            self.assertEqual(report["worker_gid"], os.getegid())
            self.assertEqual(
                report["runtime_digest"], fixture.binding["runtime_digest"]
            )
            self.assertEqual(report["policy_digest"], canonical_digest(fixture.policy))
            self.assertTrue(
                all(
                    report[name] is False
                    for name in (
                        "activation_performed",
                        "native_capture",
                        "run_qualified",
                    )
                )
            )
            self.assertEqual(
                fixture.events[-2:], ["broker-release", "activation-release"]
            )
            for fd in fixture.closed_fds:
                with self.assertRaises(OSError):
                    os.fstat(fd)
            core = subject.receipts.NativeToolReceiptStore(
                fixture.store, report["genesis_digest"]
            )
            self.assertFalse(core._halted)
            self.assertEqual(
                core.genesis_digest,
                canonical_digest(
                    subject.broker._parse_canonical_document(source, "test genesis")
                ),
            )
            self.assertEqual(
                {
                    str(path.relative_to(fixture.store))
                    for path in fixture.store.rglob("*")
                },
                {
                    "cas",
                    "cas/blobs",
                    "cas/blobs/sha256",
                    "genesis.json",
                    "state.json",
                    "receipt.lock",
                },
            )

    def test_any_existing_store_or_source_is_untouched_even_if_empty_or_identical(self):
        for existing in (
            "empty-store",
            "partial-store",
            "source",
            "source-symlink",
            "store-symlink",
            "complete",
        ):
            with (
                self.subTest(existing=existing),
                tempfile.TemporaryDirectory() as temporary,
            ):
                fixture = Fixture(Path(temporary).resolve())
                if existing in {"empty-store", "partial-store"}:
                    fixture.store.mkdir(mode=0o700)
                    if existing == "partial-store":
                        fixture.write(fixture.store / "state.json", b"unresolved")
                elif existing == "source":
                    fixture.write(fixture.source, b"existing root authority")
                elif existing == "source-symlink":
                    fixture.source.symlink_to(fixture.root / "absent")
                elif existing == "store-symlink":
                    fixture.store.symlink_to(
                        fixture.root / "absent", target_is_directory=True
                    )
                else:
                    fixture.run()
                before = fixture.snapshot()
                with self.assertRaises(subject.NativeToolProvisioningError):
                    fixture.run()
                self.assertEqual(fixture.snapshot(), before)

    def test_bad_binding_policy_identity_custody_or_active_service_has_no_publication(
        self,
    ):
        for mutation in (
            "binding-boolean",
            "binding-noncanonical",
            "binding-mode",
            "policy-digest",
            "policy-version",
            "policy-boolean",
            "worker-boolean",
            "parent-mode",
            "active",
            "populated",
            "socket",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                fixture = Fixture(Path(temporary).resolve())
                with fixture.patched(), ExitStack() as stack:
                    if mutation == "binding-boolean":
                        fixture.binding["policy_version"] = True
                        fixture.write(
                            fixture.binding_path, canonical_json(fixture.binding)
                        )
                    elif mutation == "binding-noncanonical":
                        fixture.write(
                            fixture.binding_path,
                            canonical_json(fixture.binding) + b"\n",
                        )
                    elif mutation == "binding-mode":
                        fixture.binding_path.chmod(0o600)
                    elif mutation.startswith("policy-"):
                        fixture.policy["version"] = (
                            True if mutation == "policy-boolean" else 2
                        )
                        fixture.write(
                            fixture.policy_path, canonical_json(fixture.policy)
                        )
                        if mutation != "policy-digest":
                            fixture.binding["policy_digest"] = canonical_digest(
                                fixture.policy
                            )
                            fixture.write(
                                fixture.binding_path, canonical_json(fixture.binding)
                            )
                    elif mutation == "worker-boolean":
                        changed = list(fixture.identities)
                        changed[1] = True
                        stack.enter_context(
                            mock.patch.object(
                                subject.response,
                                "_identities",
                                return_value=tuple(changed),
                            )
                        )
                    elif mutation == "parent-mode":
                        fixture.var.chmod(0o777)
                    elif mutation == "active":
                        stack.enter_context(
                            mock.patch.object(
                                subject.response,
                                "_unit_state",
                                return_value={"ActiveState": "active"},
                            )
                        )
                    elif mutation == "populated":
                        stack.enter_context(
                            mock.patch.object(
                                subject.response,
                                "_cgroup_empty",
                                side_effect=subject.response.RuntimeResponseError(
                                    "populated"
                                ),
                            )
                        )
                    else:
                        fixture.socket.write_bytes(b"not a socket")
                    with self.assertRaises(subject.NativeToolProvisioningError):
                        subject.provision_runtime_native_tool_receipts()
                self.assertFalse(fixture.store.exists())
                self.assertFalse(fixture.source.exists())
                fixture.var.chmod(0o700)
        with (
            mock.patch.object(subject.sys, "platform", "not-linux"),
            mock.patch.object(subject.response, "_activation_guard") as guard,
            self.assertRaises(subject.NativeToolProvisioningError),
        ):
            subject.provision_runtime_native_tool_receipts()
        guard.assert_not_called()

    def test_partial_store_handoff_and_source_publication_failures_never_reset(self):
        for point in (
            "cas-mkdir",
            "state-published",
            "handoff",
            "source-published",
            "unlock",
            "late-close",
        ):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary).resolve())
                original_mkdir = subject._mkdir
                original_create = subject._create_document
                original_chown = os.fchown
                original_close = os.close
                close_target = []

                def mkdir(
                    parent, name, held, point=point, original_mkdir=original_mkdir
                ):
                    if point == "cas-mkdir" and name == "cas":
                        raise OSError("inert injected mkdir failure")
                    return original_mkdir(parent, name, held)

                def create(
                    parent,
                    name,
                    raw,
                    held,
                    point=point,
                    original_create=original_create,
                    fixture=fixture,
                    close_target=close_target,
                ):
                    entry = original_create(parent, name, raw, held)
                    if name == fixture.source.name:
                        close_target.append(entry.fd)
                    if (point == "state-published" and name == "state.json") or (
                        point == "source-published" and name == fixture.source.name
                    ):
                        raise OSError("inert injected publication failure")
                    return entry

                def chown(fd, uid, gid, point=point, original_chown=original_chown):
                    original_chown(fd, uid, gid)
                    if point == "handoff":
                        raise OSError("inert injected ownership failure")

                def close(
                    fd,
                    point=point,
                    original_close=original_close,
                    close_target=close_target,
                ):
                    original_close(fd)
                    if point == "late-close" and close_target == [fd]:
                        raise OSError("inert injected close failure")

                if point == "unlock":
                    fixture.unlock_error = OSError("inert injected unlock failure")
                with (
                    fixture.patched(),
                    mock.patch.object(subject, "_mkdir", side_effect=mkdir),
                    mock.patch.object(subject, "_create_document", side_effect=create),
                    mock.patch.object(subject.os, "fchown", side_effect=chown),
                    mock.patch.object(subject.os, "close", side_effect=close),
                    self.assertRaises(subject.NativeToolProvisioningError),
                ):
                    subject.provision_runtime_native_tool_receipts()
                self.assertTrue(fixture.store.is_dir())
                self.assertEqual(
                    fixture.source.exists(),
                    point in {"source-published", "unlock", "late-close"},
                )
                before = fixture.snapshot()
                fixture.unlock_error = None
                with self.assertRaises(subject.NativeToolProvisioningError):
                    fixture.run()
                self.assertEqual(fixture.snapshot(), before)

    def test_no_replace_source_race_preserves_preexisting_matching_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary).resolve())
            original = subject._create_document
            race = []

            def create(parent, name, raw, held):
                if name == fixture.source.name:
                    fixture.write(fixture.source, raw)
                    race.append((fixture.source.lstat(), raw))
                return original(parent, name, raw, held)

            with (
                fixture.patched(),
                mock.patch.object(subject, "_create_document", side_effect=create),
                self.assertRaises(subject.NativeToolProvisioningError),
            ):
                subject.provision_runtime_native_tool_receipts()
            self.assertEqual(fixture.source.read_bytes(), race[0][1])
            self.assertEqual(
                subject.broker._file_identity(fixture.source.lstat()),
                subject.broker._file_identity(race[0][0]),
            )
            self.assertEqual(
                {path.name for path in fixture.etc.iterdir()},
                {fixture.binding_path.name, fixture.source.name},
            )

    def test_late_binding_and_namespace_drift_never_returns_success(self):
        for point in ("binding", "extra-store-entry", "source-fsync"):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary).resolve())
                original = subject._create_document
                original_fsync = os.fsync

                def changed(
                    parent,
                    name,
                    raw,
                    held,
                    point=point,
                    original=original,
                    fixture=fixture,
                ):
                    entry = original(parent, name, raw, held)
                    if name == "state.json":
                        if point == "binding":
                            document = copy.deepcopy(fixture.binding)
                            document["runtime_digest"] = "sha256:" + "2" * 64
                            fixture.write(
                                fixture.binding_path, canonical_json(document)
                            )
                        elif point == "extra-store-entry":
                            (fixture.store / "unexpected").mkdir()
                    return entry

                def fsync(
                    fd, point=point, original_fsync=original_fsync, fixture=fixture
                ):
                    original_fsync(fd)
                    if point == "source-fsync" and fixture.source.exists():
                        actual = os.fstat(fd)
                        source = fixture.source.lstat()
                        if (actual.st_dev, actual.st_ino) == (
                            source.st_dev,
                            source.st_ino,
                        ):
                            raise OSError("inert injected final fsync failure")

                with (
                    fixture.patched(),
                    mock.patch.object(subject, "_create_document", side_effect=changed),
                    mock.patch.object(subject.os, "fsync", side_effect=fsync),
                    self.assertRaises(subject.NativeToolProvisioningError),
                ):
                    subject.provision_runtime_native_tool_receipts()
                self.assertTrue(fixture.store.exists())
                self.assertEqual(fixture.source.exists(), point == "source-fsync")


if __name__ == "__main__":
    unittest.main()
