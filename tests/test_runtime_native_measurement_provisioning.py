"""Temporary-file provisioning fixtures; no privileged or live service operation."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from io import BytesIO
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aragorn import phase3_quantitative_metrics as metrics
from aragorn import runtime_native_measurement_provisioning as subject
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_runtime_broker_measurement_plan as prepared_fixture


class Fixture:
    """Real private files with caller UID standing in for root and broker.

    Account lookup, root guard, systemd query and cooperative lock boundaries are
    replaced; the prepared-input consumer, fixed-path joins, filesystem custody,
    exclusive publication, modes, raw readbacks and CAS bytes remain real.
    """

    def __init__(self, test):
        old = prepared_fixture.BrokerMeasurementPlanTests()
        old.setUp()
        test.addCleanup(old.doCleanups)
        self.root = old.root
        # macOS descendants inherit the parent directory's group. Normalize
        # only our caller-owned fixture root before creating custody inputs;
        # never change or assume ownership of system temporary ancestors.
        os.chown(self.root, os.geteuid(), os.getegid())
        self.etc, self.var, self.modules = (
            self.root / name for name in ("etc", "var-lib", "modules")
        )
        self.runtime = self.var / "aragorn-runtime-action"
        self.control, self.protected = (
            self.runtime / "control",
            self.runtime / "protected",
        )
        self.cgroup = self.root / "cgroup"
        for directory in (self.etc, self.var, self.modules, self.cgroup):
            directory.mkdir(mode=0o700)
        self.runtime.mkdir(mode=0o755)
        self.runtime.chmod(0o755)
        for directory in (self.control, self.protected):
            directory.mkdir(mode=0o710)
            directory.chmod(0o710)
        self.store = self.control / "decision-measurement-inputs"
        self.credential = self.etc / "runtime-broker-decision-measurement.json"
        self.boot = self.root / "boot-id"
        self.worker = self.etc / "runtime-action-worker.json"
        self.runtime_binding = self.etc / "runtime-action-runtime.json"
        self.grant_path = self.etc / "runtime-capability-grant.json"
        self.source_pins = {}
        for name in subject._SOURCE_NAMES:
            raw = (
                Path(metrics.__file__).read_bytes()
                if name == "phase3_quantitative_metrics.py"
                else ("# Inert fixture source " + name + "\n").encode()
            )
            self.write(self.modules / name, raw, 0o644)
            self.source_pins[name] = subject._digest(raw)
        self.policy = {
            "schema": "aragorn/runtime-action-policy/v1",
            "id": "inert-provisioning",
            "version": 1,
            "default": "BLOCK",
            "sensor_digest": prepared_fixture.PIN,
            "revocation_source_digest": prepared_fixture.PIN,
            "allow": [],
        }
        self.binding = {
            "schema": "aragorn/runtime-action-worker-binding/v1",
            "runtime_digest": prepared_fixture.PIN,
            "active_skill_digest": prepared_fixture.PIN,
            "policy_digest": canonical_digest(self.policy),
            "policy_version": 1,
        }
        source = CAS(old.arguments["source_cas"].root)
        self.grant = subject.broker._parse_canonical_document(
            source.read(old.arguments["expected_grant_digest"]), "inert grant"
        )
        self.grant["policy_digest"] = canonical_digest(self.policy)
        self.path = {
            "schema": "aragorn/runtime-protected-path/v1",
            "root_device": self.protected.stat().st_dev,
            "root_inode": self.protected.stat().st_ino,
            "target_name": "inert.txt",
        }
        old.arguments.update(
            expected_grant_digest=source.put(
                BytesIO(canonical_json(self.grant)), max_bytes=4096
            ),
            expected_path_digest=source.put(
                BytesIO(canonical_json(self.path)), max_bytes=4096
            ),
            expected_broker_source_pins=self.source_pins,
        )
        self.prepared = (
            prepared_fixture.subject.prepare_broker_decision_measurement_binding(
                **old.arguments
            )
        )
        self.source_cas = CAS(old.arguments["target_cas"].root, read_only=True)
        self.arguments = {
            "prepared_raw": canonical_json(self.prepared),
            "expected_prepared_digest": canonical_digest(self.prepared),
            "expected_binding_digest": self.prepared["binding_digest"],
            "expected_broker_source_pins": self.source_pins,
            "source_cas": self.source_cas,
        }
        self.write(self.worker, canonical_json(self.binding))
        self.write(
            self.runtime_binding,
            canonical_json(
                {
                    "schema": "aragorn/runtime-action-runtime-binding/v2",
                    "runtime_digest": prepared_fixture.PIN,
                    "runtime_profile_digest": prepared_fixture.PIN,
                }
            ),
        )
        self.write(self.grant_path, canonical_json(self.grant))
        self.write(self.control / "policy.json", canonical_json(self.policy))
        self.write(self.boot, (old.arguments["expected_boot_id"] + "\n").encode())
        uid, gid = os.geteuid(), os.getegid()
        self.identities = (uid, uid + 1, gid, uid + 2, gid + 1, uid + 3, gid + 2)
        self.events, self.commands, self.closed = [], [], []
        self.ancestry_paths, self.file_reads = [], []
        self.unit_mutation = None
        self.release_error = None

    @staticmethod
    def write(path, raw, mode=0o400):
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(raw)
        os.chown(path, os.geteuid(), os.getegid())
        path.chmod(mode)

    def ancestry(self, path, expected_uid):
        """Apply the real ancestry predicate through our real private root.

        Only the operating system's temporary ancestors outside this fixture
        are excluded. Every actual in-fixture ancestor, including the root,
        retains the production lstat/type/owner/writable-mode checks.
        """
        current = Path(path)
        if not current.is_relative_to(self.root):
            raise AssertionError("ancestry check escaped the private fixture")
        while True:
            self.ancestry_paths.append(current)
            metadata = os.lstat(current)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid not in {0, expected_uid}
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise subject.broker._ProtectedFileError(
                    "runtime broker protected ancestry is unsafe"
                )
            if current == self.root:
                return
            current = current.parent

    @contextmanager
    def activation(self):
        self.events.append("activation-lock")
        try:
            yield
        finally:
            self.events.append("activation-release")

    @contextmanager
    def broker(self, config):
        self.events.append("broker-lock")
        fd = os.open(config.control_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            yield fd
        finally:
            os.close(fd)
            self.events.append("broker-release")
            if self.release_error:
                raise self.release_error

    def command(self, argv, *, timeout):
        self.commands.append((argv, timeout))
        if (
            argv[:5]
            != [
                "/usr/bin/systemctl",
                "--system",
                "--no-pager",
                "--no-ask-password",
                "show",
            ]
            or timeout != 3
        ):
            raise AssertionError("only the bounded read-only unit query is allowed")
        unit = argv[-1]
        user, group = subject._UNITS[unit]
        state = {
            "Id": unit,
            "LoadState": "loaded",
            "User": user,
            "Group": group,
            "ActiveState": "inactive",
            "SubState": "dead",
            "MainPID": "0",
            "ControlPID": "0",
            "ControlGroup": "",
            "KillMode": "control-group",
            "Delegate": "no",
            "Restart": "no",
        }
        if self.unit_mutation:
            self.unit_mutation(unit, state)
        return "".join(f"{key}={value}\n" for key, value in state.items()).encode()

    @contextmanager
    def patched(self):
        close = subject.custody._close
        hold_file = subject.custody._hold_file

        def close_all(entries):
            self.closed.extend(entry.fd for entry in entries)
            close(entries)

        def observed_file(parent, name, *args):
            self.file_reads.append((name, "before"))
            result = hold_file(parent, name, *args)
            self.file_reads.append((name, "complete"))
            return result

        with ExitStack() as stack:
            for name, value in {
                "_ROOT_UID": os.geteuid(),
                "_ROOT_GID": os.getegid(),
                "_require_root": lambda: None,
                "_RUNTIME_ROOT": self.runtime,
                "_CONTROL": self.control,
                "_PROTECTED": self.protected,
                "_STORE": self.store,
                "_CREDENTIAL": self.credential,
                "_EVIDENCE": self.control / "decision-measurement-evidence",
                "_PENDING": self.control / "decision-measurement-pending.json",
                "_COMPLETE": self.control / "decision-measurement-complete.json",
                "_WORKER": self.worker,
                "_RUNTIME": self.runtime_binding,
                "_GRANT": self.grant_path,
                "_SOURCES": self.modules,
                "_BOOT": self.boot,
                "_CGROUP": self.cgroup,
            }.items():
                stack.enter_context(patch.object(subject, name, value))
            for name, value in {
                "_ROOT_UID": os.geteuid(),
                "_ROOT_GID": os.getegid(),
                "_close": close_all,
                "_hold_file": observed_file,
            }.items():
                stack.enter_context(patch.object(subject.custody, name, value))
            stack.enter_context(
                patch.object(
                    subject.broker, "_require_protected_ancestry", self.ancestry
                )
            )
            for name, value in {
                "_identities": lambda: self.identities,
                "_activation_guard": self.activation,
                "_broker_guard": self.broker,
                "_broker_config": lambda *args: SimpleNamespace(
                    control_root=self.control
                ),
                "_command": self.command,
                "_process_cgroup": lambda pid: "/init.scope",
            }.items():
                stack.enter_context(patch.object(subject.response, name, value))
            stack.enter_context(patch.object(subject.time, "time", return_value=1))
            yield

    def run(self):
        with self.patched():
            return subject.provision_runtime_native_measurement(**self.arguments)

    def snapshot(self):
        result = {}
        for path in (
            self.etc,
            self.runtime,
            *self.etc.rglob("*"),
            *self.runtime.rglob("*"),
        ):
            info = path.lstat()
            raw = (
                os.readlink(path)
                if path.is_symlink()
                else path.read_bytes()
                if path.is_file()
                else None
            )
            result[str(path)] = (
                info.st_ino,
                info.st_uid,
                info.st_gid,
                stat.S_IMODE(info.st_mode),
                info.st_nlink,
                raw,
            )
        return result


class NativeMeasurementProvisioningTests(unittest.TestCase):
    def assert_boundary(self, error, expected):
        """A negative test must fail in its intended boundary, not setup."""
        self.assertIsNotNone(error.__cause__)
        names = []
        cause = error.__cause__
        while cause is not None:
            traceback = cause.__traceback__
            while traceback is not None:
                names.append(traceback.tb_frame.f_code.co_name)
                traceback = traceback.tb_next
            cause = cause.__cause__
        self.assertIn(expected, names)
        if expected != "ancestry":
            self.assertNotIn("ancestry", names)

    def test_exact_inputs_handoff_then_root_credential_with_real_read_only_cas(self):
        fixture = Fixture(self)
        handoffs = []
        original_chown, original_create = os.fchown, subject.custody._create_document

        def chown(fd, uid, gid):
            handoffs.append((os.fstat(fd).st_ino, uid, gid))
            original_chown(fd, uid, gid)

        def create(parent, name, raw, held):
            self.assertEqual(name, fixture.credential.name)
            self.assertEqual(handoffs[-1][0], fixture.store.stat().st_ino)
            self.assertNotIn("broker-release", fixture.events)
            self.assertFalse(fixture.credential.exists())
            return original_create(parent, name, raw, held)

        with (
            fixture.patched(),
            patch.object(subject.os, "fchown", side_effect=chown),
            patch.object(subject.custody, "_create_document", side_effect=create),
        ):
            unused = subject.require_native_measurement_unused()
            self.assertIs(unused["reset_authorized"], False)
            report = subject.provision_runtime_native_measurement(**fixture.arguments)
        self.assertEqual(
            fixture.credential.read_bytes(), canonical_json(fixture.prepared["binding"])
        )
        self.assertEqual(stat.S_IMODE(fixture.credential.stat().st_mode), 0o400)
        self.assertEqual(report["binding_digest"], fixture.prepared["binding_digest"])
        self.assertEqual(
            report["payload_digest_expectation"],
            fixture.prepared["binding"]["payload_digest"],
        )
        for key in (
            "activation_performed",
            "measurement_collected",
            "run_qualified",
            "quantitative_metrics_eligible",
            "phase3_exit_eligible",
            "payload_bytes_verified",
        ):
            self.assertIs(report[key], False)
        store = CAS(fixture.store, read_only=True)
        for row in fixture.prepared["input_blobs"]:
            self.assertEqual(
                store.read(row["digest"]), fixture.source_cas.read(row["digest"])
            )
        self.assertEqual(report["input_blobs"], fixture.prepared["input_blobs"])
        self.assertEqual(
            len(handoffs),
            3
            + len({row["digest"][7:9] for row in report["input_blobs"]})
            + len(report["input_blobs"]),
        )
        self.assertEqual(fixture.events[-2:], ["broker-release", "activation-release"])
        self.assertEqual(
            {argv[-1] for argv, _ in fixture.commands}, set(subject._UNITS)
        )
        self.assertIn(fixture.root, fixture.ancestry_paths)
        self.assertTrue(
            all(path.is_relative_to(fixture.root) for path in fixture.ancestry_paths)
        )
        for fd in fixture.closed:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_every_prior_destination_and_result_refuses_without_modification(self):
        for name in (
            "decision-measurement-inputs",
            "decision-measurement-evidence",
            "decision-measurement-pending.json",
            "decision-measurement-complete.json",
            "capability-grant-state.json",
            "profile-pending.json",
            "profile-receipt.json",
            "capability-grant-profile-receipt-old.json",
            "credential",
            "symlink",
        ):
            with self.subTest(name=name):
                fixture = Fixture(self)
                path = (
                    fixture.credential
                    if name in {"credential", "symlink"}
                    else fixture.control / name
                )
                if name == "symlink":
                    path.symlink_to(fixture.root / "absent")
                elif name.endswith("inputs") or name.endswith("evidence"):
                    path.mkdir(mode=0o700)
                else:
                    fixture.write(path, b"preserved prior state")
                before = fixture.snapshot()
                boundary = (
                    "_unused_control"
                    if name == "capability-grant-profile-receipt-old.json"
                    else "_absent"
                )
                with fixture.patched():
                    with self.assertRaises(
                        subject.NativeMeasurementProvisioningError
                    ) as refused:
                        subject.require_native_measurement_unused()
                    self.assert_boundary(refused.exception, boundary)
                    with self.assertRaises(
                        subject.NativeMeasurementProvisioningError
                    ) as refused:
                        subject.provision_runtime_native_measurement(
                            **fixture.arguments
                        )
                    self.assert_boundary(refused.exception, boundary)
                self.assertEqual(fixture.snapshot(), before)

    def test_all_four_unit_and_kernel_cgroup_guards_are_required(self):
        for selected in subject._UNITS:
            with self.subTest(unit=selected):
                fixture = Fixture(self)
                fixture.unit_mutation = lambda unit, state: (
                    state.update(ActiveState="active", MainPID="100")
                    if unit == selected
                    else None
                )
                with (
                    fixture.patched(),
                    self.assertRaises(
                        subject.NativeMeasurementProvisioningError
                    ) as refused,
                ):
                    subject.require_native_measurement_unused()
                self.assert_boundary(refused.exception, "_stopped")
                self.assertEqual(fixture.commands[-1][0][-1], selected)
                self.assertFalse(fixture.store.exists())
        fixture = Fixture(self)
        selected = next(iter(subject._UNITS))
        cgroup = fixture.cgroup / "system.slice" / selected
        cgroup.mkdir(parents=True)
        fixture.write(cgroup / "cgroup.events", b"populated 1\nfrozen 0\n", 0o644)
        with (
            fixture.patched(),
            self.assertRaises(subject.NativeMeasurementProvisioningError) as refused,
        ):
            subject.provision_runtime_native_measurement(**fixture.arguments)
        self.assert_boundary(refused.exception, "_empty_cgroup")
        self.assertFalse(fixture.store.exists())

    def test_actual_boot_sources_grant_policy_runtime_and_protected_inode_join(self):
        for mode in (
            "boot",
            "source",
            "source-missing",
            "grant",
            "stale",
            "worker",
            "runtime",
            "policy",
            "protected-inode",
            "target-present",
            "source-mode",
            "credential-hardlink",
        ):
            with self.subTest(mode=mode):
                fixture = Fixture(self)
                with fixture.patched(), ExitStack() as stack:
                    if mode == "boot":
                        fixture.write(
                            fixture.boot, b"00000000-0000-0000-0000-000000000002\n"
                        )
                    elif mode == "source":
                        fixture.write(
                            fixture.modules / "runtime_action_broker_v4.py",
                            b"changed\n",
                            0o644,
                        )
                    elif mode == "source-missing":
                        (fixture.modules / "runtime_action_broker_v4.py").unlink()
                    elif mode == "grant":
                        changed = {**fixture.grant, "grant_id": "f" * 64}
                        fixture.write(fixture.grant_path, canonical_json(changed))
                    elif mode == "stale":
                        stack.enter_context(
                            patch.object(subject.time, "time", return_value=2)
                        )
                    elif mode == "worker":
                        fixture.write(
                            fixture.worker,
                            canonical_json(
                                {
                                    **fixture.binding,
                                    "active_skill_digest": "sha256:" + "f" * 64,
                                }
                            ),
                        )
                    elif mode == "runtime":
                        raw = subject.broker._parse_canonical_document(
                            fixture.runtime_binding.read_bytes(), "fixture"
                        )
                        fixture.write(
                            fixture.runtime_binding,
                            canonical_json(
                                {**raw, "runtime_profile_digest": "sha256:" + "f" * 64}
                            ),
                        )
                    elif mode == "policy":
                        fixture.write(
                            fixture.control / "policy.json",
                            canonical_json({**fixture.policy, "id": "changed"}),
                        )
                    elif mode == "protected-inode":
                        fixture.protected.rename(fixture.runtime / "retained-protected")
                        fixture.protected.mkdir(mode=0o710)
                        fixture.protected.chmod(0o710)
                    elif mode == "target-present":
                        fixture.write(
                            fixture.protected / "inert.txt", b"existing target"
                        )
                    elif mode == "source-mode":
                        (fixture.modules / "runtime_action_broker_v4.py").chmod(0o666)
                    else:
                        os.link(fixture.grant_path, fixture.root / "grant-extra-link")
                    before = fixture.snapshot()
                    with self.assertRaises(
                        subject.NativeMeasurementProvisioningError
                    ) as refused:
                        subject.provision_runtime_native_measurement(
                            **fixture.arguments
                        )
                    boundary = (
                        "_protected_inputs"
                        if mode in {"policy", "protected-inode", "target-present"}
                        else "_actual_inputs"
                    )
                    self.assert_boundary(refused.exception, boundary)
                    expected_read = (
                        (sorted(subject._SOURCE_NAMES)[-1], "complete")
                        if mode == "boot"
                        else (
                            "runtime_action_broker_v4.py",
                            "complete" if mode == "source" else "before",
                        )
                        if mode in {"source", "source-mode", "source-missing"}
                        else ("policy.json", "complete")
                        if mode in {"policy", "protected-inode", "target-present"}
                        else (
                            fixture.grant_path.name,
                            "before" if mode == "credential-hardlink" else "complete",
                        )
                    )
                    self.assertEqual(fixture.file_reads[-1], expected_read)
                    self.assertEqual(fixture.snapshot(), before)
                self.assertFalse(fixture.store.exists())
                self.assertFalse(fixture.credential.exists())

    def test_copy_handoff_and_publication_failures_retain_partial_state_no_reuse(self):
        for mode in ("write", "handoff", "credential", "unlock"):
            with self.subTest(mode=mode):
                fixture = Fixture(self)
                original_write, original_chown = subject.broker.write_all, os.fchown
                original_create = subject.custody._create_document
                injected = []

                def write(fd, raw):
                    if mode == "write":
                        os.write(fd, raw[:1])
                        injected.append("write")
                        raise OSError("inert partial copy")
                    original_write(fd, raw)

                def chown(fd, uid, gid):
                    original_chown(fd, uid, gid)
                    if mode == "handoff":
                        injected.append("handoff")
                        raise OSError("inert handoff fault")

                def create(parent, name, raw, held):
                    result = original_create(parent, name, raw, held)
                    if mode == "credential":
                        injected.append("credential")
                        raise OSError("inert post-publication fault")
                    return result

                if mode == "unlock":
                    fixture.release_error = OSError("inert lock cleanup fault")
                with (
                    fixture.patched(),
                    patch.object(subject.broker, "write_all", side_effect=write),
                    patch.object(subject.os, "fchown", side_effect=chown),
                    patch.object(
                        subject.custody, "_create_document", side_effect=create
                    ),
                ):
                    with self.assertRaises(
                        subject.NativeMeasurementProvisioningError
                    ) as refused:
                        subject.provision_runtime_native_measurement(
                            **fixture.arguments
                        )
                if mode == "unlock":
                    self.assertIs(refused.exception.__cause__, fixture.release_error)
                    self.assertEqual(
                        fixture.events[-2:], ["broker-release", "activation-release"]
                    )
                else:
                    self.assertEqual(injected, [mode])
                    self.assert_boundary(
                        refused.exception,
                        {"write": "write", "handoff": "chown", "credential": "create"}[
                            mode
                        ],
                    )
                self.assertTrue(fixture.store.exists())
                self.assertEqual(
                    fixture.credential.exists(), mode in {"credential", "unlock"}
                )
                before = fixture.snapshot()
                with (
                    fixture.patched(),
                    self.assertRaises(subject.NativeMeasurementProvisioningError),
                ):
                    subject.provision_runtime_native_measurement(**fixture.arguments)
                self.assertEqual(fixture.snapshot(), before)

    def test_changed_cas_or_actual_file_at_final_readback_prevents_credential(self):
        for mode in ("cas", "source", "target", "boot", "expired"):
            with self.subTest(mode=mode):
                fixture = Fixture(self)
                audit = subject._audit
                mutated = False

                def after_copy(*args):
                    nonlocal mutated
                    result = audit(*args)
                    if not mutated:
                        mutated = True
                        if mode == "cas":
                            fixture.source_cas.read = lambda *args, **kwargs: (
                                _ for _ in ()
                            ).throw(CASError("inert source lost"))
                        elif mode == "source":
                            fixture.write(
                                fixture.modules / "runtime_action_broker_v4.py",
                                b"changed source",
                                0o644,
                            )
                        elif mode == "target":
                            fixture.write(
                                fixture.protected / "inert.txt", b"raced target"
                            )
                        elif mode == "boot":
                            fixture.write(
                                fixture.boot, b"00000000-0000-0000-0000-000000000002\n"
                            )
                        else:
                            subject.time.time.return_value = 2
                    return result

                with (
                    fixture.patched(),
                    patch.object(subject, "_audit", side_effect=after_copy),
                ):
                    with self.assertRaises(
                        subject.NativeMeasurementProvisioningError
                    ) as refused:
                        subject.provision_runtime_native_measurement(
                            **fixture.arguments
                        )
                self.assertTrue(mutated, "the completed-copy audit was not reached")
                self.assert_boundary(
                    refused.exception,
                    {
                        "cas": "<genexpr>",
                        "source": "_readback",
                        "target": "_absent",
                        "boot": "provision_runtime_native_measurement",
                        "expired": "parse_runtime_capability_grant",
                    }[mode],
                )
                self.assertTrue(fixture.store.exists())
                self.assertFalse(fixture.credential.exists())

    def test_guard_handles_absent_parents_without_creating_or_repairing_them(self):
        fixture = Fixture(self)
        # The test seam must not hide a real unsafe ancestor inside the owned
        # fixture, including its actual root. Production code stays unchanged.
        for directory, boundary in (
            (fixture.root, "ancestry"),
            (fixture.var, "require_owned_directory"),
        ):
            previous = stat.S_IMODE(directory.stat().st_mode)
            directory.chmod(0o777)
            try:
                with (
                    fixture.patched(),
                    self.assertRaises(
                        subject.NativeMeasurementProvisioningError
                    ) as refused,
                ):
                    subject.require_native_measurement_unused()
                self.assert_boundary(refused.exception, boundary)
                self.assertEqual(fixture.ancestry_paths[-1], fixture.root)
            finally:
                directory.chmod(previous)
        # This guard is deliberately usable before the frozen setup creates its
        # runtime/control directories; unrelated files are preserved elsewhere.
        fixture.runtime.rename(fixture.var / "unrelated-runtime")
        before = set(fixture.var.iterdir())
        with fixture.patched():
            report = subject.require_native_measurement_unused()
        self.assertEqual(report["status"], "MEASUREMENT_PATHS_ABSENT")
        self.assertEqual(set(fixture.var.iterdir()), before)
        self.assertFalse(fixture.runtime.exists())
        fixture.runtime.symlink_to(
            fixture.var / "unrelated-runtime", target_is_directory=True
        )
        with (
            fixture.patched(),
            self.assertRaises(subject.NativeMeasurementProvisioningError) as refused,
        ):
            subject.require_native_measurement_unused()
        self.assert_boundary(refused.exception, "_held_directory")

    def test_postpublication_expiry_or_source_loss_retains_all_outputs(self):
        for mode in ("expiry", "source"):
            with self.subTest(mode=mode):
                fixture = Fixture(self)
                create = subject.custody._create_document
                published = []

                def after_publication(*args):
                    result = create(*args)
                    published.append(result.raw)
                    if mode == "expiry":
                        subject.time.time.return_value = 2
                    else:
                        fixture.source_cas.read = lambda *args, **kwargs: (
                            _ for _ in ()
                        ).throw(CASError("inert late source loss"))
                    return result

                with (
                    fixture.patched(),
                    patch.object(
                        subject.custody,
                        "_create_document",
                        side_effect=after_publication,
                    ),
                ):
                    with self.assertRaises(
                        subject.NativeMeasurementProvisioningError
                    ) as refused:
                        subject.provision_runtime_native_measurement(
                            **fixture.arguments
                        )
                self.assertEqual(
                    published, [canonical_json(fixture.prepared["binding"])]
                )
                self.assert_boundary(
                    refused.exception,
                    "parse_runtime_capability_grant"
                    if mode == "expiry"
                    else "<genexpr>",
                )
                self.assertTrue(fixture.store.exists())
                self.assertEqual(
                    fixture.credential.read_bytes(),
                    canonical_json(fixture.prepared["binding"]),
                )
                with (
                    fixture.patched(),
                    self.assertRaises(subject.NativeMeasurementProvisioningError),
                ):
                    subject.require_native_measurement_unused()

    def test_bad_prepared_pin_or_source_inventory_refuses_before_runtime_locks(self):
        for mode in ("prepared", "missing-source", "changed-source"):
            with self.subTest(mode=mode):
                fixture = Fixture(self)
                arguments = dict(fixture.arguments)
                if mode == "prepared":
                    arguments["expected_prepared_digest"] = prepared_fixture.PIN
                else:
                    pins = dict(fixture.source_pins)
                    if mode == "missing-source":
                        pins.pop("runtime_action_broker_v4.py")
                    else:
                        pins["runtime_action_broker_v4.py"] = prepared_fixture.PIN
                    arguments["expected_broker_source_pins"] = pins
                with (
                    fixture.patched(),
                    self.assertRaises(subject.NativeMeasurementProvisioningError),
                ):
                    subject.provision_runtime_native_measurement(**arguments)
                self.assertEqual(fixture.events, [])
                self.assertFalse(fixture.store.exists())

    def test_non_linux_refuses_before_validator_or_any_guard(self):
        with (
            patch.object(subject.sys, "platform", "not-linux"),
            patch.object(
                subject, "validate_prepared_native_measurement_inputs"
            ) as validator,
            self.assertRaises(subject.NativeMeasurementProvisioningError),
        ):
            subject.provision_runtime_native_measurement(
                prepared_raw=b"",
                expected_prepared_digest="",
                expected_binding_digest="",
                expected_broker_source_pins={},
                source_cas=None,
            )
        validator.assert_not_called()


if __name__ == "__main__":
    unittest.main()
