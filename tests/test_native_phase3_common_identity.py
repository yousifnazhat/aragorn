"""New common-reader paths with inert kernel doubles; no live service is read."""

from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn import native_phase3_common_identity as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_capability_grant import GRANT_AUTHORITY, GRANT_SCHEMA

PIN = "sha256:" + "a" * 64
BOOT = "00000000-1111-2222-3333-444444444444"
CONTAINER = "c" * 64


class NativeCommonIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fd = os.open(temporary.name, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)

    def documents(self):
        old = subject.prior
        raw = {path: ("inert bytes: " + path).encode() for path in subject.FILE_PATHS}
        policy = {
            "schema": "aragorn/runtime-action-policy/v1",
            "version": 1,
            "sensor_digest": PIN,
        }
        profile = {"runtime_digest": PIN}
        runtime_profile = canonical_digest(profile)
        grant = {
            "schema": GRANT_SCHEMA,
            "authority": GRANT_AUTHORITY,
            "grant_id": "f" * 64,
            "source_manifest_digest": PIN,
            "install_context_digest": PIN,
            "runtime_profile_digest": runtime_profile,
            "runtime_digest": PIN,
            "active_skill_digest": PIN,
            "sensor_digest": PIN,
            "policy_digest": canonical_digest(policy),
            "policy_version": 1,
            "operation_digest": canonical_digest(
                {"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}
            ),
            "issued_at_unix": 90,
            "expires_at_unix": 120,
            "max_actions": 1,
        }
        docs = {
            old._CONFIG: {"token": "inert-secret-not-returned"},
            old._POLICY: policy,
            old._GRANT: grant,
            old._WORKER: {
                "schema": "aragorn/runtime-action-worker-binding/v1",
                "runtime_digest": PIN,
                "active_skill_digest": PIN,
                "policy_digest": canonical_digest(policy),
                "policy_version": 1,
            },
            old._RUNTIME: {
                "schema": "aragorn/runtime-action-runtime-binding/v2",
                "runtime_digest": PIN,
                "runtime_profile_digest": runtime_profile,
            },
            old._OBSERVATION: {
                "schema": "aragorn/runtime-observation-binding/v2",
                "sensor_digest": PIN,
                "runtime_profile": profile,
            },
        }
        binding = {
            "schema": "aragorn/runtime-broker-decision-measurement-binding/v1",
            "boot_id": BOOT,
            "attempt_id": "inert-common-attempt",
            **{
                key: PIN
                for key in (
                    "deployment_identity_digest",
                    "measurement_schedule_digest",
                    "collection_commitment_digest",
                    "scheduled_measurement_request_digest",
                    "path_digest",
                    "payload_digest",
                )
            },
            "grant_digest": canonical_digest(grant),
            "source_pins": {
                name: old._digest(raw[path])
                for name, path in subject.MEASUREMENT_SOURCES.items()
            },
            **{
                key: grant[key]
                for key in (
                    "runtime_profile_digest",
                    "sensor_digest",
                    "runtime_digest",
                    "policy_digest",
                    "active_skill_digest",
                    "operation_digest",
                )
            },
        }
        docs[subject.MEASUREMENT_BINDING] = binding
        raw.update({path: canonical_json(value) for path, value in docs.items()})
        return raw

    def harness(
        self, stack, *, raw=None, mutate_read=None, mutate_process=None, fail_pidfd=None
    ):
        old = subject.prior
        raw = self.documents() if raw is None else raw
        pins = {path: old._digest(value) for path, value in raw.items()}
        roles = tuple(old._UNITS)
        accounts = {
            "gateway": (101, 201),
            "worker": (102, 202),
            "sensor": (103, 203),
            "broker": (104, 202),
        }
        root_stat = os.stat("/")
        records = {
            role: {
                "pid": 1001 + index,
                "role": role,
                "root_identity": [root_stat.st_dev, root_stat.st_ino],
            }
            for index, role in enumerate(roles)
        }
        real_open, opened, views, reads, counts, process_counts = (
            os.open,
            [],
            {},
            [],
            {},
            {},
        )

        def open_root(path, *args, **kwargs):
            if str(path).startswith("/proc/") and str(path).endswith("/root"):
                self.assertEqual(len(opened), 4)
                for fd in opened:
                    os.fstat(fd)  # All PIDFD stand-ins must still be held.
                fd = real_open("/", os.O_RDONLY | os.O_DIRECTORY)
                views[fd] = roles[int(str(path).split("/")[2]) - 1001]
                return fd
            return real_open(path, *args, **kwargs)

        def pidfd(record):
            if record["role"] == fail_pidfd:
                raise old.NativeLiveIdentityError("inert PIDFD refusal")
            fd = os.dup(self.fd)
            opened.append(fd)
            return fd

        def read_at(fd, path, **kwargs):
            source = path
            for role, credentials in subject.CREDENTIALS.items():
                for name, original in credentials.items():
                    if path == f"/run/credentials/{old._UNITS[role]}/{name}":
                        source = original
            key = (views.get(fd, "observer"), path)
            counts[key] = counts.get(key, 0) + 1
            content = raw[source]
            if mutate_read:
                content = mutate_read(key, counts[key], content)
            if source == subject.MEASUREMENT_BINDING:
                self.assertEqual(kwargs["limit"], 4096)
                self.assertEqual(kwargs["owner"], 0)
                if path == source:
                    self.assertEqual(kwargs["modes"], {0o400})
                    self.assertEqual(kwargs["owner_gid"], 0)
                else:
                    self.assertEqual(kwargs["credential_owner"], accounts["broker"][0])
                    self.assertEqual(kwargs["credential_gid"], accounts["broker"][1])
            if source in subject.MEASUREMENT_SOURCES.values():
                self.assertEqual(kwargs["owner"], 0)
                self.assertEqual(kwargs["modes"], {0o644})
            mode = stat.S_IFREG | (
                0o400 if source == subject.MEASUREMENT_BINDING else 0o644
            )
            metadata = {
                "bytes": len(content),
                "digest": old._digest(content),
                "identity": [1, 2, mode, 0, 0, 1, len(content), 3, 4],
            }
            reads.append((key, counts[key]))
            return content, metadata

        def measured(role, *args):
            process_counts[role] = process_counts.get(role, 0) + 1
            record = deepcopy(records[role])
            return (
                mutate_process(role, process_counts[role], record)
                if mutate_process
                else record
            )

        for item in (
            patch.object(subject.sys, "platform", "linux"),
            patch.object(subject.os, "geteuid", return_value=0),
            patch.object(subject.os, "pidfd_open", create=True),
            patch.object(subject.os, "open", side_effect=open_root),
            patch.object(old, "_accounts", return_value=accounts),
            patch.object(old, "_boot", return_value=BOOT),
            patch.object(old, "_python_link", return_value={"target": old._PYTHON}),
            patch.object(old, "_process", side_effect=measured),
            patch.object(
                subject,
                "_broker_process",
                side_effect=lambda *args: measured("broker", *args),
            ),
            patch.object(old, "_open_pidfd", side_effect=pidfd),
            patch.object(old, "_read_at", side_effect=read_at),
            patch.object(
                old.process,
                "_process_cgroup",
                return_value=f"/docker/{CONTAINER}/init.scope",
            ),
            patch.object(old.process, "require_live_pidfd"),
            patch.object(
                old.process,
                "_executable_digest",
                side_effect=lambda pid: pins[old._executable_path(roles[pid - 1001])],
            ),
        ):
            stack.enter_context(item)
        return (
            {"expected_container_id": CONTAINER, "expected_file_digests": pins},
            opened,
            reads,
        )

    def assert_closed(self, descriptors):
        for fd in descriptors:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_common_read_measures_new_sources_and_loaded_binding_then_rereads(self):
        with ExitStack() as stack:
            arguments, opened, reads = self.harness(stack)
            result = subject.read_native_common_identity(**arguments)
        self.assertEqual(result["schema"], subject.SCHEMA)
        self.assertEqual(len(result["files"]), 26)
        self.assertEqual(
            set(result["broker_module_views"]), set(subject.MEASUREMENT_SOURCES)
        )
        self.assertIn(
            "decision-measurement-binding", result["loaded_process_views"]["broker"]
        )
        self.assertNotIn("inert-secret-not-returned", str(result))
        self.assertTrue(all(result[name] is False for name in subject._FALSE))
        for path in subject.MEASUREMENT_SOURCES.values():
            self.assertIn((("observer", path), 2), reads)
            self.assertIn((("broker", path), 2), reads)
        binding_path = f"/run/credentials/{subject.prior._UNITS['broker']}/decision-measurement-binding"
        self.assertIn((("broker", binding_path), 2), reads)
        self.assertEqual(result["measured_joins"]["measurement_boot_id"], BOOT)
        self.assert_closed(opened)

    def test_loaded_binding_and_module_mismatch_refuse_without_retry(self):
        targets = (
            f"/run/credentials/{subject.prior._UNITS['broker']}/decision-measurement-binding",
            subject.MEASUREMENT_SOURCES["runtime_action_broker_v4.py"],
        )
        for path in targets:
            with self.subTest(path=path), ExitStack() as stack:
                arguments, opened, reads = self.harness(
                    stack,
                    mutate_read=lambda key, count, content: (
                        content + b" " if key == ("broker", path) else content
                    ),
                )
                with self.assertRaises(subject.NativeCommonIdentityError):
                    subject.read_native_common_identity(**arguments)
                self.assertEqual(
                    [item for item in reads if item[0] == ("broker", path)],
                    [(("broker", path), 1)],
                )
            self.assert_closed(opened)

    def test_final_root_and_loaded_readback_changes_refuse(self):
        targets = (
            ("observer", subject.MEASUREMENT_BINDING),
            (
                "observer",
                subject.MEASUREMENT_SOURCES["runtime_broker_decision_measurement.py"],
            ),
            ("broker", subject.MEASUREMENT_SOURCES["phase3_quantitative_metrics.py"]),
            (
                "broker",
                f"/run/credentials/{subject.prior._UNITS['broker']}/decision-measurement-binding",
            ),
        )
        for target in targets:
            with self.subTest(target=target), ExitStack() as stack:
                arguments, opened, _ = self.harness(
                    stack,
                    mutate_read=lambda key, count, content: (
                        content + b" " if key == target and count == 2 else content
                    ),
                )
                with self.assertRaises(subject.NativeCommonIdentityError):
                    subject.read_native_common_identity(**arguments)
            self.assert_closed(opened)

    def test_binding_boot_and_each_source_pin_join_actual_read_bytes(self):
        original = self.documents()
        for key in ("boot_id", *subject.MEASUREMENT_SOURCES):
            raw = dict(original)
            binding = subject.prior._document(raw[subject.MEASUREMENT_BINDING])
            if key == "boot_id":
                binding[key] = "99999999-1111-2222-3333-444444444444"
            else:
                binding["source_pins"][key] = PIN
            raw[subject.MEASUREMENT_BINDING] = canonical_json(binding)
            with self.subTest(key=key), ExitStack() as stack:
                # Caller pins are rebuilt too; failure must be an actual cross-read join.
                arguments, _, _ = self.harness(stack, raw=raw)
                with self.assertRaises(subject.NativeCommonIdentityError):
                    subject.read_native_common_identity(**arguments)

    def test_protected_grant_policy_worker_and_runtime_must_join(self):
        original = self.documents()
        for path, field in (
            (subject.MEASUREMENT_BINDING, "grant_digest"),
            (subject.MEASUREMENT_BINDING, "sensor_digest"),
            (subject.prior._GRANT, "active_skill_digest"),
            (subject.prior._WORKER, "active_skill_digest"),
            (subject.prior._RUNTIME, "runtime_profile_digest"),
            (subject.prior._POLICY, "sensor_digest"),
        ):
            raw = dict(original)
            document = subject.prior._document(raw[path])
            document[field] = "sha256:" + "b" * 64
            raw[path] = canonical_json(document)
            with self.subTest(path=path, field=field), ExitStack() as stack:
                arguments, _, _ = self.harness(stack, raw=raw)
                with self.assertRaises(subject.NativeCommonIdentityError):
                    subject.read_native_common_identity(**arguments)

    def test_exact_pin_inventory_and_source_digest_are_required(self):
        for change in ("missing", "extra", "wrong"):
            with self.subTest(change=change), ExitStack() as stack:
                arguments, opened, _ = self.harness(stack)
                pins = arguments["expected_file_digests"]
                path = subject.MEASUREMENT_SOURCES["phase3_deployment.py"]
                if change == "missing":
                    pins.pop(path)
                elif change == "extra":
                    pins["/unexpected"] = PIN
                else:
                    pins[path] = PIN
                with self.assertRaises(subject.NativeCommonIdentityError):
                    subject.read_native_common_identity(**arguments)
            self.assert_closed(opened)

    def test_partial_pidfd_failure_and_process_epoch_change_close_handles(self):
        for change in ("pidfd", "process", "root"):

            def mutate(role, count, record):
                if role == "broker":
                    if change == "process" and count == 3:
                        record["pid"] += 1
                    if change == "root":
                        record["root_identity"] = [0, 0]
                return record

            with self.subTest(change=change), ExitStack() as stack:
                arguments, opened, _ = self.harness(
                    stack,
                    fail_pidfd="worker" if change == "pidfd" else None,
                    mutate_process=mutate,
                )
                with self.assertRaises(subject.NativeCommonIdentityError):
                    subject.read_native_common_identity(**arguments)
            self.assert_closed(opened)

    def broker_harness(self, stack):
        old = subject.prior
        accounts = {
            "gateway": (101, 201),
            "worker": (102, 202),
            "sensor": (103, 203),
            "broker": (104, 202),
        }
        unit, argv = old._UNITS["broker"], subject._broker_argv()
        group = f"/docker/{CONTAINER}/system.slice/{unit}"
        state = {
            "Id": unit,
            "MainPID": "1004",
            "ControlPID": "0",
            "ControlGroup": group,
            "InvocationID": "b" * 32,
            "ActiveState": "active",
            "SubState": "running",
            "User": "aragorn-broker",
            "Group": "aragorn-runtime",
            "DropInPaths": "",
            "FragmentPath": "/usr/lib/systemd/system/" + unit,
            "ExecStart": "{ path="
            + argv[0]
            + " ; argv[]="
            + " ".join(argv)
            + " ; ignore_errors=no ; pid=1004 ; }",
        }
        values = {
            "command": b"\0".join(item.encode() for item in argv) + b"\0",
            "status": b"Uid:\t104 104 104 104\nGid:\t202 202 202 202\nGroups:\t202 203\n",
        }
        directory = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_dev=1, st_ino=2
        )
        for item in (
            patch.object(old, "_show", return_value=state),
            patch.object(
                old.process,
                "_read_virtual_file",
                side_effect=lambda path, limit: values[
                    "command" if path.name == "cmdline" else "status"
                ],
            ),
            patch.object(old.process, "_process_start_time", return_value=10),
            patch.object(old.process, "_process_cgroup", return_value=group),
            patch.object(old.process, "_cgroup_processes", return_value=(1004,)),
            patch.object(
                old.process, "_mount_namespace", return_value={"device": 1, "inode": 2}
            ),
            patch.object(subject.os, "readlink", return_value=old._PYTHON),
            patch.object(subject.os, "lstat", return_value=directory),
            patch.object(subject.os, "stat", return_value=directory),
        ):
            stack.enter_context(item)
        return accounts, state, values

    def test_new_broker_kernel_and_unit_require_all_three_credential_arguments(self):
        with ExitStack() as stack:
            accounts, state, values = self.broker_harness(stack)
            record = subject._broker_process(CONTAINER, accounts)
            self.assertEqual(record["argv"], subject._broker_argv())
            self.assertEqual(record["groups"], [202, 203])
            original_command, original_start = values["command"], state["ExecStart"]
            values["command"] = (
                b"\0".join(item.encode() for item in subject.prior._argv("broker"))
                + b"\0"
            )
            with self.assertRaises(subject.NativeCommonIdentityError):
                subject._broker_process(CONTAINER, accounts)
            values["command"] = original_command
            state["ExecStart"] = original_start.replace(
                " " + subject._broker_argv()[-1], ""
            )
            with self.assertRaises(subject.NativeCommonIdentityError):
                subject._broker_process(CONTAINER, accounts)

    def test_broker_alias_groups_and_cgroup_fail_closed(self):
        with ExitStack() as stack:
            accounts, state, values = self.broker_harness(stack)
            unit = subject.prior._UNITS["broker"]
            state["FragmentPath"] = "/lib/systemd/system/" + unit
            with self.assertRaises(subject.NativeCommonIdentityError):
                subject._broker_process(CONTAINER, accounts)
            guard = Mock()
            subject._broker_process(CONTAINER, accounts, guard)
            guard.assert_called_once_with()
            state["FragmentPath"] = "/usr/lib/systemd/system/" + unit
            original_status = values["status"]
            values["status"] = values["status"].replace(b"202 203", b"202")
            with self.assertRaises(subject.NativeCommonIdentityError):
                subject._broker_process(CONTAINER, accounts)
            values["status"] = original_status
            state["ControlGroup"] = "/outside-fixture"
            with self.assertRaises(subject.NativeCommonIdentityError):
                subject._broker_process(CONTAINER, accounts)

    def test_unchanged_roles_delegate_without_rewriting_old_contracts(self):
        old_credentials, old_files = (
            deepcopy(subject.prior._CREDENTIALS),
            subject.prior.FILE_PATHS,
        )
        with patch.object(
            subject.prior, "_process", return_value={"actual": "unchanged-role"}
        ) as read:
            for role in ("gateway", "worker", "sensor"):
                guard = Mock()
                self.assertEqual(
                    subject._process(role, CONTAINER, {}, guard),
                    {"actual": "unchanged-role"},
                )
                read.assert_called_with(role, CONTAINER, {}, guard)
        self.assertEqual(subject.prior._CREDENTIALS, old_credentials)
        self.assertEqual(subject.prior.FILE_PATHS, old_files)
        self.assertNotIn(
            "decision-measurement-binding", subject.prior._CREDENTIALS["broker"]
        )

    def test_common_comparison_rejects_old_schema_changes_and_promoted_claims(self):
        with ExitStack() as stack:
            arguments, _, _ = self.harness(stack)
            before = subject.read_native_common_identity(**arguments)
        compared = subject.compare_native_common_identity(before, deepcopy(before))
        self.assertTrue(all(compared[key] is False for key in subject._FALSE))
        for key, value in (
            ("schema", subject.prior.SCHEMA),
            ("application_acknowledged", True),
            ("broker_module_views", {}),
        ):
            changed = {**before, key: value}
            with (
                self.subTest(key=key),
                self.assertRaises(subject.NativeCommonIdentityError),
            ):
                subject.compare_native_common_identity(changed, changed)
        for field in ("processes", "loaded_process_views"):
            changed = deepcopy(before)
            changed[field].pop("broker")
            with (
                self.subTest(field=field),
                self.assertRaises(subject.NativeCommonIdentityError),
            ):
                subject.compare_native_common_identity(changed, changed)
        for name in ("decision-measurement-binding", "code_view"):
            changed = deepcopy(before)
            changed["loaded_process_views"]["broker"].pop(name)
            with (
                self.subTest(name=name),
                self.assertRaises(subject.NativeCommonIdentityError),
            ):
                subject.compare_native_common_identity(changed, changed)
        after = deepcopy(before)
        after["boot_id"] = "changed"
        with self.assertRaises(subject.NativeCommonIdentityError):
            subject.compare_native_common_identity(before, after)


if __name__ == "__main__":
    unittest.main()
