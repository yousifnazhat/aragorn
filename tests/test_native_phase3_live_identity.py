"""Inert tests for the new reader; no native units, VM or retained capture runs."""

import copy
import os
import shlex
import stat
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from aragorn import native_phase3_live_identity as subject
from aragorn.oci_worker_protocol import canonical_json


class NativeLiveIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        # The pipeline intentionally drops TMPDIR. On macOS /tmp descendants
        # inherit its wheel GID, not this process's staff GID. Establish the
        # exact owned fixture group; never weaken the production custody check.
        os.chown(self.root, -1, os.getgid())
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)

    def file(self, name="file", raw=b"inert", mode=0o400):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def read(self, path="/file", **overrides):
        args = {"owner": os.getuid(), "owner_gid": os.getgid(), "modes": {0o400}}
        args.update(overrides)
        return subject._read_at(self.fd, path, **args)

    def test_direct_file_read_returns_only_digest_and_identity(self):
        self.file()
        raw, record = self.read()
        self.assertEqual(raw, b"inert")
        self.assertEqual(set(record), {"bytes", "digest", "identity"})
        self.assertEqual(record["digest"], subject._digest(raw))

    def test_symlink_hardlink_writable_and_oversize_files_refuse(self):
        path = self.file()
        (self.root / "alias").symlink_to(path)
        with self.assertRaises(OSError):
            self.read("/alias")
        os.link(path, self.root / "hardlink")
        with self.assertRaises(subject.NativeLiveIdentityError):
            self.read()
        (self.root / "hardlink").unlink()
        path.chmod(0o422)
        with self.assertRaises(subject.NativeLiveIdentityError):
            self.read(modes={0o422})
        path.chmod(0o400)
        with self.assertRaises(subject.NativeLiveIdentityError):
            self.read(limit=2)

    def test_leaf_replacement_during_read_refuses(self):
        path = self.file()
        original = os.read
        replaced = False

        def read_then_replace(fd, maximum):
            nonlocal replaced
            result = original(fd, maximum)
            if not replaced:
                replaced = True
                path.unlink()
                self.file(raw=b"other")
            return result

        with (
            patch.object(subject.os, "read", read_then_replace),
            self.assertRaises(subject.NativeLiveIdentityError),
        ):
            self.read()

    def test_service_owned_credential_requires_readonly_mount_and_explicit_gid(self):
        path = self.file()
        uid, gid = (1001, 1002) if os.getuid() == 0 else (os.getuid(), os.getgid())
        if os.getuid() == 0:
            os.chown(path, uid, gid)
        args = {"credential_owner": uid, "credential_gid": gid}
        with (
            patch.object(
                subject.os, "fstatvfs", return_value=SimpleNamespace(f_flag=0)
            ),
            self.assertRaises(subject.NativeLiveIdentityError),
        ):
            self.read(**args)
        with patch.object(
            subject.os, "fstatvfs", return_value=SimpleNamespace(f_flag=os.ST_RDONLY)
        ):
            self.assertEqual(self.read(**args)[0], b"inert")
            with self.assertRaises(subject.NativeLiveIdentityError):
                self.read(**{**args, "credential_gid": gid + 1})

    def test_fixed_unit_output_overflow_kills_only_own_reader_child(self):
        child = MagicMock()
        child.stdout.fileno.return_value = 41
        child.stderr.fileno.return_value = 42
        child.poll.return_value = None
        selector = MagicMock()
        selector.get_map.return_value = {41: object()}
        key = SimpleNamespace(data="stdout", fileobj=child.stdout)
        selector.select.return_value = [(key, 1)]
        with (
            patch.object(subject.subprocess, "Popen", return_value=child),
            patch.object(subject.selectors, "DefaultSelector") as factory,
            patch.object(subject.os, "set_blocking"),
            patch.object(subject.os, "read", side_effect=lambda fd, size: b"x" * size),
        ):
            factory.return_value.__enter__.return_value = selector
            with self.assertRaisesRegex(subject.NativeLiveIdentityError, "byte bound"):
                subject._show(subject._UNITS["worker"])
        child.kill.assert_called_once_with()
        child.stdout.close.assert_called_once_with()
        child.stderr.close.assert_called_once_with()

    def test_fixed_python_launcher_accepts_only_known_target(self):
        directory = self.root / "usr" / "bin"
        directory.mkdir(parents=True)
        path = directory / "python3.12"
        path.symlink_to(subject._PYTHON)
        record = subject._python_link(self.fd, uid=os.getuid(), gid=os.getgid())
        self.assertEqual(record["target"], subject._PYTHON)
        path.unlink()
        path.symlink_to("/usr/local/bin/other-python")
        with self.assertRaises(subject.NativeLiveIdentityError):
            subject._python_link(self.fd, uid=os.getuid(), gid=os.getgid())

    def systemd_alias(self):
        target = self.root / "usr" / "lib" / "systemd" / "system"
        target.mkdir(parents=True)
        (self.root / "lib").symlink_to("usr/lib")
        return target

    def alias_guard(self):
        return subject._systemd_library_alias(self.fd, uid=os.getuid(), gid=os.getgid())

    def test_merged_usr_alias_retains_exact_link_and_holds_target_ancestry(self):
        self.systemd_alias()
        opened = []
        original = os.open

        def tracked(*args, **kwargs):
            fd = original(*args, **kwargs)
            opened.append(fd)
            return fd

        with patch.object(subject.os, "open", side_effect=tracked):
            with self.alias_guard() as record:
                self.assertEqual(record["path"], "/lib")
                self.assertEqual(record["target"], "usr/lib")
                self.assertEqual(
                    record["canonical_unit_directory"], "/usr/lib/systemd/system"
                )
                self.assertEqual(
                    record["identity"],
                    list(subject.broker._file_identity((self.root / "lib").lstat())),
                )
                self.assertEqual(len(opened), 4)
                self.assertEqual(
                    record["target_ancestry_identities"],
                    [
                        list(subject.broker._directory_identity(os.fstat(fd)))
                        for fd in opened
                    ],
                )
        for fd in opened:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_merged_usr_alias_rejects_other_targets_and_target_symlink(self):
        target = self.systemd_alias()
        alias = self.root / "lib"
        for destination in ("/usr/lib", "./usr/lib", "usr/other"):
            with self.subTest(destination=destination):
                alias.unlink()
                alias.symlink_to(destination)
                with self.assertRaises(subject.NativeLiveIdentityError):
                    with self.alias_guard():
                        self.fail("unexpected alias target accepted")
        alias.unlink()
        alias.symlink_to("usr/lib")
        target.rename(target.with_name("real-system"))
        target.symlink_to("real-system")
        with self.assertRaises(OSError):
            with self.alias_guard():
                self.fail("symlink in target ancestry accepted")

    def test_merged_usr_alias_rechecks_link_identity_and_target_custody(self):
        target = self.systemd_alias()
        alias = self.root / "lib"
        with self.assertRaisesRegex(subject.NativeLiveIdentityError, "custody changed"):
            with self.alias_guard():
                alias.rename(self.root / "original-lib")
                alias.symlink_to("usr/lib")
        with self.assertRaisesRegex(
            subject.NativeLiveIdentityError, "ancestry changed"
        ):
            with self.alias_guard():
                target.rename(target.with_name("original-system"))
                target.mkdir()
        with self.assertRaisesRegex(
            subject.NativeLiveIdentityError, "ancestry changed"
        ):
            with self.alias_guard():
                target.chmod(0o777)
        with self.assertRaises(subject.broker._ProtectedFileError):
            with self.alias_guard():
                self.fail("writable target ancestry accepted")

    def test_launch_identity_matches_four_shipped_native_unit_contracts(self):
        root = Path(__file__).resolve().parents[1] / "packaging" / "systemd"
        groups = {
            "aragorn-agent-gateway": 201,
            "aragorn-runtime": 202,
            "aragorn-sensor": 203,
        }
        accounts = {
            role: (101 + index, groups[group])
            for index, (role, (_, group)) in enumerate(subject._ACCOUNTS.items())
        }
        for role, unit in subject._UNITS.items():
            with self.subTest(role=role):
                values = {}
                for line in (root / unit).read_text().splitlines():
                    key, separator, value = line.partition("=")
                    if separator and key in {
                        "User",
                        "Group",
                        "ExecStart",
                        "SupplementaryGroups",
                    }:
                        self.assertNotIn(key, values)
                        values[key] = value
                self.assertEqual(
                    (values["User"], values["Group"]), subject._ACCOUNTS[role]
                )
                argv = shlex.split(
                    values["ExecStart"].replace("%d", "/run/credentials/" + unit)
                )
                self.assertEqual(argv, subject._argv(role))
                expected_groups = sorted(
                    {
                        groups[values["Group"]],
                        *(
                            groups[name]
                            for name in values.get("SupplementaryGroups", "").split()
                        ),
                    }
                )
                self.assertEqual(subject._groups(role, accounts), expected_groups)

    def test_gateway_title_is_separate_from_exact_unit_launcher_contract(self):
        container, role = "a" * 64, "gateway"
        unit, argv = subject._UNITS[role], subject._argv(role)
        group = f"/docker/{container}/system.slice/{unit}"
        accounts = {
            "gateway": (101, 201),
            "worker": (102, 202),
            "sensor": (103, 203),
            "broker": (104, 202),
        }
        state = {
            "Id": unit,
            "MainPID": "1001",
            "ControlPID": "0",
            "ControlGroup": group,
            "InvocationID": "b" * 32,
            "ActiveState": "active",
            "SubState": "running",
            "User": "aragorn-agent-gateway",
            "Group": "aragorn-agent-gateway",
            "DropInPaths": "",
            "FragmentPath": "/usr/lib/systemd/system/" + unit,
            "ExecStart": "{ path="
            + argv[0]
            + " ; argv[]="
            + " ".join(argv)
            + " ; ignore_errors=no ; pid=1001 ; }",
        }
        command = b"openclaw-gateway\0\0\0"

        def virtual(path, maximum):
            if path.name == "cmdline":
                return command
            return b"Uid:\t101 101 101 101\nGid:\t201 201 201 201\nGroups:\t201\n"

        directory = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_dev=1, st_ino=2
        )
        with ExitStack() as stack:
            for item in (
                patch.object(subject, "_show", return_value=state),
                patch.object(
                    subject.process, "_read_virtual_file", side_effect=virtual
                ),
                patch.object(subject.process, "_process_start_time", return_value=10),
                patch.object(subject.process, "_process_cgroup", return_value=group),
                patch.object(
                    subject.process, "_cgroup_processes", return_value=(1001,)
                ),
                patch.object(
                    subject.process,
                    "_mount_namespace",
                    return_value={"device": 1, "inode": 2},
                ),
                patch.object(
                    subject.os, "readlink", return_value="/usr/local/bin/node"
                ),
                patch.object(subject.os, "lstat", return_value=directory),
                patch.object(subject.os, "stat", return_value=directory),
            ):
                stack.enter_context(item)
            result = subject._process(role, container, accounts)
            self.assertEqual(result["argv"], ["openclaw-gateway"])
            state["FragmentPath"] = "/lib/systemd/system/" + unit
            with self.assertRaises(subject.NativeLiveIdentityError):
                subject._process(role, container, accounts)
            alias_guard = MagicMock()
            result = subject._process(role, container, accounts, alias_guard)
            alias_guard.assert_called_once_with()
            self.assertEqual(
                result["unit"]["FragmentPath"], "/lib/systemd/system/" + unit
            )
            alias_guard.side_effect = subject.NativeLiveIdentityError("alias refused")
            with self.assertRaisesRegex(
                subject.NativeLiveIdentityError, "alias refused"
            ):
                subject._process(role, container, accounts, alias_guard)
            state["FragmentPath"] = "/usr/lib/systemd/system/" + unit
            command = b"different-title\0"
            with self.assertRaises(subject.NativeLiveIdentityError):
                subject._process(role, container, accounts)
            command = b"openclaw-gateway\0"
            state["ControlGroup"] = "/unowned/system.slice/" + unit
            with self.assertRaises(subject.NativeLiveIdentityError):
                subject._process(role, container, accounts)

    def documents(self):
        runtime = "sha256:" + "1" * 64
        policy = {"schema": "aragorn/runtime-action-policy/v1", "version": 1}
        profile = {"runtime_digest": runtime}
        documents = {
            subject._CONFIG: {"inert": "no credential output"},
            subject._POLICY: policy,
            subject._WORKER: {
                "schema": "aragorn/runtime-action-worker-binding/v1",
                "runtime_digest": runtime,
                "policy_version": 1,
                "policy_digest": subject._digest(canonical_json(policy)),
            },
            subject._RUNTIME: {
                "schema": "aragorn/runtime-action-runtime-binding/v2",
                "runtime_digest": runtime,
                "runtime_profile_digest": subject._digest(canonical_json(profile)),
            },
            subject._OBSERVATION: {
                "schema": "aragorn/runtime-observation-binding/v2",
                "runtime_profile": profile,
            },
        }
        return {
            path: canonical_json(documents[path]) if path in documents else b"inert"
            for path in subject.FILE_PATHS
        }

    def test_worker_requires_exact_gateway_supplementary_group(self):
        container, role = "a" * 64, "worker"
        unit, argv = subject._UNITS[role], subject._argv(role)
        group = f"/docker/{container}/system.slice/{unit}"
        accounts = {
            "gateway": (101, 201),
            "worker": (102, 202),
            "sensor": (103, 203),
            "broker": (104, 202),
        }
        state = {
            "Id": unit,
            "MainPID": "1002",
            "ControlPID": "0",
            "ControlGroup": group,
            "InvocationID": "b" * 32,
            "ActiveState": "active",
            "SubState": "running",
            "User": "aragorn-runtime",
            "Group": "aragorn-runtime",
            "DropInPaths": "",
            "FragmentPath": "/usr/lib/systemd/system/" + unit,
            "ExecStart": "{ path="
            + argv[0]
            + " ; argv[]="
            + " ".join(argv)
            + " ; ignore_errors=no ; pid=1002 ; }",
        }
        groups = b"201 202"

        def virtual(path, maximum):
            if path.name == "cmdline":
                return b"\0".join(item.encode() for item in argv) + b"\0"
            return (
                b"Uid:\t102 102 102 102\nGid:\t202 202 202 202\nGroups:\t"
                + groups
                + b"\n"
            )

        directory = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_dev=1, st_ino=2
        )
        with ExitStack() as stack:
            for item in (
                patch.object(subject, "_show", return_value=state),
                patch.object(
                    subject.process, "_read_virtual_file", side_effect=virtual
                ),
                patch.object(subject.process, "_process_start_time", return_value=10),
                patch.object(subject.process, "_process_cgroup", return_value=group),
                patch.object(
                    subject.process, "_cgroup_processes", return_value=(1002,)
                ),
                patch.object(
                    subject.process,
                    "_mount_namespace",
                    return_value={"device": 1, "inode": 2},
                ),
                patch.object(subject.os, "readlink", return_value=subject._PYTHON),
                patch.object(subject.os, "lstat", return_value=directory),
                patch.object(subject.os, "stat", return_value=directory),
            ):
                stack.enter_context(item)
            self.assertEqual(
                subject._process(role, container, accounts)["groups"], [201, 202]
            )
            for groups in (b"202", b"201 202 203"):
                with self.assertRaises(subject.NativeLiveIdentityError):
                    subject._process(role, container, accounts)

    def harness(
        self,
        stack,
        *,
        fail_pidfd=None,
        mutate_read=None,
        mutate_process=None,
        fragment_alias=False,
    ):
        raw = self.documents()
        pins = {path: subject._digest(content) for path, content in raw.items()}
        roles = list(subject._UNITS)
        accounts = {role: (101 + i, 201 + i) for i, role in enumerate(roles)}
        records = {
            role: {"pid": 1001 + i, "identity": role} for i, role in enumerate(roles)
        }
        opened = []
        counters = {}
        real_open = os.open

        def open_root(path, *args, **kwargs):
            if str(path).startswith("/proc/") and str(path).endswith("/root"):
                return real_open("/", os.O_RDONLY | os.O_DIRECTORY)
            return real_open(path, *args, **kwargs)

        def pidfd(record):
            if record["identity"] == fail_pidfd:
                raise subject.NativeLiveIdentityError("inert second PIDFD failure")
            fd = os.dup(self.fd)
            opened.append(fd)
            return fd

        def read_at(fd, path, **kwargs):
            source = path
            for role, names in subject._CREDENTIALS.items():
                for name, original in names.items():
                    if path == f"/run/credentials/{subject._UNITS[role]}/{name}":
                        source = original
            content = raw[source]
            counters[path] = counters.get(path, 0) + 1
            if mutate_read is not None:
                content = mutate_read(path, counters[path], content)
            mode = stat.S_IFREG | (0o400 if source not in subject._CODE else 0o644)
            record = {
                "bytes": len(content),
                "digest": subject._digest(content),
                "identity": [1, 2, mode, 0, 0, 1, len(content), 3, 4],
            }
            return content, record

        process_counts = {}

        def measurement(role, *args):
            process_counts[role] = process_counts.get(role, 0) + 1
            result = copy.deepcopy(records[role])
            if fragment_alias:
                args[-1]()
                result["unit"] = {
                    "FragmentPath": "/lib/systemd/system/" + subject._UNITS[role]
                }
            if mutate_process:
                result = mutate_process(role, process_counts[role], result)
            return result

        patches = (
            patch.object(subject.sys, "platform", "linux"),
            patch.object(subject.os, "geteuid", return_value=0),
            patch.object(subject.os, "pidfd_open", create=True),
            patch.object(subject.os, "open", side_effect=open_root),
            patch.object(subject, "_accounts", return_value=accounts),
            patch.object(subject, "_boot", return_value="boot"),
            patch.object(
                subject, "_python_link", return_value={"target": subject._PYTHON}
            ),
            patch.object(subject, "_process", side_effect=measurement),
            patch.object(subject, "_open_pidfd", side_effect=pidfd),
            patch.object(subject, "_read_at", side_effect=read_at),
            patch.object(
                subject.process,
                "_process_cgroup",
                return_value="/docker/" + "a" * 64 + "/init.scope",
            ),
            patch.object(subject.process, "require_live_pidfd"),
            patch.object(
                subject.process,
                "_executable_digest",
                side_effect=lambda pid: pins[
                    subject._executable_path(roles[pid - 1001])
                ],
            ),
        )
        for item in patches:
            stack.enter_context(item)
        return {
            "expected_container_id": "a" * 64,
            "expected_file_digests": pins,
        }, opened

    def test_measurement_reads_process_views_and_keeps_all_proof_ceilings(self):
        with ExitStack() as stack:
            args, opened = self.harness(stack)
            result = subject.read_native_live_identity(**args)
        self.assertEqual(set(result["loaded_process_views"]), set(subject._UNITS))
        self.assertEqual(result["unresolved_dimensions"], subject.UNRESOLVED_DIMENSIONS)
        self.assertNotIn("no credential output", str(result))
        self.assertFalse(result["common_deployment_fully_verified"])
        self.assertFalse(result["live_deployment_attested"])
        self.assertNotIn("fixed_systemd_library_alias", result)
        self.assertEqual(
            subject.compare_native_live_identity(result, copy.deepcopy(result))[
                "status"
            ],
            "CALLER_MEASUREMENTS_EQUAL",
        )
        for fd in opened:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_measurement_retains_alias_provenance_and_refuses_final_custody_change(
        self,
    ):
        target = self.systemd_alias()
        guard = subject._systemd_library_alias

        def owned_guard(root):
            return guard(self.fd, uid=os.getuid(), gid=os.getgid())

        def change_custody(role, count, value):
            if role == "broker" and count == 3:
                target.chmod(0o777)
            return value

        for mutate in (None, change_custody):
            with self.subTest(changed=mutate is not None), ExitStack() as stack:
                args, _ = self.harness(
                    stack, fragment_alias=True, mutate_process=mutate
                )
                factory = stack.enter_context(
                    patch.object(
                        subject, "_systemd_library_alias", side_effect=owned_guard
                    )
                )
                if mutate is None:
                    result = subject.read_native_live_identity(**args)
                    self.assertEqual(
                        result["fixed_systemd_library_alias"]["target"], "usr/lib"
                    )
                    for role in subject._UNITS:
                        self.assertEqual(
                            result["processes"][role]["unit"]["FragmentPath"],
                            "/lib/systemd/system/" + subject._UNITS[role],
                        )
                else:
                    with self.assertRaisesRegex(
                        subject.NativeLiveIdentityError, "ancestry changed"
                    ):
                        subject.read_native_live_identity(**args)
                factory.assert_called_once()

    def test_partial_pidfd_open_failure_closes_prior_handles(self):
        with ExitStack() as stack:
            args, opened = self.harness(stack, fail_pidfd="worker")
            with self.assertRaises(subject.NativeLiveIdentityError):
                subject.read_native_live_identity(**args)
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])

    def test_changed_loaded_credential_and_final_process_epoch_refuse(self):
        credential = f"/run/credentials/{subject._UNITS['worker']}/worker-binding"
        changes = (
            {
                "mutate_read": lambda path, count, content: (
                    content + b" " if path == credential and count == 2 else content
                )
            },
            {
                "mutate_process": lambda role, count, value: (
                    {**value, "pid": 9999} if role == "worker" and count == 3 else value
                )
            },
        )
        for change in changes:
            with self.subTest(change=tuple(change)), ExitStack() as stack:
                args, _ = self.harness(stack, **change)
                with self.assertRaises(subject.NativeLiveIdentityError):
                    subject.read_native_live_identity(**args)

    def test_pin_inventory_and_changed_policy_join_refuse(self):
        with ExitStack() as stack:
            args, _ = self.harness(stack)
            args["expected_file_digests"].pop(subject._ENTRY)
            with self.assertRaises(subject.NativeLiveIdentityError):
                subject.read_native_live_identity(**args)
        raw = self.documents()
        raw[subject._POLICY] = canonical_json(
            {"schema": "aragorn/runtime-action-policy/v1", "version": 2}
        )
        with self.assertRaises(subject.NativeLiveIdentityError):
            subject._joins(raw)

    def test_comparison_rejects_changes_or_promoted_claims(self):
        with ExitStack() as stack:
            args, _ = self.harness(stack)
            before = subject.read_native_live_identity(**args)
        after = copy.deepcopy(before)
        after["boot_id"] = "another boot"
        with self.assertRaises(subject.NativeLiveIdentityError):
            subject.compare_native_live_identity(before, after)
        before["route_qualified"] = True
        with self.assertRaises(subject.NativeLiveIdentityError):
            subject.compare_native_live_identity(before, before)


if __name__ == "__main__":
    unittest.main()
