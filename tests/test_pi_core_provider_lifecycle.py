"""Only the additive provider-enabled lifecycle slice; all effects are inert.

Reuse fixture setup by composition, not test inheritance. No existing lifecycle
test cases, real credentials, units, sockets, network calls or targets execute.
"""

from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import socket
import stat
import unittest
from unittest import mock

from aragorn import pi_core_provider_credential as credentials
from aragorn import pi_core_service_lifecycle as subject
from tests import test_pi_core_service_lifecycle as fixtures


class CredentialHold:
    pass


class PiProviderLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.base = fixtures.PiServiceLifecycleTests(methodName="runTest")
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.base.stack.enter_context(mock.patch.object(credentials, "PiProviderCredential", CredentialHold))
        self.credential = CredentialHold()
        self.credential.provider_inputs = self.base.public
        self.credential.deadline = 130.0
        self.credential.source = "/proc/9000/fd/71"
        self.credential.guard = mock.Mock()
        self.base.public.profile["address"] = "8.8.8.8"
        self.base.runtime.binding["source_digests"] = {subject._SOURCE_LOADER: "sha256:" + "1" * 64}
        self.startup = self.base.stack.enter_context(mock.patch.object(subject.PiServiceLifecycle, "_source_startup"))
        self.real_manager_prerequisites = subject._provider_manager_prerequisites
        self.real_credential_absence = subject._credential_directory_absent
        self.manager_prerequisites = self.base.stack.enter_context(mock.patch.object(subject, "_provider_manager_prerequisites"))
        self.credential_absence = self.base.stack.enter_context(mock.patch.object(subject, "_credential_directory_absent"))

    def instance(self, *, enabled=True):
        return subject.PiServiceLifecycle(subject._SEAL, self.base.runtime, self.base.config,
            self.base.public, self.base.binding, 125.0, 5.0,
            provider_credential=self.credential if enabled else None)

    def planned(self):
        held = self.instance()
        for service in held.services.values(): subject._plan(service, held)
        return held, held.services["provider"]

    def property_values(self, service):
        values = {name: [signature, "0"] for name, signature in subject._EMPTY.items()}
        values.update({name: [signature, "0"] for name, signature in subject._PROVIDER_EMPTY.items()})
        values["LoadCredential"] = ["a(ss)", "1", "openai-api-key", self.credential.source]
        values["RuntimeMaxUSec"], values["TimeoutStopUSec"] = ["t", "30000000"], ["t", "5000000"]
        for name, rows in service.ip_rules.items():
            value = ["a(iayu)", str(len(rows))]
            for family, octets, prefix in rows:
                value.extend([str(family), str(len(octets)), *map(str, octets), str(prefix)])
            values[name] = value
        for name, entries in service.binds.items():
            value = ["a(ssbt)", str(len(entries))]
            for source, target in entries:
                value.extend((str(source), target, "false", "16384" if name == "BindReadOnlyPaths" else "0"))
            values[name] = value
        argv = service.argv[service.argv.index("--") + 1:]
        values["ExecStart"] = ["a(sasbttttuii)", "1", argv[0], str(len(argv)), *argv, "false", *(["0"] * 7)]
        return values

    def readback(self, service, values):
        with mock.patch.object(subject, "_property", side_effect=lambda role, name, deadline: values[name]):
            return subject._readback(service, service.scalar, 120.0)

    @contextmanager
    def manager_directory(self, *, parent=None, absent=True):
        run = fixtures.metadata(701)
        def metadata(name, *, dir_fd, **kwargs):
            self.assertEqual((name, dir_fd, kwargs), ("credentials", 701, {"follow_symlinks": False}))
            if parent is None: raise FileNotFoundError
            return parent
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(subject.lineage, "_open_protected_root", return_value=701))
            stack.enter_context(mock.patch.object(os, "open", return_value=702))
            stack.enter_context(mock.patch.object(os, "stat", side_effect=metadata))
            stack.enter_context(mock.patch.object(os, "fstat", side_effect=lambda fd: run if fd == 701 else parent))
            stack.enter_context(mock.patch.object(os, "lstat", return_value=run))
            missing = stack.enter_context(mock.patch.object(subject.native, "_missing", return_value=absent))
            yield missing

    def test_provider_version_floor_is_checked_before_credential_namespace(self):
        for version in ("257", "257.5-1ubuntu3", "259 (259.1-1)"):
            self.base.command.return_value = (0, ('s "' + version + '"').encode("ascii"))
            self.real_manager_prerequisites(120.0)
        self.assertEqual(self.credential_absence.call_count, 3)
        self.assertEqual(self.base.command.call_args.args[0][-2:],
                         ("org.freedesktop.systemd1.Manager", "Version"))

    def test_unsupported_provider_manager_refuses_before_credential_namespace(self):
        self.base.command.return_value = (0, b's "256.9-1"')
        with self.assertRaises(subject.PiServiceLifecycleError): self.real_manager_prerequisites(120.0)
        self.credential_absence.assert_not_called()

    def test_malformed_provider_manager_version_refuses(self):
        for value in (b'as 0', b's ""', b's "0257"', b's "unknown"', b's "257" extra', b's "257;bad"'):
            self.base.command.return_value = (0, value)
            with self.subTest(value=value), self.assertRaises(subject.PiServiceLifecycleError):
                self.real_manager_prerequisites(120.0)
        self.credential_absence.assert_not_called()

    def test_provider_manager_version_command_failure_refuses(self):
        self.base.command.return_value = (1, b's "257"')
        with self.assertRaises(subject.PiServiceLifecycleError): self.real_manager_prerequisites(120.0)
        self.credential_absence.assert_not_called()

    def test_missing_credential_parent_is_allowed_without_creating_it(self):
        with self.manager_directory() as missing:
            self.real_credential_absence(120.0)
        missing.assert_called_once_with(701, "credentials")
        os.mkdir.assert_not_called()
        os.unlink.assert_not_called()
        self.base.close_fd.assert_called_once_with(701)

    def test_protected_credential_parent_checks_only_exact_provider_leaf(self):
        with self.manager_directory(parent=fixtures.metadata(702)) as missing:
            self.real_credential_absence(120.0)
        missing.assert_called_once_with(702, "aragorn-pi-provider.service")
        self.assertEqual(self.base.close_fd.call_args_list, [mock.call(702), mock.call(701)])
        os.unlink.assert_not_called()
        os.rmdir.assert_not_called()

    def test_preexisting_manager_credential_leaf_refuses_without_adoption(self):
        with self.manager_directory(parent=fixtures.metadata(702), absent=False), \
             self.assertRaisesRegex(subject.PiServiceLifecycleError, "not absent"):
            self.real_credential_absence(120.0)
        os.unlink.assert_not_called()
        os.rmdir.assert_not_called()

    def test_credential_parent_must_be_root_owned_nonsymlink_and_not_writable(self):
        for parent in (fixtures.metadata(702, stat.S_IFLNK | 0o777), fixtures.metadata(702, uid=1000),
                       fixtures.metadata(702, gid=1000), fixtures.metadata(702, stat.S_IFDIR | 0o777)):
            with self.subTest(parent=parent), self.manager_directory(parent=parent), \
                 self.assertRaises(subject.PiServiceLifecycleError):
                self.real_credential_absence(120.0)

    def test_credential_parent_substitution_during_open_refuses(self):
        with self.manager_directory(parent=fixtures.metadata(702)), \
             mock.patch.object(os, "fstat", side_effect=lambda fd: fixtures.metadata(701 if fd == 701 else 703)), \
             self.assertRaisesRegex(subject.PiServiceLifecycleError, "changed during open"):
            self.real_credential_absence(120.0)

    def test_credential_ancestry_substitution_refuses(self):
        with self.manager_directory(), mock.patch.object(os, "lstat", return_value=fixtures.metadata(703)), \
             self.assertRaisesRegex(subject.PiServiceLifecycleError, "ancestry changed"):
            self.real_credential_absence(120.0)

    def test_enabled_manager_preflight_failure_precedes_all_service_preparation(self):
        self.manager_prerequisites.side_effect = subject.PiServiceLifecycleError("preexisting credentials")
        with self.assertRaisesRegex(subject.PiServiceLifecycleError, "preexisting credentials"):
            with self.base.hold(provider_credential=self.credential): pass
        self.assertNotIn("prepare", self.base.events)
        self.base.command.assert_not_called()

    def test_credential_namespace_is_rechecked_immediately_before_provider_start(self):
        held = self.instance()
        self.base.prepare_service(held)
        self.credential_absence.side_effect = subject.PiServiceLifecycleError("late credential residue")
        with self.assertRaisesRegex(subject.PiServiceLifecycleError, "late credential residue"):
            held._start("provider")
        self.assertFalse(held.services["provider"].start_attempted)
        self.base.command.assert_not_called()

    def test_post_stop_credential_residue_holds_cleanup_without_deletion(self):
        with self.assertRaisesRegex(subject.PiServiceLifecycleError, "cleanup is uncertain"):
            with self.base.hold(provider_credential=self.credential) as held:
                self.credential_absence.side_effect = subject.PiServiceLifecycleError("credential residue")
        self.assertEqual(held.observation["cleanup"]["status"], "CLEANUP_HOLD")
        self.assertTrue(held.services["provider"].terminal)
        self.assertNotIn("provider_credential_cleanup", held.observation)
        os.unlink.assert_not_called()
        os.rmdir.assert_not_called()

    def test_ipv4_profile_prepares_only_provider_with_exact_credential_and_host(self):
        held, service = self.planned()
        self.assertEqual(service.scalar["PrivateNetwork"], "no")
        self.assertEqual(service.scalar["RestrictAddressFamilies"], "AF_UNIX AF_INET")
        for item in ("LoadCredential=openai-api-key:/proc/9000/fd/71", "IPAddressDeny=any", "IPAddressAllow=8.8.8.8/32"):
            self.assertIn("--property=" + item, service.argv)
        for role in ("action", "sensor"):
            other = held.services[role]
            self.assertEqual(other.scalar["PrivateNetwork"], "yes")
            self.assertEqual(other.scalar["RestrictAddressFamilies"], "AF_UNIX")
            self.assertIsNone(other.provider_credential)
            self.assertFalse(any("LoadCredential=" in arg or "IPAddress" in arg for arg in other.argv))

    def test_ipv6_profile_uses_linux_family_and_exact_host_prefix(self):
        self.base.public.profile["address"] = "2606:4700:4700::1111"
        _, service = self.planned()
        self.assertEqual(service.scalar["RestrictAddressFamilies"], "AF_UNIX AF_INET6")
        self.assertIn("--property=IPAddressAllow=2606:4700:4700::1111/128", service.argv)
        self.assertEqual(service.ip_rules["IPAddressAllow"][0][0], 10)
        self.assertTrue(self.readback(service, self.property_values(service)).startswith("sha256:"))

    def test_no_raw_credential_mount_or_worker_exposure_is_added(self):
        held, _ = self.planned()
        for service in held.services.values():
            mounts = [(str(source), target) for rows in service.binds.values() for source, target in rows]
            self.assertFalse(any("credentials" in item or self.credential.source in item
                                 for row in mounts for item in row))
            self.assertEqual(service.scalar["Environment"], "")
            self.assertEqual(service.scalar["PassEnvironment"], "")

    def test_only_provider_prepares_empty_owned_credential_mountpoint(self):
        held = self.instance()
        directories = []
        def mkdir(owner, path, uid=0, gid=0, mode=0o755):
            directories.append(path)
            owner._fds[path] = 300 + len(directories)
        def endpoint(name, *, dir_fd, **kwargs):
            role = next(role for role in subject.ROLES if held._fds[subject._ROOT / role] == dir_fd)
            return fixtures.metadata(900 + subject.ROLES.index(role), stat.S_IFSOCK | 0o660,
                                     0, self.base.ids[role]["gid"])
        with mock.patch.object(subject.lineage, "_open_protected_root", return_value=200), \
             mock.patch.object(subject.PiServiceLifecycle, "_mkdir", mkdir), \
             mock.patch.object(os, "open", return_value=400), \
             mock.patch.object(os, "fstat", side_effect=lambda fd: fixtures.metadata(200) if fd == 200
                               else fixtures.metadata(400, stat.S_IFREG | 0o444)), \
             mock.patch.object(os, "fchmod"), mock.patch.object(os, "chown"), mock.patch.object(os, "chmod"), \
             mock.patch.object(os, "stat", side_effect=endpoint), \
             mock.patch.object(socket, "socket", side_effect=lambda *args: fixtures.InertSocket()):
            self.base.real_prepare(held)
        root = held.services["provider"].root
        self.assertEqual([path for path in directories if "credentials" in path.parts],
                         [root / "run/credentials", root / "run/credentials/aragorn-pi-provider.service"])
        self.assertFalse(any("credentials" in path.parts for path, identity in held._files))
        os.read.assert_not_called()
        os.write.assert_not_called()

    def test_exact_holder_type_required_before_any_start(self):
        with self.assertRaises(subject.PiServiceLifecycleError):
            with self.base.hold(provider_credential=object()): pass
        self.base.command.assert_not_called()

    def test_subclass_holder_is_not_authority(self):
        class Substitute(CredentialHold): pass
        with self.assertRaises(subject.PiServiceLifecycleError):
            subject._guard_credential(Substitute(), self.base.public, 120.0)

    def test_different_held_public_inputs_refuse(self):
        self.credential.provider_inputs = object()
        with self.assertRaises(subject.PiServiceLifecycleError):
            with self.base.hold(provider_credential=self.credential): pass
        self.base.command.assert_not_called()

    def test_expired_or_short_credential_custody_refuses(self):
        self.credential.deadline = 119.0
        with self.assertRaises(subject.PiServiceLifecycleError):
            self.instance()._inputs(120.0)
        self.credential.guard.assert_not_called()

    def test_revoked_holder_refuses_before_service_preparation(self):
        self.credential.guard.side_effect = RuntimeError("revoked")
        with self.assertRaisesRegex(RuntimeError, "revoked"):
            with self.base.hold(provider_credential=self.credential): pass
        self.assertNotIn("prepare", self.base.events)
        self.base.command.assert_not_called()

    def test_unsafe_or_non_descriptor_source_cannot_enter_command(self):
        for source in ("/etc/key", "/proc/self/fd/71", "/proc/0/fd/71", "/proc/9000/fd/071",
                       "/proc/9000/fd/71:other", "/proc/9000/fd/71\n", Path("/proc/9000/fd/71")):
            with self.subTest(source=source), self.assertRaises(subject.PiServiceLifecycleError):
                self.credential.source = source
                self.planned()

    def test_credential_descriptor_substitution_refuses_generation(self):
        _, service = self.planned()
        self.credential.source = "/proc/9000/fd/72"
        with self.assertRaises(subject.PiServiceLifecycleError):
            subject._credential_generation(service, 120.0)

    def test_exact_enabled_properties_bind_immutable_digest(self):
        _, service = self.planned()
        self.assertTrue(self.readback(service, self.property_values(service)).startswith("sha256:"))

    def test_different_credential_mapping_is_rejected(self):
        _, service = self.planned()
        for value in (["a(ss)", "0"], ["a(ss)", "1", "other", self.credential.source],
                      ["a(ss)", "1", "openai-api-key", "/proc/9000/fd/72"],
                      ["a(ss)", "2", "openai-api-key", self.credential.source, "extra", "/etc/key"]):
            values = self.property_values(service)
            values["LoadCredential"] = value
            with self.subTest(value=value), self.assertRaises(subject.PiServiceLifecycleError):
                self.readback(service, values)

    def test_imported_and_inline_credentials_remain_forbidden(self):
        _, service = self.planned()
        for name, value in {"ImportCredential": ["as", "1", "*"],
                            "ImportCredentialEx": ["a(ss)", "1", "*", "*"],
                            "SetCredential": ["a(say)", "1", "other", "1", "1"],
                            "LoadCredentialEncrypted": ["a(ss)", "1", "other", "/etc/key"]}.items():
            values = self.property_values(service)
            values[name] = value
            with self.subTest(name=name), self.assertRaises(subject.PiServiceLifecycleError):
                self.readback(service, values)

    def test_extra_address_or_broad_prefix_is_rejected(self):
        _, service = self.planned()
        for value in (["a(iayu)", "1", "2", "4", "8", "8", "8", "8", "24"],
                      ["a(iayu)", "1", "2", "4", "8", "8", "4", "4", "32"],
                      ["a(iayu)", "2", "2", "4", "8", "8", "8", "8", "32", "2", "4", "8", "8", "4", "4", "32"]):
            values = self.property_values(service)
            values["IPAddressAllow"] = value
            with self.subTest(value=value), self.assertRaises(subject.PiServiceLifecycleError):
                self.readback(service, values)

    def test_deny_must_cover_both_complete_ip_families(self):
        _, service = self.planned()
        for value in (["a(iayu)", "0"], ["a(iayu)", "1", "2", "4", "0", "0", "0", "0", "0"],
                      ["a(iayu)", "2", "2", "4", "0", "0", "0", "0", "1", "10", "16", *(["0"] * 16), "0"]):
            values = self.property_values(service)
            values["IPAddressDeny"] = value
            with self.subTest(value=value), self.assertRaises(subject.PiServiceLifecycleError):
                self.readback(service, values)

    def test_rule_order_is_not_authority(self):
        _, service = self.planned()
        values = self.property_values(service)
        value = values["IPAddressDeny"]
        values["IPAddressDeny"] = value[:2] + value[9:] + value[2:9]
        self.assertEqual(self.readback(service, values), self.readback(service, self.property_values(service)))

    def test_malformed_or_duplicate_structured_rules_refuse(self):
        row = ["2", "4", "8", "8", "8", "8", "32"]
        for value in (["as", "1", *row], ["a(iayu)", "01", *row], ["a(iayu)", "1", "30", *row[1:]],
                      ["a(iayu)", "1", "2", "16", *row[2:]], ["a(iayu)", "2", *row, *row],
                      ["a(iayu)", "1", *row, "extra"], ["a(iayu)", "1", "2", "4", "256", "0", "0", "0", "32"],
                      ["a(iayu)", "1", "2", "4", "08", "8", "8", "8", "32"]):
            with self.subTest(value=value), self.assertRaises(subject.PiServiceLifecycleError):
                subject._ip_rules(value)

    def test_broader_address_families_or_private_network_change_refuses(self):
        _, service = self.planned()
        for changes in ({"RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6"}, {"PrivateNetwork": "yes"}):
            with self.subTest(changes=changes), self.assertRaises(subject.PiServiceLifecycleError):
                subject._readback(service, service.scalar | changes, 120.0)

    def test_property_lookup_uses_service_interface_for_ip_and_credentials(self):
        self.base.command.return_value = (0, b"a(iayu) 0")
        self.assertEqual(subject._property("provider", "IPAddressAllow", 120.0), ["a(iayu)", "0"])
        self.assertEqual(self.base.command.call_args.args[0][-2:],
                         ("org.freedesktop.systemd1.Service", "IPAddressAllow"))

    def test_enabled_observation_is_preparation_not_request_or_filter_proof(self):
        with self.base.hold(provider_credential=self.credential) as held:
            value = held.observation
            self.assertEqual(value["status"], "AUTHENTICATED_SERVICES_PROVIDER_PREPARED")
            self.assertIsNone(value["provider_dispatched"])
            self.assertIsNone(value["credential_read"])
            self.assertFalse(value["egress_filter_kernel_verified"])
            self.assertFalse(value["phase3_exit_eligible"])
        self.assertEqual(held.observation["cleanup"]["status"], "VERIFIED_OWNED_CLEANUP")
        self.assertEqual(held.observation["provider_credential_cleanup"], "MANAGER_DIRECTORY_ABSENT")

    def test_revocation_after_start_retains_captured_generation_without_retry(self):
        held = self.instance()
        self.base.prepare_service(held)
        def start(argv, deadline):
            self.credential.guard.side_effect = RuntimeError("revoked after start")
            return 0, b""
        self.base.command.side_effect = start
        with self.assertRaisesRegex(RuntimeError, "revoked after start"):
            held._start("provider")
        self.assertTrue(held.services["provider"].started)
        self.assertEqual(held.services["provider"].pid, 8003)
        self.base.command.assert_called_once()

    def test_protected_generation_guards_credential_before_and_after_identity_readback(self):
        held, service = self.planned()
        self.base.capture_service(service, 120.0)
        state = {"LoadState": "loaded", "ActiveState": "active", "MainPID": str(service.pid),
            "InvocationID": service.invocation, "ExecMainStartTimestampMonotonic": service.unit_started_at,
            "ExecMainPID": str(service.pid), "ControlGroup": service.plan.profile.cgroup}
        self.base.state.return_value = state
        self.credential.guard.reset_mock()
        with mock.patch.object(subject.native, "_cgroup_owned"), mock.patch.object(subject.native, "_exited", return_value=False), \
             mock.patch.object(subject, "_readback", return_value=service.immutable_digest), \
             mock.patch.object(subject.process, "_process_start_time", return_value=service.start_ticks), \
             mock.patch.object(subject.process, "_process_cgroup", return_value=service.plan.profile.cgroup), \
             mock.patch.object(subject.process, "_cgroup_processes", return_value=(service.pid,)):
            self.base.real_generation(service, 120.0)
        self.assertEqual(self.credential.guard.call_args_list, [mock.call(deadline=120.0)] * 2)

    def test_retired_collected_provider_still_requires_credential_custody(self):
        _, service = self.planned()
        self.credential.guard.side_effect = RuntimeError("retired custody revoked")
        with self.assertRaisesRegex(RuntimeError, "retired custody revoked"):
            subject._retired_provider_generation(service, 120.0)

    def test_cleanup_revocation_does_not_withdraw_owned_stop_authority(self):
        held, service = self.planned()
        self.base.capture_service(service, 120.0)
        service.start_attempted, service.started = True, True
        self.credential.guard.side_effect = RuntimeError("revoked")
        self.base.state.side_effect = [{"LoadState": "loaded"}, self.base.absent()]
        with mock.patch.object(subject.native, "_exited", return_value=True), \
             mock.patch.object(subject.native, "_cgroup_empty"):
            self.base.real_stop(held, service)
        self.base.generation.assert_called_once_with(service, 125.0, live=False, credential_authority=False)
        self.assertTrue(service.terminal)
        self.assertIn("stop", self.base.command.call_args.args[0])

    def test_channel_guard_rechecks_credential_before_unit_operations(self):
        with self.base.hold(provider_credential=self.credential) as held:
            self.credential.guard.side_effect = RuntimeError("channel custody revoked")
            self.base.generation.reset_mock()
            with self.assertRaisesRegex(RuntimeError, "channel custody revoked"):
                held.guard()
            self.base.generation.assert_not_called()
            self.credential.guard.side_effect = None

    def test_default_profile_remains_unavailable_after_additive_option(self):
        with self.base.hold() as held:
            self.assertEqual(held.observation["status"], "AUTHENTICATED_SERVICES_PROVIDER_UNAVAILABLE")
            self.assertEqual(held.observation["provider_mode"], "UNAVAILABLE_NO_EGRESS_NO_CREDENTIAL")
            self.assertFalse(held.observation["credential_read"])
        self.credential.guard.assert_not_called()
        self.manager_prerequisites.assert_not_called()
        self.credential_absence.assert_not_called()


if __name__ == "__main__":
    unittest.main()
