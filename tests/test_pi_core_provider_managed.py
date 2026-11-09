"""New approved caller joins only; no native or provider operations execute."""

import copy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_managed_bootstrap as managed
from aragorn import pi_core_native_provider as native_provider
from aragorn import pi_core_provider_approval as approval
from aragorn import pi_core_provider_mediation as mediation
from aragorn import pi_core_service_channels as channels
from aragorn import pi_core_service_configuration as configuration
from aragorn import pi_core_service_lifecycle as lifecycle
from aragorn import pi_core_openai_transport as transport
from tests import test_pi_core_managed_bootstrap as managed_fixtures
from tests import test_pi_core_native_provider as native_fixtures
from tests import test_pi_core_provider_start as start_fixtures
from tests import test_pi_core_provider_egress as egress_fixtures


def fixture(test, cls):
    value = cls(methodName="runTest")
    value.setUp()
    test.addCleanup(value.doCleanups)
    return value


class CredentialHold:
    pass


class ApprovalHold:
    pass


class ManagedProviderTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, managed_fixtures.ManagedBootstrapTests)
        self.enterContext(mock.patch.object(managed.credentials, "PiProviderCredential", CredentialHold))
        self.enterContext(mock.patch.object(managed.approvals, "PiProviderApproval", ApprovalHold))
        self.credential, self.approval = CredentialHold(), ApprovalHold()
        self.credential.provider_inputs, self.credential.guard = self.f.public, mock.Mock()
        self.approval.guard = mock.Mock()
        self.config = start_fixtures.configuration()
        self.approval.route_digest = self.config.provider_route_digest
        root = Path("/var/lib/aragorn/provider-control")
        self.approval.config = mediation.broker.RuntimeActionBrokerConfig(
            root / "broker.sock", root / "instance.lock", root / "broker.lock", root,
            Path("/var/lib/aragorn/provider-protected"), Path("/var/lib/aragorn/provider-staging"),
            *(root / (name + ".json") for name in ("policy", "revocations", "health", "observation", "state")),
            0, 1301, 1302, self.f.profile.runtime_digest, self.config.worker_uid, self.config.worker_gid)

    def run_enabled(self, **changes):
        return self.f.run_bootstrap(**(dict(config=self.config, provider_credential=self.credential,
                                            provider_approval=self.approval) | changes))

    def test_enabled_caller_joins_same_credential_approval_and_service_channels(self):
        result = self.run_enabled()
        self.assertIs(self.f.hold.call_args.kwargs["provider_credential"], self.credential)
        held = self.f.worker.call_args.kwargs["provider_channels"]
        self.assertIs(type(held), native_provider.PiNativeProviderChannels)
        self.assertIs(held.services, self.f.services.channels)
        self.assertIs(held.approval, self.approval)
        self.assertIs(held.config, self.approval.config)
        self.credential.guard.assert_called_once_with(deadline=125)
        self.approval.guard.assert_called_once_with(deadline=125)
        self.assertTrue(result["provider_configured"])
        self.assertFalse(result["provider_available"])
        self.assertFalse(result["useful_task_verified"])
        self.assertFalse(result["phase3_exit_eligible"])

    def test_partial_or_serialized_provider_authority_refuses_before_services(self):
        for field in ("provider_credential", "provider_approval"):
            for invalid in (None, {}):
                with self.subTest(field=field, invalid=invalid), self.assertRaises(managed.PiManagedBootstrapError):
                    self.run_enabled(**{field: invalid})
        self.f.hold.assert_not_called()

    def test_unavailable_mode_cannot_silently_receive_authority(self):
        with self.assertRaisesRegex(managed.PiManagedBootstrapError, "unavailable"):
            self.run_enabled(config=self.f.config)
        self.f.hold.assert_not_called()

    def test_different_public_input_custody_refuses(self):
        self.credential.provider_inputs = copy.copy(self.f.public)
        with self.assertRaisesRegex(managed.PiManagedBootstrapError, "profile"):
            self.run_enabled()
        self.f.hold.assert_not_called()

    def test_different_route_refuses(self):
        self.approval.route_digest = "sha256:" + "e" * 64
        with self.assertRaisesRegex(managed.PiManagedBootstrapError, "route"):
            self.run_enabled()
        self.f.hold.assert_not_called()

    def test_revoked_credential_or_approval_custody_prevents_activation(self):
        for holder in (self.credential, self.approval):
            holder.guard.side_effect = RuntimeError("held authority changed")
            with self.assertRaisesRegex(RuntimeError, "changed"):
                self.run_enabled()
            holder.guard.side_effect = None
        self.f.hold.assert_not_called()

    def test_nonroot_wrong_runtime_and_overlapping_action_control_refuse(self):
        initial = self.approval.config
        for changes in ({"expected_broker_uid": 1201}, {"expected_runtime_uid": 999},
                        {"expected_runtime_digest": "sha256:" + "f" * 64},
                        {"control_root": managed.entry.EFFECT_ROOT / "control"},
                        {"control_root": managed.entry.EFFECT_ROOT.parent}):
            self.approval.config = replace(initial, **changes)
            with self.subTest(changes=changes), self.assertRaises(managed.PiManagedBootstrapError):
                self.run_enabled()
        self.f.hold.assert_not_called()

    def test_worker_failure_does_not_retry_or_release_borrowed_authority(self):
        self.f.worker.side_effect = RuntimeError("worker failed")
        with self.assertRaisesRegex(RuntimeError, "failed"):
            self.run_enabled()
        self.f.worker.assert_called_once()
        self.assertEqual(self.f.events[-1], "services-cleanup")


class NativeApprovalBindingTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, native_fixtures.ProviderFixture)
        self.held = object.__new__(approval.PiProviderApproval)
        self.guard = self.enterContext(mock.patch.object(approval.PiProviderApproval, "guard", autospec=True))
        self.bind = self.enterContext(mock.patch.object(approval.PiProviderApproval, "bind", autospec=True))
        self.enterContext(mock.patch.object(approval.PiProviderApproval, "config", new_callable=mock.PropertyMock,
                                          return_value=self.f.config))
        self.enterContext(mock.patch.object(approval.PiProviderApproval, "route_digest", new_callable=mock.PropertyMock,
                                          return_value=self.f.pd._expected["route_digest"]))
        self.f.pd.channels = replace(self.f.provider_channels, approval=self.held)
        self.f.pd._channel_pin = self.f.pd.channels

    def test_actual_captured_identity_and_prepared_payload_bind_before_start(self):
        self.f.begin()
        self.bind.assert_called_once_with(self.held, self.f.pd._expected, native_fixtures.activation(), deadline=115)
        self.assertIsNotNone(self.f.pd._pins)
        self.f.source_health.assert_not_called()
        self.f.mediate.assert_not_called()

    def test_failed_publication_prevents_start_and_never_dispatches(self):
        self.bind.side_effect = RuntimeError("approval publication refused")
        with self.assertRaisesRegex(RuntimeError, "publication"):
            self.f.begin()
        self.assertIsNone(self.f.pd._pins)
        self.f.mediate.assert_not_called()

    def test_changed_capture_refuses_before_approval_publication(self):
        with self.assertRaisesRegex(RuntimeError, "activation differs"):
            self.f.pd.require_start({**native_fixtures.activation(), "pid": 999}, deadline=115)
        self.bind.assert_not_called()

    def test_serialized_approval_cannot_be_substituted(self):
        self.f.pd.channels = replace(self.f.provider_channels, approval={})
        self.f.pd._channel_pin = self.f.pd.channels
        with self.assertRaisesRegex(RuntimeError, "approval differs"):
            self.f.begin()
        self.bind.assert_not_called()

    def test_expired_held_authority_stops_before_source_or_provider_work(self):
        self.guard.side_effect = RuntimeError("expired approval")
        with self.assertRaisesRegex(RuntimeError, "expired"):
            self.f.begin()
        self.bind.assert_not_called()
        self.f.mediate.assert_not_called()


class HeldProviderProfileTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, native_fixtures.ProviderFixture)
        self.held = object.__new__(configuration.PiProviderInputs)
        self.f.services._lifecycle.provider_inputs = self.held
        self.profile = {"address": "8.8.8.8", "service_uid": 1501, "service_gid": 1502}
        self.enterContext(mock.patch.object(configuration.PiProviderInputs, "profile", new_callable=mock.PropertyMock,
                                          side_effect=lambda: copy.deepcopy(self.profile)))
        self.guard = self.enterContext(mock.patch.object(configuration.PiProviderInputs, "guard", autospec=True))
        self.fixed = self.enterContext(mock.patch.object(transport, "read_profile",
            side_effect=AssertionError("must not read an unrelated host profile")))

    def test_mediator_uses_guarded_public_profile_from_exact_service_lifetime(self):
        result = mediation._service_profile(self.f.services, 110)
        self.assertEqual(result, self.profile)
        self.assertIsNot(result, self.profile)
        self.guard.assert_called_once_with(self.held, deadline=110)
        self.fixed.assert_not_called()

    def test_profile_custody_refuses_unowned_lifetime_or_public_inputs(self):
        for owner in (None, SimpleNamespace(provider_inputs=self.held)):
            self.f.services._lifecycle = owner
            with self.assertRaisesRegex(RuntimeError, "LIFETIME"):
                mediation._service_profile(self.f.services, 110)
        owner = object.__new__(lifecycle.PiServiceLifecycle)
        owner.provider_inputs = {}
        self.f.services._lifecycle = owner
        with self.assertRaisesRegex(RuntimeError, "CUSTODY"):
            mediation._service_profile(self.f.services, 110)

    def test_profile_change_or_expiry_cannot_fall_back_to_host(self):
        self.guard.side_effect = RuntimeError("public inputs changed")
        with self.assertRaisesRegex(RuntimeError, "changed"):
            mediation._service_profile(self.f.services, 110)
        self.fixed.assert_not_called()

    def test_profile_lookup_cannot_extend_channel_deadline(self):
        with self.assertRaisesRegex(RuntimeError, "CUSTODY"):
            mediation._service_profile(self.f.services, 116)
        self.guard.assert_not_called()

    def test_legacy_no_custody_preserves_fixed_profile_lookup(self):
        self.fixed.side_effect = None
        self.fixed.return_value = self.profile
        self.assertEqual(mediation._service_profile(None, 110), self.profile)
        self.fixed.assert_called_once_with()
        self.guard.assert_not_called()


class HeldProfileEgressTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture(self, egress_fixtures.ProviderEgressTests)
        self.custody = object.__new__(channels.PiServiceChannels)
        self.custody._lifecycle = object.__new__(lifecycle.PiServiceLifecycle)
        self.custody._lifecycle.provider_inputs = object.__new__(configuration.PiProviderInputs)
        self.custody._connections = (object(), object(), self.f.f.provider)
        peer = self.f.f.peer
        self.custody._expected = {"provider": dict(zip(("pid", "uid", "gid"), peer))}
        self.custody._deadline, self.custody._provider_retired = 120, False
        self.enterContext(mock.patch.object(channels.PiServiceChannels, "guard", autospec=True))
        self.retire = self.enterContext(mock.patch.object(channels.PiServiceChannels, "retire_provider", autospec=True))
        self.public_guard = self.enterContext(mock.patch.object(configuration.PiProviderInputs, "guard", autospec=True))
        self.enterContext(mock.patch.object(configuration.PiProviderInputs, "profile", new_callable=mock.PropertyMock,
                                          side_effect=lambda: copy.deepcopy(self.f.profile)))
        self.f.read_profile.side_effect = AssertionError("unrelated host profile must remain unread")

    def test_same_held_profile_is_rechecked_for_initial_connect_and_send(self):
        result = self.f.f.run_request(provider_service=True, service_custody=self.custody)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["egress_checks"], 2)
        self.assertEqual(self.public_guard.call_count, 3)
        self.retire.assert_called_once()
        self.f.read_profile.assert_not_called()

    def test_changed_held_profile_between_connect_and_send_preserves_spent_claim(self):
        def change(index):
            if index == 1:
                self.f.profile["address"] = "1.1.1.1"
        self.f.before_receive = change
        result = self.f.f.run_request(provider_service=True, service_custody=self.custody)
        self.assertEqual(result["status"], "INDETERMINATE")
        self.assertEqual(result["egress_checks"], 1)
        self.assertTrue(self.f.f.claims)
        self.f.read_profile.assert_not_called()

