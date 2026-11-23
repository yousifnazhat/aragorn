"""Compose the existing inert install and action producers, never a live install or send."""
from copy import deepcopy
import json
from unittest import TestCase
from unittest.mock import patch

from aragorn import protected_install as installer, runtime_active_skill_lineage as lineage
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.protected_install_context import VerifiedInstallContextV2
from scripts import verify_pi_core_install_action_join as subject
from tests import test_pi_core_install_admission_replay as install, test_pi_core_pilot_action_replay as action


class InstallActionJoinTests(TestCase):
    @classmethod
    def setUpClass(cls):
        nomination = install.InstallAdmissionReplay
        cls.addClassCleanup(nomination.doClassCleanups)
        nomination.setUpClass()
        f = cls.f = nomination.f
        a = cls.action = action.PilotActionReplay()
        cls.addClassCleanup(a.doCleanups)
        a.setUp()
        for row in (a.node.source, a.node.loader):
            assert f.put(a.readonly.read(row["digest"], max_bytes=4096)) == row["digest"]
        a.put = f.put

        grant = action.actions.fixtures._grant()
        runtime_policy = f.document(dict(schema="aragorn/runtime-action-policy/v1", id="inert-join", default="BLOCK",
            version=grant["policy_version"], sensor_digest=grant["sensor_digest"], allow=[],
            revocation_source_digest=canonical_digest("inert runtime revocations")))
        destination = dict(root_device=1, root_inode=11, target_name="example")
        cls.context_id = "sha256:" + "9" * 64  # B93's inert installed version basename.
        version = installer._version_path(destination["target_name"], cls.context_id, f.manifest)
        encode_report = f.wrapper._public_install

        def public_report(observation):
            if observation is not None:
                ctx_pin = observation["context_digest"]
                context = json.loads(f.archive.read(ctx_pin, max_bytes=65536))
                checked = VerifiedInstallContextV2(ctx_pin, cls.context_id, context["decision_digest"], f.manifest,
                    context["target_runtime_digest"], context["runtime_conformance_digest"], **destination,
                    expires_at_unix=context["expires_at_unix"], operation="install",
                    expected_active_context_id=None, expected_active_manifest_digest=None)
                cls.transaction = installer._transaction_record(checked, tree_digest=f.tree, version_path=version)
                observation = observation | {"transaction": cls.transaction}
            return encode_report(observation)

        binding = a.sources["expected_bindings"]
        runtime = binding["runtime_digest"]
        with patch.object(f, "deployment", f.deployment | {"runtime_commit_or_image": runtime}), \
                patch.object(f.wrapper, "_public_install", side_effect=public_report):
            pins = nomination().nomination(managed=True, policy_members={"runtime_action_policy_digest": runtime_policy},
                context_changes=dict(context_id=cls.context_id, target_runtime_digest=runtime, destination=destination))
        deployment = json.loads(f.archive.read(pins["plan_pin"], max_bytes=65536))["deployment"]["digest"]
        binding["deployment_digest"] = a.node.record["bindings"]["deployment_digest"] = deployment
        active_record = canonical_digest(dict(schema=lineage.ACTIVE_RUNTIME_SCHEMA, authority=lineage.ACTIVE_RUNTIME_AUTHORITY,
                                              transaction=cls.transaction))
        grant.update(install_context_digest=pins["context_pin"], source_manifest_digest=f.manifest,
                     active_skill_digest=f.member, policy_digest=runtime_policy)
        submission = action.actions.fixtures._submission()
        submission["envelope"]["request"].update(active_skill_digest=f.member, policy_digest=runtime_policy)
        for row in (submission["measured_action"], submission["runtime_attribution"]):
            row["active_skill_digest"] = f.member
        original_setup = action.actions.NativeActionEvidenceTests.setUp

        def action_setup(fixture, **options):
            original_setup(fixture, **(options | {"tree_digest": f.tree}))
            fixture.activation["active_record_digest"] = active_record

        with patch.object(action.actions.fixtures, "_grant", return_value=grant), \
                patch.object(action.actions.fixtures, "_submission", return_value=submission), \
                patch.object(action.actions.NativeActionEvidenceTests, "setUp", action_setup):
            a.original()

        cls.pins = pins | dict(action_nomination_pin=f.document(a.nomination()), deployment_pin=deployment)

    def verify(self, **changes):
        return subject.verify_install_action_join(self.f.archive, **(self.pins | changes))

    def test_original_install_and_action_match_without_effect_or_qualification_claims(self):
        result = self.verify()
        self.assertEqual(result["schema"], "aragorn/pi-core-install-action-join/v1")
        self.assertEqual(result["status"], "CONSISTENT_RECORDED_INSTALL_AND_ACTION")
        for key in ("effect_verified", "timing_verified", "sensor_health_verified", "activation_authorized", "phase3_exit_eligible"):
            self.assertIs(result[key], False)

    def test_same_context_and_tree_do_not_substitute_for_original_transaction(self):
        owner = json.loads(self.f.archive.read(self.pins["owner_pin"], max_bytes=1 << 18))
        foreign = self.transaction | {"destination": self.transaction["destination"] | {"root_inode": 78}}
        other = self.f.put(canonical_json(owner | {"transaction_digest": canonical_digest(foreign)}) + b"\n")
        with self.assertRaises(ValueError):
            self.verify(owner_pin=other)

    def test_valid_action_replay_may_not_substitute_installed_root_or_version(self):
        for changes in (dict(root_device=77), dict(version_path=".aragorn-versions/other/version")):
            with self.subTest(changes=changes), patch.object(self.action, "records", deepcopy(self.action.records)):
                dict(self.action.records)["REQUEST_CONTEXT"]["lineage"].update(changes)
                other = self.f.document(self.action.nomination())
                self.assertTrue(action.cli.replay(self.f.archive, other,
                    expected_deployment_digest=self.pins["deployment_pin"])["terminal_records_matched"])
                with self.assertRaises(ValueError):
                    self.verify(action_nomination_pin=other)

    def test_independent_deployment_cannot_be_selected_by_either_record(self):
        deployment = json.loads(self.f.archive.read(self.pins["deployment_pin"], max_bytes=4096))
        other = self.f.document(deployment | {"worker": canonical_digest("another worker")})
        with self.assertRaises(ValueError):
            self.verify(deployment_pin=other)
