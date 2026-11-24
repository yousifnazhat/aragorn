"""Join a disposable sink observation to B99's inert records; no pilot or service."""
from io import BytesIO
from copy import deepcopy
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts.pi_core_pilot_output_observer import hold_pilot_output
from scripts.verify_pi_core_pilot_output import verify_pilot_output
from tests import test_pi_core_public_pilot_action_join as b99


class PilotOutputJoinTests(TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(cls.enterClassContext(TemporaryDirectory()))
        cls.evidence = CAS(root / "observer-cas")
        cls.readonly_output = CAS(cls.evidence.root, read_only=True)
        cls.action = b99.pilot.PilotActionReplay()
        cls.addClassCleanup(cls.action.doCleanups)
        cls.action.setUp()
        for name in ("protected", "decoy"):
            (root / name).mkdir(mode=0o700)
        cls.directory = root / "protected"
        cls.decoy = root / "decoy"
        cls.path_pin = canonical_digest(cls.descriptor(cls.directory.stat()))
        donors = b99.pilot.actions.fixtures
        submission = donors._submission()
        submission["envelope"]["request"]["path_digest"] = cls.path_pin
        submission["measured_action"]["path_digest"] = cls.path_pin
        with patch.object(donors, "_submission", side_effect=lambda: deepcopy(submission)):
            cls.provider_pin, _, _, cls.deployment_pin = b99._public_records(cls.action, output_path_digest=cls.path_pin)
            cls.action_pin = cls.action.put(canonical_json(cls.action.nomination()))
            cls.activation_id = cls.action.activation["activation_id"]
            # Identical already-prepared provider inputs; only the action outcome changes.
            cls.action.original("effective", public_pilot_call_id=b99.CALL,
                                public_pilot_policy_digest=cls.action.activation["policy_digest"])
            cls.blocked_pin = cls.action.put(canonical_json(cls.action.nomination()))
            # Same measured path and observation, but no action rule in this original policy.
            cls.provider_only, _, _, cls.provider_only_deployment = b99._public_records(cls.action)
            cls.provider_only_action = cls.action.put(canonical_json(cls.action.nomination()))
        cls.observation = cls.observe(cls.directory)
        cls.output_pin = cls.retain(cls.observation)

    @staticmethod
    def descriptor(meta):
        return dict(schema="aragorn/runtime-protected-path/v1", root_device=meta.st_dev,
                    root_inode=meta.st_ino, target_name="result.json")

    @classmethod
    def observe(cls, directory):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with hold_pilot_output(fd, cls.descriptor(os.fstat(fd)), expected_activation_id=cls.activation_id) as after:
                with (directory / "result.json").open("xb") as file:
                    os.fchmod(file.fileno(), 0o400)
                    file.write(b'{"total":3}')  # Test author, not a broker or provider.
                return after()
        finally:
            os.close(fd)

    @classmethod
    def retain(cls, observation):
        raw = canonical_json(observation)
        return cls.evidence.put(BytesIO(raw), max_bytes=len(raw))

    def verify(self, **changes):
        inputs = dict(action_pin=self.action_pin, provider_archive=self.action.readonly,
                      provider_pin=self.provider_pin, deployment_pin=self.deployment_pin,
                      output_archive=self.readonly_output, output_pin=self.output_pin,
                      expected_path_digest=self.path_pin)
        return verify_pilot_output(self.action.readonly, **(inputs | changes))

    def test_original_observation_and_records_match_without_crediting_a_live_effect(self):
        report = self.verify()
        self.assertEqual(report["status"], "MATCHED_RECORDED_PILOT_OUTPUT")
        self.assertEqual((report["action_nomination_digest"], report["output_observation_digest"],
                          report["path_digest"]), (self.action_pin, self.output_pin, self.path_pin))
        self.assertIs(report["recorded_create_rule_matched"], True)
        for field in ("acquisition_authenticity_verified", "writer_attribution_verified", "effect_verified", "phase3_qualified"):
            self.assertIs(report[field], False)

    def test_observation_from_another_directory_cannot_be_self_nominated(self):
        actual = self.observe(self.decoy)
        with self.assertRaisesRegex(ValueError, "PILOT_OUTPUT_ACTION_DIFFERS"):
            self.verify(output_pin=self.retain(actual), expected_path_digest=canonical_digest(actual["path_descriptor"]))

    def test_changed_activation_content_or_external_pin_refuses(self):
        for key, value in (("activation_id", "1" * 32), ("payload_digest", canonical_digest({"total": 4})),
                           ("payload_hex", b'{"total":4}'.hex()), ("before", "PRESENT")):
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.verify(output_pin=self.retain(self.observation | {key: value}))
        with self.assertRaises((CASError, ValueError)):
            self.verify(output_pin=canonical_digest("not in the observer archive"))

    def test_matching_file_does_not_upgrade_a_blocked_action(self):
        with self.assertRaisesRegex(ValueError, "PILOT_OUTPUT_NO_RECORDED_CREATE"):
            self.verify(action_pin=self.blocked_pin)

    def test_provider_only_policy_cannot_authorize_a_create(self):
        with self.assertRaisesRegex(ValueError, "PILOT_OUTPUT_NO_CREATE_RULE"):
            self.verify(action_pin=self.provider_only_action, provider_pin=self.provider_only,
                        deployment_pin=self.provider_only_deployment)
