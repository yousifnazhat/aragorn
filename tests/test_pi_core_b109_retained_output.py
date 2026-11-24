"""B110 join across a disposable private receipt, raw CAS object and inert B99 originals."""
from copy import deepcopy
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import time
from unittest import TestCase
from unittest.mock import patch

from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.pi_core_pilot_output_observer import hold_pilot_output
from scripts import verify_pi_core_b109_retained_output as verifier
from tests import test_pi_core_mask_custody as temporary, test_pi_core_public_pilot_action_join as b99


class B109RetainedOutput(TestCase):
    @classmethod
    def setUpClass(cls):
        # Only substitute outer host ancestry and developer uid/gid as in the
        # existing custody fixture. These files are not a deployment or a pilot.
        private = temporary.MaskCustodyTests()
        cls.addClassCleanup(private.doCleanups)
        private.setUp()
        donor = b99.pilot.PilotActionReplay()
        cls.addClassCleanup(donor.doCleanups)
        donor.setUp()
        sink = private.root / "inert-result-directory"
        sink.mkdir(mode=0o700)
        meta = sink.stat()
        descriptor = dict(schema="aragorn/runtime-protected-path/v1", target_name="result.json",
                          root_device=meta.st_dev, root_inode=meta.st_ino)
        path_pin = canonical_digest(descriptor)
        fixture = b99.pilot.actions.fixtures
        submission = fixture._submission()
        submission["envelope"]["request"]["path_digest"] = submission["measured_action"]["path_digest"] = path_pin
        with patch.object(fixture, "_submission", side_effect=lambda: deepcopy(submission)):
            provider, _, _, deployment = b99._public_records(donor, output_path_digest=path_pin)
            action = donor.put(canonical_json(donor.nomination()))
        activation = donor.activation["activation_id"]
        common = dict(store=private.store, receipt_directory=private.receipts, attempt_id="c" * 32,
                      deployment_digest=deployment, plan_digest=canonical_digest("inert-plan"),
                      release_digest=canonical_digest("inert-release"), expected_path_digest=path_pin)
        nominated = dict(expected_roots=private.roots, deadline=time.monotonic() + 15)
        verifier.custody.preflight(**common, **nominated)
        fd = os.open(sink, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with hold_pilot_output(fd, descriptor, expected_activation_id=activation) as after:
                with (sink / "result.json").open("xb") as out:
                    os.fchmod(out.fileno(), 0o400)
                    out.write(b'{"total":3}')  # One fixture write; no provider or service.
                observation = after()
        finally:
            os.close(fd)
        raw = canonical_json(observation)
        receipt = verifier.custody.retain(**common, **nominated, expected_activation_id=activation, observation_raw=raw)
        (sink / "result.json").unlink()  # Replay must no longer need the original worker directory.
        archive = CAS(donor.readonly.root.resolve(), read_only=True)
        cls.args = dict(store=private.store, receipt_directory=private.receipts, attempt_id=common["attempt_id"],
                        expected_activation_id=activation, expected_path_digest=path_pin, plan_pin=common["plan_digest"],
                        release_pin=common["release_digest"],
                        deployment_pin=deployment, output_pin=canonical_digest(observation), receipt_pin=receipt["receipt_digest"],
                        action_archive=archive, action_pin=action, provider_archive=archive, provider_pin=provider)

    def test_independent_private_original_matches_the_recorded_create_after_sink_cleanup(self):
        with patch.object(CAS, "put_expected", side_effect=AssertionError("replay tried to publish")):
            report = verifier.verify_retained_output(**self.args)
        self.assertEqual(report["status"], "MATCHED_LOCAL_CUSTODY_AND_RECORDED_PILOT_OUTPUT")
        for field in ("output_observation_digest", "receipt_digest", "deployment_digest", "plan_digest", "release_digest"):
            key = {"output_observation_digest": "output_pin"}.get(field, field.replace("_digest", "_pin"))
            self.assertEqual(report[field], self.args[key])
        self.assertEqual(report["base_payload_digest"],
                         "sha256:f84e61381e72d7630964e07d5b4a6ee97006e7642a1666eaba4fbce7e1563232")
        for flag in ("acquisition_authenticity_verified", "writer_attribution_verified", "effect_verified",
                     "release_authority_verified", "installed_identity_verified", "cleanup_verified",
                     "operational_success_verified", "phase3_qualified"):
            self.assertIs(report[flag], False)
        self.assertNotIn("payload_hex", report)

    def test_correct_observation_without_matching_out_of_band_custody_does_not_reach_action_replay(self):
        with patch.object(verifier, "verify_pilot_output", side_effect=AssertionError("unbound custody reached B107")):
            for key in ("plan_pin", "release_pin", "receipt_pin", "deployment_pin", "output_pin"):
                with self.subTest(field=key), self.assertRaises((ValueError, OSError, CASError)):
                    verifier.verify_retained_output(**(self.args | {key: canonical_digest("foreign")}))

    def test_submitted_archives_cannot_double_as_private_custody(self):
        with TemporaryDirectory(dir=self.args["store"]) as t:
            child = CAS(Path(t))
            for archive in (CAS(self.args["store"], read_only=True), CAS(child.root, read_only=True)):
                with self.subTest(root=archive.root), patch.object(
                        verifier.custody, "read_retained", side_effect=AssertionError("alias accepted")):
                    with self.assertRaisesRegex(ValueError, "overlapping evidence roots"):
                        verifier.verify_retained_output(**(self.args | {"provider_archive": archive}))
