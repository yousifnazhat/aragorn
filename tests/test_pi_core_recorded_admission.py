"""Exercise the real managed composer and install/action reader; no live acquisition."""
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase3_deployment import build_phase3_deployment_identity
from aragorn.phase3_exit_qualification import _digest
from scripts import verify_pi_core_recorded_admission as reader
from tests import test_pi_core_install_action_join as installed, test_pi_core_phase3_qualification as managed


REQ = "MP1/ADM-01/exact-admitted-bytes"


class RecordedAdmission(TestCase):
    @classmethod
    def setUpClass(cls):
        join = installed.InstallActionJoinTests
        cls.addClassCleanup(join.doClassCleanups)
        original = installed.action.PilotActionReplay.setUp
        # The B104 reader accepts the original B85 report producer, not today's wrapper.
        donor = installed.install.materialization
        checkout = donor.SOURCE.parents[2]
        raw = subprocess.run(["git", "--no-replace-objects", "cat-file", "blob",
                              "e8a445efeee6432afdcff0beb45af7ebc10941aa"], cwd=checkout, check=True,
                             env=os.environ | {"GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": ""},
                             stdout=subprocess.PIPE, timeout=5).stdout
        if _digest(raw) != donor.reader.SPINE_V2_WRAPPER_PIN:
            raise AssertionError("wrong archived report producer")
        root = Path(cls.enterClassContext(TemporaryDirectory()))
        (root / "src").symlink_to(checkout / "src", target_is_directory=True)
        wrapper = root / "packaging/pi-core/coordinator.py"
        wrapper.parent.mkdir(parents=True)
        wrapper.write_bytes(raw)

        def resolvable_runtime(fixture):
            original(fixture)
            for pins in (fixture.sources["expected_bindings"], fixture.node.record["bindings"]):
                pins["runtime_digest"] = canonical_digest("runtime_commit_or_image")

        with patch.object(installed.action.PilotActionReplay, "setUp", resolvable_runtime), patch.object(donor, "SOURCE", wrapper):
            join.setUpClass()
        cls.f, cls.pins = join.f, join.pins
        cls.bindings = json.loads(cls.f.archive.read(cls.pins["deployment_pin"]))
        for key, pin in cls.bindings.items():
            if key != "policy":
                assert cls.f.document(key) == pin
        cls.source = _digest(Path(reader.__file__).read_bytes())

    def replay(self, *, bindings=None, extra=None, changes=None, source=None):
        # Share the inert originals; all production readers still open the CAS read-only.
        case = managed.PiCorePhase3QualificationTests()
        self.addCleanup(case.doCleanups)
        identity = build_phase3_deployment_identity(bindings or self.bindings)
        with patch.object(managed.legacy_fixture, "CAS", return_value=self.f.store), \
                patch.object(managed.legacy_fixture, "build_phase3_deployment_identity", return_value=identity):
            case.setUp()
        args = case.arguments
        del args["verifiers"][REQ]
        if extra:
            args["verifiers"].update(extra)
        envelope = {"schema": "aragorn/pi-core-recorded-admission-inputs/v1", **self.pins, **(changes or {})}
        args["evidence_by_requirement"][REQ] = self.f.document(envelope)
        return reader.qualify_with_recorded_admission(verifier_source_digest=source or self.source, **args)

    def test_matching_originals_remain_not_tested_in_actual_composer(self):
        result = self.replay()
        row = result["requirements"][REQ]
        self.assertEqual(row["status"], "NOT_TESTED")
        self.assertIn("RECORDED_INSTALL_ACTION_MATCHED", row["reason_codes"])
        self.assertFalse(result["decision"]["phase3_exit_eligible"])
        self.assertIsNone(result["quantitative_metrics"])

    def test_different_worker_in_operator_deployment_refuses(self):
        with self.assertRaisesRegex(ValueError, "deployment"):
            self.replay(bindings=self.bindings | {"worker": self.f.document("other worker")})

    def test_mismatched_original_install_transaction_refuses(self):
        owner = json.loads(self.f.archive.read(self.pins["owner_pin"]))
        pin = self.f.put(canonical_json(owner | {"transaction_digest": canonical_digest("foreign transaction")}) + b"\n")
        with self.assertRaisesRegex(ValueError, "TRANSACTION"):
            self.replay(changes={"owner_pin": pin})

    def test_no_self_reported_verdict_or_verifier_substitution(self):
        with self.assertRaisesRegex(ValueError, "nomination"):
            self.replay(changes={"status": "PASS"})
        with self.assertRaisesRegex(ValueError, "verifier"):
            self.replay(extra={REQ: object()})
        with self.assertRaisesRegex(ValueError, "source"):
            self.replay(source=canonical_digest("unreviewed verifier"))
