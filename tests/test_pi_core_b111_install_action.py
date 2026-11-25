"""Real B111 report encoder and inert install/action records; no install or worker."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import verify_pi_core_b111_install_action as subject
from tests import test_pi_core_install_action_join as prior


ROOT = Path(__file__).resolve().parents[1]


class B111InstallActionTests(TestCase):
    @classmethod
    def setUpClass(cls):
        join = prior.InstallActionJoinTests
        cls.addClassCleanup(join.doClassCleanups)
        cls.profile = json.loads((ROOT / "tests/fixtures/pi_core/b111-coordinator-host.json").read_bytes())
        signed = json.loads((ROOT / "packaging/pi-core/managed-payload-b111.json").read_bytes())
        cls.host_pin = "sha256:" + signed["host_profile_sha256"]
        if canonical_digest(cls.profile) != cls.host_pin:
            raise AssertionError("wrong B111 profile fixture")
        rows = {r["path"]: r["digest"] for r in cls.profile["files"]}
        wrapper = prior.install.materialization.SOURCE
        if "sha256:" + sha256(wrapper.read_bytes()).hexdigest() != rows[cls.profile["wrapper_path"]]:
            raise AssertionError("wrong B111 report encoder")

        def b111_host(nomination):
            f = nomination.f
            # Keep the real pinned inventory; this fixture does not claim live source custody.
            host = f.host | dict(host_profile_digest=f.document(cls.profile), files=len(rows),
                                 python_executable=cls.profile["python_executable"])
            sources = [dict(r, digest=rows["/" + r["path"]]) for r in f.snap]
            path = "opt/aragorn/src/aragorn/pi_core_bundle_launch.py"
            sources.append(dict(module="aragorn.pi_core_bundle_launch", path=path, digest=rows["/" + path]))
            return host, sources

        action = prior.action.PilotActionReplay
        broker = prior.action.actions.NativeActionEvidenceTests
        original, issue = action.original, broker.set_receipt
        def record_receipt(fixture, outcome):
            issue(fixture, outcome)
            # Independent test input: broker's original control bytes, before any nomination is formed.
            cls.receipt = "sha256:" + sha256(fixture.files["profile-receipt.json"]).hexdigest()

        def original_actions(fixture):
            original(fixture, "effective")
            cls.blocked_action, cls.blocked_receipt = fixture.put(canonical_json(fixture.nomination())), cls.receipt
            original(fixture, "created")

        with patch.object(prior.install.InstallAdmissionReplay, "managed_host", b111_host), \
                patch.object(broker, "set_receipt", record_receipt), patch.object(action, "original", original_actions):
            join.setUpClass()
        cls.f, cls.pins, cls.action = join.f, join.pins, join.action

    def verify(self, **changes):
        return subject.verify_b111_install_action_join(self.f.archive,
            **(self.pins | {"expected_action_receipt_pin": self.receipt} | changes))

    def owner_document(self):
        return json.loads(self.f.archive.read(self.pins["owner_pin"], max_bytes=270336))

    def put_owner(self, row):
        return self.f.put(canonical_json(row) + b"\n")

    def test_matching_originals_only_prove_recorded_correspondence(self):
        finding = self.verify()
        self.assertEqual(finding["status"], "CONSISTENT_RECORDED_B111_INSTALL_AND_ACTION")
        self.assertEqual(finding["host_profile_digest"], self.host_pin)
        self.assertEqual(finding["install_owner_digest"], self.pins["owner_pin"])
        self.assertEqual(finding["action_nomination_digest"], self.pins["action_nomination_pin"])
        self.assertEqual(finding["action_receipt_digest"], self.receipt)
        for key in ("worker_consumption_verified", "continuous_filesystem_custody_verified", "effect_verified",
                    "acquisition_authenticity_verified", "activation_authorized", "phase3_exit_eligible"):
            self.assertIs(finding[key], False)

    def test_other_wrapper_refuses_even_if_owner_and_plan_agree(self):
        profile = deepcopy(self.profile)
        next(row for row in profile["files"] if row["path"] == profile["wrapper_path"])["digest"] = canonical_digest("other wrapper")
        wrong = self.f.document(profile)
        plan = json.loads(self.f.archive.read(self.pins["plan_pin"]))
        plan_pin = self.f.document(plan | {"host_profile_digest": wrong})
        owner = self.owner_document()
        host = owner["host_before"] | {"host_profile_digest": wrong}
        owner_pin = self.put_owner(owner | dict(host_before=host, host_after=host, plan_digest=plan_pin))
        with self.assertRaises(ValueError):
            self.verify(plan_pin=plan_pin, owner_pin=owner_pin)

    def test_substituted_context_refuses_even_with_resealed_install_transaction(self):
        context = json.loads(self.f.archive.read(self.pins["context_pin"]))
        alternate = self.f.document(context | {"expires_at_unix": context["expires_at_unix"] + 1})
        plan = json.loads(self.f.archive.read(self.pins["plan_pin"]))
        plan_pin = self.f.document(plan | {"context": plan["context"] | {"digest": alternate}})
        transaction = prior.InstallActionJoinTests.transaction | {"context_digest": alternate}
        owner_pin = self.put_owner(self.owner_document() | dict(plan_digest=plan_pin, context_digest=alternate,
                                   transaction_digest=canonical_digest(transaction)))
        with self.assertRaises(ValueError):
            self.verify(context_pin=alternate, plan_pin=plan_pin, owner_pin=owner_pin)

    def test_different_terminal_on_same_install_requires_its_own_receipt(self):
        self.assertNotEqual(self.blocked_receipt, self.receipt)
        other = self.verify(action_nomination_pin=self.blocked_action, expected_action_receipt_pin=self.blocked_receipt)
        self.assertEqual(other["action_receipt_digest"], self.blocked_receipt)
        with self.assertRaises(ValueError):
            self.verify(action_nomination_pin=self.blocked_action)
        with self.assertRaises(ValueError):
            self.verify(expected_action_receipt_pin=self.blocked_receipt)

    def test_self_consistent_action_with_same_receipt_cannot_substitute_the_install_root(self):
        a = self.action
        with patch.object(a, "records", deepcopy(a.records)):
            dict(a.records)["REQUEST_CONTEXT"]["lineage"]["root_inode"] += 1
            wrong = self.f.document(a.nomination())
        replay = prior.action.cli.replay(self.f.archive, wrong, expected_deployment_digest=self.pins["deployment_pin"])
        self.assertEqual(replay["receipt_digest"], self.receipt)
        with self.assertRaises(ValueError):
            self.verify(action_nomination_pin=wrong)

    def test_substituted_transaction_refuses_even_when_context_and_tree_match(self):
        transaction = prior.InstallActionJoinTests.transaction
        foreign = transaction | {"destination": transaction["destination"] | {"root_inode": 78}}
        owner_pin = self.put_owner(self.owner_document() | {"transaction_digest": canonical_digest(foreign)})
        with self.assertRaises(ValueError):
            self.verify(owner_pin=owner_pin)
