"""Offline public formatter only. Fixtures are not installed or consumed code."""
from copy import deepcopy
import unittest

from aragorn import pi_core_restricted_profile as fixed
import test_pi_core_inventory_dispatch as fixtures


class RestrictedPublicInventoryTests(unittest.TestCase):
    def setUp(self):
        previous = fixtures.InventoryDispatchTests()
        self.addCleanup(previous.doCleanups)
        previous.setUp()
        self.s = previous.s
        self.value = previous.prepared_observation()
        items = self.value["artifacts"]
        profile = items["profile"]
        profile.update(schema=fixed.PROFILE_SCHEMA)
        profile["pins"].update(gate_digest="sha256:" + fixed.GATE_SHA256,
                               node_digest="sha256:" + fixed.NODE_SHA256)
        profile["sources"][0]["digest"] = "sha256:" + fixed.BUNDLE_SHA256
        items["source_inventory"]["sources"][0].update(profile["sources"][0])
        for row in items["preparation"]["code"]:
            if row["path"] in {fixed.GATE_PATH, fixed.NODE_ARGV[0]}:
                row["digest"] = profile["pins"]["gate_digest" if row["path"] == fixed.GATE_PATH else "node_digest"]
        self.repin(self.value)

    def digest(self, value):
        return self.s._digest(self.s._canonical(value))

    def repin(self, value):
        items = value["artifacts"]
        profile, receipt = items["profile"], items["preparation"]
        for name in ("source_inventory", "loader_inventory"):
            receipt[name + "_digest"] = profile["pins"][name + "_digest"] = self.digest(items[name])
        receipt["profile_digest"] = self.digest(profile)
        source_plan = {**profile, "schema": fixed.PLAN_SCHEMA, "pins": {key: pin for key, pin in profile["pins"].items()
                       if key not in {"source_inventory_digest", "loader_inventory_digest"}}}
        receipt["expected_manifest_digest"] = self.digest(source_plan)
        value["artifact_digests"] = {name: self.digest(document) for name, document in items.items()}

    def test_fixed_public_contract_does_not_claim_launch_or_health(self):
        report = self.s._public_preparation(self.value)
        self.assertEqual(report["artifact_digests"], self.value["artifact_digests"])
        self.assertEqual(report["authority"], self.value["artifacts"]["preparation"]["authority"])
        self.assertFalse(report["phase3_exit_eligible"])
        self.assertIs(report["managed_call_attempted"], False)
        self.assertNotIn("raw_cmdline_hex", str(report))

    def test_legacy_label_with_rehashed_restricted_inventory_is_refused(self):
        self.value["artifacts"]["profile"]["schema"] = "aragorn/pi-core-node-source-profile/v1"
        self.repin(self.value)
        with self.assertRaisesRegex(ValueError, "profile version"):
            self.s._public_preparation(self.value)

    def test_rehashed_installed_source_and_code_must_match_restricted_profile(self):
        for selected in ("source", "code", "source_plan"):
            value = deepcopy(self.value)
            if selected == "source":
                value["artifacts"]["source_inventory"]["sources"][0]["digest"] = "sha256:" + "a"*64
            if selected == "code":
                value["artifacts"]["preparation"]["code"][0]["path"] += ".other"
            self.repin(value)
            if selected == "source_plan":
                receipt = value["artifacts"]["preparation"]
                receipt["expected_manifest_digest"] = "sha256:" + "b"*64
                value["artifact_digests"]["preparation"] = self.digest(receipt)
            with self.subTest(selected=selected), self.assertRaisesRegex(ValueError, "restricted"):
                self.s._public_preparation(value)

    def test_unknown_runtime_member_or_misclassified_entry_refused_even_when_rehashed(self):
        for mutation in ("foreign", "loader"):
            value = deepcopy(self.value)
            items = value["artifacts"]
            prof = items["profile"]
            row = dict(path=fixed.PREFIX + "pi-core/unknown.js", digest="sha256:" + "c"*64)
            field, artifact, rows = "sources", "source_inventory", "sources"
            if mutation == "loader":
                row = dict(prof["sources"][0])
                field, artifact, rows = "loader_files", "loader_inventory", "loaders"
            prof[field].append(row)
            items[artifact][rows].append({**items[artifact][rows][0], **row})
            items["preparation"]["source_files" if rows == "sources" else "loader_files"] += 1
            self.repin(value)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "source role"):
                self.s._public_preparation(value)
