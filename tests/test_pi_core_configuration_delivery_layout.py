"""Late delivery as bytes only; no clock, grant issuance, guest installation or service."""
import hashlib
import json
from pathlib import Path
import unittest

from aragorn import pi_core_restricted_profile as fixed
from aragorn import pi_core_service_configuration as config
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import pi_core_configuration_delivery_layout as delivery
from tests.test_pi_core_service_configuration import configurations


def fixture_configurations(**profile_changes):
    roles = configurations()
    profile = roles["sensor"]["observation_binding"]["runtime_profile"]
    context_id = "b" * 64
    manifest_hex = roles["action"]["capability_grant"]["source_manifest_digest"].removeprefix("sha256:")
    version = f"{context_id}-{manifest_hex}"
    profile.update({"executable_digest": "sha256:" + fixed.NODE_SHA256, "runtime_digest": fixed.RUNTIME_DIGEST,
                    "skill_path": "/var/lib/aragorn/admitted/.aragorn-versions/example/" + version + "/SKILL.md",
                    "cgroup": "/system.slice/aragorn-pi-" + "1" * 32 + ".service"} | profile_changes)
    digest = canonical_digest(profile)
    for role in ("action", "sensor"):
        roles[role]["capability_grant"].update(runtime_profile_digest=digest, runtime_digest=profile["runtime_digest"])
    roles["action"]["runtime_binding"].update(runtime_profile_digest=digest, runtime_digest=profile["runtime_digest"])
    return roles


class DeliveryLayout(unittest.TestCase):
    def deliver(self, roles, now=100):
        return delivery.layout(canonical_json(roles), canonical_digest(roles), now)

    def test_existing_holder_inputs_receipt_modes_and_absolute_plan_section(self):
        roles = fixture_configurations()
        members, section = self.deliver(roles)
        root = Path("/run/aragorn-pi-config")
        self.assertEqual(set(section), {"deployment_path", "receipt_digest", "manifest", "configurations"})
        self.assertEqual(Path(section["deployment_path"]), root / "installed")
        for field in ("manifest", "configurations"):
            local = f"inputs/{field}.json"
            mode, raw = members[local]
            self.assertEqual(mode, 0o400)
            self.assertEqual(raw, canonical_json(json.loads(raw)))
            self.assertEqual(section[field], {"path": str(root / local), "digest": canonical_digest(json.loads(raw))})
        self.assertEqual(members["inputs/configurations.json"][1], canonical_json(roles))
        manifest = json.loads(members["inputs/manifest.json"][1])
        pinned, parsed = config._inputs(manifest, section["manifest"]["digest"], roles, section["configurations"]["digest"])
        expected = {"inputs/manifest.json", "inputs/configurations.json"}
        for name, mode in {"/": 0o700, "inputs": 0o700, "installed": 0o755, "installed/root": 0o755}.items():
            self.assertEqual(members[name], (mode, None))
            expected.add(name)
        for name in pinned["directories"]:
            local = "installed/root/" + name
            self.assertEqual(members[local], (0o555, None))
            expected.add(local)
        for role, name in config.PATHS.items():
            local = "installed/root/" + name
            self.assertEqual(members[local], (0o444, canonical_json(parsed[role])))
            expected.add(local)
        receipt = config._receipt(root / "installed/root", section["manifest"]["digest"], parsed, section["configurations"]["digest"])
        local = "installed/" + config.RECEIPT
        self.assertEqual(members[local], (0o444, canonical_json(receipt)))
        self.assertEqual(section["receipt_digest"], canonical_digest(receipt))
        self.assertFalse(receipt["service_ready"] or receipt["current_grant_authority"] or receipt["phase3_exit_eligible"])
        self.assertEqual(set(members), expected | {local})

    def test_rejects_independent_pin_mismatch_and_noncanonical_input(self):
        roles = fixture_configurations()
        raw, pin = canonical_json(roles), canonical_digest(roles)
        noncanonical = raw + b"\n"
        for data, expected in ((raw, "sha256:" + "e" * 64),
                               (noncanonical, "sha256:" + hashlib.sha256(noncanonical).hexdigest())):
            with self.subTest(data_size=len(data)), self.assertRaises((ValueError, RuntimeError)):
                delivery.layout(data, expected, 100)

    def test_valid_time_and_both_ends_of_shared_single_use_window(self):
        roles = fixture_configurations()
        grant = roles["action"]["capability_grant"]
        start, end = grant["issued_at_unix"], grant["expires_at_unix"]
        self.deliver(roles, start)
        self.deliver(roles, end - 1)
        for instant in (start - 1, end, True):
            with self.subTest(instant=instant), self.assertRaises((ValueError, RuntimeError)):
                self.deliver(roles, instant)

    def test_rejects_different_worker_identity_or_source_even_with_resealed_grants(self):
        path = Path(fixture_configurations()["sensor"]["observation_binding"]["runtime_profile"]["skill_path"])
        context_id, _ = path.parent.name.split("-")
        wrong_manifest = path.parent.parent / (context_id + "-" + "e" * 64) / path.name
        for changed in ({"executable_digest": "sha256:" + "e" * 64}, {"cgroup": "/system.slice/other.service"},
                        {"runtime_digest": "sha256:" + "f" * 64},
                        {"skill_path": str(wrong_manifest)},
                        {"skill_path": "/var/lib/aragorn/admitted/.aragorn-versions/example/unbound/SKILL.md"}):
            with self.subTest(changed=changed), self.assertRaises((ValueError, RuntimeError)):
                self.deliver(fixture_configurations(**changed))

    def test_role_substitution_or_credential_fields_cannot_enter_public_layout(self):
        roles = fixture_configurations()
        roles["sensor"]["capability_grant"]["grant_id"] = "c" * 64
        with self.assertRaises((RuntimeError, ValueError)):
            self.deliver(roles)
        roles = fixture_configurations()
        roles["provider"]["api_key"] = "inert-forbidden-field"
        with self.assertRaises((RuntimeError, ValueError)):
            self.deliver(roles)
