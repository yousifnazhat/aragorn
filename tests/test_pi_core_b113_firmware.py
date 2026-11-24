"""Exercise only the new proposal/host-request joins. Never open a VM or store."""
import json
import struct
import unittest

from scripts import prepare_pi_core_b113_firmware as fw
from scripts.build_pi_core_linux import BuildError, regular_bytes, sha256


class B113FirmwareProposal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs = tuple(regular_bytes(p, 16384) for p in (
            fw.TEMPLATE, fw.MEDIA, fw.HERE / "boot-request.json", fw.HERE / "firmware-proposal.json"))

    def test_b112_request_joins_exact_retained_detached_candidate_without_store(self):
        proposal = fw.inspect()
        request = json.loads(self.inputs[2])
        self.assertTrue(all(v is None for v in request["private_bindings_required"].values()))
        self.assertTrue(all(v is False for v in request["authority_now"].values()))
        self.assertNotEqual(proposal["authenticode_sha256"], proposal["uki_sha256"])
        self.assertEqual(proposal["boot_request_sha256"], sha256(self.inputs[2]))
        self.assertIsNone(proposal["approved_policy_sha256"])

    def test_predecessor_and_substituted_catalog_refuse(self):
        template, media, request, proposal = self.inputs
        for cases in ((template, media, template, proposal), (template, media + b" ", request, proposal),
                      (request, media, request, proposal)):
            with self.subTest(), self.assertRaises(BuildError):
                fw.validate_public(*cases)

    def test_broader_trust_authority_and_store_substitutions_refuse(self):
        # Mutations affect the request or proposal, not a test-only flag outside the consumer.
        for n, path, value in (
                (2, ("guest", "disk_bytes"), 3542227456),
                (2, ("firmware", "raw_uki_sha256"), json.loads(self.inputs[1])["authenticode_sha256"]),
                (2, ("authority_now", "boot"), True),
                (2, ("private_bindings_required", "approved_kek_db_dbx_baseline_and_revocations"), "nominated"),
                (2, ("proposed_limits_after_separate_approvals", "automatic_retries"), 1),
                (3, ("db_allow_sha256",), ["0" * 64, "1" * 64]),
                (3, ("broad_default_allow_signatures",), True),
                (3, ("preserve_approved_revocations",), False),
                (3, ("approved_policy_sha256",), "0" * 64),
                (3, ("private_store_identity",), "nominated"),
                (3, ("enrollment_observed",), True)):
            data = list(self.inputs)
            obj = json.loads(data[n])
            node = obj
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
            data[n] = (json.dumps(obj, indent=2) + "\n").encode()
            with self.subTest(path=path), self.assertRaises(BuildError):
                fw.validate_public(*data)

    def test_esl_must_encode_the_proposed_hash_not_the_whole_file_or_another_owner(self):
        proposal = json.loads(self.inputs[3])
        for owner, image in ((fw.OWNER.bytes_le, proposal["uki_sha256"]),
                             (bytes(16), proposal["authenticode_sha256"])):
            record = struct.pack("<16sIII16s32s", fw.EFI_CERT_SHA256.bytes_le, 76, 0, 48, owner,
                                 bytes.fromhex(image))
            with self.subTest(owner=owner), self.assertRaises(BuildError):
                fw.validate_esl(dict(proposal, esl_sha256=sha256(record)), record)
