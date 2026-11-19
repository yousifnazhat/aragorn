"""Negative host-codegen trust-boundary checks; never run Blink, BPF or a target."""
import gzip
import json
import unittest

from scripts import prepare_pi_core_host_bpf_inputs as bpf
from scripts.build_pi_core_linux import BuildError, regular_bytes


class AlpineCodegenInputs(unittest.TestCase):
    def test_authentic_alpine_index_signature_rejects_substituted_index(self):
        lock = json.loads(regular_bytes(bpf.LOCK))
        actual = regular_bytes(bpf.WORK / "main.index.gz", 8 << 20)
        signed, _ = bpf.members(actual, 2)
        # Preserve the exact official signature, replace only what that signature covers.
        forged = signed[0] + gzip.compress(b"substituted compressed APKINDEX")
        with self.assertRaisesRegex(BuildError, "RSA signature rejected"):
            bpf.authenticated(forged, bpf.WORK / lock["key"], 2)

    def test_unaccounted_gzip_member_is_rejected_before_interpreting_data(self):
        member = gzip.compress(b"index fragment")
        with self.assertRaisesRegex(BuildError, "too many Alpine gzip members"):
            bpf.members(member * 3, 2)
