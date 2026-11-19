"""Inspect the one real retained stage, never rebuild it or execute an ARM64 ELF."""
import json
import unittest

from scripts import build_pi_core_host_clients as build
from scripts import inspect_pi_core_host_clients as inspector
from scripts import prepare_pi_core_host_build_tools as tools
from scripts.build_pi_core_linux import regular_bytes


class StagedUbuntuClients(unittest.TestCase):
    def test_three_real_elfs_and_their_ubuntu_providers(self):
        expected = json.loads(regular_bytes(build.PACK / "clients.json", 8192))
        attempt = build.WORK / expected["fingerprint"]
        bindings = json.loads(regular_bytes(attempt / "inputs.json", 1 << 20))
        host = tools.verify_existing()
        self.assertEqual(bindings["tool_manifest"], host["manifest_sha256"])
        self.assertEqual(bindings["tool_tree"], host["sealed_sha256"])
        self.assertEqual(bindings["host_helper_inputs"], host["bpf_input"])
        self.assertEqual(bindings["host_helper_runner"], host["runner_sha256"])
        certificate = inspector.verify_attempt(attempt, expected)
        for name in inspector.CLIENTS:
            requester = "/usr/bin/" + name
            self.assertTrue(any(edge["requester"] == requester and edge["provider_soname"] == "libc.so.6"
                                and edge["versioned_symbol_count"] > 0 for edge in certificate["versioned_edges"]))
        self.assertIs(certificate["target_executed"], False)
        self.assertIs(certificate["phase3_exit_eligible"], False)
        print(json.dumps(certificate, sort_keys=True, separators=(",", ":")), flush=True)
