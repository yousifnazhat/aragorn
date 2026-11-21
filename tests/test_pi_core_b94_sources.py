"""Check only the B75 → B93 trusted-source projection. Never import or run projected code."""
from hashlib import sha256
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from scripts import prepare_pi_core_b69_sources as reader
from scripts import prepare_pi_core_b94_sources as successor


ROOT = Path.home() / "Library/Application Support"
HOST = "etc/aragorn/coordinator-host.json"
MANIFEST = "etc/aragorn/service-runtime-inputs/manifest.json"
BINDING = "etc/aragorn/service-runtime-inputs/runtime-binding.json"
PREFIX = "opt/aragorn/src/aragorn/"
OBSERVER = PREFIX + "pi_core_node_source_observer.py"
PINS = {
    HOST: "33e26ff2934733f75614d379a810f188d4b9b01f16c9f7e036368b7623ba7d7c",
    MANIFEST: "7e74b1096e2b1f4faeba4c6b4db76b11dc6e90421a5c96c593d2faa6e786d55f",
    BINDING: "e552608746e862534e64071ce68baefbd24f6612c3bea041cde44b188a3ddb45",
}


class B94SignedSources(TestCase):
    def retained(self, batch, name, digest):
        raw = (ROOT / ("Aragorn-" + batch + "-Offline") / "root" / name).read_bytes()
        self.assertEqual(sha256(raw).hexdigest(), digest, name)
        return raw

    def test_b93_storage_and_stopped_socket_dependencies_ship_only_as_trusted_sources(self):
        originals = successor.original_inventories()
        self.assertEqual([sha256(raw).hexdigest() for raw in originals], [PINS[n] for n in (HOST, MANIFEST, BINDING)])
        host, service, meta = successor.prepare(*originals)
        self.assertEqual(meta["source_revision"], "0aa14e486199b33b84e03bf62ae46c6ca790feaf")
        old = json.loads(originals[2])["source_digests"]
        self.assertEqual(old[OBSERVER], "sha256:7eca9a6c0457089c32b3d2bf80a8809db0c820c4cb64cafc2118d64729be8c02")
        for name, digest in {
            "node_source_observer": "82851dcea5299a9455574694ee00f62a2e2d1647744a80fdafb7524ac6736dcd",
            "owned_socket_directories": "b1dc4e8cbe8b63d1f6ec367960f9123aa18506bf1751761a74b56c9162581061",
            "sensor_state_observer": "bfe24f25a1756afe01077d251b7204a13070b441c321b3e7736e2d16dafe6bb0",
            "state_backing_leaf": "78cd227fa50a6e21b8003f70cbc79202e2dcedf39dcb69cbbea2e1e0ca3dfb2c",
            "state_dm_mapping": "87c662913f488161537378b112c5ca8a53fe8a6ade9257be7a4b15c6d0c7e202",
            "state_luks_headers": "804147d2de617cbca3f810e694bda021212e8de671976ebb2d5823643371461a",
        }.items():
            path = PREFIX + "pi_core_" + name + ".py"
            self.assertEqual(host["/" + path], service[path], name)
            self.assertEqual(sha256(service[path]).hexdigest(), digest, name)
        for name in ("native_supervisor", "native_request", "native_provider", "stopped_mask_view", "state_admission"):
            path = PREFIX + "pi_core_" + name + ".py"
            self.assertEqual(host["/" + path], service[path])

        # No Node, gate, filesystem archive, unit or launch plan is projected.
        wrappers = {"opt/aragorn/bin/" + role + ".py" for role in ("action", "provider", "sensor")}
        self.assertEqual({p for p in host if not p.startswith("/" + PREFIX)}, {"/opt/aragorn/bin/coordinator.py"})
        self.assertEqual({p for p in service if not p.startswith(PREFIX)}, wrappers)
        self.assertTrue(all(p.endswith(".py") for p in (*host, *service)))
        for module in ("pi_core_action_index_verify", "pi_core_action_terminal_verify", "pi_core_phase3_qualification",
                       "phase3_measurement_replay"):
            self.assertNotIn(PREFIX + module + ".py", service)
            self.assertNotIn("/" + PREFIX + module + ".py", host)
        # One exclusive publication of deployment inventories, not an installed or bootable payload.
        pins = successor.retain_inventories(*originals, host, service)
        self.assertEqual(set(pins), {"coordinator-host.json", "manifest.json", "runtime-binding.json",
                                     "service-runtime-receipt.json"})

    def test_real_b69_binding_cannot_replace_b75_binding_for_b93(self):
        host, manifest = (self.retained("B75", name, PINS[name]) for name in (HOST, MANIFEST))
        foreign = self.retained("B69", BINDING, "242d3aa1eda96eec5bc88f2107a019305ce5a4765318b78c344748905cace610")
        with patch.object(reader, "_git", side_effect=AssertionError("mixed predecessors must refuse before Git")):
            with self.assertRaisesRegex(ValueError, "predecessor"):
                successor.prepare(host, manifest, foreign)
