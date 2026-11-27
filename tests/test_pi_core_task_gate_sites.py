"""Original artifact bytes are required; no rebuilding, execution, or guest access."""
from functools import cache
import json
from pathlib import Path
from unittest import TestCase

from scripts import verify_pi_core_task_gate_sites as sites


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "packaging/pi-core/task-worker-v1/gate-stop-sites.json"
BUILD = CATALOG.with_name("build.json")
RETAINED = Path.home() / "Library/Application Support/Aragorn-Task-Guest-v1-Offline/root/var/lib/aragorn/pi-task-runtime/observer/source-gate"


@cache
def gate_bytes():
    return sites.elf.regular_bytes(RETAINED, limit=4176)


class GateSiteTests(TestCase):
    def test_exact_packaged_gate_has_two_distinct_post_svc_pcs_on_either_side_of_fixed_view(self):
        from aragorn import pi_core_task_gate_stop_reader as reader
        catalog = json.loads(CATALOG.read_bytes())
        gate = gate_bytes()
        self.assertEqual(sites.verify_gate_sites(gate, catalog), catalog)
        self.assertEqual(json.loads(BUILD.read_bytes())["outputs"]["source-gate"],
                         {"bytes":len(gate), "sha256":catalog["gate_sha256"]})
        self.assertEqual(reader.POST_SVC_PC, {"first":catalog["first_return_pc"],"final":catalog["final_return_pc"]})
        seg = catalog["rx_segment"]
        self.assertEqual((reader.RX_OFFSET,reader.RX_VADDR,reader.RX_SIZE),(seg["offset"],seg["vaddr"],seg["size"]))
        self.assertLess(catalog["first_return_pc"],catalog["fixed_view_call_pc"])
        self.assertLess(catalog["fixed_view_call_pc"],catalog["final_return_pc"])
        self.assertLess(catalog["final_return_pc"],catalog["execve_svc_pc"])

    def test_nonrelease_bytes_cannot_describe_a_gate_site(self):
        catalog = json.loads(CATALOG.read_bytes())
        with self.assertRaisesRegex(ValueError,"gate bytes"):
            sites.verify_gate_sites(bytes(4176),catalog)

    def test_exchanged_sites_or_wrong_fixed_view_target_refuse(self):
        catalog = json.loads(CATALOG.read_bytes())
        raw = gate_bytes()
        for change in (dict(first_return_pc=catalog["final_return_pc"],final_return_pc=catalog["first_return_pc"]),
                       dict(first_return_pc=catalog["first_return_pc"]-4),dict(fixed_view_entry=catalog["execve_svc_pc"])):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError,"site catalog"):
                sites.verify_gate_sites(raw,catalog | change)
