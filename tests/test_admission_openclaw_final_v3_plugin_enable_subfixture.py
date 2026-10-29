from __future__ import annotations

import json
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

from aragorn import admission_openclaw_final_v3_plugin_enable_subfixture as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest

_ROOT = Path(__file__).resolve().parents[1]
_verify = subject.verify_openclaw_final_v3_plugin_enable_semantic_compatibility


def _document():
    return json.loads((_ROOT / subject.old._EVIDENCE["path"]).read_bytes())[
        "route_observation"
    ]["document"]


def _refresh_commands(document):
    before, after = (
        document["action"]["prerequisites"],
        document["action"]["observations"],
    )
    for side, suffix in ((before, "before"), (after, "after")):
        value = side[f"system_info_{suffix}"]
        raw = (json.dumps(value["response"]["value"]) + "\n").encode()
        value["command"].update(
            stdout_excerpt=raw.decode(),
            stdout_bytes=len(raw),
            stdout_digest=subject.old._digest(raw),
        )
    document["action"]["commands"] = deepcopy(
        [
            before["version"],
            before["system_info_before"]["command"],
            before["plugin_before"]["command"],
            after["native_enable"]["command"],
            after["plugin_after"]["command"],
            after["system_info_after"]["command"],
        ]
    )


def _fresh_document():
    """Synthetic freshness changes compatibility only; this is not a capture."""
    document = _document()
    pids = {
        command["pid"]: 20000 + index
        for index, command in enumerate(document["action"]["commands"])
    }

    def shift(value):
        if isinstance(value, dict):
            for key, item in value.items():
                value[key] = shift(item)
            if "argv" in value:
                value["pid"] = pids[value["pid"]]
            if value.get("type") in ("file", "directory"):
                value["device"] += 1000
                value["inode"] += 1000
            if "root" in value and "tree_digest" in value:
                value["tree_digest"] = canonical_digest(value["entries"])
        elif isinstance(value, list):
            return [shift(item) for item in value]
        elif isinstance(value, str) and value.startswith("2026-08-28T"):
            return (
                (datetime.fromisoformat(value) + timedelta(days=14))
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )
        return value

    document = shift(document)
    document["run_nonce"] = "c" * 32
    action = document["action"]
    for side, suffix in (
        (action["prerequisites"], "before"),
        (action["observations"], "after"),
    ):
        side[f"gateway_process_{suffix}"].update(
            pid=12345, hostname="abcdef123456", start_time_ticks="987654321"
        )
        side[f"boundary_{suffix}"]["route_input"]["records"][0]["root"] = (
            "/docker/volumes/aragorn-fresh-plugin-fixture/_data"
        )
        side[f"system_info_{suffix}"]["response"]["value"].update(
            pid=12345,
            hostname="abcdef123456",
            machineName="abcdef123456",
            release="6.8.0-fixture-refresh",
            osLabel="Linux 6.8.0-fixture-refresh",
            memoryTotalBytes=32_000_000_000,
            diskTotalBytes=64_000_000_000,
            cpuCount=2,
            loadAverage=[0, 0.5, 1],
        )
    _refresh_commands(document)
    return document


class PluginEnableSemanticTests(unittest.TestCase):
    def test_retained_and_fresh_compatible_input_confer_no_authority(self):
        for document in (_document(), _fresh_document()):
            unchanged = deepcopy(document)
            result = _verify(document)
            self.assertEqual(document, unchanged)
            self.assertEqual(
                result["bindings"]["input_document_canonical_digest"],
                canonical_digest(document),
            )
            self.assertEqual(
                result["decision"]["status"],
                "PLUGIN_ENABLE_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
            )
            self.assertTrue(
                all(
                    value is False
                    for key, value in result["decision"].items()
                    if key != "status"
                )
            )
            self.assertFalse(result["route_semantics"]["pass_authority"])

    def test_document_identity_and_trust_shapes_are_exact(self):
        for mutate in (
            lambda d: d.update(run_nonce="invalid"),
            lambda d: d.update(implementation_digest="sha256:" + "0" * 64),
            lambda d: d.update(phase3_exit_eligible=True),
            lambda d: d["route"].update(status="PASS"),
            lambda d: d["runtime_binding"].update(version="2026.7.2"),
            lambda d: d["action"]["observations"]["native_enable"].update(extra=None),
            lambda d: d["action"]["observations"]["gateway_process_after"].update(
                start_time_ticks="123"
            ),
        ):
            document = _fresh_document()
            mutate(document)
            with self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_coherent_boundary_and_content_mutations_fail(self):
        for mutate in (
            lambda b: b["boundary_before"]["route_input"]["records"][0].update(
                root="/arbitrary/path"
            ),
            lambda b: b["boundary_before"]["runtime"]["records"][0][
                "mount_options"
            ].append("rw"),
            lambda b: b["boundary_before"]["configuration"]["file"].update(
                digest="sha256:" + "0" * 64
            ),
            lambda b: b["boundary_before"]["configuration"]["plugin_policy"].update(
                target_allowlisted=0
            ),
            lambda b: b["boundary_before"]["workspace"].update(writable=False),
            lambda b: b["config_lock_before"].update(exists=0),
            lambda b: b["gateway_process_before"].update(
                effective_capabilities="0000000000000001"
            ),
            lambda b: b["plugin_tree_before"]["entries"][0].update(
                digest="sha256:" + "0" * 64
            ),
            lambda b: b["plugin_tree_before"]["entries"][0].update(nlink=2),
            lambda b: b["plugin_tree_before"]["root"].update(mode="777"),
            lambda b: b["openclaw_before"].update(extra=0),
        ):
            document = _fresh_document()
            before, after = (
                document["action"]["prerequisites"],
                document["action"]["observations"],
            )
            mutate(before)
            before["config_before"] = deepcopy(
                before["boundary_before"]["configuration"]
            )
            before["plugin_tree_before"]["tree_digest"] = canonical_digest(
                before["plugin_tree_before"]["entries"]
            )
            for name in subject._STABLE:
                after[f"{name}_after"] = deepcopy(before[f"{name}_before"])
            with self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_native_denial_and_command_causality_remain_exact(self):
        for mutate in (
            lambda b, a: b["version"].update(pid=True),
            lambda b, a: b["version"].update(pid=b["gateway_process_before"]["pid"]),
            lambda b, a: a["native_enable"]["command"].update(pid=b["version"]["pid"]),
            lambda b, a: b["version"].update(
                completed_at=a["system_info_after"]["command"]["completed_at"]
            ),
            lambda b, a: a["native_enable"]["command"].update(argv=["unexpected"]),
            lambda b, a: a["native_enable"]["command"].update(exit_code=0),
            lambda b, a: a["native_enable"]["command"].update(stderr_bytes=1),
            lambda b, a: a["native_enable"].update(process_started=1),
            lambda b, a: a["native_enable"].update(target_plugin_id="another-plugin"),
        ):
            document = _fresh_document()
            mutate(
                document["action"]["prerequisites"], document["action"]["observations"]
            )
            _refresh_commands(document)
            with self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_truncated_inspection_excerpt_and_response_are_independently_bound(self):
        for mutate in (
            lambda v: v["response"]["value"]["plugin"].update(enabled=True),
            lambda v: v["response"]["value"]["plugin"].update(imported=True),
            lambda v: v["response"]["value"].update(capabilityCount=True),
            lambda v: v["response"].update(extra=0),
            lambda v: v["command"].update(stdout_digest="sha256:" + "0" * 64),
            lambda v: v["command"].update(
                stdout_excerpt=v["command"]["stdout_excerpt"].replace(
                    "disabled", "DISABLED", 1
                )
            ),
        ):
            document = _fresh_document()
            before, after = (
                document["action"]["prerequisites"],
                document["action"]["observations"],
            )
            mutate(before["plugin_before"])
            after["plugin_after"]["response"] = deepcopy(
                before["plugin_before"]["response"]
            )
            for key in ("stdout_digest", "stdout_excerpt"):
                after["plugin_after"]["command"][key] = before["plugin_before"][
                    "command"
                ][key]
            _refresh_commands(document)
            with self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_runtime_facts_and_numeric_telemetry_are_enforced(self):
        for key, value in (
            ("arch", "x64"),
            ("nodeVersion", "v99.0.0"),
            ("osLabel", "wrong kernel"),
            ("cpuCount", True),
            ("memoryFreeBytes", 2**53),
            ("uptimeMs", -1),
            ("loadAverage", [float("nan"), 0, 0]),
            ("loadAverage", [float("inf"), 0, 0]),
            ("loadAverage", [-1, 0, 0]),
            ("loadAverage", [True, 0, 0]),
        ):
            with self.subTest(key=key, value=value):
                document = _fresh_document()
                action = document["action"]
                for side, suffix in (
                    (action["prerequisites"], "before"),
                    (action["observations"], "after"),
                ):
                    side[f"system_info_{suffix}"]["response"]["value"][key] = value
                _refresh_commands(document)
                with self.assertRaises(AdmissionEvidenceError):
                    _verify(document)


if __name__ == "__main__":
    unittest.main()
