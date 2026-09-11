from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

from aragorn import admission_openclaw_final_v3_config_entry_subfixture as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest

_ROOT = Path(__file__).resolve().parents[1]
_verify = subject.verify_openclaw_final_v3_config_entry_semantic_compatibility


def _document():
    return json.loads((_ROOT / subject.old._EVIDENCE["path"]).read_bytes())[
        "route_observation"
    ]["document"]


def _refresh_commands(document):
    action = document["action"]
    before, after = action["prerequisites"], action["observations"]
    for value in [*before.values(), *after.values()]:
        if isinstance(value, dict) and "command" in value and "response" in value:
            raw = (json.dumps(value["response"]["value"]) + "\n").encode()
            value["command"].update(
                stdout_excerpt=raw.decode(),
                stdout_bytes=len(raw),
                stdout_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
            )
    action["commands"] = deepcopy(
        [
            before["version"],
            before["system_info_before"]["command"],
            before["discovery_before"]["command"],
            after["update"]["command"],
            after["discovery_after"]["command"],
            after["system_info_after"]["command"],
        ]
    )


def _fresh_document():
    """Synthetic identity variation tests compatibility, not actual freshness."""
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
    document["run_nonce"] = "b" * 32
    action = document["action"]
    for side, suffix in (
        (action["prerequisites"], "before"),
        (action["observations"], "after"),
    ):
        gateway = side[f"gateway_process_{suffix}"]
        gateway.update(pid=12345, hostname="abcdef123456", start_time_ticks="987654321")
        side[f"boundary_{suffix}"]["probe"]["records"][0]["root"] = (
            "/docker/volumes/aragorn-fresh-config-fixture/_data"
        )
        side[f"system_info_{suffix}"]["response"]["value"].update(
            pid=gateway["pid"],
            hostname=gateway["hostname"],
            machineName=gateway["hostname"],
            release="6.8.0-fixture-refresh",
            osLabel="Linux 6.8.0-fixture-refresh",
            memoryTotalBytes=32_000_000_000,
            diskTotalBytes=64_000_000_000,
            cpuCount=2,
            loadAverage=[0, 0.5, 1],
        )
    _refresh_commands(document)
    return document


class ConfigEntrySemanticTests(unittest.TestCase):
    def test_retained_and_coherent_fresh_input_never_confer_authority(self):
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
                "CONFIG_ENTRY_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
            )
            self.assertTrue(
                all(
                    value is False
                    for key, value in result["decision"].items()
                    if key != "status"
                )
            )
            self.assertFalse(result["route_semantics"]["pass_authority"])

    def test_document_identity_and_shapes_are_exact(self):
        for mutate in (
            lambda d: d.update(run_nonce="invalid"),
            lambda d: d.update(implementation_digest="sha256:" + "0" * 64),
            lambda d: d.update(phase3_exit_eligible=True),
            lambda d: d["route"].update(status="PASS"),
            lambda d: d["runtime_binding"].update(version="2026.7.2"),
            lambda d: d["action"]["observations"]["update"].update(extra=None),
            lambda d: d["action"]["observations"]["gateway_process_after"].update(
                start_time_ticks="123"
            ),
        ):
            document = _fresh_document()
            mutate(document)
            with self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_coherent_boundary_mutations_fail_after_refresh(self):
        for mutate in (
            lambda b: b["boundary_before"]["probe"]["records"][0].update(
                root="/arbitrary/path"
            ),
            lambda b: b["boundary_before"]["runtime"]["records"][0][
                "mount_options"
            ].append("rw"),
            lambda b: b["boundary_before"]["configuration"]["file"].update(
                digest="sha256:" + "0" * 64
            ),
            lambda b: b["boundary_before"]["roots"]["workspace_skills"][
                "observation"
            ].update(uid=0),
            lambda b: b["gateway_process_before"].update(
                effective_capabilities="0000000000000001"
            ),
            lambda b: b["target_before"]["entries"][0].update(
                digest="sha256:" + "0" * 64
            ),
            lambda b: b["target_before"]["entries"][0].update(nlink=2),
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
            before["target_before"]["tree_digest"] = canonical_digest(
                before["target_before"]["entries"]
            )
            for name in subject._STABLE:
                after[f"{name}_after"] = deepcopy(before[f"{name}_before"])
            with self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_command_alias_and_causality_mutations_fail(self):
        for mutate in (
            lambda b, a: b["version"].update(pid=True),
            lambda b, a: b["version"].update(pid=b["gateway_process_before"]["pid"]),
            lambda b, a: a["update"]["command"].update(pid=b["version"]["pid"]),
            lambda b, a: b["version"].update(
                completed_at=a["system_info_after"]["command"]["completed_at"]
            ),
            lambda b, a: a["update"]["command"].update(argv=["unexpected"]),
            lambda b, a: a["update"]["command"].update(exit_code=0),
            lambda b, a: a["update"]["command"].update(stderr_bytes=1),
        ):
            document = _fresh_document()
            mutate(
                document["action"]["prerequisites"], document["action"]["observations"]
            )
            _refresh_commands(document)
            with self.assertRaises(AdmissionEvidenceError):
                _verify(document)
        document = _fresh_document()
        document["action"]["commands"][0]["pid"] += 1
        with self.assertRaises(AdmissionEvidenceError):
            _verify(document)

    def test_response_and_params_mutations_fail_with_consistent_output(self):
        for mutate in (
            lambda a: a["update"]["params"].update(enabled=False),
            lambda a: a["update"]["params"].update(enabled=1),
            lambda a: a["update"]["params"].update(skillKey="another-skill"),
            lambda a: a["update"]["response"]["value"].update(ok=True),
            lambda a: a["update"]["response"]["value"]["error"].update(code="OTHER"),
            lambda a: a["discovery_after"]["response"]["value"].update(eligible=False),
            lambda a: a["system_info_after"]["response"].update(extra=0),
        ):
            document = _fresh_document()
            mutate(document["action"]["observations"])
            _refresh_commands(document)
            with self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_runtime_facts_and_typed_telemetry_are_enforced(self):
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
