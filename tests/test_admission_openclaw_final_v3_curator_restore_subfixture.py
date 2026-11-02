from __future__ import annotations

import hashlib
import json
import re
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

from aragorn import admission_openclaw_final_v3_curator_restore_subfixture as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest

_ROOT = Path(__file__).resolve().parents[1]
_verify = subject.verify_openclaw_final_v3_curator_restore_semantic_compatibility


def _document():
    return json.loads((_ROOT / subject.old._EVIDENCE["path"]).read_bytes())[
        "route_observation"
    ]["document"]


def _refresh_commands(document):
    """Refresh successful system-info bytes only; denial bytes stay exact."""
    action = document["action"]
    before, after = action["prerequisites"], action["observations"]
    for value in (before["system_info_before"], after["system_info_after"]):
        raw = (
            json.dumps(value["response"]["value"], ensure_ascii=False) + "\n"
        ).encode()
        value["command"].update(
            stdout_excerpt=raw.decode(),
            stdout_bytes=len(raw),
            stdout_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        )
    action["commands"] = deepcopy(
        [
            before["version"],
            before["system_info_before"]["command"],
            before["curator_status_before_seed"]["command"],
            after["curator_status_before"]["command"],
            after["discovery_before"]["command"],
            after["gateway_restore"]["command"],
            after["invalid_token_gateway_control"]["command"],
            after["cli_fallback_restore"]["command"],
            after["curator_status_after"]["command"],
            after["discovery_after"]["command"],
            after["system_info_after"]["command"],
        ]
    )


def _fresh_document():
    """Coherent synthetic variation proves compatibility, never capture freshness."""
    document = _document()
    command_pids = {
        command["pid"]: 20000 + index
        for index, command in enumerate(document["action"]["commands"])
    }

    def shift(value):
        if type(value) is dict:
            for key, item in value.items():
                value[key] = shift(item)
            if "argv" in value:
                value["pid"] = command_pids[value["pid"]]
            if value.get("type") in ("file", "directory"):
                value["device"] += 1000
                value["inode"] += 1000
            if "root" in value and "tree_digest" in value:
                value["tree_digest"] = canonical_digest(value["entries"])
        elif type(value) is list:
            return [shift(item) for item in value]
        elif type(value) is str and re.fullmatch(r"2026-08-31T[0-9:.]+Z", value):
            return (
                (datetime.fromisoformat(value) + timedelta(days=1))
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )
        return value

    document = shift(document)
    document["run_nonce"] = "a" * 32
    before, after = (
        document["action"]["prerequisites"],
        document["action"]["observations"],
    )
    for side, suffix in ((before, "before"), (after, "after")):
        gateway = side[f"gateway_process_{suffix}"]
        gateway.update(pid=12345, hostname="abcdef123456", start_time_ticks="987654321")
        side[f"boundary_{suffix}"]["probe"]["records"][0]["root"] = (
            "/docker/volumes/aragorn-fresh-curator-fixture/_data"
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
    for index, name in enumerate(
        ("database_before", "database_after_gateway", "database_after_cli")
    ):
        after[name]["data_version"] = 7 + index * 3
    _refresh_commands(document)
    return document


class CuratorRestoreSemanticTests(unittest.TestCase):
    def test_retained_and_fresh_compatible_input_never_confer_authority(self):
        for document in (_document(), _fresh_document()):
            with self.subTest(nonce=document["run_nonce"]):
                unchanged = deepcopy(document)
                result = _verify(document)
                self.assertEqual(document, unchanged)
                self.assertEqual(
                    result["bindings"]["input_document_canonical_digest"],
                    canonical_digest(document),
                )
                self.assertEqual(
                    result["decision"]["status"],
                    "CURATOR_RESTORE_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
                )
                self.assertTrue(
                    all(
                        value is False
                        for key, value in result["decision"].items()
                        if key != "status"
                    )
                )
                self.assertFalse(result["route_semantics"]["pass_authority"])

    def test_contract_and_selected_row_mutations_are_rejected(self):
        mutations = (
            lambda d: d.update(run_nonce="not-a-nonce"),
            lambda d: d.update(admission_profile_eligible=True),
            lambda d: d["route"].update(status="PASS"),
            lambda d: d["implementation_digests"].update(probe="sha256:" + "0" * 64),
            lambda d: d["action"]["observations"]["database_after_cli"]["row"].update(
                state="active"
            ),
            lambda d: d["action"]["observations"]["database_after_cli"]["row"].update(
                pinned=False
            ),
            lambda d: d["action"]["observations"]["database_after_cli"].update(
                data_version=True
            ),
            lambda d: d["action"]["observations"]["database_after_cli"]["file"].update(
                inode=987654
            ),
            lambda d: d["action"]["observations"]["gateway_restore"]["response"][
                "value"
            ].update(ok=True),
            lambda d: d["action"]["observations"]["cli_fallback_restore"][
                "command"
            ].update(exit_code=0),
            lambda d: d["action"]["observations"]["gateway_process_after"].update(
                start_time_ticks="123"
            ),
            lambda d: d["action"]["observations"]["system_info_after"][
                "response"
            ].update(extra="untrusted"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                document = _fresh_document()
                mutate(document)
                with self.assertRaises(AdmissionEvidenceError):
                    _verify(document)

    def test_coherent_boundary_changes_cannot_bypass_validation(self):
        mutations = (
            lambda p: p["boundary_before"]["configuration"]["document"]["skills"][
                "workshop"
            ].update(restoreAuthority="local"),
            lambda p: p["boundary_before"]["probe"]["records"][0].update(
                root="/arbitrary/path"
            ),
            lambda p: p["boundary_before"]["runtime"]["records"][0][
                "mount_options"
            ].append("rw"),
            lambda p: p["boundary_before"]["roots"]["workspace_skills"][
                "observation"
            ].update(extra=0),
            lambda p: p["target_before"]["entries"][0].update(uid=992),
            lambda p: p["target_before"]["entries"][0].update(
                digest="sha256:" + "0" * 64
            ),
            lambda p: p["modules_before"]["curator"]["observed"].update(nlink=2),
            lambda p: p["gateway_process_before"].update(
                effective_capabilities="0000000000000001"
            ),
            lambda p: p["config_tree_before"].update(tree_digest="sha256:" + "0" * 64),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                document = _fresh_document()
                before, after = (
                    document["action"]["prerequisites"],
                    document["action"]["observations"],
                )
                mutate(before)
                for name in subject._STABLE:
                    after[f"{name}_after"] = deepcopy(before[f"{name}_before"])
                with self.assertRaises(AdmissionEvidenceError):
                    _verify(document)

    def test_coherent_invalid_system_telemetry_is_rejected(self):
        for key, value in (
            ("arch", "x64"),
            ("nodeVersion", "v99.0.0"),
            ("osLabel", "not the kernel release"),
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
                before, after = (
                    document["action"]["prerequisites"],
                    document["action"]["observations"],
                )
                for side, suffix in ((before, "before"), (after, "after")):
                    side[f"system_info_{suffix}"]["response"]["value"][key] = value
                _refresh_commands(document)
                with self.assertRaises(AdmissionEvidenceError):
                    _verify(document)

    def test_command_tampering_is_rejected_after_copy_refresh(self):
        for mutate in (
            lambda b, a: b["version"].update(pid=True),
            lambda b, a: b["version"].update(
                completed_at=a["system_info_after"]["command"]["completed_at"]
            ),
            lambda b, a: a["cli_fallback_restore"]["command"].update(
                pid=b["version"]["pid"]
            ),
            lambda b, a: a["gateway_restore"]["command"].update(stderr_bytes=1),
            lambda b, a: a["invalid_token_gateway_control"]["command"].update(
                argv=["unexpected"]
            ),
        ):
            document = _fresh_document()
            before, after = (
                document["action"]["prerequisites"],
                document["action"]["observations"],
            )
            mutate(before, after)
            _refresh_commands(document)
            with self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_parsed_output_rejects_duplicate_json_keys_with_valid_output_digest(self):
        document = _fresh_document()
        command = document["action"]["prerequisites"]["system_info_before"]["command"]
        raw = (
            command["stdout_excerpt"]
            .replace('{"arch":', '{"arch":"wrong","arch":', 1)
            .encode()
        )
        command.update(
            stdout_excerpt=raw.decode(),
            stdout_bytes=len(raw),
            stdout_digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        )
        document["action"]["commands"][1] = deepcopy(command)
        with self.assertRaises(AdmissionEvidenceError):
            _verify(document)


if __name__ == "__main__":
    unittest.main()
