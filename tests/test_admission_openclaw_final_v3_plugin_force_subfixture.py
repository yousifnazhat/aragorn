from __future__ import annotations

import json
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

from aragorn import admission_openclaw_final_v3_plugin_force_subfixture as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest

_ROOT = Path(__file__).resolve().parents[1]
_VERIFY = subject.verify_openclaw_final_v3_plugin_force_semantic_compatibility
_ZERO = "sha256:" + "0" * 64


def _document():
    return json.loads((_ROOT / subject.old._EVIDENCE["path"]).read_bytes())[
        "route_observation"
    ]["document"]


def _rehash(value):
    if type(value) is dict:
        for item in value.values():
            _rehash(item)
        if "tree_digest" in value:
            value["tree_digest"] = canonical_digest(value["entries"])
    elif type(value) is list:
        for item in value:
            _rehash(item)


def _commands(document):
    before, after = (
        document["action"]["prerequisites"],
        document["action"]["observations"],
    )
    for side, suffix in ((before, "before"), (after, "after")):
        system = side[f"system_info_{suffix}"]
        raw = (json.dumps(system["response"]["value"]) + "\n").encode()
        system["command"].update(
            stdout_excerpt=raw.decode(),
            stdout_bytes=len(raw),
            stdout_digest=subject.old._digest(raw),
        )
    document["action"]["commands"] = deepcopy(
        [
            before["version"],
            before["system_info_before"]["command"],
            before["skills_status_before"]["command"],
            before["plugin_before"]["command"],
            after["native_force_reinstall"]["command"],
            after["plugin_after"]["command"],
            after["skills_status_after"]["command"],
            after["system_info_after"]["command"],
        ]
    )


def _fresh(directory_links=1):
    """Synthetic identities exercise compatibility; no new execution is claimed."""
    document = _document()
    pids = {
        command["pid"]: 21000 + index
        for index, command in enumerate(document["action"]["commands"])
    }

    def shift(value):
        if type(value) is dict:
            for key, item in value.items():
                value[key] = shift(item)
            if "argv" in value:
                value["pid"] = pids[value["pid"]]
            if value.get("type") in {"file", "directory"}:
                value["device"] += 1000
                value["inode"] += 1000
                if value["type"] == "directory":
                    value.update(nlink=directory_links, size=8192)
        elif type(value) is list:
            return [shift(item) for item in value]
        elif type(value) is str and value.startswith("2026-08-28T"):
            return (
                (datetime.fromisoformat(value) + timedelta(days=20))
                .isoformat()
                .replace("+00:00", "Z")
            )
        return value

    shift(document)
    document["run_nonce"] = "d" * 32
    before, after = (
        document["action"]["prerequisites"],
        document["action"]["observations"],
    )
    for side, suffix in ((before, "before"), (after, "after")):
        boundary = side[f"boundary_{suffix}"]
        boundary["gateway_process"].update(pid=13579, start_time_ticks="987654321")
        boundary["route_input_mount"]["records"][0].update(
            root="/docker/volumes/aragorn-phase3-final-combined-v3-plugin-force-reinstall-route-input-90001/_data",
            source="/dev/vdz1",
        )
        system = side[f"system_info_{suffix}"]["response"]["value"]
        system.update(
            pid=13579,
            hostname="abcdef123456",
            machineName="abcdef123456",
            release="6.8.0-synthetic",
            osLabel="Linux 6.8.0-synthetic",
            loadAverage=[0, 0.5, 1],
            memoryTotalBytes=32_000_000_000,
            diskTotalBytes=64_000_000_000,
        )
        for index in (1, 2):
            boundary["state_store"]["entries"][index]["digest"] = (
                "sha256:" + ("a" if suffix == "before" else "b") * 64
            )
        boundary["state_store"]["entries"][2]["size"] += 4120 * 3
    _rehash(document)
    _commands(document)
    return document


def _boundaries(document):
    return (
        document["action"]["prerequisites"]["boundary_before"],
        document["action"]["observations"]["boundary_after"],
    )


class PluginForceSemanticTests(unittest.TestCase):
    def test_retained_and_fresh_metadata_preserve_only_compatibility(self):
        for document in (_document(), *(_fresh(nlink) for nlink in (1, 2, 4))):
            unchanged = deepcopy(document)
            result = _VERIFY(document)
            self.assertEqual(document, unchanged)
            self.assertEqual(
                result["bindings"]["input_document_canonical_digest"],
                canonical_digest(document),
            )
            self.assertTrue(
                all(
                    value is False
                    for key, value in result["decision"].items()
                    if key.endswith("_eligible")
                )
            )
            self.assertIn(
                "SQLITE_DIGEST_METADATA_DELTA_ONLY_NOT_RAW_BYTES_OR_LOGICAL_EQUIVALENCE",
                result["limitations"],
            )

    def test_document_identity_and_nonce_cannot_be_promoted_or_weakened(self):
        for key, value in (
            ("run_nonce", "+" + "0" * 31),
            ("run_nonce", "A" * 32),
            ("implementation_digest", _ZERO),
            ("schema", "wrong"),
            ("phase3_exit_eligible", True),
        ):
            with self.subTest(key=key, value=value):
                document = _fresh()
                document[key] = value
                with self.assertRaises(AdmissionEvidenceError):
                    _VERIFY(document)
        document = _fresh()
        document["route"]["status"] = "PASS"
        with self.assertRaises(AdmissionEvidenceError):
            _VERIFY(document)

    def test_coherent_static_custody_source_and_alias_mutations_reject(self):
        for mutation in (
            "owner",
            "mode",
            "link_zero",
            "link_bool",
            "file_links",
            "extra",
            "source_digest",
            "target_alias",
            "inode_contents",
            "standalone_inode",
            "config",
            "mount",
        ):
            with self.subTest(mutation=mutation):
                document = _fresh()
                for boundary in _boundaries(document):
                    root = boundary["baseline_source"]["tree"]["root"]
                    entry = boundary["baseline_source"]["tree"]["entries"][0]
                    if mutation == "owner":
                        root["uid"] = 992
                    elif mutation == "mode":
                        root["mode"] = "777"
                    elif mutation == "link_zero":
                        root["nlink"] = 0
                    elif mutation == "link_bool":
                        root["nlink"] = True
                    elif mutation == "file_links":
                        entry["nlink"] = 2
                    elif mutation == "extra":
                        root["extra"] = None
                    elif mutation == "source_digest":
                        entry["digest"] = _ZERO
                    elif mutation == "target_alias":
                        boundary["target_plugin"]["candidate"]["tree"]["entries"][0][
                            "inode"
                        ] += 1
                    elif mutation == "inode_contents":
                        boundary["baseline_source"]["tree"]["entries"][1]["inode"] = (
                            entry["inode"]
                        )
                    elif mutation == "standalone_inode":
                        for key in ("device", "inode"):
                            boundary["openclaw"][key] = boundary[
                                "install_policy_command"
                            ][key]
                    elif mutation == "config":
                        boundary["config"]["install_policy"]["enabled"] = False
                    else:
                        boundary["route_input_mount"]["read_only"] = False
                _rehash(document)
                with self.assertRaises(AdmissionEvidenceError):
                    _VERIFY(document)
        # Different logical paths can validly expose the same bound inode.
        file = _boundaries(_fresh())[0]["baseline_source"]["tree"]["entries"][0]
        subject._aliases({"left": file, "right": {**file, "path": "/bind/index.js"}})

    def test_denial_truncated_output_and_catalog_predicates_remain_exact(self):
        for mutation in (
            "force",
            "denial",
            "plugin",
            "truncation",
            "catalog",
            "containment",
        ):
            with self.subTest(mutation=mutation):
                document = _fresh()
                before, after = (
                    document["action"]["prerequisites"],
                    document["action"]["observations"],
                )
                if mutation == "force":
                    after["native_force_reinstall"]["command"]["argv"][-1] = "--help"
                elif mutation == "denial":
                    after["native_force_reinstall"]["command"]["exit_code"] = 0
                elif mutation in {"plugin", "truncation"}:
                    for side, suffix in ((before, "before"), (after, "after")):
                        value = side[f"plugin_{suffix}"]
                        if mutation == "plugin":
                            value["response"]["value"]["plugin"]["enabled"] = True
                        else:
                            value["command"]["stdout_digest"] = _ZERO
                elif mutation == "catalog":
                    for side, suffix in ((before, "before"), (after, "after")):
                        side[f"skills_status_{suffix}"]["response"]["value"][
                            "skills"
                        ] = []
                else:
                    after["post_write_containment"]["state_store_unchanged"] = True
                _commands(document)
                with self.assertRaises(AdmissionEvidenceError):
                    _VERIFY(document)

    def test_sqlite_delta_is_same_inode_typed_and_not_claimed_unchanged(self):
        for mutation in (
            "inode",
            "root",
            "digest",
            "wal_size",
            "wal_alignment",
            "database",
            "shm",
            "missing",
        ):
            with self.subTest(mutation=mutation):
                document = _fresh()
                before, after = (
                    boundary["state_store"] for boundary in _boundaries(document)
                )
                if mutation == "inode":
                    after["entries"][1]["inode"] += 1
                elif mutation == "root":
                    after["root"]["inode"] += 1
                elif mutation == "digest":
                    after["entries"][2]["digest"] = before["entries"][2]["digest"]
                elif mutation == "wal_size":
                    after["entries"][2]["size"] = before["entries"][2]["size"]
                elif mutation == "wal_alignment":
                    after["entries"][2]["size"] += 1
                elif mutation == "database":
                    before["entries"][0]["digest"] = after["entries"][0]["digest"] = (
                        _ZERO
                    )
                elif mutation == "shm":
                    after["entries"][1]["size"] = True
                else:
                    after["entries"].pop()
                _rehash(document)
                with self.assertRaises(AdmissionEvidenceError):
                    _VERIFY(document)

    def test_actual_command_pid_system_and_chronology_joins_reject_drift(self):
        for mutation in (
            "pid",
            "gateway",
            "hostname",
            "arch",
            "node",
            "uptime",
            "chronology",
            "alias",
        ):
            with self.subTest(mutation=mutation):
                document = _fresh()
                before, after = (
                    document["action"]["prerequisites"],
                    document["action"]["observations"],
                )
                system = after["system_info_after"]["response"]["value"]
                if mutation == "pid":
                    after["native_force_reinstall"]["command"]["pid"] = before[
                        "version"
                    ]["pid"]
                elif mutation == "gateway":
                    system["pid"] += 1
                elif mutation == "hostname":
                    system["hostname"] = "123456abcdef"
                elif mutation == "arch":
                    system["arch"] = "x64"
                elif mutation == "node":
                    system["nodeVersion"] = "v24.15.0"
                elif mutation == "uptime":
                    system["uptimeMs"] = 1
                elif mutation == "chronology":
                    document["recorded_at"] = before["version"]["started_at"]
                _commands(document)
                if mutation == "alias":
                    document["action"]["commands"][0]["pid"] += 1
                with self.assertRaises(AdmissionEvidenceError):
                    _VERIFY(document)
