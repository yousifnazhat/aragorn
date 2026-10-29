from __future__ import annotations

import json
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

from aragorn import (
    admission_openclaw_final_v3_missing_prompt_blob_subfixture as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest

_ROOT = Path(__file__).resolve().parents[1]
_verify = subject.verify_openclaw_final_v3_missing_prompt_blob_semantic_compatibility


def _document():
    return json.loads((_ROOT / subject.old._EVIDENCE["path"]).read_bytes())[
        "route_observation"
    ]["document"]


def _refresh_commands(document):
    action = document["action"]
    before, after = action["prerequisites"], action["observations"]
    wrappers = [before["system_info_before"], after["system_info_after"]]
    for name in ("initial_turn", "rebuild_turn"):
        wrappers.extend(after[name][key] for key in ("send", "wait"))
    for wrapper in wrappers:
        raw = (
            json.dumps(wrapper["response"]["value"], ensure_ascii=False) + "\n"
        ).encode()
        wrapper["command"].update(
            stdout_excerpt=raw.decode(),
            stdout_bytes=len(raw),
            stdout_digest=subject.old._digest(raw),
        )
    for name in ("initial_turn", "rebuild_turn"):
        turn = after[name]
        turn["commands"] = deepcopy([turn["send"]["command"], turn["wait"]["command"]])
    action["commands"] = deepcopy(
        [
            before["version"],
            before["system_info_before"]["command"],
            *after["initial_turn"]["commands"],
            *after["rebuild_turn"]["commands"],
            after["system_info_after"]["command"],
        ]
    )


def _fresh_document():
    """Synthetic fixture changes prove compatibility only, not a new capture."""
    document = _document()
    action = document["action"]
    pids = {
        command["pid"]: 20000 + index
        for index, command in enumerate(action["commands"])
    }
    replacements = {
        document["run_nonce"]: "c" * 32,
        action["observations"]["initial_snapshot"]["entry"][
            "session_id"
        ]: "11111111-1111-4111-8111-111111111111",
    }
    delta_ms = 12 * 86400 * 1000

    def shift(value):
        if isinstance(value, dict):
            for key, item in value.items():
                value[key] = (
                    str(int(item) + delta_ms * 1_000_000)
                    if key == "mtime_ns"
                    else shift(item)
                )
            if "argv" in value:
                value["pid"] = pids[value["pid"]]
            if value.get("type") in ("file", "directory"):
                value["device"] += 1000
                value["inode"] += 1000
            if "root" in value and "tree_digest" in value:
                value["tree_digest"] = canonical_digest(value["entries"])
        elif isinstance(value, list):
            return [shift(item) for item in value]
        elif type(value) is int and value >= 10**12:
            return value + delta_ms
        elif type(value) is str:
            for before, after in replacements.items():
                value = value.replace(before, after)
            if value.startswith("2026-08-30T"):
                value = (
                    (datetime.fromisoformat(value) + timedelta(days=12))
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z")
                )
        return value

    document = shift(document)
    action = document["action"]
    for side, suffix in (
        (action["prerequisites"], "before"),
        (action["observations"], "after"),
    ):
        side[f"gateway_process_{suffix}"].update(
            pid=12345, hostname="abcdef123456", start_time_ticks="987654321"
        )
        side[f"boundary_{suffix}"]["probe"]["records"][0]["root"] = (
            "/docker/volumes/aragorn-fresh-prompt-fixture/_data"
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
    for name in ("store_before", "store_after_rewrite"):
        action["observations"]["invalidation"][name].update(
            bytes=8000, digest=subject.old._digest(b"synthetic-unchanged-session-store")
        )
    _refresh_commands(document)
    return document


def _sync_protected_state(document):
    before, after = (
        document["action"]["prerequisites"],
        document["action"]["observations"],
    )
    for name in ("config_tree", "target"):
        tree = before[f"{name}_before"]
        tree["tree_digest"] = canonical_digest(tree["entries"])
    for tree in before["protected_root_trees_before"].values():
        tree["tree_digest"] = canonical_digest(tree["entries"])
    for name in subject._STABLE:
        after[f"{name}_after"] = deepcopy(before[f"{name}_before"])


class MissingPromptBlobSemanticTests(unittest.TestCase):
    def test_retained_and_fresh_input_confer_no_authority(self):
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
                "MISSING_PROMPT_BLOB_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
            )
            self.assertTrue(
                all(
                    value is False
                    for key, value in result["decision"].items()
                    if key != "status"
                )
            )
            self.assertFalse(result["route_semantics"]["pass_authority"])
            self.assertFalse(
                result["route_semantics"]["native_independent_route_execution_verified"]
            )

    def test_document_and_nested_trust_shapes_are_exact(self):
        for index, mutate in enumerate(
            (
                lambda d: d.update(run_nonce="invalid"),
                lambda d: d["implementation_digests"].update(
                    helper="sha256:" + "0" * 64
                ),
                lambda d: d.update(phase3_exit_eligible=True),
                lambda d: d["route"].update(status="PASS"),
                lambda d: d["runtime_binding"].update(version="2026.7.2"),
                lambda d: d["action"]["observations"]["initial_turn"].update(extra=0),
                lambda d: d["action"]["observations"]["initial_snapshot"][
                    "entry"
                ].update(extra=0),
                lambda d: d["action"]["observations"]["invalidation"][
                    "store_before"
                ].update(extra=0),
                lambda d: d["action"]["observations"]["initial_snapshot"][
                    "entry"
                ].update(snapshot_version=True),
                lambda d: d["action"]["observations"]["initial_snapshot"]["blob"][
                    "prompt_ref"
                ].update(version=True),
                lambda d: d["action"]["prerequisites"].update(
                    session_entry_absent_before=False
                ),
            )
        ):
            document = _fresh_document()
            mutate(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_coherent_protected_content_and_join_mutations_fail(self):
        for index, mutate in enumerate(
            (
                lambda b: b["boundary_before"]["probe"]["records"][0].update(
                    root="/unexpected"
                ),
                lambda b: b["boundary_before"]["runtime"]["records"][0][
                    "mount_options"
                ].append("rw"),
                lambda b: b["boundary_before"]["configuration"]["document"][
                    "tools"
                ].update(profile="full"),
                lambda b: b["boundary_before"]["configuration"]["file"].update(
                    digest="sha256:" + "0" * 64
                ),
                lambda b: b["target_before"]["entries"][0].update(
                    digest="sha256:" + "0" * 64
                ),
                lambda b: b["target_before"]["entries"][0].update(nlink=2),
                lambda b: b["config_tree_before"]["root"].update(inode=123456),
                lambda b: b["protected_root_trees_before"]["extensions"]["root"].update(
                    inode=123456
                ),
                lambda b: b["openclaw_before"].update(extra=0),
                lambda b: b["gateway_process_before"].update(
                    effective_capabilities="0000000000000001"
                ),
            )
        ):
            document = _fresh_document()
            mutate(document["action"]["prerequisites"])
            _sync_protected_state(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_blob_rebuild_and_unchanged_store_predicates_are_enforced(self):
        for index, mutate in enumerate(
            (
                lambda a: a["rebuilt_snapshot"]["entry"].update(
                    session_id="22222222-2222-4222-8222-222222222222"
                ),
                lambda a: a["rebuilt_snapshot"]["entry"].update(snapshot_version=1),
                lambda a: a["rebuilt_snapshot"]["entry"].update(
                    skill_filter=["different-skill"]
                ),
                lambda a: a["invalidation"].update(blob_exists_after_unlink=True),
                lambda a: a["invalidation"].update(blob_path="/different/blob"),
                lambda a: a["invalidation"]["store_after_rewrite"].update(
                    digest="sha256:" + "0" * 64
                ),
                lambda a: a["invalidation"]["store_after_rewrite"].update(bytes=1),
                lambda a: a["invalidation"]["store_after_rewrite"].update(
                    mtime_ns=a["invalidation"]["store_before"]["mtime_ns"]
                ),
                lambda a: a["rebuilt_snapshot"]["blob"].update(
                    mtime_ns=a["invalidation"]["store_after_rewrite"]["mtime_ns"]
                ),
                lambda a: a["invalidation"]["store_before"].update(
                    mtime_ns="+1788111366423299414"
                ),
                lambda a: a["invalidation"]["store_before"].update(digest="invalid"),
            )
        ):
            document = _fresh_document()
            mutate(document["action"]["observations"])
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)
        document = _fresh_document()
        after = document["action"]["observations"]
        raw = b"coherently changed prompt"
        digest = subject.old._digest(raw)
        path = (
            "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/skills-prompts/sha256/"
            + digest[7:9]
            + "/"
            + digest[7:]
            + ".txt"
        )
        for name in ("initial_snapshot", "rebuilt_snapshot"):
            snapshot = after[name]
            snapshot["prompt"].update(
                bytes=len(raw), digest=digest, exact_text=raw.decode()
            )
            snapshot["blob"].update(bytes=len(raw), digest=digest, path=path)
            snapshot["blob"]["prompt_ref"].update(bytes=len(raw), hash=digest[7:])
        after["invalidation"]["blob_path"] = path
        with self.assertRaises(AdmissionEvidenceError):
            _verify(document)

    def test_command_output_identity_and_chronology_are_bound(self):
        for index, mutate in enumerate(
            (
                lambda d, b, a: b["version"].update(pid=True),
                lambda d, b, a: b["version"].update(
                    pid=b["gateway_process_before"]["pid"]
                ),
                lambda d, b, a: a["rebuild_turn"]["send"]["command"].update(
                    pid=a["initial_turn"]["send"]["command"]["pid"]
                ),
                lambda d, b, a: a["rebuild_turn"]["send"]["command"].update(
                    argv=["unexpected"]
                ),
                lambda d, b, a: a["initial_turn"]["wait"]["response"]["value"].update(
                    status="ok"
                ),
                lambda d, b, a: a["rebuild_turn"]["wait"]["response"]["value"].update(
                    error="different error"
                ),
                lambda d, b, a: a["invalidation"].update(started_at=d["recorded_at"]),
                lambda d, b, a: d.update(recorded_at=b["version"]["started_at"]),
                lambda d, b, a: a["initial_turn"]["send"]["command"].update(extra=0),
            )
        ):
            document = _fresh_document()
            mutate(
                document,
                document["action"]["prerequisites"],
                document["action"]["observations"],
            )
            _refresh_commands(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)
        for key, value in (
            ("stdout_bytes", 1),
            ("stdout_digest", "sha256:" + "0" * 64),
        ):
            document = _fresh_document()
            document["action"]["observations"]["rebuild_turn"]["wait"]["command"][
                key
            ] = value
            with self.subTest(key=key), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_runtime_facts_and_safe_numeric_telemetry_are_enforced(self):
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
        ):
            document = _fresh_document()
            for side, suffix in (
                (document["action"]["prerequisites"], "before"),
                (document["action"]["observations"], "after"),
            ):
                side[f"system_info_{suffix}"]["response"]["value"][key] = value
            _refresh_commands(document)
            with (
                self.subTest(key=key, value=value),
                self.assertRaises(AdmissionEvidenceError),
            ):
                _verify(document)


if __name__ == "__main__":
    unittest.main()
