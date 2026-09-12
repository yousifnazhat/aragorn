from __future__ import annotations

import json
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

from aragorn import (
    admission_openclaw_final_v3_chat_session_snapshot_subfixture as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest

_ROOT = Path(__file__).resolve().parents[1]
_verify = subject.verify_openclaw_final_v3_chat_session_snapshot_semantic_compatibility


def _document():
    return json.loads((_ROOT / subject.old._EVIDENCE["path"]).read_bytes())[
        "route_observation"
    ]["document"]


def _refresh_commands(document):
    before, after = (
        document["action"]["prerequisites"],
        document["action"]["observations"],
    )
    wrappers = [before["system_info_before"], after["system_info_after"]]
    for name in ("initial_turn", "injected_turn"):
        wrappers.extend(after[name][key] for key in ("send", "wait"))
    for wrapper in wrappers:
        raw = (json.dumps(wrapper["response"]["value"], indent=2) + "\n").encode()
        wrapper["command"].update(
            stdout_excerpt=raw.decode(),
            stdout_bytes=len(raw),
            stdout_digest=subject.old._digest(raw),
        )
    for name in ("initial_turn", "injected_turn"):
        after[name]["commands"] = deepcopy(
            [after[name]["send"]["command"], after[name]["wait"]["command"]]
        )
    document["action"]["commands"] = deepcopy(
        [
            before["version"],
            before["system_info_before"]["command"],
            *after["initial_turn"]["commands"],
            *after["injected_turn"]["commands"],
            after["system_info_after"]["command"],
        ]
    )


def _refresh_replay(document):
    replay = document["action"]["observations"]["compiled_route_replay"]
    replay["non_skill_render_inputs_digest"] = canonical_digest(
        replay["non_skill_render_inputs"]
    )
    resolver = replay["resolver"]
    for prefix in ("baseline", "injected"):
        resolver[f"{prefix}_snapshot_digest"] = canonical_digest(
            resolver[f"{prefix}_snapshot"]
        )
        prompt = replay[f"{prefix}_render"]["system_prompt"]
        replay[f"{prefix}_report"]["systemPrompt"].update(
            chars=len(prompt.encode("utf-16-le")) // 2,
            nonProjectContextChars=len(prompt.encode("utf-16-le")) // 2,
            hash=subject.old._digest(prompt.encode()).removeprefix("sha256:"),
        )


def _fresh_document():
    """Synthetic projections and reported digests, not captured raw session state."""
    document = _document()
    action = document["action"]
    after = action["observations"]
    nonce = "c" * 32
    injected = after["mutated_snapshot"]["prompt"]["exact_text"].replace(
        document["run_nonce"], nonce
    )
    old_hash = after["mutated_snapshot"]["prompt"]["digest"].removeprefix("sha256:")
    new_hash = subject.old._digest(injected.encode()).removeprefix("sha256:")
    replacements = {
        f"/sha256/{old_hash[:2]}/{old_hash}.txt": (
            f"/sha256/{new_hash[:2]}/{new_hash}.txt"
        ),
        old_hash: new_hash,
        document["run_nonce"]: nonce,
        after["initial_snapshot"]["entry"][
            "session_id"
        ]: "11111111-1111-4111-8111-111111111111",
    }
    opaque = [
        after[name][key]["digest"]
        for name in ("initial_snapshot", "mutated_snapshot", "final_snapshot")
        for key in ("store",)
    ]
    opaque += [
        after[name]["entry_digest"]
        for name in ("initial_snapshot", "mutated_snapshot", "final_snapshot")
    ]
    opaque += [after["mutation"]["preserved_entry_without_prompt_ref"]["before_digest"]]
    opaque += [
        after["compiled_route_replay"][key]
        for key in ("baseline_loaded_entry_digest", "mutated_loaded_entry_digest")
    ]
    replacements.update(
        {
            value: subject.old._digest(("fresh-reported-" + value).encode())
            for value in opaque
        }
    )
    pids = {
        command["pid"]: 20000 + index
        for index, command in enumerate(action["commands"])
    }
    delta_ms = 11 * 86400 * 1000

    def shift(value):
        if type(value) is dict:
            for key, item in value.items():
                value[key] = (
                    str(int(item) + delta_ms * 1_000_000)
                    if key == "mtime_ns"
                    else shift(item)
                )
            for key in ("device", "inode"):
                if key in value:
                    value[key] += 1000
            if "argv" in value:
                value["pid"] = pids[value["pid"]]
            if "bytes" in value and value.get("path", "").startswith(
                "/var/lib/aragorn-agent-gateway/state/agents/main/sessions/sessions.json"
            ):
                value["bytes"] += 125
            if "tree_digest" in value and "root" in value:
                value["tree_digest"] = canonical_digest(value["entries"])
            if "metadata_digest" in value and "metadata" in value:
                value["metadata_digest"] = canonical_digest(value["metadata"])
        elif type(value) is list:
            return [shift(item) for item in value]
        elif type(value) is int and value >= 10**12:
            return value + delta_ms
        elif type(value) is str:
            for old, new in replacements.items():
                value = value.replace(old, new)
            if value.startswith("2026-09-01T"):
                value = (
                    (datetime.fromisoformat(value) + timedelta(days=11))
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z")
                )
        return value

    document = shift(document)
    before, after = (
        document["action"]["prerequisites"],
        document["action"]["observations"],
    )
    for side, suffix in ((before, "before"), (after, "after")):
        side[f"gateway_process_{suffix}"].update(
            pid=12345, hostname="abcdef123456", start_time_ticks="9988776655"
        )
        side[f"boundary_{suffix}"]["probe"]["records"][0].update(
            root="/docker/volumes/fresh-chat-snapshot-probe/_data", source="/dev/vdz1"
        )
        side[f"system_info_{suffix}"]["response"]["value"].update(
            pid=12345,
            hostname="abcdef123456",
            machineName="abcdef123456",
            release="6.8.0-fresh",
            osLabel="Linux 6.8.0-fresh",
            memoryTotalBytes=32_000_000_000,
            diskTotalBytes=64_000_000_000,
            loadAverage=[0, 0.5, 1],
        )
    _refresh_commands(document)
    _refresh_replay(document)
    return document


def _sync_stable(document):
    before, after = (
        document["action"]["prerequisites"],
        document["action"]["observations"],
    )
    for tree in (
        before["config_tree_before"],
        before["target_before"],
        *before["protected_root_trees_before"].values(),
    ):
        tree["tree_digest"] = canonical_digest(tree["entries"])
    for name in subject._STABLE:
        after[f"{name}_after"] = deepcopy(before[f"{name}_before"])


class ChatSessionSnapshotSemanticTests(unittest.TestCase):
    def test_retained_and_fresh_reported_projections_without_authority(self):
        for document in (_document(), _fresh_document()):
            unchanged = deepcopy(document)
            result = _verify(document)
            self.assertEqual(document, unchanged)
            self.assertEqual(
                result["bindings"]["input_document_canonical_digest"],
                canonical_digest(document),
            )
            self.assertTrue(
                all(
                    value is False
                    for key, value in result["decision"].items()
                    if key != "status"
                )
            )
            for key in (
                "entry_and_store_raw_bytes_verified",
                "full_session_state_equivalence_verified",
                "pass_authority",
                "native_independent_route_execution_verified",
            ):
                self.assertIs(result["route_semantics"][key], False)
            self.assertEqual(
                result["bindings"]["compiled_closure"]["archive"],
                subject.old.session._CLOSURE["archive"],
            )
        self.assertIsInstance(subject._reference_bytes(), bytes)
        first = json.loads(subject._reference_bytes())
        first["route"]["status"] = "PASS"
        self.assertEqual(
            json.loads(subject._reference_bytes())["route"]["status"], "OBSERVED"
        )

    def test_exact_shapes_types_and_authority(self):
        for index, mutate in enumerate(
            (
                lambda d: d.update(phase3_exit_eligible=True),
                lambda d: d["route"].update(status="PASS"),
                lambda d: d["action"]["observations"]["initial_snapshot"][
                    "entry"
                ].update(extra=0),
                lambda d: d["action"]["observations"]["native_recovery_timing"].update(
                    extra=0
                ),
                lambda d: d["action"]["observations"]["mutation"][
                    "atomic_store_replacement"
                ].update(rename_completed=1),
                lambda d: d["action"]["observations"]["initial_snapshot"][
                    "blob"
                ].update(inode=True),
                lambda d: d["action"]["observations"]["initial_snapshot"].update(
                    entry_digest="sha256:" + "+" + "0" * 63
                ),
                lambda d: d["action"]["prerequisites"]["system_info_before"][
                    "response"
                ]["value"].update(loadAverage=[float("nan"), 0, 0]),
            )
        ):
            document = _fresh_document()
            mutate(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_coherent_static_source_and_boundary_changes(self):
        for index, mutate in enumerate(
            (
                lambda b: b["target_before"]["entries"][0].update(
                    digest="sha256:" + "0" * 64
                ),
                lambda b: b["config_before"]["document"]["tools"].update(
                    profile="full"
                ),
                lambda b: b["boundary_before"]["runtime"]["records"][0][
                    "mount_options"
                ].append("rw"),
                lambda b: b["boundary_before"]["probe"]["entry"].update(mode="777"),
                lambda b: b["gateway_process_before"].update(
                    effective_capabilities="0000000000000001"
                ),
                lambda b: b["config_tree_before"]["root"].update(inode=999),
                lambda b: b["openclaw_before"].update(device=999),
            )
        ):
            document = _fresh_document()
            mutate(document["action"]["prerequisites"])
            _sync_stable(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)
        document = _fresh_document()
        modules = document["action"]["observations"]["compiled_route_replay"][
            "module_files"
        ]
        names = list(modules)[:2]
        modules[names[0]], modules[names[1]] = modules[names[1]], modules[names[0]]
        with self.assertRaises(AdmissionEvidenceError):
            _verify(document)

    def test_reported_mutation_and_recovery_joins(self):
        for index, mutate in enumerate(
            (
                lambda a: a["mutation"].update(
                    entry_before_digest="sha256:" + "0" * 64
                ),
                lambda a: a["mutation"]["preserved_entry_without_prompt_ref"].update(
                    after_digest="sha256:" + "0" * 64
                ),
                lambda a: a["mutation"]["store_after_rewrite"].update(bytes=1),
                lambda a: a["mutation"].update(changed_json_paths=["other.path"]),
                lambda a: a["mutated_snapshot"]["prompt"].update(
                    exact_text="changed inert fixture"
                ),
                lambda a: a["final_snapshot"]["entry"].update(
                    session_id="22222222-2222-4222-8222-222222222222"
                ),
                lambda a: a.update(attacker_blob_unreferenced_after=False),
                lambda a: a["compiled_route_replay"]["baseline_store_copy"].update(
                    digest="sha256:" + "0" * 64
                ),
            )
        ):
            document = _fresh_document()
            mutate(document["action"]["observations"])
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_coherent_compiled_render_resolver_and_report_changes(self):
        for mode in ("inputs", "render", "resolver", "report", "bridge"):
            document = _fresh_document()
            replay = document["action"]["observations"]["compiled_route_replay"]
            if mode == "inputs":
                replay["non_skill_render_inputs"]["defaultThinkLevel"] = "high"
            elif mode == "render":
                for prefix in ("baseline", "injected"):
                    replay[f"{prefix}_render"]["system_prompt"] += (
                        "\nUnexpected static text."
                    )
            elif mode == "resolver":
                for prefix in ("baseline", "injected"):
                    replay["resolver"][f"{prefix}_snapshot"]["resolvedSkills"][0][
                        "description"
                    ] = "changed"
            elif mode == "report":
                for prefix in ("baseline", "injected"):
                    replay[f"{prefix}_report"]["skills"]["promptChars"] = 736
            else:
                handoff = next(iter(replay["handoff_statements"].values()))
                handoff["statement"] += " "
                handoff["digest"] = subject.old._digest(handoff["statement"].encode())
            _refresh_replay(document)
            with self.subTest(mode=mode), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_seven_commands_and_native_recovery_chronology(self):
        for index, mutate in enumerate(
            (
                lambda a: a["injected_turn"]["send"]["command"].update(pid=12345),
                lambda a: a["injected_turn"]["wait"]["command"].update(
                    started_at="2026-09-12T00:00:00Z"
                ),
                lambda a: a["native_recovery_timing"].update(final_store_mtime_ms=1),
                lambda a: a["final_snapshot"]["entry"].update(ended_at=1),
                lambda a: a["initial_turn"]["wait"]["response"]["value"].update(
                    status="ok"
                ),
                lambda a: a["injected_turn"].update(tools_allow_supplied=True),
            )
        ):
            document = _fresh_document()
            mutate(document["action"]["observations"])
            _refresh_commands(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)
        document = _fresh_document()
        document["action"]["commands"].pop()
        with self.assertRaises(AdmissionEvidenceError):
            _verify(document)


if __name__ == "__main__":
    unittest.main()
