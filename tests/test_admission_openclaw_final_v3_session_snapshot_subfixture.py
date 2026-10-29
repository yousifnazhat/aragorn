from __future__ import annotations

import json
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

from aragorn import admission_openclaw_final_v3_session_snapshot_subfixture as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest
from tests.test_admission_openclaw_final_v3_chat_session_snapshot_subfixture import (
    _refresh_commands,
    _refresh_replay,
    _sync_stable,
)

_ROOT = Path(__file__).resolve().parents[1]
_verify = subject.verify_openclaw_final_v3_session_snapshot_semantic_compatibility


def _document():
    return json.loads((_ROOT / subject.old._EVIDENCE["path"]).read_bytes())[
        "route_observation"
    ]["document"]


def _fresh_document():
    """Rotate this fixture's reported identities, preserving its own chronology."""
    document = _document()
    after = document["action"]["observations"]
    nonce = "c" * 32
    injected = after["mutated_snapshot"]["prompt"]["exact_text"].replace(
        document["run_nonce"], nonce
    )
    old_hash = after["mutated_snapshot"]["prompt"]["digest"].removeprefix("sha256:")
    new_hash = subject.old._digest(injected.encode()).removeprefix("sha256:")
    replacements = {
        f"/sha256/{old_hash[:2]}/{old_hash}.txt": f"/sha256/{new_hash[:2]}/{new_hash}.txt",
        old_hash: new_hash,
        document["run_nonce"]: nonce,
        after["initial_snapshot"]["entry"][
            "session_id"
        ]: "11111111-1111-4111-8111-111111111111",
    }
    reported = [
        digest
        for name in ("initial_snapshot", "mutated_snapshot", "final_snapshot")
        for digest in (after[name]["entry_digest"], after[name]["store"]["digest"])
    ] + [
        after["mutation"]["preserved_entry_without_prompt_ref"]["before_digest"],
        *[
            after["compiled_route_replay"][key]
            for key in ("baseline_loaded_entry_digest", "mutated_loaded_entry_digest")
        ],
    ]
    replacements.update(
        {
            value: subject.old._digest(("reported-fresh-" + value).encode())
            for value in reported
        }
    )
    pids = {
        command["pid"]: 20000 + index
        for index, command in enumerate(document["action"]["commands"])
    }
    delta_ms = 12 * 86400 * 1000

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
            if value.startswith("2026-08-31T"):
                value = (
                    (datetime.fromisoformat(value) + timedelta(days=12))
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z")
                )
        return value

    document = shift(document)
    for side, suffix in (("prerequisites", "before"), ("observations", "after")):
        value = document["action"][side]
        value[f"gateway_process_{suffix}"].update(
            pid=12345, hostname="abcdef123456", start_time_ticks="9988776655"
        )
        value[f"boundary_{suffix}"]["probe"]["records"][0].update(
            root="/docker/volumes/fresh-session-snapshot-probe/_data",
            source="/dev/vdz1",
        )
        value[f"system_info_{suffix}"]["response"]["value"].update(
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


class SessionSnapshotSemanticTests(unittest.TestCase):
    def test_retained_and_fresh_bounded_proofs_preserve_input(self):
        for document in (_document(), _fresh_document()):
            before = deepcopy(document)
            result = _verify(document)
            self.assertEqual(before, document)
            self.assertEqual(result["bindings"]["target_case_id"], subject.old._ROUTE)
            self.assertEqual(
                result["bindings"]["input_document_canonical_digest"],
                canonical_digest(document),
            )
            self.assertEqual(
                result["bindings"]["signed_template_retention"], subject.old._RETENTION
            )
            for key in subject.old.contract._ELIGIBILITY_KEYS:
                self.assertIs(result["decision"][key], False)
            for key in (
                "entry_and_store_raw_bytes_verified",
                "full_session_state_equivalence_verified",
                "native_independent_route_execution_verified",
                "pass_authority",
            ):
                self.assertIs(result["route_semantics"][key], False)
            final = document["action"]["observations"]["final_snapshot"]
            # This session route reads the blob after persisting updated_at.
            self.assertLess(
                final["entry"]["updated_at"],
                int(final["blob"]["mtime_ns"]) // 1_000_000,
            )
        self.assertIsInstance(subject._reference_bytes(), bytes)
        altered = json.loads(subject._reference_bytes())
        altered["route"]["status"] = "PASS"
        self.assertEqual(
            json.loads(subject._reference_bytes())["route"]["status"], "OBSERVED"
        )

    def test_exact_types_shapes_and_route_authority(self):
        mutations = (
            lambda d: d.update(phase3_exit_eligible=True),
            lambda d: d["route"].update(status="PASS"),
            lambda d: d["route"].update(
                id="ADM-02/reload/chat-session-snapshot-consumer"
            ),
            lambda d: d["action"]["observations"]["initial_snapshot"]["store"].update(
                inode=True
            ),
            lambda d: d["action"]["observations"]["initial_snapshot"].update(
                entry_digest="sha256:+" + "0" * 63
            ),
            lambda d: d["action"]["observations"]["mutation"][
                "atomic_store_replacement"
            ].update(rename_completed=1),
            lambda d: d["action"]["observations"]["injected_turn"]["wait"]["response"][
                "value"
            ].update(extra=0),
            lambda d: d["action"]["prerequisites"]["system_info_before"]["response"][
                "value"
            ].update(loadAverage=[float("nan"), 0, 0]),
        )
        for index, mutate in enumerate(mutations):
            document = _fresh_document()
            mutate(document)
            _refresh_commands(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_coherent_protected_boundary_changes(self):
        for index, mutate in enumerate(
            (
                lambda b: b["target_before"]["entries"][0].update(
                    digest="sha256:" + "0" * 64
                ),
                lambda b: b["boundary_before"]["probe"]["entry"].update(mode="777"),
                lambda b: b["openclaw_before"].update(device=999),
                lambda b: b["gateway_process_before"].update(
                    effective_capabilities="0000000000000001"
                ),
            )
        ):
            document = _fresh_document()
            mutate(document["action"]["prerequisites"])
            _sync_stable(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_reported_state_and_recovery_joins(self):
        for index, mutate in enumerate(
            (
                lambda a: a["mutation"]["preserved_entry_without_prompt_ref"].update(
                    after_digest="sha256:" + "0" * 64
                ),
                lambda a: a["mutation"]["store_after_rewrite"].update(bytes=1),
                lambda a: a["final_snapshot"]["entry"].update(
                    session_id="22222222-2222-4222-8222-222222222222"
                ),
                lambda a: a["mutation"].update(changed_json_paths=["other.path"]),
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

    def test_coherent_compiled_prompt_inputs_resolver_and_modules(self):
        for mode in ("inputs", "render", "resolver", "roles", "bridge"):
            document = _fresh_document()
            replay = document["action"]["observations"]["compiled_route_replay"]
            if mode == "inputs":
                replay["non_skill_render_inputs"]["defaultThinkLevel"] = "high"
            elif mode == "render":
                for prefix in ("baseline", "injected"):
                    replay[f"{prefix}_render"]["system_prompt"] += (
                        "\nChanged static text."
                    )
            elif mode == "resolver":
                for prefix in ("baseline", "injected"):
                    replay["resolver"][f"{prefix}_snapshot"]["resolvedSkills"][0][
                        "description"
                    ] = "changed"
            elif mode == "roles":
                modules = replay["module_files"]
                left, right = list(modules)[:2]
                modules[left], modules[right] = modules[right], modules[left]
            else:
                bridge = next(iter(replay["handoff_statements"].values()))
                bridge["statement"] += " "
                bridge["digest"] = subject.old._digest(bridge["statement"].encode())
            _refresh_replay(document)
            with self.subTest(mode=mode), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_seven_native_commands_nonce_and_timing_aliases(self):
        for mode in ("pid", "nonce", "timing", "epoch", "blob", "extra-command"):
            document = _fresh_document()
            after = document["action"]["observations"]
            if mode == "pid":
                after["injected_turn"]["send"]["command"]["pid"] = 12345
            elif mode == "nonce":
                for label in ("initial", "injected"):
                    after[f"{label}_turn"] = json.loads(
                        json.dumps(after[f"{label}_turn"]).replace(
                            document["run_nonce"], "d" * 32
                        )
                    )
            elif mode == "timing":
                after["native_recovery_timing"]["final_store_mtime_ms"] += 1
            elif mode == "epoch":
                after["final_snapshot"]["entry"]["ended_at"] = 1
            elif mode == "blob":
                final = after["final_snapshot"]
                final["blob"]["mtime_ns"] = str(
                    (final["entry"]["updated_at"] - 1) * 1_000_000
                )
            _refresh_commands(document)
            if mode == "extra-command":
                document["action"]["commands"].append(
                    deepcopy(document["action"]["commands"][-1])
                )
            with self.subTest(mode=mode), self.assertRaises(AdmissionEvidenceError):
                _verify(document)


if __name__ == "__main__":
    unittest.main()
