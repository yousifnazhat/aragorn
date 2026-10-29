from __future__ import annotations

import base64
import json
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

from aragorn import admission_openclaw_final_v3_cron_rescan_subfixture as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_verify = subject.verify_openclaw_final_v3_cron_rescan_semantic_compatibility


def _document():
    return json.loads((_ROOT / subject.old._EVIDENCE["path"]).read_bytes())[
        "route_observation"
    ]["document"]


def _refresh_commands(document):
    def walk(value):
        if type(value) is dict:
            for item in value.values():
                walk(item)
            if "command" in value and "response" in value:
                raw = (json.dumps(value["response"]["value"], indent=2) + "\n").encode()
                command = value["command"]
                command.update(
                    stdout_excerpt=raw.decode(),
                    stdout_bytes=len(raw),
                    stdout_digest=subject.old._digest(raw),
                )
                if "params" in value:
                    command["argv"] = (
                        subject.old.semantics.parent.parent.legacy._gateway_argv(
                            command["argv"][4], "5000", value["params"]
                        )
                    )
        elif type(value) is list:
            for item in value:
                walk(item)

    walk(document)
    before, after = (
        document["action"]["prerequisites"],
        document["action"]["observations"],
    )
    document["action"]["commands"] = deepcopy(
        [
            before["version"],
            before["system_info_before"]["command"],
            before["cron_inventory_before"]["list"]["command"],
            after["job"]["command"],
            after["cron_inventory_after_add"]["list"]["command"],
            after["run"]["request"]["command"],
            after["run"]["terminal_poll"]["command"],
            after["cleanup"]["command"],
            after["cron_inventory_after_remove"]["list"]["command"],
            after["system_info_after"]["command"],
        ]
    )


def _raw(value):
    raw = (json.dumps(value, indent=2) + "\n").encode()
    return {
        "base64": base64.b64encode(raw).decode(),
        "bytes": len(raw),
        "digest": subject.old._digest(raw),
    }


def _refresh_stores(document, pre_document=None):
    before, after = (
        document["action"]["prerequisites"],
        document["action"]["observations"],
    )
    pre, snapshot = after["session_state_before_forced_run"], after["snapshot"]
    if pre_document is None:
        pre_document = json.loads(base64.b64decode(pre["store_raw"]["base64"]))
    pre["store_raw"] = _raw(pre_document)
    pre["store_document_digest"] = pre["store_raw"]["digest"]
    pre["store"].update(
        bytes=pre["store_raw"]["bytes"], digest=pre["store_raw"]["digest"]
    )
    before["session_store_before"].update(
        size=pre["store"]["bytes"], digest=pre["store"]["digest"]
    )
    snapshot["entry_digest"] = canonical_digest(snapshot["entry_document"])
    snapshot["snapshot"]["metadata_digest"] = canonical_digest(
        snapshot["snapshot"]["metadata"]
    )
    post_document = {
        **pre_document,
        snapshot["base_session_key"]: deepcopy(snapshot["entry_document"]),
    }
    snapshot["store_document"] = post_document
    snapshot["store_document_digest"] = canonical_digest(post_document)
    snapshot["store_document_bytes"] = len(canonical_json(post_document))
    snapshot["store_raw"] = _raw(post_document)
    snapshot["store"].update(
        bytes=snapshot["store_raw"]["bytes"], digest=snapshot["store_raw"]["digest"]
    )
    after["session_store_after"].update(
        size=snapshot["store"]["bytes"], digest=snapshot["store"]["digest"]
    )


def _fresh_document():
    """Rotate synthetic metadata only; this is not a newly executed cron run."""
    document = _document()
    action = document["action"]
    after = action["observations"]
    delta_ms = 13 * 86400 * 1000
    old_run = after["run"]["request"]["response"]["value"]["runId"]
    run_parts = old_run.split(":")
    job = "11111111-1111-4111-8111-111111111111"
    run_parts[1], run_parts[2] = job, str(int(run_parts[2]) + delta_ms)
    replacements = {
        old_run: ":".join(run_parts),
        after["job"]["response"]["value"]["id"]: job,
        after["terminal_result"]["sessionId"]: "22222222-2222-4222-8222-222222222222",
        after["snapshot"]["entry_document"][
            "lifecycleRevision"
        ]: "33333333-3333-4333-8333-333333333333",
        document["run_nonce"]: "d" * 32,
    }
    pids = {
        command["pid"]: 20000 + index
        for index, command in enumerate(action["commands"])
    }

    def shift(value):
        if type(value) is dict:
            shifted = {}
            for key, item in value.items():
                shifted[shift(key)] = (
                    str(int(item) + delta_ms * 1_000_000)
                    if key == "mtime_ns"
                    else shift(item)
                )
            if "argv" in shifted:
                shifted["pid"] = pids[shifted["pid"]]
            for key in ("inode", "device"):
                if key in shifted:
                    shifted[key] += 1000
            if "root" in shifted and "tree_digest" in shifted:
                shifted["tree_digest"] = canonical_digest(shifted["entries"])
            return shifted
        if type(value) is list:
            return [shift(item) for item in value]
        if type(value) is int and value >= 10**12:
            return value + delta_ms
        if type(value) is str:
            for before, after in replacements.items():
                value = value.replace(before, after)
            if value.startswith("2026-08-30T"):
                value = (
                    (datetime.fromisoformat(value) + timedelta(days=13))
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z")
                )
        return value

    pre_document = shift(
        json.loads(
            base64.b64decode(
                after["session_state_before_forced_run"]["store_raw"]["base64"]
            )
        )
    )
    pre_document["agent:main:aragorn-worker-coherent"]["synthetic_note"] = (
        "Preserved unrelated pre-existing session metadata."
    )
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
            root="/docker/volumes/fresh-cron-probe/_data", source="/dev/vdz1"
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
    for inventory in (
        before["cron_inventory_before"],
        after["cron_inventory_after_add"],
        after["cron_inventory_after_remove"],
    ):
        for name in ("database", "shared_memory", "write_ahead_log"):
            record = inventory["store"][name]
            record["digest"] = subject.old._digest(
                ("fresh-" + record["digest"]).encode()
            )
            record["bytes"] += 4096
    _refresh_stores(document, pre_document)
    _refresh_commands(document)
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


class CronRescanSemanticTests(unittest.TestCase):
    def test_retained_and_fresh_inputs_without_authority(self):
        fresh = _fresh_document()
        self.assertNotEqual(
            fresh["action"]["prerequisites"]["session_store_before"]["size"], 5308
        )
        for document in (_document(), fresh):
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
            self.assertFalse(result["route_semantics"]["pass_authority"])
            self.assertFalse(
                result["route_semantics"]["native_independent_route_execution_verified"]
            )

    def test_document_shapes_and_scalar_guards(self):
        for index, mutate in enumerate(
            (
                lambda d: d.update(phase3_exit_eligible=True),
                lambda d: d["route"].update(status="PASS"),
                lambda d: d["implementation_digests"].update(
                    helper="sha256:" + "0" * 64
                ),
                lambda d: d["action"]["observations"]["run"].update(extra=0),
                lambda d: d["action"]["observations"]["job"]["response"][
                    "value"
                ].update(enabled=1),
                lambda d: d["action"]["observations"]["snapshot"]["entry_document"][
                    "skillsSnapshot"
                ]["promptRef"].update(version=True),
                lambda d: d["action"]["prerequisites"]["system_info_before"][
                    "response"
                ]["value"].update(loadAverage=[0, float("inf"), 0]),
            )
        ):
            document = _fresh_document()
            mutate(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_coherent_protected_state_and_runtime_mutations(self):
        for index, mutate in enumerate(
            (
                lambda b: b["config_before"]["document"]["tools"].update(
                    profile="full"
                ),
                lambda b: b["target_before"]["entries"][0].update(
                    digest="sha256:" + "0" * 64
                ),
                lambda b: b["module_files_before"]["cron"]["observed"].update(
                    mode="666"
                ),
                lambda b: b["module_files_before"]["cron"]["expected"].update(
                    digest="sha256:" + "0" * 64
                ),
                lambda b: b["boundary_before"]["probe"]["records"][0][
                    "mount_options"
                ].append("rw"),
                lambda b: b["config_tree_before"]["root"].update(inode=999),
                lambda b: b["gateway_process_before"].update(
                    effective_capabilities="0000000000000001"
                ),
                lambda b: b["session_store_before"].update(mode="644"),
            )
        ):
            document = _fresh_document()
            mutate(document["action"]["prerequisites"])
            _sync_stable(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_actual_session_raw_and_prompt_joins(self):
        for index, mutate in enumerate(
            (
                lambda a: a["session_state_before_forced_run"]["store_raw"].update(
                    bytes=5308
                ),
                lambda a: a["session_state_before_forced_run"]["store_raw"].update(
                    base64="e30="
                ),
                lambda a: a["session_state_before_forced_run"]["store"].update(
                    inode=999
                ),
                lambda a: a["snapshot"]["store_document"][
                    "agent:main:aragorn-worker-coherent"
                ].update(synthetic_note="changed"),
                lambda a: a["snapshot"]["prompt"].update(bytes=736),
                lambda a: a["snapshot"]["blob"]["prompt_ref"].update(hash="0" * 64),
                lambda a: a["snapshot"]["entry_document"].update(
                    lifecycleRevision="not-a-uuid"
                ),
                lambda a: a["session_store_after"].update(inode=999),
            )
        ):
            document = _fresh_document()
            mutate(document["action"]["observations"])
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

        # Even rehashing every post-store alias cannot authorize changing the
        # unrelated pre-existing session alongside the single new cron entry.
        document = _fresh_document()
        after = document["action"]["observations"]
        snapshot = after["snapshot"]
        post = snapshot["store_document"]
        post["agent:main:aragorn-worker-coherent"]["synthetic_note"] = "changed"
        snapshot["store_document_digest"] = canonical_digest(post)
        snapshot["store_document_bytes"] = len(canonical_json(post))
        snapshot["store_raw"] = _raw(post)
        snapshot["store"].update(
            bytes=snapshot["store_raw"]["bytes"],
            digest=snapshot["store_raw"]["digest"],
        )
        after["session_store_after"].update(
            size=snapshot["store"]["bytes"], digest=snapshot["store"]["digest"]
        )
        with self.assertRaises(AdmissionEvidenceError):
            _verify(document)

    def test_job_terminal_and_command_chronology(self):
        for index, mutate in enumerate(
            (
                lambda a: a["job"]["params"]["payload"].update(timeoutSeconds=10),
                lambda a: a["job"]["response"]["value"].update(id="not-a-uuid"),
                lambda a: a["run"].update(poll_count=2),
                lambda a: a["run"]["request"]["response"]["value"].update(
                    runId="manual:invalid"
                ),
                lambda a: a["terminal_result"].update(status="ok"),
                lambda a: a["terminal_result"].update(runAtMs=1),
                lambda a: a["cleanup"]["response"]["value"].update(removed=False),
                lambda a: a["cleanup"]["command"].update(pid=12345),
                lambda a: a["cleanup"]["command"].update(
                    started_at="2026-09-12T00:00:00Z"
                ),
            )
        ):
            document = _fresh_document()
            mutate(document["action"]["observations"])
            if index in (4, 5):
                after = document["action"]["observations"]
                poll = after["run"]["terminal_poll"]
                poll["response"]["value"]["entries"] = [
                    deepcopy(after["terminal_result"])
                ]
                after["run"]["polls"] = [deepcopy(poll)]
            _refresh_commands(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)
        document = _fresh_document()
        document["action"]["commands"].pop()
        with self.assertRaises(AdmissionEvidenceError):
            _verify(document)

    def test_sqlite_inventory_custody_and_wal_transitions(self):
        for index, mutate in enumerate(
            (
                lambda a: a["cron_inventory_after_add"]["store"]["database"].update(
                    inode=999
                ),
                lambda a: a["cron_inventory_after_add"]["store"][
                    "shared_memory"
                ].update(mode="644"),
                lambda a: a["cron_inventory_after_remove"]["store"][
                    "write_ahead_log"
                ].update(bytes=1),
                lambda a: a["cron_inventory_after_remove"]["store"][
                    "write_ahead_log"
                ].update(mtime_ns="1"),
                lambda a: a["cron_inventory_after_remove"]["store"][
                    "shared_memory"
                ].update(path="/tmp/openclaw.sqlite-shm"),
                lambda a: a["cron_inventory_after_remove"]["list"]["response"][
                    "value"
                ].update(total=1),
            )
        ):
            document = _fresh_document()
            mutate(document["action"]["observations"])
            _refresh_commands(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)


if __name__ == "__main__":
    unittest.main()
