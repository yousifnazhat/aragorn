from __future__ import annotations

import json
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

from aragorn import (
    admission_openclaw_final_v3_fresh_session_reset_subfixture as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest

_ROOT = Path(__file__).resolve().parents[1]
_verify = subject.verify_openclaw_final_v3_fresh_session_reset_semantic_compatibility


def _document():
    return json.loads((_ROOT / subject.old._EVIDENCE["path"]).read_bytes())[
        "route_observation"
    ]["document"]


def _refresh_commands(document):
    action = document["actions"][0]
    prerequisites, observed = action["prerequisites"], action["observations"]
    wrappers = [prerequisites["system_info"]]
    for name in ("initialization_turn", "rebuild_turn"):
        wrappers.extend(observed[name][key] for key in ("send", "wait"))
    for wrapper in wrappers:
        raw = (
            json.dumps(wrapper["response"]["value"], ensure_ascii=False) + "\n"
        ).encode()
        wrapper["command"].update(
            stdout_excerpt=raw.decode(),
            stdout_bytes=len(raw),
            stdout_digest=subject.old._digest(raw),
        )
    prerequisites["commands"][1] = deepcopy(prerequisites["system_info"]["command"])
    for name in ("initialization_turn", "rebuild_turn"):
        turn = observed[name]
        turn["commands"] = deepcopy([turn["send"]["command"], turn["wait"]["command"]])
    action["commands"] = deepcopy(
        observed["initialization_turn"]["commands"]
        + observed["rebuild_turn"]["commands"]
    )


def _fresh_document():
    """Coherent synthetic identities exercise compatibility, never capture freshness."""
    document = _document()
    action = document["actions"][0]
    pids = {
        command["pid"]: 20000 + index
        for index, command in enumerate(
            action["prerequisites"]["commands"] + action["commands"]
        )
    }
    observed = action["observations"]
    replacements = {
        document["run_nonce"]: "c" * 32,
        observed["session_before_reset"]["entry"][
            "session_id"
        ]: "11111111-1111-4111-8111-111111111111",
        observed["session_after_reset"]["entry"][
            "session_id"
        ]: "22222222-2222-4222-8222-222222222222",
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
        elif isinstance(value, list):
            return [shift(item) for item in value]
        elif type(value) is int and value >= 10**12:
            return value + 14 * 86400 * 1000
        elif type(value) is str:
            for before, after in replacements.items():
                value = value.replace(before, after)
            if value.startswith("2026-08-28T"):
                value = (
                    (datetime.fromisoformat(value) + timedelta(days=14))
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z")
                )
        return value

    document = shift(document)
    observed = document["actions"][0]["observations"]
    for index, name in enumerate(
        ("session_before_reset", "session_after_rotation", "session_after_reset"),
        start=1,
    ):
        observed[name]["file"].update(
            digest=subject.old._digest(f"synthetic-session-store-{index}".encode()),
            size=7000 + index,
        )
    prerequisites = document["actions"][0]["prerequisites"]
    prerequisites["gateway_process"].update(
        pid=12345, hostname="abcdef123456", start_time_ticks="987654321"
    )
    prerequisites["system_info"]["response"]["value"].update(
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


class FreshSessionResetSemanticTests(unittest.TestCase):
    def test_retained_and_coherent_fresh_input_confer_no_authority(self):
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
                "FRESH_SESSION_RESET_SEMANTIC_COMPATIBILITY_VERIFIED_NOT_OBSERVED_OR_QUALIFIED",
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

    def test_document_identity_and_trust_shapes_are_exact(self):
        for index, mutate in enumerate(
            (
                lambda d: d.update(run_nonce="invalid"),
                lambda d: d.update(implementation_digest="sha256:" + "0" * 64),
                lambda d: d.update(phase3_exit_eligible=True),
                lambda d: d["routes"][0].update(status="PASS"),
                lambda d: d["runtime_binding"].update(version="2026.7.2"),
                lambda d: d["actions"][0]["observations"].update(extra=None),
                lambda d: d["actions"][0].update(status="PASS"),
            )
        ):
            document = _fresh_document()
            mutate(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_protected_content_and_snapshot_predicates_remain_exact(self):
        for index, mutate in enumerate(
            (
                lambda d, p, o: d["protected_boundary"]["runtime"]["records"][0][
                    "mount_options"
                ].append("rw"),
                lambda d, p, o: d["protected_boundary"]["configuration"]["file"].update(
                    digest="sha256:" + "0" * 64
                ),
                lambda d, p, o: p["runtime_files"]["node"]["file"].update(size=1),
                lambda d, p, o: p["runtime_files"]["node"]["file"].update(nlink=2),
                lambda d, p, o: p["runtime_files"]["openclaw"]["file"].update(extra=0),
                lambda d, p, o: o["session_before_reset"]["entry"].update(
                    skill_names=["different-skill"]
                ),
                lambda d, p, o: o["session_before_reset"]["entry"]["prompt"].update(
                    digest="sha256:" + "0" * 64
                ),
                lambda d, p, o: o["session_after_reset"]["file"].update(
                    inode=o["session_before_reset"]["file"]["inode"]
                ),
                lambda d, p, o: o["session_after_reset"]["entry"].update(
                    snapshot_version=o["session_before_reset"]["entry"][
                        "snapshot_version"
                    ]
                    + 1
                ),
                lambda d, p, o: o["session_after_reset_check"].update(ready=1),
            )
        ):
            document = _fresh_document()
            action = document["actions"][0]
            mutate(document, action["prerequisites"], action["observations"])
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_reset_identity_and_cleared_snapshot_cannot_be_forged_by_summary(self):
        for index, mutate in enumerate(
            (
                lambda o: o["reset_turn"]["params"].update(deliver=True),
                lambda o: o["reset_turn"]["params"].update(message="arbitrary action"),
                lambda o: o["reset_turn"]["response"].update(runId="different-run"),
                lambda o: o["reset_turn"].update(scopes=["operator.admin"]),
                lambda o: o["session_after_rotation"]["entry"].update(
                    session_id=o["session_before_reset"]["entry"]["session_id"]
                ),
                lambda o: o["session_after_rotation"]["entry"].update(
                    snapshot_present=True
                ),
                lambda o: o["session_after_rotation"]["entry"]["prompt"].update(
                    bytes=0
                ),
                lambda o: o["session_after_rotation"]["entry"].update(runtime_ms=0),
                lambda o: o["session_after_rotation"]["entry"].update(updated_at=True),
                lambda o: o["session_after_rotation"]["entry"].update(
                    updated_at=o["session_before_reset"]["entry"]["updated_at"]
                ),
            )
        ):
            document = _fresh_document()
            mutate(document["actions"][0]["observations"])
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_command_identity_output_and_causality_are_bound(self):
        for index, mutate in enumerate(
            (
                lambda d, p, o: p["commands"][0].update(pid=True),
                lambda d, p, o: p["commands"][0].update(
                    pid=p["gateway_process"]["pid"]
                ),
                lambda d, p, o: o["rebuild_turn"]["send"]["command"].update(
                    pid=o["initialization_turn"]["send"]["command"]["pid"]
                ),
                lambda d, p, o: o["rebuild_turn"]["send"]["command"].update(
                    argv=["unexpected"]
                ),
                lambda d, p, o: o["rebuild_turn"]["wait"]["response"]["value"].update(
                    status="ok"
                ),
                lambda d, p, o: o["initialization_turn"]["wait"]["response"][
                    "value"
                ].update(error="different error"),
                lambda d, p, o: o["reset_turn"].update(started_at=d["recorded_at"]),
                lambda d, p, o: d.update(recorded_at=p["commands"][0]["started_at"]),
            )
        ):
            document = _fresh_document()
            action = document["actions"][0]
            mutate(document, action["prerequisites"], action["observations"])
            _refresh_commands(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)
        for key, value in (
            ("stdout_bytes", 1),
            ("stdout_digest", "sha256:" + "0" * 64),
        ):
            document = _fresh_document()
            command = document["actions"][0]["observations"]["rebuild_turn"]["wait"][
                "command"
            ]
            command[key] = value
            with self.subTest(key=key), self.assertRaises(AdmissionEvidenceError):
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
        ):
            document = _fresh_document()
            system = document["actions"][0]["prerequisites"]["system_info"]
            system["response"]["value"][key] = value
            _refresh_commands(document)
            with (
                self.subTest(key=key, value=value),
                self.assertRaises(AdmissionEvidenceError),
            ):
                _verify(document)


if __name__ == "__main__":
    unittest.main()
