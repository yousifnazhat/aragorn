from __future__ import annotations

import json
import unittest
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from aragorn import (
    admission_openclaw_final_v3_archive_replacement_subfixture as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest

_ROOT = Path(__file__).resolve().parents[1]
_verify = subject.verify_openclaw_final_v3_archive_replacement_semantic_compatibility


def _document():
    return json.loads((_ROOT / subject.old._EVIDENCE["path"]).read_bytes())[
        "route_observation"
    ]["document"]


def _refresh(document):
    action = document["action"]
    before, after = action["prerequisites"], action["observations"]
    for wrapper in (
        before["system_info"],
        before["discovery"],
        after["upload_begin"],
        after["upload_install"],
    ):
        raw = (
            json.dumps(wrapper["response"]["value"], ensure_ascii=False) + "\n"
        ).encode()
        wrapper["command"].update(
            stdout_excerpt=raw.decode(),
            stdout_bytes=len(raw),
            stdout_digest=subject.old._digest(raw),
        )
    action["commands"] = deepcopy(
        [
            before["version"],
            before["system_info"]["command"],
            before["positive_control"]["install"],
            before["discovery"]["command"],
            after["upload_begin"]["command"],
            after["upload_install"]["command"],
            after["source_install"]["command"],
            after["discovery_after"]["command"],
        ]
    )


def _origin(document, when=None, **fields):
    control = document["action"]["prerequisites"]["positive_control"]
    if when is None:
        when = subject._epoch_ms(control["install"]["started_at"])
    value = json.loads(subject._origin_bytes(when))
    value.update(fields)
    raw = (json.dumps(value, indent=2) + "\n").encode()
    control["target_after"]["entries"][2]["digest"] = subject.old._digest(raw)
    control["target_after"]["tree_digest"] = canonical_digest(
        control["target_after"]["entries"]
    )


def _fresh_document():
    """Synthetic identity rotation proves compatibility, never capture freshness."""
    document = _document()
    pid_map = {
        value["pid"]: 20000 + index
        for index, value in enumerate(document["action"]["commands"])
    }

    def shift(value):
        if type(value) is dict:
            for key, item in value.items():
                value[key] = shift(item)
            if "argv" in value:
                value["pid"] = pid_map[value["pid"]]
            if value.get("type") in ("file", "directory"):
                value["device"] += 1000
                value["inode"] += 1000
            if "root" in value and "tree_digest" in value:
                value["tree_digest"] = canonical_digest(value["entries"])
        elif type(value) is list:
            return [shift(item) for item in value]
        elif type(value) is str and value.startswith("2026-08-31T"):
            return (
                (datetime.fromisoformat(value) + timedelta(days=12))
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )
        return value

    document = shift(document)
    document["run_nonce"] = "c" * 32
    before, after = (
        document["action"]["prerequisites"],
        document["action"]["observations"],
    )
    for gateway in (before["gateway_process"], after["gateway_after"]):
        gateway.update(pid=12345, hostname="abcdef123456", start_time_ticks="987654321")
    for boundary in (document["protected_boundary"], after["boundary_after"]):
        for name in ("source", "probe"):
            boundary["inputs"][name]["records"][0].update(
                root=f"/docker/volumes/fresh-archive-{name}/_data", source="/dev/vdz1"
            )
    before["system_info"]["response"]["value"].update(
        pid=12345,
        hostname="abcdef123456",
        machineName="abcdef123456",
        release="6.8.0-fresh",
        osLabel="Linux 6.8.0-fresh",
        memoryTotalBytes=32_000_000_000,
        diskTotalBytes=64_000_000_000,
        cpuCount=2,
        loadAverage=[0, 0.5, 1],
    )
    _origin(document)
    _refresh(document)
    return document


def _sync_state(document):
    before, after = (
        document["action"]["prerequisites"],
        document["action"]["observations"],
    )
    for name in ("source", "target_before"):
        before[name]["tree_digest"] = canonical_digest(before[name]["entries"])
    for left, right in (
        ("source", "source_after"),
        ("target_before", "target_after"),
        ("gateway_process", "gateway_after"),
    ):
        after[right] = deepcopy(before[left])
    after["boundary_after"] = deepcopy(document["protected_boundary"])
    after["boundary_after"]["roots"]["workspace_skills"]["observation"].update(
        entries=["template-skill"], entry_count=1, nlink=3
    )
    _refresh(document)


class ArchiveReplacementSemanticTests(unittest.TestCase):
    def test_retained_and_fresh_inputs_confer_no_authority(self):
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
            self.assertFalse(result["route_semantics"]["pass_authority"])
            self.assertFalse(
                result["route_semantics"]["native_independent_route_execution_verified"]
            )
        for edge in ("started_at", "completed_at"):
            document = _fresh_document()
            _origin(
                document,
                subject._epoch_ms(
                    document["action"]["prerequisites"]["positive_control"]["install"][
                        edge
                    ]
                ),
            )
            _verify(document)

    def test_exact_shapes_scalars_and_authority(self):
        for index, mutate in enumerate(
            (
                lambda d: d.update(extra=0),
                lambda d: d.update(phase3_exit_eligible=True),
                lambda d: d.update(implementation_digest="sha256:" + "0" * 64),
                lambda d: d["route"].update(status="PASS"),
                lambda d: d["action"]["prerequisites"]["positive_control"].update(
                    extra=0
                ),
                lambda d: d["action"]["observations"]["source_install"].update(extra=0),
                lambda d: d["action"]["observations"]["discovery_after"][
                    "response"
                ].update(parsed=True),
                lambda d: d["protected_boundary"]["effective_identity"].update(
                    uid=False
                ),
                lambda d: d["protected_boundary"]["configuration"]["file"].update(
                    inode=True
                ),
                lambda d: d["action"]["prerequisites"]["system_info"]["response"][
                    "value"
                ].update(loadAverage=[0, float("nan"), 0]),
            )
        ):
            document = _fresh_document()
            mutate(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_coherent_custody_and_source_mutations_rejected(self):
        for index, mutate in enumerate(
            (
                lambda d: d["action"]["prerequisites"]["source"]["entries"][0].update(
                    digest="sha256:" + "0" * 64
                ),
                lambda d: d["action"]["prerequisites"]["source"]["entries"][0].update(
                    size=145
                ),
                lambda d: d["action"]["prerequisites"]["target_before"]["entries"][
                    0
                ].update(mode="644"),
                lambda d: d["action"]["prerequisites"]["source"]["root"].update(
                    device=999
                ),
                lambda d: d["protected_boundary"]["configuration"]["file"].update(
                    digest="sha256:" + "0" * 64
                ),
                lambda d: d["protected_boundary"]["inputs"]["source"]["records"][0][
                    "mount_options"
                ].append("rw"),
                lambda d: d["protected_boundary"]["inputs"]["source"]["records"][
                    0
                ].update(root="/unexpected"),
                lambda d: d["protected_boundary"]["inputs"]["probe"]["entry"].update(
                    uid=992
                ),
                lambda d: d["action"]["prerequisites"]["openclaw"].update(extra=0),
                lambda d: d["action"]["prerequisites"]["system_info"]["response"][
                    "value"
                ].update(nodeVersion="v24.17.0"),
            )
        ):
            document = _fresh_document()
            mutate(document)
            _sync_state(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_denials_and_exact_allowed_residue(self):
        for index, mutate in enumerate(
            (
                lambda a: a["upload_begin"]["response"]["value"]["error"].update(
                    code="FORBIDDEN"
                ),
                lambda a: a["upload_install"]["command"]["argv"].__setitem__(-1, "{}"),
                lambda a: a["source_install"]["command"].update(exit_code=1),
                lambda a: a["discovery_after"]["command"].update(exit_code=0),
                lambda a: a.update(staging_after=["unexpected"]),
                lambda a: a["boundary_after"]["roots"]["workspace_skills"][
                    "observation"
                ].update(entries=[], entry_count=0, nlink=2),
                lambda a: a["boundary_after"]["roots"]["extensions"][
                    "observation"
                ].update(entries=["template-skill"], entry_count=1, nlink=3),
                lambda a: a["boundary_after"]["roots"]["workspace_skills"][
                    "observation"
                ].update(inode=999),
            )
        ):
            document = _fresh_document()
            mutate(document["action"]["observations"])
            _refresh(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_eight_command_output_pid_and_chronology_joins(self):
        for index, mutate in enumerate(
            (
                lambda d: d["action"]["commands"].pop(),
                lambda d: d["action"]["commands"][0].update(pid=9999),
                lambda d: d["action"]["prerequisites"]["positive_control"][
                    "install"
                ].update(pid=12345),
                lambda d: d["action"]["prerequisites"]["positive_control"][
                    "install"
                ].update(started_at="2026-09-12T00:00:00Z"),
                lambda d: d["action"]["observations"]["source_install"][
                    "command"
                ].update(stdout_bytes=10000),
                lambda d: d["action"]["observations"]["discovery_after"][
                    "command"
                ].update(stderr_digest="sha256:" + "0" * 64),
                lambda d: d.update(recorded_at="2026-09-12T00:00:00Z"),
            )
        ):
            document = _fresh_document()
            mutate(document)
            if index >= 2:
                _refresh(document)
            with self.subTest(index=index), self.assertRaises(AdmissionEvidenceError):
                _verify(document)

    def test_origin_content_interval_and_resource_bound(self):
        for edge, offset in (("started_at", -1), ("completed_at", 1)):
            document = _fresh_document()
            control = document["action"]["prerequisites"]["positive_control"]
            _origin(document, subject._epoch_ms(control["install"][edge]) + offset)
            with self.subTest(edge=edge), self.assertRaises(AdmissionEvidenceError):
                _verify(document)
        for fields in ({"slug": "another-skill"}, {"source": "file"}, {"version": 2}):
            document = _fresh_document()
            _origin(document, **fields)
            with self.subTest(fields=fields), self.assertRaises(AdmissionEvidenceError):
                _verify(document)
        document = _fresh_document()
        control = document["action"]["prerequisites"]["positive_control"]
        control["install"].update(
            started_at="2000-01-01T00:00:00.000Z",
            completed_at="2000-01-01T00:00:00.001Z",
        )
        _origin(document)
        self.assertEqual(control["target_after"]["entries"][2]["size"], 133)
        self.assertEqual(
            len(
                subject._origin_bytes(
                    subject._epoch_ms(control["install"]["started_at"])
                )
            ),
            132,
        )
        with self.assertRaises(AdmissionEvidenceError):
            subject._verify_positive_control(control)
        control["install"].update(
            started_at="2026-09-12T00:00:00.000Z",
            completed_at="2026-09-12T00:01:00.001Z",
        )
        with (
            patch.object(
                subject,
                "_origin_bytes",
                side_effect=AssertionError("enumerated overlong interval"),
            ),
            self.assertRaisesRegex(
                AdmissionEvidenceError, "bounded origin timestamp interval"
            ),
        ):
            subject._verify_positive_control(control)


if __name__ == "__main__":
    unittest.main()
