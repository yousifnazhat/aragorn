from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from aragorn.vendor_reports import (  # noqa: E402
    VendorReportError,
    normalize_cisco_report,
    normalize_nvidia_report,
)


SUBJECT = "sha256:" + "a" * 64
POLICY = "7e571f3db6d7aa3d0c8a40e9ae8f8f6a0f0a721fe518e59f71943a11b418c91f"


def encode(document: object) -> bytes:
    return json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode()


def cisco_report(*, rule_id: str = "DATA_EXFIL_HTTP_POST") -> dict:
    return {
        "skill_name": "example",
        "skill_path": "/workspace",
        "is_safe": False,
        "max_severity": "HIGH",
        "findings_count": 1,
        "findings": [
            {
                "id": "finding-1",
                "rule_id": rule_id,
                "category": "data_exfiltration",
                "severity": "HIGH",
                "title": "Outbound transfer",
                "description": "Data may leave the workspace.",
                "file_path": "/workspace/scripts/run.py",
                "line_number": 7,
                "snippet": "secret text that must not be retained",
                "remediation": "Remove the transfer.",
                "analyzer": "static",
                "metadata": {
                    "scan_policy_name": "strict",
                    "scan_policy_version": "1.0",
                    "scan_policy_preset_base": "strict",
                    "scan_policy_fingerprint_sha256": POLICY,
                },
            }
        ],
        "scan_duration_seconds": 0.125,
        "duration_ms": 125,
        "analyzers_used": [
            "static_analyzer",
            "bytecode",
            "pipeline",
            "behavioral_analyzer",
        ],
        "timestamp": "2026-07-22T12:00:00+00:00",
        "scan_metadata": {
            "policy_name": "strict",
            "policy_version": "1.0",
            "policy_preset_base": "strict",
            "policy_fingerprint_sha256": POLICY,
        },
    }


def nvidia_issue(*, rule_id: str = "PE3") -> dict:
    return {
        "id": rule_id,
        "category": "privilege_escalation",
        "pattern": "dangerous-call",
        "severity": "HIGH",
        "confidence": 0.9,
        "location": {"file": "scripts/run.py", "start_line": 7, "end_line": 8},
        "finding": "secret matched text",
        "explanation": "The script invokes a privileged operation.",
        "remediation": "Remove the operation.",
        "code_snippet": "do_not_retain()",
        "intent": None,
        "tags": ["static"],
    }


def nvidia_report(*, score: int = 60, before: int = 1) -> dict:
    recommendation = "DO_NOT_INSTALL" if score >= 51 else "CAUTION" if score >= 21 else "SAFE"
    severity = "CRITICAL" if score >= 81 else "HIGH" if score >= 51 else "MEDIUM" if score >= 21 else "LOW"
    dropped = before - 1
    limitations = ["LLM meta-analysis was disabled (--no-llm)"]
    if dropped:
        limitations.append(
            f"{dropped} finding(s) filtered by meta-analyzer or heuristics"
        )
    return {
        "skill": {
            "name": "example",
            "source": "/workspace",
            "scanned_at": "2026-07-22T12:00:00+00:00",
        },
        "risk_assessment": {
            "score": score,
            "severity": severity,
            "recommendation": recommendation,
        },
        "components": [
            {
                "path": "scripts/run.py",
                "type": "python",
                "lines": 10,
                "executable": True,
                "size_bytes": 100,
            }
        ],
        "issues": [nvidia_issue()],
        "suppressed_count": 0,
        "suppressed": [],
        "metadata": {
            "has_executable_scripts": True,
            "skillspector_version": "2.4.3",
            "llm_requested": False,
            "llm_available": False,
            "meta_analysis_applied": False,
            "filtering_mode": "heuristic",
        },
        "analysis_completeness": {
            "total_components": 1,
            "scanned_components": 1,
            "coverage_percent": 100.0,
            "llm_analysis": "skipped",
            "findings_before_filtering": before,
            "findings_after_filtering": 1,
            "limitations": limitations,
            "is_complete": False,
        },
    }


class CiscoVendorReportTests(unittest.TestCase):
    def test_success_binds_report_and_omits_snippet(self) -> None:
        raw = encode(cisco_report())

        observations = normalize_cisco_report(
            raw, subject_digest=SUBJECT, returncode=0
        )

        self.assertEqual(
            [item.reason_code for item in observations],
            ["CISCO_DATA_EXFIL_HTTP_POST", "CISCO_SCAN_COMPLETED"],
        )
        expected_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        for item in observations:
            self.assertIn(expected_digest, item.document_json)
            self.assertNotIn("secret text", item.document_json)
        finding = json.loads(observations[0].document_json)
        self.assertEqual(
            finding["evidence"]["finding"]["file_path"], "scripts/run.py"
        )

    def test_semantically_duplicate_findings_have_unique_observation_digests(
        self,
    ) -> None:
        report = cisco_report()
        duplicate = copy.deepcopy(report["findings"][0])
        duplicate["snippet"] = "different raw evidence, same observation"
        report["findings"].append(duplicate)
        report["findings_count"] = 2

        observations = normalize_cisco_report(
            encode(report), subject_digest=SUBJECT, returncode=0
        )
        digests = [
            hashlib.sha256(observation.document_json.encode("ascii")).digest()
            for observation in observations
        ]

        self.assertEqual(len(digests), len(set(digests)))
        self.assertEqual(
            [observation.reason_code for observation in observations],
            ["CISCO_DATA_EXFIL_HTTP_POST", "CISCO_SCAN_COMPLETED"],
        )

    def test_completeness_path_and_unknown_fields_fail_closed(self) -> None:
        variants = []
        missing_analyzer = cisco_report()
        missing_analyzer["analyzers_used"].pop()
        variants.append(missing_analyzer)
        escaped = cisco_report()
        escaped["findings"][0]["file_path"] = "/etc/passwd"
        variants.append(escaped)
        unknown = cisco_report()
        unknown["unexpected"] = True
        variants.append(unknown)
        wrong_count = cisco_report()
        wrong_count["findings_count"] = 0
        variants.append(wrong_count)
        for report in variants:
            with self.subTest(report=report), self.assertRaises(VendorReportError):
                normalize_cisco_report(
                    encode(report), subject_digest=SUBJECT, returncode=0
                )

    def test_rule_specific_metadata_is_bounded_and_not_retained(self) -> None:
        report = cisco_report()
        report["findings"][0]["metadata"] = {
            "matched_string": "$ssh_key_exfil",
            "threat_type": "TOOL CHAINING ABUSE",
            "yara_namespace": "tool_chaining_abuse_generic",
            "yara_rule": "tool_chaining_abuse_generic",
        }
        observations = normalize_cisco_report(
            encode(report), subject_digest=SUBJECT, returncode=0
        )

        self.assertNotIn("matched_string", observations[0].document_json)
        report["findings"][0]["metadata"] = {"large": "x" * (64 * 1024)}
        with self.assertRaises(VendorReportError):
            normalize_cisco_report(
                encode(report), subject_digest=SUBJECT, returncode=0
            )

    def test_noncanonical_rule_ids_use_collision_safe_full_hashes(self) -> None:
        first = normalize_cisco_report(
            encode(cisco_report(rule_id="unsafe-rule")),
            subject_digest=SUBJECT,
            returncode=0,
        )[0].reason_code
        second = normalize_cisco_report(
            encode(cisco_report(rule_id="unsafe_rule")),
            subject_digest=SUBJECT,
            returncode=0,
        )[0].reason_code

        self.assertRegex(first, r"^CISCO_RULE_SHA256_[0-9A-F]{64}$")
        self.assertRegex(second, r"^CISCO_RULE_SHA256_[0-9A-F]{64}$")
        self.assertNotEqual(first, second)

    def test_reserved_rule_id_is_hashed(self) -> None:
        observations = normalize_cisco_report(
            encode(cisco_report(rule_id="SCAN_COMPLETED")),
            subject_digest=SUBJECT,
            returncode=0,
        )

        self.assertRegex(
            observations[0].reason_code, r"^CISCO_RULE_SHA256_[0-9A-F]{64}$"
        )
        self.assertEqual(observations[1].reason_code, "CISCO_SCAN_COMPLETED")

    def test_malformed_severity_and_duration_are_typed_errors(self) -> None:
        malformed_severity = cisco_report()
        malformed_severity["findings"][0]["severity"] = []
        huge_duration = cisco_report()
        huge_duration["scan_duration_seconds"] = 1e308
        huge_duration["duration_ms"] = 0
        for report in (malformed_severity, huge_duration):
            with self.subTest(report=report), self.assertRaises(VendorReportError):
                normalize_cisco_report(
                    encode(report), subject_digest=SUBJECT, returncode=0
                )


class NvidiaVendorReportTests(unittest.TestCase):
    def test_success_binds_report_and_omits_snippets(self) -> None:
        raw = encode(nvidia_report())

        observations = normalize_nvidia_report(
            raw, subject_digest=SUBJECT, returncode=1
        )

        self.assertEqual(
            [item.reason_code for item in observations],
            [
                "NVIDIA_AGGREGATE_RISK_HIGH",
                "NVIDIA_ANALYSIS_INCOMPLETE",
                "NVIDIA_PE3",
                "NVIDIA_SCAN_COMPLETED",
            ],
        )
        expected_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        for item in observations:
            self.assertIn(expected_digest, item.document_json)
            self.assertNotIn("secret matched text", item.document_json)
            self.assertNotIn("do_not_retain", item.document_json)

    def test_filtering_is_explicit_medium_evidence(self) -> None:
        raw = encode(nvidia_report(before=3))

        observations = normalize_nvidia_report(
            raw, subject_digest=SUBJECT, returncode=1
        )

        filtered = next(
            item
            for item in observations
            if item.reason_code == "NVIDIA_FINDINGS_FILTERED"
        )
        self.assertEqual(filtered.severity, "medium")
        document = json.loads(filtered.document_json)
        self.assertEqual(document["evidence"]["findings_filtered"], 2)

    def test_path_coverage_suppression_and_exit_coherence_fail_closed(self) -> None:
        variants: list[tuple[dict, int]] = []
        escaped = nvidia_report()
        escaped["issues"][0]["location"]["file"] = "../outside.py"
        variants.append((escaped, 1))
        partial = nvidia_report()
        partial["analysis_completeness"]["scanned_components"] = 0
        partial["analysis_completeness"]["coverage_percent"] = 0
        variants.append((partial, 1))
        suppressed = nvidia_report()
        suppressed["suppressed_count"] = 1
        suppressed["suppressed"] = [{"id": "hidden"}]
        variants.append((suppressed, 1))
        variants.append((nvidia_report(score=50), 1))
        variants.append((nvidia_report(score=51), 0))
        for report, returncode in variants:
            with self.subTest(report=report), self.assertRaises(VendorReportError):
                normalize_nvidia_report(
                    encode(report),
                    subject_digest=SUBJECT,
                    returncode=returncode,
                )

    def test_reason_hash_is_stable_and_collision_safe(self) -> None:
        one = nvidia_report()
        one["issues"][0] = nvidia_issue(rule_id="rule-one")
        two = copy.deepcopy(one)
        two["issues"][0]["id"] = "rule_one"

        first = next(
            observation.reason_code
            for observation in normalize_nvidia_report(
                encode(one), subject_digest=SUBJECT, returncode=1
            )
            if observation.reason_code.startswith("NVIDIA_RULE_SHA256_")
        )
        second = next(
            observation.reason_code
            for observation in normalize_nvidia_report(
                encode(two), subject_digest=SUBJECT, returncode=1
            )
            if observation.reason_code.startswith("NVIDIA_RULE_SHA256_")
        )

        self.assertRegex(first, r"^NVIDIA_RULE_SHA256_[0-9A-F]{64}$")
        self.assertRegex(second, r"^NVIDIA_RULE_SHA256_[0-9A-F]{64}$")
        self.assertNotEqual(first, second)

    def test_reserved_rule_id_is_hashed(self) -> None:
        report = nvidia_report()
        report["issues"][0]["id"] = "FINDINGS_FILTERED"
        observations = normalize_nvidia_report(
            encode(report), subject_digest=SUBJECT, returncode=1
        )

        hashed = next(
            observation.reason_code
            for observation in observations
            if observation.reason_code.startswith("NVIDIA_RULE_SHA256_")
        )
        self.assertRegex(hashed, r"^NVIDIA_RULE_SHA256_[0-9A-F]{64}$")

    def test_malformed_severity_is_a_typed_error(self) -> None:
        report = nvidia_report()
        report["issues"][0]["severity"] = {}
        with self.assertRaises(VendorReportError):
            normalize_nvidia_report(
                encode(report), subject_digest=SUBJECT, returncode=1
            )

    def test_incomplete_and_unexplained_high_risk_never_reduce_to_completion(self) -> None:
        for score, returncode, expected in (
            (0, 0, {"NVIDIA_ANALYSIS_INCOMPLETE", "NVIDIA_SCAN_COMPLETED"}),
            (
                100,
                1,
                {
                    "NVIDIA_AGGREGATE_RISK_HIGH",
                    "NVIDIA_ANALYSIS_INCOMPLETE",
                    "NVIDIA_SCAN_COMPLETED",
                },
            ),
        ):
            report = nvidia_report(score=score, before=1)
            report["issues"] = []
            report["analysis_completeness"]["findings_before_filtering"] = 0
            report["analysis_completeness"]["findings_after_filtering"] = 0
            observations = normalize_nvidia_report(
                encode(report), subject_digest=SUBJECT, returncode=returncode
            )
            self.assertEqual(
                {observation.reason_code for observation in observations}, expected
            )


class VendorJsonBoundaryTests(unittest.TestCase):
    def test_malformed_duplicate_and_nonfinite_json_fail_closed(self) -> None:
        malformed = b"{"
        duplicate = b'{"skill":{},"skill":{}}'
        nonfinite = (
            b'{"skill":{},"risk_assessment":{"score":NaN},'
            b'"components":[],"issues":[],"suppressed_count":0,"suppressed":[],'
            b'"metadata":{},"analysis_completeness":{}}'
        )
        overflow_float = nonfinite.replace(b"NaN", b"1e999")
        for raw in (malformed, duplicate, nonfinite, overflow_float):
            with self.subTest(raw=raw), self.assertRaises(VendorReportError):
                normalize_nvidia_report(
                    raw, subject_digest=SUBJECT, returncode=0
                )

    def test_input_size_is_bounded_before_parsing(self) -> None:
        with patch("aragorn.vendor_reports.MAX_VENDOR_REPORT_BYTES", 8):
            with self.assertRaisesRegex(VendorReportError, "byte limit"):
                normalize_cisco_report(
                    b" " * 9, subject_digest=SUBJECT, returncode=0
                )


if __name__ == "__main__":
    unittest.main()
