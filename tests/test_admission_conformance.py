from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from datetime import datetime
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

from aragorn.admission_conformance import (
    MANDATORY_ADMISSION_SCENARIOS,
    AdmissionConformanceError,
)
from aragorn.admission_gate import validate_retained_admission_conformance
from aragorn.cas import CAS

_EVIDENCE_RAW = b'{"schema":"aragorn/test-admission-evidence/v1"}'
_DIGEST = f"sha256:{hashlib.sha256(_EVIDENCE_RAW).hexdigest()}"
_ROOT = Path(__file__).resolve().parents[1]


def _sha256(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _canonical_digest(document: object) -> str:
    return _sha256(
        json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    )


def _result(status: str = "PASS") -> dict[str, object]:
    reasons = [] if status == "PASS" else ["TEST_INCOMPLETE"]
    evidence = [_DIGEST] if status in {"PASS", "FAIL"} else []
    return {
        "schema": "aragorn/admission-conformance-result/v1",
        "profile": "admission-conformant/v1",
        "recorded_at": "2026-07-27T00:00:00Z",
        "bindings": {
            "runtime": {
                "name": "example-runtime",
                "version": "1.0.0",
                "repository_url": "https://github.com/example/runtime",
                "commit": "1" * 40,
                "source_tree_digest": _DIGEST,
            },
            "adapter": {
                "name": "example-adapter",
                "implementation_digest": _DIGEST,
                "configuration_digest": _DIGEST,
            },
            "environment": {
                "worker_digest": _DIGEST,
                "os_profile_digest": _DIGEST,
            },
            "aragorn": {
                "implementation_digest": _DIGEST,
                "policy_digest": _DIGEST,
            },
        },
        "properties": [
            {
                "id": property_id,
                "status": status,
                "scenarios": [
                    {
                        "id": scenario_id,
                        "status": status,
                        "evidence_digests": evidence.copy(),
                        "reason_codes": reasons.copy(),
                    }
                    for scenario_id in scenario_ids
                ],
            }
            for property_id, scenario_ids in MANDATORY_ADMISSION_SCENARIOS.items()
        ],
        "decision": {
            "status": status,
            "installer_work_eligible": status == "PASS",
        },
    }


class AdmissionConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(prefix="aragorn-admission-gate-test-")
        self.addCleanup(self.temporary.cleanup)
        self.cas = CAS(self.temporary.name)
        self.assertEqual(
            self.cas.put(BytesIO(_EVIDENCE_RAW), max_bytes=len(_EVIDENCE_RAW)),
            _DIGEST,
        )

    def test_all_mandatory_scenarios_cannot_grant_authority_yet(self) -> None:
        with self.assertRaisesRegex(
            AdmissionConformanceError,
            "installer authority remains disabled",
        ):
            validate_retained_admission_conformance(
                _result(),
                evidence_cas=self.cas,
            )

    def test_not_tested_cannot_authorize_installer_work(self) -> None:
        document = _result("NOT_TESTED")
        document["decision"]["installer_work_eligible"] = True
        with self.assertRaisesRegex(
            AdmissionConformanceError,
            "installer eligibility",
        ):
            validate_retained_admission_conformance(document)

    def test_one_failed_scenario_fails_property_and_profile(self) -> None:
        document = _result()
        failed = document["properties"][2]["scenarios"][3]
        failed.update(
            {
                "status": "FAIL",
                "reason_codes": ["RENAME_BYPASS"],
            }
        )
        document["properties"][2]["status"] = "FAIL"
        document["decision"] = {
            "status": "FAIL",
            "installer_work_eligible": False,
        }
        self.assertEqual(
            validate_retained_admission_conformance(
                document,
                evidence_cas=self.cas,
            ),
            "FAIL",
        )

    def test_evidence_bearing_result_requires_retained_cas(self) -> None:
        with self.assertRaisesRegex(
            AdmissionConformanceError,
            "retained evidence CAS",
        ):
            validate_retained_admission_conformance(_result("FAIL"))

    def test_missing_retained_evidence_is_rejected(self) -> None:
        document = _result("FAIL")
        missing = "sha256:" + "2" * 64
        for item in document["properties"]:
            for scenario in item["scenarios"]:
                scenario["evidence_digests"] = [missing]
        with self.assertRaisesRegex(
            AdmissionConformanceError,
            "cannot verify retained evidence",
        ):
            validate_retained_admission_conformance(
                document,
                evidence_cas=self.cas,
            )

    def test_evidence_digest_must_be_canonical(self) -> None:
        document = _result("FAIL")
        document["properties"][0]["scenarios"][0]["evidence_digests"] = ["not-a-digest"]
        with self.assertRaisesRegex(
            AdmissionConformanceError,
            "canonical SHA-256",
        ):
            validate_retained_admission_conformance(
                document,
                evidence_cas=self.cas,
            )

    def test_missing_activation_path_is_rejected(self) -> None:
        document = _result()
        document["properties"][2]["scenarios"].pop()
        with self.assertRaisesRegex(
            AdmissionConformanceError,
            "every mandatory path",
        ):
            validate_retained_admission_conformance(
                document,
                evidence_cas=self.cas,
            )

    def test_forged_aggregate_pass_is_rejected(self) -> None:
        document = _result("NOT_TESTED")
        document["decision"] = {
            "status": "PASS",
            "installer_work_eligible": True,
        }
        with self.assertRaisesRegex(
            AdmissionConformanceError,
            "profile status",
        ):
            validate_retained_admission_conformance(document)

    def test_evidence_and_reasons_must_be_canonical(self) -> None:
        document = deepcopy(_result())
        scenario = document["properties"][0]["scenarios"][0]
        scenario["evidence_digests"] = [
            _DIGEST,
            "sha256:" + "2" * 64,
        ]
        with self.assertRaisesRegex(
            AdmissionConformanceError,
            "sorted and unique",
        ):
            validate_retained_admission_conformance(
                document,
                evidence_cas=self.cas,
            )

    def test_retained_openclaw_elimination_result_is_bound(self) -> None:
        evidence_path = (
            _ROOT
            / "benchmark"
            / "evidence"
            / "openclaw-v2026.7.1-admission-probe-2026-07-27.json"
        )
        receipt_path = (
            _ROOT
            / "benchmark"
            / "receipts"
            / "phase1-openclaw-admission-probe-2026-07-27.json"
        )
        evidence_raw = evidence_path.read_bytes()
        evidence = json.loads(evidence_raw)
        receipt = json.loads(receipt_path.read_bytes())
        evidence_digest = _sha256(evidence_raw)
        self.assertEqual(
            self.cas.put(BytesIO(evidence_raw), max_bytes=len(evidence_raw)),
            evidence_digest,
        )

        self.assertEqual(
            validate_retained_admission_conformance(
                receipt,
                evidence_cas=self.cas,
            ),
            "FAIL",
        )
        self.assertEqual(receipt["recorded_at"], evidence["recorded_at"])
        self.assertEqual(evidence["decision"]["status"], "FAIL")
        self.assertTrue(evidence["decision"]["candidate_eliminated"])
        self.assertEqual(
            {scenario["id"]: scenario["status"] for scenario in evidence["scenarios"]},
            {"ADM-02/install": "PASS", "ADM-02/direct-write": "FAIL"},
        )
        self.assertEqual(
            {
                digest
                for item in receipt["properties"]
                for scenario in item["scenarios"]
                for digest in scenario["evidence_digests"]
            },
            {evidence_digest},
        )

        bindings = receipt["bindings"]
        self.assertEqual(
            bindings["runtime"]["source_tree_digest"],
            evidence["runtime"]["runtime_tree"]["tree_digest"],
        )
        self.assertEqual(
            evidence["runtime"]["package_runtime_match"],
            {
                "checked_files": evidence["runtime"]["source_tree"]["file_count"],
                "status": "MATCH",
            },
        )
        self.assertEqual(
            bindings["adapter"]["implementation_digest"],
            _sha256(
                (
                    _ROOT
                    / "benchmark"
                    / "admission"
                    / "openclaw-v2026.7.1"
                    / "probe.mjs"
                ).read_bytes()
            ),
        )
        self.assertEqual(
            bindings["adapter"]["implementation_digest"],
            evidence["adapter"]["implementation_digest"],
        )
        self.assertEqual(
            bindings["adapter"]["configuration_digest"],
            _canonical_digest(evidence["adapter"]["configuration"]),
        )
        self.assertEqual(
            bindings["adapter"]["configuration_digest"],
            evidence["adapter"]["configuration_digest"],
        )
        effective = evidence["environment"]["effective_container"]
        isolation = evidence["environment"]["isolation"]
        self.assertEqual(
            (
                isolation["capabilities"],
                effective["cap_drop"],
                effective["devices"],
                effective["privileged"],
                effective["exit_code"],
            ),
            ([], ["ALL"], [], False, 0),
        )
        self.assertEqual(
            bindings["environment"]["worker_digest"],
            effective["image_platform_manifest_digest"],
        )
        self.assertEqual(
            bindings["environment"]["os_profile_digest"],
            _canonical_digest(isolation),
        )
        self.assertEqual(
            bindings["environment"]["os_profile_digest"],
            evidence["environment"]["os_profile_digest"],
        )
        self.assertEqual(
            {
                "cpus": effective["nano_cpus"] // 1_000_000_000,
                "memory_bytes": effective["memory_bytes"],
                "network": effective["network_mode"],
                "no_new_privileges": effective["no_new_privileges"],
                "nofile": effective["ulimits"][0]["hard"],
                "pids": effective["pids_limit"],
                "root_filesystem": (
                    "read-only" if effective["read_only_rootfs"] else "writable"
                ),
                "runtime_volume": (
                    "read-only"
                    if all(mount["read_only"] for mount in effective["mounts"])
                    else "writable"
                ),
                "tmpfs": f"/tmp:{effective['tmpfs']['/tmp']}",
                "user": effective["user"],
            },
            {key: isolation[key] for key in isolation if key != "capabilities"},
        )
        self.assertEqual(
            bindings["aragorn"]["implementation_digest"],
            _sha256((_ROOT / "src" / "aragorn" / "admission_conformance.py").read_bytes()),
        )
        self.assertEqual(
            bindings["aragorn"]["implementation_digest"],
            evidence["aragorn"]["implementation_digest"],
        )
        expected_policy = {
            "aggregate": {
                "fail_if_any": "FAIL",
                "not_tested_if_any_and_no_fail": "NOT_TESTED",
                "pass_only_if_all": "PASS",
            },
            "mandatory_scenarios": {
                key: list(value) for key, value in MANDATORY_ADMISSION_SCENARIOS.items()
            },
            "profile": "admission-conformant/v1",
        }
        self.assertEqual(evidence["aragorn"]["policy"], expected_policy)
        self.assertEqual(
            bindings["aragorn"]["policy_digest"],
            _canonical_digest(expected_policy),
        )
        self.assertEqual(
            bindings["aragorn"]["policy_digest"],
            evidence["aragorn"]["policy_digest"],
        )

    def test_retained_openclaw_contained_profile_is_partial_and_bound(self) -> None:
        evidence_dir = _ROOT / "benchmark" / "evidence"
        probe_raw = (
            evidence_dir
            / "openclaw-v2026.7.1-contained-profile-probe-2026-07-27.json"
        ).read_bytes()
        environment_raw = (
            evidence_dir
            / "openclaw-v2026.7.1-contained-profile-environment-2026-07-27.json"
        ).read_bytes()
        probe = json.loads(probe_raw)
        environment = json.loads(environment_raw)
        receipt = json.loads(
            (
                _ROOT
                / "benchmark"
                / "receipts"
                / "phase1-openclaw-contained-profile-probe-2026-07-27.json"
            ).read_bytes()
        )
        evidence_digests = sorted((_sha256(environment_raw), _sha256(probe_raw)))
        for raw, digest in (
            (environment_raw, evidence_digests[0]),
            (probe_raw, evidence_digests[1]),
        ):
            self.assertEqual(
                self.cas.put(BytesIO(raw), max_bytes=len(raw)),
                digest,
            )

        self.assertEqual(
            validate_retained_admission_conformance(
                receipt,
                evidence_cas=self.cas,
            ),
            "NOT_TESTED",
        )
        self.assertEqual(
            receipt["decision"],
            {"status": "NOT_TESTED", "installer_work_eligible": False},
        )
        formal = {
            f"{item['id']}/{scenario['id']}": scenario
            for item in receipt["properties"]
            for scenario in item["scenarios"]
        }
        self.assertEqual(
            {key: value["status"] for key, value in formal.items()},
            {
                "DET-01/identical-canonical-input-replay": "NOT_TESTED",
                "ADM-01/exact-admitted-bytes": "NOT_TESTED",
                "ADM-02/install": "PASS",
                "ADM-02/update": "NOT_TESTED",
                "ADM-02/direct-write": "PASS",
                "ADM-02/rename": "PASS",
                "ADM-02/symlink": "PASS",
                "ADM-02/auto-discovery": "PASS",
                "ADM-02/reload": "NOT_TESTED",
                "ADM-02/restart": "NOT_TESTED",
                "ADM-03/policy-failure": "NOT_TESTED",
                "ADM-03/policy-tampering": "NOT_TESTED",
            },
        )
        self.assertEqual(
            {
                key: value["reason_codes"]
                for key, value in formal.items()
                if value["status"] == "NOT_TESTED"
            },
            {
                "DET-01/identical-canonical-input-replay": [
                    "IDENTICAL_REPLAY_NOT_TESTED"
                ],
                "ADM-01/exact-admitted-bytes": [
                    "EXACT_ACTIVATED_BYTES_NOT_TESTED"
                ],
                "ADM-02/update": ["UPDATE_PATH_NOT_TESTED"],
                "ADM-02/reload": ["LIVE_RELOAD_NOT_TESTED"],
                "ADM-02/restart": ["RUNTIME_RESTART_NOT_TESTED"],
                "ADM-03/policy-failure": ["POLICY_FAILURE_NOT_TESTED"],
                "ADM-03/policy-tampering": ["POLICY_TAMPERING_NOT_TESTED"],
            },
        )
        for scenario in formal.values():
            if scenario["status"] == "PASS":
                self.assertEqual(scenario["evidence_digests"], evidence_digests)

        self.assertEqual(_sha256(probe_raw), "sha256:a81138e1bec12e0471068aafe4eee0b625635de5d39ba6bc3665d8251b76f6af")
        self.assertEqual(len(probe_raw), 20_607)
        self.assertEqual(
            {item["id"]: item["status"] for item in probe["scenarios"]},
            {
                "ADM-01/exact-admitted-bytes": "PASS",
                "ADM-02/install": "PASS",
                "ADM-02/direct-write": "PASS",
                "ADM-02/rename": "PASS",
                "ADM-02/symlink": "PASS",
                "ADM-02/auto-discovery": "PASS",
                "ADM-02/restart": "PASS",
            },
        )
        self.assertEqual(
            probe["decision"],
            {"installer_work_eligible": False, "status": "NOT_TESTED"},
        )

        bindings = receipt["bindings"]
        adapter = probe["adapter"]
        self.assertEqual(
            _sha256(
                (
                    _ROOT
                    / "benchmark"
                    / "admission"
                    / "openclaw-v2026.7.1"
                    / "contained-probe.mjs"
                ).read_bytes()
            ),
            adapter["implementation"]["contained_probe_digest"],
        )
        self.assertEqual(
            _sha256(
                (
                    _ROOT
                    / "benchmark"
                    / "admission"
                    / "openclaw-v2026.7.1"
                    / "probe.mjs"
                ).read_bytes()
            ),
            adapter["implementation"]["baseline_probe_digest"],
        )
        self.assertEqual(
            bindings["adapter"]["implementation_digest"],
            _canonical_digest(adapter["implementation"]),
        )
        self.assertEqual(
            bindings["adapter"]["configuration_digest"],
            _canonical_digest(adapter["configuration"]),
        )
        self.assertEqual(
            probe["profile"]["admitted"]["digest"],
            "sha256:5a951f65ad92bc209f9a00139fb88e38015fab9b5ac3035407a027a7d502853d",
        )
        self.assertEqual(
            bindings["runtime"]["source_tree_digest"],
            probe["runtime"]["runtime_tree"]["tree_digest"],
        )
        self.assertEqual(
            probe["baseline"]["prior_retained_evidence"],
            {
                "digest": "sha256:c26c1a99f271c632254fb2865b8295714ac09a2dbba4a6cb29820939dde666a0",
                "path": "benchmark/evidence/openclaw-v2026.7.1-admission-probe-2026-07-27.json",
            },
        )

        self.assertEqual(_sha256(environment_raw), evidence_digests[0])
        self.assertEqual(
            environment["container"]["probe_stdout"],
            {"bytes": len(probe_raw), "digest": _sha256(probe_raw)},
        )
        self.assertEqual(
            environment["docker"]["assurance"],
            "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
        )
        self.assertIn(
            "ENGINE_CONTAINER_AND_HOST_NOT_INDEPENDENTLY_ATTESTED",
            environment["limitations"],
        )
        self.assertEqual(
            environment["os_profile_digest"],
            _canonical_digest(environment["isolation"]),
        )
        self.assertEqual(
            bindings["environment"]["os_profile_digest"],
            environment["os_profile_digest"],
        )
        self.assertEqual(
            bindings["environment"]["worker_digest"],
            environment["container"]["image"]["platform_manifest_digest"],
        )
        isolation = environment["isolation"]
        self.assertEqual(
            (
                isolation["cap_drop"],
                isolation["devices"],
                isolation["nano_cpus"],
                isolation["memory_bytes"],
                isolation["memory_swap_bytes"],
                isolation["network_mode"],
                isolation["no_new_privileges"],
                isolation["pids_limit"],
                isolation["privileged"],
                isolation["read_only_rootfs"],
                isolation["user"],
            ),
            (
                ["ALL"],
                [],
                1_000_000_000,
                805_306_368,
                805_306_368,
                "none",
                True,
                128,
                False,
                True,
                "1000:1000",
            ),
        )
        self.assertEqual(
            isolation["environment"],
            {
                "HOME": "/profile/home",
                "NODE_VERSION": "24.16.0",
                "OPENCLAW_CONFIG_PATH": "/profile/config/openclaw.json",
                "OPENCLAW_STATE_DIR": "/profile/state",
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "YARN_VERSION": "1.22.22",
            },
        )
        self.assertEqual(
            {mount["destination"] for mount in isolation["mounts"]},
            {
                "/acquisition",
                "/probe",
                "/profile/config",
                "/profile/home/.agents",
                "/profile/state/plugin-skills",
                "/profile/state/skills",
                "/profile/workspace/.agents",
                "/profile/workspace/skills",
                "/runtime",
            },
        )
        self.assertTrue(all(mount["read_only"] for mount in isolation["mounts"]))
        self.assertEqual(environment["container"]["state"]["exit_code"], 0)

        exact = next(
            item
            for item in probe["scenarios"]
            if item["id"] == "ADM-01/exact-admitted-bytes"
        )
        self.assertEqual(
            [item["name"] for item in exact["evidence"]["effective_skills"]],
            ["aragorn-admitted"],
        )
        discovery = next(
            item
            for item in probe["scenarios"]
            if item["id"] == "ADM-02/auto-discovery"
        )
        self.assertEqual(discovery["evidence"]["discovered_injected"], [])
        unadmitted = [
            item
            for item in discovery["evidence"]["observed_skills"]
            if item["name"] != "aragorn-admitted"
        ]
        self.assertTrue(unadmitted)
        self.assertTrue(
            all(
                item["blockedByAgentFilter"]
                and not item["modelVisible"]
                and not item["commandVisible"]
                for item in unadmitted
            )
        )

        implementation = {
            "admission_conformance": _sha256(
                (_ROOT / "src" / "aragorn" / "admission_conformance.py").read_bytes()
            ),
            "admission_gate": _sha256(
                (_ROOT / "src" / "aragorn" / "admission_gate.py").read_bytes()
            ),
        }
        self.assertEqual(
            bindings["aragorn"]["implementation_digest"],
            _canonical_digest(implementation),
        )

    def test_retained_openclaw_adm03_profile_is_partial_and_bound(self) -> None:
        evidence_dir = _ROOT / "benchmark" / "evidence"
        probe_raw = (
            evidence_dir
            / "openclaw-v2026.7.1-contained-adm03-probe-2026-07-27.json"
        ).read_bytes()
        environment_raw = (
            evidence_dir
            / "openclaw-v2026.7.1-contained-adm03-environment-2026-07-27.json"
        ).read_bytes()
        probe = json.loads(probe_raw)
        environment = json.loads(environment_raw)
        receipt = json.loads(
            (
                _ROOT
                / "benchmark"
                / "receipts"
                / "phase1-openclaw-contained-adm03-probe-2026-07-27.json"
            ).read_bytes()
        )
        prior_receipt = json.loads(
            (
                _ROOT
                / "benchmark"
                / "receipts"
                / "phase1-openclaw-contained-profile-probe-2026-07-27.json"
            ).read_bytes()
        )
        prior_environment = json.loads(
            (
                evidence_dir
                / "openclaw-v2026.7.1-contained-profile-environment-2026-07-27.json"
            ).read_bytes()
        )
        evidence_digests = sorted((_sha256(environment_raw), _sha256(probe_raw)))
        for raw, digest in (
            (probe_raw, evidence_digests[0]),
            (environment_raw, evidence_digests[1]),
        ):
            self.assertEqual(
                self.cas.put(BytesIO(raw), max_bytes=len(raw)),
                digest,
            )

        self.assertEqual(
            validate_retained_admission_conformance(
                receipt,
                evidence_cas=self.cas,
            ),
            "NOT_TESTED",
        )
        self.assertEqual(
            receipt["decision"],
            {"status": "NOT_TESTED", "installer_work_eligible": False},
        )
        formal = {
            f"{item['id']}/{scenario['id']}": scenario
            for item in receipt["properties"]
            for scenario in item["scenarios"]
        }
        self.assertEqual(
            {
                key
                for key, scenario in formal.items()
                if scenario["status"] == "PASS"
            },
            {
                "ADM-02/install",
                "ADM-02/direct-write",
                "ADM-02/rename",
                "ADM-02/symlink",
                "ADM-02/auto-discovery",
                "ADM-03/policy-failure",
                "ADM-03/policy-tampering",
            },
        )
        self.assertEqual(
            {
                key: scenario["reason_codes"]
                for key, scenario in formal.items()
                if scenario["status"] == "NOT_TESTED"
            },
            {
                "DET-01/identical-canonical-input-replay": [
                    "IDENTICAL_REPLAY_NOT_TESTED"
                ],
                "ADM-01/exact-admitted-bytes": [
                    "EXACT_ACTIVATED_BYTES_NOT_TESTED"
                ],
                "ADM-02/update": ["UPDATE_PATH_NOT_TESTED"],
                "ADM-02/reload": ["LIVE_RELOAD_NOT_TESTED"],
                "ADM-02/restart": ["RUNTIME_RESTART_NOT_TESTED"],
            },
        )
        for scenario in formal.values():
            if scenario["status"] == "PASS":
                self.assertEqual(scenario["evidence_digests"], evidence_digests)

        self.assertEqual(_sha256(probe_raw), "sha256:8cf42093a592dac5579b5d2de6e208a278994f133f0a7d5ddc7cace92446220a")
        self.assertEqual(len(probe_raw), 25_977)
        self.assertEqual(
            {scenario["id"]: scenario["status"] for scenario in probe["scenarios"]},
            {
                "ADM-03/policy-failure": "PASS",
                "ADM-03/policy-tampering": "PASS",
            },
        )
        self.assertEqual(
            probe["decision"],
            {"installer_work_eligible": False, "status": "NOT_TESTED"},
        )
        self.assertIn(
            "TAMPER_RESISTANCE_SCOPED_TO_UNPRIVILEGED_CONTAINER_UID_1000",
            probe["limitations"],
        )
        failure, tampering = probe["scenarios"]
        self.assertEqual(
            (failure["command"]["exit_code"], failure["command"]["stderr"]),
            (
                1,
                "install policy failed closed: policy command exited with code 1\n",
            ),
        )
        self.assertTrue(failure["evidence"]["target_absent"])
        self.assertTrue(
            all(item["blocked"] for item in tampering["evidence"]["attempts"])
        )
        self.assertEqual(
            tampering["evidence"]["config_digest_before"],
            tampering["evidence"]["config_digest_after"],
        )
        self.assertEqual(
            tampering["evidence"]["policy_script_digest_before"],
            tampering["evidence"]["policy_script_digest_after"],
        )
        self.assertEqual(
            (
                tampering["command"]["exit_code"],
                tampering["command"]["stderr"],
                tampering["evidence"]["policy_request"]["request"]["kind"],
                tampering["evidence"]["target_absent"],
            ),
            (
                1,
                "blocked by install policy: Aragorn contained profile block\n",
                "skill-install",
                True,
            ),
        )

        implementation = probe["adapter"]["implementation"]
        for field, filename in (
            ("adm03_probe_digest", "adm03-probe.mjs"),
            ("contained_probe_digest", "contained-probe.mjs"),
            ("baseline_probe_digest", "probe.mjs"),
        ):
            self.assertEqual(
                implementation[field],
                _sha256(
                    (
                        _ROOT
                        / "benchmark"
                        / "admission"
                        / "openclaw-v2026.7.1"
                        / filename
                    ).read_bytes()
                ),
            )
        self.assertEqual(
            receipt["bindings"]["adapter"]["implementation_digest"],
            _canonical_digest(implementation),
        )
        self.assertEqual(
            receipt["bindings"]["adapter"]["configuration_digest"],
            _canonical_digest(probe["adapter"]["configuration"]),
        )
        contained = probe["contained_profile"]["evidence"]
        contained_raw = (
            json.dumps(
                contained,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
        self.assertEqual(probe["contained_profile"]["digest"], _sha256(contained_raw))
        self.assertEqual(
            {scenario["status"] for scenario in contained["scenarios"]},
            {"PASS"},
        )
        self.assertEqual(
            receipt["bindings"]["runtime"],
            prior_receipt["bindings"]["runtime"],
        )
        self.assertEqual(
            receipt["bindings"]["aragorn"],
            prior_receipt["bindings"]["aragorn"],
        )

        self.assertEqual(_sha256(environment_raw), evidence_digests[1])
        self.assertEqual(
            environment["container"]["probe_stdout"],
            {"bytes": len(probe_raw), "digest": _sha256(probe_raw)},
        )
        self.assertEqual(
            environment["os_profile_digest"],
            _canonical_digest(environment["isolation"]),
        )
        self.assertEqual(
            receipt["bindings"]["environment"],
            {
                "os_profile_digest": environment["os_profile_digest"],
                "worker_digest": environment["container"]["image"][
                    "platform_manifest_digest"
                ],
            },
        )
        self.assertEqual(environment["container"]["state"]["exit_code"], 0)
        self.assertFalse(environment["container"]["state"]["oom_killed"])
        self.assertEqual(
            environment["container"]["command"],
            [
                "/bin/sh",
                "-c",
                "/usr/local/bin/node /probe/contained-probe.mjs > "
                "/tmp/contained-profile.json && exec /usr/local/bin/node "
                "/driver/adm03-probe.mjs",
            ],
        )
        self.assertEqual(
            environment["docker"]["assurance"],
            "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
        )
        self.assertEqual(
            environment["limitations"],
            [
                "CONTAINER_EXIT_DOES_NOT_ESTABLISH_CROSS_HOST_REPRODUCIBILITY",
                "DOCKER_CONTROL_PLANE_SELF_REPORTED",
                "ENGINE_CONTAINER_AND_HOST_NOT_INDEPENDENTLY_ATTESTED",
                "PLATFORM_MANIFEST_DIGEST_RETAINED_NOT_INDEPENDENTLY_REDERIVED",
            ],
        )
        driver_mount = {
            "destination": "/driver",
            "read_only": True,
            "source": "aragorn-openclaw-2026-7-1-adm03-driver-v1",
            "type": "volume",
        }
        expected_isolation = deepcopy(prior_environment["isolation"])
        expected_isolation["mounts"] = sorted(
            [*expected_isolation["mounts"], driver_mount],
            key=lambda mount: mount["destination"],
        )
        self.assertEqual(
            environment["isolation"],
            expected_isolation,
        )

    def test_retained_openclaw_restart_profile_is_partial_and_bound(self) -> None:
        evidence_dir = _ROOT / "benchmark" / "evidence"
        receipt_dir = _ROOT / "benchmark" / "receipts"
        files = {
            "probe": evidence_dir / "openclaw-v2026.7.1-contained-restart-probe-2026-07-27.json",
            "environment": evidence_dir / "openclaw-v2026.7.1-contained-restart-environment-2026-07-27.json",
        }
        raw = {name: path.read_bytes() for name, path in files.items()}
        probe, environment = (json.loads(raw[name]) for name in ("probe", "environment"))
        receipt = json.loads(
            (receipt_dir / "phase1-openclaw-contained-restart-probe-2026-07-27.json").read_bytes()
        )
        prior = json.loads(
            (receipt_dir / "phase1-openclaw-contained-adm03-probe-2026-07-27.json").read_bytes()
        )
        digests = sorted(_sha256(value) for value in raw.values())
        for value in raw.values():
            self.assertEqual(self.cas.put(BytesIO(value), max_bytes=len(value)), _sha256(value))
        self.assertEqual(
            validate_retained_admission_conformance(receipt, evidence_cas=self.cas),
            "NOT_TESTED",
        )
        self.assertEqual(
            receipt["decision"],
            {"status": "NOT_TESTED", "installer_work_eligible": False},
        )

        formal = {
            f"{item['id']}/{scenario['id']}": scenario
            for item in receipt["properties"]
            for scenario in item["scenarios"]
        }
        self.assertEqual(
            {key: item["status"] for key, item in formal.items()},
            {
                "DET-01/identical-canonical-input-replay": "NOT_TESTED",
                "ADM-01/exact-admitted-bytes": "NOT_TESTED",
                "ADM-02/install": "PASS",
                "ADM-02/update": "NOT_TESTED",
                "ADM-02/direct-write": "PASS",
                "ADM-02/rename": "PASS",
                "ADM-02/symlink": "PASS",
                "ADM-02/auto-discovery": "PASS",
                "ADM-02/reload": "NOT_TESTED",
                "ADM-02/restart": "PASS",
                "ADM-03/policy-failure": "PASS",
                "ADM-03/policy-tampering": "PASS",
            },
        )
        self.assertEqual(
            {
                key: item["reason_codes"]
                for key, item in formal.items()
                if item["status"] == "NOT_TESTED"
            },
            {
                "DET-01/identical-canonical-input-replay": ["IDENTICAL_REPLAY_NOT_TESTED"],
                "ADM-01/exact-admitted-bytes": ["EXACT_ACTIVATED_BYTES_NOT_TESTED"],
                "ADM-02/update": ["UPDATE_PATH_NOT_TESTED"],
                "ADM-02/reload": ["LIVE_RELOAD_NOT_TESTED"],
            },
        )
        self.assertTrue(
            all(item["evidence_digests"] == digests for item in formal.values() if item["status"] == "PASS")
        )

        implementation_paths = {
            "adm03_probe_digest": "adm03-probe.mjs",
            "baseline_probe_digest": "probe.mjs",
            "contained_probe_digest": "contained-probe.mjs",
            "restart_probe_digest": "restart-probe.mjs",
        }
        admission_dir = _ROOT / "benchmark" / "admission" / "openclaw-v2026.7.1"
        implementation = {
            field: _sha256((admission_dir / filename).read_bytes())
            for field, filename in implementation_paths.items()
        }
        self.assertEqual(probe["adapter"]["implementation"], implementation)
        self.assertEqual(
            receipt["bindings"]["adapter"],
            {
                "name": "openclaw-contained-profile-restart",
                "implementation_digest": _canonical_digest(implementation),
                "configuration_digest": _canonical_digest(probe["adapter"]["configuration"]),
            },
        )
        self.assertEqual(
            (receipt["bindings"]["runtime"], receipt["bindings"]["aragorn"]),
            (prior["bindings"]["runtime"], prior["bindings"]["aragorn"]),
        )
        self.assertEqual(receipt["recorded_at"], probe["recorded_at"])

        adm03 = probe["adm03_profile"]["evidence"]
        self.assertEqual(probe["runtime"], adm03["runtime"])
        self.assertEqual(
            receipt["bindings"]["runtime"],
            {
                "name": probe["runtime"]["name"],
                "version": probe["runtime"]["version"],
                "repository_url": prior["bindings"]["runtime"]["repository_url"],
                "commit": probe["runtime"]["commit"],
                "source_tree_digest": probe["runtime"]["runtime_tree"]["tree_digest"],
            },
        )
        adm03_raw = (
            json.dumps(adm03, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
            + b"\n"
        )
        self.assertEqual(probe["adm03_profile"]["digest"], _sha256(adm03_raw))
        self.assertEqual(
            [(item["id"], item["status"]) for item in adm03["scenarios"]],
            [
                ("ADM-03/policy-failure", "PASS"),
                ("ADM-03/policy-tampering", "PASS"),
            ],
        )
        self.assertEqual(
            [
                (item["id"], item["status"])
                for item in adm03["contained_profile"]["evidence"]["scenarios"]
            ],
            [
                ("ADM-01/exact-admitted-bytes", "PASS"),
                ("ADM-02/install", "PASS"),
                ("ADM-02/direct-write", "PASS"),
                ("ADM-02/rename", "PASS"),
                ("ADM-02/symlink", "PASS"),
                ("ADM-02/auto-discovery", "PASS"),
                ("ADM-02/restart", "PASS"),
            ],
        )

        scenario = probe["scenarios"][0]
        self.assertEqual(
            (scenario["id"], scenario["status"], probe["decision"]),
            (
                "ADM-02/restart",
                "PASS",
                {"installer_work_eligible": False, "status": "NOT_TESTED"},
            ),
        )
        evidence = scenario["evidence"]
        restart = evidence["restart_response"]
        self.assertEqual(
            (
                restart["ok"],
                restart["result"],
                restart["preflight"]["safe"],
                restart["preflight"]["blockers"],
                set(restart["preflight"]["counts"].values()),
                {key: restart["restart"][key] for key in ("ok", "pid", "signal", "reason", "mode")},
            ),
            (
                True,
                "scheduled",
                True,
                [],
                {0},
                {"ok": True, "pid": 1, "signal": "SIGUSR1", "reason": "gateway.restart.safe", "mode": "emit"},
            ),
        )

        lifecycle = evidence["lifecycle"]
        order = ("first_ready", "signal", "restarting", "shutdown", "restart_mode", "second_ready")
        self.assertEqual(
            [lifecycle[key]["offset"] for key in order],
            sorted(lifecycle[key]["offset"] for key in order),
        )
        self.assertEqual(
            [lifecycle[key]["message"] for key in ("first_ready", "signal", "restarting", "second_ready")],
            ["gateway ready", "signal SIGUSR1 received", "received SIGUSR1; restarting", "gateway ready"],
        )
        self.assertTrue(lifecycle["shutdown"]["message"].startswith("shutdown completed cleanly "))
        self.assertTrue(lifecycle["restart_mode"]["message"].startswith("restart mode: in-process restart "))
        self.assertEqual(lifecycle["process_before"], lifecycle["process_after"])
        self.assertEqual(
            (lifecycle["process_before"]["pid"], lifecycle["process_before"]["cmdline"]),
            (1, ["openclaw-gateway"]),
        )

        commands = scenario["commands"]
        clients = evidence["rpc_clients"]
        parse_time = lambda value: datetime.fromisoformat(value.replace("Z", "+00:00"))
        self.assertNotEqual(clients["skills_before"]["pid"], clients["skills_after"]["pid"])
        self.assertLessEqual(
            parse_time(clients["skills_before"]["completed_at"]),
            parse_time(commands["restart"]["started_at"]),
        )
        self.assertGreaterEqual(
            parse_time(clients["skills_after"]["started_at"]),
            parse_time(lifecycle["second_ready"]["time"]),
        )
        self.assertEqual(commands["skills_before"]["argv"], commands["skills_after"]["argv"])
        self.assertEqual(
            commands["skills_before"]["argv"][2:],
            [
                "gateway", "call", "skills.status", "--json", "--timeout", "5000",
                "--params", '{"agentId":"main"}',
            ],
        )
        self.assertEqual(
            (
                commands["skills_before"]["exit_code"],
                commands["skills_after"]["exit_code"],
                commands["skills_before"]["stdout_bytes"] > 0,
                commands["skills_before"]["stdout_bytes"] == commands["skills_after"]["stdout_bytes"],
                commands["skills_before"]["stdout_digest"] == commands["skills_after"]["stdout_digest"],
            ),
            (0, 0, True, True, True),
        )
        for key in ("authentication_before", "authentication_after"):
            authentication = commands[key]
            self.assertEqual(
                (
                    authentication["status"],
                    authentication["command"]["exit_code"],
                    authentication["response"]["error"]["code"],
                ),
                ("PASS", 1, 1008),
            )

        skills = evidence["skills"]
        self.assertTrue(skills["raw_bytes_equal"])
        self.assertEqual(skills["projection_before"], skills["projection_after"])
        projection = skills["projection_after"]
        effective = [
            item
            for item in projection["skills"]
            if not item["disabled"]
            and not item["blocked_by_allowlist"]
            and not item["blocked_by_agent_filter"]
            and (item["eligible"] or item["model_visible"] or item["command_visible"])
        ]
        self.assertEqual(len(effective), 1)
        admitted = effective[0]
        self.assertEqual(
            (
                admitted["name"], admitted["source"], admitted["file_path"], admitted["base_dir"],
                admitted["eligible"], admitted["model_visible"], admitted["command_visible"],
            ),
            (
                "aragorn-admitted", "openclaw-managed",
                "/profile/state/skills/aragorn-admitted/SKILL.md",
                "/profile/state/skills/aragorn-admitted", True, True, True,
            ),
        )
        self.assertTrue(
            all(
                item["blocked_by_agent_filter"] and not item["model_visible"] and not item["command_visible"]
                for item in projection["skills"]
                if item["name"] != "aragorn-admitted"
            )
        )
        self.assertEqual(evidence["protected_state_before"], evidence["protected_state_after"])
        protected = evidence["protected_state_before"]
        self.assertEqual(
            (protected["admitted_digest"], protected["implementation"], protected["policy_digest"]),
            (
                "sha256:5a951f65ad92bc209f9a00139fb88e38015fab9b5ac3035407a027a7d502853d",
                implementation,
                implementation["contained_probe_digest"],
            ),
        )

        log = evidence["gateway_log"]
        log_raw = ("\n".join(log["lines"]) + "\n").encode("utf-8")
        self.assertEqual((len(log_raw), _sha256(log_raw)), (log["bytes"], log["digest"]))
        self.assertNotIn(b"aragorn-contained-restart-token-v1", log_raw)
        self.assertNotIn(b"aragorn-invalid-test-token-v1", log_raw)
        offset = 0
        records = {}
        for line in log["lines"]:
            records[offset] = json.loads(line)
            offset += len(line.encode("utf-8")) + 1
        self.assertEqual(offset, log["bytes"])
        self.assertTrue(
            all(records[lifecycle[key]["offset"]]["message"] == lifecycle[key]["message"] for key in order)
        )

        probe_exec = environment["container"]["probe_exec"]
        self.assertEqual(
            (
                probe_exec["command"], probe_exec["exit_code"], probe_exec["recorded_at"],
                probe_exec["stdout"], probe_exec["user"],
            ),
            (
                ["/usr/local/bin/node", "/probe/restart-probe.mjs"], 0, probe["recorded_at"],
                {"bytes": len(raw["probe"]), "digest": _sha256(raw["probe"])}, "1000:1000",
            ),
        )
        state = environment["container"]["state"]
        self.assertEqual((state["status"], state["exit_code"], state["oom_killed"]), ("exited", 0, False))
        command = environment["container"]["command"]
        self.assertEqual(command[:2], ["/bin/sh", "-c"])
        for required in (
            "/probe/contained-probe.mjs", "/probe/adm03-probe.mjs", "gateway run",
            "--auth token", "--bind loopback", "--tailscale off", "--ws-log full",
        ):
            self.assertIn(required, command[2])
        self.assertNotIn("--force", command[2])

        isolation = environment["isolation"]
        self.assertEqual(environment["os_profile_digest"], _canonical_digest(isolation))
        self.assertEqual(
            receipt["bindings"]["environment"],
            {
                "os_profile_digest": environment["os_profile_digest"],
                "worker_digest": environment["container"]["image"]["platform_manifest_digest"],
            },
        )
        self.assertEqual(
            (
                isolation["cap_drop"], isolation["devices"], isolation["memory_bytes"],
                isolation["memory_swap_bytes"], isolation["nano_cpus"], isolation["network_mode"],
                isolation["no_new_privileges"], isolation["pids_limit"], isolation["privileged"],
                isolation["read_only_rootfs"], isolation["user"],
            ),
            (
                ["ALL"], [], 1_073_741_824, 1_073_741_824, 1_000_000_000, "none",
                True, 128, False, True, "1000:1000",
            ),
        )
        self.assertEqual(
            isolation["environment"]["OPENCLAW_GATEWAY_TOKEN"],
            "aragorn-contained-restart-token-v1",
        )
        mounts = {item["destination"]: item for item in isolation["mounts"]}
        self.assertEqual(
            set(mounts),
            {
                "/acquisition", "/probe", "/profile/config", "/profile/home/.agents",
                "/profile/state/plugin-skills", "/profile/state/skills",
                "/profile/workspace/.agents", "/profile/workspace/skills", "/runtime",
            },
        )
        self.assertTrue(all(item["read_only"] for item in mounts.values()))
        self.assertEqual(mounts["/probe"]["source"], "aragorn-openclaw-2026-7-1-contained-probe-v7")
        self.assertEqual(
            environment["docker"]["platform_manifest_resolution"]["digest"],
            environment["container"]["image"]["platform_manifest_digest"],
        )
        self.assertEqual(environment["docker"]["assurance"], "SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED")

if __name__ == "__main__":
    unittest.main()
