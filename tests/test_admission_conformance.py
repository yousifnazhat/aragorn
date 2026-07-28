from __future__ import annotations

import hashlib
import json
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

import aragorn.admission_evidence as admission_evidence
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
    def test_docker_nanosecond_timestamp_is_portable(self) -> None:
        parsed = admission_evidence._time("2026-07-28T02:57:06.663894352Z")
        self.assertEqual(
            parsed.isoformat(),
            "2026-07-28T02:57:06.663894+00:00",
        )

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

    def test_retained_openclaw_restart_evidence_is_authority_disabled(self) -> None:
        evidence_dir = _ROOT / "benchmark" / "evidence"
        receipt = json.loads(
            (
                _ROOT
                / "benchmark"
                / "receipts"
                / "phase1-openclaw-contained-restart-probe-2026-07-27.json"
            ).read_bytes()
        )
        evidence_paths = (
            evidence_dir
            / "openclaw-v2026.7.1-contained-restart-probe-2026-07-27.json",
            evidence_dir
            / "openclaw-v2026.7.1-contained-restart-environment-2026-07-27.json",
        )
        evidence_digests = []
        for path in evidence_paths:
            raw = path.read_bytes()
            evidence_digests.append(
                self.cas.put(BytesIO(raw), max_bytes=len(raw))
            )
        evidence_digests.sort()

        self.assertIsNone(
            admission_evidence.verify_openclaw_restart_evidence(
                receipt,
                evidence_cas=self.cas,
            )
        )

        promoted = deepcopy(receipt)
        scenario = promoted["properties"][1]["scenarios"][0]
        scenario.update(
            status="PASS",
            evidence_digests=evidence_digests,
            reason_codes=[],
        )
        promoted["properties"][1]["status"] = "PASS"

        authority = deepcopy(receipt)
        for item in authority["properties"]:
            item["status"] = "PASS"
            for candidate in item["scenarios"]:
                candidate.update(
                    status="PASS",
                    evidence_digests=evidence_digests,
                    reason_codes=[],
                )
        authority["decision"] = {
            "status": "PASS",
            "installer_work_eligible": True,
        }

        drifted = deepcopy(receipt)
        drifted["bindings"]["adapter"]["name"] = "unbound-adapter"
        for label, mutation in (
            ("scenario promotion", promoted),
            ("installer authority", authority),
            ("binding drift", drifted),
        ):
            with self.subTest(label), self.assertRaises(
                admission_evidence.AdmissionEvidenceError
            ):
                admission_evidence.verify_openclaw_restart_evidence(
                    mutation,
                    evidence_cas=self.cas,
                )

        probe = json.loads(evidence_paths[0].read_bytes())
        environment = json.loads(evidence_paths[1].read_bytes())
        restart_mutations = {}

        timing = deepcopy(probe)
        timing["scenarios"][0]["evidence"]["lifecycle"]["signal"]["time"] = (
            "2026-07-27T22:27:40.000Z"
        )
        restart_mutations["lifecycle timing"] = timing

        log_binding = deepcopy(probe)
        log_binding["scenarios"][0]["evidence"]["lifecycle"]["signal"]["time"] = (
            "2026-07-27T22:27:50.127+00:00"
        )
        restart_mutations["log timestamp binding"] = log_binding

        projection = deepcopy(probe)
        for key in ("projection_before", "projection_after"):
            unadmitted = projection["scenarios"][0]["evidence"]["skills"][key][
                "skills"
            ][0]
            unadmitted["blocked_by_agent_filter"] = False
            unadmitted["model_visible"] = True
        restart_mutations["skill projection"] = projection

        admitted = deepcopy(probe)
        for key in ("projection_before", "projection_after"):
            current = admitted["scenarios"][0]["evidence"]["skills"][key]
            current["workspace_dir"] = "/unbound-workspace"
            next(
                item
                for item in current["skills"]
                if item["name"] == "aragorn-admitted"
            )["user_invocable"] = False
        restart_mutations["admitted profile"] = admitted

        protected = deepcopy(probe)
        protected["scenarios"][0]["evidence"]["protected_state_after"][
            "admitted_digest"
        ] = "sha256:" + "0" * 64
        restart_mutations["protected state"] = protected

        for label, mutation in restart_mutations.items():
            with self.subTest(label), self.assertRaises(
                admission_evidence.AdmissionEvidenceError
            ):
                admission_evidence._verify_restart(mutation)

        isolation = deepcopy(environment)
        isolation["isolation"]["mounts"][0]["source"] = "unbound-volume"
        with self.subTest("isolation policy"), self.assertRaises(
            admission_evidence.AdmissionEvidenceError
        ):
            admission_evidence._verify_environment(probe, isolation)

        duplicate_mount = deepcopy(environment)
        duplicate_mount["isolation"]["mounts"].append(
            deepcopy(duplicate_mount["isolation"]["mounts"][0])
        )
        with self.subTest("duplicate mount"), self.assertRaises(
            admission_evidence.AdmissionEvidenceError
        ):
            admission_evidence._verify_environment(probe, duplicate_mount)

    def test_retained_openclaw_update_slice_is_bound_and_non_authoritative(
        self,
    ) -> None:
        evidence_dir = _ROOT / "benchmark" / "evidence"
        receipt = json.loads(
            (
                _ROOT
                / "benchmark"
                / "receipts"
                / "phase1-openclaw-contained-update-probe-2026-07-27.json"
            ).read_bytes()
        )
        evidence_paths = (
            evidence_dir
            / "openclaw-v2026.7.1-contained-update-probe-2026-07-27.json",
            evidence_dir
            / "openclaw-v2026.7.1-contained-update-environment-2026-07-27.json",
        )
        for path in evidence_paths:
            raw = path.read_bytes()
            self.cas.put(BytesIO(raw), max_bytes=len(raw))

        self.assertIsNone(
            admission_evidence.verify_openclaw_update_slice_evidence(
                receipt,
                evidence_cas=self.cas,
            )
        )

        promoted = deepcopy(receipt)
        update = promoted["properties"][2]["scenarios"][1]
        update.update(status="PASS", reason_codes=[])
        with self.assertRaises(admission_evidence.AdmissionEvidenceError):
            admission_evidence.verify_openclaw_update_slice_evidence(
                promoted,
                evidence_cas=self.cas,
            )

        probe = json.loads(evidence_paths[0].read_bytes())
        environment = json.loads(evidence_paths[1].read_bytes())
        request = deepcopy(probe)
        request["scenario"]["evidence"]["policy_request"]["request"]["mode"] = (
            "install"
        )
        managed = deepcopy(probe)
        managed["scenario"]["evidence"]["managed_after"][2]["digest"] = (
            "sha256:" + "0" * 64
        )
        for label, mutation in (
            ("policy request", request),
            ("managed root", managed),
        ):
            with self.subTest(label), self.assertRaises(
                admission_evidence.AdmissionEvidenceError
            ):
                admission_evidence._verify_update_probe(mutation)

        isolation = deepcopy(environment)
        isolation["isolation"]["network_mode"] = "bridge"
        with self.assertRaises(admission_evidence.AdmissionEvidenceError):
            admission_evidence._verify_update_environment(probe, isolation)

    def test_retained_openclaw_live_reload_slice_is_bound_and_non_authoritative(
        self,
    ) -> None:
        evidence_dir = _ROOT / "benchmark" / "evidence"
        receipt = json.loads(
            (
                _ROOT
                / "benchmark"
                / "receipts"
                / "phase1-openclaw-contained-live-reload-probe-2026-07-27.json"
            ).read_bytes()
        )
        evidence_paths = (
            evidence_dir
            / "openclaw-v2026.7.1-contained-live-reload-probe-2026-07-27.json",
            evidence_dir
            / "openclaw-v2026.7.1-contained-live-reload-environment-2026-07-27.json",
        )
        for path in evidence_paths:
            raw = path.read_bytes()
            self.cas.put(BytesIO(raw), max_bytes=len(raw))

        self.assertIsNone(
            admission_evidence.verify_openclaw_live_reload_slice_evidence(
                receipt,
                evidence_cas=self.cas,
            )
        )

        for scenario_index in (1, 6):
            promoted = deepcopy(receipt)
            scenario = promoted["properties"][2]["scenarios"][scenario_index]
            scenario.update(status="PASS", reason_codes=[])
            with self.subTest(scenario=scenario["id"]), self.assertRaises(
                admission_evidence.AdmissionEvidenceError
            ):
                admission_evidence.verify_openclaw_live_reload_slice_evidence(
                    promoted,
                    evidence_cas=self.cas,
                )

        probe = json.loads(evidence_paths[0].read_bytes())
        environment = json.loads(evidence_paths[1].read_bytes())
        policy = deepcopy(probe)
        policy["scenarios"][0]["evidence"]["policy_records"][0]["decision"] = (
            "allow"
        )
        session = deepcopy(probe)
        session["scenarios"][1]["evidence"]["snapshot_after"]["session_id"] = (
            "unbound-session"
        )
        for label, mutation in (("policy decision", policy), ("session", session)):
            with self.subTest(label), self.assertRaises(
                admission_evidence.AdmissionEvidenceError
            ):
                admission_evidence._verify_live_reload_probe(mutation)

        isolation = deepcopy(environment)
        isolation["isolation"]["network_mode"] = "bridge"
        with self.assertRaises(admission_evidence.AdmissionEvidenceError):
            admission_evidence._verify_live_reload_environment(probe, isolation)

    def test_retained_openclaw_live_reload_cron_is_distinct_and_non_authoritative(
        self,
    ) -> None:
        evidence_dir = _ROOT / "benchmark" / "evidence"
        receipt = json.loads(
            (
                _ROOT
                / "benchmark"
                / "receipts"
                / (
                    "phase1-openclaw-contained-live-reload-cron-"
                    "probe-2026-07-28.json"
                )
            ).read_bytes()
        )
        evidence_paths = (
            evidence_dir
            / (
                "openclaw-v2026.7.1-contained-live-reload-cron-"
                "probe-2026-07-28.json"
            ),
            evidence_dir
            / (
                "openclaw-v2026.7.1-contained-live-reload-cron-"
                "environment-2026-07-28.json"
            ),
        )
        for path in evidence_paths:
            raw = path.read_bytes()
            self.cas.put(BytesIO(raw), max_bytes=len(raw))

        self.assertIsNone(
            admission_evidence.verify_openclaw_live_reload_cron_slice_evidence(
                receipt,
                evidence_cas=self.cas,
            )
        )

        for scenario_index in (1, 6):
            promoted = deepcopy(receipt)
            scenario = promoted["properties"][2]["scenarios"][scenario_index]
            scenario.update(status="PASS", reason_codes=[])
            with self.subTest(scenario=scenario["id"]), self.assertRaises(
                admission_evidence.AdmissionEvidenceError
            ):
                admission_evidence.verify_openclaw_live_reload_cron_slice_evidence(
                    promoted,
                    evidence_cas=self.cas,
                )

        probe = json.loads(evidence_paths[0].read_bytes())
        cron = probe["scenarios"][3]["evidence"]
        prompt = deepcopy(probe)
        prompt_cron = prompt["scenarios"][3]["evidence"]
        prompt_cron["snapshot_after"]["prompt_digest"] = prompt_cron[
            "snapshot_before"
        ]["prompt_digest"]

        session = deepcopy(probe)
        session_cron = session["scenarios"][3]["evidence"]
        before_session = session_cron["run_before"]["result"]["sessionId"]
        session_cron["run_after"]["result"]["sessionId"] = before_session
        session_cron["run_after"]["history"]["response"]["entries"][0][
            "sessionId"
        ] = before_session
        before_key = session_cron["run_before"]["result"]["sessionKey"]
        session_cron["run_after"]["result"]["sessionKey"] = before_key
        session_cron["run_after"]["history"]["response"]["entries"][0][
            "sessionKey"
        ] = before_key

        cleanup = deepcopy(probe)
        cleanup["scenarios"][3]["evidence"]["cleanup"]["response"]["removed"] = (
            False
        )

        timing = deepcopy(probe)
        timing_cron = timing["scenarios"][3]["evidence"]
        timing_cron["snapshot_after"]["updated_at"] = (
            cron["run_after"]["result"]["diagnostics"]["entries"][0]["ts"] + 1
        )

        for label, mutation in (
            ("prompt transition", prompt),
            ("isolated sessions", session),
            ("cleanup", cleanup),
            ("causal timing", timing),
        ):
            with self.subTest(label), self.assertRaises(
                admission_evidence.AdmissionEvidenceError
            ):
                admission_evidence._verify_live_reload_cron_probe(mutation)

        environment = json.loads(evidence_paths[1].read_bytes())
        isolation = deepcopy(environment)
        isolation["isolation"]["restart_policy"]["name"] = "always"
        with self.assertRaises(admission_evidence.AdmissionEvidenceError):
            admission_evidence._verify_live_reload_environment(
                probe,
                isolation,
                cron=True,
            )

    def test_retained_openclaw_config_activation_is_read_only_and_non_authoritative(
        self,
    ) -> None:
        evidence_dir = _ROOT / "benchmark" / "evidence"
        receipt = json.loads(
            (
                _ROOT
                / "benchmark"
                / "receipts"
                / ("phase1-openclaw-contained-config-activation-probe-2026-07-27.json")
            ).read_bytes()
        )
        evidence_paths = (
            evidence_dir
            / ("openclaw-v2026.7.1-contained-config-activation-probe-2026-07-27.json"),
            evidence_dir
            / (
                "openclaw-v2026.7.1-contained-config-activation-"
                "environment-2026-07-27.json"
            ),
            evidence_dir / "openclaw-v2026.7.1-contained-profile-probe-2026-07-27.json",
        )
        for path in evidence_paths:
            raw = path.read_bytes()
            self.cas.put(BytesIO(raw), max_bytes=len(raw))

        self.assertIsNone(
            admission_evidence.verify_openclaw_config_activation_slice_evidence(
                receipt,
                evidence_cas=self.cas,
            )
        )

        for scenario_index in (1, 6):
            promoted = deepcopy(receipt)
            scenario = promoted["properties"][2]["scenarios"][scenario_index]
            scenario.update(status="PASS", reason_codes=[])
            with (
                self.subTest(scenario=scenario["id"]),
                self.assertRaises(admission_evidence.AdmissionEvidenceError),
            ):
                admission_evidence.verify_openclaw_config_activation_slice_evidence(
                    promoted,
                    evidence_cas=self.cas,
                )

        probe = json.loads(evidence_paths[0].read_bytes())
        environment = json.loads(evidence_paths[1].read_bytes())
        write_guard = deepcopy(probe)
        write_guard["scenarios"][0]["evidence"]["write_guard"]["blocked"] = False
        target = deepcopy(probe)
        target["scenarios"][0]["evidence"]["target_after"][1]["digest"] = (
            "sha256:" + "0" * 64
        )
        session = deepcopy(probe)
        session["scenarios"][1]["evidence"]["disabled"]["snapshot"]["session_id"] = (
            "unbound-session"
        )
        version = deepcopy(probe)
        reload_evidence = version["scenarios"][1]["evidence"]
        reload_evidence["disabled"]["snapshot"]["version"] = reload_evidence[
            "initial_snapshot"
        ]["version"]
        marker = deepcopy(probe)
        marker["scenarios"][1]["evidence"]["enabled"]["snapshot"]["marker_present"] = (
            False
        )
        blob_not_deleted = deepcopy(probe)
        blob_not_deleted["scenarios"][2]["evidence"]["invalidation"][
            "blob_exists_after_unlink"
        ] = True
        store_changed = deepcopy(probe)
        store_changed["scenarios"][2]["evidence"]["invalidation"][
            "store_after_rewrite"
        ]["digest"] = "sha256:" + "0" * 64
        blob_changed = deepcopy(probe)
        blob_changed["scenarios"][2]["evidence"]["blob_after"]["digest"] = (
            "sha256:" + "0" * 64
        )
        rebuilt_session = deepcopy(probe)
        rebuilt_session["scenarios"][2]["evidence"]["rebuilt_snapshot"][
            "session_id"
        ] = "unbound-session"
        rebuild_timing = deepcopy(probe)
        rebuild_timing["scenarios"][2]["evidence"]["invalidation"]["completed_at"] = (
            "2026-07-28T04:44:00.000Z"
        )
        rebuilt_timestamp = deepcopy(probe)
        rebuilt = rebuilt_timestamp["scenarios"][2]["evidence"]["rebuilt_snapshot"]
        rebuilt["started_at"] = rebuilt["ended_at"] = 9_999_999_999_999
        future_mtimes = deepcopy(probe)
        future_evidence = future_mtimes["scenarios"][2]["evidence"]
        future_evidence["invalidation"]["store_before"]["mtime_ns"] = (
            "9999999999996000000"
        )
        future_evidence["blob_before"]["mtime_ns"] = "9999999999997000000"
        future_evidence["invalidation"]["store_after_rewrite"]["mtime_ns"] = (
            "9999999999998000000"
        )
        future_evidence["blob_after"]["mtime_ns"] = "9999999999999000000"
        restarted = deepcopy(probe)
        restarted["scenarios"][1]["evidence"]["gateway_log_after"][
            "restart_count"
        ] = 1
        for label, mutation in (
            ("write guard", write_guard),
            ("target digest", target),
            ("session", session),
            ("version", version),
            ("marker", marker),
            ("blob not deleted", blob_not_deleted),
            ("session store changed", store_changed),
            ("blob changed", blob_changed),
            ("rebuilt session", rebuilt_session),
            ("rebuild timing", rebuild_timing),
            ("rebuilt timestamp", rebuilt_timestamp),
            ("future mtimes", future_mtimes),
            ("post-route restart", restarted),
        ):
            with (
                self.subTest(label),
                self.assertRaises(admission_evidence.AdmissionEvidenceError),
            ):
                admission_evidence._verify_config_activation_probe(mutation)

        writable = deepcopy(environment)
        next(
            item
            for item in writable["isolation"]["mounts"]
            if item["destination"] == "/profile/state/skills"
        )["read_only"] = False
        networked = deepcopy(environment)
        networked["isolation"]["network_mode"] = "bridge"
        runtime_identity = deepcopy(probe)
        runtime_identity["gateway"]["info"]["diskPath"] = "/unbound-state"
        runtime_environment = deepcopy(environment)
        runtime_raw = (
            json.dumps(
                runtime_identity,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        runtime_environment["container"]["probe_exec"]["stdout"] = {
            "bytes": len(runtime_raw),
            "digest": _sha256(runtime_raw),
        }
        for label, mutation in (
            ("writable admitted mount", writable),
            ("network", networked),
        ):
            with (
                self.subTest(label),
                self.assertRaises(admission_evidence.AdmissionEvidenceError),
            ):
                admission_evidence._verify_config_activation_environment(
                    probe,
                    mutation,
                )
        with self.assertRaises(admission_evidence.AdmissionEvidenceError):
            admission_evidence._verify_config_activation_environment(
                runtime_identity,
                runtime_environment,
            )

    def test_retained_openclaw_model_activation_binds_exact_tool_bytes(  # noqa: PLR0915
        self,
    ) -> None:
        evidence_dir = _ROOT / "benchmark" / "evidence"
        receipt = json.loads(
            (
                _ROOT
                / "benchmark"
                / "receipts"
                / (
                    "phase1-openclaw-contained-model-activation-"
                    "probe-2026-07-28.json"
                )
            ).read_bytes()
        )
        evidence_paths = (
            evidence_dir
            / (
                "openclaw-v2026.7.1-contained-model-activation-"
                "probe-2026-07-28.json"
            ),
            evidence_dir
            / (
                "openclaw-v2026.7.1-contained-model-activation-"
                "environment-2026-07-28.json"
            ),
            evidence_dir
            / "openclaw-v2026.7.1-contained-profile-probe-2026-07-27.json",
        )
        for path in evidence_paths:
            raw = path.read_bytes()
            self.cas.put(BytesIO(raw), max_bytes=len(raw))

        self.assertIsNone(
            admission_evidence.verify_openclaw_model_activation_evidence(
                receipt,
                evidence_cas=self.cas,
            )
        )
        probe_path = (
            _ROOT
            / "benchmark"
            / "admission"
            / "openclaw-v2026.7.1"
            / "model-activation-probe.mjs"
        )
        self.assertEqual(
            _sha256(probe_path.read_bytes()),
            receipt["bindings"]["adapter"]["implementation_digest"],
        )

        promoted = deepcopy(receipt)
        install = promoted["properties"][2]["scenarios"][0]
        install.update(
            status="PASS",
            reason_codes=[],
            evidence_digests=receipt["properties"][1]["scenarios"][0][
                "evidence_digests"
            ],
        )
        with self.assertRaises(admission_evidence.AdmissionEvidenceError):
            admission_evidence.verify_openclaw_model_activation_evidence(
                promoted,
                evidence_cas=self.cas,
            )

        probe = json.loads(evidence_paths[0].read_bytes())
        environment = json.loads(evidence_paths[1].read_bytes())

        def rebind_request(document: dict[str, object], index: int) -> None:
            record = document["provider"]["records"][index]
            raw = json.dumps(
                record["body"],
                ensure_ascii=False,
                separators=(",", ":"),
            )
            raw_bytes = raw.encode()
            record["body_raw"] = raw
            record["body_bytes"] = len(raw_bytes)
            record["body_digest"] = _sha256(raw_bytes)

        raw_mismatch = deepcopy(probe)
        raw_mismatch["provider"]["records"][0]["body_raw"] += " "

        prompt = deepcopy(probe)
        prompt_body = prompt["provider"]["records"][0]["body"]
        prompt_body["messages"][0]["content"] = prompt_body["messages"][0][
            "content"
        ].replace(
            "sha256:5a951f65ad92bc20",
            "sha256:0000000000000000",
        )
        rebind_request(prompt, 0)

        tool_result = deepcopy(probe)
        tool_result["provider"]["records"][1]["body"]["messages"][3][
            "content"
        ] += "changed"
        rebind_request(tool_result, 1)

        extra_request = deepcopy(probe)
        extra_request["provider"]["records"].append(
            deepcopy(extra_request["provider"]["records"][-1])
        )
        extra_request["provider"]["records"][-1]["sequence"] = 3
        extra_request["provider"]["request_count"] = 3

        target = deepcopy(probe)
        target["scenario"]["evidence"]["target_after"][1]["digest"] = (
            "sha256:" + "0" * 64
        )

        history = deepcopy(probe)
        history["scenario"]["evidence"]["history"]["response"]["messages"][-1][
            "content"
        ][0]["text"] = "stale success"

        restarted = deepcopy(probe)
        restarted["gateway"]["log_after"]["restart_count"] = 1

        for label, mutation in (
            ("raw request", raw_mismatch),
            ("skill version", prompt),
            ("tool result", tool_result),
            ("extra request", extra_request),
            ("target", target),
            ("history", history),
            ("restart", restarted),
        ):
            with (
                self.subTest(label),
                self.assertRaises(admission_evidence.AdmissionEvidenceError),
            ):
                admission_evidence._verify_model_activation_probe(mutation)

        writable = deepcopy(environment)
        next(
            item
            for item in writable["isolation"]["mounts"]
            if item["destination"] == "/profile/state/skills"
        )["read_only"] = False
        networked = deepcopy(environment)
        networked["isolation"]["network_mode"] = "bridge"
        extra_writable = deepcopy(environment)
        next(
            item
            for item in extra_writable["isolation"]["mounts"]
            if item["destination"] == "/probe"
        )["read_only"] = False
        for label, mutation in (
            ("writable admitted mount", writable),
            ("network", networked),
            ("writable probe", extra_writable),
        ):
            with (
                self.subTest(label),
                self.assertRaises(admission_evidence.AdmissionEvidenceError),
            ):
                admission_evidence._verify_model_activation_environment(
                    probe,
                    mutation,
                )

    def test_retained_deterministic_authority_replay_is_det_only(self) -> None:
        vector_path = (
            _ROOT
            / "benchmark"
            / "admission"
            / "openclaw-v2026.7.1"
            / "deterministic-authority-vectors-v1.json"
        )
        replay_path = (
            _ROOT
            / "benchmark"
            / "evidence"
            / (
                "openclaw-v2026.7.1-contained-deterministic-authority-"
                "replay-2026-07-28.json"
            )
        )
        receipt = json.loads(
            (
                _ROOT
                / "benchmark"
                / "receipts"
                / (
                    "phase1-openclaw-contained-deterministic-authority-"
                    "replay-2026-07-28.json"
                )
            ).read_bytes()
        )
        for path in (vector_path, replay_path):
            raw = path.read_bytes()
            self.cas.put(BytesIO(raw), max_bytes=len(raw))

        self.assertEqual(
            validate_retained_admission_conformance(
                receipt,
                evidence_cas=self.cas,
            ),
            "NOT_TESTED",
        )
        self.assertIsNone(
            admission_evidence.verify_openclaw_deterministic_replay_evidence(
                receipt,
                evidence_cas=self.cas,
            )
        )
        self.assertEqual(
            receipt["decision"],
            {"installer_work_eligible": False, "status": "NOT_TESTED"},
        )

        promoted = deepcopy(receipt)
        promoted["properties"][1]["status"] = "PASS"
        promoted["properties"][1]["scenarios"][0] = {
            "evidence_digests": receipt["properties"][0]["scenarios"][0][
                "evidence_digests"
            ],
            "id": "exact-admitted-bytes",
            "reason_codes": [],
            "status": "PASS",
        }
        binding_drift = deepcopy(receipt)
        binding_drift["bindings"]["runtime"]["source_tree_digest"] = (
            "sha256:" + "0" * 64
        )
        for mutation in (promoted, binding_drift):
            with self.assertRaises(admission_evidence.AdmissionEvidenceError):
                admission_evidence.verify_openclaw_deterministic_replay_evidence(
                    mutation,
                    evidence_cas=self.cas,
                )

        vectors = json.loads(vector_path.read_bytes())
        replay = json.loads(replay_path.read_bytes())
        missing_seed = deepcopy(replay)
        missing_seed["cases"][0]["replays"].pop()
        changed_output = deepcopy(replay)
        changed_output["cases"][0]["replays"][0]["stdout_digest"] = (
            "sha256:" + "1" * 64
        )
        changed_source = deepcopy(replay)
        changed_source["adapter"]["implementation"]["analyze_digest"] = (
            "sha256:" + "3" * 64
        )
        changed_runtime = deepcopy(vectors)
        changed_runtime["vectors"][0]["request"]["target_runtime"]["runtime"][
            "runtime_tree_digest"
        ] = "sha256:" + "2" * 64
        for changed_vectors, changed_replay in (
            (vectors, missing_seed),
            (vectors, changed_output),
            (vectors, changed_source),
            (changed_runtime, replay),
        ):
            with self.assertRaises(admission_evidence.AdmissionEvidenceError):
                admission_evidence._verify_deterministic_replay(
                    receipt,
                    changed_vectors,
                    changed_replay,
                )


if __name__ == "__main__":
    unittest.main()
