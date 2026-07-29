from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_COMMIT = "972f368fb0bc0647f8fafe903eb95e2f490c71a2"
_BROKER = "benchmark/admission/openclaw-v2026.7.1/protected-install-broker.py"
_LAUNCHER = "packaging/libexec/aragorn-protected-install-launcher.py"
_SERVICE = "packaging/systemd/aragorn-protected-install.service"
_TMPFILES = "packaging/systemd/aragorn-gateway.tmpfiles"
_LIVE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / (
        "openclaw-v2026.7.1-agent-skill-protected-service-live-"
        "972f368f-2026-07-29.json"
    )
)
_RETENTION = (
    _ROOT
    / "benchmark"
    / "receipts"
    / (
        "phase1-protected-install-service-live-retention-"
        "972f368f-2026-07-29.json"
    )
)
_PACKAGE_INCLUDES = (
    _BROKER,
    "requirements-worker.lock",
    "scripts/verify_build_inputs.py",
    "src/aragorn",
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _commit_bytes(path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{_COMMIT}:{path}"],
        check=True,
        cwd=_ROOT,
        stdout=subprocess.PIPE,
    ).stdout


def _commit_package_digest() -> tuple[str, list[str]]:
    paths = subprocess.run(
        [
            "git",
            "ls-tree",
            "-r",
            "--name-only",
            _COMMIT,
            "--",
            *_PACKAGE_INCLUDES,
        ],
        check=True,
        cwd=_ROOT,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.splitlines()
    result = hashlib.sha256()
    for path in paths:
        raw = _commit_bytes(path)
        path_bytes = path.encode()
        mode = 0o444 if path == _BROKER else 0o644
        result.update(len(path_bytes).to_bytes(8, "big"))
        result.update(path_bytes)
        result.update(mode.to_bytes(4, "big"))
        result.update(len(raw).to_bytes(8, "big"))
        result.update(hashlib.sha256(raw).digest())
    return "sha256:" + result.hexdigest(), paths


class ProtectedInstallServiceLiveTests(unittest.TestCase):
    def test_retained_service_capture_is_exact_and_non_authoritative(self) -> None:
        live_raw = _LIVE.read_bytes()
        retention_raw = _RETENTION.read_bytes()
        live = json.loads(live_raw)
        retention = json.loads(retention_raw)
        self.assertEqual(live_raw, _canonical(live) + b"\n")
        self.assertEqual(retention_raw, _canonical(retention) + b"\n")
        self.assertEqual(
            _digest(live_raw),
            "sha256:71bfaa2318576443841ee7b6de097ba0"
            "df07c19ad1be22d42bed39c058fb0d04",
        )
        self.assertEqual(retention["positive"]["evidence_digest"], _digest(live_raw))
        self.assertEqual(
            retention["positive"]["evidence_path"],
            _LIVE.relative_to(_ROOT).as_posix(),
        )

        self.assertEqual(
            retention["schema"],
            "aragorn/phase1-protected-install-service-live-retention/v1",
        )
        self.assertEqual(
            retention["assurance"],
            (
                "OPERATOR_CAPTURE_OF_FIXED_SYSTEMD_CREDENTIAL_BOUNDARY_"
                "NOT_PHASE1_EXIT_AUTHORITY"
            ),
        )
        self.assertEqual(
            retention["status"],
            "SERVICE_BOUNDARY_PASS_PHASE_EXIT_INELIGIBLE",
        )
        self.assertTrue(retention["service_boundary_pass"])
        self.assertFalse(retention["phase1_exit_eligible"])
        self.assertEqual(
            set(retention["limitations"]),
            {
                "OPERATOR_CAPTURE_NOT_INDEPENDENT_ATTESTATION",
                "LIVE_DEVICE_AND_INODE_CUSTODY_REQUIRES_ORIGINAL_VM",
                "JOURNAL_CAPTURE_NOT_SIGNED_PLATFORM_ATTESTATION",
                "CURRENT_RUNTIME_CONFORMANCE_LEDGER_IS_FAIL",
                "ANALYZER_EXECUTES_AS_ROOT_INSIDE_SERVICE_SANDBOX",
                "ANALYZER_AND_BROKER_SHARE_QUARANTINE_AND_PROTECTED_WRITE_ACCESS",
                "ARTIFACT_CLOSURE_LIMITED_TO_SELF_CONTAINED_GITHUB_MARKDOWN_V1",
                "INITIAL_INSTALL_ONLY_NO_UPDATE_DIFF",
                "TRUSTED_COORDINATOR_REQUEST_CREATION_AND_UNIT_START_NOT_IMPLEMENTED",
                "NO_AGGREGATE_PHASE1_EXIT_RECEIPT",
            },
        )

        implementation = retention["implementation"]
        self.assertEqual(implementation["commit"], _COMMIT)
        package_digest, package_paths = _commit_package_digest()
        self.assertEqual(len(package_paths), 54)
        self.assertEqual(package_digest, implementation["package_tree_digest"])
        self.assertEqual(_digest(_commit_bytes(_BROKER)), implementation["broker_digest"])
        self.assertEqual(
            _digest(_commit_bytes(_LAUNCHER)),
            implementation["launcher_digest"],
        )
        self.assertEqual(
            _digest(_commit_bytes(_SERVICE)),
            implementation["service_file_digest"],
        )
        self.assertEqual(
            _digest(_commit_bytes(_TMPFILES)),
            implementation["tmpfiles_digest"],
        )
        self.assertEqual(
            implementation["package_path"],
            "/opt/aragorn-broker-" + _COMMIT[:12],
        )
        self.assertEqual(
            live["producer_implementation_digest"],
            implementation["broker_digest"],
        )

        service = _commit_bytes(_SERVICE).decode()
        for line in (
            "Type=oneshot",
            "User=root",
            (
                "LoadCredential=install-request:"
                "/run/aragorn-protected-install/request.json"
            ),
            "PrivateNetwork=yes",
            "InaccessiblePaths=/run/aragorn-protected-install/request.json",
            (
                "ReadWritePaths="
                "/var/lib/aragorn-quarantine "
                "/var/lib/aragorn-protected/skills"
            ),
        ):
            self.assertIn(line + "\n", service)
        self.assertNotIn("[Install]", service)
        self.assertIn(
            "--service-request %d/install-request "
            "--cas-root /var/lib/aragorn-quarantine "
            "--protected-root /var/lib/aragorn-protected/skills "
            "--expected-broker-uid 0 "
            "--revocation-file "
            "/etc/aragorn/protected-install-revocations.json",
            service,
        )
        tmpfiles = _commit_bytes(_TMPFILES).decode()
        self.assertIn(
            "d /var/lib/aragorn-protected/skills 0700 root root -\n",
            tmpfiles,
        )

        request_authority = live["request_authority"]
        self.assertEqual(live["mode"], "github-live")
        self.assertEqual(live["slice_status"], "PASS")
        self.assertEqual(
            live["assurance"],
            (
                "LIVE_GITHUB_CUSTODY_TO_PROTECTED_INSTALL_EVIDENCE_ONLY_"
                "NOT_INSTALLER_AUTHORITY"
            ),
        )
        self.assertEqual(
            request_authority["authority"],
            "PROTECTED_CANONICAL_REQUEST_CREDENTIAL",
        )
        self.assertEqual(
            request_authority["request_schema"],
            "aragorn/protected-install-broker-request/v1",
        )
        credential = request_authority["credential"]
        self.assertEqual(
            credential["path"],
            "/run/credentials/aragorn-protected-install.service/install-request",
        )
        self.assertEqual(
            {
                key: credential[key]
                for key in ("gid", "links", "mode", "size", "uid")
            },
            {"gid": 0, "links": 1, "mode": 0o400, "size": 1633, "uid": 0},
        )
        positive = retention["positive"]
        self.assertEqual(
            positive["request_digest"],
            request_authority["request_digest"],
        )
        self.assertEqual(positive["service_result"], "success")
        self.assertEqual(positive["systemd_analyze_verify"], "pass")

        gateway = retention["gateway"]
        source = live["source"]
        self.assertEqual(gateway["request"], source["request"])
        self.assertEqual(
            gateway["request_digest"],
            _digest(_canonical(gateway["request"])),
        )
        self.assertEqual(
            gateway["canonical_namespace"],
            "/var/lib/aragorn-quarantine/" + gateway["request_digest"][7:],
        )
        for key in (
            "gateway_profile_digest",
            "manifest_digest",
            "protected_cas",
            "quarantine_receipt_digest",
            "source_proof_digest",
        ):
            live_key = (
                "quarantine_protected_cas"
                if key == "protected_cas"
                else key
            )
            self.assertEqual(gateway[key], source[live_key])
        self.assertEqual(
            gateway["cleanup"],
            {"gateway_root_entries": 0, "transient_units": 0},
        )
        self.assertEqual(
            gateway["handoff_manifest_digest"],
            "sha256:83d2b199b67ca0dd658c77641012b6"
            "fac9fe917cc9cf9334bdcb67e5c81dd569",
        )

        active = positive["active"]
        transaction = live["transaction"]
        context = live["context"]
        self.assertEqual(active["protected_root"], "/var/lib/aragorn-protected/skills")
        self.assertEqual(active["file_mode"], 0o444)
        self.assertEqual(
            active["file_digest"],
            "sha256:eb685d91de039ed864fbd790cddf316"
            "84b017fd4a34ee1a55760d8d7cdbadefa",
        )
        self.assertEqual(active["tree_digest"], source["tree_digest"])
        self.assertEqual(active["tree_digest"], live["active"]["tree_digest"])
        self.assertEqual(active["root_device"], context["destination"]["root_device"])
        self.assertEqual(active["root_inode"], context["destination"]["root_inode"])
        self.assertEqual(transaction["context_id"], context["context_id"])
        self.assertEqual(transaction["context_digest"], context["digest"])
        self.assertEqual(transaction["destination"], context["destination"])
        self.assertEqual(transaction["manifest_digest"], source["manifest_digest"])
        self.assertEqual(transaction["tree_digest"], active["tree_digest"])
        self.assertEqual(live["active"]["link_target"], transaction["version_path"])
        self.assertFalse(live["decision"]["installer_work_eligible"])
        self.assertEqual(
            live["transaction"]["authority"],
            "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
        )

        negative = retention["negative"]
        malformed = negative["malformed_credential"]
        self.assertEqual(malformed["slice_status"], "ERROR")
        self.assertEqual(malformed["exec_main_status"], 1)
        self.assertEqual(
            malformed["error_message"],
            "service request must be one exact canonical request object",
        )
        self.assertEqual(
            malformed["request_restored_digest"],
            positive["request_digest"],
        )
        self.assertEqual(
            malformed["snapshot_before"],
            malformed["snapshot_after"],
        )
        self.assertEqual(malformed["snapshot_after"], active["snapshot_digest"])
        tampered = negative["tampered_package"]
        self.assertEqual(tampered["exec_main_status"], 126)
        self.assertEqual(
            tampered["expected_broker_digest"],
            implementation["broker_digest"],
        )
        self.assertEqual(
            tampered["expected_package_tree_digest"],
            implementation["package_tree_digest"],
        )
        self.assertNotEqual(
            tampered["actual_broker_digest"],
            tampered["expected_broker_digest"],
        )
        self.assertNotEqual(
            tampered["actual_package_tree_digest"],
            tampered["expected_package_tree_digest"],
        )
        self.assertEqual(
            tampered["identity_restored_digest"],
            implementation["identity_digest"],
        )
        self.assertEqual(tampered["snapshot_before"], tampered["snapshot_after"])
        self.assertEqual(
            tampered["snapshot_after"],
            active["snapshot_digest"],
        )
        self.assertEqual(
            tampered["stderr_utf8"],
            "aragorn protected launcher: "
            "package tree digest does not match its pin\n",
        )
        for attempt in retention["discarded_attempts"]:
            self.assertFalse(attempt["retained_as_exit_evidence"])
            self.assertEqual(attempt["slice_status"], "ERROR")


if __name__ == "__main__":
    unittest.main()
