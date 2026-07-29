from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from copy import deepcopy
from pathlib import Path

from aragorn import admission_evidence_broker as evidence
from aragorn.admission_evidence import AdmissionEvidenceError

_ROOT = Path(__file__).resolve().parents[1]
_PROBE = (
    _ROOT
    / "benchmark"
    / "admission"
    / "openclaw-v2026.7.1"
    / "broker-symlink-probe.mjs"
)
_NODE = shutil.which("node")


@unittest.skipUnless(_NODE, "Node.js is required for the probe self-check")
class BrokerSymlinkProbeTests(unittest.TestCase):
    def test_self_check_is_canonical_bounded_and_non_authoritative(self) -> None:
        self.assertNotIn("const process = processIdentity()", _PROBE.read_text())
        completed = subprocess.run(
            [_NODE, str(_PROBE), "self-check"],
            capture_output=True,
            check=False,
            cwd=_ROOT,
            text=True,
            timeout=5,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        result = json.loads(completed.stdout)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(
            result["assurance"],
            "SELF_REPORTED_EVIDENCE_ONLY_NOT_CONFORMANCE_AUTHORITY",
        )
        self.assertEqual(
            result["implementation_digest"], evidence._IMPLEMENTATION_DIGEST
        )
        self.assertEqual(
            result["configuration_digest"], evidence._CONFIGURATION["digest"]
        )
        self.assertTrue(all(result["checks"].values()))
        self.assertEqual(
            result["mount_contract"],
            {
                "broker": {
                    "mode": "rw",
                    "path": "/profile/workspace/skills",
                    "uid": 2000,
                },
                "runtime": {
                    "mode": "ro",
                    "nested_mountpoint": True,
                    "path": "/profile/workspace/skills",
                    "uid": 1000,
                },
                "shared_volume_count": 1,
            },
        )
        self.assertEqual(
            result["pinned_source_review"]["status"],
            "SOURCE_REVIEWED_RUNTIME_LIVE_PROOF_PENDING",
        )
        self.assertLess(len(completed.stdout.encode()), 16 * 1024)
        canonical = json.dumps(
            result,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        self.assertEqual(completed.stdout, f"{canonical}\n")


def _digest(value: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _command(argv: list[str], start: int, *, stdout_bytes: int = 3) -> dict:
    return {
        "argv": argv,
        "completed_at": f"2026-07-29T03:00:{start + 1:02d}.000Z",
        "error": None,
        "exit_code": 0,
        "pid": 100 + start,
        "signal": None,
        "started_at": f"2026-07-29T03:00:{start:02d}.000Z",
        "stderr_bytes": 0,
        "stderr_digest": evidence._EMPTY_DIGEST,
        "stdout_bytes": stdout_bytes,
        "stdout_digest": _digest(f"stdout-{start}"),
    }


def _rpc(method: str, params: dict, start: int, timeout: int = 5_000) -> dict:
    return _command(
        [
            evidence._NODE,
            evidence._OPENCLAW,
            "gateway",
            "call",
            method,
            "--json",
            "--timeout",
            str(timeout),
            "--params",
            json.dumps(params, ensure_ascii=True, separators=(",", ":"), sort_keys=True),
        ],
        start,
    )


def _boundary(role: str) -> dict:
    uid = 2000 if role == "broker" else 1000
    mode = "rw" if role == "broker" else "ro"
    return {
        "active_root": {
            "device": 5,
            "gid": 2000,
            "inode": 10,
            "mode": "755",
            "uid": 2000,
        },
        "effective_identity": {"gid": uid, "uid": uid},
        "mount": {
            "filesystem": "ext4",
            "mount_options": ["relatime", mode],
            "mount_point": evidence._ACTIVE_ROOT,
            "root": (
                "/docker/volumes/"
                "aragorn-openclaw-2026-7-1-broker-skills-v99/_data"
            ),
            "source": "/dev/vdb1",
            "super_options": ["rw"],
        },
        "role": role,
    }


def _link(version: str, inode: int) -> dict:
    tree = evidence._FIXTURES[version]["tree_digest"]
    target = (
        f".aragorn-versions/{evidence._NAME}/"
        f"{tree.removeprefix('sha256:')}"
    )
    return {
        "device": 5,
        "inode": inode,
        "resolved_target": f"{evidence._ACTIVE_ROOT}/{target}",
        "target": target,
        "tree_digest": tree,
        "type": "symlink",
        "version": version,
    }


def _proof(version: str, location: str) -> dict:
    fixture = evidence._FIXTURES[version]
    offset = 20 if version == "v1" else 30
    realpath = (
        f"{evidence._VERSION_ROOT}/{evidence._NAME}/"
        f"{fixture['tree_digest'].removeprefix('sha256:')}"
        if location == "installed"
        else f"/probe/fixtures/{version}"
    )
    if location == "source":
        offset -= 10
    device = 5 if location == "installed" else 6
    return {
        "directory": {
            "device": device,
            "inode": offset + 1,
            "mode": "555",
            "realpath": realpath,
            "type": "directory",
        },
        "file": {
            "device": device,
            "digest": fixture["file_digest"],
            "inode": offset + 2,
            "links": 1,
            "mode": "444",
            "path": "SKILL.md",
            "size": fixture["bytes"],
            "type": "file",
        },
        "manifest": deepcopy(fixture["manifest"]),
        "tree_digest": fixture["tree_digest"],
        "version": version,
    }


def _envelope(schema: str, payload: dict, second: int) -> dict:
    return {
        "assurance": evidence._ASSURANCE,
        "decision": {"installer_work_eligible": False, "status": "NOT_TESTED"},
        "limitations": deepcopy(evidence._LIMITATIONS),
        "payload": payload,
        "recorded_at": f"2026-07-29T03:00:{second:02d}.000Z",
        "schema": schema,
        "slice_status": "PASS",
    }


def _activation(version: str, prior: dict | None, second: int) -> dict:
    final = _proof(version, "installed")
    source = _proof(version, "source")
    active = _link(version, 23 if version == "v1" else 33)
    return _envelope(
        evidence._ACTIVATION_SCHEMA,
        {
            "action": f"activate-{version}",
            "active_after": active,
            "active_before": prior,
            "atomic_relative_symlink_rename": True,
            "broker_boundary": _boundary("broker"),
            "implementation_digest": evidence._IMPLEMENTATION_DIGEST,
            "materialized": {
                "final": final,
                "promoted": True,
                "promotion_same_filesystem": True,
                "source": source,
                "staged_device": final["directory"]["device"],
                "staged_inode": final["directory"]["inode"],
            },
            "native_openclaw_route_used": False,
            "requested_tree_digest": final["tree_digest"],
            "single_volume_same_filesystem": True,
            "temporary_link": {
                "device": active["device"],
                "inode": active["inode"],
                "target": active["target"],
            },
        },
        second,
    )


def _session(version: str, snapshot_version: int) -> dict:
    return {
        "active_marker": version,
        "ended_at": 1_785_294_400_200 + snapshot_version,
        "markers": {"v1": version == "v1", "v2": version == "v2"},
        "prompt_bytes": 700,
        "prompt_digest": _digest(f"prompt-{version}"),
        "prompt_storage": "promptRef",
        "run_status": "done",
        "runtime_ms": 100,
        "session_id": "test-only-broker-session",
        "skill_names": [evidence._NAME],
        "started_at": 1_785_294_400_000 + snapshot_version,
        "version": snapshot_version,
    }


def _turn(version: str, attempt: int, sequence: int, start: int) -> dict:
    run_id = f"aragorn-broker-switch-{version}-{attempt}"
    send_params = {
        "deliver": False,
        "idempotencyKey": run_id,
        "message": (
            "Read the active Aragorn broker skill file, then return its fixed result. "
            f"ARAGORN_BROKER_EXPECT_{version.upper()}"
        ),
        "sessionKey": evidence._SESSION_KEY,
        "timeoutMs": 10_000,
    }
    return {
        "consumption": {
            "final_text": f"ARAGORN_BROKER_{version.upper()}_OK",
            "roles": ["user", "assistant", "toolResult", "assistant"],
            "tool_content_digest": evidence._FIXTURES[version]["file_digest"],
            "tool_path": evidence._ACTIVE_FILE,
            "valid": True,
        },
        "history_command": _rpc(
            "chat.history",
            {"limit": 100, "sessionKey": evidence._SESSION_KEY},
            start + 4,
        ),
        "provider": {
            "first_sequence": sequence,
            "prompt_digest": _digest(f"provider-{version}-{attempt}"),
            "prompt_marker": version,
            "record_count": 2,
            "second_sequence": sequence + 1,
            "tool_content_digest": evidence._FIXTURES[version]["file_digest"],
            "valid": True,
        },
        "send": {
            "command": _rpc("chat.send", send_params, start),
            "response": {"runId": run_id, "status": "started"},
        },
        "wait": {
            "command": _rpc(
                "agent.wait",
                {"runId": run_id, "timeoutMs": 15_000},
                start + 2,
                17_000,
            ),
            "response": {
                "endedAt": 1_785_294_400_300 + start,
                "runId": run_id,
                "status": "ok",
            },
        },
    }


def _log(size: int, label: str) -> dict:
    return {
        "bytes": size,
        "digest": _digest(label),
        "path": "openclaw-2026-07-29.log",
        "ready_count": 1,
        "restart_count": 0,
    }


def _readiness(start: int) -> dict:
    return _command(
        [
            evidence._NODE,
            evidence._OPENCLAW,
            "gateway",
            "call",
            "system.info",
            "--json",
            "--timeout",
            "5000",
        ],
        start,
    )


def _guards(active: dict) -> dict:
    roots = [
        ("active-workspace-skills", evidence._ACTIVE_ROOT),
        ("active-version-directory", active["resolved_target"]),
        ("project-agents", "/profile/workspace/.agents"),
        ("personal-agents", "/profile/home/.agents"),
        ("managed-skills", "/profile/state/skills"),
        ("plugin-skills", "/profile/state/plugin-skills"),
        ("extensions", "/profile/state/extensions"),
        ("configuration", "/profile/config"),
        ("bundled-runtime-skills", "/runtime/lib/node_modules/openclaw/skills"),
    ]
    return {
        "all_blocked": True,
        "direct_writes": [
            {
                "blocked": True,
                "code": "EROFS",
                "id": guard_id,
                "operation": "direct-write",
                "root": root,
            }
            for guard_id, root in roots
        ],
        "mountpoint": [
            {
                "blocked": True,
                "code": "EBUSY",
                "operation": "rename-skills-mountpoint",
                "root": evidence._ACTIVE_ROOT,
            },
            {
                "blocked": True,
                "code": "EISDIR",
                "operation": "unlink-skills-mountpoint",
                "root": evidence._ACTIVE_ROOT,
            },
        ],
        "replacements": [
            {
                "blocked": True,
                "code": "EXDEV",
                "id": guard_id,
                "operation": "alternate-root-replacement",
                "root": root,
                "target": f"{root}/{evidence._NAME}",
            }
            for guard_id, root in roots[2:]
        ],
        "runtime_boundary": _boundary("runtime"),
    }


def _document() -> dict:
    # Synthetic in-memory unit input only; it is never retained as live evidence.
    process = {"cmdline": ["openclaw-gateway"], "pid": 1, "start_time_ticks": "42"}
    active_v1 = _link("v1", 23)
    active_v2 = _link("v2", 33)
    activation_v1 = _activation("v1", None, 1)
    activation_v2 = _activation("v2", active_v1, 20)
    runtime_version = _command(
        [evidence._NODE, evidence._OPENCLAW, "--version"],
        2,
        stdout_bytes=28,
    )
    runtime_version["stdout_digest"] = (
        "sha256:9e98975ff3973bcd88f224e1820a177c3c881f7a46b51b7dc5ec5d050f72607f"
    )
    baseline = {
        "configuration": deepcopy(evidence._CONFIGURATION),
        "gateway": {
            "log": _log(100, "before"),
            "process": process,
            "readiness_command": _readiness(4),
            "system_info": {
                "arch": "arm64",
                "node_version": "v24.16.0",
                "pid": 1,
                "platform": "linux",
                "port": 18789,
            },
        },
        "implementation_digest": evidence._IMPLEMENTATION_DIGEST,
        "link": active_v1,
        "recorded_at": "2026-07-29T03:00:15.000Z",
        "runtime_boundary": _boundary("runtime"),
        "runtime_version": runtime_version,
        "schema": evidence._BASELINE_SCHEMA,
        "session": _session("v1", 100),
        "turn": _turn("v1", 1, 1, 6),
    }
    observation = {
        "attempt": 1,
        "session": _session("v2", 101),
        "turn": _turn("v2", 1, 3, 22),
    }
    gateway = {
        "log_after": _log(200, "after"),
        "log_before": baseline["gateway"]["log"],
        "process_after": process,
        "process_before": process,
        "readiness_command": _readiness(21),
    }
    return _envelope(
        evidence._SCHEMA,
        {
            "active_after": active_v2,
            "active_before": active_v1,
            "activations": {"v1": activation_v1, "v2": activation_v2},
            "baseline": baseline,
            "configuration": deepcopy(evidence._CONFIGURATION),
            "exact_old_and_new_versions_retained": True,
            "gateway": gateway,
            "guards": _guards(active_v2),
            "implementation_digest": evidence._IMPLEMENTATION_DIGEST,
            "no_gateway_restart": True,
            "observations": [observation],
            "observed_snapshots_only_v1_or_v2": True,
            "runtime": {
                "commit": evidence._COMMIT,
                "name": "OpenClaw",
                "source_review": deepcopy(evidence._SOURCE_REVIEW),
                "version": "2026.7.1",
            },
            "runtime_boundary_after": _boundary("runtime"),
            "runtime_boundary_before": _boundary("runtime"),
            "same_session_advanced": True,
            "selected_attempt": 1,
            "version_proofs": {
                "v1": _proof("v1", "installed"),
                "v2": _proof("v2", "installed"),
            },
        },
        30,
    )


class BrokerSymlinkEvidenceTests(unittest.TestCase):
    def test_strict_replay_binds_switch_mounts_guards_and_non_authority(self) -> None:
        document = _document()
        evidence.verify_openclaw_broker_symlink_evidence(document)

        mutations = [
            lambda item: item["decision"].update(status="PASS"),
            lambda item: item["payload"]["runtime"].update(version="2026.7.2"),
            lambda item: item["payload"]["activations"]["v1"]["payload"][
                "broker_boundary"
            ]["mount"].update(mount_options=["relatime", "ro"]),
            lambda item: item["payload"]["baseline"]["turn"]["consumption"].update(
                tool_content_digest=evidence._FIXTURES["v2"]["file_digest"]
            ),
            lambda item: item["payload"]["observations"][0]["session"].update(
                session_id="different-session"
            ),
            lambda item: item["payload"]["guards"]["direct_writes"][0].update(
                blocked=False
            ),
            lambda item: item["payload"]["activations"]["v1"]["payload"][
                "materialized"
            ].update(staged_device=6),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                changed = deepcopy(document)
                mutate(changed)
                with self.assertRaises(AdmissionEvidenceError):
                    evidence.verify_openclaw_broker_symlink_evidence(changed)


if __name__ == "__main__":
    unittest.main()
