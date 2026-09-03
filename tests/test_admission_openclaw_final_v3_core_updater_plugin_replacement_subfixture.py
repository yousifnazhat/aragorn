from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from aragorn import (
    admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest
from scripts import (
    materialize_openclaw_final_v3_core_updater_plugin_replacement as materializer,
)
from scripts import (
    runtime_action_worker_final_combined_v3_core_updater_plugin_replacement_systemd_probe as capture,
)

_ROOT = Path(__file__).resolve().parents[1]
_ADMISSION = _ROOT / "benchmark/admission/openclaw-v2026.7.1"
_NODE = shutil.which("node")
_GIT = shutil.which("git")


def _command(argv: list[str], *, pid: int = 100) -> dict[str, object]:
    return {
        "argv": argv,
        "completed_at": "2026-01-01T00:00:01.000Z",
        "error": None,
        "exit_code": 0,
        "pid": pid,
        "signal": None,
        "started_at": "2026-01-01T00:00:00.000Z",
        "stderr_bytes": 0,
        "stderr_digest": "sha256:" + hashlib.sha256(b"").hexdigest(),
        "stderr_excerpt": "",
        "stdout_bytes": 3,
        "stdout_digest": "sha256:" + hashlib.sha256(b"{}\n").hexdigest(),
        "stdout_excerpt": "{}\n",
    }


def _git_command(argv: list[str]) -> dict[str, object]:
    empty = "sha256:" + hashlib.sha256(b"").hexdigest()
    return {
        "argv": argv,
        "error": None,
        "exit_code": 0,
        "signal": None,
        "stderr_bytes": 0,
        "stderr_digest": empty,
        "stdout_bytes": 0,
        "stdout_digest": empty,
    }


def _target() -> dict[str, object]:
    return {
        name: {
            "bytes": bytes_,
            "digest": digest,
            "gid": 0,
            "mode": "644",
            "nlink": 1,
            "path": f"{subject._TARGET}/{name}",
            "type": "file",
            "uid": 0,
        }
        for name, (bytes_, digest) in subject._TARGET_DIGESTS.items()
    }


def _working_configs() -> tuple[dict[str, object], dict[str, object]]:
    before_document = json.loads(
        (_ADMISSION / "protected-final-combined-config-v3.json").read_bytes()
    )
    before_raw = json.dumps(
        before_document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    after_document = deepcopy(before_document)
    after_document["plugins"]["entries"][subject._PLUGIN_ID]["enabled"] = False
    after_document["plugins"].pop("allow")
    after_document["plugins"]["bundledDiscovery"] = "compat"
    after_document["wizard"] = {
        "lastRunAt": "2026-01-01T00:00:00.000Z",
        "lastRunCommand": "doctor",
        "lastRunMode": "local",
        "lastRunVersion": "2026.7.1",
    }
    after_document["meta"] = {
        "lastTouchedAt": "2026-01-01T00:00:01.000Z",
        "lastTouchedVersion": "2026.7.1",
    }
    custody = {
        "gid": 992,
        "mode": "600",
        "nlink": 1,
        "path": subject._WORKING_CONFIG,
        "type": "file",
        "uid": 992,
    }
    before = {
        "bytes": len(before_raw),
        "canonical_digest": "sha256:" + hashlib.sha256(before_raw).hexdigest(),
        "digest": "sha256:" + hashlib.sha256(before_raw).hexdigest(),
        "document": before_document,
        **custody,
    }
    after = {
        "bytes": 2_240,
        "canonical_digest": canonical_digest(after_document),
        "digest": "sha256:" + "8" * 64,
        "document": after_document,
        **custody,
    }
    return before, after


def _document() -> dict[str, object]:
    openclaw = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
    inventory_argv = [
        "/usr/local/bin/node",
        openclaw,
        "plugins",
        "list",
        "--json",
    ]
    repair_argv = [
        "/usr/local/bin/node",
        openclaw,
        "update",
        "repair",
        "--timeout",
        "10",
        "--yes",
        "--json",
        "--no-restart",
    ]
    commands = [
        _command(inventory_argv, pid=101),
        _command(repair_argv, pid=102),
        _command(inventory_argv, pid=103),
    ]
    warning = {
        "guidance": list(subject._GUIDANCE),
        "message": subject._GUIDED_MESSAGE,
        "pluginId": subject._PLUGIN_ID,
        "reason": subject._RAW_FAILURE,
    }
    response = {
        "channel": "stable",
        "mode": "finalize",
        "postUpdate": {
            "doctor": {"status": "ok"},
            "plugins": {
                "changed": True,
                "integrityDrifts": [],
                "npm": {
                    "changed": True,
                    "outcomes": [dict(subject._EXPECTED_OUTCOME)],
                },
                "status": "warning",
                "sync": {
                    "changed": False,
                    "errors": [],
                    "switchedToBundled": [],
                    "switchedToNpm": [],
                    "warnings": [],
                },
                "warnings": [warning],
            },
        },
        "restart": False,
        "root": "/runtime/lib/node_modules/openclaw",
        "status": "warning",
    }
    boundary_config = {"ready": True}
    observations = {
        "configuration_after": boundary_config,
        "inventory_after": {
            "command": commands[2],
            "response": {"parsed": True, "value": {"plugins": []}},
        },
        "inventory_before": {
            "command": commands[0],
            "response": {"parsed": True, "value": {"plugins": [{}]}},
        },
        "roots_after": {"extensions": {}, "plugin_skills": {}},
        "roots_before": {"extensions": {}, "plugin_skills": {}},
        "update_repair": {
            "command": commands[1],
            "response": {"parsed": True, "value": response},
        },
    }
    git_argv = [
        ["/usr/bin/git", "init", "--quiet", "--object-format=sha1", "."],
        [
            "/usr/bin/git",
            "add",
            "--",
            "index.js",
            "openclaw.plugin.json",
            "package.json",
        ],
        [
            "/usr/bin/git",
            "commit",
            "--quiet",
            "--no-gpg-sign",
            "-m",
            "Pinned core updater replacement fixture",
        ],
        ["/usr/bin/git", "rev-parse", "--show-object-format"],
        ["/usr/bin/git", "rev-parse", "HEAD"],
        ["/usr/bin/git", "rev-parse", "HEAD^{tree}"],
    ]
    candidates = [
        {
            "bytes": bytes_,
            "digest": digest,
            "gid": 0,
            "mode": "444",
            "nlink": 1,
            "path": (
                "/route-input/core-updater-plugin-replacement/"
                f"candidate-source/{name}"
            ),
            "type": "file",
            "uid": 0,
        }
        for name, (bytes_, digest) in subject._CANDIDATE_FILES.items()
    ]
    managed = {
        "entries": [],
        "gid": 992,
        "mode": "700",
        "path": subject._MANAGED_REPOSITORY,
        "type": "directory",
        "uid": 992,
    }
    writer = {
        "alias": "s",
        "bytes": 10_000,
        "digest": "sha256:" + "1" * 64,
        "path": (
            "/runtime/lib/node_modules/openclaw/dist/"
            "installed-plugin-index-records-Fixture.js"
        ),
    }
    diagnostic = {
        "alias": "o",
        "bytes": 20_000,
        "digest": "sha256:" + "2" * 64,
        "path": (
            "/runtime/lib/node_modules/openclaw/dist/"
            "diagnostic-events-Fixture.js"
        ),
    }
    event = {
        "action": "plugin.audit.failed",
        "actor": {"kind": "operator"},
        "attributes": {"mode": "update", "source_family": "git"},
        "category": "plugin",
        "control": {"family": "supply_chain", "id": "plugin.install.audit"},
        "eventId": "12345678-1234-4123-8123-123456789abc",
        "outcome": "denied",
        "policy": {
            "decision": "deny",
            "id": "plugin.install",
            "reason": "security_scan_blocked",
        },
        "reason": "security_scan_blocked",
        "seq": 1,
        "severity": "medium",
        "target": {"kind": "plugin", "name": subject._PLUGIN_ID},
        "ts": 1,
        "type": "security.event",
    }
    before_config, after_config = _working_configs()
    record = {
        "gitCommit": subject._CANDIDATE_COMMIT,
        "gitRef": subject._CANDIDATE_COMMIT,
        "gitUrl": f"file://{subject._CANDIDATE_REPOSITORY}",
        "installPath": subject._TARGET,
        "installedAt": "2026-01-01T00:00:00.000Z",
        "plugin_id": subject._PLUGIN_ID,
        "resolvedAt": "2026-01-01T00:00:00.000Z",
        "source": "git",
        "spec": subject._SPEC,
        "version": "0.1.0",
    }
    preflight = {
        "candidate_repository": {
            "candidates": candidates,
            "commands": [_git_command(argv) for argv in git_argv],
            "commit": subject._CANDIDATE_COMMIT,
            "object_format": "sha1",
            "path": subject._CANDIDATE_REPOSITORY,
            "tree": subject._CANDIDATE_TREE,
        },
        "delegated_probe": {
            "bytes": 45_137,
            "digest": subject._DELEGATED_DIGEST,
            "path": (
                "/route-input/core-updater-plugin-replacement/"
                "protected-route-action-probe.mjs"
            ),
        },
        "installed_index": {
            "managed_repository_after": managed,
            "managed_repository_before": managed,
            "record": record,
            "store": {
                "bytes": 4096,
                "gid": 992,
                "mode": "600",
                "nlink": 1,
                "path": (
                    "/var/lib/aragorn-agent-gateway/state/state/openclaw.sqlite"
                ),
                "type": "file",
                "uid": 992,
            },
            "writer_module": writer,
        },
        "policy_outcome": dict(subject._EXPECTED_OUTCOME),
        "policy_reason": subject._POLICY_REASON,
        "ready": True,
        "target_after": _target(),
        "target_before": _target(),
        "trusted_policy_audit": {
            "diagnostic_module": diagnostic,
            "event": event,
            "journal": {
                "bytes": 1024,
                "digest": "sha256:" + "3" * 64,
                "gid": 992,
                "mode": "600",
                "nlink": 1,
                "path": (
                    "/var/lib/aragorn-agent-gateway/state/"
                    "core-updater-policy-audit.jsonl"
                ),
                "type": "file",
                "uid": 992,
            },
            "metadata": {"trusted": True},
        },
        "working_config_after": after_config,
        "working_config_before": before_config,
    }
    return {
        "actions": [
            {
                "commands": commands,
                "execution_error": None,
                "id": subject._ACTION,
                "observations": observations,
                "prerequisites": {"ready": True},
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ],
        "assurance": "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY",
        "core_updater_preflight": preflight,
        "delegated_implementation_digest": subject._DELEGATED_DIGEST,
        "implementation_digest": subject._IMPLEMENTATION_DIGEST,
        "protected_boundary": {"configuration": boundary_config, "ready": True},
        "recorded_at": "2026-01-01T00:00:02.000Z",
        "routes": [
            {
                "action_id": subject._ACTION,
                "id": subject._ROUTE,
                "reason_codes": [],
                "status": "OBSERVED",
            }
        ],
        "run_nonce": "a" * 32,
        "runtime_binding": {
            "commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
            "node_path": "/usr/local/bin/node",
            "openclaw_digest": (
                "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188"
            ),
            "openclaw_path": openclaw,
            "version": "2026.7.1",
        },
        "schema": subject._SCHEMA,
        "selected_route_ids": [subject._ROUTE],
    }


class CoreUpdaterMaterializerTests(unittest.TestCase):
    def test_dedicated_bundle_is_exact_deterministic_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first"
            second = Path(temporary) / "second"
            manifest = materializer.materialize_openclaw_final_v3_core_updater_plugin_replacement(
                first
            )
            repeated = materializer.materialize_openclaw_final_v3_core_updater_plugin_replacement(
                second
            )
            self.assertEqual(manifest, repeated)
            self.assertEqual(manifest["case_id"], subject._ROUTE)
            self.assertEqual(
                capture._ROUTES[capture._ROUTE]["directories"],
                ("candidate-source",),
            )
            self.assertEqual(
                [item["name"] for item in manifest["files"]],
                [
                    "protected-core-updater-plugin-replacement-v3-probe.mjs",
                    "protected-route-action-probe.mjs",
                    "core-updater-plugin-replacement-audit-listener.mjs",
                    "candidate-source/index.js",
                    "candidate-source/openclaw.plugin.json",
                    "candidate-source/package.json",
                ],
            )
            self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o555)
            self.assertEqual(
                stat.S_IMODE((first / "candidate-source").stat().st_mode), 0o555
            )
            for item in manifest["files"]:
                path = first / item["name"]
                raw = path.read_bytes()
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
                self.assertEqual(item["bytes"], len(raw))
                self.assertEqual(
                    item["digest"], "sha256:" + hashlib.sha256(raw).hexdigest()
                )
                self.assertEqual(raw, (second / item["name"]).read_bytes())
            delegated = (first / materializer._DELEGATED_PROBE).read_text()
            self.assertIn(subject._ROUTE, delegated)
            self.assertIn(
                "--import=/route-input/core-updater-plugin-replacement/"
                "core-updater-plugin-replacement-audit-listener.mjs",
                delegated,
            )
            self.assertIn(subject._WORKING_CONFIG, delegated)
            probe = (first / materializer._PROBE).read_text(encoding="utf-8")
            self.assertIn(
                'writeFileSync(WORKING_CONFIG, sourceRaw, { flag: "wx", mode: 0o600 })',
                probe,
            )
            self.assertNotIn("copyFileSync(CONFIG, WORKING_CONFIG)", probe)
            self.assertIn("OPENCLAW_CONFIG_PATH: WORKING_CONFIG", probe)
            audit = (
                first / "core-updater-plugin-replacement-audit-listener.mjs"
            ).read_text(encoding="utf-8")
            self.assertNotIn("/profile/", probe + delegated + audit)

    def test_materializer_fails_closed_on_reuse_or_source_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            existing = Path(temporary) / "existing"
            existing.mkdir()
            with self.assertRaises(materializer.CoreUpdaterMaterializationError):
                materializer.materialize_openclaw_final_v3_core_updater_plugin_replacement(
                    existing
                )
            with (
                patch.object(materializer, "_REBINDER_BYTES", 1),
                self.assertRaises(materializer.CoreUpdaterMaterializationError),
            ):
                materializer.materialize_openclaw_final_v3_core_updater_plugin_replacement(
                    Path(temporary) / "drift"
                )

    def test_capture_wrapper_generates_pinned_cleanup_safe_recipe(self) -> None:
        recipe = _ROOT / (
            "scripts/capture_runtime_action_worker_final_combined_v3_"
            "core_updater_plugin_replacement_systemd.sh"
        )
        result = subprocess.run(
            ["sh", str(recipe)],
            cwd=_ROOT,
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 64)
        self.assertIn("usage:", result.stderr)

        wrapper = recipe.read_text(encoding="utf-8")
        git_source = (
            "sha256:8530f76a96d88820d288761f022e318970dda93d01536919fbc16076b7983e63"
        )
        self.assertIn(git_source, wrapper)
        self.assertIn('docker --context "$docker_context" image inspect', wrapper)
        transformer = wrapper.partition("<<'PY'\n")[2].partition("\nPY\nchmod")[0]
        inherited = _ROOT / (
            "scripts/capture_runtime_action_worker_final_combined_v3_"
            "workshop_proposal_apply_systemd.sh"
        )
        with tempfile.TemporaryDirectory() as temporary:
            generated = Path(temporary) / "capture.sh"
            generated.touch()
            transformed = subprocess.run(
                [sys.executable, "-", str(inherited), str(generated)],
                input=transformer,
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(transformed.returncode, 0, transformed.stderr)
            generated_text = generated.read_text(encoding="utf-8")
            self.assertIn(
                "removal_id=$(docker container inspect --format "
                "'{{.Id}}' \"$container\" 2>/dev/null || :)",
                generated_text,
            )
            self.assertIn(
                "current_image=$(docker container inspect --format "
                "'{{.Image}}' \"$removal_id\" 2>/dev/null || :)",
                generated_text,
            )
            self.assertIn(
                '"$removal_id" 2>/dev/null || :)',
                generated_text,
            )
            self.assertIn(
                "materialize_openclaw_final_v3_core_updater_plugin_replacement.py",
                generated_text,
            )
            self.assertIn(
                "scripts/materialize_openclaw_final_v3_rebound_probes.py",
                generated_text,
            )
            create = "created_volume=$(docker volume create"
            self.assertLess(
                generated_text.index("route_input_volume_created=1\n" + create),
                generated_text.index(create),
            )
            self.assertNotIn(
                '"$route_input_volume")\nroute_input_volume_created=1',
                generated_text,
            )
            for cleanup_binding in (
                'dev.aragorn.source-commit',
                'dev.aragorn.role',
                'final-combined-v3-core-updater-plugin-replacement-route-input',
            ):
                self.assertIn(cleanup_binding, generated_text)
            syntax = subprocess.run(
                ["sh", "-n", str(generated)],
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)

        docker = (
            _ROOT
            / "benchmark/runtime-action-worker-final-combined-v3-core-updater-"
            "plugin-replacement-systemd/Dockerfile"
        ).read_text(encoding="utf-8")
        self.assertIn(git_source, docker)
        self.assertIn("COPY --from=git-source /usr/bin/git /usr/bin/git", docker)
        self.assertIn("ln -s git /usr/bin/git-upload-pack", docker)
        for archived_mode in (
            "regular file:0:0:700:1:8295",
            "regular file:0:0:600:1:7691",
            "regular file:0:0:700:1:19627",
            "regular file:0:0:700:1:8364",
            "regular file:0:0:600:1:28641",
            "regular file:0:0:600:1:27682",
            "regular file:0:0:600:1:3177",
        ):
            self.assertIn(archived_mode, docker)
        self.assertIn(
            "8321a6c423b03c283d175185de6886ca12aaa08c244f81b67be3a73a47279a1c",
            docker,
        )
        for path in (
            recipe,
            _ROOT
            / "scripts/materialize_openclaw_final_v3_core_updater_plugin_replacement.py",
            _ROOT
            / "scripts/runtime_action_worker_final_combined_v3_core_updater_"
            "plugin_replacement_systemd_probe.py",
            _ROOT
            / "src/aragorn/admission_openclaw_final_v3_core_updater_plugin_"
            "replacement_subfixture.py",
        ):
            raw = path.read_bytes()
            self.assertIn(hashlib.sha256(raw).hexdigest(), docker)
            self.assertIn(str(len(raw)), docker)

    def test_failed_live_route_reports_bounded_token_safe_diagnostic(self) -> None:
        failed = subprocess.CompletedProcess(
            args=[], returncode=2, stdout=b"", stderr=b"bounded route failure\n"
        )
        with (
            patch.object(capture, "_probe_bundle", return_value=[]),
            patch.object(
                capture.proposal.v1_route.subprocess,
                "run",
                return_value=failed,
            ),
            self.assertRaisesRegex(
                capture.combined.openclaw.ProbeError,
                "core-updater route exited 2: bounded route failure",
            ),
        ):
            capture._run_route({"OPENCLAW_GATEWAY_TOKEN": "safe-token"}, 123)

    @unittest.skipUnless(_NODE, "Node.js is required")
    def test_all_materialized_javascript_is_syntactically_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            manifest = materializer.materialize_openclaw_final_v3_core_updater_plugin_replacement(
                output
            )
            for item in manifest["files"]:
                if item["name"].endswith((".js", ".mjs")):
                    subprocess.run(
                        [_NODE, "--check", str(output / item["name"])],
                        check=True,
                        capture_output=True,
                        text=True,
                    )

    @unittest.skipUnless(_GIT, "Git is required")
    def test_candidate_git_commit_and_tree_are_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            for source_name, destination_name in (
                ("core-updater-plugin-replacement-index.js", "index.js"),
                (
                    "core-updater-plugin-replacement-openclaw.plugin.json",
                    "openclaw.plugin.json",
                ),
                ("core-updater-plugin-replacement-package.json", "package.json"),
            ):
                shutil.copyfile(_ADMISSION / source_name, repository / destination_name)
            env = {
                "GIT_AUTHOR_DATE": "2026-01-01T00:00:00.000Z",
                "GIT_AUTHOR_EMAIL": "fixture@aragorn.invalid",
                "GIT_AUTHOR_NAME": "Aragorn capture fixture",
                "GIT_COMMITTER_DATE": "2026-01-01T00:00:00.000Z",
                "GIT_COMMITTER_EMAIL": "fixture@aragorn.invalid",
                "GIT_COMMITTER_NAME": "Aragorn capture fixture",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_EDITOR": "",
                "GIT_EXTERNAL_DIFF": "",
                "GIT_SEQUENCE_EDITOR": "",
                "GIT_TEMPLATE_DIR": "",
                "GIT_TERMINAL_PROMPT": "0",
                "HOME": temporary,
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "TZ": "UTC",
            }
            commands = (
                ["init", "--quiet", "--object-format=sha1", "."],
                ["add", "--", "index.js", "openclaw.plugin.json", "package.json"],
                [
                    "commit",
                    "--quiet",
                    "--no-gpg-sign",
                    "-m",
                    "Pinned core updater replacement fixture",
                ],
            )
            for command in commands:
                subprocess.run(
                    [_GIT, *command], cwd=repository, env=env, check=True
                )
            commit = subprocess.run(
                [_GIT, "rev-parse", "HEAD"],
                cwd=repository,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            tree = subprocess.run(
                [_GIT, "rev-parse", "HEAD^{tree}"],
                cwd=repository,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertEqual(commit, subject._CANDIDATE_COMMIT)
            self.assertEqual(tree, subject._CANDIDATE_TREE)


class CoreUpdaterSemanticCompatibilityTests(unittest.TestCase):
    def verify(self, document: dict[str, object] | None = None) -> dict[str, object]:
        return subject.verify_openclaw_final_v3_core_updater_plugin_replacement_semantic_compatibility(
            _document() if document is None else document
        )

    def test_exact_policy_denial_preserves_claim_ceiling(self) -> None:
        result = self.verify()
        self.assertEqual(result, self.verify())
        self.assertEqual(
            result["decision"]["status"],
            "CORE_UPDATER_POLICY_BLOCK_SEMANTIC_COMPATIBILITY_VERIFIED_"
            "NOT_OBSERVED_OR_QUALIFIED",
        )
        self.assertNotIn("PASS", result["decision"].values())
        self.assertNotIn("OBSERVED", result["decision"].values())
        self.assertTrue(
            all(result["decision"][key] is False for key in subject._ELIGIBILITY_KEYS)
        )
        self.assertTrue(
            result["route_semantics"][
                "policy_blocked_target_specific_outcome_shape_verified"
            ]
        )
        self.assertTrue(result["route_semantics"]["replacement_target_unchanged"])
        self.assertFalse(result["route_semantics"]["pass_authority"])

    def test_noop_warning_and_duplicate_outcome_fail_closed(self) -> None:
        mutations = []
        changed = _document()
        plugins = changed["actions"][0]["observations"]["update_repair"][
            "response"
        ]["value"]["postUpdate"]["plugins"]
        plugins["changed"] = False
        plugins["npm"] = {"changed": False, "outcomes": []}
        mutations.append(changed)

        changed = _document()
        outcomes = changed["actions"][0]["observations"]["update_repair"][
            "response"
        ]["value"]["postUpdate"]["plugins"]["npm"]["outcomes"]
        outcomes.append(deepcopy(outcomes[0]))
        mutations.append(changed)

        for changed in mutations:
            with self.assertRaises(AdmissionEvidenceError):
                self.verify(changed)

    def test_untrusted_wrong_mode_or_wrong_reason_audit_fails_closed(self) -> None:
        mutations = []
        changed = _document()
        changed["core_updater_preflight"]["trusted_policy_audit"]["metadata"][
            "trusted"
        ] = False
        mutations.append(changed)

        changed = _document()
        changed["core_updater_preflight"]["trusted_policy_audit"]["event"][
            "attributes"
        ]["mode"] = "install"
        mutations.append(changed)

        changed = _document()
        changed["core_updater_preflight"]["trusted_policy_audit"]["event"][
            "reason"
        ] = "security_scan_failed"
        mutations.append(changed)

        for changed in mutations:
            with self.assertRaises(AdmissionEvidenceError):
                self.verify(changed)

    def test_target_repository_and_working_config_tampering_fail_closed(self) -> None:
        mutations = []
        changed = _document()
        changed["core_updater_preflight"]["target_after"]["index.js"][
            "digest"
        ] = "sha256:" + "0" * 64
        mutations.append(changed)

        changed = _document()
        changed["core_updater_preflight"]["installed_index"][
            "managed_repository_before"
        ]["entries"] = ["repo"]
        mutations.append(changed)

        changed = _document()
        changed["core_updater_preflight"]["working_config_after"] = deepcopy(
            changed["core_updater_preflight"]["working_config_before"]
        )
        mutations.append(changed)

        changed = _document()
        changed["core_updater_preflight"]["working_config_after"]["document"][
            "wizard"
        ]["lastRunCommand"] = "onboard"
        mutations.append(changed)

        for changed in mutations:
            with self.assertRaises(AdmissionEvidenceError):
                self.verify(changed)

    def test_route_digest_command_and_positive_eligibility_fail_closed(self) -> None:
        mutations = []
        changed = _document()
        changed["routes"][0]["id"] = "ADM-02/update/not-this-route"
        mutations.append(changed)

        changed = _document()
        changed["implementation_digest"] = "sha256:" + "0" * 64
        mutations.append(changed)

        changed = _document()
        changed["actions"][0]["commands"][1]["exit_code"] = False
        mutations.append(changed)

        changed = _document()
        changed["core_updater_preflight"]["release_eligible"] = True
        mutations.append(changed)

        for changed in mutations:
            with self.assertRaises(AdmissionEvidenceError):
                self.verify(changed)


if __name__ == "__main__":
    unittest.main()
