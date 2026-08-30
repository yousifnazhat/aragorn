from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.materialize_fixed_admission_probes import (
    FINAL_COMBINED_SELECTIONS,
    FINAL_COMBINED_SOURCE_DIGESTS,
    FINAL_COMBINED_V2_SELECTIONS,
    FINAL_COMBINED_V2_SOURCE_DIGESTS,
    SOURCE_DIGESTS,
    materialize,
    transformed_final_combined_probe,
    transformed_final_combined_v2_probe,
    transformed_probe,
    transformed_restore_authority_probe,
)
from scripts.materialize_openclaw_final_v3_rebound_probes import (
    V3RebindError,
    materialize_openclaw_final_v3_rebound_case,
)


class FixedAdmissionProbeMaterializerTests(unittest.TestCase):
    def test_default_probe_outputs_remain_byte_exact(self) -> None:
        expected = {
            "adm03-probe.mjs": (
                8_796,
                "1ac42c2baf9af313c99b5327b6c075fecd10a12e06f7dfb55d15f33b40ebb77e",
            ),
            "contained-probe.mjs": (
                17_498,
                "27e8429b8af73c4bf005a449c529f251a5ee9c36c680416dbfdd9d311725ac28",
            ),
            "config-activation-probe.mjs": (
                24_173,
                "1e2ab048d3308fbe9b4f2982e39a5eee661cb0be816da747833e6bca3794f8b8",
            ),
            "live-reload-probe.mjs": (
                31_822,
                "55c382014a746b69300c03668139848f6b12495aaedd7f0756deb7612c5ac847",
            ),
            "model-activation-probe.mjs": (
                26_057,
                "dcc974db58add93cfb80ac613fae7a78d6ed60cce465f345af55ab0318f3bbda",
            ),
            "plug01-probe.mjs": (
                60_881,
                "f317ca4c7d9656c66a7081edd744812caaf70341076b9ea5753cd063a53bb055",
            ),
            "probe.mjs": (
                13_275,
                "ae3d5431e4de17e46f81c9fae0e03c347d9834c7b20414826b062f8768765416",
            ),
            "protected-archive-replacement-probe.mjs": (
                22_549,
                "a582d06bb9872cf9d0ff09169283c18451ba9f6e9e29d6c67848a4ba9e612db1",
            ),
            "protected-config-activation-probe.mjs": (
                20_622,
                "33b9da1d16f62201ee6616434008358df29c384c0e5f1af0f184493a4e7f59d1",
            ),
            "protected-cron-rescan-probe.mjs": (
                26_778,
                "0620c17829f08a0257c0d6a797c4326405d4bdb00427984c978af5a39aba21d1",
            ),
            "protected-observation-v1.mjs": (
                13_609,
                "90dd88392ffd88b6e9e29f682223c62a12f0c6a7c6bf9648a23d2be2dc218774",
            ),
            "protected-prompt-rebuild-probe.mjs": (
                15_501,
                "a85b38660925805e5ff50c3a3a177e076f203e9c3610f62e3e732d5f198e2666",
            ),
            "protected-route-probe.mjs": (
                40_223,
                "72e4ae79a6ee3370e49a465ef1ecd440f42997e4a2555bf64f461e848f5a0c4c",
            ),
            "restart-probe.mjs": (
                17_855,
                "6a6b83079c391e7baf87092366a910a4786132e7a0446ef1ba28029859318d1f",
            ),
        }
        self.assertEqual(set(expected), set(SOURCE_DIGESTS))
        for name, (size, digest) in expected.items():
            with self.subTest(name=name):
                raw = transformed_probe(name)
                self.assertEqual(len(raw), size)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)

    def test_materializes_every_pinned_probe_without_parent_literals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixed"
            materialize(output, list(SOURCE_DIGESTS))
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                sorted(SOURCE_DIGESTS),
            )
            for path in output.iterdir():
                raw = path.read_bytes()
                self.assertEqual(raw, transformed_probe(path.name))
                self.assertNotIn(b"2d2ddc43", raw)
                self.assertNotIn(b"475772bbb9", raw)
                self.assertEqual(path.stat().st_mode & 0o777, 0o444)
                self.assertEqual(len(hashlib.sha256(raw).digest()), 32)
            cron = (output / "protected-cron-rescan-probe.mjs").read_bytes()
            self.assertIn(b"cron-snapshot.runtime-DzbSus3I.js", cron)
            self.assertIn(b"session-snapshot-CMKRWMg1.js", cron)
            workshop = (output / "protected-route-probe.mjs").read_bytes()
            self.assertIn(b'const CONFIG = "/profile/config/openclaw.json";', workshop)
            self.assertIn(b'const WORKSHOP_DRAFT = "/proposal/PROPOSAL.md";', workshop)
            self.assertIn(b'mountObservation(dirname(CONFIG), "directory")', workshop)
            self.assertIn(
                b'mountObservation(dirname(WORKSHOP_DRAFT), "directory")', workshop
            )
            self.assertIn(
                b'from "/runtime/lib/node_modules/openclaw/dist/plugin-sdk/gateway-runtime.js"',
                workshop,
            )
            self.assertIn(b'scopes: ["operator.admin", "operator.write"]', workshop)
            self.assertIn(
                b'trace.not_tested_reason = "PROTECTED_SNAPSHOT_NOT_REBUILT"',
                workshop,
            )
            self.assertIn(
                b"trace.observations.reset_snapshot_cleared = resetSnapshotCleared",
                workshop,
            )
            self.assertIn(
                b"prompt.file.size === EXPECTED_SESSION_PROMPT_BYTES", workshop
            )
            self.assertIn(b"prompt.file.digest_error === null", workshop)
            self.assertIn(
                b"prompt.file.path === EXPECTED_SESSION_PROMPT_PATH", workshop
            )
            self.assertIn(b"trace.observations.rotation_observed_at", workshop)
            self.assertIn(b"rebuild.confirmed &&", workshop)
            self.assertIn(
                b"trace.observations.rebuilt_snapshot_matches_baseline = baselineMatched",
                workshop,
            )
            self.assertIn(b'OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1"', workshop)
            self.assertNotIn(
                b'const reset = normalTurn("fresh-session-reset", "/new");',
                workshop,
            )
            self.assertIn(
                b"OpenClaw 2026.7.1 (4b198da)",
                (output / "config-activation-probe.mjs").read_bytes(),
            )
            self.assertIn(
                b"OpenClaw 2026.7.1 (4b198da)",
                (output / "live-reload-probe.mjs").read_bytes(),
            )
            self.assertIn(
                b"OpenClaw 2026.7.1 (4b198da)",
                (output / "plug01-probe.mjs").read_bytes(),
            )

    def test_materializes_restore_authority_probes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "restore-authority"
            name = "protected-config-activation-probe.mjs"
            materialize(output, [name], restore_authority=True)
            raw = (output / name).read_bytes()
            self.assertEqual(raw, transformed_restore_authority_probe(name))
            self.assertEqual(len(raw), 20_622)
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                "bf0cea804669e71bc3fa13df449635e8b703385d139c5845a65c9f054f1a2a07",
            )
            self.assertIn(b"OpenClaw 2026.7.1 (805a4b1)", raw)
            self.assertNotIn(b"4b198daf", raw)

            archive_output = Path(temporary) / "restore-authority-archive"
            archive_name = "protected-archive-replacement-probe.mjs"
            materialize(archive_output, [archive_name], restore_authority=True)
            archive = (archive_output / archive_name).read_bytes()
            self.assertEqual(archive, transformed_restore_authority_probe(archive_name))
            self.assertEqual(len(archive), 22_549)
            self.assertEqual(
                hashlib.sha256(archive).hexdigest(),
                "4b152c299a53f9b23254d73101a8785b823011f78bfd34ba0d3cd98aa83d9c7f",
            )
            for stale in (b"4b198daf", b"45860", b"45841", b"369417908"):
                self.assertNotIn(stale, archive)

            prompt_output = Path(temporary) / "restore-authority-prompt"
            helper_name = "protected-observation-v1.mjs"
            prompt_name = "protected-prompt-rebuild-probe.mjs"
            materialize(
                prompt_output,
                [helper_name, prompt_name],
                restore_authority=True,
            )
            helper = (prompt_output / helper_name).read_bytes()
            prompt = (prompt_output / prompt_name).read_bytes()
            self.assertEqual(
                sorted(path.name for path in prompt_output.iterdir()),
                sorted([helper_name, prompt_name]),
            )
            self.assertEqual(helper, transformed_restore_authority_probe(helper_name))
            self.assertEqual(prompt, transformed_restore_authority_probe(prompt_name))
            self.assertEqual(len(helper), 13_609)
            self.assertEqual(
                hashlib.sha256(helper).hexdigest(),
                "81db497cbde9c07e211a406699896da37c137358d0b7534d8580eab43c47c216",
            )
            self.assertEqual(len(prompt), 15_501)
            self.assertEqual(
                hashlib.sha256(prompt).hexdigest(),
                "cc342cd6ec87164397f842a6c921917bcd25d3ac239d978f722d4fc59c5c5af4",
            )
            self.assertIn(b'from "./protected-observation-v1.mjs"', prompt)
            self.assertIn(b"OpenClaw 2026.7.1 (805a4b1)", prompt)
            for stale in (
                b"4b198daf",
                b"45_860",
                b"45_841",
                b"369_417_908",
                b"4e866a250429632f5796d977554acbaabe6f30dbf837457e32022eacdb9152c1",
                b"ec2b2022ed27f62840583d31264826c88514a04e7e7cc94d78820b021d6288b6",
                b"6226f46581416178666681d870d3ff54c5bccebeebb090cb3c996058db1c8a4a",
            ):
                self.assertNotIn(stale, helper)
                self.assertNotIn(stale, prompt)

            rejected_selections = {
                "partial-helper": [helper_name],
                "partial-prompt": [prompt_name],
                "duplicate": [helper_name, prompt_name, prompt_name],
                "mixed": [
                    "protected-config-activation-probe.mjs",
                    helper_name,
                    prompt_name,
                ],
                "unsupported": ["probe.mjs"],
            }
            for label, selection in rejected_selections.items():
                with self.subTest(label=label):
                    rejected = Path(temporary) / f"rejected-{label}"
                    with self.assertRaises(ValueError):
                        materialize(rejected, selection, restore_authority=True)
                    self.assertFalse(rejected.exists())

    def test_materializes_restore_authority_fresh_session_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "restore-authority-fresh-session"
            name = "protected-route-probe.mjs"
            materialize(output, [name], restore_authority=True)
            raw = (output / name).read_bytes()

            self.assertEqual([path.name for path in output.iterdir()], [name])
            self.assertEqual(raw, transformed_restore_authority_probe(name))
            self.assertEqual(len(raw), 40_223)
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                "094f4879f2ddb3dea3a15c73bfef09ff309a1847ec178e12fa23648da02617c2",
            )
            self.assertEqual((output / name).stat().st_mode & 0o777, 0o444)
            self.assertIn(b"OpenClaw 2026.7.1 (805a4b1)", raw)
            self.assertIn(
                b'from "/runtime/lib/node_modules/openclaw/dist/plugin-sdk/gateway-runtime.js"',
                raw,
            )
            self.assertIn(b'"ADM-02/reload/fresh-session-reset"', raw)
            self.assertIn(
                b"417fc06b87a539654433451aff12509ca7dca28003c9f2cedc91bcc611eba16e",
                raw,
            )
            self.assertNotIn(b"4b198daf", raw)
            self.assertNotIn(
                b"6226f46581416178666681d870d3ff54c5bccebeebb090cb3c996058db1c8a4a",
                raw,
            )

    def test_materializes_exact_restore_authority_cron_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "restore-authority-cron"
            helper_name = "protected-observation-v1.mjs"
            cron_name = "protected-cron-rescan-probe.mjs"
            materialize(
                output,
                [helper_name, cron_name],
                restore_authority=True,
            )
            helper = (output / helper_name).read_bytes()
            cron = (output / cron_name).read_bytes()

            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                sorted([helper_name, cron_name]),
            )
            self.assertEqual(helper, transformed_restore_authority_probe(helper_name))
            self.assertEqual(cron, transformed_restore_authority_probe(cron_name))
            self.assertEqual(len(helper), 13_609)
            self.assertEqual(
                hashlib.sha256(helper).hexdigest(),
                "81db497cbde9c07e211a406699896da37c137358d0b7534d8580eab43c47c216",
            )
            self.assertEqual(len(cron), 26_777)
            self.assertEqual(
                hashlib.sha256(cron).hexdigest(),
                "5ddecb878780ca7dc8c939921329964e678140f0bc67aacab52a7b9e184111e4",
            )
            self.assertEqual((output / helper_name).stat().st_mode & 0o777, 0o444)
            self.assertEqual((output / cron_name).stat().st_mode & 0o777, 0o444)
            self.assertIn(b'from "./protected-observation-v1.mjs"', cron)
            self.assertIn(b"OpenClaw 2026.7.1 (805a4b1)", cron)
            self.assertIn(b"runEpoch <= result.runAtMs", cron)
            self.assertNotIn(b"result.runAtMs === runEpoch", cron)
            for expected in (
                b"cron-DOr4RFbn.js",
                b"cron-snapshot.runtime-DrQirS_k.js",
                b"isolated-agent-2U26aOeI.js",
                b"session-CagbPApz.js",
                b"session-snapshot-8MgHKMdq.js",
                b"workspace-CKU1tzCf.js",
            ):
                self.assertIn(expected, cron)
            for stale in (
                b"cron-BoFeDMVi.js",
                b"cron-snapshot.runtime-DzbSus3I.js",
                b"isolated-agent-DNWCmOH_.js",
                b"session-B4NuLEbl.js",
                b"session-snapshot-CMKRWMg1.js",
                b"workspace-BKXau6p-.js",
            ):
                self.assertNotIn(stale, cron)

            for label, selection in {
                "partial-cron": [cron_name],
                "duplicate": [helper_name, cron_name, cron_name],
                "mixed": [
                    helper_name,
                    cron_name,
                    "protected-config-activation-probe.mjs",
                ],
            }.items():
                with self.subTest(label=label):
                    rejected = Path(temporary) / f"rejected-cron-{label}"
                    with self.assertRaises(ValueError):
                        materialize(rejected, selection, restore_authority=True)
                    self.assertFalse(rejected.exists())

    def test_materializes_exact_final_combined_bundles(self) -> None:
        expected = {
            "protected-archive-replacement-probe.mjs": (
                25_498,
                "db6e1181b54529c01e240700e338df5dbb7011fd29f5d22f92bfe710f65d71de",
            ),
            "protected-config-activation-probe.mjs": (
                23_366,
                "c79d775903636736c2ae5413f381b3a8f9ec17a1a179a7807c4a6e57624662f0",
            ),
            "protected-cron-rescan-probe.mjs": (
                25_894,
                "2200529fbe50c81666359b8a5d3f11ff52c088ab32a45dcc982bd5193bede16f",
            ),
            "protected-curator-restore-denial-probe.mjs": (
                26_571,
                "145672bc46fd8a2435e8c3bcd03c34578915fb9104f826d121e7b1726f89e949",
            ),
            "protected-observation-v1.mjs": (
                16_324,
                "11650e5906c8c1bd863abe462c10288f421645c35a69961cb143eb8e7163363b",
            ),
            "protected-prompt-rebuild-probe.mjs": (
                16_464,
                "9d6eb33127e5e7fd2439adfc1e6bb5fc87286ed03b3b2717cdaf55df54227dd7",
            ),
            "protected-route-probe.mjs": (
                44_825,
                "fc5f7499141f3a09e9347355dcac2284d781133b16ea05c0b2ee95fd8e6ce820",
            ),
            "protected-session-snapshot-fixed-probe.mjs": (
                42_266,
                "9ab66a23f17b85caed2593cb0300df8a71201b9f12f6ecb28fcde6b165eccd11",
            ),
        }
        self.assertEqual(set(expected), set(FINAL_COMBINED_SOURCE_DIGESTS))
        with tempfile.TemporaryDirectory() as temporary:
            for index, selection in enumerate(FINAL_COMBINED_SELECTIONS):
                output = Path(temporary) / f"final-{index}"
                names = sorted(selection)
                materialize(output, names, final_combined=True)
                self.assertEqual(
                    sorted(path.name for path in output.iterdir()),
                    names,
                )
                for name in names:
                    with self.subTest(name=name):
                        raw = (output / name).read_bytes()
                        size, digest = expected[name]
                        self.assertEqual(raw, transformed_final_combined_probe(name))
                        self.assertEqual(len(raw), size)
                        self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
                        self.assertEqual((output / name).stat().st_mode & 0o777, 0o444)
                        syntax = subprocess.run(
                            ["node", "--check", str(output / name)],
                            check=False,
                            capture_output=True,
                            text=True,
                        )
                        self.assertEqual(syntax.returncode, 0, syntax.stderr)

            archive = transformed_final_combined_probe(
                "protected-archive-replacement-probe.mjs"
            )
            helper = transformed_final_combined_probe("protected-observation-v1.mjs")
            route = transformed_final_combined_probe("protected-route-probe.mjs")
            cron = transformed_final_combined_probe("protected-cron-rescan-probe.mjs")
            snapshot = transformed_final_combined_probe(
                "protected-session-snapshot-fixed-probe.mjs"
            )
            prompt = transformed_final_combined_probe(
                "protected-prompt-rebuild-probe.mjs"
            )
            for raw in (archive, route, cron):
                self.assertIn(b"7fa98d8", raw)
                self.assertNotIn(b"805a4b1", raw)
            self.assertIn(
                b"5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154",
                helper,
            )
            self.assertIn(
                b"ae9d44f2c347a8b10a689d55c435ed0106a2a7aec40e0c6ceaefd0ea99d2564d",
                helper,
            )
            self.assertIn(
                b'const TARGET = "/opt/aragorn/runtime-profile/template-skill";',
                archive,
            )
            curator = transformed_final_combined_probe(
                "protected-curator-restore-denial-probe.mjs"
            )
            self.assertIn(
                b'const TARGET = "/opt/aragorn/runtime-profile/template-skill";',
                curator,
            )
            self.assertIn(
                b'const CONTROL_ROOT = "/tmp/aragorn-final-archive-control";',
                archive,
            )
            self.assertIn(b"const RUNTIME_UID = 992;", route)
            self.assertIn(b"const RUNTIME_GID = 992;", route)
            self.assertIn(
                b"const expectedRunId = `aragorn-protected-route-${label}-${RUN_NONCE}`;",
                route,
            )
            self.assertIn(b"runId === expectedRunId", route)
            self.assertIn(b"parsedSend.parsed", route)
            self.assertIn(b'parsedSend.value?.status === "started"', route)
            self.assertIn(b"parsedWait.value?.error == null", route)
            self.assertIn(
                b'"\\u26a0\\ufe0f Agent failed before reply: LLM request failed: network connection error.\\nLogs: openclaw logs --follow"',
                route,
            )
            self.assertIn(b'!Object.hasOwn(before, "error")', route)
            self.assertIn(
                b"beforeAbsent && turn.confirmed && afterCheck.ready && storeExact",
                route,
            )
            self.assertIn(b"EXACT_PROTECTED_SNAPSHOT_NOT_CREATED", route)
            self.assertNotIn(b"transport_completion", route)
            self.assertNotIn(b'parsedWait.value?.status === "ok"', route)
            for raw in (archive, helper, route):
                self.assertIn(b"function writableRoots(rootPaths)", raw)
                self.assertIn(b"accessSync(path, constants.W_OK)", raw)
                self.assertIn(b"exactExternalSingleton(configuration)", raw)
                self.assertNotIn(b"writableRootAliases", raw)
                self.assertNotIn(b"const LIVE_ROOTS", raw)
            self.assertIn(b"export const PROTECTED_ROOTS", helper)
            self.assertIn(
                b"/run/credentials/aragorn-agent-gateway.service/openclaw-config",
                helper,
            )
            self.assertIn(b"configuration.file?.size === 1811", helper)
            self.assertIn(b'configuration.file?.mode === "400"', helper)
            self.assertIn(
                b'const rawPid = process.env.ARAGORN_GATEWAY_PID ?? "";',
                helper,
            )
            self.assertIn(b"const procRoot = `/proc/${rawPid}`;", helper)
            self.assertIn(b'mountObservation("/route-input")', helper)
            self.assertIn(
                b"gateway.boundary.roots.workspace_skills.ready",
                route,
            )
            self.assertIn(
                b"gateway.boundary.roots.workspace_skills.writable",
                route,
            )
            self.assertIn(b"WORKSPACE_SKILLS_WRITABLE_BOUNDARY_REQUIRED", route)
            self.assertNotIn(b"discovery", prompt)
            self.assertNotIn(b'    "skills",\n    "info",', prompt)
            self.assertIn(
                b"""commands: [
      version,
      systemBefore.command,
      ...initialTurn.commands,
      ...rebuildTurn.commands,
      systemAfter.command,
    ],""",
                prompt,
            )
            self.assertIn(b"commands: [version, systemBefore.command]", prompt)
            self.assertIn(b"function exactSnapshot(value, turn)", prompt)
            self.assertIn(b"updated_at: entry.updatedAt", prompt)
            self.assertIn(b'value.entry.run_status === "timeout"', prompt)
            self.assertIn(b'value.entry.run_status === "failed"', prompt)
            self.assertIn(
                b"value.entry.runtime_ms ===\n"
                b"      value.entry.ended_at - value.entry.started_at",
                prompt,
            )
            self.assertIn(b"value.entry.ended_at <= value.entry.updated_at", prompt)
            self.assertIn(b"sendStartedAt <= value.entry.started_at", prompt)
            self.assertIn(b"value.entry.ended_at <= waitValue.endedAt", prompt)
            self.assertIn(b"value.entry.updated_at <= waitCompletedAt", prompt)
            self.assertIn(b"!sendResponse.parsed", prompt)
            self.assertIn(b"!waitResponse.parsed", prompt)
            self.assertIn(b"terminalOk &&", prompt)
            self.assertIn(b"terminalNetworkError", prompt)
            self.assertIn(b"network connection error", prompt)
            self.assertIn(b"exactSnapshot(initialSnapshot, initialTurn)", prompt)
            self.assertIn(b"exactSnapshot(rebuiltSnapshot, rebuildTurn)", prompt)
            self.assertNotIn(b"discovery", snapshot)
            self.assertNotIn(b'    "skills",\n    "info",', snapshot)
            self.assertNotIn(b"      entries: [],\n", snapshot)
            self.assertNotIn(b"initialSnapshot.prompt.exact_text.trim()", snapshot)
            self.assertIn(
                b"baselineSkillsPrompt === initialSnapshot.prompt.exact_text", snapshot
            )
            self.assertIn(b"boundaryBefore.ready &&", snapshot)
            self.assertIn(b"exactTarget(targetBefore) &&", snapshot)
            self.assertIn(b'value.entry.run_status === "timeout"', snapshot)
            self.assertIn(b'value.entry.run_status === "failed"', snapshot)
            self.assertIn(b"function exactInitialSnapshot(value, turn)", snapshot)
            self.assertIn(
                b"value.entry.runtime_ms ===\n"
                b"      value.entry.ended_at - value.entry.started_at",
                snapshot,
            )
            self.assertIn(b"value.entry.ended_at <= value.entry.updated_at", snapshot)
            self.assertIn(b"sendStartedAt <= value.entry.started_at", snapshot)
            self.assertIn(b"value.entry.ended_at <= waitValue.endedAt", snapshot)
            self.assertIn(b"value.entry.updated_at <= waitCompletedAt", snapshot)
            self.assertIn(b"!sendResponse.parsed", snapshot)
            self.assertIn(b"!waitResponse.parsed", snapshot)
            self.assertIn(b"terminalOk &&", snapshot)
            self.assertIn(b"terminalNetworkError", snapshot)
            self.assertIn(b"network connection error", snapshot)
            self.assertIn(
                b"exactInitialSnapshot(initialSnapshot, initialTurn)", snapshot
            )
            self.assertIn(
                b"exactRecoveredSnapshot(initial, final, attackerRef, turn)",
                snapshot,
            )
            self.assertIn(b"exactInitialSnapshot(final, turn)", snapshot)
            self.assertIn(b"cron-qc-KsHeU.js", cron)
            self.assertIn(b"session-snapshot-C3iM3syv.js", cron)
            self.assertIn(b"workspace-DvqxsRU0.js", cron)
            self.assertNotIn(b"discovery", cron)
            self.assertNotIn(b'    "skills",\n    "info",', cron)
            self.assertEqual(cron.count(b"737"), 4)
            self.assertNotIn(b"728", cron)
            self.assertIn(b'      model: "openai/gpt-5.5",', cron)
            self.assertNotIn(b"aragorn-runtime-action-mock/fixture-model", cron)

            for name in FINAL_COMBINED_SOURCE_DIGESTS:
                raw = transformed_final_combined_probe(name)
                self.assertNotIn(b"3b7218cb", raw)
                self.assertNotIn(b"/proc/1", raw)
                self.assertNotIn(b"/profile/config", raw)
                self.assertNotIn(b"/profile/state", raw)
                self.assertNotIn(b"/profile/home", raw)
                self.assertNotIn(b"/profile/workspace", raw)
                self.assertNotIn(b".pid === 1", raw)
                self.assertNotRegex(
                    raw.decode(),
                    r"roots\.[a-z_]+\.(?:explicit|read_only)",
                )

            invalid = {
                "both-modes": (
                    ["protected-archive-replacement-probe.mjs"],
                    {"restore_authority": True, "final_combined": True},
                ),
                "duplicate": (
                    [
                        "protected-observation-v1.mjs",
                        "protected-prompt-rebuild-probe.mjs",
                        "protected-prompt-rebuild-probe.mjs",
                    ],
                    {"final_combined": True},
                ),
                "partial-helper": (
                    ["protected-observation-v1.mjs"],
                    {"final_combined": True},
                ),
                "final-only-default": (
                    ["protected-curator-restore-denial-probe.mjs"],
                    {},
                ),
                "unsupported": (["probe.mjs"], {"final_combined": True}),
            }
            for label, (names, options) in invalid.items():
                with self.subTest(label=label):
                    rejected = Path(temporary) / f"rejected-final-{label}"
                    with self.assertRaises(ValueError):
                        materialize(rejected, names, **options)
                    self.assertFalse(rejected.exists())

    def test_materializes_only_exact_final_combined_v2_bundles(self) -> None:
        expected = {
            "PROPOSAL.md": (
                84,
                "a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a",
            ),
            "protected-archive-replacement-probe.mjs": (
                25_498,
                "4ead71ad73da16579fb85bc1287cb760a8b8b90838de9a9ea0ad2091fca87479",
            ),
            "protected-config-activation-probe.mjs": (
                23_366,
                "69a2c203e566128a2968b35b85b130cd50107b3ba9367512a50e56e73e65ca93",
            ),
            "protected-cron-rescan-probe.mjs": (
                35_318,
                "94d3b47162fd1bdc97028f44115ef54acfe8b7a296210a47a8a24a71771bb2d0",
            ),
            "protected-curator-restore-denial-probe.mjs": (
                26_571,
                "c43bbcc718df29114e9edcee8f8d6e8d3ad96f5c4dfc7e5b29b4743f3128f60d",
            ),
            "protected-observation-v1.mjs": (
                16_324,
                "91febf12bd6aa2e98f63b14001a74213c653c2eb9c8c7db57a55b3520fdd4f22",
            ),
            "protected-prompt-rebuild-probe.mjs": (
                16_464,
                "9d6eb33127e5e7fd2439adfc1e6bb5fc87286ed03b3b2717cdaf55df54227dd7",
            ),
            "protected-route-probe.mjs": (
                44_825,
                "65fda9d7406b9813017002cd7b6cde449475685b4410e45bca5b7aeed00ae7c1",
            ),
            "protected-session-snapshot-fixed-probe.mjs": (
                42_266,
                "9ab66a23f17b85caed2593cb0300df8a71201b9f12f6ecb28fcde6b165eccd11",
            ),
        }
        v1_config_digest = (
            b"ae9d44f2c347a8b10a689d55c435ed0106a2a7aec40e0c6ceaefd0ea99d2564d"
        )
        v2_config_digest = (
            b"b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e"
        )
        config_bound = {
            "protected-archive-replacement-probe.mjs",
            "protected-config-activation-probe.mjs",
            "protected-curator-restore-denial-probe.mjs",
            "protected-observation-v1.mjs",
            "protected-route-probe.mjs",
        }
        self.assertEqual(
            {
                name: digest
                for name, digest in FINAL_COMBINED_V2_SOURCE_DIGESTS.items()
                if name not in {"PROPOSAL.md", "protected-cron-rescan-probe.mjs"}
            },
            {
                name: digest
                for name, digest in FINAL_COMBINED_SOURCE_DIGESTS.items()
                if name != "protected-cron-rescan-probe.mjs"
            },
        )
        self.assertEqual(
            FINAL_COMBINED_V2_SOURCE_DIGESTS["protected-cron-rescan-probe.mjs"],
            "3733b27d34e692271b0ac7c93956017d55b318fef1dcabc27e3478531c0e47b3",
        )
        workshop_selection = frozenset({"PROPOSAL.md", "protected-route-probe.mjs"})
        self.assertEqual(
            FINAL_COMBINED_V2_SELECTIONS - {workshop_selection},
            FINAL_COMBINED_SELECTIONS,
        )
        self.assertIn(workshop_selection, FINAL_COMBINED_V2_SELECTIONS)
        self.assertEqual(set(expected), set(FINAL_COMBINED_V2_SOURCE_DIGESTS))
        config_probe = transformed_final_combined_v2_probe(
            "protected-config-activation-probe.mjs"
        )
        self.assertNotIn(
            b"const externalAuthorityDiagnostic =",
            config_probe,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, selection in enumerate(FINAL_COMBINED_V2_SELECTIONS):
                output = root / f"final-v2-{index}"
                names = sorted(selection)
                materialize(output, names, final_combined_v2=True)
                self.assertEqual(sorted(path.name for path in output.iterdir()), names)
                for name in names:
                    with self.subTest(name=name):
                        path = output / name
                        raw = path.read_bytes()
                        workshop = selection == workshop_selection
                        size, digest = (
                            (
                                50_175,
                                "07676570b96d8c0c54f40bd44f4132a2cdb06cb36002dd6f6c406f49afc3a705",
                            )
                            if workshop and name == "protected-route-probe.mjs"
                            else expected[name]
                        )
                        self.assertEqual(
                            raw,
                            transformed_final_combined_v2_probe(
                                name, workshop=workshop
                            ),
                        )
                        self.assertEqual(len(raw), size)
                        self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
                        self.assertEqual(path.stat().st_mode & 0o777, 0o444)
                        self.assertNotIn(v1_config_digest, raw)
                        self.assertNotIn(b"1811", raw)
                        if name in config_bound:
                            self.assertIn(v2_config_digest, raw)
                            self.assertIn(b"configuration.file?.size === 1880", raw)
                        if path.suffix == ".mjs":
                            syntax = subprocess.run(
                                ["node", "--check", str(path)],
                                check=False,
                                capture_output=True,
                                text=True,
                            )
                            self.assertEqual(syntax.returncode, 0, syntax.stderr)

            cli_output = root / "final-v2-cli"
            cli = subprocess.run(
                [
                    sys.executable,
                    str(
                        Path(__file__).resolve().parents[1]
                        / "scripts"
                        / "materialize_fixed_admission_probes.py"
                    ),
                    "--final-combined-v2",
                    str(cli_output),
                    "protected-route-probe.mjs",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(cli.returncode, 0, cli.stderr)
            self.assertEqual(
                (cli_output / "protected-route-probe.mjs").read_bytes(),
                transformed_final_combined_v2_probe("protected-route-probe.mjs"),
            )
            self.assertEqual(
                hashlib.sha256(
                    (cli_output / "protected-route-probe.mjs").read_bytes()
                ).hexdigest(),
                "65fda9d7406b9813017002cd7b6cde449475685b4410e45bca5b7aeed00ae7c1",
            )
            workshop_output = root / "final-v2-workshop"
            materialize(
                workshop_output,
                sorted(workshop_selection),
                final_combined_v2=True,
            )
            self.assertEqual(
                (workshop_output / "PROPOSAL.md").read_bytes(),
                (
                    Path(__file__).resolve().parents[1]
                    / "benchmark/fixtures/phase1-protected-workshop/PROPOSAL.md"
                ).read_bytes(),
            )
            workshop_probe = (
                workshop_output / "protected-route-probe.mjs"
            ).read_bytes()
            for literal in (
                b'const WORKSHOP_DRAFT = "/route-input/workshop-proposal-apply/PROPOSAL.md";',
                b"response: parsed,",
                b"trace.observations.target_after_proposal",
                b"trace.observations.native_proposal_result",
                b"trace.observations.native_apply_result",
                b"trace.observations.immediate_post_apply_snapshot",
                b"trace.observations.catalog_after_apply",
                b"trace.observations.next_same_session_turn",
                b"trace.observations.final_snapshot_transition",
                b"snapshot_version_advanced:",
                b"trace.observations.final_catalog",
            ):
                with self.subTest(literal=literal):
                    self.assertIn(literal, workshop_probe)

            invalid = {
                "both-final-modes": (
                    ["protected-route-probe.mjs"],
                    {"final_combined": True, "final_combined_v2": True},
                ),
                "restore-and-v2": (
                    ["protected-route-probe.mjs"],
                    {"restore_authority": True, "final_combined_v2": True},
                ),
                "duplicate": (
                    [
                        "protected-observation-v1.mjs",
                        "protected-prompt-rebuild-probe.mjs",
                        "protected-prompt-rebuild-probe.mjs",
                    ],
                    {"final_combined_v2": True},
                ),
                "partial-helper": (
                    ["protected-observation-v1.mjs"],
                    {"final_combined_v2": True},
                ),
                "unsupported": (["probe.mjs"], {"final_combined_v2": True}),
            }
            for label, (names, options) in invalid.items():
                with self.subTest(label=label):
                    rejected = root / f"rejected-final-v2-{label}"
                    with self.assertRaises(ValueError):
                        materialize(rejected, names, **options)
                    self.assertFalse(rejected.exists())

    def test_final_combined_v2_cron_retains_bounded_store_and_inventory_closure(
        self,
    ) -> None:
        cron = transformed_final_combined_v2_probe("protected-cron-rescan-probe.mjs")
        for literal in (
            b"const MAX_SESSION_STORE_BYTES = 512 * 1024;",
            b"const MAX_SQLITE_FILE_BYTES = 4 * 1024 * 1024;",
            b'const list = nativeCall("cron.list", CRON_LIST_PARAMS, commands);',
            b"cron_inventory_before: cronInventoryBefore,",
            b"cron_inventory_after_add: cronInventoryAfterAdd,",
            b"cron_inventory_after_remove: cronInventoryAfterRemove,",
            b"entry_document: entry,",
            b"store_document: store,",
            b'base64: raw.toString("base64"),',
            b'base64: storeRaw.toString("base64"),',
            b"canonicalJson(snapshot.store_document[sessionKey]) === canonicalEntry",
            b"snapshot.store.digest === sha256(retainedStoreRaw)",
            b"canonicalJson(snapshot.entry_document.skillsSnapshot?.promptRef) ===",
            b"canonicalJson([COHERENT_SESSION_KEY, sessionKey].sort())",
            b'"openclaw.sqlite"',
        ):
            with self.subTest(literal=literal):
                self.assertEqual(cron.count(literal), 1)

    def test_materializes_all_six_exact_v3_rebound_bundles(self) -> None:
        expected = {
            "ADM-02/update/archive-source-force-replacement": {
                "protected-archive-replacement-probe.mjs": "c89af8975bcdc8963659b39b354fc8b754d4805f7249a1cc766458cdad891328",
            },
            "ADM-02/update/core-updater-plugin-replacement": {
                "protected-route-probe.mjs": "4687054e9d7ea264c6772de4e0560fafb195ebbbfc7397333297abd6cc4347ff",
            },
            "ADM-02/update/curator-restore-activation": {
                "protected-curator-restore-denial-probe.mjs": "fd3fa9ec7dce5b626eb1243c3391279093d08555e7c81f67d1b4549160fca089",
                "protected-observation-v1.mjs": "672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
            },
            "ADM-02/reload/cron-rescan": {
                "protected-cron-rescan-probe.mjs": "94d3b47162fd1bdc97028f44115ef54acfe8b7a296210a47a8a24a71771bb2d0",
                "protected-observation-v1.mjs": "672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
            },
            "ADM-02/reload/missing-prompt-blob-rebuild": {
                "protected-prompt-rebuild-probe.mjs": "9d6eb33127e5e7fd2439adfc1e6bb5fc87286ed03b3b2717cdaf55df54227dd7",
                "protected-observation-v1.mjs": "672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
            },
            "ADM-02/reload/session-snapshot-consumer": {
                "protected-session-snapshot-fixed-probe.mjs": "9ab66a23f17b85caed2593cb0300df8a71201b9f12f6ecb28fcde6b165eccd11",
                "protected-observation-v1.mjs": "672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for ordinal, (case_id, files) in enumerate(expected.items()):
                with self.subTest(case_id=case_id):
                    output = root / f"case-{ordinal}"
                    manifest = materialize_openclaw_final_v3_rebound_case(
                        case_id, output
                    )
                    self.assertEqual(manifest["case_id"], case_id)
                    self.assertEqual(
                        [item["name"] for item in manifest["files"]], list(files)
                    )
                    self.assertEqual(output.stat().st_mode & 0o777, 0o555)
                    for name, digest in files.items():
                        path = output / name
                        self.assertEqual(path.stat().st_mode & 0o777, 0o444)
                        self.assertEqual(
                            hashlib.sha256(path.read_bytes()).hexdigest(), digest
                        )

            rejected = root / "rejected"
            with self.assertRaisesRegex(V3RebindError, "exact V3 rebound"):
                materialize_openclaw_final_v3_rebound_case("DET-01", rejected)
            self.assertFalse(rejected.exists())


if __name__ == "__main__":
    unittest.main()
