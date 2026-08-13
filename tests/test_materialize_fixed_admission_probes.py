from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.materialize_fixed_admission_probes import (
    SOURCE_DIGESTS,
    materialize,
    transformed_probe,
    transformed_restore_authority_probe,
)


class FixedAdmissionProbeMaterializerTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
