"""First focused contracts for the new offline update branch; no native execution."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import capture_runtime_native_plugin_update_check as capture
from scripts import materialize_native_plugin_update_fixture as fixture
from scripts import runtime_native_plugin_update_check as guest


class NativePluginUpdateTests(unittest.TestCase):
    def test_exact_bundle_and_inert_marketplace(self):
        adapter = fixture._adapter()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / guest._STAGED.name
            root.mkdir()
            manifest = fixture.materialize(root / "plugin-package-skill-replacement")
            root.chmod(0o555)
            try:
                capture._audit_bundle(root, manifest)
                self.assertEqual(len(manifest["files"]), 13)
                self.assertEqual(set(fixture.payloads()), set(guest._BUNDLE))
                self.assertEqual(
                    adapter.marketplace()["plugins"][0]["source"], "./candidate-source"
                )
                for version in ("1.0.0", "2.0.0"):
                    package = json.loads(adapter.fixture_files(version)["package.json"])
                    self.assertEqual(package["name"], adapter.PLUGIN_ID)
                    self.assertFalse(
                        {"scripts", "dependencies", "optionalDependencies"}
                        & set(package)
                    )
                path = root / "plugin-package-skill-replacement/marketplace.json"
                path.chmod(0o644)
                with self.assertRaisesRegex(Exception, "update input custody changed"):
                    capture._audit_bundle(root, manifest)
            finally:
                for path in sorted(root.rglob("*"), key=lambda p: len(p.parts)):
                    if path.is_dir():
                        path.chmod(0o755)
                root.chmod(0o755)

    def test_update_contract_preserves_records_and_rejects_mutation(self):
        adapter = fixture._adapter()
        prior = adapter._prior()
        base = adapter._base(prior)
        retained = json.loads(
            (
                fixture._ROOT
                / "benchmark/evidence/runtime-action-worker-final-combined-v3-route-plugin-force-reinstall-systemd-p3-final-2026-08-28.json"
            ).read_bytes()
        )["route_observation"]["document"]["action"]
        action = {
            "before": {
                "boundary": retained["prerequisites"]["boundary_before"],
                "plugin": retained["prerequisites"]["plugin_before"],
                "skills": retained["prerequisites"]["skills_status_before"],
                "info": retained["prerequisites"]["system_info_before"],
            },
            "after": {
                "boundary": retained["observations"]["boundary_after"],
                "plugin": retained["observations"]["plugin_after"],
                "skills": retained["observations"]["skills_status_after"],
                "info": retained["observations"]["system_info_after"],
            },
            "commands": retained["commands"],
        }
        for side in ("before", "after"):
            value = action[side]["plugin"]["response"]["value"]
            value["plugin"]["id"] = adapter.PLUGIN_ID
            value["plugin"]["source"] = str(base.TARGET_ROOT / "index.js")
            value["install"] = adapter.install_record()
            for key in ("baseline_source", "candidate_source"):
                action[side]["boundary"][key]["manifest"]["skills"] = ["."]
        output = (
            f"Install policy target=plugin:{adapter.PLUGIN_ID} request=plugin-dir/update "
            "origin=plugin-package pathKind=directory source=local-path/user: "
            f"blocked by install policy: {base.EXPECTED_BLOCK_REASON}\n"
            f"Failed to update {adapter.PLUGIN_ID}: blocked by install policy: {base.EXPECTED_BLOCK_REASON} "
            f"(marketplace plugin {adapter.PLUGIN_ID} from {adapter.ROOT / 'marketplace.json'}).\n"
        ).encode()
        action["commands"][4].update(
            argv=[base.NODE, base.OPENCLAW, "plugins", "update", adapter.PLUGIN_ID],
            stdout_excerpt=output.decode(),
            stdout_bytes=len(output),
            stdout_digest=adapter.digest(output),
            stderr_excerpt="",
            stderr_bytes=0,
            stderr_digest=adapter.digest(b""),
        )
        records = {adapter.PLUGIN_ID: adapter.install_record()}
        result = adapter.validate(
            action, base, prior, records, records, dict.fromkeys(adapter.CHECKS, False)
        )
        self.assertTrue(result["explicit_policy_denial"])
        self.assertTrue(result["tracked_record_unchanged"])
        self.assertFalse(result["logical_database_unchanged_verified"])
        self.assertFalse(result["qualification_eligible"])
        for mutation in (
            "record",
            "argv",
            "config",
            "channel",
            "omitted_prefix",
            "extra_line",
        ):
            changed = copy.deepcopy(action)
            after_records = copy.deepcopy(records)
            if mutation == "record":
                after_records[adapter.PLUGIN_ID]["version"] = "2.0.0"
            elif mutation == "argv":
                changed["commands"][4]["argv"][-2] = "install"
            elif mutation == "config":
                changed["after"]["boundary"]["config"]["canonical_digest"] = (
                    "sha256:" + "0" * 64
                )
            elif mutation == "channel":
                changed["commands"][4]["stderr_bytes"] = 1
            else:
                changed_output = (
                    output.split(b"\n", 1)[1]
                    if mutation == "omitted_prefix"
                    else output + b"unexpected\n"
                )
                changed["commands"][4].update(
                    stdout_excerpt=changed_output.decode(),
                    stdout_bytes=len(changed_output),
                    stdout_digest=adapter.digest(changed_output),
                )
            with self.subTest(mutation=mutation), self.assertRaises(adapter.Refusal):
                adapter.validate(
                    changed,
                    base,
                    prior,
                    records,
                    after_records,
                    dict.fromkeys(adapter.CHECKS, False),
                )

    def test_new_guest_only_invocation_and_controlled_failure(self):
        adapter = fixture._adapter()
        diagnostic = adapter.diagnostic("POLICY_DENIAL")
        raw = adapter.canonical(diagnostic) + b"\n"
        token = "a" * 64
        p37b = SimpleNamespace(
            _GATEWAY_HOME=Path("/var/lib/aragorn-agent-gateway/home"),
            _GATEWAY_STATE=Path("/var/lib/aragorn-agent-gateway/state"),
            _GATEWAY_WORKSPACE=Path("/var/lib/aragorn-agent-gateway/workspace"),
        )
        with (
            patch.object(
                guest.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 126, raw, b""),
            ) as run,
            self.assertRaises(guest.prior.PluginFixtureError),
        ):
            guest._invoke(p37b, 123, token)
        argv = run.call_args.args[0]
        self.assertEqual(argv[-1], str(guest.prior._INPUT / "adapter" / fixture._PROBE))
        self.assertNotIn(token, repr(argv))
        self.assertEqual(run.call_args.kwargs["env"]["OPENCLAW_GATEWAY_TOKEN"], token)
        envelope = b"native plugin update fixture refused: PLUGIN_PACKAGE_DENIAL: adapter POLICY_DENIAL\n"
        with patch.object(
            capture.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 126, b"", envelope + raw),
        ):
            refused = capture._invoke_guest(["exec", "fixed"], "b" * 64)
        self.assertEqual(refused["status"], "REFUSED")
        self.assertFalse(refused["phase3_eligible"])
        bad = copy.deepcopy(diagnostic)
        bad["checks"]["sources"] = "untrusted text"
        with self.assertRaises(guest.prior.PluginFixtureError):
            guest._decode_diagnostic(adapter.canonical(bad) + b"\n", None)
        sentinel = {"plugin_package": {"document": "new route only"}}
        with patch.object(guest.prior, "_run", return_value=sentinel) as inherited:
            result = guest._run("b" * 64, (os.geteuid(), os.getegid()))
        inherited.assert_called_once()
        self.assertIn("plugin_update", result)
        self.assertNotIn("plugin_package", result)
        self.assertFalse(result["route_qualified"])


if __name__ == "__main__":
    unittest.main()
