"""Semantic replay of inert admission inputs, not analyzer execution, B95 evidence or install authority."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
from unittest import TestCase

from aragorn.admission_artifact_graph import retain_admission_artifact_graph
from aragorn.analyze import AnalyzerResult
from aragorn.analyzer_receipt import retain_analyzer_run
from aragorn.cas import CASError
from aragorn.decision_receipt import DecisionReceiptError, retain_decision_v3
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import verify_pi_core_installed_bundle_readback as reader
from scripts.verify_pi_core_installed_bundle_readback import main, verify_installed_bundle_readback
from tests import test_pi_core_installed_bundle_readback as materialization


class InstallAdmissionReplay(TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse B76's actual wrapper/stdout encoder and retained source manifest.
        f = cls.f = materialization.InstalledReadback
        cls.addClassCleanup(f.doClassCleanups)
        f.setUpClass()
        cls.graph_verifier = canonical_digest("inert graph verifier identity")
        cls.analyzer_verifier = canonical_digest("inert analyzer verifier identity")
        cls.graph = retain_admission_artifact_graph(f.store, f.manifest, verifier_implementation_digest=cls.graph_verifier)
        # No executable is read, written as a program or invoked. The marker is
        # opaque CAS input for the analyzer receipt's byte-identity check only.
        marker = f.put(b"B100 inert protocol identity; not a program")
        tool = "/fixture/never-executed"
        config = dict(name="inert-scanner", version="1", argv=[tool], operator_argv0=tool, executable_digest=marker)
        config_pin = f.document(config)
        identity = dict(name=config["name"], version=config["version"], config_digest=config_pin, executable_digest=marker)
        request = dict(schema="aragorn/analyzer-request/v1", workspace="/fixture/no-workspace", subject_digest=f.tree,
                       analyzer=identity, limits=dict(timeout_seconds=1, output_bytes=4096))
        protocol_fixture = AnalyzerResult(**identity, status="ok", returncode=0, raw_configuration=canonical_json(config),
                                          raw_request=canonical_json(request) + b"\n")
        cls.receipt = retain_analyzer_run(f.store, protocol_fixture, verifier_implementation_digest=cls.analyzer_verifier)
        cls.decisions = {}
        for missing, required in ((False, [config["name"]]), (True, [config["name"], "missing-scanner"])):
            policy = f.document(dict(schema="aragorn/policy/v1", id="test-only", version=1, required_analyzers=required,
                                     hard_deny_reason_codes=[], review_severities=["high"]))
            pin = retain_decision_v3(f.store, manifest_digest=f.manifest, artifact_graph_digest=cls.graph, policy_digest=policy,
                analyzer_run_receipt_digests=[cls.receipt], analyzer_verifier_digest=cls.analyzer_verifier,
                artifact_graph_verifier_digest=cls.graph_verifier)
            cls.decisions[missing] = (policy, pin)
        cls.clean_revocations = f.document(dict(schema="aragorn/protected-install-revocations/v1", context_ids=[]))
        cls.runtime_policy = f.document(dict(schema="aragorn/runtime-action-policy/v1", id="test-only",
            version=1, default="BLOCK", sensor_digest=canonical_digest("sensor"),
            revocation_source_digest=canonical_digest("revocation source"), allow=[]))

    def managed_host(self):
        f = self.f
        rows = {r["path"]: r for r in f.host_profile["files"]}
        sources = {"/" + r["path"]: r for r in f.snap}
        for path in (reader.ENTRY, reader.POLICY_MANIFEST_HELPER):
            source = (materialization.SOURCE.parents[2] / path.removeprefix("/opt/aragorn/")).read_bytes()
            digest = "sha256:" + hashlib.sha256(source).hexdigest()
            rows[path] = dict(path=path, digest=digest, size=len(source))
            module = "aragorn." + path.split("/")[-1].removesuffix(".py")
            sources[path] = dict(module=module, path=path[1:], digest=digest)
        host_pin = f.document(f.host_profile | dict(files=[rows[k] for k in sorted(rows)]))
        return f.host | dict(host_profile_digest=host_pin, files=len(rows)), list(sources.values())

    def nomination(self, *, missing_required=False, forge_allow=False, context_changes=None, revocations=None,
                   managed=False, policy_members=None, legacy_pin=False, omit_helper=False):
        f = self.f
        policy_pin, pin = self.decisions[missing_required]
        decision = json.loads(f.archive.read(pin))
        self.assertEqual(decision["verdict"], "ERROR" if missing_required else "ALLOW")
        if forge_allow:
            self.assertTrue(missing_required)
            pin = f.document(decision | dict(verdict="ALLOW", reason_codes=[]))
        context = f.context | dict(decision_digest=pin, artifact_graph_digest=self.graph, policy_digest=policy_pin,
            analyzer_run_receipt_digests=[self.receipt], analyzer_verifier_digest=self.analyzer_verifier,
            artifact_graph_verifier_digest=self.graph_verifier) | (context_changes or {})
        context_pin = f.document(context)
        host, snap, deployment_policy = f.host, f.snap, policy_pin
        if managed:
            host, snap = self.managed_host()
            if omit_helper:
                snap = [r for r in snap if "/" + r["path"] != reader.POLICY_MANIFEST_HELPER]
            if not legacy_pin:
                deployment_policy = f.document(dict(schema="aragorn/pi-core-policy-manifest/v1",
                    admission_policy_digest=policy_pin, runtime_action_policy_digest=self.runtime_policy) |
                    (policy_members or {}))
        plan = f.plan | dict(host_profile_digest=host["host_profile_digest"], context=f.plan["context"] | dict(digest=context_pin),
            deployment=f.plan["deployment"] | dict(digest=f.document(f.deployment | dict(policy=deployment_policy))),
            revocations=f.plan["revocations"] | dict(digest=revocations or self.clean_revocations))
        status, raw = f.stdout(plan, context, host=host, snap=snap)
        self.assertEqual(status, 0)
        return dict(owner_pin=f.put(raw), plan_pin=f.document(plan), context_pin=context_pin, manifest_pin=f.manifest)

    def test_replayed_allow_and_pinned_revocations_do_not_authorize_current_context(self):
        pins = self.nomination()
        report = verify_installed_bundle_readback(self.f.archive, **pins, replay_admission=True)
        self.assertEqual(report["schema"], "aragorn/pi-core-installed-bundle-admission-finding/v1")
        self.assertEqual(report["retained_decision_verdict"], "ALLOW")
        self.assertIs(report["context_absent_from_pinned_revocations"], True)
        self.assertIs(report["decision_or_revocation_replayed"], True)
        self.assertIs(report["reported_installed_tree_matches_approved_bytes"], True)
        for name in ("current_context_validity_verified", "activation_authorized", "phase3_exit_eligible",
                     "live_filesystem_readback_reperformed", "worker_consumption_verified", "private_transaction_replayed"):
            self.assertIs(report[name], False)
        base = verify_installed_bundle_readback(self.f.archive, **pins)
        self.assertIs(base["decision_or_revocation_replayed"], False)
        self.assertNotIn("retained_decision_verdict", base)
        self.assertNotIn("policy_manifest_digest", report)

    def test_managed_replay_validates_two_original_documents_and_replays_only_admission(self):
        pins = self.nomination(managed=True)
        report = verify_installed_bundle_readback(self.f.archive, **pins, replay_admission=True)
        self.assertEqual(report["schema"], "aragorn/pi-core-installed-bundle-admission-finding/v2")
        self.assertEqual(report["admission_policy_digest"], self.decisions[False][0])
        self.assertEqual(report["runtime_action_policy_digest"], self.runtime_policy)
        self.assertEqual(report["policy_manifest_digest"], canonical_digest(dict(schema="aragorn/pi-core-policy-manifest/v1",
            admission_policy_digest=self.decisions[False][0], runtime_action_policy_digest=self.runtime_policy)))
        self.assertEqual(report["retained_decision_verdict"], "ALLOW")
        self.assertFalse(report["activation_authorized"])
        self.assertFalse(report["phase3_exit_eligible"])

    def test_managed_replay_refuses_mixed_roles_missing_bytes_legacy_pin_and_missing_source(self):
        admission = self.decisions[False][0]
        variants = ((dict(policy_members=dict(admission_policy_digest=self.runtime_policy,
                                             runtime_action_policy_digest=admission)), "policy manifest"),
                    (dict(policy_members=dict(runtime_action_policy_digest=canonical_digest("absent runtime policy"))),
                     "policy manifest"),
                    (dict(legacy_pin=True), "policy manifest"),
                    (dict(context_changes=dict(policy_digest=self.runtime_policy)), "approved install context differs"),
                    (dict(omit_helper=True), "missing protected install source"))
        for changes, reason in variants:
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, reason):
                verify_installed_bundle_readback(self.f.archive, **self.nomination(managed=True, **changes),
                                                 replay_admission=True)

    def test_real_nonallow_and_resealed_allow_refuse(self):
        for forged, why in ((False, "does not allow"), (True, "does not match replayed evidence")):
            with self.subTest(forged=forged), self.assertRaisesRegex(ValueError, why):
                verify_installed_bundle_readback(self.f.archive, **self.nomination(missing_required=True, forge_allow=forged),
                                                 replay_admission=True)

    def test_missing_selected_bytes_and_wrong_analyzer_verifier_refuse(self):
        missing = canonical_digest("absent input")
        variants = ((dict(revocations=missing), CASError), (dict(context_changes={"decision_digest":missing}), DecisionReceiptError),
                    (dict(context_changes={"analyzer_verifier_digest":canonical_digest("another verifier")}), DecisionReceiptError))
        for changes, error in variants:
            with self.subTest(changes=changes), self.assertRaises(error):
                verify_installed_bundle_readback(self.f.archive, **self.nomination(**changes), replay_admission=True)

    def test_revoked_context_refuses_even_with_semantically_valid_allow(self):
        pin = self.f.document(dict(schema="aragorn/protected-install-revocations/v1", context_ids=[self.f.context["context_id"]]))
        with self.assertRaisesRegex(ValueError, "appears in pinned revocations"):
            verify_installed_bundle_readback(self.f.archive, **self.nomination(revocations=pin), replay_admission=True)

    def test_cli_refusal_is_redacted_and_has_no_json_result(self):
        pins = self.nomination(revocations=canonical_digest("missing private revocation snapshot"))
        argv = ["--archive", str(self.f.archive.root), "--replay-admission"]
        for name, pin in pins.items():
            argv.extend(["--" + name.replace("_", "-"), pin])
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(main(argv), 1)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(err.getvalue(), "Install admission replay refused.\n")
