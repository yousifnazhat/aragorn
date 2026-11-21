"""Readback comparison only: real wrapper stdout, inert producer/custody, original retained text."""
from contextlib import ExitStack, redirect_stdout
import copy
import hashlib
import importlib.util
from io import BytesIO, StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from aragorn import pi_core_bundle_install_entry as install
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase3_deployment import BINDING_DIMENSIONS
from scripts import verify_pi_core_installed_bundle_readback as reader


SOURCE = Path(__file__).resolve().parents[1] / "packaging/pi-core/coordinator.py"


class InstalledReadback(unittest.TestCase):
    @classmethod
    def put(cls, raw):
        return cls.store.put(BytesIO(raw), max_bytes=len(raw))

    @classmethod
    def document(cls, value):
        return cls.put(canonical_json(value))

    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.store = CAS(Path(tmp.name) / "archive")
        cls.archive = CAS(cls.store.root, read_only=True)
        # Construction exercises the actual retained manifest parser; no acquisition or installation.
        payload = b"Sum the fabricated numbers.\n"
        files = [dict(path="SKILL.md", digest=cls.put(payload), size=len(payload), executable=False)]
        cls.tree = canonical_digest(files)
        cls.manifest = cls.document(dict(schema="aragorn/manifest/v1", source=dict(kind="local", path="bundle"),
                                   tree_digest=cls.tree, files=files, closure=dict(scope="source_tree", status="complete")))
        cls.member = files[0]["digest"]
        pin = canonical_digest
        cls.deployment = {k: pin(k) for k in BINDING_DIMENSIONS}
        cls.context = dict(schema="aragorn/protected-install-context/v2", authority="BROKER_CONTEXT_ONLY_NOT_INSTALLER_AUTHORITY",
            context_id=pin("context"), status="active", expires_at_unix=200, operation="install", expected_active=None,
            decision_digest=pin("decision"), manifest_digest=cls.manifest, artifact_graph_digest=pin("graph"),
            policy_digest=cls.deployment["policy"], analyzer_run_receipt_digests=[pin("analysis")],
            analyzer_verifier_digest=pin("consumer"), artifact_graph_verifier_digest=pin("graph-consumer"),
            target_runtime_digest=cls.deployment["runtime_commit_or_image"], runtime_conformance_digest=pin("conformance"),
            destination=dict(target_name="my-skill", root_device=2, root_inode=3))
        spec = importlib.util.spec_from_file_location("_b76_install_test_wrapper", SOURCE)
        cls.wrapper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.wrapper)
        src = "opt/aragorn/src/"
        names = ("aragorn", "aragorn.pi_core_coordinator_entry", "aragorn.pi_core_bundle_install_entry")
        paths = (src + "aragorn/__init__.py", src + "aragorn/pi_core_coordinator_entry.py",
                 src + "aragorn/pi_core_bundle_install_entry.py")
        def code(path):
            return (SOURCE.parents[2] / path.removeprefix("opt/aragorn/")).read_bytes()
        def digest(raw):
            return "sha256:" + hashlib.sha256(raw).hexdigest()
        cls.snap = [dict(module=n, path=p, digest=digest(code(p))) for n, p in zip(names, paths)]
        python, std = "/usr/bin/python3.12", "/usr/lib/python3.12"
        expected = {Path("/" + p): code(p) for p in paths}
        for path in (Path(python), *cls.wrapper._TOOLS):
            expected[path] = str(path).encode()
        expected[cls.wrapper._LOADER] = code(str(cls.wrapper._LOADER)[1:])
        expected[cls.wrapper._WRAPPER] = SOURCE.read_bytes()
        cls.host_profile = dict(schema="aragorn/pi-core-coordinator-host/v1", target="linux-arm64-cpython312",
            python_executable=python, wrapper_path=str(cls.wrapper._WRAPPER), stdlib_roots=[std], sys_path=[std],
            absent_sys_path=[], files=[dict(path=str(p), digest=digest(expected[p]), size=len(expected[p])) for p in sorted(expected)])
        cls.wrapper._profile(cls.host_profile)  # Same format as a real prepared host; never open a named path.
        cls.host_pin = cls.document(cls.host_profile)
        cls.host = dict(schema="aragorn/pi-core-coordinator-host-observation/v1",
            authority="PINNED_HOST_TCB_ONLY_NOT_CONSUMED_CODE_OR_PHASE3", pid=os.getpid(),
            host_profile_digest=cls.host_pin, python_executable=python, files=len(expected), phase3_exit_eligible=False)
        cls.plan = dict(schema="aragorn/pi-core-bundle-install-plan/v1", host_profile_digest=cls.host_pin,
            candidate_cas_root="/owned/candidate", predecessor_cas_root=None, runtime_conformance_digest=pin("conformance"),
            context=dict(path="/owned/context", digest=cls.document(cls.context)),
            deployment=dict(path="/owned/deployment", digest=cls.document(cls.deployment)),
            revocations=dict(path="/owned/revocations", digest=pin("revocations")), launch=dict(path="/owned/launch", digest=pin("launch")))
        cls.plan_pin = cls.document(cls.plan)
        code, raw = cls.stdout(cls.plan, cls.context)
        if code != 0:
            raise AssertionError("real wrapper refused inert readback fixture: " + raw.decode("ascii"))
        cls.raw, cls.owner = raw, json.loads(raw)
        cls.pins = dict(plan_pin=cls.plan_pin, context_pin=cls.plan["context"]["digest"], manifest_pin=cls.manifest,
                        owner_pin=cls.put(raw))

    @classmethod
    def stdout(cls, plan, context):
        s = cls.wrapper
        raw = StringIO()
        plan_pin = canonical_digest(plan)
        argv = [str(s._WRAPPER), "--install-bundle", "/owned/host", cls.host_pin, "/owned/plan", plan_pin,
                str(time.monotonic_ns() + 10_000_000_000)]
        obs = dict(schema="aragorn/pi-core-bundle-install-result/v1", authority="PROTECTED_MATERIALIZATION_ONLY_NOT_ACTIVATION_OR_PHASE3",
            status="INSTALLED_NOT_ACTIVATED_OR_QUALIFIED", phase3_exit_eligible=False, failure_stage=None,
            managed_call_attempted=False, managed_result=None, owned_inputs_closed=True, owned_destination_closed=True,
            plan_digest=plan_pin, deployment_digest=plan["deployment"]["digest"], context_digest=canonical_digest(context),
            host_before=cls.host, host_after=cls.host, source_before=cls.snap, source_after=cls.snap,
            installation_attempted=True, publication_state="PUBLISHER_RETURNED", input_cleanup_uncertainty=[],
            transaction=dict(schema="aragorn/protected-install-transaction/v1", tree_digest=cls.tree),
            recovery=None, observed_tree_digest=cls.tree)
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {s.__name__: s}))
            sys.modules.pop(s._PRIVATE, None)
            stack.enter_context(patch.object(s, "__file__", str(s._WRAPPER)))
            stack.enter_context(patch.object(s, "_flags"))
            stack.enter_context(patch.object(s, "_hold_host", return_value=Mock()))
            stack.enter_context(patch.object(s, "_bootstrap", return_value=Mock()))
            entry = stack.enter_context(patch.object(install, "run", return_value=obs))
            stack.enter_context(patch.object(sys, "argv", argv))
            stack.enter_context(redirect_stdout(raw))
            code = s.main()
            entry.assert_called_once()
        return code, raw.getvalue().encode("ascii")

    def verify(self, **changes):
        return reader.verify_installed_bundle_readback(self.archive, **(self.pins | changes))

    def altered(self, **changes):
        return self.put(canonical_json(self.owner | changes) + b"\n")

    def test_actual_wrapper_stdout_and_approved_bytes_give_only_a_reported_materialization_match(self):
        result = self.verify()
        self.assertTrue(result["reported_installed_tree_matches_approved_bytes"])
        self.assertEqual(result["observed_tree_digest"], self.tree)
        self.assertEqual(result["verified_retained_members"], 1)
        self.assertFalse(any(result[k] for k in ("live_filesystem_readback_reperformed", "private_transaction_replayed",
            "decision_or_revocation_replayed", "worker_consumption_verified", "activation_authorized", "phase3_exit_eligible")))

    def test_update_readback_uses_approved_successor_and_predecessor_context_shape(self):
        context = self.context | dict(operation="update", expected_active={
            "context_id": canonical_digest("prior"), "manifest_digest": canonical_digest("old-source")})
        pin = self.document(context)
        plan = self.plan | dict(context=self.plan["context"] | dict(digest=pin), predecessor_cas_root="/owned/predecessor")
        code, raw = self.stdout(plan, context)
        self.assertEqual(code, 0)
        self.assertEqual(self.verify(owner_pin=self.put(raw), context_pin=pin, plan_pin=self.document(plan))["operation"], "update")

    def test_v1_missing_readback_noncanonical_stdout_and_missing_independent_owner_refuse(self):
        for raw in (canonical_json(self.owner | dict(schema="aragorn/pi-core-bundle-install-report/v1")) + b"\n",
                    canonical_json(self.owner | dict(observed_tree_digest=None)) + b"\n", self.raw[:-1], self.raw + b"\n"):
            with self.subTest(raw=raw[-2:]), self.assertRaises((ValueError, RuntimeError)):
                self.verify(owner_pin=self.put(raw))
        with self.assertRaises(CASError):
            self.verify(owner_pin=canonical_digest("no selected report"))

    def test_uncertain_custody_and_unbound_source_refuse_even_with_a_matching_tree(self):
        changed = copy.deepcopy(self.snap)
        changed[-1]["digest"] = canonical_digest("other source")
        for fields in (dict(wrapper_stage="WRAPPER_CLEANUP"), dict(wrapper_cleanup={"host": "CLEANUP_HOLD", "source_loader": "CLOSED"}),
                       dict(owned_inputs_closed=False), dict(input_cleanup_uncertainty_digest=canonical_digest(["unknown"])),
                       dict(host_after=self.host | dict(pid=self.host["pid"] + 1)),
                       dict(host_before=self.host | dict(qualified=True), host_after=self.host | dict(qualified=True)),
                       dict(source_before=changed, source_after=changed), dict(source_before=self.snap[:-1]),
                       dict(activation_authorized=True)):
            with self.subTest(fields=fields.keys()), self.assertRaises(ValueError):
                self.verify(owner_pin=self.altered(**fields))

    def test_no_substitution_between_owner_tree_approved_plan_context_or_manifest(self):
        for kwargs in (dict(owner_pin=self.altered(observed_tree_digest=canonical_digest("other tree"))),
                       dict(plan_pin=self.document(self.plan | {"candidate_cas_root": "/other/candidate"})),
                       dict(context_pin=self.document(self.context | {"context_id": canonical_digest("other context")})),
                       dict(manifest_pin=canonical_digest("foreign manifest"))):
            with self.subTest(pin=tuple(kwargs)), self.assertRaises(ValueError):
                self.verify(**kwargs)

    def test_resealed_contexts_outside_install_contract_cannot_match(self):
        for field in (dict(context_id="sha256:" + "0" * 64), dict(expires_at_unix=True),
                      dict(destination=self.context["destination"] | dict(root_inode=0)),
                      dict(destination=self.context["destination"] | dict(target_name="../other")),
                      dict(decision_digest="unknown"), dict(artifact_graph_verifier_digest="unknown"),
                      dict(analyzer_run_receipt_digests=[canonical_digest("one")] * 2),
                      dict(quarantine_receipt_digest=canonical_digest("quarantine"), gateway_profile_digest=None)):
            context_pin = self.document(self.context | field)
            plan_pin = self.document(self.plan | dict(context=self.plan["context"] | dict(digest=context_pin)))
            report_pin = self.altered(plan_digest=plan_pin, context_digest=context_pin)
            with self.subTest(field=tuple(field)), self.assertRaises(ValueError):
                self.verify(context_pin=context_pin, plan_pin=plan_pin, owner_pin=report_pin)

    def test_resealed_v2_report_and_matching_source_rows_cannot_upgrade_a_real_v1_wrapper_or_old_installer(self):
        for path, earlier in ((reader.WRAPPER, "sha256:256db44b799ad54efd3739e370716be89d2ac7315336d9c90a3cf90f8b4ee949"),
                              (reader.ENTRY, "sha256:a3fc8eca03c23154c89766bc712c47b52df8852ccfe68da452287840d1f88912")):
            rows = [r | dict(digest=earlier) if r["path"] == path else r for r in self.host_profile["files"]]
            host_pin = self.document(self.host_profile | dict(files=rows))
            host = self.host | dict(host_profile_digest=host_pin)
            plan_pin = self.document(self.plan | dict(host_profile_digest=host_pin))
            sources = [r | dict(digest=earlier) if "/" + r["path"] == path else r for r in self.snap]
            report = self.altered(host_before=host, host_after=host, plan_digest=plan_pin,
                                  source_before=sources, source_after=sources)
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unreviewed"):
                self.verify(plan_pin=plan_pin, owner_pin=report)

    def test_neither_matching_digests_without_member_bytes_nor_writable_cas_can_satisfy_replay(self):
        with self.assertRaisesRegex(ValueError, "read-only"):
            reader.verify_installed_bundle_readback(self.store, **self.pins)
        # Export all required objects except the source blob to another private fixture.
        with tempfile.TemporaryDirectory() as tmp:
            other = CAS(Path(tmp) / "only-metadata")
            for pin in {*self.pins.values(), self.host_pin, self.plan["deployment"]["digest"]}:
                raw = self.archive.read(pin)
                other.put_expected(BytesIO(raw), expected_digest=pin, max_bytes=len(raw))
            with self.assertRaisesRegex(ValueError, "source blob"):
                reader.verify_installed_bundle_readback(CAS(other.root, read_only=True), **self.pins)
