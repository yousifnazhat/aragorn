"""Inert orchestration tests: no old scenario, service, namespace or VM executes."""

import ast
import copy
import io
import json
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import runtime_native_plugin_update_identity_check as subject


class NativePluginUpdateIdentityGuestTests(unittest.TestCase):
    def setUp(self):
        self.container = "a" * 64
        self.manifest = {
            "schema": subject.STATIC_SCHEMA,
            "file_digests": {
                path: subject._digest(path.encode()) for path in subject.STATIC_PATHS
            },
        }
        self.manifest_raw = subject.canonical_json(self.manifest)
        self.manifest_digest = subject._digest(self.manifest_raw)
        self.documents = {
            path: {"inert_writer_input": path} for path in subject.DYNAMIC_PATHS
        }
        self.provisioned = {
            path: subject._digest(subject.canonical_json(value))
            for path, value in self.documents.items()
        }
        self.old_observation = {
            "schema": subject.update._SCHEMA,
            "status": "OBSERVED",
            "authority": subject.update._AUTHORITY,
            "route_id": subject.update._ROUTE,
            "branch": "TRACKED_LOCAL_MARKETPLACE_DIRECTORY_UPDATE",
            "fixture_container": self.container,
            "route_qualified": False,
            "phase3_eligible": False,
            "run_conformance_eligible": False,
            "production_activation_eligible": False,
            "fixture_stack_cleanup": {"inert": True},
        }

    def run_guest(
        self,
        *,
        omit=None,
        duplicate=None,
        post_freeze_write=False,
        fail_read=None,
        changed_after=False,
        twice=False,
        manifest=None,
    ):
        events, writes, reads = [], [], []
        supplied = self.manifest if manifest is None else manifest

        def write_document(path, document, *args, **kwargs):
            writes.append((str(path), subject.canonical_json(document)))
            events.append("write:" + str(path))

        def create_document(parent, name, raw, held):
            writes.append((subject.identity._GENESIS, raw))
            events.append("genesis")
            return object()

        p37b = SimpleNamespace(
            _write_document=write_document,
            capability=SimpleNamespace(_write_control=write_document),
        )
        native = SimpleNamespace(
            provision=SimpleNamespace(_create_document=create_document)
        )

        def activate(*args, **kwargs):
            events.append("activate")
            if post_freeze_write:
                p37b._write_document(Path(subject.identity._WORKER), {"changed": True})

        def prepare():
            for path in subject.DYNAMIC_PATHS:
                if path == omit:
                    continue
                if path == subject.identity._GENESIS:
                    native.provision._create_document(
                        100,
                        Path(path).name,
                        subject.canonical_json(self.documents[path]),
                        [],
                    )
                elif path == subject.identity._POLICY:
                    p37b.capability._write_control(
                        Path(path), self.documents[path], 100, 200
                    )
                else:
                    p37b._write_document(Path(path), self.documents[path])
                if path == duplicate:
                    p37b._write_document(Path(path), self.documents[path])
            native._activate("inert context", "inert token")

        native._activate, native._prepare = activate, prepare

        def inherited_run(container, copied_owner):
            events.append("runner")
            loaded = subject.update.prior._native()
            inherited_activate = loaded._activate

            def seed_then_activate(*args, **kwargs):
                events.append("seed")
                return inherited_activate(*args, **kwargs)

            try:
                with patch.object(loaded, "_activate", seed_then_activate):
                    loaded._prepare()
                subject.update._invoke(p37b, 444, "inert token")
                if twice:
                    subject.update._invoke(p37b, 444, "inert token")
                return copy.deepcopy(self.old_observation)
            finally:
                events.append("cleanup")

        def original_invoke(*args):
            events.append("invoke")
            return {"inert_original_update": True}

        def read(**kwargs):
            reads.append(copy.deepcopy(kwargs))
            number = len(reads)
            events.append("read:" + str(number))
            if fail_read == number:
                raise subject.identity.NativeLiveIdentityError("inert reader refusal")
            return {
                "processes": {
                    "gateway": {"pid": 445 if changed_after and number == 2 else 444}
                },
                "fixed_measured_bytes": True,
            }

        def compare(before, after):
            subject._require(before == after, "INERT_IDENTITY_CHANGED")
            events.append("compare")
            return {"status": "CALLER_MEASUREMENTS_EQUAL", "phase3_eligible": False}

        real_invoke = subject.update._invoke
        real_factory = subject.update.prior._native
        with ExitStack() as stack:
            for item in (
                patch.object(
                    subject, "_static_manifest", return_value=copy.deepcopy(supplied)
                ),
                patch.object(subject, "_p37b", return_value=p37b),
                patch.object(subject.update.prior, "_native", return_value=native),
                patch.object(subject.update, "_run", side_effect=inherited_run),
                patch.object(subject.update, "_invoke", side_effect=original_invoke),
                patch.object(
                    subject.identity, "read_native_live_identity", side_effect=read
                ),
                patch.object(
                    subject.identity,
                    "compare_native_live_identity",
                    side_effect=compare,
                ),
            ):
                stack.enter_context(item)
            result = subject._run(self.container, (100, 200), self.manifest_digest)
            self.assertIs(native._prepare, prepare)
            self.assertIs(native._activate, activate)
            self.assertIs(p37b._write_document, write_document)
            self.assertIs(native.provision._create_document, create_document)
        self.assertIs(subject.update._invoke, real_invoke)
        self.assertIs(subject.update.prior._native, real_factory)
        return result, events, writes, reads

    def test_static_manifest_requires_exact_canonical_caller_pinned_inventory(self):
        self.assertEqual(
            subject._parse_static_manifest(self.manifest_raw, self.manifest_digest),
            self.manifest,
        )
        changed = copy.deepcopy(self.manifest)
        changed["file_digests"][subject.DYNAMIC_PATHS[0]] = "sha256:" + "0" * 64
        for raw, digest in (
            (self.manifest_raw, "sha256:" + "0" * 64),
            (self.manifest_raw + b"\n", subject._digest(self.manifest_raw + b"\n")),
            (
                subject.canonical_json(changed),
                subject._digest(subject.canonical_json(changed)),
            ),
            (b'{"schema":1,"schema":2}', subject._digest(b'{"schema":1,"schema":2}')),
        ):
            with (
                self.subTest(raw=raw[:40]),
                self.assertRaises(subject.NativeIdentityGuestError),
            ):
                subject._parse_static_manifest(raw, digest)

    def test_existing_writer_source_contract_matches_intercepted_paths_and_bytes(self):
        root = Path(__file__).resolve().parents[1]
        names = (
            "scripts/runtime_action_worker_openclaw_systemd_probe.py",
            "scripts/runtime_capability_openclaw_systemd_probe.py",
            "scripts/runtime_active_lineage_openclaw_systemd_probe.py",
            "scripts/runtime_native_receipt_systemd_check.py",
            "scripts/runtime_action_worker_final_combined_v2_systemd_probe.py",
            "scripts/runtime_process_profile_systemd_probe.py",
            "scripts/runtime_action_systemd_probe.py",
            "src/aragorn/runtime_native_tool_provisioning.py",
            "scripts/runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe.py",
        )
        trees = {name: ast.parse((root / name).read_text()) for name in names}

        def assignment(name, key):
            return next(
                node.value
                for node in trees[name].body
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == key
                    for target in node.targets
                )
            )

        def function(name, key):
            return next(
                node
                for node in trees[name].body
                if isinstance(node, ast.FunctionDef) and node.name == key
            )

        (
            worker,
            capability,
            lineage,
            native,
            combined,
            profile,
            action,
            provisioning,
            v3,
        ) = names
        self.assertTrue(
            any(
                isinstance(node, ast.Import)
                and any(
                    item.name == "runtime_action_worker_final_combined_v2_systemd_probe"
                    and item.asname == "combined"
                    for item in node.names
                )
                for node in trees[v3].body
            )
        )
        for source, key, expected in (
            (worker, "_WORKER_BINDING", subject.identity._WORKER),
            (worker, "_GATEWAY_CONFIG", subject.identity._CONFIG),
            (capability, "_RUNTIME_BINDING", subject.identity._RUNTIME),
            (capability, "_OBSERVATION_BINDING", subject.identity._OBSERVATION),
            (capability, "_GRANT_SOURCE", subject.identity._GRANT),
            (provisioning, "_GENESIS_SOURCE", subject.identity._GENESIS),
        ):
            value = assignment(source, key)
            self.assertIsInstance(value, ast.Call)
            self.assertEqual(ast.unparse(value.func), "Path")
            self.assertEqual(ast.literal_eval(value.args[0]), expected)
        for key in ("_RUNTIME_BINDING", "_OBSERVATION_BINDING", "_GRANT_SOURCE"):
            self.assertEqual(ast.unparse(assignment(worker, key)), "lineage." + key)
            self.assertEqual(ast.unparse(assignment(lineage, key)), "capability." + key)
        self.assertEqual(
            ast.literal_eval(assignment(capability, "_ROOT").args[0]),
            str(Path(subject.identity._POLICY).parent.parent),
        )
        self.assertEqual(
            ast.unparse(assignment(capability, "_CONTROL")), "_ROOT / 'control'"
        )
        stack_writes = [
            node
            for node in ast.walk(function(worker, "_write_stack_inputs"))
            if isinstance(node, ast.Call)
            and ast.unparse(node.func) == "_write_document"
        ]
        self.assertEqual(
            [ast.unparse(node.args[0]) for node in stack_writes],
            [
                "_RUNTIME_BINDING",
                "_OBSERVATION_BINDING",
                "_WORKER_BINDING",
                "_GRANT_SOURCE",
            ],
        )
        control_writes = [
            node
            for node in ast.walk(function(worker, "_write_stack_inputs"))
            if isinstance(node, ast.Call)
            and ast.unparse(node.func) == "capability._write_control"
        ]
        self.assertEqual(len(control_writes), 1)
        self.assertEqual(
            ast.unparse(control_writes[0].args[0]), "lineage._CONTROL / f'{name}.json'"
        )
        self.assertIn(
            "p37c.p37b._write_document(p37c.p37b._GATEWAY_CONFIG, config)",
            ast.unparse(function(combined, "_prepare_gateway")),
        )
        self.assertIn(
            "_write_file(path, canonical_json(document), uid, gid, mode)",
            ast.unparse(function(profile, "_write_document")),
        )
        self.assertIn(
            "raw = canonical_json(document)",
            ast.unparse(function(action, "_write_control")),
        )
        self.assertIn(
            "path.write_bytes(raw)", ast.unparse(function(action, "_write_control"))
        )
        body = ast.unparse(function(native, "_prepare"))
        self.assertLess(
            body.index("p37b._write_stack_inputs("),
            body.index("provision.provision_runtime_native_tool_receipts()"),
        )
        self.assertLess(
            body.index("provision.provision_runtime_native_tool_receipts()"),
            body.index("_activate("),
        )
        self.assertIn(
            "_create_document(etc_fd, _GENESIS_SOURCE.name, genesis_raw, held)",
            ast.unparse(
                function(provisioning, "provision_runtime_native_tool_receipts")
            ),
        )

    def test_writer_inputs_freeze_before_activation_and_one_real_adapter_call(self):
        result, events, writes, reads = self.run_guest()
        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(result["provisioning_file_digests"], self.provisioned)
        self.assertEqual(
            {path: subject._digest(raw) for path, raw in writes}, self.provisioned
        )
        self.assertTrue(all(not raw.endswith(b"\n") for _, raw in writes))
        self.assertEqual(
            result["expected_file_digests"],
            {**self.manifest["file_digests"], **self.provisioned},
        )
        self.assertEqual(result["update_observation"], self.old_observation)
        self.assertEqual(result["static_pin_manifest"], self.manifest)
        self.assertEqual(result["static_pin_manifest_digest"], self.manifest_digest)
        self.assertEqual(
            (result["activation_count"], result["invocation_count"]), (1, 1)
        )
        self.assertTrue(result["pins_frozen_before_activation"])
        self.assertEqual(len(reads), 2)
        self.assertTrue(
            all(
                read["expected_file_digests"] == result["expected_file_digests"]
                for read in reads
            )
        )
        significant = [
            event
            for event in events
            if event
            in {"seed", "activate", "read:1", "invoke", "read:2", "compare", "cleanup"}
        ]
        self.assertEqual(
            significant,
            ["seed", "activate", "read:1", "invoke", "read:2", "compare", "cleanup"],
        )
        stamps = [result["boundaries_monotonic_ns"][name] for name in subject._STAMPS]
        self.assertEqual(stamps, sorted(stamps))
        self.assertTrue(all(result[name] is False for name in subject._FALSE_FLAGS))

    def test_missing_or_duplicate_writer_input_prevents_activation(self):
        for arguments in (
            {"omit": subject.identity._GRANT},
            {"duplicate": subject.identity._CONFIG},
        ):
            with self.subTest(arguments=arguments):
                result, events, _, reads = self.run_guest(**arguments)
                self.assertEqual(result["status"], "REFUSED")
                self.assertNotIn("activate", events)
                self.assertNotIn("invoke", events)
                self.assertEqual(reads, [])
                self.assertEqual(events.count("cleanup"), 1)

    def test_post_freeze_writer_input_is_refused_without_update(self):
        result, events, _, reads = self.run_guest(post_freeze_write=True)
        self.assertEqual(result["refusal"]["reason"], "WRITE_AFTER_PIN_FREEZE")
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(events.count("activate"), 1)
        self.assertNotIn("invoke", events)
        self.assertEqual(reads, [])

    def test_before_failure_prevents_effect_and_after_failure_retains_partial_evidence(
        self,
    ):
        for number in (1, 2):
            with self.subTest(reader=number):
                result, events, _, _ = self.run_guest(fail_read=number)
                self.assertEqual(result["status"], "REFUSED")
                self.assertEqual(events.count("invoke"), number - 1)
                self.assertEqual(events.count("cleanup"), 1)
                self.assertEqual(result["invocation_count"], number - 1)
                self.assertIsNone(result["comparison"])
                if number == 2:
                    self.assertIsNotNone(result["before"])
                    self.assertIsNone(result["after"])
                    self.assertGreater(
                        result["boundaries_monotonic_ns"]["invocation_finished_ns"], 0
                    )

    def test_changed_epoch_or_second_invocation_never_replays_effect(self):
        for arguments in ({"changed_after": True}, {"twice": True}):
            with self.subTest(arguments=arguments):
                result, events, _, _ = self.run_guest(**arguments)
                self.assertEqual(result["status"], "REFUSED")
                self.assertEqual(events.count("invoke"), 1)
                self.assertEqual(result["invocation_count"], 1)
                self.assertEqual(events.count("cleanup"), 1)

    def test_pin_input_refusal_never_loads_native_fixture(self):
        with (
            patch.object(
                subject,
                "_static_manifest",
                side_effect=ValueError("do not expose this"),
            ),
            patch.object(subject.update.prior, "_native") as native,
        ):
            result = subject._run(self.container, (100, 200), self.manifest_digest)
        native.assert_not_called()
        self.assertEqual(result["refusal"]["phase"], "PIN_INPUT")
        self.assertEqual(result["refusal"]["reason"], "GUEST_EXECUTION_REFUSED")
        self.assertFalse(result["refusal"]["diagnostic"]["retry_performed"])
        self.assertNotIn("do not expose this", json.dumps(result))

    def test_refusal_locations_include_reader_cause_without_messages_or_locals(self):
        try:
            try:
                subject.identity._require(False, "credential-never-emit")
            except subject.identity.NativeLiveIdentityError as cause:
                raise subject.identity.NativeLiveIdentityError(
                    "secret-wrapper"
                ) from cause
        except subject.identity.NativeLiveIdentityError as error:
            result = subject._refusal_location(error)
            # A forged explicit cycle must not turn diagnostics into a hang.
            error.__cause__.__cause__ = error
            self.assertEqual(subject._refusal_location(error), result)
        self.assertEqual(len(result["source_frames"]), 1)
        self.assertEqual(
            result["source_frames"][0]["source"],
            "src/aragorn/native_phase3_live_identity.py",
        )
        self.assertEqual(result["source_frames"][0]["function"], "_require")
        self.assertGreater(result["source_frames"][0]["line"], 0)
        for key in ("exception_text_retained", "locals_retained", "retry_performed"):
            self.assertIs(result[key], False)
        self.assertNotIn("credential-never-emit", json.dumps(result))
        self.assertNotIn("secret-wrapper", json.dumps(result))

    def test_cli_emits_structured_refusal_and_no_retry(self):
        value = {"schema": subject.SCHEMA, "status": "REFUSED"}
        output = SimpleNamespace(buffer=io.BytesIO())
        with (
            patch.object(subject, "_run", return_value=value) as run,
            patch.object(subject.sys, "stdout", output),
        ):
            status = subject.main([self.container, "100", "200", self.manifest_digest])
        self.assertEqual(status, 126)
        run.assert_called_once_with(self.container, (100, 200), self.manifest_digest)
        self.assertEqual(
            output.buffer.getvalue(), subject.canonical_json(value) + b"\n"
        )
        self.assertEqual(subject.main([self.container, "100", "200"]), 64)


if __name__ == "__main__":
    unittest.main()
