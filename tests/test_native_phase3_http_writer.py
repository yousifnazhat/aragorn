"""Focused inert HTTP writer checks; no service, subprocess, socket or fixture.

Only selected rendered function ASTs execute with wholly replaced boundaries.
Fabricated unit inputs do not count as deployment or qualification evidence.
"""

import ast
from contextlib import nullcontext
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import MagicMock, patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import materialize_native_phase3_http_writer as subject
from scripts import stage_runtime_phase3_http_profile as http_stage

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = {
    "container_id": "d" * 64,
    "boot_id": "11111111-2222-3333-4444-555555555555",
    "netns_device": 4,
    "netns_inode": 1234,
}
BINDING = {
    "schema": "aragorn/runtime-http-fixture-binding/v1",
    "fixture": FIXTURE,
    "expected_broker_uid": 995,
    "expected_broker_gid": 997,
}
ACTION = {
    "operation_digest": "sha256:" + "a" * 64,
    "path_digest": "sha256:" + "b" * 64,
    "payload_digest": "sha256:" + "c" * 64,
}


class Prepared(BaseException):
    """Inert equivalent of the outer setup's successful interception."""


def _expect(value, message):
    if not value:
        raise ValueError(message)


def _rendered():
    original = (ROOT / subject.SOURCE).read_bytes()
    return subject.render({subject.SOURCE: original})[subject.SOURCE]


def _functions(raw, names, namespace):
    nodes = []
    for node in ast.parse(raw).body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            # Do not import a historical helper or a runtime module. Every
            # imported boundary is injected below as an inert test double.
            node.body = [
                item for item in node.body
                if not isinstance(item, (ast.Import, ast.ImportFrom))
            ]
            nodes.append(node)
    if {node.name for node in nodes} != set(names):
        raise AssertionError("rendered function inventory changed")
    module = ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))
    exec(compile(module, "<inert-http-writer-functions>", "exec"), namespace)


class NativeHttpWriterTests(unittest.TestCase):
    def wrapper(self):
        raw = (ROOT / "benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json").read_bytes()
        template = raw.replace(
            b'"alsoAllow":["aragorn_runtime_create","read"]',
            b'"alsoAllow":["aragorn_runtime_create","aragorn_runtime_http_canary","read"]',
        ).removesuffix(b"\n")
        calls = []
        held = SimpleNamespace(guard=MagicMock())
        reader = MagicMock(return_value=(template, {"identity": [1, 2]}))
        http = SimpleNamespace(
            BINDING_PATH=Path("/etc/aragorn/runtime-http-fixture.json"),
            effect_for_attempt=MagicMock(side_effect=lambda attempt: calls.append("validate-attempt")),
            load_fixture_binding=MagicMock(return_value=deepcopy(BINDING)),
            action_digests=MagicMock(side_effect=lambda *_: calls.append("action") or dict(ACTION)),
        )
        provision = SimpleNamespace(
            _new_binding=MagicMock(return_value=deepcopy(BINDING)),
            _stopped=MagicMock(),
            provision_fixture_binding=MagicMock(side_effect=lambda *_: calls.append("provision") or {
                "completed": True, "created": True, "activation_performed": False,
                "cleanup_failed": False, "binding_digest": canonical_digest(BINDING),
            }),
        )
        fake_os = SimpleNamespace(
            O_RDONLY=0, O_DIRECTORY=1, O_NOFOLLOW=2, O_CLOEXEC=4,
            open=MagicMock(return_value=9), close=MagicMock(),
            path=SimpleNamespace(lexists=MagicMock(return_value=False)),
        )
        callback = MagicMock(side_effect=lambda value: calls.append(("writer", value)))

        def body(action, gateway_reader, guard):
            calls.append("body")
            self.assertEqual(action, ACTION)
            config, metadata = gateway_reader(Path(subject.HTTP_TEMPLATE_PATH))
            self.assertEqual(canonical_json(config), template)
            self.assertEqual(metadata["canonical_digest"], subject.HTTP_TEMPLATE_PIN[1])
            calls.append("gateway-written")
            guard()
            raise Prepared()

        namespace = {
            "_expect": _expect, "_http_identity": SimpleNamespace(_read_at=reader),
            "_http": http, "_http_provision": provision,
            "owned_http_fixture": MagicMock(return_value=nullcontext(held)),
            "json": json, "os": fake_os, "sys": sys,
            "_HTTP_TEMPLATE": Path(subject.HTTP_TEMPLATE_PATH),
            "_HTTP_TEMPLATE_PIN": subject.HTTP_TEMPLATE_PIN,
            "prior": SimpleNamespace(_digest=lambda value: "sha256:" + hashlib.sha256(value).hexdigest()),
            "provision": SimpleNamespace(_STORE="/inert/store", _GENESIS_SOURCE="/inert/genesis"),
            "canonical_json": canonical_json, "canonical_digest": canonical_digest,
            "_prepare_http_inputs": MagicMock(side_effect=body),
        }
        _functions(_rendered(), {"_prepare", "_http_writer_cleanup"}, namespace)
        arguments = {
            "expected_http_fixture": deepcopy(FIXTURE),
            "http_attempt_id": "p3-lab-a001", "http_binding_writer": callback,
        }
        return namespace, arguments, calls, http, provision, fake_os, reader, callback

    def test_exact_source_render_only_and_frozen_input_unchanged(self):
        before = (ROOT / subject.SOURCE).read_bytes()
        value = subject.render({subject.SOURCE: before})
        self.assertEqual(set(value), {subject.SOURCE})
        self.assertEqual((ROOT / subject.SOURCE).read_bytes(), before)
        text = value[subject.SOURCE].decode()
        ast.parse(text)
        self.assertIn('"id": "owned-native-receipt-http-canary"', text)
        self.assertNotIn('"id": "owned-native-receipt-read-create"', text)
        self.assertNotIn("action = p37c._action_digests(fd, p37b._TARGET, p37b._PAYLOAD)", text)
        self.assertIn('combined, "_canonical_source", http_gateway_reader', text)

    def test_changed_predecessor_and_missing_input_refused(self):
        raw = (ROOT / subject.SOURCE).read_bytes()
        for value in ({}, {subject.SOURCE: raw + b"\n"}, {subject.SOURCE: raw.decode()}):
            with self.subTest(value_type=type(value.get(subject.SOURCE))):
                with self.assertRaises(subject.NativeHttpWriterRenderError):
                    subject.render(value)

    def test_template_constant_matches_actual_http93_stage_payload(self):
        _, rendered, _ = http_stage._verified_payloads()
        raw = rendered[http_stage._destination(http_stage.ingress.GATEWAY_CONFIG)[0]][2]
        self.assertEqual((len(raw), "sha256:" + hashlib.sha256(raw).hexdigest()), subject.HTTP_TEMPLATE_PIN)
        self.assertEqual(canonical_json(json.loads(raw)), raw)
        self.assertEqual("/" + http_stage._destination(http_stage.ingress.GATEWAY_CONFIG)[0], subject.HTTP_TEMPLATE_PATH)

    def test_render_does_not_execute_or_import_predecessor(self):
        with patch("builtins.exec", side_effect=AssertionError("execution forbidden")), patch(
            "builtins.__import__", side_effect=AssertionError("import forbidden")
        ):
            # Source read is outside the patched boundary; renderer accepts bytes.
            value = subject.render({subject.SOURCE: self.source_raw})
        self.assertEqual(set(value), {subject.SOURCE})

    @classmethod
    def setUpClass(cls):
        cls.source_raw = (ROOT / subject.SOURCE).read_bytes()

    def test_eighth_writer_before_provision_then_http_action_and_gateway(self):
        ns, args, calls, http, provision, fake_os, reader, callback = self.wrapper()
        with self.assertRaises(Prepared):
            ns["_prepare"](**args)
        self.assertEqual(calls, ["validate-attempt", ("writer", canonical_json(BINDING)), "provision", "action", "body", "gateway-written"])
        callback.assert_called_once_with(canonical_json(BINDING))
        provision.provision_fixture_binding.assert_called_once_with(FIXTURE)
        http.action_digests.assert_called_once_with(args["http_attempt_id"], BINDING)
        fake_os.close.assert_called_once_with(9)
        self.assertGreaterEqual(reader.call_count, 4)

    def test_template_pin_or_lf_change_refused_before_writer(self):
        for changed in (b"{}", "newline"):
            ns, args, _, _, provision, fake_os, reader, callback = self.wrapper()
            prior = reader.return_value
            reader.return_value = (prior[0] + b"\n" if changed == "newline" else changed, prior[1])
            with self.assertRaisesRegex(ValueError, "template pin changed"):
                ns["_prepare"](**args)
            callback.assert_not_called()
            provision.provision_fixture_binding.assert_not_called()
            fake_os.close.assert_called_once_with(9)

    def test_existing_credential_or_stream_refused_without_write(self):
        ns, args, _, _, provision, fake_os, _, callback = self.wrapper()
        fake_os.path.lexists.return_value = True
        with self.assertRaisesRegex(ValueError, "absent credential"):
            ns["_prepare"](**args)
        callback.assert_not_called()
        provision.provision_fixture_binding.assert_not_called()

    def test_callback_failure_prevents_provision_and_body(self):
        ns, args, _, _, provision, _, _, callback = self.wrapper()
        callback.side_effect = RuntimeError("inert capture failed")
        with self.assertRaisesRegex(RuntimeError, "inert capture failed"):
            ns["_prepare"](**args)
        provision.provision_fixture_binding.assert_not_called()
        ns["_prepare_http_inputs"].assert_not_called()

    def test_provision_readback_mismatch_prevents_seven_writers(self):
        ns, args, _, http, _, _, _, callback = self.wrapper()
        http.load_fixture_binding.return_value = {**BINDING, "expected_broker_uid": 999}
        with self.assertRaisesRegex(ValueError, "writer binding changed"):
            ns["_prepare"](**args)
        callback.assert_called_once()
        ns["_prepare_http_inputs"].assert_not_called()

    def test_final_guard_error_replaces_success_sentinel(self):
        ns, args, _, http, _, fake_os, _, _ = self.wrapper()

        def body(*_):
            http.load_fixture_binding.return_value = {}
            raise Prepared()

        ns["_prepare_http_inputs"].side_effect = body
        with self.assertRaisesRegex(ValueError, "credential changed during setup"):
            ns["_prepare"](**args)
        fake_os.close.assert_called_once_with(9)

    def test_interrupt_survives_final_guard_and_close_errors(self):
        ns, args, _, http, _, fake_os, _, _ = self.wrapper()
        interrupt = KeyboardInterrupt()

        def body(*_):
            http.load_fixture_binding.return_value = {}
            raise interrupt

        ns["_prepare_http_inputs"].side_effect = body
        fake_os.close.side_effect = OSError("inert close failure")
        with self.assertRaises(KeyboardInterrupt) as caught:
            ns["_prepare"](**args)
        self.assertIs(caught.exception, interrupt)

    def test_partial_provision_observation_survives_close_failure(self):
        ns, args, _, _, provision, fake_os, _, _ = self.wrapper()
        failure = OSError("inert partial write")
        failure.http_provisioning_observation = {"created": True, "completed": False}
        provision.provision_fixture_binding.side_effect = failure
        fake_os.close.side_effect = OSError("inert close failure")
        with self.assertRaises(OSError) as caught:
            ns["_prepare"](**args)
        self.assertEqual(caught.exception.http_provisioning_observation, failure.http_provisioning_observation)
        ns["_prepare_http_inputs"].assert_not_called()

    def test_writer_body_retains_activation_interception_after_http_guard(self):
        tree = ast.parse(_rendered())
        function = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "_prepare_http_inputs")
        calls = [item for item in function.body if isinstance(item, ast.Expr) and isinstance(item.value, ast.Call)]
        names = [item.value.func.id for item in calls if isinstance(item.value.func, ast.Name)]
        guard_index = names.index("http_guard")
        self.assertEqual(names[guard_index:guard_index + 3], ["http_guard", "_phase", "_activate"])
        prepare = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "_prepare")
        self.assertEqual([item.arg for item in prepare.args.kwonlyargs], ["expected_http_fixture", "http_attempt_id", "http_binding_writer"])
        self.assertEqual(prepare.args.kw_defaults, [None, None, None])


if __name__ == "__main__":
    unittest.main()
