"""Only new HTTP guest seams; no live activation or inherited suite execution."""

import ast
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest

from aragorn import native_phase3_http_canary_contract as canary
from aragorn import runtime_http_action as http_action
from aragorn.oci_worker_protocol import canonical_json
from scripts import materialize_native_phase3_http_attempt as renderer
from scripts import materialize_native_phase3_http_ready_helpers as ready_helpers

ROOT = Path(__file__).resolve().parents[1]


class HttpAttemptGuestTests(unittest.TestCase):
    def test_finite_lifecycle_and_public_records(self):
        original = {name: (ROOT / name).read_bytes() for name in renderer.INPUTS}
        generated = renderer.render(original)
        ready = ready_helpers.render(
            {name: (ROOT / name).read_bytes() for name in ready_helpers.INPUTS}
        )
        writer = renderer.render_writer(ready[ready_helpers.writer.SOURCE]).decode(
            "ascii"
        )
        ast.parse(writer)
        self.assertIn("def guard(*, require_stopped=True):", writer)
        self.assertIn(
            "if require_stopped:\n                    _http_provision._stopped()",
            writer,
        )
        self.assertIn(
            "_http_writer_cleanup(sys.exception(), lambda: guard(require_stopped=False))",
            writer,
        )
        with self.assertRaisesRegex(
            renderer.NativeHttpAttemptRenderError, "writer predecessor"
        ):
            renderer.render_writer(ready[ready_helpers.writer.SOURCE] + b"\n")
        output = generated[renderer.SOURCE]
        tree = ast.parse(output)
        snapshot = generated[renderer.SNAPSHOT].decode("ascii")
        ast.parse(snapshot)
        self.assertIn(
            'SCHEMA = "aragorn/native-http-measurement-evidence-snapshot/v1"', snapshot
        )
        self.assertIn("verified = http_verify.verify_http_worker_ingress(", snapshot)
        self.assertIn("http_capability.validate_broker_result(item", snapshot)
        self.assertIn("HTTP_SNAPSHOT_FIXTURE_ACTION_CHANGED", snapshot)
        self.assertEqual(
            original[renderer.SOURCE], (ROOT / renderer.SOURCE).read_bytes()
        )
        self.assertNotIn(b"workload.run_native_blocked_create_workload(", output)
        text = output.decode("ascii")
        self.assertLess(
            text.index("ready = ready_stack.enter_context"),
            text.index('phase = "FIRST_ACTIVATION"'),
        )
        self.assertLess(
            text.index("ready.finish("),
            text.index("http_collection.collect_native_http_attempt("),
        )
        self.assertLess(
            text.index("ready_stack.close()"), text.index('retain("broker_readiness"')
        )
        self.assertIn('state["provisioning_file_digests"].update', text)
        self.assertIn('expected_node_digest=pins["/usr/local/bin/node"]', text)
        self.assertIn('"HTTP_GATEWAY_PROCESS_JOIN_CHANGED"', text)
        self.assertIn("mode = 0o644 if path in {", text)
        self.assertIn(
            'failure("BROKER_READINESS_CONTEXT_CLOSE_REFUSED", ready_stack.close)', text
        )
        self.assertIn('result["fixture_stack_cleanup"] = setup._cleanup(native)', text)
        nodes = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_http_records"
        ]
        self.assertEqual(len(nodes), 1)

        def require(value, reason):
            if not value:
                raise ValueError(reason)

        digest = lambda raw: "sha256:" + hashlib.sha256(raw).hexdigest()
        namespace = {
            "canonical_json": canonical_json,
            "_require": require,
            "workload": SimpleNamespace(_digest=digest),
        }
        exec(
            compile(
                ast.Module(body=nodes, type_ignores=[]), "<http-record-seam>", "exec"
            ),
            namespace,
        )
        driver, sink, terminal = (
            {"driver": "fixed"},
            {"sink": "fixed"},
            {"terminal": "fixed"},
        )
        raw = canonical_json(driver)
        report = {
            "driver": {"document": driver, "bytes": len(raw), "digest": digest(raw)},
            "sink": sink,
        }
        native = SimpleNamespace(
            _snapshot=lambda genesis, count: {"receipts": [{}, terminal]}
        )
        namespace["_http_records"](report, native, "genesis")
        self.assertEqual(set(report["records"]), {"driver", "sink", "terminal"})
        for name, value in (("driver", driver), ("sink", sink), ("terminal", terminal)):
            self.assertEqual(
                report["records"][name]["text"].encode("ascii"), canonical_json(value)
            )
        report["driver"]["digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "HTTP_DRIVER_RECORD_CHANGED"):
            namespace["_http_records"](report, native, "genesis")

        def exact(value, fields):
            require(type(value) is dict and set(value) == set(fields), "shape")
            return value

        node = next(
            node
            for node in ast.parse(snapshot).body
            if isinstance(node, ast.FunctionDef) and node.name == "_http_ingress"
        )
        namespace.update(
            _exact=exact,
            http_action=http_action,
            canary=canary,
            canonical_digest=lambda value: digest(canonical_json(value)),
        )
        exec(
            compile(
                ast.Module(body=[node], type_ignores=[]), "<http-snapshot-seam>", "exec"
            ),
            namespace,
        )
        request = {
            "schema": "aragorn/runtime-http-worker-request/v1",
            "authority": "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            "attempt_id": "p3-lab-a001",
            "session_id": "session",
            "run_id": "run",
            "tool_call_digest": "sha256:" + "b" * 64,
        }
        body = {
            "worker_request": request,
            "worker_request_digest": digest(canonical_json(request)),
            "gateway_peer": {"pid": 10, "uid": 1000, "gid": 1000},
        }
        plan = {
            "attempt_id": "p3-lab-a001",
            "payload_digest": canary.digest(canary.canary_request("p3-lab-a001")),
        }
        self.assertEqual(namespace["_http_ingress"](body, plan), request)
        with self.assertRaisesRegex(ValueError, "PUBLIC_HTTP_INGRESS_CHANGED"):
            namespace["_http_ingress"](
                body, plan | {"payload_digest": "sha256:" + "0" * 64}
            )
        verify = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_verify"
        )
        peer = dict(body["gateway_peer"])
        namespace.update(
            http_verify=SimpleNamespace(
                verify_native_http_collection=lambda **kwargs: {
                    "ingress": {"gateway_peer": dict(peer)}
                }
            ),
            _raw=lambda row: b"{}",
            identity=SimpleNamespace(
                prior=SimpleNamespace(_WORKER="worker", _GENESIS="genesis")
            ),
        )
        exec(
            compile(
                ast.Module(body=[verify], type_ignores=[]),
                "<http-gateway-join>",
                "exec",
            ),
            namespace,
        )
        row = {"digest": digest(b"{}")}
        work = {"records": dict.fromkeys(("sink", "driver", "terminal"), row)}
        measured = {
            "records": dict.fromkeys(
                ("startup", "ingress", "attempt", "action", "completion"), row
            )
        }
        args = (
            work,
            measured,
            {"before": b"{}", "after": b"{}"},
            {"worker": {}, "gateway": dict(peer)},
            {},
            {},
            {
                "measurement_binding_digest": row["digest"],
                "expected_file_digests": {
                    "worker": row["digest"],
                    "genesis": row["digest"],
                },
            },
            b"{}",
            {},
            None,
            b"{}",
            {},
            "c" * 32,
        )
        self.assertIn("http_collection", namespace["_verify"](*args))
        peer["pid"] += 1
        with self.assertRaisesRegex(ValueError, "HTTP_GATEWAY_PROCESS_JOIN_CHANGED"):
            namespace["_verify"](*args)
        changed = dict(original)
        changed[renderer.SOURCE] += b"\n"
        with self.assertRaisesRegex(
            renderer.NativeHttpAttemptRenderError, "predecessor pin"
        ):
            renderer.render(changed)


if __name__ == "__main__":
    unittest.main()
