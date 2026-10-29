"""One combined source/bundle/host seam check; no live capture or old suites."""

import ast
from copy import deepcopy
import hashlib
from pathlib import Path
import unittest

from aragorn.oci_worker_protocol import canonical_json
from scripts import capture_native_phase3_http_attempt as launcher
from scripts import materialize_native_phase3_http_attempt_capture as renderer
from tests.test_native_phase3_http_ready_helpers import ReadyPreparationFixture

ROOT = Path(__file__).resolve().parents[1]


class CombinedHttpCaptureTests(unittest.TestCase):
    def test_installed_source_closure_and_serialized_host_lifecycle(self):
        original = {
            name: (ROOT / name).read_bytes() for name in renderer.source_paths()
        }
        generated = renderer.compose(original)
        for name, raw in generated.items():
            ast.parse(raw, filename=name)
        host = launcher.build_controller(original)
        data = ReadyPreparationFixture(self)
        base, inputs = host.base.contract, host.inputs
        base_sources = {name: original[name] for name in base.SOURCE_PATHS}
        base_generated = {name: generated[name] for name in base.GENERATED_SOURCES}
        installed = original | generated
        arguments = {
            key: value
            for key, value in data.arguments.items()
            if key not in {"container_id", "provisioning_inputs"}
        }
        arguments["implementation_source_raws"] = {
            name: installed[name] for name in base.IMPLEMENTATION_PATHS
        }
        bundle = base.prepare_common_setup_inputs(
            **arguments,
            http_attempt_id="p3-lab-a001",
            source_raws=base_sources,
            generated_source_raws=base_generated,
            setup_source_raw=installed[base.SETUP_SOURCE],
            wrapper_source_raw=installed[base.WRAPPER_SOURCE],
            host_source_raw=installed[base.HOST_SOURCE],
        )
        identifiers = [f"p3-lab-a{index:03}" for index in range(1, 101)]
        plan = {
            "expected_attempt_ids": identifiers,
            "expected_attempt_families": {
                name: "EXFILTRATION" if index < 50 else "DESTRUCTIVE"
                for index, name in enumerate(identifiers)
            },
            "expected_unattributed_attempt_id": identifiers[-1],
            "expected_overhead_pair_bindings": {
                f"test-pair-{index:03}": {
                    "task_digest": "sha256:" + "a" * 64,
                    "input_digest": f"sha256:{index + 1:064x}",
                    "host_profile_digest": "sha256:" + "b" * 64,
                }
                for index in range(100)
            },
            "expected_gate_manifest_digest": "sha256:" + "c" * 64,
            "expected_campaign_contract_digest": "sha256:" + "d" * 64,
            "selected_attempt_id": identifiers[0],
        }
        kwargs = dict(
            setup_bundle_raw=bundle["bundle_raw"],
            expected_setup_bundle_digest=bundle["bundle_digest"],
            plan_arguments=plan,
            source_raws={name: original[name] for name in inputs.EXTRA_SOURCE_PATHS},
            generated_source_raws=generated,
        )
        bound = inputs.prepare_common_attempt_inputs(**kwargs)
        self.assertEqual(
            inputs.inspect_common_attempt_inputs(
                bound["bundle_raw"], expected_bundle_digest=bound["bundle_digest"]
            ),
            bound,
        )
        self.assertEqual(
            set(bound["expected_source_digests"]), set(host.guest.attempt.SOURCE_PATHS)
        )
        self.assertEqual(
            bound["common_arguments"]["readiness_nonce"],
            data.arguments["readiness_nonce"],
        )
        self.assertEqual(bound["common_arguments"]["http_attempt_id"], identifiers[0])
        self.assertIs(host.guest.attempt.setup, host.base.setup)
        self.assertIs(host.private_inputs.planning.inputs, inputs)
        self.assertIs(host.guest.contract, inputs)
        host._stage_guard(data.stage, canonical_json(data.stage))
        self.assertFalse(
            set(inputs.FIXTURE_HELPERS.values())
            & {row["path"] for row in data.stage["files"]}
        )
        rows = {
            name: {
                "path": name,
                "mode": "100644",
                "bytes": len(original[name]),
                "digest": base._digest(original[name]),
                "blob": hashlib.sha1(
                    b"blob "
                    + str(len(original[name])).encode()
                    + b"\0"
                    + original[name]
                ).hexdigest(),
            }
            for name in inputs.FIXTURE_HELPERS
        }
        metadata = base.helper_records(
            bound, rows, fixture_helpers=inputs.FIXTURE_HELPERS
        )
        for name, row in metadata.items():
            self.assertEqual(row["generated"], name in generated)
            self.assertEqual(row["digest"], base._digest(installed[name]))
        bad = deepcopy(generated)
        bad[base.SETUP_SOURCE] += b"\n"
        with self.assertRaises(inputs.NativeCommonAttemptInputsError):
            inputs.prepare_common_attempt_inputs(
                **(kwargs | {"generated_source_raws": bad})
            )
        changed = dict(original)
        changed[renderer.HOST] += b"\n"
        with self.assertRaisesRegex(ValueError, "predecessor changed"):
            renderer.compose(changed)
        text = generated[renderer.HOST].decode()
        self.assertEqual(text.count('result["guest"] = _invoke('), 1)
        self.assertLess(
            text.index("_retain_guest_exports(store, result, interrupts)"),
            text.index("private_retention_complete = True"),
        )
        self.assertIn("_suspend_preserved(result, interrupts)", text)
        self.assertNotIn("materialize_native_blocked_create_driver", text)
        self.assertTrue(
            all(value is False for value in bound["bundle"]["decision"].values())
        )


if __name__ == "__main__":
    unittest.main()
