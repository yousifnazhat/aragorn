"""Only ready94 nested-bundle composition deltas; no setup or live capture."""

import ast
from functools import lru_cache
import hashlib
from pathlib import Path
import unittest

from scripts import capture_native_phase3_http_setup as loader
from scripts import materialize_native_phase3_http_ready_setup_capture as subject
from scripts import stage_runtime_phase3_http_ready_profile as stage

ROOT = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def composed():
    original = {name: (ROOT / name).read_bytes() for name in subject.INPUTS}
    return original, subject.compose(original)


def contract():
    _, generated = composed()
    modules = {}
    for name in (
        "runtime_broker_decision_measurement_verify",
        "runtime_broker_measurement_plan",
        "native_phase3_common_identity",
        "runtime_native_measurement_inputs",
        "native_phase3_common_preparation",
        "native_phase3_common_setup_capture",
    ):
        loader._load_fixed(
            generated["src/aragorn/" + name + ".py"],
            "src/aragorn/" + name + ".py",
            modules,
        )
    return modules["aragorn.native_phase3_common_setup_capture"]


class ReadySetupCaptureTests(unittest.TestCase):
    def test_exact_thirteen_outputs_match_ready94_runtime_and_compile(self):
        original, generated = composed()
        self.assertEqual(set(generated), set(subject.GENERATED_SOURCES))
        self.assertEqual(len(generated), 13)
        payloads, replacements, _ = stage._verified_payloads()
        by_source = {
            source: raw for source, _, raw in (payloads | replacements).values()
        }
        for name, raw in generated.items():
            self.assertNotEqual(raw, original[name])
            compile(raw, name, "exec")
        for name in (
            subject.collection.PLAN,
            subject.collection.PRIOR,
            subject.collection.EFFECTIVE,
        ):
            self.assertEqual(generated[name], by_source[name])
        expected_helpers = subject.helpers.render(
            {name: original[name] for name in subject.helpers.INPUTS}
        )
        writer = subject.helpers.writer.SOURCE
        expected_helpers[writer] = subject.attempt_guest.render_writer(
            expected_helpers[writer]
        )
        self.assertEqual(
            {name: generated[name] for name in subject.helpers.INPUTS}, expected_helpers
        )
        self.assertIn(b"lambda: guard(require_stopped=False)", generated[writer])

    def test_nonce_and_nine_writer_contract_are_bound_without_an_extra_launcher(self):
        _, generated = composed()
        api = contract()
        self.assertIn(subject.LAUNCHER, api.SOURCE_PATHS)
        self.assertNotIn(subject.prior.LAUNCHER, api.SOURCE_PATHS)
        self.assertEqual(api.STAGER_SOURCE, subject.STAGER)
        self.assertEqual(
            api.preparation.PROVISIONING_PATHS[-1], subject.helpers.READINESS
        )
        self.assertEqual(api.BUNDLE_SCHEMA, "aragorn/native-http-ready-setup-inputs/v1")
        parsed = ast.parse(generated[subject.HOST])
        prepare = next(
            node
            for node in parsed.body
            if isinstance(node, ast.FunctionDef) and node.name == "_prepare"
        )
        self.assertEqual(
            [arg.arg for arg in prepare.args.args],
            ["store", "case_id", "nonce", "http_attempt_id", "readiness_nonce"],
        )
        text = generated[subject.CONSUMER].decode()
        self.assertIn('"readiness_nonce": args["readiness_nonce"]', text)
        self.assertIn('"writer_digest_count": 9', text)
        self.assertIn("preparation.HTTP_READINESS) else {0o400}", text)

    def test_helper_provenance_accepts_explicit_combined_inventory_only(self):
        api = contract()
        source, installed = b"original\n", b"installed\n"
        name, target = (
            "scripts/runtime_native_common_attempt.py",
            "/opt/aragorn/example.py",
        )
        origin = {
            "path": name,
            "mode": "100644",
            "bytes": len(source),
            "digest": api._digest(source),
            "blob": hashlib.sha1(
                b"blob " + str(len(source)).encode() + b"\0" + source
            ).hexdigest(),
        }
        result = api.helper_records(
            {
                "source_raws": {name: source},
                "installed_source_raws": {name: installed},
                "generated_source_raws": {name: installed},
            },
            {name: origin},
            fixture_helpers={name: target},
        )
        self.assertEqual(set(result), {name})
        self.assertEqual(result[name]["installed_path"], target)
        self.assertEqual(result[name]["installed_mode"], "0444")
        self.assertEqual(result[name]["digest"], api._digest(installed))
        self.assertEqual(result[name]["source_origin"], origin)
        self.assertTrue(result[name]["generated"])
        with self.assertRaises(api.NativeCommonSetupCaptureError):
            api.helper_records(
                {
                    "source_raws": {name: source},
                    "installed_source_raws": {name: installed},
                    "generated_source_raws": {name: installed},
                },
                {name: origin | {"digest": api._digest(installed)}},
                fixture_helpers={name: target},
            )

    def test_changed_signed_predecessor_is_rejected_before_composition(self):
        original, _ = composed()
        with self.assertRaises(ValueError):
            subject.compose(original | {subject.HOST: original[subject.HOST] + b"\n"})


if __name__ == "__main__":
    unittest.main()
