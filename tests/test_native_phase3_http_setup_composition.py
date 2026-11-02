"""Only the helper-composition check affected by corrected bridge renderers."""

from contextlib import ExitStack, contextmanager
import unittest
from unittest.mock import patch

import test_native_phase3_http_setup as setup_cases
from tests.test_native_phase3_http_preparation import HttpPreparationFixture


class HttpSetupCompositionTests(unittest.TestCase):
    def test_actual_preparation_and_retention_join_eight_inert_writer_intents(self):
        data = HttpPreparationFixture(self)
        harness = setup_cases.HttpSetupTests()
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        subject = harness.subject
        subject.preparation = data.subject
        subject._IMPLEMENTATION_PATHS = {
            name: "/usr/lib/aragorn/" + name.removeprefix("src/")
            if name.startswith("src/")
            else "/opt/aragorn/" + name.rsplit("/", 1)[1]
            for name in data.subject.IMPLEMENTATION_SOURCE_PATHS
        }
        harness.stage = data.stage
        validate, retain = subject._inputs, subject._retain_preparation
        build = data.subject.prepare_native_common_deployment

        @contextmanager
        def store():
            yield data.cas, data.reader, lambda: None

        with ExitStack() as stack:
            harness.harness(stack)
            harness.raw_inputs = {
                path: raw
                for path, raw in data.inputs.items()
                if path != data.subject.HTTP_FIXTURE
            }
            stack.enter_context(
                patch.object(setup_cases, "BINDING", data.fixture_binding)
            )
            stack.enter_context(
                patch.object(setup_cases, "FIXTURE", data.fixture_binding["fixture"])
            )
            stack.enter_context(patch.object(subject, "_inputs", validate))
            stack.enter_context(patch.object(subject, "_fresh_store", store))
            stack.enter_context(patch.object(subject, "_retain_preparation", retain))
            stack.enter_context(
                patch.object(
                    subject.preparation, "prepare_native_common_deployment", build
                )
            )
            result = harness.run_setup(
                **{
                    key: value
                    for key, value in data.arguments.items()
                    if key not in {"container_id", "provisioning_inputs"}
                }
            )
        self.assertEqual(result["status"], "PREPARED_NOT_ACTIVATED", result)
        record = result["preparation"]
        self.assertTrue(record["local_readback"])
        self.assertEqual(len(record["preparation"]["provisioning_file_digests"]), 8)
        self.assertEqual(result["setup_state"]["activation_count"], 0)
        self.assertEqual(len(result["writer_readback"]), 8)
        harness.native._activate.assert_not_called()
        for pin in record["retained_blob_digests"]:
            self.assertNotIn(data.reader.read(pin), data.inputs.values())


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(
        [
            setup_cases.HttpSetupTests(
                "test_six_helper_composition_is_exact_and_compiles_without_execution"
            ),
            loader.loadTestsFromTestCase(HttpSetupCompositionTests),
        ]
    )
