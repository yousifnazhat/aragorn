"""Only the provider source/output additions and four affected inert checks."""

import unittest
from unittest import mock

from tests import test_pi_core_linux_build as fixtures


class ProviderBuildTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.LinuxBuildTests(methodName="runTest")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def test_missing_provider_source_refuses_before_build_directory_creation(self):
        output, node, ts, compiler = self.fixture.fixture()
        (self.fixture.root / fixtures.build.PACKAGE / "provider.ts").unlink()
        with self.assertRaises(FileNotFoundError):
            fixtures.build.prepare(self.fixture.root, output, node, ts, compiler)
        self.assertFalse(output.exists())

    def test_missing_provider_output_refuses_and_cleans_owned_compiler_resources(self):
        subject, _calls, removed = self.fixture.executor()
        (subject.output / "deployment/pi-core/provider.js").unlink()
        with mock.patch.object(fixtures.build.os, "getuid", return_value=501), \
                mock.patch.object(fixtures.build.os, "getgid", return_value=20):
            with self.assertRaisesRegex(fixtures.build.BuildError, "output is incomplete"):
                subject.compile()
        self.assertEqual(removed, {"container", "image"})
        self.assertFalse((subject.output / "build-receipt.json").exists())


def load_tests(loader, tests, pattern):
    for name in (
        "test_preparation_keeps_runtime_and_legacy_relative_layout",
        "test_compiler_command_is_networkless_nonprivileged_and_bounded",
        "test_receipt_explicitly_disclaims_runtime_execution_and_qualification",
        "test_compiler_config_has_only_explicit_entrypoints",
    ):
        tests.addTest(fixtures.LinuxBuildTests(name))
    return tests
