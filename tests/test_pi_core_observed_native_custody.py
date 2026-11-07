"""Only the new supervisor-observer handoff; existing kernel fixtures stay inert."""

from dataclasses import replace
import unittest

from aragorn import pi_core_native_request as request
from aragorn import pi_core_source_observer as source
from tests import test_pi_core_native_request as fixtures


class ObservedNativeCustodyTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.InertTests(methodName="runTest")
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def other_observer(self):
        value = object.__new__(source.PiSourceObserver)
        value._owned = self.f.owned
        return value

    def test_supervisor_observer_works_without_replacing_service_channels(self):
        self.f.channels = replace(self.f.channels, source_observer=None)
        self.f.dispatch.channels = self.f.channels
        original = self.f.channels
        self.f.owned.source_observer = self.f.source_observer
        self.assertEqual(self.f.handle()["status"], "COMPLETED")
        self.assertIs(self.f.dispatch.channels, original)
        self.assertIs(self.f.forward.call_args.kwargs["native_custody"]._channels, original)
        self.f.source_health.assert_called_once()

    def test_matching_configured_and_launched_observer_is_one_custody(self):
        self.f.owned.source_observer = self.f.source_observer
        self.assertEqual(self.f.handle()["status"], "COMPLETED")
        self.f.source_health.assert_called_once()

    def test_different_configured_and_launched_observers_refuse(self):
        self.f.owned.source_observer = self.other_observer()
        with self.assertRaisesRegex(request.PiNativeRequestError, "observers disagree"):
            self.f.handle()
        self.f.source_health.assert_not_called()
        self.f.forward.assert_not_called()

    def test_launched_observer_cannot_be_replaced_during_request(self):
        self.f.owned.source_observer = self.f.source_observer
        def forwarded(*args, **options):
            self.f.owned.source_observer = self.other_observer()
            options["native_custody"].guard()
        self.f.forward.side_effect = forwarded
        with self.assertRaisesRegex(request.PiNativeRequestError, "observers disagree"):
            self.f.handle()
        self.f.source_health.assert_called_once()

    def test_missing_launched_observer_cannot_fall_back_to_new_custody(self):
        self.f.channels = replace(self.f.channels, source_observer=None)
        self.f.dispatch.channels = self.f.channels
        self.f.owned.source_observer = self.f.source_observer
        def forwarded(*args, **options):
            self.f.owned.source_observer = None
            options["native_custody"].guard()
        self.f.forward.side_effect = forwarded
        with self.assertRaisesRegex(request.PiNativeRequestError, "exact held source observer"):
            self.f.handle()
        self.f.source_health.assert_called_once()

    def test_launched_only_observer_is_pinned_for_the_request(self):
        self.f.channels = replace(self.f.channels, source_observer=None)
        self.f.dispatch.channels = self.f.channels
        self.f.owned.source_observer = self.f.source_observer
        def forwarded(*args, **options):
            self.f.owned.source_observer = self.other_observer()
            options["native_custody"].guard()
        self.f.forward.side_effect = forwarded
        with self.assertRaisesRegex(request.PiNativeRequestError, "exact held source observer"):
            self.f.handle()
        self.f.source_health.assert_called_once()

    def test_configured_only_observer_remains_explicit_supported_custody(self):
        self.assertEqual(self.f.handle()["status"], "COMPLETED")
        self.f.source_health.assert_called_once()

    def test_neither_observer_still_refuses_before_handoff(self):
        with self.assertRaisesRegex(request.PiNativeRequestError, "exact held source observer"):
            self.f.handle(source_observer=None)
        self.f.forward.assert_not_called()


if __name__ == "__main__":
    unittest.main()
