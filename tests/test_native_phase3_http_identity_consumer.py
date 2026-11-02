"""Only the two affected HTTP retained-consumer checks after the shadow fix.

The seven unchanged reader/rendering checks have retained successful evidence.
Shared fixture helpers are imported, never their test methods or live readers.
"""

from copy import deepcopy
import stat
import unittest

from test_native_phase3_http_identity import (
    ACCOUNTS,
    PIN,
    _documents,
    _inert_read,
    _subjects,
)


class NativeHttpIdentityConsumerTests(unittest.TestCase):
    def setUp(self):
        self.reader, self.verifier, _, _ = _subjects()
        self.result, _, _, self.pins = _inert_read(self.reader, _documents(self.reader))
        # Inert metadata labels, not process qualification or a loaded-code claim.
        for role, views in self.result["loaded_process_views"].items():
            for name, record in views.items():
                if name != "code_view":
                    record["identity"][2] = stat.S_IFREG | 0o400
            if role == "gateway":
                views["code_view"]["identity"][3:5] = [1000, 1000]

    def test_offline_http_file_consumer_accepts_real_reader_shape_not_loaded_claim(
        self,
    ):
        self.verifier._files(self.result, self.pins, ACCOUNTS)
        for target in ("worker", "sensor", "broker"):
            bad = deepcopy(self.result)
            bad["http_fixture_views"][target]["identity"][2] = stat.S_IFREG | 0o644
            with (
                self.subTest(target=target),
                self.assertRaisesRegex(
                    self.verifier.frozen.NativePluginUpdateLiveBindingError,
                    "unsafe or inconsistent retained file metadata",
                ),
            ):
                self.verifier._files(bad, self.pins, ACCOUNTS)

    def test_offline_http_consumer_rejects_changed_fixture_payload_and_inventory(self):
        # A clean control must pass before mutations; failure elsewhere cannot
        # accidentally satisfy every negative case.
        self.verifier._files(self.result, self.pins, ACCOUNTS)
        mutations = (
            (
                lambda x: x["http_fixture_views"].pop("worker"),
                "HTTP fixture process-view inventory changed",
            ),
            (
                lambda x: x["measured_joins"]["http_fixture_binding"].update(
                    expected_broker_uid=True
                ),
                "HTTP protected fixture binding join changed",
            ),
            (
                lambda x: x["measured_joins"].update(http_attempt_id="p3-lab-a026"),
                "HTTP attempt identity changed",
            ),
            (
                lambda x: x["measured_joins"][
                    "declared_input_digests_not_cas_readback"
                ].update(payload_digest=PIN),
                "HTTP retained action digest join changed",
            ),
            (
                lambda x: x["files"].pop(
                    self.reader.MEASUREMENT_SOURCES["runtime_action_service.py"]
                ),
                "HTTP41 file inventory changed",
            ),
        )
        for mutate, reason in mutations:
            bad = deepcopy(self.result)
            mutate(bad)
            with (
                self.subTest(reason=reason),
                self.assertRaisesRegex(
                    self.verifier.NativeCommonProcessVerificationError, reason
                ),
            ):
                self.verifier._files(bad, self.pins, ACCOUNTS)
