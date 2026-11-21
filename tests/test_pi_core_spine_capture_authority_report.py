"""Offline B71 report upgrade: release spending, the worker and the guest are inert."""
from hashlib import sha256
import unittest
from unittest.mock import patch

from aragorn import pi_core_mask_capture_entry as entry
from tests import test_pi_core_mask_capture_entry as entry_fx
from tests import test_pi_core_mask_capture_release as release_fx
from tests import test_pi_core_mask_capture_wrapper as wrapper_fx
from tests import test_pi_core_worker_handle_authority as handle_fx


ENTRY_V2 = "aragorn/pi-core-mask-capture-entry/v2"
PUBLIC_V2 = "aragorn/pi-core-mask-capture-report/v2"


class SpineAuthorityReport(unittest.TestCase):
    fixture = handle_fx.HandleAuthority.fixture

    def spine(self):
        c = self.fixture(entry_fx.EntryTests)
        c.plan["schema"] = entry.SPINE_PLAN
        media = entry.entry.configuration.carrier_media.ROOT
        section = c.plan["service_configuration"]
        section.update(deployment_path=str(media / "installed"),
                       carrier=dict(device="259:4", image_bytes=4096, image_sha256="7" * 64))
        for key in ("manifest", "configurations"):
            section[key]["path"] = str(media / "inputs" / (key + ".json"))
        c.raw["retention"]["worker_spine_digest"] = entry_fx.pin(303)
        return c

    @staticmethod
    def v2():
        return dict(wrapper_fx.retained(), schema=ENTRY_V2, capture_authority={
            name: wrapper_fx.pin(c) for name, c in zip(
                ("host_profile_digest", "plan_digest", "release_digest", "claim_digest"), "abcd")})

    def withheld(self, code, report):
        self.assertNotEqual(code, 0)
        self.assertNotEqual(report["schema"], PUBLIC_V2)
        self.assertNotIn("capture_authority", report)
        self.assertIsNone(report["capture_digest"])
        self.assertIsNone(report["receipt_digest"])

    def test_entry_names_the_claim_bytes_returned_by_its_one_release_call(self):
        # Use the real claim format with mocked kernel inputs and spent-name storage.
        make_claim = entry.release.claim_capture_release
        r = self.fixture(release_fx.MaskRelease)
        c = self.spine()
        pin = entry_fx.pin
        r.inputs.rows[0]["pin"] = pin(2)
        r.inputs.deadline = c.deadline.return_value
        r.doc.update(scope=entry.release.SPINE_SCOPE, host_profile_digest=pin(1), plan_digest=pin(2),
                     deployment_digest=pin(5), expires_unix_ns=r.doc["not_before_unix_ns"] + 10**10)

        def spend(inputs, **kwargs):
            self.assertIs(inputs, c.inputs)
            # Entry's holder is inert; keep the release validator's exact-type guard intact.
            with patch.object(entry.entry, "_Inputs", type(r.inputs)):
                return make_claim(r.inputs, **kwargs)

        c.claim.side_effect = spend
        result = c.invoke()
        claim_digest = "sha256:" + sha256(r.spend.call_args.args[2]).hexdigest()
        r.spend.assert_called_once()
        c.claim.assert_called_once()
        self.assertEqual(c.edge.call_args.kwargs["claim_digest"], claim_digest)
        self.assertEqual(result["schema"], ENTRY_V2)
        self.assertEqual(result["capture_authority"], dict(host_profile_digest=pin(1), plan_digest=pin(2),
                                                          release_digest=pin(3), claim_digest=claim_digest))
        self.assertEqual((result["capture_digest"], result["receipt_digest"]), (pin(301), pin(302)))

    def test_final_veto_and_post_capture_input_cleanup_do_not_expose_spine_authority(self):
        for failure in ("final-release", "configuration-close", "inputs-close"):
            with self.subTest(failure=failure):
                c = self.spine()
                if failure == "final-release":
                    c.edge.side_effect = ValueError("withdrawn")
                elif failure == "configuration-close":
                    c.unwind_failure = True
                else:
                    c.inputs.close.side_effect = OSError("close refused")
                observation = c.refusal()
                self.assertFalse(observation["cleanup_verified"])
                self.assertNotIn("capture_authority", observation)
                self.assertNotEqual(observation["schema"], ENTRY_V2)

    def test_only_original_positive_arguments_publish_the_four_pins_with_the_two_member_pins(self):
        wrapper = self.fixture(wrapper_fx.MaskCaptureWrapper)
        value = self.v2()
        code, report = wrapper.invoke(value)
        self.assertEqual((code, report["schema"], report["status"]), (0, PUBLIC_V2, "CAPTURE_RETAINED_ONLY"))
        for name in ("capture_authority", "capture_digest", "receipt_digest"):
            self.assertEqual(report[name], value[name])
        self.assertEqual(report["wrapper_cleanup"], {"host": "CLOSED", "source_loader": "CLOSED"})
        self.assertFalse(report["activation_authorized"] or report["phase3_exit_eligible"])

    def test_stale_host_plan_substituted_release_and_aliased_claim_cannot_publish(self):
        wrapper = self.fixture(wrapper_fx.MaskCaptureWrapper)
        for name, new in (("host_profile_digest", "e"), ("plan_digest", "e"),
                          ("release_digest", "e"), ("claim_digest", "9")):
            with self.subTest(name=name):
                value = self.v2()
                value["capture_authority"][name] = wrapper_fx.pin(new)
                self.withheld(*wrapper.invoke(value))

    def test_exception_carried_success_post_call_veto_and_both_outer_close_failures_strip_pins(self):
        wrapper = self.fixture(wrapper_fx.MaskCaptureWrapper)
        for change in (dict(error=True), dict(guard=[None, ValueError("withdrawn")]),
                       dict(cleanup="host"), dict(cleanup="source_loader")):
            with self.subTest(change=change):
                self.withheld(*wrapper.invoke(self.v2(), **change))

    def test_verified_negative_stays_v1_and_legacy_report_cannot_smuggle_authority(self):
        c = self.spine()
        c.raw = entry_fx.native_result(False)
        c.raw["retention"]["worker_spine_digest"] = entry_fx.pin(303)
        negative = c.invoke()
        self.assertEqual((negative["schema"], negative["status"]),
                         ("aragorn/pi-core-mask-capture-entry/v1", "CAPTURE_RETAINED_INCONSISTENT"))
        self.assertNotIn("capture_authority", negative)
        wrapper = self.fixture(wrapper_fx.MaskCaptureWrapper)
        code, report = wrapper.invoke(negative)
        self.assertEqual((code, report["schema"], report["receipt_digest"]),
                         (126, "aragorn/pi-core-mask-capture-report/v1", entry_fx.pin(302)))
        self.assertNotIn("capture_authority", report)
        self.withheld(*wrapper.invoke(dict(wrapper_fx.retained(), capture_authority=self.v2()["capture_authority"])))
