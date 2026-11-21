"""Offline joins only. The release kernel, unit, protected sources and worker are all inert."""
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aragorn import pi_core_mask_capture_entry as entry, pi_core_mask_capture_release as release
from tests import test_pi_core_mask_capture_entry as entry_fx
from tests import test_pi_core_mask_capture_release as release_fx
from tests import test_pi_core_mask_native_start_guard as native_fx


class HandleAuthority(unittest.TestCase):
    def fixture(self, cls):
        case = cls()
        self.addCleanup(case.doCleanups)
        case.setUp()
        return case

    def test_only_new_plan_with_protected_configuration_requests_handles(self):
        c = self.fixture(entry_fx.EntryTests)
        c.plan["schema"] = entry.SPINE_PLAN
        self.assertEqual(c.refusal()["status"], "REFUSED")
        c.claim.assert_not_called()
        media = entry.entry.configuration.carrier_media.ROOT
        section = c.plan["service_configuration"]
        section.update(deployment_path=str(media / "installed"),
                       carrier=dict(device="259:4", image_bytes=4096, image_sha256="7"*64))
        for key in ("manifest", "configurations"):
            section[key]["path"] = str(media / "inputs" / (key + ".json"))
        c.raw["retention"]["worker_spine_digest"] = entry_fx.pin(303)
        result = c.invoke()
        self.assertEqual(result["status"], "CAPTURE_RETAINED_ONLY")
        cap = c.native.call_args.kwargs["capture"]
        self.assertIs(cap.worker_spine, True)
        self.assertIs(c.claim.call_args.kwargs["capture"], cap)
        self.assertIs(c.edge.call_args.kwargs["capture"], cap)
        self.assertEqual(c.events, ["claim", "prepared", "edge", "would-start"])
        self.assertNotIn("worker_spine_digest", result)  # Separate reader dereferences the two public pins.

    def test_retained_response_cannot_downgrade_or_smuggle_the_extra_member(self):
        for requested, added in ((True, {}), (True, {"worker_spine_digest":entry_fx.pin(302)}),
                                 (False, {"worker_spine_digest":entry_fx.pin(303)})):
            raw = entry_fx.native_result()
            raw["retention"].update(added)
            with self.subTest(requested=requested, added=added), self.assertRaises(entry.entry.PiCoordinatorEntryError):
                entry._result(raw, {}, worker_spine=requested)

    def test_handle_release_and_legacy_release_are_not_interchangeable(self):
        f = self.fixture(release_fx.MaskRelease)
        original = f.cfg
        for handles, scope in ((True, release.SCOPE), (False, release.SPINE_SCOPE)):
            f.cfg = replace(original, worker_spine=handles)
            f.doc["scope"] = scope
            with self.subTest(handles=handles), self.assertRaisesRegex(ValueError, "not for this capture"):
                f.claim()
        f.spend.assert_not_called()
        f.cfg = replace(original, worker_spine=True)
        f.doc["scope"] = release.SPINE_SCOPE
        guard, _, _ = f.arm()
        proof = guard()
        release.require_handle_start(proof, f.cfg, f.inputs.deadline)
        for cap, deadline in ((original, f.inputs.deadline), (f.cfg, f.inputs.deadline + 1)):
            with self.assertRaisesRegex(ValueError, "no confirmed release"):
                release.require_handle_start(proof, cap, deadline)
        with self.assertRaisesRegex(ValueError, "already used"):
            guard()
        f.spend.assert_called_once()

    def test_native_caller_cannot_use_absent_or_mask_only_callback(self):
        f = self.fixture(native_fx.CaptureStartGuard)
        f.custody = replace(f.custody, worker_spine=True)
        with self.assertRaises(entry.native.PiNativeSupervisorError):
            f.run_capture(_before_start=None)
        f.prep.assert_not_called()
        self.assertEqual(f.run_capture(_before_start=lambda: None)["status"], "REFUSED")
        f.start.assert_not_called()
        f.arm.assert_not_called()

    def test_native_positive_uses_the_proof_returned_by_the_real_final_release_guard(self):
        r = self.fixture(release_fx.MaskRelease)
        f = self.fixture(native_fx.CaptureStartGuard)
        r.cfg = f.custody = replace(r.cfg, worker_spine=True)
        r.inputs.deadline = 20.
        r.doc["scope"] = release.SPINE_SCOPE
        r.wall.return_value = 10**12
        r.inputs.rows.append(dict(path=release.RELEASE_PATH, pin=release_fx.pin("c"),
                                  raw=release.canonical_json(r.doc), fd=42))
        args = dict(release_digest=release_fx.pin("c"), capture=r.cfg, deadline=20.)
        with patch.object(release.os, "pread", return_value=release.canonical_json(r.doc)), \
             patch.object(release, "_read_claim"), patch.object(release.time, "monotonic_ns", return_value=18*10**9):
            pin = release.claim_capture_release(r.inputs, plan_digest=release_fx.pin("a"),
                    host_profile_digest=release_fx.pin("b"), **args)
            f.arm.side_effect = f.stub_observer
            f.receipt.update(worker_spine_digest=entry_fx.pin(303))
            result = f.run_capture(_before_start=lambda: release.guard_capture_start(r.inputs, claim_digest=pin, **args))
        self.assertEqual(result["status"], "CAPTURE_RETAINED_ONLY")
        f.start.assert_called_once()
        r.spend.assert_called_once()

    def test_opt_in_source_modules_must_have_been_consumed(self):
        names = entry._CORE + entry._SPINE_CORE
        pins = {"opt/aragorn/src/aragorn/" + name + ".py":entry_fx.pin(i+10) for i,name in enumerate(names)}
        rows = [dict(module="aragorn."+name, path=p, digest=pin) for name,(p,pin) in zip(names,pins.items())]
        with patch.object(entry.entry, "_custody", return_value=(entry_fx.pin(1), rows, {"python_executable":str(entry._PYTHON)})):
            args = SimpleNamespace(source_digests=pins), SimpleNamespace(_expected={entry._PYTHON:{"digest":entry_fx.pin(2)}}), 10.
            self.assertEqual(entry._custody(*args, worker_spine=True), (entry_fx.pin(1), entry_fx.pin(2)))
            rows.pop()
            with self.assertRaisesRegex(entry.entry.PiCoordinatorEntryError, "SOURCE_NOT_CONSUMED"):
                entry._custody(*args, worker_spine=True)
