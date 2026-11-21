"""Only the strict worker-device replay delta. All device numbers are inert fixture data."""
from pathlib import Path
import stat
from unittest import TestCase
from unittest.mock import patch

from aragorn import pi_core_state_admission as admission
from aragorn.cas import CAS
from aragorn.pi_core_state_exposure import _verify_pi_exposure
from scripts import verify_pi_core_joined_mask_receipts as masks
from scripts import verify_pi_core_joined_sensor_state as sensors
import test_pi_core_state_exposure as walks
import test_pi_core_state_mask_archive as archives


def link(walk, name, target):
    dev = walk["tree"]["/dev"]
    for edge in ("before", "after"):
        dev[edge] = sorted([*dev[edge], name])
    walk["tree"]["/dev/" + name] = dict(stat=walks._stat(stat.S_IFLNK, dev="0:21", ino=990, mnt_id=2),
                                         resolved=dict(target))


def strict(walk):
    return _verify_pi_exposure(walk, verified_masks={}, device="253:7", backing_devices=["259:0"],
                               pid=71, start_ticks=955, mount_namespace=9001, worker_root=walks.WORKER_ROOT,
                               admitted_cwd=walks.ADMITTED, namespace=walks.NAMESPACE, strict_worker_devices=True)


class StrictWorkerDevices(TestCase):
    def test_inherited_null_must_be_the_complete_corresponding_standard_descriptor(self):
        for fd, name in enumerate(("stdin", "stdout", "stderr")):
            walk = walks.pi_exposure_sample()
            walk["fds"][str(fd)] = target = dict(walk["fds"][str(fd)], dev="0:88", mnt_id=770, ino=601+fd)
            link(walk, name, target)
            with self.subTest(name=name):
                self.assertIsNone(strict(walk))  # Ordinary objects in this walk retain st_rdev=0:0.
        for change in ("sibling", "mode", "rdev"):
            walk = walks.pi_exposure_sample()
            first = walk["fds"]["0"]
            walk["fds"]["1"] = dict(first, ino=first["ino"]+1)
            wrong = {"sibling": walk["fds"]["1"], "mode": dict(first, mode=stat.S_IFCHR | 0o600),
                     "rdev": dict(first, rdev="1:5")}[change]
            link(walk, "stdin", wrong)  # Both the link and this target use the listed /dev mount.
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "held descriptor"):
                strict(walk)

    def test_unknown_filesystem_device_does_not_prove_exclusion_even_on_matching_stdio(self):
        walk = walks.pi_exposure_sample()
        walk["fds"]["0"] = target = dict(walk["fds"]["0"], dev="0:0", mnt_id=770)
        link(walk, "stdin", target)
        with self.assertRaises(ValueError):
            strict(walk)

    def test_resealed_archive_rejects_unrelated_external_null_only_in_strict_mode(self):
        donor = archives.MaskArchiveTests()
        self.addCleanup(donor.doCleanups)
        donor.setUp()
        target = dict(donor.walk["fds"]["0"], dev="0:88", mnt_id=770)
        donor.walk["fds"]["0"] = target
        link(donor.walk, "stdin", target)
        result = admission.verify_state_archive_v2(donor.base.reader, *donor.pins(), strict_worker_devices=True)
        self.assertIs(result["worker_device_records_consistent"], True)
        self.assertTrue(all(result[key] is False for key in
                            ("installed_isolation_verified", "activation_authorized", "phase3_exit_eligible")))
        link(donor.walk, "alternate", target)  # Even matching fd 0 is not a pathname exemption.
        pins = donor.pins()
        self.assertFalse(admission.verify_state_archive_v2(donor.base.reader, *pins)["activation_authorized"])
        with self.assertRaisesRegex(ValueError, "outside worker namespace"):
            admission.verify_state_archive_v2(donor.base.reader, *pins, strict_worker_devices=True)

    def test_both_strict_callers_select_device_checks_without_changing_legacy_default(self):
        class AtArchive(Exception):
            pass
        archive = object.__new__(CAS)
        archive.root, archive.read_only = Path("/unopened/fixture"), True
        common = dict(archive=archive, store=archive.root/"store", receipt_directory=archive.root/"receipts",
                      **dict.fromkeys(("profile_pin","latest_pin","witness_pin","capture_pin","receipt_pin"), "fixture"))
        for enabled in (False, True):
            for module, run, options in (
                (sensors, sensors.verify_joined_sensor_state, dict(plan_pin="plan", owner_pin="owner",
                    require_current_volume_and_sensor=enabled)),
                (masks, masks.verify_joined_masks, dict(require_owned_worker_spine=enabled, **(
                    dict.fromkeys(("plan_pin","release_pin","claim_pin","owner_pin","boot_id","invocation_id","attempt_id"),
                                  "fixture") if enabled else {}))),
            ):
                with self.subTest(run=run.__name__, strict=enabled), patch.object(module, "_separate"), \
                     patch.object(module, "verify_state_archive_v2", side_effect=AtArchive) as called:
                    with self.assertRaises(AtArchive):
                        run(**common, **options)
                    self.assertIs(called.call_args.kwargs.get("strict_worker_devices", False), enabled)
