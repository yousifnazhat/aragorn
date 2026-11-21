"""Join separately held fixture archives. No worker or namespace is opened."""
from contextlib import redirect_stderr
from copy import deepcopy
import hashlib
from io import StringIO
import unittest
from unittest.mock import patch

from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_json
from aragorn.pi_core_mask_probe import _PROGRAM
from aragorn.pi_core_state_mounts import ACTION, ANCHOR, PROVIDER
from scripts.verify_pi_core_joined_mask_receipts import main, verify_joined_masks
import test_pi_core_mask_custody as local
import test_pi_core_state_mask_archive as outer


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class JoinedMasks(unittest.TestCase):
    def setUp(self):
        # Use only the existing fixture setup, not historical test methods.
        self.outer, self.local = outer.MaskArchiveTests(), local.MaskCustodyTests()
        for fixture in (self.outer, self.local):
            self.addCleanup(fixture.doCleanups)
            fixture.setUp()
        self.base = self.outer.base
        self.attempt = 0

    def retain(self, mutate=None):
        b = self.base
        self.attempt += 1
        worker_raw, manager_raw = (b.reader.read(b.capture["roles"][k]["mountinfo"]) for k in ("pi", "manager"))
        witness, walk = deepcopy(self.outer.proof), self.outer.walk
        worker, manager = witness["worker"], witness["manager"]
        names = walk["tree"]["/dev"]["before"]
        bindings = dict(schema="aragorn/pi-core-stopped-mask-binding/v1", attempt_id=f"{self.attempt:032x}",
                        deployment=b.capture["deployment"], profile=digest(b"fixture-source-profile"),
                        interpreter=digest(b"fixture-interpreter"), probe_source=digest(_PROGRAM.encode("ascii")),
                        unit="aragorn-pi-" + "d" * 32 + ".service", invocation="d" * 32, launch=digest(b"launch"),
                        clock=dict(boot_id=b.head["boot_id"], clock_id="CLOCK_BOOTTIME", time_namespace_inode=8101),
                        worker=worker, manager=manager, storage=dict(device=b.capture["mapping"]["device"],
                        backing_devices=b.capture["mapping"]["backing_devices"], fs_type=b.capture["volume"]["fs_type"]))
        def held(row):
            return {k:v for k,v in row.items() if k != "probe"}
        view = dict(schema="aragorn/pi-core-stopped-mask-view/v1", worker=worker, manager=manager,
                    source=witness["source"], directories={p:held(r) for p,r in witness["directories"].items()},
                    ptmx=held(witness["ptmx"]), dev_names=names, worker_root=walk["root"],
                    worker_dev=walk["tree"]["/dev"]["stat"], opened_boottime_ns=9000, closed_boottime_ns=21000)
        proof = dict(witness=witness, names_before=names, names_after=names)
        parts = dict(bindings=bindings, vantage=view, proof=proof, worker=worker_raw, manager=manager_raw)
        if mutate is not None:
            mutate(parts)
        for role in ("worker", "manager"):
            view[role + "_mountinfo_digest"] = digest(parts[role])
        encoded = {k:(v if isinstance(v, bytes) else canonical_json(v)) for k,v in parts.items()}
        capture_pin = digest(encoded["bindings"])
        receipt = self.local.retain(capture_digest=capture_pin, **{k + "_raw":v for k,v in encoded.items()})
        return dict(store=self.local.store, receipt_directory=self.local.receipts,
                    capture_pin=capture_pin, receipt_pin=receipt)

    def keys(self, **kwargs):
        profile, latest, witness = self.outer.pins(**kwargs)
        return dict(archive=self.base.reader, profile_pin=profile, latest_pin=latest, witness_pin=witness)

    def manager_view(self, parts):
        roots = self.base.capture["source_roots"]
        targets = self.base.capture["roles"]["manager"]["targets"]
        anchor_mount = targets[ANCHOR]["mount_id"]
        frame = dict(sources={p: dict(roots[p], rdev="0:0", mnt_id=anchor_mount)
                              for p in (ANCHOR, ACTION, PROVIDER)},
                     targets={p: dict(roots[p], rdev="0:0", mnt_id=targets[p]["mount_id"])
                              for p in (ACTION, PROVIDER)})
        parts["bindings"]["schema"] = "aragorn/pi-core-stopped-mask-binding/v2"
        parts["vantage"].update(schema="aragorn/pi-core-stopped-mask-view/v2",
                                manager_state=dict(before=frame, after=deepcopy(frame)))

    def test_manager_state_compares_both_archives_without_authorizing_or_promoting_a_capture(self):
        args = self.keys() | self.retain(self.manager_view)
        result = verify_joined_masks(**args, require_manager_state=True)
        self.assertIs(result["manager_state_roots_and_targets_matched"], True)
        self.assertEqual(result["status"], "consistent-offline-records-only")
        for key in ("external_freshness_verified", "same_capture_interval_verified", "recovery_authorized",
                    "activation_authorized", "installed_isolation_verified", "phase3_exit_eligible"):
            self.assertIs(result[key], False)

    def test_manager_state_requirement_refuses_legacy_receipts_at_cli(self):
        args = self.keys() | self.retain()
        options = [value for k, v in args.items() for value in
                   ("--" + k.replace("_", "-"), str(v.root if k == "archive" else v))]
        with redirect_stderr(StringIO()) as error:
            self.assertEqual(main([*options, "--require-manager-state"]), 2)
        self.assertIn("manager-state evidence required", error.getvalue())

    def test_resealed_v2_manager_source_and_alias_with_different_inode_cannot_join(self):
        def other_objects(parts):
            self.manager_view(parts)
            for frame in parts["vantage"]["manager_state"].values():
                for side in ("sources", "targets"):
                    frame[side][ACTION]["ino"] += 1000
        args = self.keys() | self.retain(other_objects)
        # The local source and its bind agree. Even compatibility mode cannot ignore a v2 disagreement.
        with self.assertRaisesRegex(ValueError, "different manager-state source roots"):
            verify_joined_masks(**args)

    def test_resealed_outer_state_with_a_different_root_cannot_join_local_manager_observation(self):
        local_args = self.retain(self.manager_view)
        source = self.base.capture["source_roots"][PROVIDER]
        source["ino"] += 1000
        for entry in self.base.capture["roles"].values():
            if PROVIDER in entry["targets"]:
                entry["targets"][PROVIDER]["ino"] = source["ino"]
        with self.assertRaisesRegex(ValueError, "different manager-state source roots"):
            verify_joined_masks(**self.keys(), **local_args, require_manager_state=True)

    def test_separate_matching_archives_are_joined_without_writing_or_granting_authority(self):
        args = self.keys() | self.retain()
        with patch.object(CAS, "put", side_effect=AssertionError("offline verifier wrote a blob")), \
             patch.object(CAS, "put_expected", side_effect=AssertionError("offline verifier wrote a pinned blob")), \
             patch.object(CAS, "materialize", side_effect=AssertionError("offline verifier wrote a receipt")):
            report = verify_joined_masks(**args)
        self.assertEqual(report["status"], "consistent-offline-records-only")
        for result, key in (("mask_capture_binding", "capture_pin"), ("local_receipt", "receipt_pin"),
                            ("mask_witness", "witness_pin"), ("independent_head", "latest_pin")):
            self.assertEqual(report[result], args[key])
        for key in ("installed_isolation_verified", "activation_authorized", "recovery_authorized",
                    "phase3_exit_eligible", "same_capture_interval_verified", "external_freshness_verified",
                    "manager_state_roots_and_targets_matched"):
            self.assertIs(report[key], False)

    def test_resealed_boot_deployment_storage_and_subject_from_another_capture_refuse(self):
        args = self.keys()
        for name, change in (
                ("boot", lambda p: p["bindings"]["clock"].update(boot_id="16b05d90-4b09-4521-af78-e5f4440eaeba")),
                ("deployment", lambda p: p["bindings"].update(deployment=digest(b"different deployment"))),
                ("another backing", lambda p: p["bindings"]["storage"].update(backing_devices=["259:1"])),
                ("manager", lambda p: p["bindings"]["manager"].update(pid=999))):
            local_args = self.retain(change)
            with self.subTest(name=name), self.assertRaises(ValueError):
                verify_joined_masks(**args, **local_args)

    def test_resealed_worker_and_manager_streams_must_match_byte_for_byte_not_just_as_mount_sets(self):
        args = self.keys()
        for role in ("worker", "manager"):
            def reorder(parts):
                rows = parts[role].splitlines(keepends=True)
                parts[role] = b"".join([rows[0], *reversed(rows[1:])])
                self.assertNotEqual(parts[role], b"".join(rows))
            local_args = self.retain(reorder)
            with self.subTest(role=role), self.assertRaises(ValueError):
                verify_joined_masks(**args, **local_args)

    def test_mask_probe_witness_and_full_device_enumeration_must_agree(self):
        args = self.keys()
        def other_probe(p):
            obs = p["proof"]["witness"]["directories"]["/dev/pts"]["probe"]
            obs["finished_ns"] += 1  # still within the valid B58 timing window
        def other_inventory(p):
            names = sorted([*p["vantage"]["dev_names"], "unrelated-device-name"])
            p["vantage"]["dev_names"] = p["proof"]["names_before"] = p["proof"]["names_after"] = names
        for label, change in (("different lookup", other_probe), ("different /dev", other_inventory)):
            local_args = self.retain(change)
            with self.subTest(label=label), self.assertRaises(ValueError):
                verify_joined_masks(**args, **local_args)

    def test_local_mask_record_cannot_repair_incomplete_full_walk_or_stale_outer_head(self):
        local_args = self.retain()
        fresh = self.keys()
        b = self.base
        b.head["generation"] += 1
        b.capture["generation"] += 1
        successor = self.keys()
        with self.assertRaises(ValueError):
            verify_joined_masks(**(fresh | {"latest_pin": successor["latest_pin"]}), **local_args)
        del self.outer.walk["tree"]["/var"]["after"]
        incomplete = self.keys()
        with self.assertRaises(ValueError):
            verify_joined_masks(**incomplete, **local_args)

    def test_missing_or_wrong_independent_pins_and_missing_private_receipt_refuse(self):
        args = self.keys() | self.retain()
        for key in ("witness_pin", "latest_pin", "receipt_pin"):
            with self.subTest(key=key), self.assertRaises((ValueError, CASError, OSError)):
                verify_joined_masks(**(args | {key:digest(b"no external evidence")}))
        only_receipt, = self.local.receipts.iterdir()
        only_receipt.unlink()
        with self.assertRaises((ValueError, CASError, OSError)):
            verify_joined_masks(**args)

    def test_writable_outer_store_or_shared_storage_cannot_count_as_independent(self):
        args = self.keys() | self.retain()
        for label, changes in (("writable", {"archive":self.base.writer}),
                               ("one store for both roles", {"store":self.base.location}),
                               ("outer store is receipt directory", {"receipt_directory":self.base.location})):
            with self.subTest(label=label), self.assertRaises((ValueError, CASError)):
                verify_joined_masks(**(args | changes))
