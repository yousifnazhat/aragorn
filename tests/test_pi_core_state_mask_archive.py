"""B58: compose sealed inert records only, including the unchanged v1 entrypoint."""
from contextlib import redirect_stdout
from copy import deepcopy
from io import StringIO
import json
import unittest

from aragorn import pi_core_state_admission as admission
from aragorn.cas import CASError
import test_pi_core_state_admission as v1
from test_pi_core_state_masks import mask_sample, masked_pi_mountinfo


class MaskArchiveTests(unittest.TestCase):
    def setUp(self):
        self.base = b = v1.StateAdmissionTests()
        self.addCleanup(b.doCleanups)
        b.setUp()
        self.legacy_pins = b.profile, b.independent_head()
        profile = json.loads(b.reader.read(b.profile))
        b.profile = b.put(profile | {"schema": admission.MASK_PROFILE})
        b.head.update(profile=b.profile, schema=admission.MASK_LATEST)
        b.capture.update(profile=b.profile, schema=admission.MASK_CAPTURE)
        for role in ("pi", "manager"):
            b.head["subjects"][role]["user_namespace"] = 4026531837
            for edge in ("before", "after"):
                b.capture["roles"][role][edge] = deepcopy(b.head["subjects"][role])
        self.walk, self.proof = mask_sample(subject=b.head["subjects"]["pi"],
                                             manager_subject=b.head["subjects"]["manager"])
        self.mounts = masked_pi_mountinfo()
        b.capture["roles"]["pi"]["mountinfo"] = b.put(self.mounts)

    def pins(self, *, override=None):
        b = self.base
        b.capture["pi_exposure"] = b.put(dict(schema=admission.MASK_WALK, walk=self.walk))
        head = b.independent_head()
        outer = dict(schema=admission.MASK_WITNESS, profile=b.profile, independent_head=head,
                     capture=b.put(b.capture), pi_exposure=b.capture["pi_exposure"],
                     boot_id=b.head["boot_id"], proof=self.proof)
        return b.profile, head, b.put(outer | (override or {}))

    def verify(self, **kwargs):
        return admission.verify_state_archive_v2(self.base.reader, *self.pins(**kwargs))

    def test_cli_requires_separately_held_witness_and_only_reports_consistency(self):
        profile, head, witness = self.pins()
        with redirect_stdout(StringIO()) as output:
            self.assertEqual(admission.main([str(self.base.location), profile, head, "--mask-witness", witness]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual((result["mask_witness"], result["status"]), (witness, "consistent-offline-records-only"))
        self.assertTrue(all(result[k] is False for k in ("installed_isolation_verified", "activation_authorized",
                                                         "recovery_authorized", "phase3_exit_eligible")))
        with self.assertRaises(ValueError):
            admission.verify_state_archive(self.base.reader, profile, head)
        with self.assertRaises(ValueError):
            admission.verify_state_archive_v2(self.base.reader, *self.legacy_pins, witness)
        with self.assertRaises(CASError):
            admission.verify_state_archive_v2(self.base.reader, profile, head, v1.pin("f"))

    def test_witness_cannot_select_its_own_subject_or_capture(self):
        for field in ("profile", "independent_head", "capture", "pi_exposure", "boot_id", "schema"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify(override={field: v1.pin("a")})
        self.base.capture["roles"]["pi"]["after"]["user_namespace"] += 1
        with self.assertRaises(ValueError):
            self.verify()

    def test_reparsed_raw_mount_options_and_backing_root_are_authoritative(self):
        for instead in ("rw", "exec", "other-source"):
            rows = self.mounts.decode("ascii").splitlines()
            i = next(i for i, row in enumerate(rows) if row.split()[4] == "/dev/pts")
            fields = rows[i].split()
            if instead == "other-source":
                fields[3] = "/other-source"
            else:
                flags = fields[5].split(",")
                flags[flags.index("ro" if instead == "rw" else "noexec")] = instead
                fields[5] = ",".join(flags)
            rows[i] = " ".join(fields)
            self.base.capture["roles"]["pi"]["mountinfo"] = self.base.put(("\n".join(rows) + "\n").encode())
            with self.subTest(instead=instead), self.assertRaises(ValueError):
                self.verify()

    def test_probe_cannot_borrow_the_pid_of_another_protected_role(self):
        for edge in ("before", "after"):
            self.proof[edge]["probe"]["pid"] = self.base.head["subjects"]["sensor"]["pid"]
        with self.assertRaisesRegex(ValueError, "protected role"):
            self.verify()

    def test_unknown_marker_hidden_child_and_missing_unrelated_listing_refuse(self):
        original = deepcopy(self.walk)
        for problem in ("marker", "child", "missing-list", "fake-empty"):
            self.walk = deepcopy(original)
            tree = self.walk["tree"]
            if problem == "marker":
                tree["/var"] = dict(stat=tree["/var"]["stat"], mask_proof="denied-directory")
            elif problem == "child":
                tree["/dev/pts/hidden"] = deepcopy(tree["/dev/null"])
            elif problem == "fake-empty":
                for edge in ("before", "after"):
                    tree["/dev"][edge].append("zzz")
                tree["/dev/zzz"] = dict(stat={**tree["/dev"]["stat"], "ino": 877, "mode": 0o040000},
                                        before=[], after=[])
            else:
                del tree["/var"]["after"]
            with self.subTest(problem=problem), self.assertRaises(ValueError):
                self.verify()

    def test_v1_still_accepts_its_own_complete_walk_and_refuses_mask_markers(self):
        b = self.base
        self.assertNotIn("mask_witness", admission.verify_state_archive(b.reader, *self.legacy_pins))
        profile, old_head = self.legacy_pins
        head = json.loads(b.reader.read(old_head))
        capture = json.loads(b.reader.read(head["capture"]))
        walk = json.loads(b.reader.read(capture["pi_exposure"]))
        walk["tree"]["/dev"] = dict(stat=walk["tree"]["/dev"]["stat"], mask_proof="denied-directory")
        head["capture"] = b.put(capture | {"pi_exposure": b.put(walk)})
        with self.assertRaises(ValueError):
            admission.verify_state_archive(b.reader, profile, b.put(head))
