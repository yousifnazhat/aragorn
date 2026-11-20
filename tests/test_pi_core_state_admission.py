"""Inert B55 composition records only. No volume, process, mount or guest is inspected."""
from copy import deepcopy
from io import BytesIO, StringIO
from contextlib import redirect_stdout
import json
import stat
from pathlib import Path
import tempfile
import unittest

from aragorn import pi_core_state_admission as admission
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_json
from test_pi_core_state_exposure import ADMITTED, WORKER_ROOT, pi_exposure_sample
from test_pi_core_state_mounts import sample_mountinfo


def pin(value):
    return "sha256:" + value * 64


class StateAdmissionTests(unittest.TestCase):
    def put(self, value):
        raw = value if isinstance(value, bytes) else canonical_json(value) + b"\n"
        return self.writer.put(BytesIO(raw), max_bytes=len(raw))

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.location = Path(tmp.name).resolve()
        self.writer = CAS(self.location)
        self.reader = CAS(self.location, read_only=True)
        roles = ("manager", "action", "sensor", "provider", "pi")
        ids = {role: dict(uid=i * 10, gid=i * 10) for i, role in enumerate(roles)}
        volume = dict(backing_identity=pin("a"), encryption_uuid="ac1fc095-d8de-4ad8-9c6d-a8593cfb1fcc",
                      filesystem_uuid="03202fed-ed69-43dc-81b4-d6cb7309c17e", fs_type="ext4")
        self.profile = self.put(dict(schema=admission.PROFILE, roles=ids, volume=volume, deployment=pin("1"),
                                     configuration=pin("2"), image=pin("3")))
        dev = "253:7"
        A, S, P = admission.ANCHOR, admission.ACTION, admission.PROVIDER
        source = {target: dict(dev=dev, ino=1000 + i, uid=0, gid=0, mode=stat.S_IFDIR | (0o755 if target == S else 0o700))
                  for i, target in enumerate((A, S, P))}
        views = {"manager": {A: 3, S: 4, P: 5}, "action": {S: 4}, "sensor": {S: 4}, "provider": {}, "pi": {}}
        subjects = {role: dict(pid=i+71, start_ticks=i+955, mount_namespace=i+9001, **ids[role])
                    for i, role in enumerate(roles)}
        records = {role: dict(before=deepcopy(subjects[role]), after=deepcopy(subjects[role]),
                              mountinfo=self.put(sample_mountinfo(role, device=dev)),
                              targets={path: dict(source[path], mount_id=mid) for path, mid in views[role].items()})
                   for role in roles}
        pi = subjects["pi"]
        self.exposure = pi_exposure_sample(device=dev, **{k: pi[k] for k in ("pid", "start_ticks", "mount_namespace")})
        mapping = dict(type="dm-crypt", device=dev, backing_devices=["259:0"])
        common = dict(profile=self.profile, boot_id="d362104a-845f-4b13-9e21-ebaf13ebd96c",
                      attachment=dict(backing_identity=pin("a"), writer_deployments=[pin("1")], fence=pin("4"),
                                      mapping=deepcopy(mapping)),
                      generation=7, state_digest=pin("5"), unresolved_attempts=[])
        self.head = dict(deepcopy(common), schema=admission.LATEST, subjects=subjects,
                         worker_root=WORKER_ROOT, admitted_cwd=ADMITTED)
        self.capture = dict(deepcopy(common), schema=admission.CAPTURE, volume=volume,
                            deployment=pin("1"), configuration=pin("2"), image=pin("3"),
                            mapping=mapping,
                            source_roots=source, roles=records, pi_exposure=self.put(self.exposure))

    def independent_head(self, capture=None, **changes):
        cap = self.put(self.capture if capture is None else capture)
        return self.put(self.head | {"capture": cap} | changes)

    def check(self, capture=None, **changes):
        return admission.verify_state_archive(self.reader, self.profile, self.independent_head(capture, **changes))

    def test_read_only_cli_reports_consistency_not_activation_or_installed_isolation(self):
        head = self.independent_head()
        with redirect_stdout(StringIO()) as out:
            self.assertEqual(admission.main([str(self.location), self.profile, head]), 0)
        result = json.loads(out.getvalue())
        self.assertEqual((result["status"], result["profile"], result["independent_head"], result["capture"]),
                         ("consistent-offline-records-only", self.profile, head, self.put(self.capture)))
        self.assertTrue(all(result[k] is False for k in ("activation_authorized", "recovery_authorized",
                                                        "installed_isolation_verified", "phase3_exit_eligible")))

    def test_matching_uuid_does_not_substitute_for_backing_or_exclusive_writer(self):
        wrong = self.capture["volume"] | {"backing_identity": pin("b")}
        with self.assertRaises(ValueError):
            self.check(self.capture | {"volume": wrong})
        dual = self.head["attachment"] | {"writer_deployments": [pin("1"), pin("2")]}
        with self.assertRaises(ValueError):
            self.check(self.capture | {"attachment": dual}, attachment=dual)
        # Every role agrees on the substitute device, but the attachment witness does not.
        cap = deepcopy(self.capture)
        cap["mapping"].update(device="253:8", backing_devices=["259:1"])
        for obj in cap["source_roots"].values():
            obj["dev"] = "253:8"
        for role, obs in cap["roles"].items():
            obs["mountinfo"] = self.put(sample_mountinfo(role, device="253:8"))
            for target in obs["targets"].values():
                target["dev"] = "253:8"
        with self.assertRaises(ValueError):
            self.check(cap)

    def test_independent_latest_state_cannot_be_superseded_by_capture(self):
        for field, value in (("generation", 6), ("state_digest", pin("e")), ("image", pin("9")),
                             ("boot_id", "5aa18d65-5c76-4535-9fa8-df8186c47d26"),
                             ("unresolved_attempts", ["unfinished"])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(self.capture | {field: value})
        with self.assertRaises(ValueError):
            self.check(self.capture | {"unresolved_attempts": ["unknown"]}, unresolved_attempts=["unknown"])

    def test_mounted_object_must_match_manager_not_just_device_or_path(self):
        sensor = self.capture["roles"]["sensor"]
        cap = deepcopy(self.capture)
        cap["source_roots"][admission.ACTION]["mode"] = stat.S_IFREG | 0o755
        with self.assertRaises(ValueError):
            self.check(cap)
        for field in ("ino", "mount_id"):
            cap = deepcopy(self.capture)
            cap["roles"]["sensor"]["targets"][admission.ACTION][field] = 9999
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(cap)
        sensor["mountinfo"] = self.capture["roles"]["action"]["mountinfo"]
        with self.assertRaises(ValueError):
            self.check()

    def test_pi_descriptor_and_process_subject_both_checked(self):
        leak = deepcopy(self.exposure)
        leak["fds"]["0"]["dev"] = self.capture["mapping"]["device"]
        with self.assertRaises(ValueError):
            self.check(self.capture | {"pi_exposure": self.put(leak)})
        for field, replacement in (("pid", True), ("mount_namespace", self.head["subjects"]["sensor"]["mount_namespace"])):
            cap, subjects = deepcopy(self.capture), deepcopy(self.head["subjects"])
            for obs in (subjects["pi"], cap["roles"]["pi"]["before"], cap["roles"]["pi"]["after"]):
                obs[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(cap, subjects=subjects)

    def test_incomplete_custody_untrusted_profile_and_writable_store_are_refused(self):
        head = self.independent_head()
        with self.assertRaises(ValueError):
            admission.verify_state_archive(self.writer, self.profile, head)
        with self.assertRaises(CASError):
            self.check(self.capture | {"pi_exposure": pin("f")})
        other = self.put(dict(schema="unrelated"))
        with self.assertRaises(ValueError):
            self.check(self.capture | {"profile": other})
        with tempfile.TemporaryDirectory() as tmp:
            store = CAS(Path(tmp).resolve())
            with self.assertRaises(CASError):
                admission.verify_state_archive(CAS(store.root, read_only=True), self.profile, head)
