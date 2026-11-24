"""Offline release, source, and mount substitution cases. No kernel operations."""
from copy import deepcopy
import os
import stat
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from aragorn import pi_core_pilot_retention_entry as subject


def pin(c):
    return "sha256:" + c * 64


class RetentionBindingTests(TestCase):
    def setUp(self):
        self.device = os.makedev(8, 41)
        path = dict(schema="aragorn/runtime-protected-path/v1", target_name="result.json", root_device=7, root_inode=55)
        self.plan = dict(deployment={"digest": pin("d")}, mode="PROTECTED", cas_root="/var/lib/aragorn/cas",
                         pilot_output=dict(path_descriptor=path, reader_source_digest="sha256:" +
                                           subject._B109["pi_core_pilot_output_observer"]),
                         service_runtime=dict(manifest={"digest": subject._SERVICE[0]},
                                              runtime_binding={"digest": subject._SERVICE[1]}, receipt_digest=subject._SERVICE[2]))
        self.doc = dict(schema="aragorn/pi-core-pilot-output-local-release/v1", scope=subject.SCOPE,
                        base_payload_digest=subject.sink.B109_PAYLOAD_DIGEST, host_profile_digest=pin("b"),
                        plan_digest=pin("a"), deployment_digest=pin("d"), path_digest=subject.canonical_digest(path),
                        attempt_id="c" * 32, boot_id="owner-boot", not_before_unix_ns=50, expires_unix_ns=100,
                        mount_id=3, roots=[[self.device, i, stat.S_IFDIR | 0o700, 0, 0] for i in (23, 24)])

    def bind(self, doc=None, plan=None):
        return subject._binding(self.doc if doc is None else doc, self.plan if plan is None else plan, pin("a"), pin("b"))

    def test_release_binds_materials_actual_successor_and_distinct_private_roots(self):
        self.assertEqual(self.bind()["expected_roots"], tuple(map(tuple, self.doc["roots"])))
        for key, wrong in (("base_payload_digest", pin("0")), ("host_profile_digest", subject.sink.B109_HOST_PROFILE_DIGEST),
                           ("plan_digest", pin("9")), ("deployment_digest", pin("1")), ("path_digest", pin("f")),
                           ("attempt_id", "0" * 32), ("scope", "PILOT"), ("mount_id", True),
                           ("roots", self.doc["roots"][:1] * 2)):
            with self.subTest(key=key), self.assertRaises(subject.entry.PiCoordinatorEntryError):
                self.bind(doc=self.doc | {key: wrong})
        for key in ("manifest", "runtime_binding", "receipt_digest"):
            plan = deepcopy(self.plan)
            plan["service_runtime"][key] = pin("9") if key == "receipt_digest" else {"digest": pin("9")}
            with self.subTest(service=key), self.assertRaises(subject.entry.PiCoordinatorEntryError):
                self.bind(plan=plan)

    def test_missing_duplicate_or_replaced_consumed_caller_source_refuses(self):
        pins = {name: "sha256:" + v for name, v in subject._B109.items()}
        pins.update(pi_core_pilot_retention_entry=pin("1"), pi_core_pilot_output_custody=pin("2"))
        rows = [dict(module="aragorn." + name, path="opt/aragorn/src/aragorn/" + name + ".py", digest=v)
                for name, v in pins.items()]
        for selected in (rows, rows[:-1], rows + rows[:1], [dict(rows[0], digest=pin("a"))] + rows[1:]):
            loader = SimpleNamespace(source_digests={r["path"]: r["digest"] for r in selected})
            with patch.object(subject.entry, "_custody", return_value=(pin("b"), selected, {})):
                if selected is rows:
                    self.assertEqual(subject._source(loader, object(), 10), pin("b"))
                else:
                    with self.assertRaises(subject.entry.PiCoordinatorEntryError):
                        subject._source(loader, object(), 10)

    def test_boot_mount_and_state_or_archive_alias_refuse_before_spend(self):
        line = b"3 2 8:41 / /run/aragorn-pilot-output-evidence rw,nodev,nosuid,noexec - ext4 /dev/test rw\n"
        prefix = b"1 1 8:5 / / ro - ext4 /dev/root ro\n2 1 0:4 / /run rw - tmpfs tmpfs rw\n"
        alias = b"4 1 8:41 / /alias rw - ext4 /dev/test rw\n"
        for boot, rows, cas, ok in [
                ("owner-boot", line, self.plan["cas_root"], True), ("wrong-boot", line, self.plan["cas_root"], False),
                ("owner-boot", line + alias, self.plan["cas_root"], False),
                ("owner-boot", line.replace(b"3 2 ", b"8 2 "), self.plan["cas_root"], False),
                ("owner-boot", line, str(subject.BASE / "cas"), False)]:
            with patch.object(subject.protected, "_window"), patch.object(subject.protected, "_kernel_inputs",
                    return_value=(boot, prefix + rows)):
                if ok:
                    subject._location(self.doc, self.plan, 10)
                else:
                    with self.assertRaises((ValueError, subject.entry.PiCoordinatorEntryError)):
                        subject._location(self.doc, self.plan | {"cas_root": cas}, 10)
