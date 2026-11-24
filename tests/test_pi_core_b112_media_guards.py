"""Offline, bounded refusal controls. These do not read or decompress media."""
import unittest

from scripts import verify_pi_core_b112_media as subject
from scripts.build_pi_core_linux import BuildError


def profiles():
    old, fresh = 'a' * 64, 'b' * 64
    shared = {k: old for k in ('kernel_sha256', 'init_sha256', 'loader_sha256', 'manager_sha256')}
    changed = ('root_sha256', 'initramfs_sha256', 'uki_sha256', 'esp_sha256', 'disk_sha256',
               'authenticode_sha256', 'esl_sha256')
    previous = dict(shared, **dict.fromkeys(changed, old), kernel_version=subject.b41.LINUX_VERSION)
    current = dict(previous, **dict.fromkeys(changed, fresh), esl_bytes=76, root_size=1025, disk_bytes=10240,
                   uki_bytes=256, cmdline=subject.CMDLINE, osrel=subject.OSREL, sector_size=512,
                   schema='aragorn/pi-core-b112-successor-media/v1', base_boot_receipt_sha256=subject.B44_PIN,
                   inventory_sha256=subject.LOGICAL, inventory_entries=subject.ROWS,
                   b111_outcome_sha256=subject.B111_OUTCOME, payload_sha256=subject.B111_PAYLOAD,
                   boot_observed=False, secure_boot_enrollment=False, phase3_exit_eligible=False)
    return previous, current


class TestB112Refusals(unittest.TestCase):
    def test_inventory_refuses_foreign_contents_or_incomplete_extent(self):
        for digest, rows, attrs in [('0' * 64, subject.ROWS, subject.XATTRS),
                                    (subject.LOGICAL, subject.ROWS + 1, subject.XATTRS),
                                    (subject.LOGICAL, subject.ROWS, subject.XATTRS - 1)]:
            with self.subTest(rows=rows, attrs=attrs, digest=digest), self.assertRaises(BuildError):
                subject._logical(digest, rows, attrs)

    def test_only_unique_retained_policy_member_may_change(self):
        before, after = b'A' * 112, b'B' * 112
        predecessor, candidate = b'header|' + before + b'|init', b'header|' + after + b'|init'
        subject._cpio(predecessor, candidate, before, after)
        for old, new, src, dst in [(predecessor, candidate[:-1], before, after),
                                   (predecessor + before, candidate + before, before, after),
                                   (predecessor, predecessor, before, before),
                                   (predecessor, candidate, before, after[:-1])]:
            with self.subTest(old=len(old), new=len(new), dst=len(dst)), self.assertRaises(BuildError):
                subject._cpio(old, new, src, dst)

    def test_wrong_lineage_changed_retained_inputs_and_inherited_trust_refuse(self):
        previous, current = profiles()
        subject._profile(current, previous)
        for key, wrong in [('payload_sha256', 'c'*64), ('b111_outcome_sha256', 'd'*64),
                           ('base_boot_receipt_sha256', 'e'*64), ('kernel_sha256', 'f'*64),
                           ('root_sha256', previous['root_sha256']), ('esl_sha256', previous['esl_sha256']),
                           ('boot_observed', True), ('secure_boot_enrollment', True), ('phase3_exit_eligible', 0),
                           ('sector_size', 4096), ('authorization_granted', True)]:
            with self.subTest(key=key), self.assertRaises(BuildError):
                subject._profile(dict(current, **{key: wrong}), previous)

    def test_duplicate_private_receipt_fields_refuse(self):
        with self.assertRaisesRegex(BuildError, 'ambiguous media receipt'):
            subject._receipt(b'{"boot_observed":true,"boot_observed":false}')
