"""Offline format examples only. No receipts, trusted host, nomination or boot permission."""
import json
import unittest

from scripts.build_pi_core_linux import BuildError, ROOT, canonical, sha256
from scripts.pi_core_single_use_release import DISK_SHA256, SCHEMA, parse_release, release_digest, validate_release


def entry():
    return {"attempt_uuid": "ca0712fe-fc60-4241-8323-f04c29866f12", "host_identity_sha256": "1" * 64,
            "fixture": "/nonexistent/B50 FORMAT TEST", "fixture_identity": {"dev": 1, "ino": 5},
            "disk_identity": {"dev": 1, "ino": 6}, "store_identity": {"dev": 1, "ino": 7},
            "disk_sha256": DISK_SHA256, "store_sha256": "2" * 64, "policy_sha256": "3" * 64,
            "nomination_sha256": "4" * 64, "enrollment_sha256": "5" * 64, "boot_approval_sha256": "6" * 64,
            "not_before_utc": 120, "expires_utc": 420}


def envelope(*entries):
    return {"schema": SCHEMA, "approved_attempts": list(entries)}


class SingleUseRelease(unittest.TestCase):
    def test_candidate_pin_and_canonical_digest_for_hold_or_singleton(self):
        media = json.loads((ROOT / "packaging/pi-core/immutable-host-b44/media-output.json").read_bytes())
        self.assertEqual(DISK_SHA256, media["disk_sha256"])
        for obj in (envelope(), envelope(entry())):
            with self.subTest(obj=obj):
                self.assertEqual(parse_release(json.dumps(obj, indent=2).encode()), obj)
                self.assertEqual(release_digest(parse_release(canonical(obj))), sha256(canonical(obj)))
        self.assertNotEqual(release_digest(envelope()), release_digest(envelope(entry())))

    def test_rejects_duplicate_keys_nonintegral_numbers_and_unbounded_input(self):
        raw = canonical(envelope(entry()))
        for bad in (raw.replace(b'"ino":5', b'"ino":5,"ino":5'), raw.replace(b'"ino":5', b'"ino":5.0'),
                    raw.replace(b'"ino":5', b'"ino":Infinity'), b" " * 8193, b"", b"null", b"\xff",
                    b"[" * 1200 + b"]" * 1200, b'{"schema":"bad","schema":"bad"}'):
            with self.subTest(size=len(bad)), self.assertRaises(BuildError):
                parse_release(bad)

    def test_no_multiple_uuids_or_extra_or_missing_fields(self):
        e = entry()
        for bad in (envelope(e, e), envelope() | {"allow_boot": True}, envelope() | {"schema": "other"},
                    envelope() | {"approved_attempts": {}}, envelope(e | {"retry": True}),
                    *(envelope({k: v for k, v in e.items() if k != omit}) for omit in e)):
            with self.subTest(short=str(bad)[:100]), self.assertRaises(BuildError):
                validate_release(bad)

    def test_refuses_noncanonical_uuid_and_ambiguous_paths(self):
        for uid in ("00000000-0000-0000-0000-000000000000", entry()["attempt_uuid"].upper(), 1):
            with self.subTest(uid=uid), self.assertRaises(BuildError):
                validate_release(envelope(entry() | {"attempt_uuid": uid}))
        for path in ("/", "/a/../b", "//ambiguous", "relative", "/a/./b", "/a//b", "/a/", "/a\x00b",
                     "/a\nb", "/é", "/" + "a" * 256, "/" + ("a/" * 511) + "ab"):
            with self.subTest(path=path), self.assertRaises(BuildError):
                validate_release(envelope(entry() | {"fixture": path}))

    def test_rejects_substituted_disk_invalid_digests_and_collapsed_approval_roles(self):
        e = entry()
        for k in (k for k in e if k.endswith("_sha256")):
            for malformed in ("0" * 64, "A" * 64, "1" * 63, None):
                with self.subTest(k=k, malformed=malformed), self.assertRaises(BuildError):
                    validate_release(envelope(e | {k: malformed}))
        for k, substitute in (("disk_sha256", "7" * 64), ("enrollment_sha256", e["nomination_sha256"]),
                              ("boot_approval_sha256", e["enrollment_sha256"])):
            with self.subTest(k=k), self.assertRaises(BuildError):
                validate_release(envelope(e | {k: substitute}))

    def test_bound_inodes_distinct_and_window_in_whole_utc_seconds(self):
        e = entry()
        for k, v in (("fixture_identity", {"dev": True, "ino": 4}), ("store_identity", {"dev": 1, "ino": 0}),
                     ("disk_identity", e["store_identity"]), ("disk_identity", {"dev": 2**64, "ino": 1}),
                     ("disk_identity", {"dev": 1, "ino": 2, "alias": False}), ("not_before_utc", True),
                     ("not_before_utc", 0), ("expires_utc", 120), ("expires_utc", 119), ("expires_utc", 253402300800)):
            with self.subTest(k=k, v=v), self.assertRaises(BuildError):
                validate_release(envelope(e | {k: v}))
