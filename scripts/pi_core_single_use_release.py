"""B50 offline boot-release format. A valid entry describes one grant; parsing never issues it."""
import re

from scripts.build_pi_core_linux import canonical, require, sha256
from scripts.verify_pi_core_owner_records import _object


SCHEMA = "aragorn/b50-single-use-release/v1"
DISK_SHA256 = "c87cf6ef3a6f728958256bd278a748f5f71fae78b3f0de91c02ee1dba1a4837c"  # B44 raw image
APPROVALS = ("nomination_sha256", "enrollment_sha256", "boot_approval_sha256")
HASHES = ("disk_sha256", "host_identity_sha256", "store_sha256", "policy_sha256", *APPROVALS)
IDENTITIES = ("fixture_identity", "disk_identity", "store_identity")


def validate_release(obj):
    """Check the zero-or-one release shape, not private custody, signatures, or freshness."""
    require(type(obj) is dict and obj.keys() == {"schema", "approved_attempts"} and obj["schema"] == SCHEMA,
            "invalid B50 release envelope")
    attempts = obj["approved_attempts"]
    require(type(attempts) is list and len(attempts) <= 1, "release must be held or bind exactly one attempt")
    if not attempts:
        return obj
    e = attempts[0]
    require(type(e) is dict and e.keys() == {*HASHES, *IDENTITIES, "attempt_uuid", "fixture", "not_before_utc",
                                           "expires_utc"}, "missing or unexpected single-use release field")
    uid = e["attempt_uuid"]
    require(type(uid) is str and re.fullmatch("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", uid)
            and uid != "00000000-0000-0000-0000-000000000000", "invalid canonical attempt UUID")
    path = e["fixture"]
    # Lexical check only; the native owner must confirm the named private directory and held files.
    require(type(path) is str and path.startswith("/") and len(path) < 1024 and path.isascii()
            and path.isprintable() and all(p not in ("", ".", "..") and len(p) <= 255 for p in path[1:].split("/")),
            "expected one canonical absolute fixture path")
    for k in HASHES:
        h = e[k]
        require(type(h) is str and re.fullmatch("[0-9a-f]{64}", h) and h != "0" * 64, "invalid digest: " + k)
    require(e["disk_sha256"] == DISK_SHA256, "wrong B44 candidate disk")
    require(len({e[k] for k in APPROVALS}) == len(APPROVALS), "approval records must be distinct for each gate")
    nodes = set()
    for name in IDENTITIES:
        fs = e[name]
        require(type(fs) is dict and fs.keys() == {"dev", "ino"} and type(fs["dev"]) is int
                and 0 <= fs["dev"] < 2**64 and type(fs["ino"]) is int and 0 < fs["ino"] < 2**64,
                "invalid filesystem identity: " + name)
        nodes.add((fs["dev"], fs["ino"]))
    require(len(nodes) == len(IDENTITIES), "fixture, disk and store must be distinct")
    start, end = e["not_before_utc"], e["expires_utc"]
    require(type(start) is int and type(end) is int and 0 < start < end <= 253402300799,
            "invalid half-open UTC window")
    return obj


def parse_release(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 8192, "invalid boot release byte length")
    return validate_release(_object(raw))


def release_digest(obj):
    """Fingerprint validated content canonicalized identically to the embedded release."""
    return sha256(canonical(validate_release(obj)))
