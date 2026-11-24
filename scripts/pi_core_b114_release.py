"""B112 compatibility boot build seal. No approval issuer, enrollment, boot or retry.

The externally trusted signer must authenticate the original nomination, enrollment
and one-attempt boot decision *before* sealing their three distinct digests. Merely
hashing private files does not verify a decision or provision an authority.
"""
from pathlib import Path
import re
import time

from scripts import prepare_pi_core_b113_owner as owner
from scripts import verify_pi_core_b113_boot_evidence as b113
from scripts.build_pi_core_linux import ROOT, canonical, require, sha256
from scripts.pi_core_single_use_release import APPROVALS, HASHES, IDENTITIES
from scripts.prepare_pi_core_host_lifecycle import require_local_custody
from scripts.verify_pi_core_host_binding import identity, retained
from scripts.verify_pi_core_owner_records import _object


BASELINE = "ff6f08ade6cb070bc8d096f8a70d99d6a281beb8"
PACK = ROOT / "packaging/pi-core/immutable-host-b114"
SEAL, ARTIFACT = PACK / "build-seal.json", PACK / "runner-output.json"
DISK = "aae016bd1b7ef412e619bd82adc6cb9b436349fe9bfe48a0a0ba091e8b646cec"
HELD_SEAL = {"schema": "aragorn/b114-private-build-seal/v1",
             "purpose": "prepare-one-b112-compatibility-owner-only", "candidate": b113.EXACT, "approved": None}
PIN_KEYS = {"release_sha256", *APPROVALS}
# An issued receipt is an output. It cannot be required in the prebuild tree.
NEW = frozenset({SEAL, *(ROOT / "scripts" / (name + ".py") for name in (
    "pi_core_b114_release", "prepare_pi_core_b114_owner", "verify_pi_core_b114_boot_evidence"))})
FROZEN = frozenset({*(ROOT / path for path in b113.PATHS.values()),
    *(owner.BASE / f"immutable-host-b{batch}" / name for batch, name in owner.SOURCES),
    *(ROOT / "scripts" / (name + ".py") for name in (
        "build_pi_core_linux", "inspect_pi_core_guest_disk", "inspect_pi_core_observable_serial",
        "pi_core_host_evidence_export", "pi_core_host_watchdog", "pi_core_owner_archive", "pi_core_single_use_release",
        "prepare_pi_core_b113_owner", "prepare_pi_core_bound_host_runner", "prepare_pi_core_guest_disk",
        "prepare_pi_core_guest_firmware_trust", "prepare_pi_core_host_lifecycle", "prepare_pi_core_host_sysroot",
        "verify_pi_core_b113_boot_evidence", "verify_pi_core_host_binding", "verify_pi_core_owner_records",
        "verify_pi_core_owner_watchdog"))})
REVIEWED_SOURCES = NEW | FROZEN


def _hash(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) and value != "0" * 64


def _pins(pins):
    require(type(pins) is dict and pins.keys() == PIN_KEYS and all(_hash(x) for x in pins.values())
            and len(set(pins.values())) == len(PIN_KEYS), "missing, invalid or aliased build approval digests")
    return pins


def approved_digest(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 8192, "invalid build seal size")
    seal = _object(raw)
    require(seal.keys() == HELD_SEAL.keys() and canonical(seal | {"approved": None}) == canonical(HELD_SEAL),
            "wrong B114 build seal or B112 candidate")
    require(seal["approved"] is not None, "held B114 seal: no one-time build approved")
    return _pins(seal["approved"])


def validate_release(obj):
    # Preserve B50's field/bounds contract without rewriting B112 into a synthetic
    # B44 entry for the old, explicitly B44-only validator.
    require(type(obj) is dict and obj.keys() == owner.HELD.keys() and obj["schema"] == owner.HELD["schema"],
            "wrong B113 native release schema")
    slots = obj["approved_attempts"]
    require(type(slots) is list and len(slots) <= 1, "expected zero or one attempt")
    if not slots:
        return obj
    e = slots[0]
    require(type(e) is dict and e.keys() == {*HASHES, *IDENTITIES, "attempt_uuid", "fixture",
                                             "not_before_utc", "expires_utc"}, "wrong private release fields")
    uid, path = e["attempt_uuid"], e["fixture"]
    require(type(uid) is str and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", uid)
            and uid.replace("-", "") != "0"*32, "invalid attempt UUID")
    require(type(path) is str and path.startswith("/") and len(path) < 1024 and path.isascii()
            and path.isprintable() and all(p not in ("", ".", "..") and len(p) <= 255 for p in path[1:].split("/")),
            "invalid fixture path")
    require(all(_hash(e[k]) for k in HASHES) and e["disk_sha256"] == DISK
            and len({e[k] for k in APPROVALS}) == len(APPROVALS), "wrong B112 disk or private binding digests")
    nodes = set()
    for k in IDENTITIES:
        node = e[k]
        require(type(node) is dict and node.keys() == {"dev", "ino"} and
                type(node["dev"]) is int and 0 <= node["dev"] < 2**64 and
                type(node["ino"]) is int and 0 < node["ino"] < 2**64, "invalid filesystem identity")
        nodes.add((node["dev"], node["ino"]))
    lo, hi = e["not_before_utc"], e["expires_utc"]
    require(len(nodes) == len(IDENTITIES) and type(lo) is type(hi) is int and 0 < lo < hi <= 253402300799,
            "aliased filesystem identities or invalid UTC window")
    return obj


def parse_release(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 8192, "invalid release size")
    return validate_release(_object(raw))


def release_digest(obj):
    return sha256(canonical(validate_release(obj)))


def match_private(pins, raw):
    _pins(pins)
    release = parse_release(raw)
    slots = release["approved_attempts"]
    require(len(slots) == 1 and release_digest(release) == pins["release_sha256"] and
            all(slots[0][key] == pins[key] for key in APPROVALS), "private release does not match approved seal")
    return release


def _commit(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value), "need full commit hash")


def verify_commit(commit, signer):
    _commit(commit)
    require(type(signer) is str and re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", signer), "need trusted SSH fingerprint")
    require(b113._git("log", "-1", "--no-notes", "--no-show-signature", "--format=%H%n%G?%n%GF", commit)
            .decode("ascii").splitlines() == [commit, "G", signer], "wrong source or signer")


def require_ancestor(older, newer):
    _commit(older)
    _commit(newer)
    require(older != newer, "expected distinct approval and artifact commits")
    b113._git("merge-base", "--is-ancestor", older, newer)


def signed_blob(commit, path):
    """Read one allowed regular Git blob; caller must authenticate the commit first."""
    _commit(commit)
    require(path in REVIEWED_SOURCES or path == ARTIFACT, "unreviewed signed input path")
    name = path.relative_to(ROOT).as_posix()
    row = b113._git("ls-tree", "-z", commit, "--", name)
    match = re.fullmatch(rb"100(?:644|755) blob ([a-f0-9]{40})\t" + re.escape(name.encode("ascii")) + b"\x00", row)
    require(match is not None, "missing or nonregular signed input: " + name)
    oid = match[1].decode("ascii")
    size = int(b113._git("cat-file", "-s", oid))
    require(0 < size <= (8192 if path in (SEAL, ARTIFACT) else 1 << 20), "oversized signed input")
    raw = b113._git("cat-file", "blob", oid)
    require(len(raw) == size, "incomplete signed input")
    return raw


def approved_source(commit, signer):
    """Read authenticated historical inputs only (including the seal from that commit)."""
    verify_commit(commit, signer)
    seal = signed_blob(commit, SEAL)
    pins = approved_digest(seal)  # held path stops before any private-file argument or target access
    require_ancestor(BASELINE, commit)
    sources = {p: signed_blob(commit, p) for p in REVIEWED_SOURCES if p != SEAL} | {SEAL: seal}
    require(all(sources[p] == signed_blob(BASELINE, p) for p in FROZEN), "changed frozen B112/B113 input")
    b113.joined({key: sources[ROOT / path] for key, path in b113.PATHS.items()})
    return pins, sha256(seal), sources


def read_private(pins, path):
    _pins(pins)
    require(isinstance(path, Path) and path.is_absolute() and path.resolve(strict=True) == path,
            "private release must be canonical")
    require_local_custody(path)
    original = identity(path.parent, True)
    raw = retained(path, 8192)
    require(identity(path.parent, True) == original, "private release parent changed")
    return match_private(pins, raw)


def authorized_material(commit, signer, private_path):
    """Build only: verify current regular source bytes, then read the nominated sealed release."""
    pins, seal_sha, sources = approved_source(commit, signer)
    require(set(sources) == REVIEWED_SOURCES and all(owner.host.source_bytes(p) == raw for p, raw in sources.items()),
            "working sources differ from signed prebuild")
    release = read_private(pins, private_path)
    require(time.time_ns() < release["approved_attempts"][0]["expires_utc"] * 10**9, "expired private build window")
    return release, seal_sha, sources
