"""Offline B44 guest record reader. It cannot authenticate a VM, capture window or reporter."""
import argparse
import json
from pathlib import Path
import re

from scripts.build_pi_core_linux import ROOT, regular_bytes, require, sha256
from scripts.prepare_pi_core_guest_disk import opened

PINS = ROOT / "packaging/pi-core/immutable-host-b44/media-output.json"
LIMIT = 8 << 20
FAMILY = b"ARAGORN_B"
RECORD = re.compile(
    rb"ARAGORN_B44_V1 boot=(?P<boot>[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})"
    rb" disk_ro=1 part_ro=1 sector=512 part_bytes=(?P<size>[1-9][0-9]{0,10})"
    rb" root_ro=1 lib_ro=1 lib_same=1 pid=1 manager_sha256=(?P<manager>[0-9a-f]{64})"
    rb" root_sha256=(?P<root>[0-9a-f]{64})\r?\n"
)


def inspect_serial(raw: bytes, *, expected_boot_id: str | None = None) -> dict:
    """Compare to pins in the reviewed checkout; offsets are into original bytes, including line endings."""
    require(type(raw) is bytes and 0 < len(raw) < LIMIT, "empty or at/over serial capture limit")
    require(b"aragorn early boot refused" not in raw and b"Kernel panic - not syncing" not in raw,
            "guest refusal or panic in capture")
    require(raw.endswith(b"\n"), "unterminated capture")
    require(raw.count(FAMILY) == 1, "absent, duplicate or mixed guest records")
    start = raw.index(FAMILY)
    require(start == 0 or raw[start - 1] == 10, "guest record is not at a line boundary")
    end = raw.index(b"\n", start) + 1
    match = RECORD.fullmatch(raw, start, end)
    require(match is not None, "malformed or conflicting guest record")
    boot = match["boot"].decode("ascii")
    require(expected_boot_id is None or boot == expected_boot_id, "boot ID mismatch")
    # The same boot policy pins the manager and root. A serial line cannot attest its containing UKI.
    pins = json.loads(regular_bytes(PINS, 32768))
    require(pins["boot_observed"] is False and pins["sector_size"] == 512
            and int(match["size"]) == (pins["root_size"] + 511) // 512 * 512
            and match["root"].decode("ascii") == pins["root_sha256"]
            and match["manager"].decode("ascii") == pins["manager_sha256"],
            "guest record does not match the signed successor pins")
    return {"schema": "aragorn/observable-guest-serial/v1", "status": "matching_guest_record_only",
            "capture_sha256": sha256(raw), "capture_bytes": len(raw),
            "record_offset": start, "record_bytes": end - start, "boot_id": boot,
            "external_boot_id_compared": expected_boot_id is not None,
            "candidate_disk_sha256": pins["disk_sha256"], "candidate_uki_sha256": pins["uki_sha256"],
            "host_custody_verified": False, "phase3_exit_eligible": False}


def inspect_capture(path: Path, expected_sha256: str, expected_boot_id: str | None = None):
    with opened(path) as f:
        raw = f.read(LIMIT)
    require(len(raw) < LIMIT and sha256(raw) == expected_sha256, "capture limit or external digest mismatch")
    return inspect_serial(raw, expected_boot_id=expected_boot_id)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path, help="absolute path to retained raw bytes (not a terminal)")
    parser.add_argument("capture_sha256", help="digest from the separate host capture record")
    parser.add_argument("--expected-boot-id")
    args = parser.parse_args()
    print(json.dumps(inspect_capture(args.capture, args.capture_sha256, args.expected_boot_id), sort_keys=True))
