"""Authenticate the B45 executable from a signed Git pin; optionally replay a no-boot binding."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid

from scripts.build_pi_core_linux import ROOT, canonical, require, sha256
from scripts.prepare_pi_core_bound_host_runner import PACK, verify_runner
from scripts.prepare_pi_core_guest_disk import opened


PIN = PACK / "runner-output.json"
MEDIA = PACK.parent / "immutable-host-b44/media-output.json"


def unique(pairs):
    result = dict(pairs)
    require(len(pairs) == len(result), "duplicate binding field")
    return result


def signed_pin(commit, signer):
    """Trust inputs (commit and SSH signer fingerprint) must be supplied out of band."""
    require(re.fullmatch("[0-9a-f]{40}", commit) and re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", signer),
            "expected full approved commit and SSH signer fingerprint")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()), "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0"}

    def git(*args):
        return subprocess.run(["/usr/bin/git", "--no-replace-objects", *args], cwd=ROOT, env=env,
                              stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=15).stdout

    require(git("log", "-1", "--no-notes", "--no-show-signature", "--format=%H%n%G?%n%GF", commit)
            .decode("ascii").splitlines() == [commit, "G", signer], "release signature or signer mismatch")
    return json.loads(git("cat-file", "blob", commit + ":" + PIN.relative_to(ROOT).as_posix()),
                      object_pairs_hook=unique)


def match_executable(binary, pin):
    require(pin["schema"] == "aragorn/bound-host-runner-artifact/v1" and pin["boot_authorized"] is False,
            "not a preparation-only artifact pin")
    props = verify_runner(binary)
    require(canonical(props) == canonical({k: pin[k] for k in props}), "binary differs from signed pin")
    return props


def retained(path, limit):
    with opened(path) as f:
        s = os.fstat(f.fileno())
        require(s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o400 and s.st_size <= limit,
                "unexpected evidence ownership, mode or size")
        data = f.read(limit + 1)
        require(len(data) == s.st_size, "evidence length mismatch")
        return data


def identity(path, private_dir=False):
    s = path.lstat()
    if private_dir:
        require(path.resolve(strict=True) == path and stat.S_ISDIR(s.st_mode) and
                s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700, "expected private directory")
    return {"dev": s.st_dev, "ino": s.st_ino}


def replay(attempt, disk, receipt_sha256, pin, *, expected_store=None, expected_policy=None):
    """Read only. No authentic capture or firmware assertion can be minted by replay."""
    require(attempt.is_absolute() and str(uuid.UUID(attempt.name)) == attempt.name,
            "expected named absolute private attempt")
    identity(attempt, True)
    fixture = identity(attempt.parent, True)
    receipt = retained(attempt / "binding.json", 65536)
    require(sha256(receipt) == receipt_sha256, "externally retained binding digest mismatch")
    b = json.loads(receipt, object_pairs_hook=unique)
    raw = retained(attempt / "serial.raw", 8 << 20)
    with opened(MEDIA) as f:
        data = f.read(32769)
    require(sha256(data) == pin["media_pins_sha256"], "media catalog differs from release")
    media = json.loads(data, object_pairs_hook=unique)
    require((expected_store is None) == (expected_policy is None), "expected both private firmware pins")
    target = expected_store is not None
    require(b["schema"] == "aragorn/b44-host-binding/v1" and b["mode"] == ("bind-existing" if target else "preview")
            and b["attempt_uuid"] == attempt.name and b["fixture_identity"] == fixture, "wrong attempt or mode")
    require(disk.resolve(strict=True) == disk and b["disk_identity"] == identity(disk), "different disk object")
    require(b["runner_cdhash"] == pin["cdhash"] and
            all(b[k] == pin[k] for k in ("runner_sha256", "request_sha256", "disk_sha256", "media_pins_sha256"))
            and all(b[k] == media[k] for k in ("disk_sha256", "disk_bytes", "uki_sha256",
                    "authenticode_sha256", "esl_sha256")), "release or candidate mismatch")
    if target:
        s = b["store"]
        require(all(re.fullmatch("[a-f0-9]{64}", h) for h in (expected_store, expected_policy))
                and s["sha256"] == expected_store and s["policy_sha256"] == expected_policy
                and s["secure_boot_enabled"] is True and s["identity"] == identity(attempt.parent / "efi-vars.fd"),
                "store or policy does not match the independent enrollment record")
    else:
        require(b["store"] is None, "local descriptor preview cannot bind firmware")
    graph = {"platform": "generic-arm64-efi", "cpu_count": 2, "memory_bytes": 4 << 30, "nvme_controllers": 1,
             "raw_disks": 1, "attachment_read_only": True, "serial_output_only": 1, "guest_serial_input": False,
             "other_devices": 0, "variable_store_bound": target}
    require(canonical(b["graph"]) == canonical(graph) and sha256(canonical(graph)) == b["graph_sha256"],
            "device graph mismatch")
    c = b["capture"]
    require(c["schema"] == "aragorn/bounded-host-serial/v1" and c["clock"] == "CLOCK_MONOTONIC_RAW" and
            c["raw_file"] == "serial.raw" and raw == b"" and c["capture_sha256"] == sha256(raw) and
            type(c["capture_bytes"]) is int and c["capture_bytes"] == 0 and c["status"] == c["stream_termination"]
            == "empty" and c["sync_verified"] is True and c["pipe_eof"] is True, "not a sealed empty transport")
    times = [c[k] for k in ("attempt_start_ns", "record_start_ns", "record_end_ns")]
    retired = b["graph_retired_ns"]
    require(all(type(n) is int and 0 < n < 1 << 64 for n in (*times, retired)) and times == sorted(times)
            and times[1] <= retired <= times[2] and b["recorder_armed_with_graph"] is True
            and times[2] - times[0] < 180_000_000_000, "invalid recorder/graph lifetime")
    require(b["vm_created"] is False and all(r[k] is False for r in (b, c) for k in
            ("boot_observed", "phase3_exit_eligible")), "binding exceeds preparation authority")
    return {"status": "matched_no_boot_binding", "attempt_uuid": attempt.name, "binding_sha256": receipt_sha256,
            "runner_sha256": pin["runner_sha256"], "boot_observed": False, "phase3_exit_eligible": False}


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("commit", help="full trusted signed release commit")
    ap.add_argument("signer", help="expected trusted SSH signer fingerprint")
    ap.add_argument("binary", type=Path)
    ap.add_argument("--binding", nargs=3, metavar=("ATTEMPT_DIR", "DISK", "BINDING_SHA256"))
    ap.add_argument("--firmware", nargs=2, metavar=("STORE_SHA256", "POLICY_SHA256"))
    args = ap.parse_args()
    if args.firmware and not args.binding:
        ap.error("--firmware requires --binding")
    release = signed_pin(args.commit, args.signer)
    result = match_executable(args.binary, release)
    if args.binding:
        attempt, disk, digest = args.binding
        store, policy = args.firmware or (None, None)
        result = replay(Path(attempt), Path(disk), digest, release, expected_store=store, expected_policy=policy)
    print(json.dumps(result, sort_keys=True))
