"""One separately nominated capture on one boot. No provisioning, cleanup, or retry."""
from contextlib import ExitStack, contextmanager
import math
import os
from pathlib import Path
import re
import stat
import time

from . import pi_core_mask_custody as custody
from . import pi_core_stopped_mask_view as view
from .oci_worker_protocol import canonical_digest, canonical_json
from .pi_core_state_admission import _keys, _need, _pin, _same, _uint, _uuid
from .pi_core_state_mounts import verify_mounts


RELEASE_PATH = Path("/etc/aragorn/approvals/stopped-mask-release.json")
CLAIM_ROOT = Path("/var/lib/aragorn-capture-claims")
SCOPE = "ONE_STOPPED_WORKER_MASK_CAPTURE_NO_PROVIDER_NO_ACTIVATION"
_WINDOW_NS = 300_000_000_000


def _window(doc, deadline):
    _need(type(deadline) in (float, int) and math.isfinite(deadline), "invalid capture deadline")
    start, end = (_uint(doc[k], high=1 << 63) for k in ("not_before_unix_ns", "expires_unix_ns"))
    mono = time.monotonic_ns()
    now = time.time_ns()
    # Round the remaining deadline up so a fractional nanosecond cannot widen approval.
    left = int(deadline * 1e9) + 1 - mono
    _need(0 < left <= 30_000_000_001 and start <= now and now + left <= end and
          0 < end - start <= _WINDOW_NS, "invalid or insufficient capture release window")


def _kernel_inputs(deadline):
    with ExitStack() as stack:
        proc, mount = view._proc(stack)
        sysctl = proc
        for part in ("sys", "kernel", "random"):
            sysctl = view._proc_child(stack, sysctl, part, os.O_RDONLY | os.O_DIRECTORY, mount)
        boot = view._read(sysctl, "boot_id", 37, mount, deadline)
        _need(len(boot) == 37, "invalid kernel boot UUID")
        caller = view._magic(stack, proc, "thread-self", os.O_RDONLY | os.O_DIRECTORY, mount)
        raw = view._read(caller, "mountinfo", 1 << 20, mount, deadline)
    return _uuid(boot[:-1].decode("ascii")), raw


def _locations(mounts, ledger, capture, roots, protected):
    table = {Path(p): m for p, m in mounts.items()}
    def location(p):
        point = next(t for t in (p, *p.parents) if t in table)
        m = table[point]
        return m, Path(m["root"]) / p.relative_to(point)
    def overlaps(a, b):
        return a.is_relative_to(b) or b.is_relative_to(a)
    previous = []
    for path, dev in ((CLAIM_ROOT, ledger["dev"]), (capture.store, roots[0][0]), (capture.receipt_directory, roots[1][0])):
        m, fs_path = location(path)
        if isinstance(dev, int):
            dev = f"{os.major(dev)}:{os.minor(dev)}"
        _need(m["dev"] == dev and m["fs_type"] in ("ext4", "xfs") and "rw" in m["options"] and
              dev not in (capture.volume_device, *capture.backing_devices) and
              all(t == path or not t.is_relative_to(path) for t in table), "invalid capture custody filesystem")
        if path == CLAIM_ROOT:
            _need(m["mount_id"] == ledger["mnt_id"], "ledger mount disagrees with retained directory")
        for otherdev, coord in previous:
            _need(dev != otherdev or not overlaps(fs_path, coord), "aliased capture storage")
        previous.append((dev, fs_path))
        for protected_path in protected:
            p, base = location(protected_path)
            _need(not overlaps(path, protected_path) and
                  (p["dev"] != dev or not overlaps(fs_path, base)), "capture storage overlaps protected inputs")
            _need(all(not (k.is_relative_to(protected_path) and row["dev"] == dev and overlaps(fs_path, Path(row["root"])))
                      for k, row in table.items()), "capture storage reachable through protected subtree")


def _spend(fd, name, raw):
    # A failed or interrupted write intentionally leaves the exclusive name occupied.
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400, dir_fd=fd)
    try:
        before = os.fstat(out)
        _need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o400 and
              before.st_uid == before.st_gid == 0 and before.st_nlink == 1 and before.st_size == 0,
              "unsafe capture claim")
        custody.files.write_all(out, raw)
        os.fsync(out)
        os.fsync(fd)
        identity = custody.files._file_identity(os.fstat(out))
        _read_claim(fd, name, raw, identity)
        return identity
    finally:
        os.close(out)


def _read_claim(fd, name, raw, identity):
    before = os.stat(name, dir_fd=fd, follow_symlinks=False)
    _need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o400 and
          before.st_uid == before.st_gid == 0 and before.st_nlink == 1 and before.st_size == len(raw)
          and custody.files._file_identity(before) == identity, "capture claim identity changed")
    _need(custody.files._read_owned_bytes_at(fd, name, max_bytes=4096, expected_uid=0,
              exact_mode=0o400, label="capture claim") == raw and identity ==
          custody.files._file_identity(os.stat(name, dir_fd=fd, follow_symlinks=False)), "capture claim readback differs")


@contextmanager
def _hold_claim(inputs, doc, capture, protected, deadline):
    with custody._roots(RELEASE_PATH.parent, CLAIM_ROOT, deadline) as (fd, guard, private_roots), \
         custody._roots(capture.store, capture.receipt_directory, deadline) as (_, evidence_guard, roots):
        def check():
            inputs.guard()
            guard()
            evidence_guard()
            boot, raw = _kernel_inputs(deadline)
            _need(boot == doc["boot_id"], "release for another guest boot")
            ledger = view._stat(fd)
            _same({k:ledger[k] for k in doc["claim_directory"]}, doc["claim_directory"], "foreign capture claim root")
            mounts = {}
            verify_mounts("manager", raw, device=capture.volume_device, backing_devices=capture.backing_devices,
                          fs_type=capture.fs_type, mount_details=mounts)
            _locations(mounts, ledger, capture, roots, protected)
            _window(doc, deadline)
        check()
        yield fd, (private_roots, roots)
        check()
    _window(doc, deadline)


def claim_capture_release(inputs, *, release_digest, plan_digest, host_profile_digest, capture, deadline,
                          protected_paths=()):
    from .pi_core_coordinator_entry import _Inputs
    from .pi_core_stopped_mask_capture import StoppedMaskCapture

    _need(type(inputs) is _Inputs and inputs.deadline == deadline and type(capture) is StoppedMaskCapture
          and len({_pin(release_digest), _pin(plan_digest), _pin(host_profile_digest)}) == 3 and
          any(r["pin"] == plan_digest and r["path"] != RELEASE_PATH for r in inputs.rows),
          "independently pinned capture plan, host and release required")
    _need(type(capture.attempt_id) is str and re.fullmatch(r"[0-9a-f]{32}", capture.attempt_id)
          and int(capture.attempt_id, 16), "invalid capture attempt")
    view._platform()
    doc = inputs.read(RELEASE_PATH, release_digest, 8192)
    expected = dict(schema="aragorn/pi-core-stopped-mask-release/v1", scope=SCOPE, plan_digest=plan_digest,
                    host_profile_digest=host_profile_digest, deployment_digest=_pin(capture.deployment_digest),
                    attempt_id=capture.attempt_id, max_starts=1)
    _keys(doc, (*expected, "boot_id", "claim_directory", "not_before_unix_ns", "expires_unix_ns"))
    _same({k:doc[k] for k in expected}, expected, "release not for this capture")
    _uuid(doc["boot_id"])
    _keys(doc["claim_directory"], ("dev", "ino", "mnt_id"))
    _window(doc, deadline)
    name = "spent-" + capture.attempt_id + ".json"
    claim = dict(schema="aragorn/pi-core-mask-start-claim/v1", status="SPENT", release_digest=release_digest,
                 plan_digest=plan_digest, boot_id=doc["boot_id"], attempt_id=capture.attempt_id)
    protected = (RELEASE_PATH.parent, *(r["path"].parent for r in inputs.rows),
                 *(p for p, _, _ in inputs.directories), *protected_paths)
    _need(all(isinstance(p, Path) and p.is_absolute() and p.anchor == "/" and ".." not in p.parts
              for p in protected), "invalid capture separation path")
    raw, claim_digest = canonical_json(claim), canonical_digest(claim)
    with _hold_claim(inputs, doc, capture, protected, deadline) as (fd, roots):
        identity = _spend(fd, name, raw)
    inputs._mask_start = (release_digest, claim_digest, capture, deadline, doc, protected, roots, name, raw, identity)
    return claim_digest


def guard_capture_start(inputs, *, release_digest, claim_digest, capture, deadline):
    """Last ordered readback before the sole native start. No allocation or re-claim."""
    from .pi_core_coordinator_entry import _Inputs

    _need(type(inputs) is _Inputs, "original capture input holder required")
    authority = vars(inputs).pop("_mask_start", None)
    _need(authority is not None, "capture start authority absent or already used")
    grant, pin, owner, cutoff, doc, protected, original_roots, name, raw, identity = authority
    _need(release_digest == grant and claim_digest == pin and capture is owner and
          deadline == inputs.deadline == cutoff, "capture start binding changed")
    with _hold_claim(inputs, doc, capture, protected, deadline) as (fd, roots):
        _need(roots == original_roots, "capture custody roots changed before start")
        held = [r for r in inputs.rows if r["path"] == RELEASE_PATH and r["pin"] == grant]
        _need(len(held) == 1 and os.pread(held[0]["fd"], 8193, 0) == held[0]["raw"],
              "held capture release withdrawn or changed")
        _read_claim(fd, name, raw, identity)
