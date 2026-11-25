"""One offline local capability, not the managed Pi deployment or a service."""
import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import sys

sys.path.insert(0, "/opt/aragorn/src")
sys.path.insert(0, str(Path(__file__).parent))
from aragorn.cas import CAS
from aragorn.local_quickstart_sum_observer import hold_sum_output
from aragorn.oci_worker_protocol import canonical_json
from aragorn.pi_core_pilot_output_observer import hold_pilot_output
from aragorn.runtime_action_broker import _atomic_create
from local_approval import approved_worker, inventory_worker, retained_source


# Reviewed source tree, NOT calculated from the current mount at startup.
BUNDLED_TREE = "sha256:c3a61be90f2b094dd0edf9598f07ff40b9a86854f2ca12650aafd2628a97f8c9"
CAPABILITY_DIR = Path("/root/aragorn-capability")
ROOT = Path("/fixture")
OUTPUT = ROOT / "out"
STAGING = ROOT / "staging"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def mediate(request, out_fd, stage_fd, *, spent, expected):
    """Local grant: one create of one exact leaf and reviewed content; no retries."""
    if type(request) is not dict or set(request) != {"op", "target", "value"}:
        return "BLOCK", "invalid request"
    if request["op"] != "create" or request["target"] != "result.json":
        return "BLOCK", "outside grant"
    raw = canonical_json(request["value"])
    if spent or raw != expected:
        return "BLOCK", "spent grant or unexpected content"
    # Never pass a caller-controlled pathname to the filesystem primitive.
    require(_atomic_create(stage_fd, out_fd, "result.json", raw), "create did not complete")
    return "ALLOW", "created"


def bounded_line(stream):
    line = stream.readline(1025)
    require(len(line) <= 1024 and line.endswith(b"\n"), "missing or oversized worker message")
    return line[:-1]


def exercise(worker_bytes, out_fd, stage_fd, operands):
    # Execute the exact bytes that were checked. No directory fd, credential,
    # supplementary group, or writable checkout is handed to the worker.
    a, b = (1, 2) if operands is None else operands
    expected_bytes = canonical_json({"total": a + b})
    data_args = [] if operands is None else [str(a), str(b)]
    proc = subprocess.Popen(
        [sys.executable, "-I", "-B", "-S", "-c", worker_bytes, *data_args],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/", env={},
        user=65534, group=65534, extra_groups=[], close_fds=True,
    )
    try:
        spent = False
        for target, expected_verdict in (("result.json", "ALLOW"), ("forbidden.json", "BLOCK")):
            request = json.loads(bounded_line(proc.stdout))
            verdict, reason = mediate(request, out_fd, stage_fd, spent=spent, expected=expected_bytes)
            require(request["target"] == target and verdict == expected_verdict, "unexpected request or decision")
            if verdict == "ALLOW":
                spent = True
            else:
                require(reason == "outside grant", "denial did not come from the target restriction")
            proc.stdin.write(verdict.encode("ascii") + b"\n")
            proc.stdin.flush()
        proc.stdin.close()
        require(bounded_line(proc.stdout) == b"DIRECT EACCES", "missing kernel denial")
        require(proc.stdout.read(1) == b"" and proc.wait() == 0, "worker did not finish cleanly")
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdin.close()
        proc.stdout.close()


def wire_int32(text):
    # The Mac launcher normalizes user input. Accept only that numeric wire form.
    if len(text) <= 11 and text.isascii() and text.removeprefix("-").isdecimal():
        value = int(text, 10)
        if str(value) == text and -(2**31) <= value < 2**31:
            return value
    raise argparse.ArgumentTypeError("expected a canonical signed 32-bit integer")


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--inventory", action="store_true")
    mode.add_argument("--approve-tree")
    parser.add_argument("--sum", nargs=2, type=wire_int32, metavar=("A", "B"))
    parser.add_argument("--emit-result", action="store_true")
    args = parser.parse_args()
    require(not (args.inventory and (args.emit_result or args.sum is not None)),
            "inventory does not run calculations or export results")
    operands = None if args.sum is None else tuple(args.sum)
    require(sys.platform == "linux" and os.geteuid() == 0 and os.path.ismount(ROOT),
            "use the Colima launcher with its private fixture mount")
    require(not os.listdir(ROOT), "fixture is not fresh")
    cas = CAS(ROOT / "cas")
    if args.inventory:
        manifest = inventory_worker(CAPABILITY_DIR, cas)
        source = retained_source(manifest, cas).decode("utf-8")
        # Escape control characters: reviewed source is data, not terminal output.
        print(json.dumps(dict(tree_digest=manifest["tree_digest"], files=manifest["files"],
                              worker_source=source), ensure_ascii=True))
        return
    pin = args.approve_tree if args.approve_tree is not None else BUNDLED_TREE
    worker = approved_worker(CAPABILITY_DIR, cas, pin)
    parent = CAPABILITY_DIR.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not (parent.st_mode & 0o077),
            "live capability input must not be traversable by the worker")
    OUTPUT.mkdir(mode=0o755)
    STAGING.mkdir(mode=0o700)
    # Ensure search access: direct EACCES must be a denial of creation, not
    # merely the inability to resolve the path to an absent parent.
    OUTPUT.chmod(0o755)
    out_fd = os.open(OUTPUT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(out_fd)
        descriptor = dict(schema="aragorn/runtime-protected-path/v1",
                          root_device=meta.st_dev, root_inode=meta.st_ino, target_name="result.json")
        stage_fd = os.open(STAGING, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            require(not os.listdir(out_fd), "output directory was not empty")
            observer = (hold_pilot_output(out_fd, descriptor, expected_activation_id=secrets.token_hex(16))
                        if operands is None else hold_sum_output(out_fd, operands))
            with observer as after:
                exercise(worker, out_fd, stage_fd, operands)
                raw = bytes.fromhex(after()["payload_hex"]) if operands is None else after()
            # Exact directory entry inventory also rejects a dangling symlink.
            require(os.listdir(out_fd) == ["result.json"] and not os.listdir(stage_fd),
                    "unexpected output or staging residue")
        finally:
            os.close(stage_fd)
    finally:
        os.close(out_fd)
    emit_result = args.emit_result
    log = sys.stderr if emit_result else sys.stdout
    print("ALLOW result.json — verified bytes:", raw.decode("ascii"), file=log)
    denial = ("direct Linux write: EACCES" if pin == BUNDLED_TREE
              else "worker reported EACCES")
    print(f"BLOCK forbidden.json — outside grant; {denial}; verified absent", file=log)
    if emit_result:
        sys.stdout.buffer.write(raw)


def timeout(signum, frame):
    raise TimeoutError("local quickstart exceeded its 15-second execution window")


if __name__ == "__main__":
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(15)
    main()
