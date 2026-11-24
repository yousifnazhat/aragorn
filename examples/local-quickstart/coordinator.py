"""One offline local capability, not the managed Pi deployment or a service."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys

sys.path.insert(0, "/opt/aragorn/src")
from aragorn.oci_worker_protocol import canonical_json
from aragorn.pi_core_pilot_output_observer import hold_pilot_output
from aragorn.runtime_action_broker import _atomic_create


WORKER_SHA256 = "fb43597bfeef51cb28eb66766fc4f4df6ad7d03eb9de160bc69718d6baa6a195"
RESULT_SHA256 = "9f827af5202050f264dfa05aeec4603d0fcec968de43ed7b039ce6a2d6231b08"
ROOT = Path("/fixture")
OUTPUT = ROOT / "out"
STAGING = ROOT / "staging"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def mediate(request, out_fd, stage_fd, *, spent):
    """Local grant: one create of one exact leaf and reviewed content; no retries."""
    if type(request) is not dict or set(request) != {"op", "target", "value"}:
        return "BLOCK", "invalid request"
    if request["op"] != "create" or request["target"] != "result.json":
        return "BLOCK", "outside grant"
    raw = canonical_json(request["value"])
    if spent or hashlib.sha256(raw).hexdigest() != RESULT_SHA256:
        return "BLOCK", "spent grant or unexpected content"
    # Never pass a caller-controlled pathname to the filesystem primitive.
    require(_atomic_create(stage_fd, out_fd, "result.json", raw), "create did not complete")
    return "ALLOW", "created"


def bounded_line(stream):
    line = stream.readline(1025)
    require(len(line) <= 1024 and line.endswith(b"\n"), "missing or oversized worker message")
    return line[:-1]


def exercise(worker_bytes, out_fd, stage_fd):
    # Execute the exact bytes that were checked. No directory fd, credential,
    # supplementary group, or writable checkout is handed to the worker.
    proc = subprocess.Popen(
        [sys.executable, "-I", "-B", "-S", "-c", worker_bytes],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd="/", env={},
        user=65534, group=65534, extra_groups=[], close_fds=True,
    )
    try:
        spent = False
        for target, expected in (("result.json", "ALLOW"), ("forbidden.json", "BLOCK")):
            request = json.loads(bounded_line(proc.stdout))
            verdict, reason = mediate(request, out_fd, stage_fd, spent=spent)
            require(request["target"] == target and verdict == expected, "unexpected request or decision")
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


def main():
    require(sys.platform == "linux" and os.geteuid() == 0 and os.path.ismount(ROOT),
            "use the Colima launcher with its private fixture mount")
    worker = Path(__file__).with_name("worker.py").read_bytes()
    require(hashlib.sha256(worker).hexdigest() == WORKER_SHA256, "unreviewed worker bytes; refusing")
    require(not os.listdir(ROOT), "fixture is not fresh")
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
            with hold_pilot_output(out_fd, descriptor, expected_activation_id=secrets.token_hex(16)) as after:
                exercise(worker, out_fd, stage_fd)
                observation = after()
            # Exact directory entry inventory also rejects a dangling symlink.
            require(os.listdir(out_fd) == ["result.json"] and not os.listdir(stage_fd),
                    "unexpected output or staging residue")
        finally:
            os.close(stage_fd)
    finally:
        os.close(out_fd)
    print("ALLOW result.json — verified bytes:", bytes.fromhex(observation["payload_hex"]).decode("ascii"))
    print("BLOCK forbidden.json — outside grant; direct Linux write: EACCES; verified absent")


def timeout(signum, frame):
    raise TimeoutError("local quickstart exceeded its 15-second execution window")


if __name__ == "__main__":
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(15)
    main()
