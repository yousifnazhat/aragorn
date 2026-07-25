"""Run, authenticate, and compose the frozen Phase 0 comparator batch."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from aragorn.benchmark_authenticated_handoff_v2 import (
    collect_signed_worker_output,
    load_verified_worker_output_acceptance,
)
from aragorn.benchmark_protocol_v2 import (
    canonical_request_digest_v2,
    validate_worker_request_v2,
)
from aragorn.benchmark_worker_measurement import load_worker_trust_store
from aragorn.cas import CAS, CASError
from aragorn.label_blind_prepare import validate_worker_worklist
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase0_candidate import (
    candidate_implementation_digest,
    compose_candidate_batch,
)
from scripts.freeze_hidden_suite import (
    FreezeError,
    _decode_json,
    _lexical_absolute,
    _read,
    _reject_symlink_components,
    _require_private_directory,
)
from scripts.prepare_hidden_suite import (
    _FREEZE_RECEIPT_PATH,
    _LOCK_PATH,
    _PREPARATION_RECEIPT_PATH,
    _git,
    _state_paths,
    validate_retained_preparation_receipt,
)

_EXPECTED_JOBS = 896
_EXPECTED_OUTCOMES = 1_344
_TRUST_DOMAIN = "phase0.hidden-independent-v1.0.0"
_WORKER_ID = "isolated-worker-01"
_MAX_JSON = 128 * 1024 * 1024
_MAX_ENVELOPE = 256 * 1024
_MAX_COMMAND_OUTPUT = 8 * 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_JOB_ID = re.compile(r"[0-9a-f]{32}\Z")
_CHALLENGE = re.compile(r"[0-9a-f]{64}\Z")
_VM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_GUEST_PATH = re.compile(r"/[A-Za-z0-9._/-]{1,4095}\Z")
_ATTEMPT = re.compile(r"job-([0-9]{6})-attempt-([0-9]{4})\Z")
_RETURN = re.compile(r"return-([0-9]{6})-copy-([0-9]{4})\Z")
_CISCO_IMAGE = "aragorn/cisco-skill-scanner:2.0.12"
_NVIDIA_IMAGE = "aragorn/skillspector:2.4.3-a54947c"
_IMAGE_IDS = {
    _CISCO_IMAGE: "sha256:f06e307a2765d2ecd389fc8c706bd991f2ab5a47be6cb88caf69f48971a8b72b",
    _NVIDIA_IMAGE: "sha256:21de7549ea44da85465c854e26f776f87454a6fca6a92e817bbceb58b25d4468",
}
_PYTHON_EXECUTABLE_DIGEST = (
    "001718d5edf61e6fbc3642c9668def38d2bf28cc320e75196e6a95d49614cca8"
)
_SYSTEM_PYTHON_EXECUTABLE_DIGEST = (
    "d7dc1ef6da10929a8bb44e1e3f1d666b83fa746f92db9c50f889e4c747c6dc26"
)
_DOCKER_EXECUTABLE_DIGEST = (
    "242d23ba3267159f5eca1a2d89db77ddbf86dc552827e1059bcb878e2ecb005d"
)
_BASELINE_LOCK_DIGEST = (
    "f8ce11cba91d3557bd15192c44c5eb64b8db13568c63b2df260ef4004dafc83b"
)
_RUNTIME_DISTRIBUTIONS = (
    '[["cffi","2.1.0"],["cryptography","49.0.0"],["pycparser","3.0"]]'
)
_RUNTIME_CLOSURE_DIGEST = (
    "sha256:b93a776f874b105dd7d7a8c63b2797a85aa83c297237fffadc6ea7e92ad93edf"
)


class ExecutionError(ValueError):
    """The authenticated hidden worker batch could not complete safely."""


@dataclass(frozen=True)
class Job:
    ordinal: int
    job_id: str
    request_digest: str
    challenge: str
    input_manifest_digest: str
    input_bundle: Path


def _execute(
    executable: Path,
    arguments: Sequence[str],
    *,
    label: str,
    timeout: int,
    maximum: int = _MAX_COMMAND_OUTPUT,
) -> bytes:
    environment = {
        "HOME": os.environ["HOME"],
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/opt/homebrew/bin:/usr/bin:/bin",
    }
    if "LIMA_HOME" in os.environ:
        environment["LIMA_HOME"] = os.environ["LIMA_HOME"]
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        process = subprocess.Popen(
            [os.fspath(executable), *arguments],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        if process.stdout is None or process.stderr is None:
            raise OSError("subprocess pipes unavailable")
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            ready = selector.select(remaining)
            if not ready:
                raise TimeoutError
            for key, _events in ready:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                output = captured[key.data]
                if len(output) + len(chunk) > maximum:
                    raise ExecutionError(f"{label} failed")
                output.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        returncode = process.wait(timeout=remaining)
    except ExecutionError:
        raise
    except (OSError, subprocess.TimeoutExpired, TimeoutError) as exc:
        raise ExecutionError(f"{label} could not complete") from exc
    finally:
        selector.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait()
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
    if returncode != 0:
        raise ExecutionError(f"{label} failed")
    return bytes(captured["stdout"])


def _resolve_executable(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    metadata = os.lstat(resolved)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
    ):
        raise ExecutionError(f"{label} must be a non-writable executable")
    return resolved


def _limactl(
    executable: Path,
    arguments: Sequence[str],
    *,
    label: str,
    timeout: int = 300,
    maximum: int = _MAX_COMMAND_OUTPUT,
) -> bytes:
    return _execute(
        executable,
        arguments,
        label=label,
        timeout=timeout,
        maximum=maximum,
    )


def _guest_command(
    limactl: Path,
    vm: str,
    script: str,
    arguments: Sequence[str],
    *,
    label: str,
    timeout: int = 300,
) -> bytes:
    return _limactl(
        limactl,
        ["shell", vm, "--", "bash", "-c", script, "aragorn-hidden", *arguments],
        label=label,
        timeout=timeout,
    )


def _canonical_document(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    raw = _read(path, max_bytes=_MAX_JSON)
    document = _decode_json(raw, label)
    if canonical_json(document) != raw:
        raise ExecutionError(f"{label} must use canonical JSON bytes")
    return document, raw


def _private_root(path: Path, label: str) -> Path:
    _reject_symlink_components(path, label)
    if not os.path.lexists(path):
        try:
            os.mkdir(path, mode=0o700)
        except OSError as exc:
            raise ExecutionError(f"cannot create {label}") from exc
    _require_private_directory(path, label)
    return path


def _separate(paths: Sequence[Path]) -> None:
    resolved = [path.resolve(strict=False) for path in paths]
    for index, left in enumerate(resolved):
        for right in resolved[index + 1 :]:
            if (
                left == right
                or left.is_relative_to(right)
                or right.is_relative_to(left)
            ):
                raise ExecutionError("worker controller security boundaries overlap")


def _controller_lock(run_state_root: Path) -> int:
    path = run_state_root / ".worker-controller.lock"
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ExecutionError("worker controller lock is not protected")
        os.fchmod(descriptor, 0o600)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o600:
            raise ExecutionError("worker controller lock is not protected")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except ExecutionError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except (BlockingIOError, OSError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ExecutionError("another hidden worker controller is active") from exc


def _validate_staging_root(staging_root: Path) -> None:
    for path in staging_root.iterdir():
        metadata = os.lstat(path)
        if (
            _RETURN.fullmatch(path.name) is None
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ExecutionError("worker return root contains an unsafe entry")


def _load_preparation() -> tuple[dict[str, object], bytes, str]:
    preparation, raw = _canonical_document(
        ROOT / _PREPARATION_RECEIPT_PATH,
        "hidden preparation receipt",
    )
    hidden_lock, _lock_raw = _canonical_document(
        ROOT / _LOCK_PATH,
        "hidden suite lock",
    )
    freeze_receipt, _freeze_raw = _canonical_document(
        ROOT / _FREEZE_RECEIPT_PATH,
        "hidden freeze receipt",
    )
    validate_retained_preparation_receipt(
        preparation,
        raw,
        hidden_lock,
        freeze_receipt,
    )
    source_digest = candidate_implementation_digest()
    candidates = [
        system for system in hidden_lock["systems"] if system.get("name") == "aragorn"
    ]
    if (
        len(candidates) != 1
        or candidates[0].get("implementation_digest") != source_digest
    ):
        raise ExecutionError("signed candidate source identity changed")
    return preparation, raw, source_digest


def _directory_names(path: Path, label: str) -> set[str]:
    try:
        entries = list(path.iterdir())
    except OSError as exc:
        raise ExecutionError(f"cannot inspect {label}") from exc
    names: set[str] = set()
    for entry in entries:
        metadata = os.lstat(entry)
        if stat.S_ISLNK(metadata.st_mode) or entry.name in names:
            raise ExecutionError(f"{label} contains an unsafe entry")
        names.add(entry.name)
    return names


def _manifest_digest(path: Path) -> str:
    raw = _read(path, max_bytes=80)
    try:
        digest = raw.decode("ascii").removesuffix("\n")
    except UnicodeDecodeError as exc:
        raise ExecutionError("input manifest digest is not ASCII") from exc
    if raw != digest.encode("ascii") + b"\n" or _DIGEST.fullmatch(digest) is None:
        raise ExecutionError("input manifest digest is malformed")
    return digest


def _load_jobs(
    *,
    jobs_root: Path,
    ledger_root: Path,
    preparation: dict[str, object],
) -> list[Job]:
    worklist, _worklist_raw = _canonical_document(
        jobs_root / "worklist.json",
        "worker worklist",
    )
    validate_worker_worklist(worklist)
    if (
        canonical_digest(worklist) != preparation["preparation"]["worklist_digest"]
        or len(worklist["jobs"]) != _EXPECTED_JOBS
        or preparation["matrix"]["job_count"] != _EXPECTED_JOBS
    ):
        raise ExecutionError("worker worklist does not match signed preparation")
    expected_job_entries = {
        "worklist.json",
        *(entry["job_id"] for entry in worklist["jobs"]),
    }
    if _directory_names(jobs_root, "jobs root") != expected_job_entries:
        raise ExecutionError("jobs root does not match the signed worklist")

    jobs: list[Job] = []
    expected_issuances: set[str] = set()
    seen_jobs: set[str] = set()
    seen_challenges: set[str] = set()
    for ordinal, entry in enumerate(worklist["jobs"], start=1):
        job_id = entry["job_id"]
        request_digest = entry["request_digest"]
        if (
            _JOB_ID.fullmatch(job_id) is None
            or _DIGEST.fullmatch(request_digest) is None
            or job_id in seen_jobs
        ):
            raise ExecutionError("worker worklist identity is invalid")
        seen_jobs.add(job_id)
        job_root = jobs_root / job_id
        if _directory_names(job_root, "worker job") != {
            "input-bundle",
            "input-manifest-digest.txt",
            "request.json",
        }:
            raise ExecutionError("worker job layout changed")
        request_raw = _read(job_root / "request.json", max_bytes=64 * 1024)
        request = _decode_json(request_raw, "worker request")
        if canonical_json(request) != request_raw:
            raise ExecutionError("worker request is not canonical")
        validate_worker_request_v2(request)
        challenge = request["verifier_challenge"]
        if (
            request["job_id"] != job_id
            or canonical_request_digest_v2(request) != request_digest
            or _CHALLENGE.fullmatch(challenge) is None
            or challenge in seen_challenges
        ):
            raise ExecutionError("worker request changed its worklist binding")
        seen_challenges.add(challenge)
        input_bundle = job_root / "input-bundle"
        if not input_bundle.is_dir() or input_bundle.is_symlink():
            raise ExecutionError("worker input bundle is not a real directory")
        jobs.append(
            Job(
                ordinal=ordinal,
                job_id=job_id,
                request_digest=request_digest,
                challenge=challenge,
                input_manifest_digest=_manifest_digest(
                    job_root / "input-manifest-digest.txt"
                ),
                input_bundle=input_bundle,
            )
        )
        expected_issuances.add(f"{challenge}.json")

    issuance_root = ledger_root / "issuances"
    receipt_root = ledger_root / "receipts"
    if _directory_names(issuance_root, "challenge issuances") != expected_issuances:
        raise ExecutionError("challenge issuance set changed")
    receipts = _directory_names(receipt_root, "acceptance receipts")
    if not receipts.issubset(expected_issuances):
        raise ExecutionError("acceptance receipt set contains an unknown challenge")
    for job in jobs:
        issuance, _raw = _canonical_document(
            issuance_root / f"{job.challenge}.json",
            "challenge issuance",
        )
        if issuance != {
            "schema": "aragorn/benchmark-worker-measurement-issuance/v1",
            "trust_domain": _TRUST_DOMAIN,
            "worker_id": _WORKER_ID,
            "job_id": job.job_id,
            "request_digest": job.request_digest,
            "verifier_challenge": job.challenge,
        }:
            raise ExecutionError("challenge issuance changed its worker binding")
    return jobs


def _worker_binding(
    preparation: dict[str, object],
    trust_store_path: Path,
) -> str:
    trust_store = load_worker_trust_store(trust_store_path)
    keys = trust_store["keys"]
    if (
        canonical_digest(trust_store) != preparation["worker"]["trust_store_digest"]
        or trust_store["trust_domain"] != _TRUST_DOMAIN
        or len(keys) != 1
        or keys[0]["worker_id"] != _WORKER_ID
        or keys[0]["key_id"] != preparation["worker"]["key_id"]
        or keys[0]["status"] != "active"
    ):
        raise ExecutionError("worker trust store does not match signed preparation")
    return keys[0]["key_id"]


def _vm_preflight(
    *,
    limactl: Path,
    vm: str,
    guest_source: str,
    guest_python: str,
    guest_signing_key: str,
    guest_execution_root: str,
    expected_source_digest: str,
) -> None:
    raw = _limactl(
        limactl,
        ["list", "--json", vm],
        label="Lima instance inspection",
        timeout=30,
    )
    try:
        instance = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExecutionError("Lima instance metadata is malformed") from exc
    config = instance.get("config")
    ssh = config.get("ssh") if isinstance(config, dict) else None
    if (
        instance.get("name") != vm
        or instance.get("status") != "Running"
        or instance.get("protected") is not True
        or instance.get("arch") != "aarch64"
        or not isinstance(config, dict)
        or config.get("mounts") is not None
        or not isinstance(ssh, dict)
        or ssh.get("forwardAgent") is not False
        or ssh.get("loadDotSSHPubKeys") is not False
    ):
        raise ExecutionError("Lima worker isolation metadata changed")

    script = r"""
set -euo pipefail
umask 077
source_root=$1
python=$2
signing_key=$3
execution_root=$4
source_digest=$5
python_digest=$6
runtime_distributions=$7
docker_digest=$8
baseline_digest=$9
system_python_digest=${10}
runtime_digest=${11}
runtime_root=${python%/venv/bin/python}
system_python=/usr/bin/python3
test -z "$(findmnt -rn -t virtiofs,9p,fuse.sshfs || true)"
test "$(docker context show)" = rootless
docker info --format '{{json .SecurityOptions}}' | grep -q rootless
docker=$(command -v docker)
test "$(sha256sum "$docker" | cut -d ' ' -f1)" = "$docker_digest"
test "$(sha256sum "$system_python" | cut -d ' ' -f1)" = "$system_python_digest"
test "$(docker image inspect "${12}" --format '{{.Id}}')" = "${13}"
test "$(docker image inspect "${14}" --format '{{.Id}}')" = "${15}"
test -d "$source_root"
test ! -L "$source_root"
test "$(readlink -f "$source_root")" = "$source_root"
test -d "$runtime_root"
test ! -L "$runtime_root"
test "$(readlink -f "$runtime_root")" = "$runtime_root"
case "$(readlink -f "$python")" in
  "$runtime_root"/*) ;;
  *) exit 5 ;;
esac
test "$(stat -c '%U:%G' "$source_root")" = root:root
test "$(stat -c '%U:%G' "$runtime_root")" = root:root
test -z "$(find "$source_root" "$runtime_root" \( -type f -o -type d \) ! -user root -print -quit)"
test -z "$(find "$source_root" "$runtime_root" \( -type f -o -type d \) -perm /0222 -print -quit)"
while IFS= read -r -d '' link; do
  case "$(readlink -f "$link")" in
    "$runtime_root"/*) ;;
    *) exit 5 ;;
  esac
done < <(find "$runtime_root" -type l -print0)
test -f "$source_root/src/aragorn/worker_supervisor_v2.py"
test ! -L "$source_root/src/aragorn"
test -f "$source_root/benchmark/baselines.lock.json"
test ! -L "$source_root/benchmark/baselines.lock.json"
test -x "$python"
test "$("$python" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')" = 3.12.13
test "$(sha256sum "$(readlink -f "$python")" | cut -d ' ' -f1)" = "$python_digest"
test "$(PYTHONDONTWRITEBYTECODE=1 "$python" -c \
  'import importlib.metadata as m,json; print(json.dumps(sorted((d.metadata["Name"].lower(),d.version) for d in m.distributions()),separators=(",",":")))')" = "$runtime_distributions"
test "$(sha256sum "$source_root/benchmark/baselines.lock.json" | cut -d ' ' -f1)" = "$baseline_digest"
actual_source=$("$system_python" -I -S - "$source_root" <<'PY'
import hashlib
from pathlib import Path
import stat
import sys

root = Path(sys.argv[1])
src_root = root / "src"
source = src_root / "aragorn"
if (
    src_root.is_symlink()
    or not src_root.is_dir()
    or [path.name for path in src_root.iterdir()] != ["aragorn"]
):
    raise SystemExit(5)
entries = list(source.rglob("*"))
if any(
    path.is_symlink()
    or (
        not path.is_dir()
        and (not path.is_file() or path.suffix != ".py")
    )
    for path in entries
):
    raise SystemExit(5)
paths = sorted(
    (path for path in entries if path.is_file()),
    key=lambda path: path.relative_to(source).as_posix(),
)
digest = hashlib.sha256(b"aragorn-python-source-and-lock-closure/v1\0")
for path in paths:
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SystemExit(5)
    relative = path.relative_to(source).as_posix().encode()
    content = path.read_bytes()
    digest.update(len(relative).to_bytes(4, "big"))
    digest.update(relative)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)
lock = root / "requirements-worker.lock"
metadata = lock.lstat()
if (
    lock.is_symlink()
    or not stat.S_ISREG(metadata.st_mode)
    or metadata.st_nlink != 1
):
    raise SystemExit(5)
content = lock.read_bytes()
name = b"requirements-worker.lock"
digest.update(len(name).to_bytes(4, "big"))
digest.update(name)
digest.update(len(content).to_bytes(8, "big"))
digest.update(content)
if not paths:
    raise SystemExit(5)
print("sha256:" + digest.hexdigest())
PY
)
test "$actual_source" = "$source_digest"
actual_runtime=$("$system_python" -I -S - "$runtime_root" <<'PY'
import hashlib
import os
from pathlib import Path
import stat
import sys

root = Path(sys.argv[1])
digest = hashlib.sha256(b"aragorn-guest-runtime-closure/v1\0")
entries = sorted(
    root.rglob("*"),
    key=lambda path: path.relative_to(root).as_posix(),
)
for path in entries:
    relative = path.relative_to(root).as_posix().encode()
    metadata = path.lstat()
    if stat.S_ISREG(metadata.st_mode):
        kind = b"f"
        payload = path.read_bytes()
    elif stat.S_ISDIR(metadata.st_mode):
        kind = b"d"
        payload = b""
    elif stat.S_ISLNK(metadata.st_mode):
        kind = b"l"
        target = os.readlink(path)
        if os.path.isabs(target):
            try:
                target = "@ROOT/" + Path(target).relative_to(root).as_posix()
            except ValueError:
                pass
        payload = os.fsencode(target)
    else:
        raise SystemExit(5)
    digest.update(len(relative).to_bytes(4, "big"))
    digest.update(relative)
    digest.update(kind)
    digest.update(stat.S_IMODE(metadata.st_mode).to_bytes(4, "big"))
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
digest.update(len(entries).to_bytes(8, "big"))
print("sha256:" + digest.hexdigest())
PY
)
test "$actual_runtime" = "$runtime_digest"
test "$(stat -c '%a:%s:%h' "$signing_key")" = "600:32:1"
if test ! -e "$execution_root"; then
  mkdir -m 700 "$execution_root"
fi
test "$(stat -c '%a:%U' "$execution_root")" = "700:$(id -un)"
flock -n "$execution_root/.worker.lock" true
printf 'ok\n'
"""
    output = _guest_command(
        limactl,
        vm,
        script,
        [
            guest_source,
            guest_python,
            guest_signing_key,
            guest_execution_root,
            expected_source_digest,
            _PYTHON_EXECUTABLE_DIGEST,
            _RUNTIME_DISTRIBUTIONS,
            _DOCKER_EXECUTABLE_DIGEST,
            _BASELINE_LOCK_DIGEST,
            _SYSTEM_PYTHON_EXECUTABLE_DIGEST,
            _RUNTIME_CLOSURE_DIGEST,
            _CISCO_IMAGE,
            _IMAGE_IDS[_CISCO_IMAGE],
            _NVIDIA_IMAGE,
            _IMAGE_IDS[_NVIDIA_IMAGE],
        ],
        label="guest worker preflight",
        timeout=60,
    )
    if output != b"ok\n":
        raise ExecutionError("guest worker preflight output changed")


def _guest_attempts(
    *,
    limactl: Path,
    vm: str,
    guest_execution_root: str,
    ordinal: int,
) -> tuple[str | None, int]:
    ordinal_text = f"{ordinal:06d}"
    script = r"""
set -euo pipefail
root=$1
ordinal=$2
prefix="job-${ordinal}-attempt-"
for path in "$root"/"$prefix"*; do
  test -e "$path" || continue
  test -d "$path"
  name=${path##*/}
  case "$name" in
    "$prefix"[0-9][0-9][0-9][0-9]) ;;
    *) exit 5 ;;
  esac
  if test -d "$path/output-bundle" && test -f "$path/measurement.dsse.json"; then
    printf 'complete\t%s\n' "$name"
  else
    printf 'partial\t%s\n' "$name"
  fi
done
"""
    raw = _guest_command(
        limactl,
        vm,
        script,
        [guest_execution_root, ordinal_text],
        label="guest attempt inspection",
        timeout=30,
    )
    return _parse_guest_attempts(raw, ordinal)


def _parse_guest_attempts(raw: bytes, ordinal: int) -> tuple[str | None, int]:
    complete: list[str] = []
    highest = 0
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ExecutionError("guest attempt inventory is malformed") from exc
    for line in lines:
        try:
            status_text, name = line.split("\t")
        except ValueError as exc:
            raise ExecutionError("guest attempt inventory is malformed") from exc
        match = _ATTEMPT.fullmatch(name)
        if (
            match is None
            or int(match.group(1)) != ordinal
            or status_text not in {"complete", "partial"}
        ):
            raise ExecutionError("guest attempt inventory changed")
        highest = max(highest, int(match.group(2)))
        if status_text == "complete":
            complete.append(name)
    if complete:
        return min(complete), highest + 1
    if highest >= 9_999:
        raise ExecutionError("guest attempt limit reached")
    return None, highest + 1


def _create_guest_attempt(
    *,
    limactl: Path,
    vm: str,
    guest_execution_root: str,
    name: str,
    input_bundle: Path,
) -> None:
    script = r"""
set -euo pipefail
umask 077
root=$1
name=$2
job="$root/$name"
test ! -e "$job"
mkdir -m 700 "$job"
mkdir -m 700 "$job/workspace"
"""
    _guest_command(
        limactl,
        vm,
        script,
        [guest_execution_root, name],
        label="guest attempt creation",
        timeout=30,
    )
    _limactl(
        limactl,
        [
            "copy",
            "--backend=scp",
            "--recursive",
            os.fspath(input_bundle),
            f"{vm}:{guest_execution_root}/{name}/",
        ],
        label="worker input transfer",
        timeout=300,
    )


def _run_worker(
    *,
    limactl: Path,
    vm: str,
    guest_source: str,
    guest_python: str,
    guest_signing_key: str,
    guest_execution_root: str,
    attempt_name: str,
    job: Job,
    key_id: str,
) -> dict[str, object]:
    script = r"""
set -euo pipefail
source_root=$1
python=$2
signing_key=$3
execution_root=$4
attempt=$5
manifest_digest=$6
request_digest=$7
challenge=$8
key_id=$9
job="$execution_root/$attempt"
docker=$(command -v docker)
site_packages="${python%/bin/python}/lib/python3.12/site-packages"
flock -n "$execution_root/.worker.lock" \
  "$python" -I -S -B -c \
    'import runpy,sys; source=sys.argv.pop(1); packages=sys.argv.pop(1); sys.path[:0]=[source,packages]; runpy.run_module("aragorn.worker_supervisor_v2",run_name="__main__")' \
    "$source_root/src" "$site_packages" run \
    --input-bundle "$job/input-bundle" \
    --input-manifest-digest "$manifest_digest" \
    --request-digest "$request_digest" \
    --expected-challenge "$challenge" \
    --input-state "$job/input-state" \
    --output-state "$job/output-state" \
    --output-bundle "$job/output-bundle" \
    --measurement-output "$job/measurement.dsse.json" \
    --signing-key "$signing_key" \
    --worker-id isolated-worker-01 \
    --trust-domain phase0.hidden-independent-v1.0.0 \
    --key-id "$key_id" \
    --lock "$source_root/benchmark/baselines.lock.json" \
    --docker "$docker" \
    --workspace-root "$job/workspace"
"""
    raw = _guest_command(
        limactl,
        vm,
        script,
        [
            guest_source,
            guest_python,
            guest_signing_key,
            guest_execution_root,
            attempt_name,
            job.input_manifest_digest,
            job.request_digest,
            job.challenge,
            key_id,
        ],
        label=f"worker execution ordinal {job.ordinal}",
        timeout=240,
    )
    if not raw.endswith(b"\n"):
        raise ExecutionError("worker supervisor output is malformed")
    document = _decode_json(raw[:-1], "worker supervisor result")
    if canonical_json(document) != raw[:-1]:
        raise ExecutionError("worker supervisor result is not canonical")
    if (
        document.get("schema") != "aragorn/benchmark-worker-supervisor-result/v1"
        or document.get("request_digest") != job.request_digest
    ):
        raise ExecutionError("worker supervisor result changed its request binding")
    return document


def _host_returns(staging_root: Path, ordinal: int) -> tuple[Path | None, int]:
    complete: list[Path] = []
    highest = 0
    for path in staging_root.iterdir():
        match = _RETURN.fullmatch(path.name)
        if match is None:
            raise ExecutionError("worker return root contains an unknown entry")
        if int(match.group(1)) != ordinal:
            continue
        if path.is_symlink() or not path.is_dir():
            raise ExecutionError("worker return staging contains an unsafe entry")
        highest = max(highest, int(match.group(2)))
        if _directory_names(path, "worker return staging") == {
            "measurement.dsse.json",
            "output-bundle",
        }:
            complete.append(path)
    if complete:
        return min(complete), highest + 1
    if highest >= 9_999:
        raise ExecutionError("worker return copy limit reached")
    return None, highest + 1


def _tighten_return(path: Path) -> None:
    for directory, directories, files in os.walk(path, followlinks=False):
        current = Path(directory)
        if current.is_symlink():
            raise ExecutionError("worker return contains a symlink")
        os.chmod(current, 0o700)
        for name in directories:
            child = current / name
            if child.is_symlink():
                raise ExecutionError("worker return contains a symlink")
        for name in files:
            child = current / name
            metadata = os.lstat(child)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ExecutionError("worker return contains an unsafe file")
            os.chmod(child, 0o600)


def _copy_worker_return(
    *,
    limactl: Path,
    vm: str,
    guest_execution_root: str,
    attempt_name: str,
    staging_root: Path,
    ordinal: int,
    copy_number: int,
) -> Path:
    destination = staging_root / (f"return-{ordinal:06d}-copy-{copy_number:04d}")
    try:
        os.mkdir(destination, mode=0o700)
    except OSError as exc:
        raise ExecutionError("cannot create worker return staging") from exc
    _limactl(
        limactl,
        [
            "copy",
            "--backend=scp",
            "--recursive",
            (f"{vm}:{guest_execution_root}/{attempt_name}/output-bundle"),
            (f"{vm}:{guest_execution_root}/{attempt_name}/measurement.dsse.json"),
            os.fspath(destination),
        ],
        label="worker output transfer",
        timeout=300,
    )
    _tighten_return(destination)
    if _directory_names(destination, "worker return staging") != {
        "measurement.dsse.json",
        "output-bundle",
    }:
        raise ExecutionError("worker return transfer is incomplete")
    return destination


def _validate_acceptance(
    *,
    acceptance: dict[str, object],
    job: Job,
    preparation: dict[str, object],
    supervisor: dict[str, object] | None = None,
) -> None:
    receipt = acceptance["receipt"]
    if (
        receipt["trust_store_digest"] != preparation["worker"]["trust_store_digest"]
        or receipt["key_id"] != preparation["worker"]["key_id"]
        or receipt["trust_domain"] != _TRUST_DOMAIN
        or receipt["worker_id"] != _WORKER_ID
        or receipt["job_id"] != job.job_id
        or receipt["request_digest"] != job.request_digest
        or receipt["verifier_challenge"] != job.challenge
    ):
        raise ExecutionError("worker acceptance changed its signed preparation binding")
    if supervisor is not None and (
        supervisor["request_digest"] != receipt["request_digest"]
        or supervisor["result_digest"] != receipt["result_digest"]
        or supervisor["handoff_manifest_digest"] != receipt["handoff_manifest_digest"]
        or supervisor["envelope_digest"] != receipt["envelope_digest"]
    ):
        raise ExecutionError("worker acceptance differs from supervisor output")


def _collect(
    *,
    job: Job,
    staged: Path,
    destination: CAS,
    trust_store_path: Path,
    ledger_root: Path,
    preparation: dict[str, object],
    supervisor: dict[str, object] | None,
) -> dict[str, object]:
    envelope = _read(
        staged / "measurement.dsse.json",
        max_bytes=_MAX_ENVELOPE,
    )
    receipt = collect_signed_worker_output(
        staged / "output-bundle",
        destination,
        envelope,
        trust_store_path=trust_store_path,
        ledger_root=ledger_root,
        verifier_challenge=job.challenge,
    )
    accepted = load_verified_worker_output_acceptance(
        destination,
        ledger_root,
        job.challenge,
    )
    if accepted["receipt"] != receipt:
        raise ExecutionError("retained worker acceptance differs after replay")
    _validate_acceptance(
        acceptance=accepted,
        job=job,
        preparation=preparation,
        supervisor=supervisor,
    )
    return accepted


def _cleanup_ordinal(
    *,
    limactl: Path,
    vm: str,
    guest_execution_root: str,
    staging_root: Path,
    ordinal: int,
) -> None:
    ordinal_text = f"{ordinal:06d}"
    script = r"""
set -euo pipefail
root=$1
ordinal=$2
prefix="job-${ordinal}-attempt-"
for path in "$root"/"$prefix"*; do
  test -e "$path" || continue
  name=${path##*/}
  case "$name" in
    "$prefix"[0-9][0-9][0-9][0-9]) rm -rf -- "$path" ;;
    *) exit 5 ;;
  esac
done
"""
    _guest_command(
        limactl,
        vm,
        script,
        [guest_execution_root, ordinal_text],
        label="verified guest attempt cleanup",
        timeout=60,
    )
    for path in list(staging_root.iterdir()):
        match = _RETURN.fullmatch(path.name)
        if match is not None and int(match.group(1)) == ordinal:
            if path.is_symlink() or not path.is_dir():
                raise ExecutionError("unsafe worker return prevents cleanup")
            shutil.rmtree(path)


def _retain_exact(path: Path, raw: bytes, *, mode: int, label: str) -> None:
    stage = path.with_name(f".{path.name}.staging")
    parent_descriptor = -1
    stage_descriptor = -1
    stage_owned = False
    try:
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        if os.path.lexists(stage):
            staged = os.lstat(stage)
            if (
                not stat.S_ISREG(staged.st_mode)
                or staged.st_uid != os.geteuid()
                or stat.S_IMODE(staged.st_mode) != mode
                or staged.st_nlink not in {1, 2}
            ):
                raise ExecutionError(f"staged {label} is not protected")
            if staged.st_nlink == 2:
                if not os.path.lexists(path):
                    raise ExecutionError(f"staged {label} link is not recoverable")
                retained = os.lstat(path)
                if (
                    not stat.S_ISREG(retained.st_mode)
                    or retained.st_dev != staged.st_dev
                    or retained.st_ino != staged.st_ino
                ):
                    raise ExecutionError(f"staged {label} link is not recoverable")
            os.unlink(stage.name, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)

        if os.path.lexists(path):
            metadata = os.lstat(path)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != mode
                or metadata.st_nlink != 1
            ):
                raise ExecutionError(f"retained {label} is not protected")
            existing = _read(path, max_bytes=_MAX_JSON)
            if existing != raw:
                raise ExecutionError(f"retained {label} differs")
            return

        stage_descriptor = os.open(
            stage.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            mode,
            dir_fd=parent_descriptor,
        )
        stage_owned = True
        with os.fdopen(stage_descriptor, "wb", closefd=True) as stream:
            stage_descriptor = -1
            stream.write(raw)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.fsync(stream.fileno())
        os.link(
            stage.name,
            path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        os.unlink(stage.name, dir_fd=parent_descriptor)
        stage_owned = False
        os.fsync(parent_descriptor)
    except OSError as exc:
        raise ExecutionError(f"cannot retain {label}") from exc
    finally:
        if stage_descriptor >= 0:
            os.close(stage_descriptor)
        if parent_descriptor >= 0:
            try:
                if stage_owned:
                    os.unlink(stage.name, dir_fd=parent_descriptor)
            finally:
                os.close(parent_descriptor)


def _write_outcomes(path: Path, outcomes: list[dict[str, object]]) -> bytes:
    raw = b"".join(canonical_json(outcome) + b"\n" for outcome in outcomes)
    _retain_exact(path, raw, mode=0o600, label="composed outcomes")
    return raw


def _retain_cas_document(
    destination: CAS,
    document: dict[str, object],
    *,
    label: str,
) -> str:
    raw = canonical_json(document)
    digest = canonical_digest(document)
    if (
        destination.put_expected(
            BytesIO(raw),
            expected_digest=digest,
            max_bytes=len(raw),
        )
        != digest
        or destination.read(digest, max_bytes=len(raw)) != raw
    ):
        raise ExecutionError(f"{label} was not retained exactly")
    return digest


def _runner_commit() -> str:
    try:
        commit = (
            _git(["rev-parse", "--verify", "HEAD^{commit}"]).decode("ascii").strip()
        )
    except UnicodeDecodeError as exc:
        raise ExecutionError("runner commit identity is malformed") from exc
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ExecutionError("runner commit identity is malformed")
    return commit


def _run_receipt(
    *,
    runner_commit: str,
    preparation: dict[str, object],
    preparation_raw: bytes,
    acceptance_set_digest: str,
    result_set_digest: str,
    composition_digest: str,
    outcomes_digest: str,
    outcomes_file_digest: str,
) -> dict[str, object]:
    return {
        "schema": "aragorn/benchmark-phase0-hidden-worker-run-receipt/v1",
        "assurance": (
            "authenticated_complete_worker_batch_not_independent_or_hardware_attested"
        ),
        "source": {
            "runner_commit": runner_commit,
            "preparation_receipt_digest": (
                "sha256:" + hashlib.sha256(preparation_raw).hexdigest()
            ),
        },
        "state": {
            "layout": "phase0-hidden-run-state/v1",
            "binding_digest": preparation["state"]["binding_digest"],
        },
        "batch": {
            "accepted_count": _EXPECTED_JOBS,
            "acceptance_set_digest": acceptance_set_digest,
            "result_set_digest": result_set_digest,
        },
        "composition": {
            "composition_digest": composition_digest,
            "outcomes_digest": outcomes_digest,
            "outcomes_file_digest": outcomes_file_digest,
            "outcome_count": _EXPECTED_OUTCOMES,
        },
        "limitations": {
            "authorship": ("technical_codex_authorship_not_independent_human_identity"),
            "custody": (
                "software_signatures_operator_uid_trusted_not_same_uid_or_hardware_attested"
            ),
            "worker_attestation": (
                "software_key_possession_not_vm_or_hardware_attestation"
            ),
        },
    }


def _validate_run_receipt(
    receipt: dict[str, object],
    raw: bytes,
    *,
    runner_commit: str,
    preparation: dict[str, object],
    preparation_raw: bytes,
    run_state_root: Path,
) -> None:
    if raw != canonical_json(receipt) or _runner_commit() != runner_commit:
        raise ExecutionError("worker run receipt source binding changed")
    current_preparation, current_raw, _source_digest = _load_preparation()
    if current_preparation != preparation or current_raw != preparation_raw:
        raise ExecutionError("worker run receipt preparation binding changed")

    state_paths = _state_paths(run_state_root)
    for label, path in state_paths.items():
        _reject_symlink_components(path, label)
    jobs_root = state_paths["jobs_root"]
    ledger_root = state_paths["challenge_ledger"]
    control_root = state_paths["control_state"]
    outcomes_path = state_paths["outcomes"]
    for path, label in (
        (jobs_root, "jobs root"),
        (ledger_root, "challenge ledger"),
        (control_root, "control state"),
    ):
        _require_private_directory(path, label)
    jobs = _load_jobs(
        jobs_root=jobs_root,
        ledger_root=ledger_root,
        preparation=preparation,
    )
    expected_receipts = {f"{job.challenge}.json" for job in jobs}
    receipt_root = ledger_root / "receipts"
    if _directory_names(receipt_root, "acceptance receipts") != expected_receipts:
        raise ExecutionError("worker run receipt acceptance matrix changed")

    control = CAS(control_root, read_only=True)
    acceptances = []
    for job in jobs:
        acceptance = load_verified_worker_output_acceptance(
            control,
            ledger_root,
            job.challenge,
        )
        _validate_acceptance(
            acceptance=acceptance,
            job=job,
            preparation=preparation,
        )
        acceptances.append(acceptance)
    receipt_digests = sorted(
        canonical_digest(acceptance["receipt"]) for acceptance in acceptances
    )
    result_digests = sorted(
        acceptance["receipt"]["result_digest"] for acceptance in acceptances
    )
    if (
        len(set(receipt_digests)) != _EXPECTED_JOBS
        or len(set(result_digests)) != _EXPECTED_JOBS
    ):
        raise ExecutionError("worker run receipt digest sets changed")
    acceptance_set = {
        "schema": "aragorn/benchmark-acceptance-digest-set/v1",
        "digests": receipt_digests,
    }
    result_set = {
        "schema": "aragorn/benchmark-result-digest-set/v1",
        "digests": result_digests,
    }
    acceptance_set_digest = canonical_digest(acceptance_set)
    result_set_digest = canonical_digest(result_set)
    if control.read(acceptance_set_digest, max_bytes=_MAX_JSON) != canonical_json(
        acceptance_set
    ) or control.read(result_set_digest, max_bytes=_MAX_JSON) != canonical_json(
        result_set
    ):
        raise ExecutionError("worker run receipt digest-set retention changed")

    composition = compose_candidate_batch(
        dispatch_digest=preparation["preparation"]["dispatch_digest"],
        control_state=control_root,
        challenge_ledger=ledger_root,
    )
    composition_digest = canonical_digest(composition)
    if (
        control.read(composition_digest, max_bytes=_MAX_JSON)
        != canonical_json(composition)
        or len(composition["outcomes"]) != _EXPECTED_OUTCOMES
        or composition["outcomes_digest"] != canonical_digest(composition["outcomes"])
    ):
        raise ExecutionError("worker run receipt composition changed")
    metadata = os.lstat(outcomes_path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise ExecutionError("worker run receipt outcomes file is not protected")
    outcomes_raw = _read(outcomes_path, max_bytes=_MAX_JSON)
    expected_outcomes_raw = b"".join(
        canonical_json(outcome) + b"\n" for outcome in composition["outcomes"]
    )
    if outcomes_raw != expected_outcomes_raw:
        raise ExecutionError("worker run receipt outcomes replay changed")

    expected = _run_receipt(
        runner_commit=runner_commit,
        preparation=preparation,
        preparation_raw=preparation_raw,
        acceptance_set_digest=acceptance_set_digest,
        result_set_digest=result_set_digest,
        composition_digest=composition_digest,
        outcomes_digest=composition["outcomes_digest"],
        outcomes_file_digest=("sha256:" + hashlib.sha256(outcomes_raw).hexdigest()),
    )
    if receipt != expected:
        raise ExecutionError("worker run receipt semantic binding changed")


def run(
    *,
    limactl_path: Path,
    vm: str,
    guest_source: str,
    guest_python: str,
    guest_signing_key: str,
    guest_execution_root: str,
    run_state_root: Path,
    verifier_root: Path,
    staging_root: Path,
    progress_every: int,
) -> dict[str, object]:
    if _VM_NAME.fullmatch(vm) is None:
        raise ExecutionError("Lima instance name is invalid")
    for value in (
        guest_source,
        guest_python,
        guest_signing_key,
        guest_execution_root,
    ):
        if (
            _GUEST_PATH.fullmatch(value) is None
            or os.path.normpath(value) != value
            or ".." in Path(value).parts
        ):
            raise ExecutionError("guest path is invalid")
    runtime_suffix = "/venv/bin/python"
    if not guest_python.endswith(runtime_suffix):
        raise ExecutionError("guest Python path does not identify the locked runtime")
    guest_boundaries = [
        Path(guest_source),
        Path(guest_python.removesuffix(runtime_suffix)),
        Path(guest_signing_key),
        Path(guest_execution_root),
    ]
    for index, left in enumerate(guest_boundaries):
        for right in guest_boundaries[index + 1 :]:
            if (
                left == right
                or left.is_relative_to(right)
                or right.is_relative_to(left)
            ):
                raise ExecutionError("guest worker security boundaries overlap")
    if not 1 <= progress_every <= _EXPECTED_JOBS:
        raise ExecutionError("progress interval is outside its bound")

    _reject_symlink_components(run_state_root, "run state root")
    _require_private_directory(run_state_root, "run state root")
    state_paths = _state_paths(run_state_root)
    for label, path in state_paths.items():
        _reject_symlink_components(path, label)
    _require_private_directory(verifier_root, "verifier root")
    preparation, preparation_raw, source_digest = _load_preparation()
    runner_commit = _runner_commit()
    _separate((ROOT, run_state_root, verifier_root, staging_root))
    staging_root = _private_root(staging_root, "worker return root")
    lock_descriptor = _controller_lock(run_state_root)
    try:
        _validate_staging_root(staging_root)
        jobs_root = state_paths["jobs_root"]
        ledger_root = state_paths["challenge_ledger"]
        control_root = state_paths["control_state"]
        outcomes_path = state_paths["outcomes"]
        for path, label in (
            (jobs_root, "jobs root"),
            (ledger_root, "challenge ledger"),
            (control_root, "control state"),
        ):
            _require_private_directory(path, label)
        trust_store_path = verifier_root / "worker-trust-store.json"
        key_id = _worker_binding(preparation, trust_store_path)
        jobs = _load_jobs(
            jobs_root=jobs_root,
            ledger_root=ledger_root,
            preparation=preparation,
        )
        destination = CAS(control_root)
        acceptances: list[dict[str, object]] = []
        receipt_root = ledger_root / "receipts"
        limactl: Path | None = None

        for job in jobs:
            receipt_path = receipt_root / f"{job.challenge}.json"
            supervisor: dict[str, object] | None = None
            if os.path.lexists(receipt_path):
                accepted = load_verified_worker_output_acceptance(
                    destination,
                    ledger_root,
                    job.challenge,
                )
                _validate_acceptance(
                    acceptance=accepted,
                    job=job,
                    preparation=preparation,
                )
            else:
                staged, copy_number = _host_returns(staging_root, job.ordinal)
                if staged is None:
                    if limactl is None:
                        limactl = _resolve_executable(limactl_path, "limactl")
                        _vm_preflight(
                            limactl=limactl,
                            vm=vm,
                            guest_source=guest_source,
                            guest_python=guest_python,
                            guest_signing_key=guest_signing_key,
                            guest_execution_root=guest_execution_root,
                            expected_source_digest=source_digest,
                        )
                    attempt_name, attempt_number = _guest_attempts(
                        limactl=limactl,
                        vm=vm,
                        guest_execution_root=guest_execution_root,
                        ordinal=job.ordinal,
                    )
                    if attempt_name is None:
                        attempt_name = (
                            f"job-{job.ordinal:06d}-attempt-{attempt_number:04d}"
                        )
                        _create_guest_attempt(
                            limactl=limactl,
                            vm=vm,
                            guest_execution_root=guest_execution_root,
                            name=attempt_name,
                            input_bundle=job.input_bundle,
                        )
                        supervisor = _run_worker(
                            limactl=limactl,
                            vm=vm,
                            guest_source=guest_source,
                            guest_python=guest_python,
                            guest_signing_key=guest_signing_key,
                            guest_execution_root=guest_execution_root,
                            attempt_name=attempt_name,
                            job=job,
                            key_id=key_id,
                        )
                    staged = _copy_worker_return(
                        limactl=limactl,
                        vm=vm,
                        guest_execution_root=guest_execution_root,
                        attempt_name=attempt_name,
                        staging_root=staging_root,
                        ordinal=job.ordinal,
                        copy_number=copy_number,
                    )
                accepted = _collect(
                    job=job,
                    staged=staged,
                    destination=destination,
                    trust_store_path=trust_store_path,
                    ledger_root=ledger_root,
                    preparation=preparation,
                    supervisor=supervisor,
                )
                if limactl is not None:
                    _cleanup_ordinal(
                        limactl=limactl,
                        vm=vm,
                        guest_execution_root=guest_execution_root,
                        staging_root=staging_root,
                        ordinal=job.ordinal,
                    )
            acceptances.append(accepted)
            if job.ordinal % progress_every == 0 or job.ordinal == len(jobs):
                print(
                    json.dumps(
                        {
                            "schema": "aragorn/benchmark-worker-progress/v1",
                            "accepted": job.ordinal,
                            "total": len(jobs),
                        },
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                    flush=True,
                )

        expected_receipts = {f"{job.challenge}.json" for job in jobs}
        if _directory_names(receipt_root, "acceptance receipts") != expected_receipts:
            raise ExecutionError("authenticated acceptance matrix is incomplete")
        receipt_digests = sorted(
            canonical_digest(acceptance["receipt"]) for acceptance in acceptances
        )
        result_digests = sorted(
            acceptance["receipt"]["result_digest"] for acceptance in acceptances
        )
        if (
            len(set(receipt_digests)) != _EXPECTED_JOBS
            or len(set(result_digests)) != _EXPECTED_JOBS
        ):
            raise ExecutionError("authenticated worker digest sets are incomplete")
        acceptance_set_digest = _retain_cas_document(
            destination,
            {
                "schema": "aragorn/benchmark-acceptance-digest-set/v1",
                "digests": receipt_digests,
            },
            label="acceptance digest set",
        )
        result_set_digest = _retain_cas_document(
            destination,
            {
                "schema": "aragorn/benchmark-result-digest-set/v1",
                "digests": result_digests,
            },
            label="result digest set",
        )
        composition = compose_candidate_batch(
            dispatch_digest=preparation["preparation"]["dispatch_digest"],
            control_state=control_root,
            challenge_ledger=ledger_root,
        )
        outcomes = composition["outcomes"]
        if (
            composition["suite_digest"] != preparation["preparation"]["suite_digest"]
            or composition["dispatch_digest"]
            != preparation["preparation"]["dispatch_digest"]
            or composition["policy_digest"]
            != preparation["preparation"]["candidate_policy_digest"]
            or composition["outcomes_digest"] != canonical_digest(outcomes)
            or len(outcomes) != _EXPECTED_OUTCOMES
            or len({canonical_digest(outcome) for outcome in outcomes})
            != _EXPECTED_OUTCOMES
        ):
            raise ExecutionError("candidate composition does not close the matrix")
        composition_digest = canonical_digest(composition)
        if destination.read(composition_digest, max_bytes=_MAX_JSON) != canonical_json(
            composition
        ):
            raise ExecutionError("candidate composition was not retained exactly")
        outcomes_raw = _write_outcomes(outcomes_path, outcomes)
        retained_preparation, retained_raw, retained_source = _load_preparation()
        if (
            retained_preparation != preparation
            or retained_raw != preparation_raw
            or retained_source != source_digest
            or _runner_commit() != runner_commit
        ):
            raise ExecutionError("signed runner state changed during worker execution")
        receipt = _run_receipt(
            runner_commit=runner_commit,
            preparation=preparation,
            preparation_raw=preparation_raw,
            acceptance_set_digest=acceptance_set_digest,
            result_set_digest=result_set_digest,
            composition_digest=composition_digest,
            outcomes_digest=composition["outcomes_digest"],
            outcomes_file_digest=("sha256:" + hashlib.sha256(outcomes_raw).hexdigest()),
        )
        receipt_raw = canonical_json(receipt)
        _validate_run_receipt(
            receipt,
            receipt_raw,
            runner_commit=runner_commit,
            preparation=preparation,
            preparation_raw=preparation_raw,
            run_state_root=run_state_root,
        )
        receipt_digest = _retain_cas_document(
            destination,
            receipt,
            label="worker run receipt",
        )
        receipt_path = verifier_root / "worker-run-receipt.json"
        _retain_exact(
            receipt_path,
            receipt_raw,
            mode=0o400,
            label="worker run receipt",
        )
        retained_receipt, retained_receipt_raw = _canonical_document(
            receipt_path,
            "worker run receipt",
        )
        if (
            retained_receipt != receipt
            or retained_receipt_raw != receipt_raw
            or canonical_digest(retained_receipt) != receipt_digest
        ):
            raise ExecutionError("worker run receipt replay changed")
        _validate_run_receipt(
            retained_receipt,
            retained_receipt_raw,
            runner_commit=runner_commit,
            preparation=preparation,
            preparation_raw=preparation_raw,
            run_state_root=run_state_root,
        )
        return receipt
    finally:
        os.close(lock_descriptor)


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ExecutionError(message)


def _parser() -> ArgumentParser:
    parser = ArgumentParser()
    parser.add_argument(
        "--limactl",
        type=Path,
        default=Path("/opt/homebrew/bin/limactl"),
    )
    parser.add_argument("--vm", required=True)
    parser.add_argument("--guest-source", required=True)
    parser.add_argument("--guest-python", required=True)
    parser.add_argument("--guest-signing-key", required=True)
    parser.add_argument("--guest-execution-root", required=True)
    parser.add_argument("--run-state-root", type=Path, required=True)
    parser.add_argument("--verifier-root", type=Path, required=True)
    parser.add_argument("--staging-root", type=Path, required=True)
    parser.add_argument("--progress-every", type=int, default=10)
    return parser


def _error_record(exc: BaseException) -> dict[str, str]:
    return {
        "schema": "aragorn/error/v1",
        "error": (
            "execution_failed"
            if isinstance(exc, ExecutionError)
            else "validation_failed"
        ),
        "message": "hidden worker controller failed",
    }


def main() -> int:
    try:
        arguments = _parser().parse_args()
        result = run(
            limactl_path=_lexical_absolute(arguments.limactl),
            vm=arguments.vm,
            guest_source=arguments.guest_source,
            guest_python=arguments.guest_python,
            guest_signing_key=arguments.guest_signing_key,
            guest_execution_root=arguments.guest_execution_root,
            run_state_root=_lexical_absolute(arguments.run_state_root),
            verifier_root=_lexical_absolute(arguments.verifier_root),
            staging_root=_lexical_absolute(arguments.staging_root),
            progress_every=arguments.progress_every,
        )
    except (
        ExecutionError,
        CASError,
        FreezeError,
        KeyError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        print(json.dumps(_error_record(exc), sort_keys=True), file=sys.stderr)
        return 4
    sys.stdout.buffer.write(canonical_json(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
