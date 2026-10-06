"""One fixed blocked-create invocation in an already active owned common fixture.

This is not setup, activation or measurement collection authority. One fixed
same-action revocation is published only after the local no-retry barrier.
The owner supplies a real plan separately and must stop
and destroy the disposable fixture after retaining the returned public evidence.
Only stdlib is imported before the owned-fixture and installed-source guards.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time

SCHEMA = "aragorn/native-blocked-create-workload/v1"
AUTHORITY = (
    "OWNED_ONCE_ONLY_WORKLOAD_READBACK_NOT_DENIAL_CAUSALITY_OR_COLLECTION_AUTHORITY"
)
SOURCE_PATH = "/opt/aragorn/runtime_native_blocked_create_workload.py"
SINK_SOURCE_PATH = "/usr/lib/aragorn/aragorn/native_phase3_denied_create_sink.py"
REVOCATION_SOURCE_PATH = "/opt/aragorn/runtime_native_blocked_create_revocation.py"
ATTEMPT_ROOT = "/run/aragorn-native-blocked-create-workload"
DRIVER_PATH = "/opt/aragorn/native-blocked-create-driver-v1.mjs"
_NODE = "/usr/local/bin/node"
_INPUT = ATTEMPT_ROOT + "/input.json"
_OUTPUT = ATTEMPT_ROOT + "/output.json"
_TOKEN = "/etc/aragorn/agent-gateway/environment"
_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_MAX_DRIVER = 512 * 1024
_MAX_RECORD = 2 * 1024 * 1024
MAX_RESULT = 32 * 1024 * 1024
_FIXED_SOURCES = {
    "/opt/aragorn/runtime-native-receipt-systemd-check.py": (
        50290,
        "sha256:5d1fc2cb45c1acd6a00b2bc42b7e1068c186e2c7fb00c2502372724f0238d8be",
        0o444,
    ),
    "/opt/aragorn/runtime_native_plugin_package_check.py": (
        24331,
        "sha256:d7b2cc380f25844ded16d471cf0044016623709aa9085e4232d01f46b7bb9df9",
        0o444,
    ),
    "/usr/lib/aragorn/aragorn/native_phase3_common_identity.py": (
        20981,
        "sha256:46aed5e163e490d7f3261930d956c3c8f3ad7dd1775816a4cdf3efc7f5b780a8",
        0o444,
    ),
    "/usr/lib/aragorn/aragorn/native_phase3_live_identity.py": (
        39110,
        "sha256:8a3f69e6ebef3f36d284942b3c9769b69d61025a5d2a563e033c25d804da646a",
        0o444,
    ),
    DRIVER_PATH: (
        16293,
        "sha256:e898ba4ab7b5cbd8742bc36c8e1ae578c7e73f45280aa660afc5815fec386df4",
        0o444,
    ),
    "/src/benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs": (
        39431,
        "sha256:e6e1803e9593d8c1bcb1ad4a3fdf2cb5c3657f1b4bd06e65470b8ad16e9e0140",
        0o555,
    ),
}
FALSE_FLAGS = (
    "activation_performed",
    "service_cleanup_performed",
    "blocked_pre_effect",
    "causal_attribution",
    "transient_effects_excluded",
    "measurement_collected",
    "elapsed_time_derived",
    "route_qualified",
    "run_conformance_eligible",
    "metrics_eligible",
    "phase3_eligible",
    "live_deployment_attested",
)
LIMITATIONS = (
    "REQUIRES_ALREADY_ACTIVE_COMMON_FIXTURE_PUBLISHES_ONE_SAME_ACTION_REVOCATION",
    "LOCAL_ABSENT_ONLY_ATTEMPT_MARKER_NOT_GLOBAL_OR_CROSS_FIXTURE_ANTI_REPLAY",
    "RECEIPT_AFTER_REQUIRES_COMPLETE_TWO_RECORD_CHAIN_NO_PARTIAL_COUNT_RETRY",
    "POINT_IN_TIME_SINK_READBACKS_NOT_TRANSIENT_EFFECT_OR_POLICY_CAUSALITY_PROOF",
    "SELECTED_SOURCE_READBACKS_NOT_LOADED_CODE_OR_COMPLETE_DEPENDENCY_ATTESTATION",
    "CALLER_PINS_REQUIRE_INDEPENDENT_PLAN_DEPLOYMENT_AND_PROCESS_BINDING",
    "OWNING_CONTROLLER_MUST_RETAIN_RESULTS_AND_CLEAN_UP_ALL_FIXTURE_SERVICES",
    "NO_CLOCK_EVENT_MEASUREMENT_COLLECTION_OR_QUALIFICATION_AUTHORITY",
)


class NativeBlockedCreateWorkloadError(ValueError):
    """Only fixed reasons; native diagnostics and credentials are never returned."""


def _require(condition, reason):
    if not condition:
        raise NativeBlockedCreateWorkloadError(reason)


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pin(value):
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "INVALID_SOURCE_OR_EVIDENCE_PIN",
    )
    return value


def _identity(metadata):
    return [
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    ]


def _directory(fd, mode=None):
    value = os.fstat(fd)
    _require(
        stat.S_ISDIR(value.st_mode)
        and value.st_uid == value.st_gid == 0
        and not stat.S_IMODE(value.st_mode) & 0o022
        and (mode is None or stat.S_IMODE(value.st_mode) == mode),
        "ROOT_DIRECTORY_CUSTODY_REFUSED",
    )
    return [value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid]


def _close_all(descriptors):
    primary, failed = sys.exception(), False
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except BaseException:
            failed = True
    if failed:
        if primary is not None:
            primary._workload_cleanup_failures = (
                *getattr(primary, "_workload_cleanup_failures", ()),
                "DESCRIPTOR_CLOSE_REFUSED",
            )
        else:
            raise NativeBlockedCreateWorkloadError("DESCRIPTOR_CLOSE_REFUSED")


@contextmanager
def _ancestry(path):
    descriptors, held = [], []
    try:
        fd = os.open("/", _FLAGS)
        descriptors.append(fd)
        held.append((fd, ".", fd, _directory(fd)))
        for name in Path(path).parts[1:]:
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            child = os.open(name, _FLAGS, dir_fd=fd)
            descriptors.append(child)
            identity = _directory(child)
            _require(
                identity
                == [
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                    before.st_uid,
                    before.st_gid,
                ],
                "ROOT_ANCESTRY_REPLACED",
            )
            held.append((fd, name, child, identity))
            fd = child

        def guard():
            for parent, name, child, expected in held:
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                _require(
                    _directory(child)
                    == expected
                    == [
                        named.st_dev,
                        named.st_ino,
                        named.st_mode,
                        named.st_uid,
                        named.st_gid,
                    ],
                    "ROOT_ANCESTRY_CHANGED",
                )

        guard()
        try:
            yield fd, guard
        finally:
            primary = sys.exception()
            try:
                guard()
            except BaseException:
                if primary is None:
                    raise
                primary._workload_cleanup_failures = (
                    *getattr(primary, "_workload_cleanup_failures", ()),
                    "ANCESTRY_FINAL_GUARD_REFUSED",
                )
    finally:
        _close_all(descriptors)


def _read_at(parent, name, mode, limit):
    descriptors = []
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=parent,
        )
        descriptors.append(fd)
        before = os.fstat(fd)
        expected = _identity(before)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == before.st_gid == 0
            and stat.S_IMODE(before.st_mode) == mode
            and before.st_nlink == 1
            and 0 < before.st_size <= limit,
            "FIXED_FILE_CUSTODY_REFUSED",
        )
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        _require(
            len(raw) == before.st_size <= limit
            and _identity(os.fstat(fd)) == expected
            and _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
            == expected,
            "FIXED_FILE_CHANGED",
        )
        return bytes(raw), {
            "bytes": len(raw),
            "digest": _digest(raw),
            "identity": expected,
        }
    finally:
        _close_all(descriptors)


def _read_fixed(path, mode, limit):
    with _ancestry(str(Path(path).parent)) as (parent, guard):
        result = _read_at(parent, Path(path).name, mode, limit)
        guard()
        return result


def _environment(container):
    _require(
        sys.platform == "linux"
        and os.geteuid() == os.getegid() == 0
        and threading.get_native_id() == os.getpid(),
        "OWNED_LINUX_ROOT_REQUIRED",
    )
    _require(
        type(container) is str and re.fullmatch(r"[0-9a-f]{64}", container) is not None,
        "INVALID_OWNED_CONTAINER",
    )
    descriptors = []
    try:
        fd = os.open("/proc/1/cgroup", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(fd)
        before = os.fstat(fd)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == before.st_gid == 0
            and stat.S_IMODE(before.st_mode) == 0o444
            and before.st_nlink == 1,
            "OWNED_CGROUP_CUSTODY_REFUSED",
        )
        raw = os.read(fd, 1025)
        _require(
            raw == f"0::/docker/{container}/init.scope\n".encode("ascii")
            and _identity(os.fstat(fd)) == _identity(before)
            and _identity(os.stat("/proc/1/cgroup", follow_symlinks=False))
            == _identity(before),
            "EXACT_OWNED_FIXTURE_REQUIRED",
        )
    finally:
        _close_all(descriptors)


def _sources(workload_pin, sink_pin, revocation_pin):
    _require(
        os.path.abspath(__file__) == SOURCE_PATH, "INSTALLED_WORKLOAD_PATH_CHANGED"
    )
    pins = {
        **_FIXED_SOURCES,
        SOURCE_PATH: (None, _pin(workload_pin), 0o444),
        SINK_SOURCE_PATH: (None, _pin(sink_pin), 0o444),
        REVOCATION_SOURCE_PATH: (None, _pin(revocation_pin), 0o444),
    }
    result = {}
    for path, (size, pin, mode) in pins.items():
        raw, metadata = _read_fixed(path, mode, 1024 * 1024)
        _require(
            metadata["digest"] == pin and (size is None or len(raw) == size),
            "FIXED_SOURCE_PIN_CHANGED",
        )
        result[path] = metadata
    return result


def _helpers():
    if not __package__:
        sys.path[:0] = ["/usr/lib/aragorn", "/opt/aragorn"]
        import runtime_native_plugin_package_check as package
        import runtime_native_blocked_create_revocation as revocation
    else:
        from scripts import runtime_native_plugin_package_check as package
        from scripts import runtime_native_blocked_create_revocation as revocation
    from aragorn import native_phase3_common_identity as common
    from aragorn import native_phase3_denied_create_sink as sink

    _require(
        os.path.abspath(package.__file__)
        == "/opt/aragorn/runtime_native_plugin_package_check.py"
        and os.path.abspath(common.__file__)
        == "/usr/lib/aragorn/aragorn/native_phase3_common_identity.py"
        and os.path.abspath(sink.__file__) == SINK_SOURCE_PATH
        and os.path.abspath(revocation.__file__) == REVOCATION_SOURCE_PATH,
        "IMPORTED_HELPER_LOCATION_CHANGED",
    )
    return package._native(), common, sink, revocation


def _record(document, *, raw=None, limit=_MAX_RECORD):
    canonical = _canonical(document)
    _require(raw is None or raw == canonical, "PUBLIC_DOCUMENT_NOT_CANONICAL")
    _require(0 < len(canonical) <= limit, "PUBLIC_RECORD_BOUND_REFUSED")
    return {
        "bytes": len(canonical),
        "digest": _digest(canonical),
        "text": canonical.decode("ascii"),
    }


def _processes(identity, expected):
    _require(
        type(expected) is dict and set(expected) == {"worker", "broker", "gateway"},
        "EXPECTED_PROCESS_INVENTORY_CHANGED",
    )
    for role, pin in expected.items():
        _require(
            type(pin) is dict
            and set(pin) == {"pid", "start_time_ticks", "uid", "gid"}
            and all(type(value) is int and 0 < value < 2**63 for value in pin.values()),
            "EXPECTED_PROCESS_PIN_CHANGED",
        )
        actual = identity["processes"][role]
        _require(
            actual["pid"] == pin["pid"]
            and actual["start_time_ticks"] == pin["start_time_ticks"]
            and actual["uids"] == [pin["uid"]] * 4
            and actual["gids"] == [pin["gid"]] * 4,
            "ACTIVE_PROCESS_PIN_CHANGED",
        )


@contextmanager
def _live_processes(common, identity, container):
    held = []
    process = common.prior.process
    try:
        for role in ("worker", "broker", "sensor", "gateway"):
            record = identity["processes"][role]
            fd = os.pidfd_open(record["pid"], 0)
            held.append(fd)

        def guard():
            _environment(container)
            for fd, role in zip(
                held, ("worker", "broker", "sensor", "gateway"), strict=True
            ):
                record = identity["processes"][role]
                process.require_live_pidfd(fd)
                _require(
                    process._process_start_time(record["pid"])
                    == record["start_time_ticks"]
                    and process._process_cgroup(record["pid"]) == record["cgroup"],
                    "HELD_PROCESS_CHANGED",
                )

        guard()
        try:
            yield guard
        finally:
            primary = sys.exception()
            try:
                guard()
            except BaseException:
                if primary is None:
                    raise
                primary._workload_cleanup_failures = (
                    *getattr(primary, "_workload_cleanup_failures", ()),
                    "HELD_PROCESS_FINAL_GUARD_REFUSED",
                )
    finally:
        _close_all(held)


def _absent(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise NativeBlockedCreateWorkloadError("LOCAL_ATTEMPT_ALREADY_EXISTS")


@contextmanager
def _attempt_files(raw, claim):
    """The retained directory/input are the local no-retry claim, never removed."""
    descriptors = []
    try:
        with _ancestry("/run") as (parent, parent_guard):
            name = Path(ATTEMPT_ROOT).name
            _absent(parent, name)
            os.mkdir(name, 0o700, dir_fd=parent)
            claim["attempt_claimed"] = True
            os.fsync(parent)
            fd = os.open(name, _FLAGS, dir_fd=parent)
            descriptors.append(fd)
            identity = _directory(fd, 0o700)
            input_identity = None

            def guard():
                parent_guard()
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                _require(
                    _directory(fd, 0o700)
                    == identity
                    == [
                        named.st_dev,
                        named.st_ino,
                        named.st_mode,
                        named.st_uid,
                        named.st_gid,
                    ],
                    "LOCAL_ATTEMPT_ROOT_CHANGED",
                )
                retained, metadata = _read_at(fd, "input.json", 0o400, 4096)
                _require(
                    retained == raw and metadata["identity"] == input_identity,
                    "LOCAL_ATTEMPT_INPUT_CHANGED",
                )

            _absent(fd, "input.json")
            _absent(fd, "output.json")
            writer = os.open(
                "input.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o400,
                dir_fd=fd,
            )
            descriptors.append(writer)
            offset = 0
            while offset < len(raw):
                count = os.write(writer, raw[offset:])
                _require(count > 0, "LOCAL_ATTEMPT_WRITE_REFUSED")
                offset += count
            os.fsync(writer)
            os.fsync(fd)
            input_identity = _identity(os.fstat(writer))
            guard()
            try:
                yield fd, guard
            finally:
                primary = sys.exception()
                try:
                    guard()
                except BaseException:
                    if primary is None:
                        raise
                    primary._workload_cleanup_failures = (
                        *getattr(primary, "_workload_cleanup_failures", ()),
                        "ATTEMPT_FINAL_GUARD_REFUSED",
                    )
    finally:
        _close_all(descriptors)


def _input(nonce):
    _require(
        type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce) is not None,
        "INVALID_FIXED_ATTEMPT_NONCE",
    )
    return (
        _canonical(
            {
                "schema": "aragorn/openclaw-worker-driver-input/v1",
                "scenario": {
                    "id": "native-blocked-create-" + nonce,
                    "target_name": "runtime-worker-qualified.txt",
                    "content": "Aragorn P3.7b distinct worker create\n",
                    "expected_result": {
                        "schema": "aragorn/runtime-action-worker-result/v1",
                        "status": "COMPLETED",
                        "broker_result": {
                            "verdict": "BLOCK",
                            "effect_status": "NOT_PERFORMED",
                        },
                    },
                },
            }
        )
        + b"\n"
    )


def _token():
    raw, metadata = _read_fixed(_TOKEN, 0o400, 256)
    match = re.fullmatch(rb"OPENCLAW_GATEWAY_TOKEN=([0-9a-f]{64})\n", raw)
    _require(match is not None, "FIXED_GATEWAY_TOKEN_REFUSED")
    return match.group(1).decode("ascii"), metadata


def _worker_binding(common, pins):
    raw, metadata = _read_fixed(common.prior._WORKER, 0o400, 16384)
    _require(metadata["digest"] == pins[common.prior._WORKER], "WORKER_BINDING_CHANGED")
    document = json.loads(raw)
    _require(_canonical(document) == raw, "WORKER_BINDING_NOT_CANONICAL")
    for name in ("runtime_digest", "policy_digest", "active_skill_digest"):
        _pin(document[name])
    return document


def _blocked_result(document, publication, container):
    _require(
        document.get("schema") == "aragorn/native-blocked-create-tool-driver/v1"
        and document.get("status") == "OBSERVED"
        and document.get("container_id") == container,
        "FIXED_DRIVER_RESULT_CHANGED",
    )
    result = document["source_result"]["document"]
    broker = result["broker_result"]
    decision = broker["decision"]
    published = publication["publication"]["published"]
    raw = published["text"].encode("ascii")
    revocations = json.loads(raw)
    _require(
        _canonical(revocations) == raw
        and len(raw) == published["bytes"]
        and _digest(raw) == published["digest"],
        "REVOCATION_PUBLICATION_CHANGED",
    )
    _require(
        result["status"] == "COMPLETED"
        and broker["verdict"] == "BLOCK"
        and broker["effect_status"] == "NOT_PERFORMED"
        and type(decision) is dict
        and type(decision["reason_codes"]) is list
        and "ACTIVE_SKILL_REVOKED" in decision["reason_codes"]
        and decision["revocation_snapshot_digest"] == published["digest"]
        and decision["revocation_generation"] == revocations["generation"],
        "ACTUAL_SAME_ACTION_REVOCATION_BLOCK_NOT_OBSERVED",
    )


def _invoke(container, token):
    """One subprocess, bounded waiting/output; token never enters argv or report."""
    argv = [_NODE, DRIVER_PATH, "blocked-create", container, _INPUT, _OUTPUT]
    child = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
        cwd="/",
        env={
            "HOME": "/var/lib/aragorn-agent-gateway/home",
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "NO_PROXY": "127.0.0.1,localhost",
            "OPENCLAW_CONFIG_PATH": "/etc/aragorn/agent-gateway/openclaw.json",
            "OPENCLAW_STATE_DIR": "/var/lib/aragorn-agent-gateway/state",
            "OPENCLAW_GATEWAY_TOKEN": token,
            "ARAGORN_MOCK_PROVIDER_TOKEN": token,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TZ": "UTC",
        },
    )
    try:
        deadline = time.monotonic() + 50
        with selectors.DefaultSelector() as selector:
            for stream in (child.stdout, child.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                _require(remaining > 0, "FIXED_DRIVER_TIMEOUT")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 1)
                    _require(not chunk, "FIXED_DRIVER_UNEXPECTED_OUTPUT")
                    selector.unregister(key.fileobj)
        _require(
            child.wait(timeout=max(0.001, deadline - time.monotonic())) == 0,
            "FIXED_DRIVER_REFUSED",
        )
        return {"argv": argv, "exit_code": 0, "stdout_bytes": 0, "stderr_bytes": 0}
    finally:
        primary, failures = sys.exception(), []
        if primary is not None or child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException:
                failures.append("DRIVER_GROUP_TERMINATION_REFUSED")
        for close in (
            child.stdout.close,
            child.stderr.close,
            lambda: child.wait(timeout=3),
        ):
            try:
                close()
            except BaseException:
                failures.append("DRIVER_DESCRIPTOR_OR_REAP_REFUSED")
        if failures:
            if primary is not None:
                primary._workload_cleanup_failures = (
                    *getattr(primary, "_workload_cleanup_failures", ()),
                    *failures,
                )
            else:
                raise NativeBlockedCreateWorkloadError("DRIVER_CLEANUP_REFUSED")


def run_native_blocked_create_workload(
    *,
    expected_container_id,
    expected_genesis_digest,
    expected_path_descriptor,
    expected_sink_source_digest,
    expected_sink_accounts,
    expected_workload_source_digest,
    expected_revocation_source_digest,
    expected_file_digests,
    expected_processes,
    nonce,
):
    """Return exact public records, even on refusal; never retry or activate.

    OBSERVED means these bounded reads completed, not that the independent
    blocked-create verifier or a real measurement collection accepted them.
    An interrupt is re-raised after final reads, with this report attached.
    """
    result = {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "status": "REFUSED",
        "container_id": expected_container_id
        if type(expected_container_id) is str
        and re.fullmatch(r"[0-9a-f]{64}", expected_container_id)
        else None,
        "nonce": nonce
        if type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce)
        else None,
        "source_digest": expected_workload_source_digest
        if type(expected_workload_source_digest) is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", expected_workload_source_digest)
        else None,
        "sources_before": None,
        "sources_after": None,
        "records": {},
        "identity_comparison": None,
        "invocation": None,
        "invocation_count": 0,
        "attempt_claimed": False,
        "revocation": None,
        "revocation_call_count": 0,
        "postcondition_failures": [],
        "refusal": None,
        "sink_failures": [],
        "limitations": list(LIMITATIONS),
        **dict.fromkeys(FALSE_FLAGS, False),
    }
    phase, primary, native, common, sink = "INPUTS", None, None, None, None
    entered, session = False, None

    def retain(name, value, **kwargs):
        result["records"][name] = _record(value, **kwargs)

    def post(label, operation):
        nonlocal primary
        try:
            operation()
        except BaseException as error:
            result["postcondition_failures"].append(label)
            if primary is None and not isinstance(error, Exception):
                primary = error
                result["refusal"] = {"phase": phase, "reason": "FIXED_WORKLOAD_REFUSED"}

    try:
        raw_input = _input(nonce)
        _pin(expected_genesis_digest)
        expected_file_digests = json.loads(_canonical(expected_file_digests))
        expected_processes = json.loads(_canonical(expected_processes))
        expected_path_descriptor = json.loads(_canonical(expected_path_descriptor))
        expected_sink_accounts = json.loads(_canonical(expected_sink_accounts))
        phase = "ENVIRONMENT"
        _environment(expected_container_id)
        phase = "SOURCE_GUARD"
        result["sources_before"] = _sources(
            expected_workload_source_digest,
            expected_sink_source_digest,
            expected_revocation_source_digest,
        )
        native, common, sink, revocation = _helpers()
        phase = "ACTIVE_COMMON_IDENTITY"
        before = common.read_native_common_identity(
            expected_container_id=expected_container_id,
            expected_file_digests=expected_file_digests,
        )
        retain("identity_before", before)
        _processes(before, expected_processes)
        _require(
            expected_file_digests[_NODE]
            == "sha256:3a988781edde7f1c76751f771cf402e0866fb4a81fbcd0852a2ce2f5bd2ccd37"
            and before["files"][common.prior._GENESIS]["digest"]
            == expected_genesis_digest
            and expected_sink_accounts["broker_uid"]
            == expected_processes["broker"]["uid"]
            and expected_sink_accounts["runtime_gid"]
            == expected_processes["broker"]["gid"]
            == expected_processes["worker"]["gid"],
            "COMMON_GENESIS_EXECUTABLE_OR_ACCOUNT_JOIN_CHANGED",
        )
        _require(
            before["measured_joins"]["declared_input_digests_not_cas_readback"][
                "path_digest"
            ]
            == _digest(_canonical(expected_path_descriptor))
            and before["measured_joins"]["declared_input_digests_not_cas_readback"][
                "payload_digest"
            ]
            == _digest(b"Aragorn P3.7b distinct worker create\n"),
            "ACTIVE_ACTION_PATH_OR_PAYLOAD_CHANGED",
        )
        worker_binding = _worker_binding(common, expected_file_digests)
        with _live_processes(common, before, expected_container_id) as live:
            phase = "RECEIPT_BEFORE"
            retain("receipt_before", native._snapshot(expected_genesis_digest, 0))
            phase = "SINK_BEFORE"
            with sink.hold_native_denied_create_sink(
                expected_container_id=expected_container_id,
                expected_path_descriptor=expected_path_descriptor,
                expected_source_digest=expected_sink_source_digest,
                expected_accounts=expected_sink_accounts,
            ) as session:
                entered = True
                retain("sink_before", session.before)
                try:
                    phase = "LOCAL_ATTEMPT_CLAIM"
                    with _attempt_files(raw_input, result) as (
                        directory,
                        attempt_guard,
                    ):
                        result["records"]["driver_input"] = {
                            "bytes": len(raw_input),
                            "digest": _digest(raw_input),
                            "text": raw_input.decode("ascii"),
                        }
                        phase = "PREINVOKE_GUARD"
                        live()
                        _require(
                            _sources(
                                expected_workload_source_digest,
                                expected_sink_source_digest,
                                expected_revocation_source_digest,
                            )
                            == result["sources_before"],
                            "SOURCES_CHANGED_BEFORE_INVOKE",
                        )
                        token, token_metadata = _token()
                        attempt_guard()
                        try:
                            phase = "REVOCATION_PUBLICATION"
                            result["revocation_call_count"] = 1
                            result["revocation"] = (
                                revocation.publish_native_blocked_create_revocation(
                                    expected_container_id=expected_container_id,
                                    expected_policy_digest=worker_binding[
                                        "policy_digest"
                                    ],
                                    expected_runtime_digest=worker_binding[
                                        "runtime_digest"
                                    ],
                                    expected_skill_digest=worker_binding[
                                        "active_skill_digest"
                                    ],
                                    expected_source_digest=expected_revocation_source_digest,
                                    expected_broker_source_digest=expected_file_digests[
                                        "/usr/lib/aragorn/aragorn/runtime_action_broker.py"
                                    ],
                                )
                            )
                            _require(
                                result["revocation"]["status"] == "PUBLISHED",
                                "REVOCATION_PUBLICATION_REFUSED",
                            )
                            phase = "DRIVER"
                            result["invocation_count"] = 1
                            try:
                                result["invocation"] = _invoke(
                                    expected_container_id, token
                                )
                            except BaseException as error:
                                if primary is None:
                                    primary = error
                                raise
                            finally:

                                def output_readback():
                                    raw, _ = _read_at(
                                        directory, "output.json", 0o600, _MAX_DRIVER
                                    )
                                    retain(
                                        "driver",
                                        json.loads(raw),
                                        raw=raw,
                                        limit=_MAX_DRIVER,
                                    )

                                post("DRIVER_OUTPUT_READBACK_REFUSED", output_readback)
                        finally:
                            token = None
                        phase = "DRIVER_READBACK"
                        _blocked_result(
                            json.loads(result["records"]["driver"]["text"]),
                            result["revocation"],
                            expected_container_id,
                        )
                        attempt_guard()
                        _require(
                            _read_fixed(_TOKEN, 0o400, 256)[1] == token_metadata,
                            "FIXED_GATEWAY_TOKEN_CHANGED",
                        )
                except BaseException as error:
                    if primary is None:
                        primary = error
                    raise
                finally:
                    post(
                        "RECEIPT_AFTER_REFUSED",
                        lambda: retain(
                            "receipt_after",
                            native._snapshot(expected_genesis_digest, 2),
                        ),
                    )

                    def sink_after():
                        observation = session.after()
                        retain("sink_after", observation)
                        _require(
                            all(
                                row["empty"] is True
                                and row["scan_complete"] is True
                                and row["entry_count_lower_bound"] == 0
                                for row in observation["directories"].values()
                            )
                            and observation["target"]["status"] == "ABSENT",
                            "FIXED_SINK_AFTER_NOT_EMPTY",
                        )

                    post("SINK_AFTER_REFUSED", sink_after)
                    post("HELD_PROCESS_AFTER_REFUSED", live)
    except BaseException as error:
        if primary is None:
            primary = error
        elif error is not primary:
            result["postcondition_failures"].append("SECONDARY_WORKLOAD_REFUSED")
        if result["revocation"] is None:
            result["revocation"] = getattr(
                error, "_native_blocked_create_revocation", None
            )
        if result["refusal"] is None:
            result["refusal"] = {"phase": phase, "reason": "FIXED_WORKLOAD_REFUSED"}
        result["postcondition_failures"].extend(
            getattr(error, "_workload_cleanup_failures", ())
        )
        result["sink_failures"].extend(getattr(error, "_native_sink_failures", ()))
    finally:
        if session is not None:
            result["sink_failures"].extend(
                reason
                for reason in session.failures
                if reason not in result["sink_failures"]
            )
        if native is not None:

            def identity_after():
                after = common.read_native_common_identity(
                    expected_container_id=expected_container_id,
                    expected_file_digests=expected_file_digests,
                )
                retain("identity_after", after)
                _processes(after, expected_processes)
                if "identity_before" in result["records"]:
                    result["identity_comparison"] = (
                        common.compare_native_common_identity(
                            json.loads(result["records"]["identity_before"]["text"]),
                            after,
                        )
                    )

            post("COMMON_IDENTITY_AFTER_REFUSED", identity_after)
        if result["sources_before"] is not None:

            def sources_after():
                result["sources_after"] = _sources(
                    expected_workload_source_digest,
                    expected_sink_source_digest,
                    expected_revocation_source_digest,
                )
                _require(
                    result["sources_after"] == result["sources_before"],
                    "FINAL_SOURCES_CHANGED",
                )

            post("SOURCES_AFTER_REFUSED", sources_after)
            post(
                "OWNED_FIXTURE_AFTER_REFUSED",
                lambda: _environment(expected_container_id),
            )
    if (
        primary is None
        and entered
        and not result["postcondition_failures"]
        and not result["sink_failures"]
    ):
        result["status"] = "OBSERVED"
    _require(len(_canonical(result)) <= MAX_RESULT, "WORKLOAD_REPORT_BOUND_REFUSED")
    if primary is not None and not isinstance(primary, Exception):
        primary._native_blocked_create_workload = result
        raise primary
    return result
