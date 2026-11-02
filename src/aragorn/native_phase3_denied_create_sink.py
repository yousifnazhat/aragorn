"""Independent fixed-sink readbacks around one caller-owned native attempt.

The session does not activate services, invoke a workload, acquire a measurement
claim, or infer a broker denial. It holds fixed directory descriptors and a
PIDFD for the owned fixture init while taking two bounded observations. An empty
pair does not rule out transient effects between those observations.
"""

from __future__ import annotations

from contextlib import contextmanager
import grp
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import threading

from . import native_phase3_live_identity as protected
from . import runtime_process_profile as process
from .oci_worker_protocol import canonical_json

SCHEMA = "aragorn/native-denied-create-sink/v1"
AUTHORITY = "LOCAL_HELD_DIRECTORY_READBACK_NOT_EFFECT_OR_CAUSALITY_PROOF"
SOURCE_PATH = "/usr/lib/aragorn/aragorn/native_phase3_denied_create_sink.py"
PROTECTED_PATH = "/var/lib/aragorn-runtime-action/protected"
STAGING_PATH = "/var/lib/aragorn-runtime-action/staging"
TARGET_NAME = "runtime-worker-qualified.txt"
FALSE_FLAGS = (
    "blocked_pre_effect",
    "causal_attribution",
    "transient_effects_excluded",
    "route_qualified",
    "run_conformance_eligible",
    "metrics_eligible",
    "phase3_eligible",
    "live_deployment_attested",
)
LIMITATIONS = (
    "POINT_IN_TIME_DIRECTORY_AND_TARGET_READS_NOT_CONTINUOUS_EFFECT_MONITORING",
    "FIXED_PROTECTED_AND_STAGING_ROOTS_ONLY_NOT_WORKSPACE_OR_GLOBAL_RESIDUE",
    "ROOT_LOCAL_READBACK_NOT_HOSTILE_ROOT_RESISTANT_OR_EXTERNAL_ATTESTATION",
    "NO_EFFECT_POLICY_CAUSALITY_REQUEST_ATTRIBUTION_OR_QUALIFICATION",
)
_ACCOUNT_KEYS = {"broker_uid", "broker_gid", "runtime_gid"}
_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_LIMIT = 1024 * 1024


class NativeDeniedCreateSinkError(ValueError):
    """A fixed custody refusal, never a claim of successful prevention."""


def _require(value: bool, reason: str) -> None:
    if not value:
        raise NativeDeniedCreateSinkError(reason)


def _integer(value: object, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value < 2**63


def _inputs(container: str, descriptor: dict, source: str, accounts: dict) -> None:
    _require(
        type(container) is str
        and re.fullmatch(r"[0-9a-f]{64}", container) is not None
        and type(source) is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", source) is not None,
        "INVALID_FIXED_SINK_IDENTITY",
    )
    _require(
        type(descriptor) is dict
        and set(descriptor) == {"schema", "root_device", "root_inode", "target_name"}
        and descriptor["schema"] == "aragorn/runtime-protected-path/v1"
        and descriptor["target_name"] == TARGET_NAME
        and _integer(descriptor["root_device"])
        and _integer(descriptor["root_inode"], 1),
        "INVALID_FIXED_SINK_DESCRIPTOR",
    )
    _require(
        type(accounts) is dict
        and set(accounts) == _ACCOUNT_KEYS
        and all(
            type(value) is int and 0 < value < 2**32 for value in accounts.values()
        ),
        "INVALID_FIXED_SINK_ACCOUNTS",
    )


def _accounts() -> dict:
    return {
        "broker_uid": pwd.getpwnam("aragorn-broker").pw_uid,
        "broker_gid": grp.getgrnam("aragorn-broker").gr_gid,
        "runtime_gid": grp.getgrnam("aragorn-runtime").gr_gid,
    }


def _environment(container: str, collector: int) -> None:
    _require(
        sys.platform == "linux"
        and os.geteuid() == os.getegid() == 0
        and os.getpid() == threading.get_native_id() == collector,
        "SAME_LINUX_ROOT_COLLECTOR_REQUIRED",
    )
    _require(
        process._read_virtual_file(Path("/proc/1/cgroup"), 1024)
        == f"0::/docker/{container}/init.scope\n".encode("ascii"),
        "EXACT_OWNED_FIXTURE_REQUIRED",
    )


def _directory(fd: int, owner: tuple[int, int], mode: int | None) -> tuple:
    item = os.fstat(fd)
    _require(
        stat.S_ISDIR(item.st_mode)
        and item.st_nlink >= 1
        and (item.st_uid, item.st_gid) == owner
        and not stat.S_IMODE(item.st_mode) & 0o022
        and bool(stat.S_IMODE(item.st_mode) & 0o100)
        and (mode is None or stat.S_IMODE(item.st_mode) == mode),
        "FIXED_SINK_DIRECTORY_CUSTODY_CHANGED",
    )
    return protected.broker._directory_identity(item)


def _empty(fd: int) -> dict:
    # Inspect at most one entry. No attacker-controlled name or content escapes.
    expected = protected.broker._directory_identity(os.fstat(fd))
    scan = os.open(".", _FLAGS, dir_fd=fd)
    try:
        _require(
            protected.broker._directory_identity(os.fstat(scan)) == expected,
            "SINK_SCAN_DIRECTORY_CHANGED",
        )
        # A fresh open file description avoids a shared/reused directory offset.
        with os.scandir(scan) as entries:
            empty = next(entries, None) is None
        _require(
            expected
            == protected.broker._directory_identity(os.fstat(scan))
            == protected.broker._directory_identity(os.fstat(fd))
            == protected.broker._directory_identity(
                os.stat(".", dir_fd=fd, follow_symlinks=False)
            ),
            "SINK_SCAN_DIRECTORY_CHANGED",
        )
        return {
            "empty": empty,
            "scan_complete": empty,
            "entry_count_lower_bound": 0 if empty else 1,
        }
    finally:
        primary = sys.exception()
        failures = _close_all([scan])
        if failures:
            if primary is not None:
                primary._native_sink_failures = (
                    *getattr(primary, "_native_sink_failures", ()),
                    *failures,
                )
            else:
                raise NativeDeniedCreateSinkError("SINK_SCAN_CLOSE_REFUSED") from None


def _target(fd: int) -> dict:
    try:
        item = os.stat(TARGET_NAME, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return {"name": TARGET_NAME, "status": "ABSENT", "identity": None}
    return {
        "name": TARGET_NAME,
        "status": "PRESENT",
        "identity": list(protected.broker._file_identity(item)),
    }


def _source(root: int, expected: str) -> dict:
    raw, metadata = protected._read_at(
        root, SOURCE_PATH, owner=0, owner_gid=0, modes={0o444}, limit=_LIMIT
    )
    _require(protected._digest(raw) == expected, "SINK_OBSERVER_SOURCE_CHANGED")
    return metadata


def _close_all(descriptors: list[int]) -> list[str]:
    failures = []
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except BaseException:
            failures.append("SINK_DESCRIPTOR_CLOSE_REFUSED")
    return failures


class _Session:
    def __init__(self, container, descriptor, source, accounts, root, leaves, guard):
        self._container = container
        self._descriptor = dict(descriptor)
        self._source = source
        self._accounts = dict(accounts)
        self._root = root
        self._leaves = dict(leaves)
        self._guard = guard
        self._closed = False
        self._after_used = False
        self._source_identity = None
        self.before = None
        self.after_observation = None
        self.failures = []

    def _observe(self, phase: str) -> dict:
        _require(not self._closed, "SINK_SESSION_CLOSED")
        self._guard()
        source = _source(self._root, self._source)
        directories = {}
        for role, path in (("protected", PROTECTED_PATH), ("staging", STAGING_PATH)):
            fd = self._leaves[role]
            directories[role] = {
                "path": path,
                "identity": list(protected.broker._directory_identity(os.fstat(fd))),
                **_empty(fd),
            }
        target = _target(self._leaves["protected"])
        self._guard()
        _require(
            _source(self._root, self._source) == source, "SINK_SOURCE_CUSTODY_CHANGED"
        )
        if phase == "AFTER":
            _require(
                tuple(source["identity"]) == self._source_identity,
                "SINK_SOURCE_CUSTODY_CHANGED",
            )
        else:
            self._source_identity = tuple(source["identity"])
        result = {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "phase": phase,
            "container_id": self._container,
            "observer_source_digest": self._source,
            "observer_source": source,
            "path_descriptor": dict(self._descriptor),
            "accounts": dict(self._accounts),
            "directories": directories,
            "target": target,
            "limitations": list(LIMITATIONS),
            **dict.fromkeys(FALSE_FLAGS, False),
        }
        _require(len(canonical_json(result)) <= 16384, "SINK_OBSERVATION_BOUND_REFUSED")
        return result

    def after(self) -> dict:
        """Take the second observation once; a failed observation cannot retry."""
        _require(
            not self._closed and not self._after_used and self.before is not None,
            "SINK_AFTER_NOT_ONCE",
        )
        self._after_used = True
        try:
            self.after_observation = self._observe("AFTER")
            return self.after_observation
        except BaseException:
            self.failures.append("SINK_AFTER_REFUSED")
            raise


@contextmanager
def hold_native_denied_create_sink(
    *,
    expected_container_id: str,
    expected_path_descriptor: dict,
    expected_source_digest: str,
    expected_accounts: dict,
):
    """Hold one fixed sink session; never execute or retry the caller's attempt.

    The caller may invoke ``session.after()`` in its own finally block. If not,
    context cleanup attempts it once and leaves its value in
    ``session.after_observation``. A primary workload exception is preserved if
    final observation or descriptor cleanup also fails. Missing/failed after
    evidence is not success and remains visible in ``session.failures``.
    """
    _inputs(
        expected_container_id,
        expected_path_descriptor,
        expected_source_digest,
        expected_accounts,
    )
    descriptor, accounts = dict(expected_path_descriptor), dict(expected_accounts)
    descriptors, held, leaves = [], [], {}
    session = None
    guard = None
    try:
        collector = os.getpid()
        _environment(expected_container_id, collector)
        _require(_accounts() == accounts, "FIXED_SINK_ACCOUNT_LOOKUP_CHANGED")
        init_start = process._process_start_time(1)
        _require(_integer(init_start, 1), "INVALID_FIXTURE_INIT_EPOCH")
        init_pidfd = os.pidfd_open(1, 0)
        descriptors.append(init_pidfd)
        process.require_live_pidfd(init_pidfd)
        root = os.open("/", _FLAGS)
        descriptors.append(root)
        held.append((root, ".", root, _directory(root, (0, 0), None), (0, 0), None))

        def child(parent, name, owner, mode):
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            fd = os.open(name, _FLAGS, dir_fd=parent)
            descriptors.append(fd)
            identity = _directory(fd, owner, mode)
            _require(
                identity == protected.broker._directory_identity(before),
                "SINK_DIRECTORY_REPLACED",
            )
            held.append((parent, name, fd, identity, owner, mode))
            return fd

        var = child(root, "var", (0, 0), None)
        lib = child(var, "lib", (0, 0), None)
        parent = child(lib, "aragorn-runtime-action", (0, 0), 0o755)
        leaves["protected"] = child(
            parent,
            "protected",
            (accounts["broker_uid"], accounts["runtime_gid"]),
            0o710,
        )
        leaves["staging"] = child(
            parent, "staging", (accounts["broker_uid"], accounts["broker_gid"]), 0o700
        )
        protected_id = os.fstat(leaves["protected"])
        staging_id = os.fstat(leaves["staging"])
        _require(
            (protected_id.st_dev, protected_id.st_ino)
            == (descriptor["root_device"], descriptor["root_inode"])
            and protected_id.st_dev == staging_id.st_dev
            and protected_id.st_ino != staging_id.st_ino,
            "SINK_DESCRIPTOR_OR_FILESYSTEM_CHANGED",
        )

        def guard():
            _environment(expected_container_id, collector)
            process.require_live_pidfd(init_pidfd)
            _require(
                process._process_start_time(1) == init_start
                and _accounts() == accounts,
                "FIXTURE_INIT_OR_ACCOUNTS_CHANGED",
            )
            for parent, name, fd, identity, owner, mode in held:
                _require(
                    identity
                    == _directory(fd, owner, mode)
                    == protected.broker._directory_identity(
                        os.stat(name, dir_fd=parent, follow_symlinks=False)
                    ),
                    "SINK_HELD_DIRECTORY_REPLACED",
                )

        session = _Session(
            expected_container_id,
            descriptor,
            expected_source_digest,
            accounts,
            root,
            leaves,
            guard,
        )
        session.before = session._observe("BEFORE")
        _require(
            all(row["empty"] is True for row in session.before["directories"].values())
            and session.before["target"]["status"] == "ABSENT",
            "FIXED_SINK_NOT_FRESH",
        )
        yield session
    finally:
        primary = sys.exception()
        failures = list(session.failures) if session is not None else []
        if (
            session is not None
            and session.before is not None
            and not session._after_used
        ):
            try:
                session.after()
            except BaseException:
                failures.append("SINK_AFTER_REFUSED")
        if guard is not None:
            try:
                guard()
            except BaseException:
                failures.append("SINK_FINAL_CUSTODY_REFUSED")
        if session is not None and session.before is not None:
            try:
                metadata = _source(session._root, session._source)
                _require(
                    tuple(metadata["identity"]) == session._source_identity,
                    "SINK_SOURCE_CUSTODY_CHANGED",
                )
            except BaseException:
                failures.append("SINK_FINAL_SOURCE_REFUSED")
        failures.extend(_close_all(descriptors))
        if session is not None:
            session._closed = True
            session.failures.extend(
                reason for reason in failures if reason not in session.failures
            )
        if failures:
            if primary is not None:
                primary._native_sink_failures = (
                    *getattr(primary, "_native_sink_failures", ()),
                    *failures,
                )
            else:
                raise NativeDeniedCreateSinkError(
                    "SINK_FINAL_READBACK_OR_CLEANUP_REFUSED"
                ) from None
