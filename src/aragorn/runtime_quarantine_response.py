"""Private installed-digest denial plus fixed-profile stop composition.

No CLI or deployment hook exposes this composition. Successor producers,
runtime service overlays and mandatory startup enforcement must be deployed
together before claiming quarantine enforcement. This check measures installed
bytes and the running worker binding, not bytes consumed by a process.
"""

from __future__ import annotations

import fcntl
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from . import runtime_response_service as response
from . import runtime_skill_startup as startup
from .oci_worker_protocol import canonical_digest
from .protected_skill_quarantine import publish_quarantine_at


class RuntimeQuarantineError(RuntimeError):
    """Refused before attempting denial publication or stopping services."""


class RuntimeQuarantineIndeterminate(RuntimeQuarantineError):
    """A denial may persist; complete stop, masking or retention is unconfirmed."""


def _require_root() -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeQuarantineError("root Linux execution is required")


@contextmanager
def _installed_guard() -> Iterator[tuple[int, list[startup._HeldEntry]]]:
    root_fd = -1
    locked = False
    entries: list[startup._HeldEntry] = []
    try:
        root_fd = startup._open_protected_root(
            startup._PROTECTED_ROOT, startup._EXPECTED_INSTALL_UID
        )
        before = os.fstat(root_fd)
        fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
        entries.append(
            startup._HeldEntry(None, startup._PROTECTED_ROOT, root_fd, before)
        )
        startup._check_entries(entries)
        yield root_fd, entries
    finally:
        failure = response.broker._release_lock_and_close(
            root_fd, locked, *(entry.fd for entry in entries if entry.fd != root_fd)
        )
        if failure is not None:
            raise RuntimeQuarantineError(
                "installed response cleanup failed"
            ) from failure


def _recheck_installed(
    root_fd: int,
    entries: list[startup._HeldEntry],
    record: dict[str, Any],
    active_before: os.stat_result,
) -> None:
    transaction = record["transaction"]
    active = startup._active_link(
        root_fd,
        transaction["destination"]["target_name"],
        transaction["version_path"],
        startup._EXPECTED_INSTALL_UID,
    )
    if response.broker._file_identity(active) != response.broker._file_identity(
        active_before
    ):
        raise RuntimeQuarantineError("active installed link changed before response")
    startup._check_entries(entries)
    startup._require_safe_ancestry(
        startup._PROTECTED_ROOT.parent, startup._EXPECTED_INSTALL_UID
    )
    if startup._PROTECTED_ROOT.resolve(strict=True) != startup._PROTECTED_ROOT:
        raise RuntimeQuarantineError("installed response root is not canonical")


def _refresh_published_root(
    root_fd: int,
    entries: list[startup._HeldEntry],
    expected_names: set[str],
    *,
    new_record: bool,
) -> None:
    # Some filesystems also count regular directory entries in st_nlink. A new
    # marker may add one; idempotent publication must retain the count. Keep all
    # immutable file baselines, exact names, and the root's custody identity.
    before = entries[0].before
    current = os.fstat(root_fd)
    named = os.lstat(startup._PROTECTED_ROOT)
    if (
        response.broker._directory_identity(before)
        != response.broker._directory_identity(current)
        or current.st_nlink not in {before.st_nlink, before.st_nlink + int(new_record)}
        or response.broker._file_identity(current)
        != response.broker._file_identity(named)
        or set(os.listdir(root_fd)) != expected_names
    ):
        raise RuntimeQuarantineError("installed root changed during denial publication")
    entries[0] = startup._HeldEntry(None, startup._PROTECTED_ROOT, root_fd, current)


def _quarantine_fixed_runtime_profile(
    expected_skill_digest: str, expected_snapshot_digest: str
) -> dict[str, Any]:
    """Bind accepted revocation to measured installed bytes; retain before return.

    Lock order is activation EX -> install-root EX -> broker lock, matching the
    existing runtime's install-root SH -> broker lock order. No caller-selected
    paths, units, PIDs, denial expiry or unquarantine operation are accepted.
    Any failure after publication begins is indeterminate, never rollback.
    """
    publication_attempted = False
    try:
        startup._digest(expected_skill_digest, "requested skill")
        startup._digest(expected_snapshot_digest, "requested revocation snapshot")
        _require_root()
        with response._activation_guard():
            identities = response._identities()
            before = [response._unit_state(unit) for unit in response._UNITS]
            service_ids = (
                (identities[3], identities[4]),
                (identities[1], identities[2]),
            )
            processes = [
                response._process_identity(unit, state, uid, gid)
                for unit, state, (uid, gid) in zip(
                    response._UNITS, before, service_ids, strict=True
                )
            ]
            binding = response._read_bindings(identities[1])
            startup._binding_document(binding)
            if binding.active_skill_digest != expected_skill_digest:
                raise RuntimeQuarantineError(
                    "requested skill is not the running binding"
                )
            config = response._broker_config(identities, binding)
            with _installed_guard() as (root_fd, entries):
                record, tree_digest, installed_digest, active = (
                    startup._installed_snapshot(root_fd, entries)
                )
                if installed_digest != expected_skill_digest:
                    raise RuntimeQuarantineError(
                        "running and installed skill bytes disagree"
                    )
                with response._broker_guard(config) as control_fd:

                    def snapshot() -> dict[str, Any]:
                        return response._locked_revocations(
                            control_fd, config, binding, expected_snapshot_digest
                        )

                    accepted = snapshot()
                    if response._read_bindings(identities[1]) != binding:
                        raise RuntimeQuarantineError(
                            "worker binding changed before denial"
                        )
                    for unit, state, process, (uid, gid) in zip(
                        response._UNITS, before, processes, service_ids, strict=True
                    ):
                        current = response._unit_state(unit)
                        if (
                            current != state
                            or response._process_identity(unit, current, uid, gid)
                            != process
                        ):
                            raise RuntimeQuarantineError(
                                "runtime identity changed before denial"
                            )
                    _recheck_installed(root_fd, entries, record, active)
                    if snapshot() != accepted:
                        raise RuntimeQuarantineError(
                            "accepted revocation changed before denial"
                        )
                    names = set(os.listdir(root_fd))
                    marker_name = (
                        ".aragorn-quarantined-skill-" + installed_digest[7:] + ".json"
                    )
                    new_record = marker_name not in names
                    names.add(marker_name)
                    publication_attempted = True
                    denial = publish_quarantine_at(
                        root_fd,
                        installed_digest,
                        expected_snapshot_digest,
                        expected_uid=startup._EXPECTED_INSTALL_UID,
                    )
                    _refresh_published_root(
                        root_fd, entries, names, new_record=new_record
                    )
                    _recheck_installed(root_fd, entries, record, active)
                    response._stop_units()
                    after = []
                    for unit, state, process in zip(
                        response._UNITS, before, processes, strict=True
                    ):
                        current = response._unit_state(unit)
                        if (
                            current["ActiveState"] != "inactive"
                            or current["SubState"] != "dead"
                            or current["MainPID"] != "0"
                            or current["ControlPID"] != "0"
                            or current["ControlGroup"]
                            not in {"", state["ControlGroup"]}
                        ):
                            raise RuntimeQuarantineError(
                                "unit termination was not confirmed"
                            )
                        empty = response._cgroup_empty(unit, state)
                        if empty["status"] == "EMPTY" and (
                            empty["device"] != process["cgroup_device"]
                            or empty["inode"] != process["cgroup_inode"]
                        ):
                            raise RuntimeQuarantineError(
                                "termination cgroup identity changed"
                            )
                        after.append({"unit": current, "cgroup": empty})
                    barrier = response._mask_future_starts()
                    _recheck_installed(root_fd, entries, record, active)
                    result = {
                        "schema": "aragorn/installed-digest-quarantine-response/v1",
                        "authority": "LOCAL_ROOT_DENIAL_AND_FIXED_PROFILE_STOP_NOT_PROCESS_CONSUMPTION_OR_QUALIFICATION",
                        "status": "DIGEST_DENIAL_RECORDED_AND_FIXED_PROFILE_STOPPED_MASKED",
                        "expected_skill_digest": installed_digest,
                        "revocation_snapshot_digest": expected_snapshot_digest,
                        "accepted_revocation": accepted,
                        "denial_record": denial,
                        "denial_record_digest": canonical_digest(denial),
                        "active_record_digest": canonical_digest(record),
                        "tree_digest": tree_digest,
                        "before": [
                            {"unit": state, "process": process}
                            for state, process in zip(before, processes, strict=True)
                        ],
                        "after": after,
                        "future_start_barrier": barrier,
                        "limitations": [
                            "PRIVATE_COMPOSITION_NOT_DEPLOYED_OR_AUTOMATIC_DISPATCH",
                            "DIGEST_ENFORCEMENT_REQUIRES_SUCCESSOR_PRODUCERS_RUNTIME_AND_STARTUP_GATE",
                            "RUNNING_BINDING_AND_INSTALLED_BYTES_NOT_PROCESS_BYTE_CONSUMPTION",
                            "FIRST_DENIAL_RECORD_PERSISTS_WITHOUT_EXPIRY_OR_UNQUARANTINE",
                            "FIXED_PROFILE_MASKS_REQUIRE_INDEPENDENT_ROOT_RECOVERY",
                            "NO_PROTECTION_AGAINST_INDEPENDENT_ROOT_CONTROL",
                            "NO_INDEPENDENT_RUN_PHASE3_EDR_OR_RELEASE_QUALIFICATION",
                        ],
                    }
                    retained = response._retain_result(result)
        return retained
    except BaseException as exc:
        if publication_attempted:
            raise RuntimeQuarantineIndeterminate(
                "denial publication was attempted; denial may persist and complete "
                "stop, masking, cleanup or evidence retention is unconfirmed"
            ) from exc
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(exc, RuntimeQuarantineError):
            raise
        raise RuntimeQuarantineError(
            f"installed quarantine response refused: {exc}"
        ) from exc
