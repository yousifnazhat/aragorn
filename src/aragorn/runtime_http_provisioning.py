"""Absent-only HTTP credential provisioning in one exact stopped owned fixture.

Never starts a service, repairs an existing credential, deletes partial output,
or discovers an environment on the caller's behalf.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat
import subprocess
import sys

from . import runtime_http_action as http
from .native_phase3_http_fixture import owned_http_fixture
from .oci_worker_protocol import canonical_digest, canonical_json

UNITS = (
    "aragorn-agent-gateway.service",
    "aragorn-runtime-action-worker.service",
    "aragorn-runtime-lineage-capability-observation-publisher.service",
    http.BROKER_UNIT,
)


def _require(value, reason):
    if not value:
        raise http.RuntimeHttpActionError(reason)


def _accounts():
    broker = pwd.getpwnam("aragorn-broker")
    worker = pwd.getpwnam("aragorn-runtime")
    group = grp.getgrnam("aragorn-runtime")
    _require(
        broker.pw_uid > 0
        and worker.pw_uid > 0
        and broker.pw_uid != worker.pw_uid
        and worker.pw_gid == group.gr_gid
        and group.gr_gid > 0,
        "HTTP_PROVISION_ACCOUNT_MISMATCH",
    )
    return broker.pw_uid, group.gr_gid


def _stopped():
    for unit in UNITS:
        value = subprocess.run(
            [
                "/usr/bin/systemctl",
                "show",
                "--property=ActiveState",
                "--property=SubState",
                "--property=MainPID",
                "--property=ControlPID",
                "--",
                unit,
            ],
            check=False,
            capture_output=True,
            timeout=2,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
        )
        lines = value.stdout.splitlines()
        pairs = [line.split(b"=", 1) for line in lines]
        _require(
            value.returncode == 0
            and value.stderr == b""
            and len(lines) == 4
            and all(len(pair) == 2 for pair in pairs),
            "HTTP_PROVISION_UNIT_REFUSED",
        )
        fields = dict(pairs)
        _require(
            fields
            == {
                b"ActiveState": b"inactive",
                b"SubState": b"dead",
                b"MainPID": b"0",
                b"ControlPID": b"0",
            },
            "HTTP_PROVISION_SERVICES_NOT_STOPPED",
        )


def _new_binding(expected_fixture):
    uid, gid = _accounts()
    return http.validate_fixture_binding(
        {
            "schema": http.BINDING_SCHEMA,
            "fixture": expected_fixture,
            "expected_broker_uid": uid,
            "expected_broker_gid": gid,
        }
    )


def validate_activation_fixture():
    """Called by the successor activator before it can start any service."""
    binding = http.load_fixture_binding()
    with owned_http_fixture(binding["fixture"]) as held:
        _require(
            _new_binding(binding["fixture"]) == binding,
            "HTTP_PROVISION_ACCOUNT_MISMATCH",
        )
        _stopped()
        held.guard()
        _require(
            http.load_fixture_binding() == binding, "HTTP_PROVISION_BINDING_CHANGED"
        )
    return canonical_digest(binding)


def provision_fixture_binding(expected_fixture):
    """One guarded write; all partial outcomes remain for outer fixture cleanup."""
    result = {
        "schema": "aragorn/runtime-http-provisioning/v1",
        "created": False,
        "bytes_written": 0,
        "completed": False,
        "binding_digest": None,
        "cleanup_failed": False,
        "activation_performed": False,
        "phase3_exit_eligible": False,
    }
    parent = descriptor = -1
    try:
        with owned_http_fixture(expected_fixture) as held:
            binding = _new_binding(expected_fixture)
            raw = canonical_json(binding)
            result["binding_digest"] = canonical_digest(binding)
            _stopped()
            for path in reversed(http.BINDING_PATH.parents):
                info = path.lstat()
                _require(
                    stat.S_ISDIR(info.st_mode)
                    and info.st_uid == 0
                    and not stat.S_IMODE(info.st_mode) & 0o022,
                    "HTTP_PROVISION_PARENT_REFUSED",
                )
            parent = os.open(
                http.BINDING_PATH.parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            before = os.fstat(parent)
            held.guard()
            result["created"] = None
            descriptor = os.open(
                http.BINDING_PATH.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o400,
                dir_fd=parent,
            )
            result["created"] = True
            os.fchown(descriptor, 0, binding["expected_broker_gid"])
            os.fchmod(descriptor, 0o440)
            result["bytes_written"] = None
            result["bytes_written"] = os.write(descriptor, raw)
            _require(result["bytes_written"] == len(raw), "HTTP_PROVISION_SHORT_WRITE")
            os.fsync(descriptor)
            os.fsync(parent)
            held.guard()
            after = http.BINDING_PATH.parent.lstat()
            _require(
                (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                "HTTP_PROVISION_PARENT_CHANGED",
            )
            _require(
                http.load_fixture_binding() == binding, "HTTP_PROVISION_BINDING_CHANGED"
            )
            _stopped()
        result["completed"] = True
        return result
    except BaseException as error:
        error.http_provisioning_observation = result
        raise
    finally:
        primary = sys.exception()
        cleanup = None
        for fd in (descriptor, parent):
            if fd >= 0:
                try:
                    os.close(fd)
                except BaseException as error:
                    cleanup = http._preserve_failure(cleanup, error)
        if cleanup is not None:
            result["completed"] = False
            result["cleanup_failed"] = True
            retained = http._preserve_failure(primary, cleanup)
            retained.http_provisioning_observation = result
            raise retained from (cleanup if retained is not cleanup else primary)
