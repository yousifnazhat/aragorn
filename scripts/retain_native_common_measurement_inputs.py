"""Retain the one missing grant privately before destroying its owned fixture.

Only the planner-identified immutable CAS file crosses this boundary. No private
bytes enter stdout, public CAS, returned metadata, or exception diagnostics.
The fixed scratch directory is a permanent once-only claim, not resumable work.
"""

from __future__ import annotations

from contextlib import contextmanager
from io import BytesIO
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

from scripts import capture_native_phase3_common_setup as base
from aragorn.cas import CAS
from aragorn import native_phase3_common_measurement_capture as planning
from aragorn.runtime_native_measurement_inputs import (
    validate_prepared_native_measurement_inputs,
)
from aragorn.oci_worker_protocol import canonical_json

SCHEMA = "aragorn/native-common-measurement-input-retention/v1"
AUTHORITY = "PRIVATE_HOST_CAS_RETENTION_NOT_MEASUREMENT_OR_QUALIFICATION"
MAX_GRANT = 65536
MAX_INPUT = 1024 * 1024
SCRATCH_NAME = "native-common-measurement-input-retention"
GRANT_NAME = "grant.json"
CAS_ROOT = "/run/aragorn-native-common-attempt/evidence"
_FALSE = (
    "deployment_attested",
    "admission_qualified",
    "run_qualified",
    "quantitative_metrics_eligible",
    "phase3_exit_eligible",
    "generic_collector_semantics_eligible",
    "blocked_pre_effect",
    "causal_attribution",
    "transient_effects_excluded",
    "host_capture_verified",
)
_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

# Installed fixed helpers provide the same original-CAS no-follow custody as
# public export. This read-only command emits metadata only, even on failures.
_GUEST_READ = """
import sys
try:
 import hashlib,json,os,stat
 container, pin, size, source_text = sys.argv[1:]
 size = int(size)
 def require(value):
  if not value: raise ValueError('PRIVATE_SOURCE_GUARD_REFUSED')
 def canonical(value):
  return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
 def digest(raw): return 'sha256:' + hashlib.sha256(raw).hexdigest()
 sources=json.loads(source_text)
 require(type(sources) is dict and 0 < len(sources) <= 256)
 fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
 identity=lambda value: tuple(getattr(value,key) for key in fields)
 directory_identity=lambda value: identity(value)[:5]
 flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
 def read_source(path,expected):
  descriptors=[]; held=[]
  try:
   names=path.split('/')
   require(names[0]=='' and len(names)>2 and all(name not in ('','.','..') for name in names[1:]))
   parent=os.open('/',flags); descriptors.append(parent)
   for name in names[1:-1]:
    before=os.stat(name,dir_fd=parent,follow_symlinks=False)
    fd=os.open(name,flags,dir_fd=parent); descriptors.append(fd)
    opened=os.fstat(fd)
    require(stat.S_ISDIR(opened.st_mode) and opened.st_uid==opened.st_gid==0 and not stat.S_IMODE(opened.st_mode)&0o022 and directory_identity(before)==directory_identity(opened))
    held.append((parent,name,fd,directory_identity(opened))); parent=fd
   name=names[-1]; before=os.stat(name,dir_fd=parent,follow_symlinks=False)
   fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent); descriptors.append(fd)
   opened=os.fstat(fd)
   require(stat.S_ISREG(opened.st_mode) and opened.st_uid==opened.st_gid==0 and stat.S_IMODE(opened.st_mode)==0o444 and opened.st_nlink==1 and 0<opened.st_size==expected['bytes']<=1048576 and identity(before)==identity(opened))
   raw=bytearray()
   while True:
    part=os.read(fd,min(65536,1048577-len(raw)))
    if not part:break
    raw.extend(part); require(len(raw)<=1048576)
   require(len(raw)==expected['bytes'] and digest(raw)==expected['digest'] and identity(opened)==identity(os.fstat(fd))==identity(os.stat(name,dir_fd=parent,follow_symlinks=False)))
   for ancestor,leaf,descriptor,checked in held:
    require(checked==directory_identity(os.fstat(descriptor))==directory_identity(os.stat(leaf,dir_fd=ancestor,follow_symlinks=False)))
   return {'bytes':len(raw),'digest':expected['digest'],'identity':list(identity(opened))}
  finally:
   failure=None
   for fd in reversed(descriptors):
    try:os.close(fd)
    except BaseException as error:failure=failure or error
   if failure is not None:raise ValueError('PRIVATE_SOURCE_CLOSE_REFUSED') from None
 def source_guard():return {path:read_source(path,expected) for path,expected in sorted(sources.items())}
 source_before=source_guard()
 try:
  sys.path[:0] = ['/usr/lib/aragorn', '/opt/aragorn']
  import runtime_native_common_attempt_capture as g
  g._require(g._pin(pin) and 0 < size <= 65536, 'PRIVATE_READ_ARGUMENTS_REFUSED')
  g.attempt.setup.predecessor._environment(container, (0, 0))
  path = '/run/aragorn-native-common-attempt/evidence/blobs/sha256/' + pin[7:9] + '/' + pin[9:]
  with g._evidence_store(blobs=True) as (fd, guard):
   raw = g._read_public_blob(fd, {'digest': pin, 'bytes': size})
   again, metadata = g._read_fixed(path, mode=0o444, limit=65536)
   g._require(raw == again and len(raw) == size and g._IDENTITY._digest(raw) == pin, 'PRIVATE_READ_PIN_REFUSED')
   guard()
  g.attempt.setup.predecessor._environment(container, (0, 0))
 finally:
  require(source_guard()==source_before)
 sys.stdout.buffer.write(canonical({'status':'CHECKED','file':metadata,'installed_source_expectations_digest':digest(source_text.encode('utf-8')),'installed_source_count':len(sources)}) + b'\\n')
except BaseException:
 sys.stdout.buffer.write(b'{"status":"REFUSED"}\\n')
 sys.exit(126)
"""


class NativeCommonMeasurementInputRetentionError(ValueError):
    """Fixed metadata-only refusal; preserve all private partial state."""


def _require(condition, reason):
    if not condition:
        raise NativeCommonMeasurementInputRetentionError(reason)


def _pin(value):
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value),
        "INPUT_PIN_REFUSED",
    )
    return value


def _digest(raw):
    return base._API._digest(raw)


def _command(argv, *, timeout, maximum):
    """One bounded client; arbitrary diagnostics are discarded, never reported."""
    child = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
    )
    output, primary, failures = bytearray(), None, []
    try:
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            for stream in (child.stdout, child.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                _require(remaining > 0, "PRIVATE_CLIENT_TIMEOUT")
                for key, _ in selector.select(remaining):
                    diagnostic = key.fileobj is child.stderr
                    chunk = os.read(
                        key.fileobj.fileno(),
                        1 if diagnostic else min(65536, maximum + 1 - len(output)),
                    )
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    _require(not diagnostic, "PRIVATE_CLIENT_DIAGNOSTIC_REFUSED")
                    output.extend(chunk)
                    _require(
                        len(output) <= maximum, "PRIVATE_CLIENT_OUTPUT_BOUND_REFUSED"
                    )
        code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        _require(code == 0, "PRIVATE_CLIENT_FAILED")
        return bytes(output)
    except BaseException as error:
        primary = error
        raise
    finally:
        terminate = primary is not None
        try:
            terminate = child.poll() is None or terminate
        except BaseException:
            terminate = True
            failures.append("CLIENT_POLL_REFUSED")
        if terminate:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException:
                failures.append("CLIENT_TERMINATION_REFUSED")
        for operation in (
            child.stdout.close,
            child.stderr.close,
            lambda: child.wait(timeout=3),
        ):
            try:
                operation()
            except BaseException:
                failures.append("CLIENT_CLOSE_OR_REAP_REFUSED")
        if failures:
            if primary is not None:
                primary._private_client_failures = failures
            else:
                error = NativeCommonMeasurementInputRetentionError(
                    "PRIVATE_CLIENT_CLEANUP_REFUSED"
                )
                error._private_client_failures = failures
                raise error


def _fixture(capture):
    container, name, owner, commit = (
        capture["fixture_container"],
        capture["fixture_name"],
        capture["fixture_owner"],
        capture["source"]["commit"],
    )
    _require(
        type(container) is str
        and re.fullmatch(r"[0-9a-f]{64}", container)
        and type(owner) is str
        and re.fullmatch(r"[0-9a-f]{64}", owner)
        and name == "aragorn-native-common-attempt-" + owner[:16]
        and type(commit) is str
        and re.fullmatch(r"[0-9a-f]{40}", commit),
        "FIXED_FIXTURE_IDENTITY_REFUSED",
    )
    raw = _command(
        [*base._API._DOCKER, "inspect", "--type", "container", container],
        timeout=10,
        maximum=256 * 1024,
    )
    values = json.loads(raw, object_pairs_hook=base._API.shared._no_duplicates)
    _require(
        type(values) is list and len(values) == 1 and type(values[0]) is dict,
        "OWNED_FIXTURE_INVENTORY_REFUSED",
    )
    value = values[0]
    base.native._verify_fixture(value, container, name, owner, commit)
    state = value["State"]
    _require(
        state["Running"] is True
        and state["Paused"] is False
        and type(state["Pid"]) is int
        and state["Pid"] > 0
        and type(state["StartedAt"]) is str
        and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z",
            state["StartedAt"],
        ),
        "OWNED_FIXTURE_STATE_REFUSED",
    )
    return {
        "container_id": container,
        "name": name,
        "owner": owner,
        "source_commit": commit,
        "image": value["Image"],
        "network_mode": value["HostConfig"]["NetworkMode"],
        "pid": state["Pid"],
        "started_at": state["StartedAt"],
    }


def _guest_source(container, pin, size, sources):
    source_raw = canonical_json(sources)
    _require(len(source_raw) <= 65536, "SOURCE_INVENTORY_BOUND_REFUSED")
    raw = _command(
        [
            *base._API._DOCKER,
            "exec",
            container,
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "-c",
            _GUEST_READ,
            container,
            pin,
            str(size),
            source_raw.decode("utf-8"),
        ],
        timeout=15,
        maximum=4096,
    )
    value = json.loads(raw, object_pairs_hook=base._API.shared._no_duplicates)
    _require(
        type(value) is dict
        and set(value)
        == {
            "status",
            "file",
            "installed_source_expectations_digest",
            "installed_source_count",
        }
        and value["status"] == "CHECKED"
        and value["installed_source_expectations_digest"] == _digest(source_raw)
        and type(value["installed_source_count"]) is int
        and value["installed_source_count"] == len(sources),
        "PRIVATE_GUEST_READ_REFUSED",
    )
    metadata = value["file"]
    base.contract.live._metadata(metadata, owners={(0, 0)}, modes={0o444})
    _require(
        metadata["digest"] == pin and metadata["bytes"] == size,
        "PRIVATE_SOURCE_PIN_REFUSED",
    )
    return metadata


def _identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _close(descriptors):
    primary, failure = sys.exception(), None
    for fd in reversed(descriptors):
        try:
            os.close(fd)
        except BaseException as error:
            if failure is None:
                failure = error
    if failure is not None and primary is None:
        if not isinstance(failure, Exception):
            raise failure
        raise NativeCommonMeasurementInputRetentionError(
            "PRIVATE_DESCRIPTOR_CLOSE_REFUSED"
        ) from None


@contextmanager
def _private_root(store):
    path = store.root.absolute()
    _require(path == path.resolve(strict=True), "PRIVATE_ROOT_INDIRECTION_REFUSED")
    descriptors, held = [], []
    try:
        parent = os.open("/", _FLAGS)
        descriptors.append(parent)
        for name in path.parts[1:]:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            fd = os.open(name, _FLAGS, dir_fd=parent)
            descriptors.append(fd)
            opened = os.fstat(fd)
            _require(
                stat.S_ISDIR(opened.st_mode)
                and opened.st_uid in {0, os.geteuid()}
                and (
                    not stat.S_IMODE(opened.st_mode) & 0o022
                    or (opened.st_uid == 0 and opened.st_mode & stat.S_ISVTX)
                )
                and _identity(before) == _identity(opened),
                "PRIVATE_ANCESTRY_CUSTODY_REFUSED",
            )
            held.append((parent, name, fd, _identity(opened)))
            parent = fd
        opened = os.fstat(parent)
        _require(
            opened.st_uid == os.geteuid() and stat.S_IMODE(opened.st_mode) == 0o700,
            "PRIVATE_ROOT_CUSTODY_REFUSED",
        )

        def guard():
            for ancestor, name, fd, identity in held:
                _require(
                    identity
                    == _identity(os.fstat(fd))
                    == _identity(os.stat(name, dir_fd=ancestor, follow_symlinks=False)),
                    "PRIVATE_ANCESTRY_REPLACED",
                )

        guard()
        try:
            yield path, parent, guard
        finally:
            base.setup._close_preserving(guard, "PRIVATE_ROOT_FINAL_CUSTODY_REFUSED")
    finally:
        _close(descriptors)


def _grant_absent(root, pin):
    """Check only the fixed planned pin; never enumerate an existing store."""
    descriptors = []
    try:
        parent = root
        for name in ("blobs", "sha256", pin[7:9]):
            try:
                fd = os.open(name, _FLAGS, dir_fd=parent)
            except FileNotFoundError:
                return
            descriptors.append(fd)
            metadata = os.fstat(fd)
            _require(
                stat.S_ISDIR(metadata.st_mode)
                and metadata.st_uid == os.geteuid()
                and stat.S_IMODE(metadata.st_mode) == 0o700,
                "PRIVATE_PIN_ANCESTRY_REFUSED",
            )
            parent = fd
        try:
            os.stat(pin[9:], dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise NativeCommonMeasurementInputRetentionError("PREEXISTING_GRANT_REFUSED")
    finally:
        _close(descriptors)


@contextmanager
def _scratch(path, root, root_guard):
    descriptors = []
    try:
        root_guard()
        os.mkdir(SCRATCH_NAME, 0o700, dir_fd=root)
        os.fsync(root)
        fd = os.open(SCRATCH_NAME, _FLAGS, dir_fd=root)
        descriptors.append(fd)
        metadata = os.fstat(fd)
        identity = _identity(metadata)
        _require(
            stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            "PRIVATE_SCRATCH_CUSTODY_REFUSED",
        )

        def guard():
            root_guard()
            _require(
                identity
                == _identity(os.fstat(fd))
                == _identity(os.stat(SCRATCH_NAME, dir_fd=root, follow_symlinks=False)),
                "PRIVATE_SCRATCH_REPLACED",
            )

        guard()
        try:
            yield path / SCRATCH_NAME / GRANT_NAME, fd, guard
        finally:
            base.setup._close_preserving(guard, "PRIVATE_SCRATCH_FINAL_CUSTODY_REFUSED")
    finally:
        _close(descriptors)


def _read_grant(directory, expected, size):
    descriptors = []
    try:
        before = os.stat(GRANT_NAME, dir_fd=directory, follow_symlinks=False)
        fd = os.open(
            GRANT_NAME,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=directory,
        )
        descriptors.append(fd)
        opened = os.fstat(fd)
        fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )

        def same(*values):
            return all(
                len({getattr(value, field) for value in values}) == 1
                for field in fields
            )

        _require(
            stat.S_ISREG(opened.st_mode)
            and opened.st_uid == os.geteuid()
            and stat.S_IMODE(opened.st_mode) in {0o400, 0o444}
            and opened.st_nlink == 1
            and 0 < opened.st_size == size <= MAX_GRANT
            and same(before, opened),
            "PRIVATE_GRANT_CUSTODY_REFUSED",
        )
        raw = bytearray()
        while chunk := os.read(fd, min(8192, MAX_GRANT + 1 - len(raw))):
            raw.extend(chunk)
            _require(len(raw) <= MAX_GRANT, "PRIVATE_GRANT_BOUND_REFUSED")
        _require(
            len(raw) == size
            and _digest(bytes(raw)) == expected
            and same(
                opened,
                os.fstat(fd),
                os.stat(GRANT_NAME, dir_fd=directory, follow_symlinks=False),
            ),
            "PRIVATE_GRANT_READBACK_REFUSED",
        )
        return bytes(raw)
    finally:
        _close(descriptors)


def _target_absent(directory):
    try:
        os.stat(GRANT_NAME, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise NativeCommonMeasurementInputRetentionError("PRIVATE_TRANSFER_TARGET_EXISTS")


def _plan(capture, public_cas):
    plan = planning.plan_native_common_measurement_inputs(
        capture, public_cas=public_cas
    )
    sources = plan["installed_sources"]
    _require(
        type(sources) is dict
        and set(sources)
        == set(planning.inputs.FIXTURE_HELPERS.values())
        | set(planning.inputs.HELPER_ALIASES)
        and len(sources) <= 256,
        "FIXED_SOURCE_INVENTORY_REFUSED",
    )
    for row in sources.values():
        _require(
            type(row) is dict
            and set(row) == {"digest", "bytes"}
            and type(row["bytes"]) is int
            and 0 < row["bytes"] <= MAX_INPUT,
            "FIXED_SOURCE_ROW_REFUSED",
        )
        _pin(row["digest"])
    rows, public, grant = (
        plan["input_rows"],
        plan["public_blobs"],
        _pin(plan["grant_digest"]),
    )
    _require(
        type(rows) is list and 1 <= len(rows) <= 13 and type(public) is dict,
        "FINITE_PRIVATE_INPUT_INVENTORY_REFUSED",
    )
    sizes = {}
    for row in rows:
        _require(
            type(row) is dict
            and set(row) == {"digest", "bytes"}
            and type(row["bytes"]) is int
            and 0 < row["bytes"] <= MAX_INPUT,
            "FINITE_PRIVATE_INPUT_ROW_REFUSED",
        )
        pin = _pin(row["digest"])
        _require(pin not in sizes, "DUPLICATE_PRIVATE_INPUT_PIN")
        sizes[pin] = row["bytes"]
    _require(
        set(sizes) - set(public) == {grant}
        and set(public) < set(sizes)
        and type(plan["grant_bytes"]) is int
        and 0 < plan["grant_bytes"] == sizes[grant] <= MAX_GRANT
        and grant not in public,
        "ONE_MISSING_PRIVATE_GRANT_REQUIRED",
    )
    for pin, raw in public.items():
        _require(
            type(raw) is bytes
            and len(raw) == sizes[pin]
            and _digest(raw) == pin
            and public_cas.read(pin, max_bytes=MAX_INPUT) == raw,
            "PUBLIC_INPUT_CUSTODY_REFUSED",
        )
    return plan


def public_retention_metadata(report, *, capture, private_cas):
    """Classify only fixed metadata before anything can enter the public CAS.

    This is neither an input-semantic verifier nor a private blob reader. It
    accepts valid partial refusal reports, but never copies unknown diagnostics,
    credential fields, or arbitrary nested objects into the public envelope.
    """
    try:
        fields = {
            "schema",
            "authority",
            "status",
            "container_id",
            "prepared_digest",
            "binding_digest",
            "grant_digest",
            "grant_bytes",
            "input_blobs",
            "input_set_digest",
            "fixture_before",
            "fixture_after",
            "grant_source_before",
            "grant_source_after",
            "scratch_directory",
            "copy_count",
            "input_validation_complete",
            "postcondition_failures",
            "refusal",
            *_FALSE,
        }
        _require(
            type(report) is dict and set(report) == fields,
            "PRIVATE_INPUT_METADATA_REFUSED",
        )
        _require(
            all(type(report[name]) is str for name in ("schema", "authority", "status"))
            and report["schema"] == SCHEMA
            and report["authority"] == AUTHORITY
            and report["status"] in {"PRIVATE_INPUTS_RETAINED", "REFUSED"}
            and all(report[name] is False for name in _FALSE)
            and type(report["copy_count"]) is int
            and report["copy_count"] in {0, 1}
            and type(report["input_validation_complete"]) is bool,
            "PRIVATE_INPUT_METADATA_REFUSED",
        )
        container = report["container_id"]
        _require(
            container is None
            or (
                type(container) is str
                and re.fullmatch(r"[0-9a-f]{64}", container)
                and container == capture["fixture_container"]
            ),
            "PRIVATE_INPUT_METADATA_REFUSED",
        )
        for name in ("prepared_digest", "binding_digest", "grant_digest"):
            if report[name] is not None:
                _pin(report[name])
        populated = container is not None
        _require(
            all(
                (report[name] is not None) is populated
                for name in (
                    "prepared_digest",
                    "binding_digest",
                    "grant_digest",
                    "grant_bytes",
                )
            ),
            "PRIVATE_INPUT_METADATA_REFUSED",
        )
        if populated:
            _require(
                type(report["grant_bytes"]) is int
                and 0 < report["grant_bytes"] <= MAX_GRANT,
                "PRIVATE_INPUT_METADATA_REFUSED",
            )
        rows = report["input_blobs"]
        _require(
            type(rows) is list and len(rows) <= 13, "PRIVATE_INPUT_METADATA_REFUSED"
        )
        pins = []
        for row in rows:
            _require(
                type(row) is dict
                and set(row) == {"digest", "bytes"}
                and type(row["bytes"]) is int
                and 0 < row["bytes"] <= MAX_INPUT,
                "PRIVATE_INPUT_METADATA_REFUSED",
            )
            pins.append(_pin(row["digest"]))
        _require(pins == sorted(set(pins)), "PRIVATE_INPUT_METADATA_REFUSED")
        if rows:
            _pin(report["input_set_digest"])
            _require(
                populated
                and report["input_set_digest"] == _digest(canonical_json(rows))
                and {"digest": report["grant_digest"], "bytes": report["grant_bytes"]}
                in rows,
                "PRIVATE_INPUT_METADATA_REFUSED",
            )
        else:
            _require(
                report["input_set_digest"] is None, "PRIVATE_INPUT_METADATA_REFUSED"
            )
        for name in ("fixture_before", "fixture_after"):
            value = report[name]
            if value is None:
                continue
            _require(
                type(value) is dict
                and set(value)
                == {
                    "container_id",
                    "name",
                    "owner",
                    "source_commit",
                    "image",
                    "network_mode",
                    "pid",
                    "started_at",
                },
                "PRIVATE_INPUT_METADATA_REFUSED",
            )
            _require(
                all(type(value[key]) is str for key in value if key != "pid")
                and populated
                and value["container_id"] == container
                and type(value["owner"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", value["owner"])
                and value["owner"] == capture["fixture_owner"]
                and value["name"]
                == capture["fixture_name"]
                == "aragorn-native-common-attempt-" + value["owner"][:16]
                and type(value["source_commit"]) is str
                and re.fullmatch(r"[0-9a-f]{40}", value["source_commit"])
                and value["source_commit"] == capture["source"]["commit"]
                and value["image"]
                == capture["fixture_image"]["Id"]
                == base.native._IMAGE
                and value["network_mode"] == "none"
                and type(value["pid"]) is int
                and 0 < value["pid"] < 2**31
                and type(value["started_at"]) is str
                and re.fullmatch(
                    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z",
                    value["started_at"],
                ),
                "PRIVATE_INPUT_METADATA_REFUSED",
            )
        _require(
            report["fixture_after"] is None or report["fixture_before"] is not None,
            "PRIVATE_INPUT_METADATA_REFUSED",
        )
        for name in ("grant_source_before", "grant_source_after"):
            value = report[name]
            if value is None:
                continue
            base.contract.live._metadata(value, owners={(0, 0)}, modes={0o444})
            _require(
                populated
                and value["digest"] == report["grant_digest"]
                and value["bytes"] == report["grant_bytes"],
                "PRIVATE_INPUT_METADATA_REFUSED",
            )
        _require(
            report["grant_source_after"] is None
            or report["grant_source_before"] is not None,
            "PRIVATE_INPUT_METADATA_REFUSED",
        )
        scratch = report["scratch_directory"]
        if scratch is not None:
            _require(
                type(private_cas) is CAS
                and type(scratch) is str
                and scratch
                == str(private_cas.root.resolve(strict=True) / SCRATCH_NAME),
                "PRIVATE_INPUT_METADATA_REFUSED",
            )
        if report["copy_count"]:
            _require(
                scratch is not None
                and report["fixture_before"] is not None
                and report["grant_source_before"] is not None,
                "PRIVATE_INPUT_METADATA_REFUSED",
            )
        failures = report["postcondition_failures"]
        allowed = {
            "CLIENT_POLL_REFUSED",
            "CLIENT_TERMINATION_REFUSED",
            "CLIENT_CLOSE_OR_REAP_REFUSED",
            "ORIGINAL_GRANT_AFTER_REFUSED",
            "OWNED_FIXTURE_AFTER_REFUSED",
        }
        _require(
            type(failures) is list
            and len(failures) <= 12
            and all(type(label) is str and label in allowed for label in failures),
            "PRIVATE_INPUT_METADATA_REFUSED",
        )
        if report["status"] == "PRIVATE_INPUTS_RETAINED":
            _require(
                report["input_validation_complete"] is True
                and report["copy_count"] == 1
                and rows
                and report["fixture_before"] == report["fixture_after"]
                and report["grant_source_before"] == report["grant_source_after"]
                and not failures
                and report["refusal"] is None,
                "PRIVATE_INPUT_METADATA_REFUSED",
            )
        else:
            refusal = report["refusal"]
            _require(
                report["input_validation_complete"] is False
                and type(refusal) is dict
                and set(refusal) == {"phase", "reason"}
                and type(refusal["phase"]) is str
                and refusal["phase"]
                in {
                    "INPUTS",
                    "OWNED_FIXTURE",
                    "PRIVATE_ROOT",
                    "ORIGINAL_GRANT_SOURCE",
                    "PRIVATE_FILE_TRANSFER",
                    "PRIVATE_INPUT_RETENTION",
                    "PRIVATE_INPUT_VALIDATION",
                    "FINAL_READBACKS",
                }
                and type(refusal["reason"]) is str
                and refusal["reason"]
                in {
                    "PRIVATE_INPUT_RETENTION_REFUSED",
                    "PRIVATE_INPUT_CUSTODY_REFUSED",
                },
                "PRIVATE_INPUT_METADATA_REFUSED",
            )
        raw = canonical_json(report)
        _require(len(raw) <= 32768, "PRIVATE_INPUT_METADATA_REFUSED")
        return json.loads(raw)
    except Exception:
        raise NativeCommonMeasurementInputRetentionError(
            "PRIVATE_INPUT_METADATA_REFUSED"
        ) from None


def retain_native_common_measurement_inputs(*, capture, public_cas, private_cas):
    """Consume one finite handoff; on failure attach metadata and preserve files."""
    report = {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "status": "REFUSED",
        "container_id": None,
        "prepared_digest": None,
        "binding_digest": None,
        "grant_digest": None,
        "grant_bytes": None,
        "input_blobs": [],
        "input_set_digest": None,
        "fixture_before": None,
        "fixture_after": None,
        "grant_source_before": None,
        "grant_source_after": None,
        "scratch_directory": None,
        "copy_count": 0,
        "input_validation_complete": False,
        "postcondition_failures": [],
        "refusal": None,
        **dict.fromkeys(_FALSE, False),
    }
    primary, interruption, phase, plan = None, None, "INPUTS", None
    try:
        _require(
            type(public_cas) is CAS
            and public_cas.read_only is True
            and type(private_cas) is CAS
            and private_cas.read_only is False,
            "EXACT_CAS_ACCESS_REQUIRED",
        )
        public_root, private_root = (
            public_cas.root.resolve(strict=True),
            private_cas.root.resolve(strict=True),
        )
        _require(
            public_root != private_root
            and not public_root.is_relative_to(private_root)
            and not private_root.is_relative_to(public_root),
            "PRIVATE_PUBLIC_CAS_SEPARATION_REQUIRED",
        )
        plan = _plan(capture, public_cas)
        report.update(
            container_id=capture["fixture_container"],
            prepared_digest=plan["prepared_digest"],
            binding_digest=plan["binding_digest"],
            grant_digest=plan["grant_digest"],
            grant_bytes=plan["grant_bytes"],
        )
        phase = "OWNED_FIXTURE"
        report["fixture_before"] = _fixture(capture)
        phase = "PRIVATE_ROOT"
        with _private_root(private_cas) as (path, root, root_guard):
            _grant_absent(root, plan["grant_digest"])
            report["scratch_directory"] = str(path / SCRATCH_NAME)
            with _scratch(path, root, root_guard) as (target, scratch, scratch_guard):
                phase = "ORIGINAL_GRANT_SOURCE"
                report["grant_source_before"] = _guest_source(
                    report["container_id"],
                    plan["grant_digest"],
                    plan["grant_bytes"],
                    plan["installed_sources"],
                )
                phase = "PRIVATE_FILE_TRANSFER"
                scratch_guard()
                _target_absent(scratch)
                source = (
                    CAS_ROOT
                    + "/blobs/sha256/"
                    + plan["grant_digest"][7:9]
                    + "/"
                    + plan["grant_digest"][9:]
                )
                report["copy_count"] = 1
                _require(
                    _command(
                        [
                            *base._API._DOCKER,
                            "cp",
                            report["container_id"] + ":" + source,
                            str(target),
                        ],
                        timeout=30,
                        maximum=0,
                    )
                    == b"",
                    "PRIVATE_COPY_OUTPUT_REFUSED",
                )
                scratch_guard()
                grant_raw = _read_grant(
                    scratch, plan["grant_digest"], plan["grant_bytes"]
                )
                phase = "PRIVATE_INPUT_RETENTION"
                blobs = {**plan["public_blobs"], plan["grant_digest"]: grant_raw}
                for pin, raw in sorted(blobs.items()):
                    scratch_guard()
                    _require(
                        private_cas.put_expected(
                            BytesIO(raw),
                            expected_digest=pin,
                            max_bytes=MAX_GRANT
                            if pin == plan["grant_digest"]
                            else MAX_INPUT,
                        )
                        == pin,
                        "PRIVATE_INPUT_PUT_REFUSED",
                    )
                    _require(
                        private_cas.read(pin, max_bytes=len(raw)) == raw,
                        "PRIVATE_INPUT_READBACK_REFUSED",
                    )
                phase = "PRIVATE_INPUT_VALIDATION"
                checked = validate_prepared_native_measurement_inputs(
                    prepared_raw=plan["prepared_raw"],
                    expected_prepared_digest=plan["prepared_digest"],
                    expected_binding_digest=plan["binding_digest"],
                    expected_broker_source_pins=plan["source_pins"],
                    source_cas=CAS(private_cas.root, read_only=True),
                )
                _require(
                    checked["input_blobs"] == blobs, "PRIVATE_VALIDATED_CLOSURE_CHANGED"
                )
                _require(
                    _read_grant(scratch, plan["grant_digest"], plan["grant_bytes"])
                    == grant_raw,
                    "PRIVATE_SCRATCH_FINAL_READBACK_REFUSED",
                )
                for pin, raw in blobs.items():
                    _require(
                        private_cas.read(pin, max_bytes=len(raw)) == raw,
                        "PRIVATE_INPUT_FINAL_READBACK_REFUSED",
                    )
                scratch_guard()
                report["input_blobs"] = [
                    {"digest": pin, "bytes": len(raw)}
                    for pin, raw in sorted(blobs.items())
                ]
                report["input_set_digest"] = _digest(
                    canonical_json(report["input_blobs"])
                )
                report["input_validation_complete"] = True
    except BaseException as error:
        primary = error
        if not isinstance(error, Exception):
            interruption = error
        report["refusal"] = {
            "phase": phase,
            "reason": "PRIVATE_INPUT_RETENTION_REFUSED",
        }
        report["postcondition_failures"].extend(
            label
            for label in getattr(error, "_private_client_failures", ())
            if label
            in {
                "CLIENT_POLL_REFUSED",
                "CLIENT_TERMINATION_REFUSED",
                "CLIENT_CLOSE_OR_REAP_REFUSED",
            }
        )
    finally:
        if report["fixture_before"] is not None:
            checks = []
            if report["grant_source_before"] is not None:
                checks.append(
                    (
                        "ORIGINAL_GRANT_AFTER_REFUSED",
                        "grant_source_after",
                        lambda: _guest_source(
                            report["container_id"],
                            plan["grant_digest"],
                            plan["grant_bytes"],
                            plan["installed_sources"],
                        ),
                    )
                )
            checks.append(
                (
                    "OWNED_FIXTURE_AFTER_REFUSED",
                    "fixture_after",
                    lambda: _fixture(capture),
                )
            )
            for label, key, operation in checks:
                try:
                    report[key] = operation()
                    before = (
                        report["grant_source_before"]
                        if key == "grant_source_after"
                        else report["fixture_before"]
                    )
                    _require(report[key] == before, "PRIVATE_FINAL_CUSTODY_CHANGED")
                except BaseException as error:
                    report["postcondition_failures"].append(label)
                    report["postcondition_failures"].extend(
                        label
                        for label in getattr(error, "_private_client_failures", ())
                        if label
                        in {
                            "CLIENT_POLL_REFUSED",
                            "CLIENT_TERMINATION_REFUSED",
                            "CLIENT_CLOSE_OR_REAP_REFUSED",
                        }
                    )
                    if interruption is None and not isinstance(error, Exception):
                        interruption = error
                    if primary is None:
                        primary = error
    if primary is not None or report["postcondition_failures"]:
        report["input_validation_complete"] = False
        if report["refusal"] is None:
            report["refusal"] = {
                "phase": "FINAL_READBACKS",
                "reason": "PRIVATE_INPUT_CUSTODY_REFUSED",
            }
        if interruption is not None:
            interruption._native_common_measurement_inputs = report
            raise interruption
        error = NativeCommonMeasurementInputRetentionError(
            "PRIVATE_INPUT_RETENTION_REFUSED"
        )
        error._native_common_measurement_inputs = report
        raise error from None
    report["status"] = "PRIVATE_INPUTS_RETAINED"
    return report
