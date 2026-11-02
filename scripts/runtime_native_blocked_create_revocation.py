"""One fixed runtime revocation publication in an owned disposable fixture.

This does not start services, invoke a workload, refresh observations, or infer
a denial. The owning controller must retain this report and its once-only
attempt marker even when publication or a subsequent readback fails.
"""

from __future__ import annotations

import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import select
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time

SOURCE_PATH = "/opt/aragorn/runtime_native_blocked_create_revocation.py"
BROKER_PATH = "/usr/lib/aragorn/aragorn/runtime_action_broker.py"
CONTROL = "/var/lib/aragorn-runtime-action/control"
SCHEMA = "aragorn/native-blocked-create-revocation/v1"
AUTHORITY = "OWNED_CONTROL_PUBLICATION_NOT_BROKER_DECISION_OR_EFFECT_AUTHORITY"
CHILD_SCHEMA = "aragorn/native-blocked-create-revocation-publication/v1"
MAX_RESULT = 4 * 1024 * 1024
_CONTROL_LIMIT = 128 * 1024
_SOURCE_LIMIT = 1024 * 1024
_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
FALSE_FLAGS = (
    "broker_decision_observed",
    "effect_observed",
    "blocked_pre_effect",
    "causal_attribution",
    "clock_domain_verified",
    "elapsed_time_derived",
    "route_qualified",
    "run_conformance_eligible",
    "metrics_eligible",
    "phase3_eligible",
    "live_deployment_attested",
)
LIMITATIONS = (
    "FRESH_FIFTEEN_SECOND_REVOCATION_NOT_GUARANTEED_FRESH_AT_LATER_DECISION",
    "EXISTING_BROKER_LOCK_AND_ATOMIC_PUBLICATION_NOT_HOSTILE_BROKER_RESISTANT",
    "SELECTED_SOURCE_BYTES_NOT_IMPORTED_CODE_OR_COMPLETE_DEPENDENCY_ATTESTATION",
    "PUBLISHED_FIELD_IS_PROPOSED_DOCUMENT_ON_REFUSAL_REQUIRE_SUCCESS_AND_AFTER_JOIN",
    "OWNING_CONTROLLER_MUST_RETAIN_ONCE_ONLY_ATTEMPT_MARKER_AND_PARTIAL_EVIDENCE",
    "NO_SERVICE_WORKLOAD_HEALTH_OBSERVATION_OR_POLICY_MUTATION",
    "NO_SOLE_CAUSE_PREVENTION_TIMING_OR_QUALIFICATION_CLAIM",
)


class NativeBlockedCreateRevocationError(ValueError):
    """Only fixed reasons may enter the public report."""


def _require(value, reason):
    if not value:
        raise NativeBlockedCreateRevocationError(reason)


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pin(value):
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value),
        "INVALID_EXPECTED_PIN",
    )
    return value


def _uint(value, minimum=0):
    return type(value) is int and minimum <= value < 2**53


def _parse(raw):
    def pairs(values):
        result = dict(values)
        _require(len(result) == len(values), "DUPLICATE_DOCUMENT_KEY")
        return result

    result = json.loads(raw, object_pairs_hook=pairs)
    _require(
        type(result) is dict and _canonical(result) == raw,
        "NONCANONICAL_PUBLIC_DOCUMENT",
    )
    return result


def _record(raw):
    return {"text": raw.decode("ascii"), "bytes": len(raw), "digest": _digest(raw)}


def _identity(item):
    return (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_uid,
        item.st_gid,
        item.st_nlink,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )


def _close_all(fds, failures):
    for fd in reversed(fds):
        try:
            os.close(fd)
        except BaseException:
            failures.append("DESCRIPTOR_CLOSE_REFUSED")


def _read_at(parent, name, *, uid, mode, limit, gid=None):
    fd = os.open(name, _FLAGS, dir_fd=parent)
    primary = None
    try:
        before = os.fstat(fd)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == uid
            and (gid is None or before.st_gid == gid)
            and stat.S_IMODE(before.st_mode) == mode
            and before.st_nlink == 1
            and 0 < before.st_size <= limit,
            "PUBLIC_FILE_CUSTODY_REFUSED",
        )
        chunks, total = [], 0
        while total <= limit:
            piece = os.read(fd, min(65536, limit + 1 - total))
            if not piece:
                break
            chunks.append(piece)
            total += len(piece)
        raw = b"".join(chunks)
        _require(
            len(raw) == before.st_size <= limit
            and _identity(before)
            == _identity(os.fstat(fd))
            == _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
            "PUBLIC_FILE_CHANGED",
        )
        return raw
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(fd)
        except BaseException:
            if primary is None:
                raise NativeBlockedCreateRevocationError("FILE_CLOSE_REFUSED")
            primary._native_revocation_cleanup = (
                *getattr(primary, "_native_revocation_cleanup", ()),
                "FILE_CLOSE_REFUSED",
            )


def _source(path, pin, mode):
    fds, ancestry, failures = [], [], []
    primary = None
    try:
        root = os.open("/", _FLAGS | os.O_DIRECTORY)
        fds.append(root)
        for part in Path(path).parts[1:-1]:
            before = os.stat(part, dir_fd=fds[-1], follow_symlinks=False)
            child = os.open(part, _FLAGS | os.O_DIRECTORY, dir_fd=fds[-1])
            fds.append(child)
            after = os.fstat(child)
            _require(
                stat.S_ISDIR(after.st_mode)
                and after.st_uid == 0
                and not stat.S_IMODE(after.st_mode) & 0o022
                and _identity(before) == _identity(after),
                "SOURCE_ANCESTRY_REFUSED",
            )
            ancestry.append((fds[-2], part, child, _identity(after)))
        raw = _read_at(
            fds[-1], Path(path).name, uid=0, gid=0, mode=mode, limit=_SOURCE_LIMIT
        )
        _require(_digest(raw) == pin, "INSTALLED_SOURCE_PIN_CHANGED")
        for parent, name, child, expected in ancestry:
            _require(
                _identity(os.fstat(child))
                == expected
                == _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                "SOURCE_ANCESTRY_CHANGED",
            )
        return {"bytes": len(raw), "digest": pin}
    except BaseException as exc:
        primary = exc
        raise
    finally:
        _close_all(fds, failures)
        if failures:
            if primary is None:
                raise NativeBlockedCreateRevocationError("SOURCE_CLOSE_REFUSED")
            primary._native_revocation_cleanup = (
                *getattr(primary, "_native_revocation_cleanup", ()),
                *failures,
            )


def _environment(container, *, root):
    _require(
        type(container) is str
        and re.fullmatch(r"[0-9a-f]{64}", container)
        and sys.platform == "linux"
        and os.getpid() == threading.get_native_id(),
        "OWNED_LINUX_MAIN_THREAD_REQUIRED",
    )
    if root:
        _require(os.geteuid() == os.getegid() == 0, "ROOT_LAUNCHER_REQUIRED")
    fd = os.open("/proc/1/cgroup", _FLAGS)
    primary = None
    try:
        raw = os.read(fd, 1025)
        _require(
            raw == f"0::/docker/{container}/init.scope\n".encode("ascii"),
            "EXACT_OWNED_FIXTURE_REQUIRED",
        )
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(fd)
        except BaseException:
            if primary is None:
                raise NativeBlockedCreateRevocationError("CGROUP_CLOSE_REFUSED")
            primary._native_revocation_cleanup = (
                *getattr(primary, "_native_revocation_cleanup", ()),
                "CGROUP_CLOSE_REFUSED",
            )


def _alive(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    _require(not poll.poll(0), "OWNED_INIT_EXITED")


def _dependencies():
    if not __package__:
        sys.path.insert(0, "/usr/lib/aragorn")
    from aragorn import runtime_action_broker as broker
    from aragorn import runtime_action_service as service
    from aragorn import runtime_action_decision as decision

    return broker, service, decision


def _config(broker, identities, runtime):
    uid, runtime_uid, runtime_gid, sensor_uid, sensor_gid = identities
    control = Path(CONTROL)
    return broker.RuntimeActionBrokerConfig(
        socket_path=control / "broker.sock",
        instance_lock_path=control / "broker.instance.lock",
        lock_path=control / "broker.lock",
        control_root=control,
        protected_root=control.parent / "protected",
        staging_root=control.parent / "staging",
        policy_path=control / "policy.json",
        revocations_path=control / "revocations.json",
        health_path=control / "health.json",
        observation_path=control / "observation.json",
        state_path=control / "state.json",
        expected_broker_uid=uid,
        expected_peer_uid=sensor_uid,
        expected_peer_gid=sensor_gid,
        expected_runtime_digest=runtime,
        expected_runtime_uid=runtime_uid,
        expected_runtime_gid=runtime_gid,
    )


def _snapshot(fd, config, destination):
    for name in ("policy", "revocations", "state"):
        raw = _read_at(
            fd,
            name + ".json",
            uid=config.expected_broker_uid,
            mode=0o400,
            limit=_CONTROL_LIMIT,
        )
        _parse(raw)
        destination[name] = _record(raw)


def _document(record):
    return _parse(record["text"].encode("ascii"))


def _candidate(before, policy_pin, runtime, skill, decision):
    policy, current, state = (
        _document(before[name]) for name in ("policy", "revocations", "state")
    )
    _require(
        before["policy"]["digest"] == policy_pin
        and type(policy.get("allow")) is list
        and len(policy["allow"]) == 1
        and policy["allow"][0].get("runtime_digest") == runtime
        and policy["allow"][0].get("active_skill_digest") == skill,
        "PINNED_SAME_ACTION_POLICY_REQUIRED",
    )
    _require(
        set(state)
        == {
            "schema",
            "authority",
            "minimum_revocation_generation",
            "minimum_mediator_health_epoch",
            "consumed",
            "effect_journal",
        }
        and state["schema"] == "aragorn/runtime-action-broker-state/v2"
        and state["authority"] == "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY"
        and state["consumed"] == []
        and state["effect_journal"] is None
        and _uint(state["minimum_revocation_generation"], 1)
        and _uint(state["minimum_mediator_health_epoch"], 1)
        and type(current.get("skill_digests")) is list
        and current["skill_digests"] == []
        and _uint(current.get("generation"), 1),
        "UNUSED_CONTROL_STATE_REQUIRED",
    )
    _require(
        decision.qualify_runtime_revocation_generation(
            policy,
            current,
            minimum_revocation_generation=1,
            now_unix=current.get("observed_at_unix"),
        )
        == current["generation"],
        "CURRENT_REVOCATION_BINDING_REFUSED",
    )
    generation = max(current["generation"], state["minimum_revocation_generation"]) + 1
    now = int(time.time())
    _require(
        _uint(generation, 1) and _uint(now) and _uint(now + 15),
        "CONTROL_COUNTER_OR_TIME_REFUSED",
    )
    return {
        "schema": "aragorn/runtime-action-revocations/v1",
        "source_digest": policy["revocation_source_digest"],
        "generation": generation,
        "observed_at_unix": now,
        "expires_at_unix": now + 15,
        "skill_digests": [skill],
    }


def _run_child(container, policy_pin, runtime, skill, source_pin, broker_pin):
    report = {
        "schema": CHILD_SCHEMA,
        "authority": AUTHORITY,
        "status": "REFUSED",
        "container_id": container,
        "expected_policy_digest": policy_pin,
        "expected_runtime_digest": runtime,
        "expected_skill_digest": skill,
        "sources": {},
        "sources_after": {},
        "before": {},
        "after": {},
        "published": None,
        "publication_attempted": False,
        "refusal": None,
        "postcondition_failures": [],
        "cleanup_failures": [],
        "limitations": list(LIMITATIONS),
        **dict.fromkeys(FALSE_FLAGS, False),
    }
    descriptors, broker, lock, locked, control, init = [], None, None, False, None, None
    phase = "PREREQUISITES"
    try:
        for value in (policy_pin, runtime, skill, source_pin, broker_pin):
            _pin(value)
        _environment(container, root=False)
        report["sources"][SOURCE_PATH] = _source(SOURCE_PATH, source_pin, 0o444)
        report["sources"][BROKER_PATH] = _source(BROKER_PATH, broker_pin, 0o644)
        broker, service, decision = _dependencies()
        identities = service._service_identities()
        config = _config(broker, identities, runtime)
        broker._validate_config(config)
        init = os.pidfd_open(1, 0)
        descriptors.append(init)
        _alive(init)
        control = broker._open_protected_directory(
            config.control_root, identities[0], "fixed control root"
        )
        descriptors.append(control)
        root_identity = broker._directory_identity(os.fstat(control))
        lock = os.open(
            "broker.lock",
            os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=control,
        )
        descriptors.append(lock)
        item = os.fstat(lock)
        _require(
            stat.S_ISREG(item.st_mode)
            and item.st_uid == identities[0]
            and stat.S_IMODE(item.st_mode) == 0o600
            and item.st_nlink == 1
            and _identity(item)
            == _identity(os.stat("broker.lock", dir_fd=control, follow_symlinks=False)),
            "BROKER_LOCK_CUSTODY_REFUSED",
        )
        broker._acquire_lock(lock, time.monotonic() + 0.5)
        locked = True
        phase = "CONTROL_BEFORE"
        _snapshot(control, config, report["before"])
        candidate = _candidate(report["before"], policy_pin, runtime, skill, decision)
        raw = _canonical(candidate)
        report["published"] = _record(raw)
        _alive(init)
        _environment(container, root=False)
        _require(
            root_identity
            == broker._directory_identity(os.lstat(CONTROL))
            == broker._directory_identity(os.fstat(control)),
            "CONTROL_ROOT_CHANGED",
        )
        phase = "PUBLICATION"
        report["publication_attempted"] = True
        try:
            # The public publisher delegates to this exact primitive after the
            # same lock; reuse it with our NONBLOCK, already-verified lock FD.
            broker._publish_control_locked(
                control,
                config.revocations_path,
                candidate,
                raw,
                config,
                int(time.time()),
            )
        except BaseException as exc:
            report["cleanup_failures"].extend(
                getattr(exc, "_native_revocation_cleanup", ())
            )
            report["refusal"] = {
                "phase": phase,
                "reason": "CONTROL_PUBLICATION_REFUSED",
            }
        finally:
            for name in ("policy", "revocations", "state"):
                try:
                    observed = _read_at(
                        control,
                        name + ".json",
                        uid=identities[0],
                        mode=0o400,
                        limit=_CONTROL_LIMIT,
                    )
                    _parse(observed)
                    report["after"][name] = _record(observed)
                except BaseException as exc:
                    report["cleanup_failures"].extend(
                        getattr(exc, "_native_revocation_cleanup", ())
                    )
                    report["postcondition_failures"].append(
                        "AFTER_" + name.upper() + "_REFUSED"
                    )
            for name, path, pin, mode in (
                ("PUBLISHER", SOURCE_PATH, source_pin, 0o444),
                ("BROKER", BROKER_PATH, broker_pin, 0o644),
            ):
                try:
                    report["sources_after"][path] = _source(path, pin, mode)
                except BaseException as exc:
                    report["cleanup_failures"].extend(
                        getattr(exc, "_native_revocation_cleanup", ())
                    )
                    report["postcondition_failures"].append(
                        "AFTER_" + name + "_SOURCE_REFUSED"
                    )
        phase = "FINAL_READBACK"
        _require(
            report["refusal"] is None and not report["postcondition_failures"],
            "PUBLICATION_OR_AFTER_READBACK_REFUSED",
        )
        after_state = _document(report["after"]["state"])
        wanted_state = {
            **_document(report["before"]["state"]),
            "minimum_revocation_generation": candidate["generation"],
        }
        _require(
            report["after"]["policy"] == report["before"]["policy"]
            and report["after"]["revocations"] == report["published"]
            and after_state == wanted_state,
            "PUBLISHED_CONTROL_JOIN_REFUSED",
        )
        _require(
            int(time.time()) < candidate["expires_at_unix"],
            "PUBLICATION_ALREADY_EXPIRED",
        )
        _alive(init)
        _environment(container, root=False)
        _require(
            report["sources_after"] == report["sources"]
            and root_identity
            == broker._directory_identity(os.lstat(CONTROL))
            == broker._directory_identity(os.fstat(control)),
            "FINAL_SOURCE_OR_ROOT_CHANGED",
        )
        report["status"] = "PUBLISHED"
    except BaseException as exc:
        report["cleanup_failures"].extend(
            getattr(exc, "_native_revocation_cleanup", ())
        )
        if report["refusal"] is None:
            report["refusal"] = {
                "phase": phase,
                "reason": "FIXED_PUBLICATION_CHECK_REFUSED",
            }
    finally:
        if locked:
            try:
                broker.fcntl.flock(lock, broker.fcntl.LOCK_UN)
            except BaseException:
                report["cleanup_failures"].append("LOCK_RELEASE_REFUSED")
        _close_all(descriptors, report["cleanup_failures"])
        if report["cleanup_failures"]:
            report["status"] = "REFUSED"
            if report["refusal"] is None:
                report["refusal"] = {
                    "phase": "CLEANUP",
                    "reason": "PUBLICATION_CLEANUP_REFUSED",
                }
    return report


def _invoke(argv):
    """One owned process group; bounded stdout, zero tolerated stderr, no retry."""
    child = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
        cwd="/",
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    output, primary, failures = bytearray(), None, []
    try:
        deadline = time.monotonic() + 5
        with selectors.DefaultSelector() as selector:
            for stream in (child.stdout, child.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                _require(remaining > 0, "PUBLISHER_CHILD_TIMEOUT")
                for key, _ in selector.select(remaining):
                    stderr = key.fileobj is child.stderr
                    chunk = os.read(
                        key.fileobj.fileno(),
                        1 if stderr else min(65536, MAX_RESULT + 1 - len(output)),
                    )
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    _require(not stderr, "PUBLISHER_CHILD_UNEXPECTED_STDERR")
                    output.extend(chunk)
                    _require(len(output) <= MAX_RESULT, "PUBLISHER_CHILD_OUTPUT_LIMIT")
        return bytes(output), child.wait(
            timeout=max(0.001, deadline - time.monotonic())
        )
    except BaseException as exc:
        primary = exc
        exc._native_revocation_stdout = bytes(output[:MAX_RESULT])
        raise
    finally:
        terminate = primary is not None
        try:
            terminate = child.poll() is None or terminate
        except BaseException:
            terminate = True
            failures.append("PUBLISHER_POLL_REFUSED")
        if terminate:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException:
                failures.append("PUBLISHER_GROUP_TERMINATION_REFUSED")
        for close in (
            child.stdout.close,
            child.stderr.close,
            lambda: child.wait(timeout=3),
        ):
            try:
                close()
            except BaseException:
                failures.append("PUBLISHER_DESCRIPTOR_OR_REAP_REFUSED")
        if failures:
            if primary is not None:
                primary._native_revocation_cleanup = (
                    *getattr(primary, "_native_revocation_cleanup", ()),
                    *failures,
                )
            else:
                error = NativeBlockedCreateRevocationError(
                    "PUBLISHER_CHILD_CLEANUP_REFUSED"
                )
                error._native_revocation_stdout = bytes(output[:MAX_RESULT])
                error._native_revocation_cleanup = tuple(failures)
                raise error


def _retain_child_output(result, stdout):
    if type(stdout) is not bytes or not 0 < len(stdout) <= MAX_RESULT:
        return
    # Retain complete structured public reports; never expose unparsed child
    # diagnostics. Incomplete output remains explicitly digest/length-only.
    result["child_output"] = {"bytes": len(stdout), "digest": _digest(stdout)}
    if not stdout.endswith(b"\n"):
        return
    raw = stdout[:-1]
    try:
        document = _parse(raw)
        _require(
            document.get("schema") == CHILD_SCHEMA
            and document.get("authority") == AUTHORITY,
            "NONPUBLIC_CHILD_OUTPUT",
        )
        _require(
            set(document)
            == {
                "schema",
                "authority",
                "status",
                "container_id",
                "expected_policy_digest",
                "expected_runtime_digest",
                "expected_skill_digest",
                "sources",
                "sources_after",
                "before",
                "after",
                "published",
                "publication_attempted",
                "refusal",
                "postcondition_failures",
                "cleanup_failures",
                "limitations",
                *FALSE_FLAGS,
            },
            "NONPUBLIC_CHILD_FIELDS",
        )
    except Exception:
        return
    result["publication_raw"] = _record(raw)
    result["publication"] = document


def publish_native_blocked_create_revocation(
    *,
    expected_container_id,
    expected_policy_digest,
    expected_runtime_digest,
    expected_skill_digest,
    expected_source_digest,
    expected_broker_source_digest,
):
    """Launch the fixed publisher once; the caller owns the durable attempt claim."""
    result = {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "status": "REFUSED",
        "container_id": expected_container_id,
        "child_attempted": False,
        "publication": None,
        "publication_raw": None,
        "child_output": None,
        "refusal": None,
        "cleanup_failures": [],
        "limitations": list(LIMITATIONS),
        **dict.fromkeys(FALSE_FLAGS, False),
    }
    init, phase, interruption = None, "LAUNCH_PREREQUISITES", None
    try:
        pins = [
            expected_policy_digest,
            expected_runtime_digest,
            expected_skill_digest,
            expected_source_digest,
            expected_broker_source_digest,
        ]
        for pin in pins:
            _pin(pin)
        _environment(expected_container_id, root=True)
        _source(SOURCE_PATH, expected_source_digest, 0o444)
        _source(BROKER_PATH, expected_broker_source_digest, 0o644)
        init = os.pidfd_open(1, 0)
        _alive(init)
        uid = pwd.getpwnam("aragorn-broker").pw_uid
        runtime_gid = grp.getgrnam("aragorn-runtime").gr_gid
        sensor_gid = grp.getgrnam("aragorn-sensor").gr_gid
        _require(
            all(_uint(value, 1) for value in (uid, runtime_gid, sensor_gid))
            and runtime_gid != sensor_gid,
            "BROKER_LAUNCH_IDENTITIES_REFUSED",
        )
        argv = [
            "/usr/bin/setpriv",
            "--reuid",
            str(uid),
            "--regid",
            str(runtime_gid),
            "--groups",
            str(sensor_gid),
            "--no-new-privs",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            SOURCE_PATH,
            expected_container_id,
            *pins,
        ]
        phase = "PUBLISHER_CHILD"
        result["child_attempted"] = True
        stdout, returncode = _invoke(argv)
        _retain_child_output(result, stdout)
        document = result["publication"]
        _require(type(document) is dict, "PUBLISHER_OUTPUT_BOUND_REFUSED")
        _require(
            document.get("schema") == CHILD_SCHEMA
            and document.get("authority") == AUTHORITY
            and document.get("container_id") == expected_container_id
            and document.get("expected_policy_digest") == expected_policy_digest
            and document.get("expected_runtime_digest") == expected_runtime_digest
            and document.get("expected_skill_digest") == expected_skill_digest
            and all(document.get(flag) is False for flag in FALSE_FLAGS)
            and document.get("limitations") == list(LIMITATIONS),
            "PUBLISHER_ENVELOPE_REFUSED",
        )
        _require(
            returncode == 0
            and document.get("status") == "PUBLISHED"
            and document.get("publication_attempted") is True
            and document.get("refusal") is None
            and document.get("postcondition_failures") == []
            and document.get("cleanup_failures") == [],
            "PUBLISHER_DID_NOT_COMPLETE",
        )
        phase = "LAUNCH_FINAL_READBACK"
        _alive(init)
        _environment(expected_container_id, root=True)
        _source(SOURCE_PATH, expected_source_digest, 0o444)
        _source(BROKER_PATH, expected_broker_source_digest, 0o644)
        result["status"] = "PUBLISHED"
    except BaseException as exc:
        _retain_child_output(result, getattr(exc, "_native_revocation_stdout", None))
        result["cleanup_failures"].extend(
            getattr(exc, "_native_revocation_cleanup", ())
        )
        if not isinstance(exc, Exception):
            interruption = exc
        result["refusal"] = {"phase": phase, "reason": "FIXED_PUBLISHER_LAUNCH_REFUSED"}
    finally:
        if init is not None:
            _close_all([init], result["cleanup_failures"])
        if result["cleanup_failures"]:
            result["status"] = "REFUSED"
            if result["refusal"] is None:
                result["refusal"] = {
                    "phase": "LAUNCH_CLEANUP",
                    "reason": "LAUNCH_CLEANUP_REFUSED",
                }
    if interruption is not None:
        interruption._native_blocked_create_revocation = result
        raise interruption
    return result


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else list(argv)
    if len(arguments) != 6:
        return 64
    result = _run_child(*arguments)
    raw = _canonical(result)
    if len(raw) >= MAX_RESULT:
        return 126
    sys.stdout.buffer.write(raw + b"\n")
    return 0 if result["status"] == "PUBLISHED" else 126


if __name__ == "__main__":
    raise SystemExit(main())
