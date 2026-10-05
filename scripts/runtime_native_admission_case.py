"""Prepare and dispatch one direct-write case in the owned admission successor.

The old plugin-update entrypoints and frozen setup remain unchanged. This guest
only accepts the new direct-write intent; other admitted inventory entries are
not executable here. The host owns creation, isolation, teardown and VM state.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from unittest.mock import patch

if __package__:
    from scripts import runtime_native_plugin_package_check as package
    from scripts import runtime_native_plugin_update_case as storage
    from scripts import runtime_native_plugin_update_identity_check as writer_parent
else:
    sys.path[:0] = ["/usr/lib/aragorn", str(Path(__file__).resolve().parent)]
    import runtime_native_plugin_package_check as package
    import runtime_native_plugin_update_case as storage
    import runtime_native_plugin_update_identity_check as writer_parent

from aragorn import native_phase3_admission_case as case
from aragorn import native_phase3_admission_direct_write as direct
from aragorn import native_phase3_live_identity as identity
from aragorn.oci_worker_protocol import canonical_json

SCHEMA = "aragorn/native-admission-case-guest/v1"
AUTHORITY = (
    "GUEST_LOCAL_PREACTIVATION_NATIVE_ADMISSION_CASE_NOT_HOST_ACK_OR_QUALIFICATION"
)
BUNDLE_SCHEMA = "aragorn/native-admission-case-inputs/v1"
BUNDLE_PATH = "/opt/aragorn/native-admission-case-inputs.json"
CAS_ROOT = "/run/aragorn-native-admission-case"
_FALSE_FLAGS = storage._FALSE_FLAGS
_FALSE = _FALSE_FLAGS
_MAX_INPUT = 2 * 1024 * 1024
_MAX_REQUEST = 16384
_OVERRIDE_PATHS = (
    "/usr/lib/systemd/system/aragorn-agent-gateway.service",
    "/usr/libexec/aragorn/activate-runtime-action-worker-host.sh",
)
_LEAF_SOURCE = "scripts/runtime_native_admission_direct_write.py"
_VERIFIER_SOURCE = "src/aragorn/native_phase3_admission_direct_write.py"
_STAMPS = writer_parent._STAMPS


class NativeAdmissionCaseGuestError(ValueError):
    """Only fixed reasons; no input or native diagnostic text is included."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise NativeAdmissionCaseGuestError(reason)


def _environment(container: str, copied_owner: tuple[int, int]) -> None:
    _require(
        sys.platform == "linux" and os.geteuid() == os.getegid() == 0,
        "LINUX_ROOT_GUEST_REQUIRED",
    )
    _require(
        type(container) is str
        and re.fullmatch(r"[0-9a-f]{64}", container) is not None
        and type(copied_owner) is tuple
        and len(copied_owner) == 2
        and all(
            type(value) is int and 0 <= value <= 2**32 - 1 for value in copied_owner
        ),
        "INVALID_OWNED_FIXTURE_ARGUMENTS",
    )
    with open("/proc/1/cgroup", "rb") as stream:
        raw = stream.read(1025)
    _require(
        raw == f"0::/docker/{container}/init.scope\n".encode("ascii"),
        "EXACT_OWNED_SYSTEMD_FIXTURE_REQUIRED",
    )


def _read_bundle(expected: str, intent_pin: str) -> dict[str, bytes]:
    writer_parent._pin(expected)
    writer_parent._pin(intent_pin)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw, _ = identity._read_at(
            fd, BUNDLE_PATH, owner=0, owner_gid=0, modes={0o444}, limit=_MAX_INPUT
        )
    finally:
        os.close(fd)
    # Reuse only its byte/inventory parser with the explicitly different schema.
    # No old intent/route validation or old observation envelope is invoked.
    with patch.object(storage, "BUNDLE_SCHEMA", BUNDLE_SCHEMA):
        return storage._parse_bundle(raw, expected, intent_pin)


@contextmanager
def _fresh_store():
    # The inherited primitive has no route fields and validates the actual fixed
    # root below. Its held-directory checks and read-only CAS handles are reused.
    with patch.object(storage, "CAS_ROOT", CAS_ROOT):
        with storage._fresh_store() as opened:
            yield opened


def _overrides(bound: dict) -> dict:
    intent, blobs = bound["intent"], bound["input_blobs"]
    profile = direct.parse(blobs[intent["staged_profile_digest"]])
    _require(
        profile["schema"] == "aragorn/runtime-native-admission-staged-profile/v1"
        and len(profile["files"]) == 70,
        "ADMISSION_PROFILE_REQUIRED",
    )
    files = {item["path"]: item for item in profile["files"]}
    _require(len(files) == 70, "DUPLICATE_PROFILE_PATH")
    result = {}
    for path, mode in zip(_OVERRIDE_PATHS, (0o644, 0o755), strict=True):
        row = files[path]
        _require(
            row["mode"] == f"{mode:04o}"
            and type(row["bytes"]) is int
            and 0 < row["bytes"] <= 131072,
            "PROFILE_OVERRIDE_CHANGED",
        )
        result[path] = (row["bytes"], writer_parent._pin(row["digest"])[7:], mode)
    return result


def _pin_sources(bound: dict, native) -> dict:
    """Read exact new helper bytes before setup; the host still binds their source."""
    expected = bound["intent"]["case_source_digests"]
    result = {}
    for source, installed in (
        (_LEAF_SOURCE, direct.PROBE),
        (_VERIFIER_SOURCE, direct.VERIFIER),
    ):
        raw = native.response._read_regular(Path(installed), 0, {0o444})
        _require(raw == bound["input_blobs"][expected[source]], "LEAF_SOURCE_CHANGED")
        result[installed] = {"bytes": len(raw), "digest": direct.digest(raw)}
    return result


def _prepare(native, before_activation, *, state=None):
    """Intercept the existing seven writers and existing single activation seam."""
    p37b = writer_parent._p37b()
    inputs = {}
    if state is None:
        state = {
            "activation_count": 0,
            "pins_frozen_before_activation": False,
            "provisioning_file_digests": {},
        }
    _require(
        state["activation_count"] == 0
        and state["pins_frozen_before_activation"] is False
        and state["provisioning_file_digests"] == {},
        "PROVISIONING_STATE_NOT_FRESH",
    )
    document_writer = p37b._write_document
    control_writer = p37b.capability._write_control
    genesis_writer = native.provision._create_document
    activate = native._activate

    def record(path, raw):
        if path not in writer_parent.DYNAMIC_PATHS:
            return
        _require(
            not state["pins_frozen_before_activation"]
            and path not in inputs
            and type(raw) is bytes
            and 0 < len(raw) <= _MAX_INPUT,
            "PROVISIONING_WRITE_INVENTORY_CHANGED",
        )
        inputs[path] = raw
        state["provisioning_file_digests"][path] = direct.digest(raw)

    def document(path, value, *args, **kwargs):
        raw = canonical_json(value)
        record(str(path), raw)
        result = document_writer(path, value, *args, **kwargs)
        _require(canonical_json(value) == raw, "PROVISIONING_WRITER_MUTATED_INPUT")
        return result

    def control(path, value, *args, **kwargs):
        raw = canonical_json(value) if str(path) == identity._POLICY else None
        if raw is not None:
            record(str(path), raw)
        result = control_writer(path, value, *args, **kwargs)
        _require(
            raw is None or canonical_json(value) == raw, "POLICY_WRITER_MUTATED_INPUT"
        )
        return result

    def genesis(parent, name, raw, held):
        if name == Path(identity._GENESIS).name:
            record(identity._GENESIS, raw)
        return genesis_writer(parent, name, raw, held)

    def freeze_then_activate(*args, **kwargs):
        _require(
            not state["pins_frozen_before_activation"]
            and state["activation_count"] == 0
            and set(inputs) == set(writer_parent.DYNAMIC_PATHS),
            "PREACTIVATION_PIN_INVENTORY_INCOMPLETE",
        )
        state["pins_frozen_before_activation"] = True
        detached = dict(inputs)
        try:
            before_activation(detached, state)
        finally:
            detached.clear()
            inputs.clear()
        state["activation_count"] += 1
        return activate(*args, **kwargs)

    try:
        with (
            patch.object(p37b, "_write_document", document),
            patch.object(p37b.capability, "_write_control", control),
            patch.object(native.provision, "_create_document", genesis),
            patch.object(native, "_activate", freeze_then_activate),
        ):
            setup = native._prepare()
        _require(
            state["activation_count"] == 1 and state["pins_frozen_before_activation"],
            "SINGLE_ACTIVATION_NOT_COMPLETED",
        )
        return setup, state
    finally:
        inputs.clear()


def _invoke_leaf(
    container: str, before: dict, setup: dict, bound: dict, token: str
) -> dict:
    gateway = before["processes"]["gateway"]
    pins = bound["intent"]["case_source_digests"]
    _require(re.fullmatch(r"[0-9a-f]{64}", token) is not None, "FIXTURE_TOKEN_REQUIRED")
    with ExitStack() as held:
        pidfd = identity._open_pidfd(gateway)
        held.callback(os.close, pidfd)
        namespace = os.open(
            f"/proc/{gateway['pid']}/ns/mnt", os.O_RDONLY | os.O_CLOEXEC
        )
        held.callback(os.close, namespace)
        namespace_stat = os.fstat(namespace)
        _require(
            {"device": namespace_stat.st_dev, "inode": namespace_stat.st_ino}
            == gateway["mount_namespace"]
            and identity.process._process_start_time(gateway["pid"])
            == gateway["start_time_ticks"]
            and identity.process._process_cgroup(gateway["pid"]) == gateway["cgroup"],
            "GATEWAY_CHANGED_BEFORE_LEAF",
        )
        argv = [
            "/usr/bin/nsenter",
            f"--mount=/proc/self/fd/{namespace}",
            "--",
            "/usr/bin/setpriv",
            "--reuid=992",
            "--regid=992",
            "--groups=992",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--bounding-set=-all",
            "--no-new-privs",
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            direct.PROBE,
            "--container",
            container,
            "--gateway-pid",
            str(gateway["pid"]),
            "--admitted-digest",
            setup["skill_digest"],
            "--probe-digest",
            pins[_LEAF_SOURCE],
            "--verifier-digest",
            pins[_VERIFIER_SOURCE],
        ]
        environment = {
            "OPENCLAW_GATEWAY_TOKEN": token,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
        }
        identity.process.require_live_pidfd(pidfd)
        result = subprocess.run(
            argv,
            env=environment,
            stdin=subprocess.DEVNULL,
            cwd="/var/lib/aragorn-agent-gateway/workspace",
            capture_output=True,
            check=False,
            timeout=150,
            pass_fds=(namespace,),
        )
        identity.process.require_live_pidfd(pidfd)
        _require(
            identity.process._process_start_time(gateway["pid"])
            == gateway["start_time_ticks"]
            and identity.process._process_cgroup(gateway["pid"]) == gateway["cgroup"],
            "GATEWAY_CHANGED_AFTER_LEAF",
        )
    _require(
        result.returncode in (0, 126)
        and not result.stderr
        and 0 < len(result.stdout) <= _MAX_INPUT
        and token.encode("ascii") not in result.stdout,
        "LEAF_EXECUTION_REFUSED",
    )
    value = direct.parse(result.stdout)
    _require(
        canonical_json(value) + b"\n" == result.stdout
        and value["schema"] == direct.SCHEMA
        and value["authority"] == direct.AUTHORITY
        and value["case_id"] == direct.CASE_ID
        and value["fixture_container"] == container
        and value["gateway_pid"] == gateway["pid"]
        and value["admitted_digest"] == setup["skill_digest"]
        and value["source_pins"]
        == {direct.PROBE: pins[_LEAF_SOURCE], direct.VERIFIER: pins[_VERIFIER_SOURCE]}
        and value["status"] == ("OBSERVED" if result.returncode == 0 else "REFUSED")
        and all(value[key] is False for key in direct.FALSE_FLAGS),
        "LEAF_ENVELOPE_CHANGED",
    )
    return {
        "document": value,
        "execution": {
            "argv": argv,
            "exit_code": result.returncode,
            "stdout": result.stdout.decode("ascii"),
            "stdout_bytes": len(result.stdout),
            "stdout_digest": direct.digest(result.stdout),
            "stderr_bytes": 0,
            "effective_identity": {"uid": 992, "gid": 992, "groups": [992]},
            "environment_names": sorted(environment),
        },
        "verification": None,
    }


def _leaf_live_joins(leaf: dict, live: dict) -> dict:
    """Bind the leaf's process and loaded configuration to both root reads."""
    for boundary in ("before", "after"):
        observed = leaf[boundary]
        gateway = live[boundary]["processes"]["gateway"]
        subject = observed["gateway"]
        _require(
            subject["pid"] == gateway["pid"]
            and subject["start_time_ticks"] == gateway["start_time_ticks"]
            and subject["cgroup"] == "0::" + gateway["cgroup"] + "\n"
            and subject["mount_namespace"] == gateway["mount_namespace"]["inode"]
            and subject["uid"] == gateway["uids"]
            and subject["gid"] == gateway["gids"],
            "LEAF_GATEWAY_LIVE_JOIN_CHANGED",
        )
        credential = live[boundary]["loaded_process_views"]["gateway"][
            "openclaw-config"
        ]
        _require(
            observed["config"]["read_only"] is True
            and {
                key: observed["config"][key] for key in ("identity", "bytes", "digest")
            }
            == credential,
            "LEAF_LOADED_CONFIGURATION_JOIN_CHANGED",
        )
    return {
        "status": "BOUNDED_LEAF_ROOT_READBACK_JOINS_MATCH",
        "joined": [
            "gateway_pid",
            "gateway_start_time_ticks",
            "gateway_cgroup",
            "gateway_mount_namespace_inode",
            "gateway_uids_and_gids",
            "loaded_configuration_identity_bytes_and_digest",
        ],
        "authority": "LOCAL_OBSERVER_JOINS_NOT_EXTERNAL_ATTESTATION_OR_QUALIFICATION",
        **dict.fromkeys(_FALSE_FLAGS, False),
    }


def _run(
    container: str,
    copied_owner: tuple[int, int],
    expected_bundle_digest: str,
    expected_intent_digest: str,
) -> dict:
    result = {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "status": "REFUSED",
        "case_id": case.DIRECT_WRITE_CASE,
        "branch": case.DIRECT_WRITE_BRANCH,
        "fixture_container": container,
        "input_bundle_digest": expected_bundle_digest,
        "intent_digest": expected_intent_digest,
        "static_pin_manifest_digest": None,
        "prepared_case": None,
        "setup": None,
        "installed_sources": None,
        "installed_sources_after": None,
        "live_identity": {
            "before": None,
            "after": None,
            "comparison": None,
            "expected_file_digests": {},
            "provisioning_file_digests": {},
            "pins_frozen_before_activation": False,
            "activation_count": 0,
            "invocation_count": 0,
            "boundaries_monotonic_ns": dict.fromkeys(_STAMPS),
        },
        "leaf": None,
        "fixture_stack_cleanup": None,
        "refusal": None,
        "post_observation": {},
        "postcondition_failures": [],
        **dict.fromkeys(_FALSE_FLAGS, False),
    }
    phase = "ENVIRONMENT"
    native = None
    cleanup_required = False
    try:
        _environment(container, copied_owner)
        phase = "BUNDLE_INPUT"
        blobs = _read_bundle(expected_bundle_digest, expected_intent_digest)
        intent_raw = blobs[expected_intent_digest]
        selected = direct.parse(intent_raw)
        _require(
            selected.get("case_id") == case.DIRECT_WRITE_CASE,
            "SELECTED_CASE_NOT_EXECUTABLE_BY_THIS_GUEST",
        )
        with _fresh_store() as (writer, reader, guard):
            for pin, raw in blobs.items():
                if pin != expected_intent_digest:
                    writer.put_expected(
                        io.BytesIO(raw), expected_digest=pin, max_bytes=_MAX_INPUT
                    )
            writer.put_expected(
                io.BytesIO(intent_raw),
                expected_digest=expected_intent_digest,
                max_bytes=_MAX_INPUT,
            )
            guard()
            phase = "INPUT_CLOSURE"
            bound = case.validate_native_admission_case_intent(
                intent_raw,
                expected_intent_digest=expected_intent_digest,
                evidence_cas=reader,
            )
            _require(bound["input_blobs"] == blobs, "BUNDLE_INPUT_CLOSURE_CHANGED")
            static_pin = bound["intent"]["static_pin_manifest_digest"]
            static = writer_parent._parse_static_manifest(blobs[static_pin], static_pin)
            result["static_pin_manifest_digest"] = static_pin
            overrides = _overrides(bound)
            phase = "OWNED_BOOTSTRAP"
            native = package._native()
            native.setup_prior._require_fixture(container)
            cleanup_required = True
            with patch.object(
                native, "_STARTUP_CODE", native._STARTUP_CODE | overrides
            ):
                phase = "SOURCE_IDENTITY"
                result["installed_sources"] = native._sources(
                    health=True, startup_reserve=True
                )
                leaf_sources = _pin_sources(bound, native)
                import runtime_native_cgroup_prerequisite as cgroup

                prerequisites = cgroup.observe(container)
                _require(
                    prerequisites["status"] == "READY", "CGROUP_PREREQUISITE_REFUSED"
                )
                callback_calls = 0

                def commit_before_activation(inputs, state):
                    nonlocal callback_calls, phase
                    phase = "PREACTIVATION_PREPARATION"
                    callback_calls += 1
                    _require(callback_calls == 1, "DUPLICATE_PREACTIVATION_CALLBACK")
                    result["live_identity"].update(state)
                    expected = (
                        static["file_digests"] | state["provisioning_file_digests"]
                    )
                    _require(
                        set(expected) == set(identity.FILE_PATHS),
                        "LIVE_PIN_INVENTORY_CHANGED",
                    )
                    result["live_identity"]["expected_file_digests"] = expected
                    prepared = case.prepare_native_admission_case(
                        intent_raw,
                        expected_intent_digest=expected_intent_digest,
                        evidence_cas=reader,
                        provisioning_inputs=inputs,
                    )
                    request_raw, request_pin = (
                        prepared["request_raw"],
                        prepared["request_digest"],
                    )
                    _require(
                        canonical_json(prepared["request"]) == request_raw,
                        "PREPARED_REQUEST_BYTES_CHANGED",
                    )
                    phase = "PREACTIVATION_PUBLICATION"
                    writer.put_expected(
                        io.BytesIO(request_raw),
                        expected_digest=request_pin,
                        max_bytes=_MAX_REQUEST,
                    )
                    _require(
                        reader.read(request_pin, max_bytes=_MAX_REQUEST) == request_raw,
                        "PREACTIVATION_REQUEST_READBACK_CHANGED",
                    )
                    guard()
                    result["prepared_case"] = {
                        "request": prepared["request"],
                        "request_digest": request_pin,
                        "local_pre_activation_readback": True,
                        "host_ack_received": False,
                        "authority": AUTHORITY,
                        **dict.fromkeys(_FALSE_FLAGS, False),
                    }
                    phase = "ACTIVATION"

                phase = "PROVISIONING"
                setup, state = _prepare(
                    native, commit_before_activation, state=result["live_identity"]
                )
                result["setup"] = setup
                result["live_identity"].update(state)
                _require(
                    callback_calls == 1 and result["prepared_case"] is not None,
                    "PREACTIVATION_COMMIT_NOT_COMPLETED",
                )
                phase = "STARTUP_IDENTITY"
                budget = native._checked_startup_budget(container, cgroup)
                installed = native.setup_prior._installed(setup["skill_digest"])
                _require(installed["denial"] is None, "ADMITTED_SKILL_NOT_ACTIVE")
                p37b = writer_parent._p37b()
                effects = p37b._snapshot_effects()
                live, stamps = (
                    result["live_identity"],
                    result["live_identity"]["boundaries_monotonic_ns"],
                )
                read_args = {
                    "expected_container_id": container,
                    "expected_file_digests": live["expected_file_digests"],
                }
                phase = "BEFORE_READ"
                stamps["before_read_started_ns"] = time.monotonic_ns()
                live["before"] = identity.read_native_live_identity(**read_args)
                stamps["before_read_finished_ns"] = time.monotonic_ns()
                phase = "LEAF_INVOCATION"
                live["invocation_count"] += 1
                stamps["invocation_started_ns"] = time.monotonic_ns()
                invocation_error = None
                try:
                    result["leaf"] = _invoke_leaf(
                        container,
                        live["before"],
                        setup,
                        bound,
                        native._fixture_token(p37b),
                    )
                except Exception as error:
                    invocation_error = error
                finally:
                    stamps["invocation_finished_ns"] = time.monotonic_ns()

                # Possible effects are never retried. Each fixed post-readback
                # is independent so one lost source cannot hide other evidence.
                phase = "POST_INVOCATION_READBACKS"
                post = result["post_observation"]
                failures = result["postcondition_failures"]

                def readback(name, observe, expected=None, *, compare=False):
                    try:
                        post[name] = observe()
                        _require(
                            not compare or post[name] == expected,
                            "POST_INVOCATION_STATE_CHANGED",
                        )
                    except Exception:
                        failures.append(name)
                    return post.get(name)

                stamps["after_read_started_ns"] = time.monotonic_ns()
                live["after"] = readback(
                    "LIVE_IDENTITY_AFTER",
                    lambda: identity.read_native_live_identity(**read_args),
                )
                stamps["after_read_finished_ns"] = time.monotonic_ns()
                if live["after"] is not None:
                    live["comparison"] = readback(
                        "LIVE_IDENTITY_COMPARISON",
                        lambda: identity.compare_native_live_identity(
                            live["before"], live["after"]
                        ),
                    )
                result["installed_sources_after"] = readback(
                    "INSTALLED_SOURCES_AFTER",
                    lambda: native._sources(health=True, startup_reserve=True),
                    result["installed_sources"],
                    compare=True,
                )
                readback(
                    "LEAF_SOURCES_AFTER",
                    lambda: _pin_sources(bound, native),
                    leaf_sources,
                    compare=True,
                )
                readback(
                    "INSTALLED_SKILL_AFTER",
                    lambda: native.setup_prior._installed(setup["skill_digest"]),
                    installed,
                    compare=True,
                )
                receipt_after = readback(
                    "RECEIPT_STORE_AFTER",
                    lambda: native._snapshot(
                        setup["provisioning"]["genesis_digest"], 0
                    ),
                    setup["empty_store"],
                    compare=True,
                )
                readback(
                    "PROTECTED_EFFECTS_AFTER",
                    p37b._snapshot_effects,
                    effects,
                    compare=True,
                )
                budget_after = readback(
                    "STARTUP_BUDGET_AFTER",
                    lambda: native._checked_startup_budget(container, cgroup),
                )
                result["setup"]["admission_observation"] = {
                    "cgroup_prerequisites": prerequisites,
                    "startup_task_budget": budget,
                    "startup_task_budget_after": budget_after,
                    "installed": installed,
                    "empty_receipt_store_after": receipt_after,
                    "protected_effects_unchanged": "PROTECTED_EFFECTS_AFTER"
                    not in failures,
                    "leaf_sources": leaf_sources,
                }
                if invocation_error is not None:
                    phase = "LEAF_INVOCATION"
                    raise invocation_error
                _require(not failures, "POST_INVOCATION_READBACK_REFUSED")
                phase = "LEAF_SEMANTIC_REPLAY"
                leaf = result["leaf"]["document"]
                _require(leaf["status"] == "OBSERVED", "DIRECT_WRITE_LEAF_REFUSED")
                joins = _leaf_live_joins(leaf, live)
                leaf_raw = canonical_json(leaf)
                source_pins = bound["intent"]["case_source_digests"]
                result["leaf"]["verification"] = (
                    direct.verify_native_admission_direct_write(
                        leaf_raw,
                        expected_raw_digest=direct.digest(leaf_raw),
                        expected_container=container,
                        expected_gateway_pid=live["before"]["processes"]["gateway"][
                            "pid"
                        ],
                        expected_admitted_digest=setup["skill_digest"],
                        expected_probe_digest=source_pins[_LEAF_SOURCE],
                        expected_verifier_digest=source_pins[_VERIFIER_SOURCE],
                    )
                )
                result["leaf"]["verification"]["native_live_identity_joins"] = joins
                phase = "FINAL_REQUEST_READBACK"
                committed = result["prepared_case"]
                _require(
                    reader.read(committed["request_digest"], max_bytes=_MAX_REQUEST)
                    == canonical_json(committed["request"]),
                    "FINAL_REQUEST_READBACK_CHANGED",
                )
                guard()
                values = list(stamps.values())
                _require(
                    all(type(value) is int and value > 0 for value in values)
                    and values == sorted(values)
                    and live["activation_count"] == live["invocation_count"] == 1,
                    "SINGLE_CASE_CHRONOLOGY_CHANGED",
                )
                result["status"] = "OBSERVED"
    except Exception as error:
        result["status"] = "REFUSED"
        result["refusal"] = {
            "phase": phase,
            "reason": str(error)
            if type(error) is NativeAdmissionCaseGuestError
            else "FIXED_ADMISSION_GUEST_REFUSED",
        }
    finally:
        if cleanup_required:
            try:
                result["fixture_stack_cleanup"] = native.prior._stop_fixture()
            except Exception:
                result["status"] = "REFUSED"
                result["refusal"] = {
                    "phase": "CLEANUP",
                    "reason": "OWNED_SERVICE_CLEANUP_UNCONFIRMED",
                    "preceding_refusal": result["refusal"],
                }
    return result


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if (
        len(args) != 5
        or re.fullmatch(r"[0-9a-f]{64}", args[0]) is None
        or any(re.fullmatch(r"[0-9]{1,10}", value) is None for value in args[1:3])
    ):
        return 64
    result = _run(args[0], tuple(int(value) for value in args[1:3]), args[3], args[4])
    sys.stdout.buffer.write(canonical_json(result) + b"\n")
    return 0 if result["status"] == "OBSERVED" else 126


if __name__ == "__main__":
    raise SystemExit(main())
