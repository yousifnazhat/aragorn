"""One fixed native plugin-update request, capture and independent offline replay.

The caller retains the intent and its complete input closure before invocation.
The guest publishes a nonsecret request before activation in guest-local CAS;
this is not a host ACK, external attestation or final campaign qualification.
No arbitrary route, command, retry, VM start or service activation on the host.
"""

from __future__ import annotations

import argparse
from io import BytesIO
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT), str(_ROOT / "src")]

from scripts import capture_runtime_native_plugin_update_identity_check as prior
from aragorn import native_phase3_plugin_update_case as case
from aragorn import native_phase3_plugin_update_collection as collection
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

_GUEST = "scripts/runtime_native_plugin_update_case.py"
_BUNDLE_PATH = "/opt/aragorn/native-plugin-update-case-inputs.json"
_BUNDLE_SCHEMA = "aragorn/native-plugin-update-case-inputs/v1"
_GUEST_SCHEMA = "aragorn/native-plugin-update-case-guest/v1"
_GUEST_AUTHORITY = "GUEST_LOCAL_PREACTIVATION_COMMITMENT_NOT_HOST_ACK_OR_QUALIFICATION"
_LIMIT = 2 * 1024 * 1024
_MODULES = (
    "phase3_deployment",
    "native_phase3_plugin_update_binding",
    "native_phase3_plugin_update_live_binding",
    "native_phase3_plugin_update_case",
)
_FILES = prior._FILES | {
    _GUEST: "/opt/aragorn/runtime_native_plugin_update_case.py",
    **{
        f"src/aragorn/{name}.py": f"/usr/lib/aragorn/aragorn/{name}.py"
        for name in _MODULES
    },
}
_FALSE = (
    "route_qualified",
    "phase3_eligible",
    "run_conformance_eligible",
    "production_activation_eligible",
    "common_deployment_fully_verified",
    "live_deployment_attested",
    "metrics_eligible",
    "fresh_campaign_execution",
    "preactivation_commit_verified",
)

# A fixed two-file seal in the already verified owned fixture. No caller path,
# archive extraction, arbitrary destination or retry enters this child program.
_SEAL = """import hashlib,os,stat,sys
items=(('/opt/aragorn/native-plugin-update-identity-pins.json',16384,sys.argv[1]),('/opt/aragorn/native-plugin-update-case-inputs.json',2097152,sys.argv[2]))
def ident(s):
 return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
for p,limit,pin in items:
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  s=os.fstat(fd)
  assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o444
  assert (s.st_uid,s.st_gid) in ((0,0),(int(sys.argv[3]),int(sys.argv[4])))
  raw=b''
  while len(raw)<=limit:
   chunk=os.read(fd,min(65536,limit+1-len(raw)))
   if not chunk: break
   raw+=chunk
  assert 0<len(raw)<=limit and not os.read(fd,1)
  assert 'sha256:'+hashlib.sha256(raw).hexdigest()==pin
  assert ident(os.stat(p,follow_symlinks=False))==ident(os.fstat(fd))==ident(s)
  os.fchown(fd,0,0)
  final=os.fstat(fd)
  assert (final.st_uid,final.st_gid)==(0,0)
  assert ident(os.stat(p,follow_symlinks=False))==ident(final)
 finally: os.close(fd)
"""


def _inspect(store: CAS, intent_pin: str) -> dict:
    raw = store.read(case._pin(intent_pin), max_bytes=16384)
    return case.validate_native_plugin_update_case_intent(
        raw, expected_intent_digest=intent_pin, evidence_cas=store
    )


def _bundle(inspected: dict, intent_pin: str) -> bytes:
    blobs = inspected["input_blobs"]
    case._require(0 < len(blobs) <= 32, "case input inventory exceeds bound")
    raw = canonical_json(
        {
            "schema": _BUNDLE_SCHEMA,
            "intent_digest": intent_pin,
            "blobs": {pin: value.decode("utf-8") for pin, value in blobs.items()},
        }
    )
    case._require(len(raw) <= _LIMIT, "case input bundle exceeds bound")
    return raw


def _source_guard(inspected: dict) -> dict:
    intent = inspected["intent"]
    # Match the inherited source recorder's fixed update probe inventory before
    # any parent snapshot, Docker call, fixture creation or activation.
    with patch.object(
        prior.prior.prior, "_FIXTURE_SOURCES", prior.prior._FIXTURE_SOURCES
    ):
        source = prior.prior.prior._source()
    case._require(
        source["commit"] == intent["source_commit"]
        and canonical_json(source)
        == inspected["input_blobs"][intent["source_record_digest"]],
        "signed checkout differs from retained intent source",
    )
    for mapping in (intent["controller_source_digests"], intent["live_source_digests"]):
        for path, pin in mapping.items():
            entry = prior._api._tree_file(intent["source_commit"], Path(path))
            raw = inspected["input_blobs"][pin]
            case._require(
                entry["digest"] == pin and entry["bytes"] == len(raw),
                "controller source differs",
            )
            _source_bytes(_ROOT / path, raw)
    return source


def _source_bytes(path: Path, expected: bytes) -> None:
    case._require(
        len(expected) <= 1024 * 1024
        and not any(part.is_symlink() for part in (path, *path.parents)),
        "controller source custody changed",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        case._require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_size == len(expected),
            "controller source metadata changed",
        )
        raw = stream.read(len(expected) + 1)
        after = os.fstat(stream.fileno())
    named = path.lstat()
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
    case._require(
        raw == expected
        and all(
            getattr(before, key) == getattr(after, key) == getattr(named, key)
            for key in fields
        ),
        "working controller source differs",
    )


def _stage_guard(manifest: dict, inspected: dict) -> None:
    intent, blobs = inspected["intent"], inspected["input_blobs"]
    deployment = case._parse(blobs[intent["deployment_digest"]])
    profile = case._parse(blobs[deployment["bindings"]["os_profile"]])["identity"]
    case._require(
        manifest["schema"] == profile["staged_schema"]
        and len(manifest["files"]) == 70
        and len({item["path"] for item in manifest["files"]}) == 70
        and not ({item["path"] for item in manifest["files"]} & set(_FILES.values()))
        and case._digest(canonical_json(manifest["files"]))
        == profile["staged_files_digest"],
        "staged profile differs from common deployment",
    )


def _invoke(
    argv: list[str], container: str, inspected: dict, intent_pin: str, bundle: bytes
) -> dict:
    case._require(
        type(container) is str
        and re.fullmatch(r"[0-9a-f]{64}", container) is not None
        and type(argv) is list
        and argv
        == [
            "exec",
            container,
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            _FILES[_GUEST],
            container,
            str(os.geteuid()),
            str(os.getegid()),
        ]
        and bundle == _bundle(inspected, intent_pin),
        "fixed case guest invocation changed",
    )
    intent, blobs = inspected["intent"], inspected["input_blobs"]
    static_pin = intent["static_pin_manifest_digest"]
    static = blobs[static_pin]
    bundle_pin = case._digest(bundle)
    with TemporaryDirectory(prefix="aragorn-native-case-inputs-") as temporary:
        for name, raw, target in (
            ("static.json", static, prior._MANIFEST),
            ("case.json", bundle, _BUNDLE_PATH),
        ):
            path = Path(temporary) / name
            prior._api._write_output(path, raw)
            path.chmod(0o444)
            prior.prior.prior.existing._docker(
                "cp", str(path), container + ":" + target
            )
        prior.prior.prior.existing._docker(
            "exec",
            container,
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "-c",
            _SEAL,
            static_pin,
            bundle_pin,
            str(os.geteuid()),
            str(os.getegid()),
        )
    completed = subprocess.run(
        [*prior._api._DOCKER, *argv, static_pin, bundle_pin, intent_pin],
        capture_output=True,
        check=False,
        timeout=240,
    )
    case._require(
        completed.returncode in (0, 126)
        and not completed.stderr
        and 0 < len(completed.stdout) <= 4 * 1024 * 1024,
        "case guest returned no bounded envelope",
    )
    value = prior._api._load_json(completed.stdout, "native case guest")
    case._require(
        type(value) is dict
        and set(value)
        == {
            "schema",
            "authority",
            "status",
            "case_id",
            "branch",
            "fixture_container",
            "input_bundle_digest",
            "intent_digest",
            "identity_observation",
            "prepared_case",
            "refusal",
            *_FALSE,
        }
        and completed.stdout == canonical_json(value) + b"\n"
        and value["schema"] == _GUEST_SCHEMA
        and value["authority"] == _GUEST_AUTHORITY
        and value["status"] == ("OBSERVED" if completed.returncode == 0 else "REFUSED")
        and value["case_id"] == case.ROUTE
        and value["branch"] == case.BRANCH
        and value["fixture_container"] == container
        and value["input_bundle_digest"] == bundle_pin
        and value["intent_digest"] == intent_pin
        and all(value[key] is False for key in _FALSE),
        "case guest contract or qualification ceiling changed",
    )
    if value["prepared_case"] is not None:
        _prepared_case(value["prepared_case"])
    case._require(
        value["status"] != "OBSERVED"
        or (
            value["prepared_case"] is not None
            and type(value["identity_observation"]) is dict
            and value["refusal"] is None
        ),
        "observed case lacks prepared identity evidence",
    )
    return value


def _prepared_case(value: object) -> None:
    case._require(
        type(value) is dict
        and set(value)
        == {
            "request",
            "request_digest",
            "local_pre_activation_readback",
            "authority",
            "host_ack_received",
            *_FALSE,
        }
        and value["authority"] == _GUEST_AUTHORITY
        and value["local_pre_activation_readback"] is True
        and value["host_ack_received"] is False
        and all(value[key] is False for key in _FALSE)
        and case._digest(canonical_json(value["request"]))
        == case._pin(value["request_digest"]),
        "guest local publication claim changed",
    )


def _capture(store: CAS, intent_pin: str) -> dict:
    inspected = _inspect(CAS(store.root, read_only=True), intent_pin)
    intent = inspected["intent"]
    source = _source_guard(inspected)
    bundle = _bundle(inspected, intent_pin)
    guest = None
    live_sources = None
    stage = prior.prior.prior.profile.stage_runtime_native_startup_profile
    static = inspected["input_blobs"][intent["static_pin_manifest_digest"]]
    pins = prior._pins(static, intent["static_pin_manifest_digest"])["file_digests"]

    def checked_stage(output):
        manifest = stage(output)
        _stage_guard(manifest, inspected)
        prior._stage_pins(manifest, pins)
        return manifest

    def invoke(argv, container):
        nonlocal guest, live_sources
        case._require(
            guest is None and live_sources is None, "case guest already invoked"
        )
        _source_guard(inspected)
        live_sources = {
            path: prior._api._tree_file(source["commit"], Path(path))
            for path in case.LIVE_SOURCE_PATHS
        }
        guest = _invoke(argv, container, inspected, intent_pin, bundle)
        live = guest["identity_observation"]
        if guest["status"] == "REFUSED":
            return {"status": "REFUSED", **dict.fromkeys(_FALSE, False)}
        case._require(
            live["status"] == "OBSERVED", "identity observation was not completed"
        )
        return prior._original_observation(live["update_observation"], container)

    # Reuse the exact owned native fixture lifecycle and original 13-file bundle;
    # only the outer guest/controller wiring is new. Never use frozen-v3 dispatch.
    with (
        patch.multiple(
            prior.prior, _CHECKER=_GUEST, _FILES=_FILES, _invoke_guest=invoke
        ),
        patch.object(
            prior.prior.prior.profile,
            "stage_runtime_native_startup_profile",
            checked_stage,
        ),
    ):
        captured = prior.prior._capture()
    _source_guard(inspected)
    case._require(
        guest is not None and live_sources is not None and captured["source"] == source,
        "case capture source changed",
    )
    live = dict(guest["identity_observation"] or {})
    live.pop("update_observation", None)
    captured["live_identity"] = live
    captured["live_identity_sources"] = live_sources
    captured["invocation"]["argv"].extend(
        [intent["static_pin_manifest_digest"], case._digest(bundle), intent_pin]
    )
    return {
        "capture": captured,
        "guest": guest,
        "input_bundle_digest": case._digest(bundle),
    }


def _retain(store: CAS, intent_pin: str, executed: dict) -> dict:
    inspected = _inspect(CAS(store.root, read_only=True), intent_pin)
    intent, blobs = inspected["intent"], inspected["input_blobs"]
    captured, guest = executed["capture"], executed["guest"]
    raw = canonical_json(captured) + b"\n"
    capture_pin = store.put(BytesIO(raw), max_bytes=len(raw))
    result = {
        "schema": "aragorn/native-plugin-update-case-capture/v1",
        "status": guest["status"],
        "intent_digest": intent_pin,
        "capture_digest": capture_pin,
        "guest": guest,
        "input_bundle_digest": executed["input_bundle_digest"],
        "collection_digest": None,
        "verification": None,
        **dict.fromkeys(_FALSE, False),
    }
    if guest["status"] != "OBSERVED":
        return result
    prepared = guest["prepared_case"]
    _prepared_case(prepared)
    request_raw = canonical_json(prepared["request"])
    store.put_expected(
        BytesIO(request_raw),
        expected_digest=prepared["request_digest"],
        max_bytes=16384,
    )
    common = {
        "expected_capture_digest": capture_pin,
        "expected_source_digest": intent["source_record_digest"],
        "expected_source_commit": intent["source_commit"],
    }
    projected = collection.prepare_native_plugin_update_collection(raw, **common)
    retained = collection.collect_native_plugin_update_live_observation(
        raw,
        **common,
        deployment_raw=projected["deployment_raw"],
        expected_deployment_digest=projected["deployment_digest"],
        expected_live_identity_digest=case._digest(
            canonical_json(captured["live_identity"])
        ),
        static_pin_manifest_raw=blobs[intent["static_pin_manifest_digest"]],
        expected_static_pin_manifest_digest=intent["static_pin_manifest_digest"],
        live_source_raws={
            path: blobs[pin] for path, pin in intent["live_source_digests"].items()
        },
        expected_live_source_digests=intent["live_source_digests"],
        evidence_cas=store,
    )
    result["collection_digest"] = retained["collection_digest"]
    result["verification"] = case.verify_native_plugin_update_case(
        request_raw,
        expected_request_digest=prepared["request_digest"],
        expected_intent_digest=intent_pin,
        expected_collection_digest=retained["collection_digest"],
        evidence_cas=CAS(store.root, read_only=True),
    )
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "capture", "replay"):
        command = commands.add_parser(name)
        command.add_argument("--cas", required=True, type=Path)
        command.add_argument("--expected-intent-digest", required=True)
        if name == "capture":
            command.add_argument("--out", required=True, type=Path)
        if name == "replay":
            command.add_argument("--expected-request-digest", required=True)
            command.add_argument("--expected-collection-digest", required=True)
    args = parser.parse_args(argv)
    try:
        case._require(args.cas.is_absolute(), "CAS must be absolute")
        readonly = CAS(args.cas, read_only=True)
        if args.command == "inspect":
            inspected = _inspect(readonly, args.expected_intent_digest)
            value = {
                "status": "INPUT_CLOSURE_VERIFIED",
                "intent": inspected["intent"],
                "blob_count": len(inspected["input_blobs"]),
                **dict.fromkeys(_FALSE, False),
            }
        elif args.command == "replay":
            raw = readonly.read(
                case._pin(args.expected_request_digest), max_bytes=16384
            )
            value = case.verify_native_plugin_update_case(
                raw,
                expected_request_digest=args.expected_request_digest,
                expected_intent_digest=args.expected_intent_digest,
                expected_collection_digest=args.expected_collection_digest,
                evidence_cas=readonly,
            )
        else:
            case._require(
                args.out.is_absolute() and not os.path.lexists(args.out),
                "output must be absent and absolute",
            )
            store = CAS(args.cas)
            executed = _capture(store, args.expected_intent_digest)
            # Preserve the one-shot envelope even if later offline retention
            # refuses. No consumer failure can cause an automatic effect retry.
            prior._api._write_output(args.out, canonical_json(executed) + b"\n")
            value = _retain(store, args.expected_intent_digest, executed)
            value["capture_envelope_path"] = str(args.out)
        print(json.dumps(value, sort_keys=True))
        return 2 if value.get("status") == "REFUSED" else 0
    except Exception as error:
        print(
            json.dumps(
                {
                    "status": "REFUSED",
                    "reason": "NATIVE_CASE_PREREQUISITE_OR_EXECUTION_FAILED",
                    "diagnostic": prior._failure_location(error),
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
