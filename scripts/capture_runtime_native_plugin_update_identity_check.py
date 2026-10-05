"""One owned update capture with caller-pinned, bracketed native identity.

This successor composes the frozen adapter; it never replays an update on error.
The old observation and 13-file input bundle are preserved, with separate live
identity evidence. Static pins must be obtained independently before invocation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT), str(_ROOT / "src")]

from scripts import capture_runtime_native_plugin_update_check as prior
from aragorn import native_phase3_live_identity as identity

_CHECKER = "scripts/runtime_native_plugin_update_identity_check.py"
_READER = "src/aragorn/native_phase3_live_identity.py"
_HOST = "scripts/capture_runtime_native_plugin_update_identity_check.py"
_SOURCES = (_HOST, _CHECKER, _READER)
_FILES = prior._FILES | {
    _CHECKER: "/opt/aragorn/runtime_native_plugin_update_identity_check.py",
    _READER: "/usr/lib/aragorn/aragorn/native_phase3_live_identity.py",
}
_STATIC_PATHS = (*identity._CODE, identity._PYTHON, "/usr/local/bin/node")
_MANIFEST = "/opt/aragorn/native-plugin-update-identity-pins.json"
_STATIC_SCHEMA = "aragorn/native-plugin-update-identity-static-pins/v1"
_LIVE_SCHEMA = "aragorn/runtime-native-plugin-update-identity-observation/v1"
_LIVE_AUTHORITY = (
    "OWNED_UPDATE_ADAPTER_WITH_LOCAL_LIVE_IDENTITY_NOT_ROUTE_OR_RUN_QUALIFICATION"
)
_LIMIT = 4 * 1024 * 1024
_expect = prior.prior._expect
_api = prior.prior.acquisition

# This runs only inside the already verified, exact owned container. The file
# was just copied there; no arbitrary destination, symlink or retry is accepted.
_SEAL = """import hashlib,json,os,stat,sys
p='/opt/aragorn/native-plugin-update-identity-pins.json'
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
def ident(s):
 return tuple(getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
try:
 s=os.fstat(fd)
 assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o444
 assert (s.st_uid,s.st_gid) in ((0,0),(int(sys.argv[2]),int(sys.argv[3])))
 raw=os.read(fd,16385)
 assert len(raw)<=16384 and not os.read(fd,1)
 assert 'sha256:'+hashlib.sha256(raw).hexdigest()==sys.argv[1]
 assert ident(os.stat(p,follow_symlinks=False))==ident(os.fstat(fd))==ident(s)
 os.fchown(fd,0,0)
 final=os.fstat(fd)
 assert (final.st_uid,final.st_gid)==(0,0)
 assert ident(os.stat(p,follow_symlinks=False))==ident(final)
finally:
 os.close(fd)
"""


def _pins(raw: bytes, expected: str) -> dict:
    _expect(
        type(expected) is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", expected) is not None
        and len(raw) <= 16384
        and _api._digest(raw) == expected,
        "static manifest differs from caller pin",
    )
    value = _api._load_json(raw, "static identity pins")
    _expect(
        raw == _api._canonical(value)
        and set(value) == {"schema", "file_digests"}
        and value["schema"] == _STATIC_SCHEMA
        and type(value["file_digests"]) is dict
        and set(value["file_digests"]) == set(_STATIC_PATHS)
        and all(
            type(pin) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", pin)
            for pin in value["file_digests"].values()
        ),
        "static identity pin inventory or encoding changed",
    )
    return value


def _read_pins(path: Path, expected: str) -> bytes:
    _expect(path.is_absolute(), "static manifest path must be absolute")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        _expect(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_size <= 16384,
            "static manifest must be one bounded regular file",
        )
        raw = os.read(fd, 16385)
        _expect(
            identity.broker._file_identity(os.fstat(fd))
            == identity.broker._file_identity(path.stat(follow_symlinks=False))
            == identity.broker._file_identity(before),
            "static manifest changed while reading",
        )
    finally:
        os.close(fd)
    _pins(raw, expected)
    return raw


def _stage_pins(manifest: dict, pins: dict) -> None:
    files = {item["path"]: item for item in manifest["files"]}
    for path in identity._CODE:
        if path == identity._ENTRY:
            expected = prior.prior.native.stage._ENTRYPOINT[1]
        else:
            expected = files[path]["digest"]
        _expect(pins[path] == expected, "caller static pin differs from staged profile")


def _invoke(argv: list[str], container: str, pin_raw: bytes, pin_digest: str) -> dict:
    # Copy only after the predecessor has verified ownership, network isolation,
    # staged payload custody and startup prerequisites. Its finally owns cleanup.
    with TemporaryDirectory(prefix="aragorn-native-identity-pins-") as temporary:
        path = Path(temporary) / "pins.json"
        _api._write_output(path, pin_raw)
        path.chmod(0o444)
        prior.prior.existing._docker("cp", str(path), container + ":" + _MANIFEST)
        prior.prior.existing._docker(
            "exec",
            container,
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "-c",
            _SEAL,
            pin_digest,
            str(os.geteuid()),
            str(os.getegid()),
        )
    result = subprocess.run(
        [*_api._DOCKER, *argv, pin_digest],
        capture_output=True,
        check=False,
        timeout=240,
    )
    _expect(
        len(result.stdout) <= _LIMIT and len(result.stderr) <= 8192,
        "identity guest output exceeded bound",
    )
    _expect(
        result.returncode in (0, 126) and not result.stderr,
        "identity guest returned no accepted envelope",
    )
    value = _api._load_json(result.stdout, "native identity observation")
    _expect(
        result.stdout == _api._canonical(value) + b"\n"
        and value["schema"] == _LIVE_SCHEMA
        and value["authority"] == _LIVE_AUTHORITY
        and value["route_id"] == prior.guest._ROUTE
        and value["branch"] == "TRACKED_LOCAL_MARKETPLACE_DIRECTORY_UPDATE"
        and value["fixture_container"] == container
        and (
            value["static_pin_manifest"] == _pins(pin_raw, pin_digest)
            or (result.returncode == 126 and value["static_pin_manifest"] is None)
        )
        and value["static_pin_manifest_digest"] == pin_digest
        and value["status"] == ("OBSERVED" if result.returncode == 0 else "REFUSED")
        and all(
            value[key] is False
            for key in (
                "phase3_eligible",
                "run_conformance_eligible",
                "production_activation_eligible",
                "route_qualified",
                "common_deployment_fully_verified",
                "live_deployment_attested",
            )
        ),
        "identity guest envelope or proof ceiling changed",
    )
    return value


def _original_observation(value: object, container: str) -> dict:
    # Preserve the frozen host's acceptance predicates without calling its
    # invocation function (which would perform a second update).
    _expect(
        type(value) is dict
        and value["schema"] == prior.guest._SCHEMA
        and value["authority"] == prior.guest._AUTHORITY
        and value["route_id"] == prior.guest._ROUTE
        and value["fixture_container"] == container
        and value["status"] == "OBSERVED"
        and value["branch"] == "TRACKED_LOCAL_MARKETPLACE_DIRECTORY_UPDATE"
        and value["input_mount_removed"] is True
        and value["inherited_input_restored"] is True
        and value["input_mount_source"] == str(prior.guest._STAGED)
        and all(
            value[key] is False
            for key in (
                "route_qualified",
                "phase3_eligible",
                "run_conformance_eligible",
                "production_activation_eligible",
            )
        ),
        "original update observation or proof ceiling changed",
    )
    return value


def _capture(pin_raw: bytes, pin_digest: str) -> dict:
    pins = _pins(pin_raw, pin_digest)["file_digests"]
    live = None
    source_before = None
    stage = prior.prior.profile.stage_runtime_native_startup_profile

    def checked_stage(output):
        manifest = stage(output)
        _stage_pins(manifest, pins)
        return manifest

    def invoke(argv, container):
        nonlocal live, source_before
        # The predecessor verifies its signed source before fixture creation.
        # Resolve our extra source entries at that same immutable commit now;
        # compare again after cleanup before any evidence is published.
        commit = prior.prior._source()["commit"]
        source_before = {path: _api._tree_file(commit, Path(path)) for path in _SOURCES}
        live = _invoke(argv, container, pin_raw, pin_digest)
        observation = live.pop("update_observation")
        if live["status"] == "REFUSED":
            return {
                "schema": "aragorn/runtime-native-plugin-update-identity-refusal/v1",
                "status": "REFUSED",
                "fixture_container": container,
                "phase3_eligible": False,
                "run_conformance_eligible": False,
                "production_activation_eligible": False,
            }
        return _original_observation(observation, container)

    with (
        patch.multiple(prior, _CHECKER=_CHECKER, _FILES=_FILES, _invoke_guest=invoke),
        patch.object(
            prior.prior.profile, "stage_runtime_native_startup_profile", checked_stage
        ),
    ):
        value = prior._capture()
    _expect(
        live is not None and source_before is not None, "identity guest was not invoked"
    )
    _expect(
        source_before
        == {
            path: _api._tree_file(value["source"]["commit"], Path(path))
            for path in _SOURCES
        },
        "identity source changed during capture",
    )
    value["live_identity"] = live
    value["live_identity_sources"] = source_before
    value["invocation"]["argv"].append(pin_digest)
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser(
        "capture", help="run one owned isolated update fixture; no retries"
    )
    capture.add_argument("--static-pins", type=Path, required=True)
    capture.add_argument("--expected-static-pins-digest", required=True)
    capture.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        _expect(
            args.out.is_absolute() and not os.path.lexists(args.out),
            "output must be absent and absolute",
        )
        raw = _read_pins(args.static_pins, args.expected_static_pins_digest)
        document = _capture(raw, args.expected_static_pins_digest)
        encoded = _api._canonical(document) + b"\n"
        _api._write_output(args.out, encoded)
        print(
            json.dumps(
                {
                    "status": document["status"],
                    "path": str(args.out),
                    "digest": _api._digest(encoded),
                }
            )
        )
        return 0 if document["status"] == "OBSERVED" else 2
    except Exception:
        # Never echo a helper exception, fixture token, command output or path.
        print(
            json.dumps(
                {
                    "status": "REFUSED",
                    "reason": "CAPTURE_PREREQUISITE_OR_EXECUTION_FAILED",
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
