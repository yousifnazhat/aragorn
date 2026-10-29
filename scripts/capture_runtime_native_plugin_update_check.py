"""Capture only the offline tracked-marketplace update branch in a fresh fixture."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT), str(_ROOT / "src")]

from scripts import capture_runtime_native_plugin_package_check as prior
from scripts import materialize_native_plugin_update_fixture as fixture
from scripts import runtime_native_plugin_update_check as guest

_SCHEMA = "aragorn/runtime-native-plugin-update-capture/v1"
_AUTHORITY = (
    "LOCAL_TRACKED_MARKETPLACE_UPDATE_BRANCH_NOT_ADMISSION_OR_PHASE3_QUALIFICATION"
)
_CHECKER = "scripts/runtime_native_plugin_update_check.py"
_FILES = (
    prior.native._HEALTH_FILES
    | prior.native._STARTUP_FILES
    | {
        _CHECKER: "/opt/aragorn/runtime_native_plugin_update_check.py",
        "scripts/runtime_native_plugin_package_check.py": "/opt/aragorn/runtime_native_plugin_package_check.py",
    }
)
_FIXTURE_SOURCES = tuple(
    "benchmark/admission/openclaw-v2026.7.1/" + name
    for name in (
        fixture._PROBE,
        "protected-plugin-package-skill-replacement-probe.py",
        "protected-plugin-force-reinstall-v3-probe.py",
        "seed-plugin-marketplace-update-record.mjs",
    )
)
_HOST_PIN = "sha256:3f07fb8b09f5e6fc88410fff76b13bf3e826efc953963af18c985d09d20a9a33"


def _audit_bundle(root, manifest):
    expected = {
        name: {"bytes": size, "digest": digest}
        for name, (size, digest) in guest._BUNDLE.items()
    }
    prior._expect(
        manifest["schema"] == fixture._SCHEMA
        and manifest["route_id"] == guest._ROUTE
        and manifest["branch"] == "TRACKED_LOCAL_MARKETPLACE_DIRECTORY_UPDATE"
        and {
            item["name"]: {key: item[key] for key in ("bytes", "digest")}
            for item in manifest["files"]
        }
        == expected
        and len(manifest["files"]) == 13
        and all(item is False for item in manifest["decision"].values()),
        "update input manifest changed",
    )
    bundle = root / "plugin-package-skill-replacement"
    directories = {
        root,
        bundle,
        *(bundle / name for name in ("adapter", "baseline-source", "candidate-source")),
    }
    files = {bundle / name for name in expected}
    prior._expect(
        root.resolve(strict=True) == root
        and set(root.rglob("*")) == (directories - {root}) | files,
        "update input inventory changed",
    )
    for path in directories | files:
        metadata = path.lstat()
        directory = path in directories
        prior._expect(
            (
                stat.S_ISDIR(metadata.st_mode)
                if directory
                else stat.S_ISREG(metadata.st_mode)
            )
            and (metadata.st_uid, metadata.st_gid) == (os.geteuid(), os.getegid())
            and stat.S_IMODE(metadata.st_mode) == (0o555 if directory else 0o444)
            and (directory or metadata.st_nlink == 1),
            "update input custody changed",
        )
        if not directory:
            raw = path.read_bytes()
            prior._expect(
                {"bytes": len(raw), "digest": prior.acquisition._digest(raw)}
                == expected[str(path.relative_to(bundle))],
                "update input bytes changed",
            )


def _invoke_guest(argv, container):
    result = subprocess.run(
        [*prior.acquisition._DOCKER, *argv],
        capture_output=True,
        check=False,
        timeout=240,
    )
    prior._expect(
        len(result.stdout) <= 2 * 1024 * 1024 and len(result.stderr) <= 8192,
        "update guest output exceeded bound",
    )
    if result.returncode == 126 and not result.stdout:
        lines = result.stderr.splitlines(keepends=True)
        prior._expect(len(lines) == 2, "update refusal is not a controlled diagnostic")
        diagnostic = guest._decode_diagnostic(lines[1], None)
        envelope = (
            "native plugin update fixture refused: PLUGIN_PACKAGE_DENIAL: adapter "
            + diagnostic["reason"]
            + "\n"
        ).encode("ascii")
        prior._expect(lines[0] == envelope, "update refusal envelope changed")
        return {
            "schema": "aragorn/runtime-native-plugin-update-refusal/v1",
            "authority": "CONTROLLED_DIAGNOSTIC_ONLY_NOT_DENIAL_OR_QUALIFICATION",
            "route_id": guest._ROUTE,
            "fixture_container": container,
            "status": "REFUSED",
            "exit_code": 126,
            "diagnostic": diagnostic,
            "stderr_bytes": len(result.stderr),
            "stderr_digest": prior.acquisition._digest(result.stderr),
            "guest_cleanup_authority": "NOT_ESTABLISHED_BY_DIAGNOSTIC",
            "phase3_eligible": False,
            "run_conformance_eligible": False,
            "production_activation_eligible": False,
        }
    prior._expect(
        result.returncode == 0 and not result.stderr,
        "update guest returned no accepted observation",
    )
    value = prior.acquisition._load_json(result.stdout, "plugin update observation")
    prior._expect(
        result.stdout == prior.acquisition._canonical(value) + b"\n"
        and value["schema"] == guest._SCHEMA
        and value["authority"] == guest._AUTHORITY
        and value["route_id"] == guest._ROUTE
        and value["fixture_container"] == container
        and value["status"] == "OBSERVED"
        and value["route_qualified"] is False
        and value["branch"] == "TRACKED_LOCAL_MARKETPLACE_DIRECTORY_UPDATE"
        and value["input_mount_removed"] is True
        and value["inherited_input_restored"] is True
        and value["input_mount_source"] == str(guest._STAGED)
        and all(
            value[key] is False
            for key in (
                "phase3_eligible",
                "run_conformance_eligible",
                "production_activation_eligible",
            )
        ),
        "update observation or proof ceiling changed",
    )
    return value


def _capture():
    prior._expect(
        prior.acquisition._digest(Path(prior.__file__).read_bytes()) == _HOST_PIN,
        "pinned host fixture helper changed",
    )
    # Keep inherited signed-source, exact runtime/parent, owned cleanup, RO input
    # overlay and startup safeguards. Replace only this route's inputs/operation.
    with patch.multiple(
        prior,
        fixture=fixture,
        guest=guest,
        _CHECKER=_CHECKER,
        _FILES=_FILES,
        _FIXTURE_SOURCES=_FIXTURE_SOURCES,
        _SCHEMA=_SCHEMA,
        _AUTHORITY=_AUTHORITY,
        _invoke_guest=_invoke_guest,
        _audit_bundle=_audit_bundle,
    ):
        value = prior._capture()
    value["branch"] = "TRACKED_LOCAL_MARKETPLACE_DIRECTORY_UPDATE"
    value["route_qualified"] = False
    value["inherited_capture_helper_digest"] = _HOST_PIN
    return value


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1 or args[0].startswith("--"):
        return 64
    output = Path(args[0])
    prior._expect(
        output.is_absolute() and not os.path.lexists(output),
        "output must be absent and absolute",
    )
    document = _capture()
    raw = prior.acquisition._canonical(document) + b"\n"
    prior.acquisition._write_output(output, raw)
    print(
        json.dumps(
            {
                "status": document["status"],
                "path": str(output),
                "digest": prior.acquisition._digest(raw),
            }
        )
    )
    return 0 if document["status"] == "OBSERVED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
