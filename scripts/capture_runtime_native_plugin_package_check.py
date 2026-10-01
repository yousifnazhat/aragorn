"""Capture only fixed inert plugin-package denial on the shared native runtime."""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT), str(_ROOT / "src")]

from scripts import capture_runtime_native_receipt_systemd_check as native
from scripts import materialize_native_plugin_package_fixture as fixture
from scripts import runtime_native_plugin_package_check as guest
from scripts import stage_runtime_native_startup_profile as profile

_CHECKER = "scripts/runtime_native_plugin_package_check.py"
_FILES = (
    native._HEALTH_FILES
    | native._STARTUP_FILES
    | {
        _CHECKER: "/opt/aragorn/runtime_native_plugin_package_check.py",
    }
)
_FIXTURE_SOURCES = (
    "benchmark/admission/openclaw-v2026.7.1/" + fixture._PROBE,
    "benchmark/admission/openclaw-v2026.7.1/protected-plugin-force-reinstall-v3-probe.py",
)
_SCHEMA = "aragorn/runtime-native-plugin-package-capture/v1"
_AUTHORITY = (
    "LOCAL_SUCCESSOR_PLUGIN_PACKAGE_DENIAL_NOT_ADMISSION_OR_PHASE3_QUALIFICATION"
)
acquisition = native.acquisition
existing = native.existing
_expect = native._expect


def _source() -> dict:
    source = existing.existing._source_identity()
    source["plugin_fixture_sources"] = {
        path: acquisition._tree_file(source["commit"], Path(path))
        for path in _FIXTURE_SOURCES
    }
    return source


def _audit_bundle(root: Path, manifest: dict) -> None:
    expected = {
        name: {"bytes": size, "digest": digest}
        for name, (size, digest) in guest._BUNDLE.items()
    }
    _expect(
        manifest["schema"] == "aragorn/native-plugin-package-fixture-bundle/v1"
        and manifest["route_id"] == guest._ROUTE
        and {
            item["name"]: {key: item[key] for key in ("bytes", "digest")}
            for item in manifest["files"]
        }
        == expected
        and len(manifest["files"]) == 10
        and all(value is False for value in manifest["decision"].values()),
        "plugin input manifest changed",
    )
    bundle = root / "plugin-package-skill-replacement"
    directories = {
        root,
        bundle,
        *(bundle / name for name in ("adapter", "baseline-source", "candidate-source")),
    }
    files = {bundle / name for name in expected}
    _expect(
        root.resolve(strict=True) == root
        and set(root.rglob("*")) == (directories - {root}) | files,
        "plugin input tree inventory changed",
    )
    for path in directories | files:
        metadata = path.lstat()
        directory = path in directories
        _expect(
            (
                stat.S_ISDIR(metadata.st_mode)
                if directory
                else stat.S_ISREG(metadata.st_mode)
            )
            and (metadata.st_uid, metadata.st_gid) == (os.geteuid(), os.getegid())
            and stat.S_IMODE(metadata.st_mode) == (0o555 if directory else 0o444)
            and (directory or metadata.st_nlink == 1),
            "plugin input tree custody changed",
        )
        if not directory:
            pin = expected[str(path.relative_to(bundle))]
            raw = path.read_bytes()
            _expect(
                (len(raw), acquisition._digest(raw)) == (pin["bytes"], pin["digest"]),
                "plugin input tree bytes changed",
            )


def _capture() -> dict:
    # Freeze all imported helpers and explicitly include both non-imported probes.
    source = _source()
    build = native._build_binding(source["commit"])
    helpers = {
        path: {
            **acquisition._tree_file(source["commit"], Path(path)),
            "installed_path": target,
            "installed_mode": "0444",
        }
        for path, target in _FILES.items()
    }
    parent = existing.campaign.current_v3_parent_identity()
    before = native.snapshot.snapshot_parent(parent)
    image = native._inspect("image", native._IMAGE)
    layers = before["image_inspect"]["RootFS"]["Layers"]
    _expect(
        image["Id"] == native._IMAGE
        and image["RootFS"]["Type"] == "layers"
        and image["RootFS"]["Layers"][: len(layers)] == layers
        and len(image["RootFS"]["Layers"]) > len(layers),
        "native fixture parent changed",
    )
    runtime_before = native._snapshot_runtime()
    owner = secrets.token_hex(32)
    name = "aragorn-native-plugin-package-" + owner[:16]
    with TemporaryDirectory(prefix="aragorn-native-plugin-package-") as temporary:
        work = Path(temporary).resolve()
        output = work / "stage"
        manifest = profile.stage_runtime_native_startup_profile(output)
        _expect(
            manifest["schema"] == profile._SCHEMA
            and manifest["authority"] == profile._AUTHORITY
            and (
                len(manifest["files"]),
                len(manifest["source_inputs"]),
                len(manifest["new_dependencies"]),
            )
            == (70, 84, 25)
            and manifest["required_runtime_not_included"]["tree"]
            == native.stage._RUNTIME_TREE
            and all(
                manifest[key] is False
                for key in (
                    "root_deployment",
                    "phase3_qualification",
                    "run_qualification",
                    "native_receipt_profile_deployed",
                    "receipt_state_provisioned",
                    "native_hook_reachability",
                    "native_causation_verified",
                    "mandatory_capture",
                )
            ),
            "native startup stage changed",
        )
        original, replacements = profile._verified_payloads()
        native.stage.base._audit_tree(output, original | replacements)
        payloads = {
            item["path"]: {
                "installed_path": item["path"],
                "installed_mode": item["mode"],
                "bytes": item["bytes"],
                "digest": item["digest"],
            }
            for item in manifest["files"]
        }
        _expect(len(payloads) == 70, "native destinations are not unique")
        inputs = work / "route-input"
        inputs.mkdir(mode=0o755)
        bundle_manifest = fixture.materialize(
            inputs / "plugin-package-skill-replacement"
        )
        inputs.chmod(0o555)
        _audit_bundle(inputs, bundle_manifest)
        started = existing.existing._now()
        try:
            container = (
                existing._docker(
                    *native._create_arguments(name, owner, source["commit"])
                )
                .decode("ascii")
                .strip()
            )
            _expect(
                re.fullmatch(r"[0-9a-f]{64}", container) is not None,
                "created container id changed",
            )
            inspected = native._inspect("container", container)
            native._verify_fixture(inspected, container, name, owner, source["commit"])
            existing._docker("cp", str(output) + "/.", container + ":/")
            native.stage.base._audit_tree(output, original | replacements)
            for path, target in _FILES.items():
                existing._docker("cp", str(_ROOT / path), container + ":" + target)
            existing._docker("cp", str(inputs), container + ":/")
            _audit_bundle(inputs, bundle_manifest)
            existing._docker("start", container)
            existing._docker(
                "exec",
                container,
                "/usr/bin/python3.12",
                "-I",
                "-S",
                "-B",
                "-c",
                native._HEALTH_VERIFY,
                json.dumps(payloads | helpers),
                container,
                json.dumps(manifest["directories"]),
                json.dumps([os.geteuid(), os.getegid()]),
            )
            argv = [
                "exec",
                container,
                "/usr/bin/python3.12",
                "-I",
                "-S",
                "-B",
                _FILES[_CHECKER],
                container,
                str(os.geteuid()),
                str(os.getegid()),
            ]
            raw = native.previous._journal_check(argv)
            observation = acquisition._load_json(raw, "plugin package observation")
            _expect(
                raw == acquisition._canonical(observation) + b"\n"
                and observation["schema"] == guest._SCHEMA
                and observation["authority"] == guest._AUTHORITY
                and observation["route_id"] == guest._ROUTE
                and observation["fixture_container"] == container
                and observation["status"] == "OBSERVED"
                and observation["input_mount_removed"] is True
                and all(
                    observation[key] is False
                    for key in (
                        "phase3_eligible",
                        "run_conformance_eligible",
                        "production_activation_eligible",
                    )
                ),
                "plugin package observation or proof ceiling changed",
            )
        finally:
            cleanup = native.snapshot._cleanup_snapshot(name, owner, native._IMAGE)
        _expect(
            cleanup["container_name_absent"] is True
            and cleanup["removed_id_absent"] is True,
            "plugin fixture cleanup unconfirmed",
        )
        _audit_bundle(inputs, bundle_manifest)
    runtime_after = native._snapshot_runtime()
    after = native.snapshot.snapshot_parent(parent)
    _expect(native.previous._parent_unchanged(before, after), "frozen parent changed")
    _expect(
        runtime_before["volume_inspect"] == runtime_after["volume_inspect"],
        "native runtime volume changed",
    )
    _expect(_source() == source, "source changed during capture")
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "status": "OBSERVED",
        "route_id": guest._ROUTE,
        "source": source,
        "build_observation": build,
        "staged_profile": manifest,
        "fixture_helpers": helpers,
        "input_bundle": bundle_manifest,
        "parent_identity": parent,
        "parent_before": before,
        "parent_after": after,
        "runtime_before": runtime_before,
        "runtime_after": runtime_after,
        "fixture_image": image,
        "fixture_container": container,
        "container_inspect": inspected,
        "invocation": {
            "argv": [*acquisition._DOCKER, *argv],
            "started_at": started,
            "completed_at": existing.existing._now(),
        },
        "observation": observation,
        "cleanup": cleanup,
        "phase3_eligible": False,
        "run_conformance_eligible": False,
        "production_activation_eligible": False,
    }


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1 or arguments[0].startswith("--"):
        print(
            "usage: capture_runtime_native_plugin_package_check ABSENT_OUTPUT_JSON",
            file=sys.stderr,
        )
        return 64
    output = Path(arguments[0])
    _expect(
        output.is_absolute() and not os.path.lexists(output),
        "output must be absent and absolute",
    )
    raw = acquisition._canonical(_capture()) + b"\n"
    acquisition._write_output(output, raw)
    print(
        json.dumps(
            {
                "status": "OBSERVED",
                "path": str(output),
                "digest": acquisition._digest(raw),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
