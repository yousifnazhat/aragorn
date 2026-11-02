"""Capture one bounded idle native sensor exit in a fresh owned container."""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT), str(_ROOT / "src")]

from scripts import capture_runtime_native_receipt_systemd_check as native
from scripts import runtime_native_sensor_loss_check as guest
from scripts import stage_runtime_native_startup_profile as profile

_CHECKER = "scripts/runtime_native_sensor_loss_check.py"
_FILES = (
    native._HEALTH_FILES
    | native._STARTUP_FILES
    | {
        _CHECKER: "/opt/aragorn/runtime_native_sensor_loss_check.py",
    }
)
acquisition, existing, _expect = native.acquisition, native.existing, native._expect


def _invoke_guest(argv: list[str], container: str) -> dict:
    result = subprocess.run(
        [*acquisition._DOCKER, *argv], capture_output=True, check=False, timeout=240
    )
    _expect(
        len(result.stdout) <= 2 * 1024 * 1024 and len(result.stderr) <= 1024,
        "sensor loss guest output exceeded its bound",
    )
    if result.returncode == 126 and not result.stdout:
        prefix = b"native sensor loss fixture refused: "
        _expect(
            result.stderr.startswith(prefix)
            and result.stderr.endswith(b"\n")
            and result.stderr.count(b"\n") == 1,
            "unrecognized sensor loss refusal envelope",
        )
        detail = result.stderr[len(prefix) : -1].decode("ascii")
        _expect(
            detail in guest._REFUSAL_REASONS
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", detail) is not None,
            "unrecognized sensor loss refusal detail",
        )
        return {
            "schema": "aragorn/runtime-native-sensor-loss-refusal/v1",
            "authority": "CONTROLLED_DIAGNOSTIC_ONLY_NOT_SENSOR_EXIT_OR_QUALIFICATION",
            "status": "REFUSED",
            "fixture_container": container,
            "exit_code": 126,
            "diagnostic": detail,
            "stderr_bytes": len(result.stderr),
            "stderr_digest": acquisition._digest(result.stderr),
            "guest_cleanup_authority": "NOT_ESTABLISHED_BY_DIAGNOSTIC",
            **dict.fromkeys(guest._FALSE_FLAGS, False),
        }
    _expect(
        result.returncode == 0 and not result.stderr,
        "sensor loss guest returned an unrecognized result",
    )
    observation = acquisition._load_json(
        result.stdout, "native sensor loss observation"
    )
    _expect(
        result.stdout == acquisition._canonical(observation) + b"\n"
        and observation["schema"] == guest._SCHEMA
        and observation["authority"] == guest._AUTHORITY
        and observation["status"] == "OBSERVED"
        and observation["fixture_container"] == container
        and observation["cleanup_sensor_reset_failed_after_terminal_evidence"] is True
        and all(observation[key] is False for key in guest._FALSE_FLAGS),
        "native sensor loss observation or proof ceiling changed",
    )
    return observation


def _capture() -> dict:
    source = existing.existing._source_identity()
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
    name = "aragorn-native-sensor-loss-" + owner[:16]
    with TemporaryDirectory(prefix="aragorn-native-sensor-loss-") as temporary:
        output = Path(temporary).resolve() / "stage"
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
        _expect(len(payloads) == 70, "native stage destinations are not unique")
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
                "created container identity changed",
            )
            inspected = native._inspect("container", container)
            native._verify_fixture(inspected, container, name, owner, source["commit"])
            existing._docker("cp", str(output) + "/.", container + ":/")
            native.stage.base._audit_tree(output, original | replacements)
            for path, target in _FILES.items():
                existing._docker("cp", str(_ROOT / path), container + ":" + target)
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
            ]
            observation = _invoke_guest(argv, container)
        finally:
            cleanup = native.snapshot._cleanup_snapshot(name, owner, native._IMAGE)
        _expect(
            cleanup["container_name_absent"] is True
            and cleanup["removed_id_absent"] is True,
            "owned sensor loss fixture cleanup unconfirmed",
        )
    runtime_after = native._snapshot_runtime()
    after = native.snapshot.snapshot_parent(parent)
    _expect(native.previous._parent_unchanged(before, after), "frozen parent changed")
    _expect(
        runtime_before["volume_inspect"] == runtime_after["volume_inspect"],
        "runtime volume changed",
    )
    _expect(
        existing.existing._source_identity() == source,
        "source changed during sensor loss capture",
    )
    return {
        "schema": "aragorn/runtime-native-sensor-loss-capture/v1",
        "authority": "LOCAL_SUCCESSOR_SENSOR_EXIT_OBSERVATION_NOT_PHASE3_OR_RUN_QUALIFICATION",
        "status": observation["status"],
        "source": source,
        "build_observation": build,
        "staged_profile": manifest,
        "fixture_helpers": helpers,
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
        **dict.fromkeys(guest._FALSE_FLAGS, False),
    }


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print(
            "usage: capture_runtime_native_sensor_loss_check ABSENT_OUTPUT_JSON",
            file=sys.stderr,
        )
        return 64
    output = Path(arguments[0])
    _expect(
        output.is_absolute() and not os.path.lexists(output),
        "output must be absent and absolute",
    )
    capture = _capture()
    raw = acquisition._canonical(capture) + b"\n"
    acquisition._write_output(output, raw)
    print(
        json.dumps(
            {
                "status": capture["status"],
                "path": str(output),
                "digest": acquisition._digest(raw),
            }
        )
    )
    return 0 if capture["status"] == "OBSERVED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
