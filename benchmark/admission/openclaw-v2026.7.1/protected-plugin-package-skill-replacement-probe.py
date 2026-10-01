"""Observe policy denial of one inert plugin package carrying replacement skills."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import types
from pathlib import Path

ROUTE = "ADM-02/update/plugin-package-skill-replacement"
PLUGIN_ID = "aragorn-plugin-skill-replacement-fixture"
ROOT = Path("/route-input/plugin-package-skill-replacement")
BASE_NAME = "protected-plugin-force-reinstall-v3-probe.py"
BASE_PIN = (
    30362,
    "sha256:58ba8c44ef474588dd48c8afaca01681c26d8a0b45c153994463c87e719f115a",
)
_MAIN = b"\n\ntry:\n    output = main(sys.argv[1:])"
_ELIGIBILITY = (
    "admission_profile_eligible",
    "aggregate_admission_eligible",
    "edr_eligible",
    "installer_work_eligible",
    "phase3_exit_eligible",
    "release_eligible",
    "run_01_eligible",
    "run_02_eligible",
    "run_eligible",
)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    ).encode("ascii")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def fixture_files(version: str) -> dict[str, bytes]:
    if version not in {"1.0.0", "2.0.0"}:
        raise ValueError("only the two fixed inert package versions are supported")
    label = "baseline" if version == "1.0.0" else "candidate"
    return {
        "index.js": (
            'export default { id: "' + PLUGIN_ID + '", '
            'name: "Aragorn inert plugin skills fixture", register() {} };\n'
        ).encode("ascii"),
        "openclaw.plugin.json": canonical(
            {
                "id": PLUGIN_ID,
                "name": "Aragorn inert plugin skills fixture",
                "version": version,
                "skills": ["."],
                "configSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            }
        )
        + b"\n",
        "package.json": canonical(
            {
                "name": "@aragorn/plugin-skill-replacement-fixture",
                "private": True,
                "type": "module",
                "version": version,
                "openclaw": {"extensions": ["./index.js"]},
            }
        )
        + b"\n",
        "SKILL.md": (
            "---\nname: aragorn-inert-plugin-skill\n"
            "description: Inert plugin package admission fixture.\n---\n"
            f"# Aragorn {label} skill\n\nThis fixture performs no actions.\n"
        ).encode("ascii"),
    }


def _read_base(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        raw = b""
        while len(raw) <= BASE_PIN[0]:
            part = os.read(fd, BASE_PIN[0] + 1 - len(raw))
            if not part:
                break
            raw += part
        after, named = os.fstat(fd), path.lstat()
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
        if (
            (len(raw), digest(raw)) != BASE_PIN
            or before.st_nlink != 1
            or any(
                getattr(before, key) != getattr(after, key)
                or getattr(after, key) != getattr(named, key)
                for key in fields
            )
        ):
            raise ValueError("pinned denial helper changed")
        return raw
    finally:
        os.close(fd)


def _base():
    source = Path(__file__).with_name(BASE_NAME)
    raw = _read_base(source)
    if raw.count(_MAIN) != 1:
        raise ValueError("pinned denial helper entrypoint changed")
    module = types.ModuleType("aragorn_plugin_package_denial_base")
    module.__file__ = str(source)
    # Reuse exact-pinned definitions only. The predecessor CLI main never runs.
    exec(compile(raw.split(_MAIN)[0], str(source), "exec"), module.__dict__)  # noqa: S102 - exact digest-pinned definitions, no legacy main
    module.PLUGIN_ID = PLUGIN_ID
    module.ROUTE_ID = ROUTE
    module.ACTION_ID = "plugin-package-skill-replacement"
    module.ROUTE_ROOT = ROOT
    module.BASELINE_SOURCE = ROOT / "baseline-source"
    module.CANDIDATE_SOURCE = ROOT / "candidate-source"
    module.TARGET_ROOT = module.STATE / "extensions" / PLUGIN_ID
    module.FORCE_ARGS = ("plugins", "install", str(module.CANDIDATE_SOURCE), "--force")
    module.EXPECTED_FIXTURES = {
        key: {
            "version": version,
            "digests": {
                name: digest(content)
                for name, content in fixture_files(version).items()
            },
        }
        for key, version in (("baseline", "1.0.0"), ("candidate", "2.0.0"))
    }

    def target_metadata(observation):
        tree = observation.get("tree", {})
        root, entries = tree.get("root", {}), tree.get("entries", [])
        return (
            root.get("type") == "directory"
            and root.get("uid") == 992
            and root.get("gid") == 992
            and root.get("mode") == "700"
            and len(entries) == 4
            and all(
                item.get("type") == "file"
                and item.get("uid") == 992
                and item.get("gid") == 992
                and item.get("mode") == "600"
                and item.get("nlink") == 1
                for item in entries
            )
        )

    module.exact_target_metadata = target_metadata
    return module


def observe() -> dict:
    if (
        sys.platform != "linux"
        or os.geteuid() != 992
        or os.getegid() != 992
        or os.getgroups() != [992]
        or not os.environ.get("OPENCLAW_GATEWAY_TOKEN")
    ):
        raise ValueError("fixed gateway namespace and credentials are required")
    base = _base()
    action = base.run_observation()
    if (
        action["status"] != "OBSERVED"
        or action["execution_error"] is not None
        or not action["observations"]["native_force_reinstall"][
            "explicit_policy_block_observed"
        ]
        or any(command["error"] is not None for command in action["commands"])
    ):
        raise ValueError("plugin package replacement denial was not established")
    before = action["prerequisites"]["boundary_before"]
    after = action["observations"]["boundary_after"]
    for boundary in (before, after):
        for item in (
            boundary["baseline_source"],
            boundary["candidate_source"],
            boundary["target_plugin"]["baseline"],
        ):
            if item["manifest"].get("skills") != ["."] or not item["ready"]:
                raise ValueError("declared plugin skill source changed")
    if fixture_files("1.0.0")["SKILL.md"] == fixture_files("2.0.0")[
        "SKILL.md"
    ] or not all(action["observations"]["state_invariants"].values()):
        raise ValueError("replacement fixture or protected state changed")
    return {
        "schema": "aragorn/native-plugin-package-skill-replacement-denial/v1",
        "authority": "FIXED_INERT_PACKAGE_POLICY_DENIAL_NOT_ADMISSION_OR_CAMPAIGN_QUALIFICATION",
        "route_id": ROUTE,
        "status": "OBSERVED",
        "action": action,
        "base_helper": {"bytes": BASE_PIN[0], "digest": BASE_PIN[1]},
        "implementation_digest": digest(Path(__file__).read_bytes()),
        "declared_skill_root": ".",
        "baseline_skill_digest": digest(fixture_files("1.0.0")["SKILL.md"]),
        "candidate_skill_digest": digest(fixture_files("2.0.0")["SKILL.md"]),
        "decision": {key: False for key in _ELIGIBILITY},
        "limitations": [
            "DORMANT_NON_ALLOWLISTED_PLUGIN_PACKAGE_ONLY_NO_PLUGIN_CODE_LOADED",
            "ORDINARY_FORCE_INSTALL_DENIED_NOT_SUCCESSFUL_PACKAGE_OR_SKILL_ACTIVATION",
            "GATEWAY_SKILLS_STATUS_CHECKED_NOT_INTERNAL_CACHE_OR_MODEL_PROMPT",
            "REQUIRES_CALLER_BOUND_RUNTIME_TREE_NAMESPACE_PARENT_AND_CLEANUP",
            "NO_FINAL_CAMPAIGN_PASS_OR_PHASE3_AUTHORITY",
        ],
    }


def main() -> int:
    if sys.argv[1:]:
        return 64
    try:
        print(canonical(observe()).decode("ascii"))
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        # Native diagnostics and credential-bearing output are never forwarded.
        print("plugin package denial fixture refused", file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
