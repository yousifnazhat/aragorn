"""One fixed inert plugin-package denial in an owned native systemd fixture."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

_ROOT = Path("/route-input")
_STAGED = Path("/opt/aragorn/native-plugin-package-input")
_INPUT = _ROOT / "plugin-package-skill-replacement"
_PROBE = "protected-plugin-package-skill-replacement-probe.py"
_ROUTE = "ADM-02/update/plugin-package-skill-replacement"
_PLUGIN = "aragorn-plugin-skill-replacement-fixture"
_SCHEMA = "aragorn/runtime-native-plugin-package-observation/v1"
_AUTHORITY = "OWNED_INERT_PLUGIN_PACKAGE_DENIAL_NOT_ADMISSION_OR_RUN_QUALIFICATION"
_PHASE = "PRECHECK"
_DIAGNOSTIC_SCHEMA = "aragorn/native-plugin-package-denial-diagnostic/v1"
_DIAGNOSTIC_REASONS = {
    "IDENTITY": {"GATEWAY_IDENTITY_REFUSED"},
    "HELPER": {"HELPER_REFUSED"},
    "PREREQUISITES": {"OBSERVATION_FAILED", "PREREQUISITE_MISSING"},
    "DENIAL": {"POLICY_DENIAL_NOT_ESTABLISHED"},
    "BOUNDARY": {"DECLARED_SKILL_CHANGED"},
    "INVARIANTS": {"PROTECTED_STATE_CHANGED"},
    "INTERNAL": {"INTERNAL_ERROR"},
}
_DIAGNOSTIC_CHECKS = {
    "version_match",
    "config_match",
    "config_custody",
    "config_mount",
    "config_lock_absent",
    "install_policy_match",
    "plugin_policy",
    "discovery_roots",
    "state_store",
    "baseline_source",
    "candidate_source",
    "target_baseline",
    "target_not_candidate",
    "target_metadata",
    "target_writable",
    "input_mount",
    "policy_command",
    "entrypoint_match",
    "gateway_identity",
    "system_info_pid",
    "skills_status",
    "plugin_disabled",
    "policy_denial",
    "state_unchanged",
    "commands_clean",
}
_DIAGNOSTIC_EXITS = {
    "version",
    "system_info_before",
    "skills_before",
    "plugin_before",
    "force",
    "plugin_after",
    "skills_after",
    "system_info_after",
}
_BUNDLE = {
    "adapter/protected-plugin-force-reinstall-v3-probe.py": (
        30362,
        "sha256:58ba8c44ef474588dd48c8afaca01681c26d8a0b45c153994463c87e719f115a",
    ),
    "adapter/" + _PROBE: (
        17008,
        "sha256:7dee1ce9f0fd591a1c3ab03e31a8baf7f87dca27092166dbaeaf81085f0d320e",
    ),
    "baseline-source/SKILL.md": (
        154,
        "sha256:6ff97ef11eb3fc88c13c6b341d565d374acc69f189b259e6e2711a25ccaf66aa",
    ),
    "baseline-source/index.js": (
        127,
        "sha256:39b9c5a247cbca515a569ca05443659ecf81ca6e65966a56d16813af59d8cc98",
    ),
    "baseline-source/openclaw.plugin.json": (
        206,
        "sha256:684957a5344e298c60d3cad7738decfdb3f2f113d8baa43a64bcb183c68fd298",
    ),
    "baseline-source/package.json": (
        143,
        "sha256:295e35934477d7de55f8840af9ae9d8ef9fd30379e4cc86938f66e8ad38ce2c9",
    ),
    "candidate-source/SKILL.md": (
        155,
        "sha256:1406a1294ff93c5bf35134236976446d3ee0585f19453274f84ec661292d2b6c",
    ),
    "candidate-source/index.js": (
        127,
        "sha256:39b9c5a247cbca515a569ca05443659ecf81ca6e65966a56d16813af59d8cc98",
    ),
    "candidate-source/openclaw.plugin.json": (
        206,
        "sha256:cb0a827d40f125ab2e8ba53f16318d011e3498db216999db89d4cbdf23aee8a6",
    ),
    "candidate-source/package.json": (
        143,
        "sha256:099c01dce098800355ced5820bf22c1d32eb3342acfb7ba5a102c6a63bafbec1",
    ),
}
_FIELDS = (
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


class PluginFixtureError(RuntimeError):
    """Fixed local assertions only, never external diagnostic text."""


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise PluginFixtureError(message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _identity(value: os.stat_result) -> tuple:
    return tuple(getattr(value, key) for key in _FIELDS)


def _bundle(
    *, copied_owner: tuple[int, int] | None = None, staged: bool = False
) -> dict:
    """Verify fixed bytes/inventory and optionally hand copied custody to root."""
    _expect(type(staged) is bool, "invalid input location selection")
    root = _STAGED if staged else _ROOT
    package = root / "plugin-package-skill-replacement"
    directories = {
        root,
        package,
        *(
            package / name
            for name in ("adapter", "baseline-source", "candidate-source")
        ),
    }
    paths = {package / name for name in _BUNDLE}
    _expect(root.resolve(strict=True) == root, "input root is not canonical")
    _expect(
        set(root.rglob("*")) == (directories - {root}) | paths,
        "input inventory changed",
    )
    records = {}
    for path in sorted(
        directories | paths, key=lambda item: (len(item.parts), str(item))
    ):
        directory = path in directories
        before = path.lstat()
        mode = 0o555 if directory else 0o444
        _expect(
            (
                stat.S_ISDIR(before.st_mode)
                if directory
                else stat.S_ISREG(before.st_mode)
            )
            and stat.S_IMODE(before.st_mode) == mode
            and (before.st_uid, before.st_gid) in ((0, 0), copied_owner)
            and (directory or before.st_nlink == 1),
            "input custody changed",
        )
        fd = os.open(
            path,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | os.O_NONBLOCK
            | os.O_CLOEXEC
            | (os.O_DIRECTORY if directory else 0),
        )
        try:
            _expect(
                _identity(os.fstat(fd)) == _identity(before),
                "input changed before custody check",
            )
            if not directory:
                expected = _BUNDLE[str(path.relative_to(package))]
                raw = os.read(fd, expected[0] + 1)
                _expect((len(raw), _digest(raw)) == expected, "input bytes changed")
            if copied_owner is not None:
                os.fchown(fd, 0, 0)
                os.fsync(fd)
            after = os.fstat(fd)
            _expect(
                (after.st_uid, after.st_gid) == (0, 0)
                and _identity(after) == _identity(path.lstat())
                and all(
                    getattr(before, key) == getattr(after, key)
                    for key in _FIELDS
                    if key not in {"st_uid", "st_gid", "st_ctime_ns"}
                ),
                "input custody handoff changed identity",
            )
            records[str(path)] = {
                "identity": list(_identity(after)),
                **(
                    {"bytes": expected[0], "digest": expected[1]}
                    if not directory
                    else {}
                ),
            }
        finally:
            os.close(fd)
    return records


def _mount_record() -> dict | None:
    entries = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if len(fields) > 6 and fields[4] == str(_ROOT):
            entries.append(fields)
    _expect(len(entries) <= 1, "input mount inventory changed")
    if not entries:
        return None
    fields = entries[0]
    return {
        "mount_id": fields[0],
        "mountpoint": fields[4],
        "options": sorted(fields[5].split(",")),
    }


def _mount_command(arguments: list[str]) -> None:
    result = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        timeout=10,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    _expect(
        result.returncode == 0 and not result.stdout and not result.stderr,
        "fixed input mount operation failed",
    )


def _underlying_input() -> dict:
    """Metadata only; never open, modify, or remove inherited fixture inputs."""
    _expect(_ROOT.resolve(strict=True) == _ROOT, "input mount target not canonical")
    root = _ROOT.lstat()
    _expect(
        stat.S_ISDIR(root.st_mode)
        and (root.st_uid, root.st_gid) == (0, 0)
        and not stat.S_IMODE(root.st_mode) & 0o022,
        "inherited input root custody changed",
    )
    result = {".": list(_identity(root))}
    for path in _ROOT.rglob("*"):
        _expect(len(result) < 256, "inherited input inventory exceeds bound")
        result[str(path.relative_to(_ROOT))] = list(_identity(path.lstat()))
    return result


def _mount_input() -> dict:
    _expect(_mount_record() is None, "input mount was not fresh")
    inherited = _underlying_input()
    source_identity = _identity(_STAGED.lstat())
    _mount_command(["/usr/bin/mount", "--bind", str(_STAGED), str(_ROOT)])
    try:
        _mount_command(
            ["/usr/bin/mount", "-o", "remount,bind,ro,nosuid,nodev,noexec", str(_ROOT)]
        )
        result = _mount_record()
        _expect(
            result is not None
            and {"ro", "nosuid", "nodev", "noexec"} <= set(result["options"])
            and _identity(_ROOT.lstat()) == source_identity,
            "input readonly mount not established",
        )
        return {"mounted": result, "inherited_input": inherited}
    except BaseException:
        _mount_command(["/usr/bin/umount", str(_ROOT)])
        _expect(
            _underlying_input() == inherited, "inherited input restoration unconfirmed"
        )
        raise


def _gateway_directory(path: Path, root: Path) -> None:
    _expect(path.is_relative_to(root), "baseline directory escaped fixed gateway root")
    if not os.path.lexists(path):
        _gateway_directory(path.parent, root)
        path.mkdir(mode=0o700)
        os.chown(path, 992, 992)
    metadata = path.lstat()
    _expect(
        path.resolve(strict=True) == path
        and stat.S_ISDIR(metadata.st_mode)
        and (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
        == (992, 992, 0o700),
        "gateway baseline directory custody changed",
    )


def _seed_baseline(p37b) -> dict:
    root, state, home, workspace = (
        p37b._GATEWAY_ROOT,
        p37b._GATEWAY_STATE,
        p37b._GATEWAY_HOME,
        p37b._GATEWAY_WORKSPACE,
    )
    for directory in (
        state / "extensions",
        state / "plugin-skills",
        state / "skills",
        home / ".agents" / "skills",
        workspace / ".agents" / "skills",
        workspace / "skills",
    ):
        _gateway_directory(directory, root)
    target = state / "extensions" / _PLUGIN
    _expect(not os.path.lexists(target), "plugin baseline target is not fresh")
    _gateway_directory(target, root)
    records = {}
    for name in ("SKILL.md", "index.js", "openclaw.plugin.json", "package.json"):
        raw = (_INPUT / "baseline-source" / name).read_bytes()
        expected = _BUNDLE["baseline-source/" + name]
        _expect((len(raw), _digest(raw)) == expected, "baseline input changed")
        fd = os.open(
            target / name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            _expect(os.write(fd, raw) == len(raw), "baseline copy incomplete")
            os.fchown(fd, 992, 992)
            os.fchmod(fd, 0o600)
            os.fsync(fd)
            records[name] = {"bytes": len(raw), "digest": _digest(raw)}
        finally:
            os.close(fd)
    return {"path": str(target), "uid": 992, "gid": 992, "files": records}


def _unique_pairs(pairs: list) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _deny_constant(value: str) -> None:
    raise ValueError("nonfinite JSON number")


def _decode_diagnostic(raw: bytes, token: str) -> dict:
    _expect(
        len(raw) <= 4096 and token.encode("ascii") not in raw,
        "adapter diagnostic unsafe",
    )
    try:
        value = json.loads(
            raw, object_pairs_hook=_unique_pairs, parse_constant=_deny_constant
        )
    except (ValueError, UnicodeError) as exc:
        raise PluginFixtureError("adapter diagnostic malformed") from exc
    _expect(
        type(value) is dict
        and set(value) == {"schema", "phase", "reason", "checks", "exit_codes"}
        and value["schema"] == _DIAGNOSTIC_SCHEMA
        and type(value["phase"]) is str
        and value["phase"] in _DIAGNOSTIC_REASONS
        and type(value["reason"]) is str
        and value["reason"] in _DIAGNOSTIC_REASONS[value["phase"]]
        and type(value["checks"]) is dict
        and set(value["checks"]) == _DIAGNOSTIC_CHECKS
        and all(type(item) is bool for item in value["checks"].values())
        and type(value["exit_codes"]) is dict
        and set(value["exit_codes"]) == _DIAGNOSTIC_EXITS
        and all(
            item is None or (type(item) is int and -255 <= item <= 255)
            for item in value["exit_codes"].values()
        )
        and raw
        == json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n",
        "adapter diagnostic schema refused",
    )
    return value


def _invoke(p37b, gateway_pid: int, token: str) -> dict:
    _expect(
        type(gateway_pid) is int
        and gateway_pid > 0
        and re.fullmatch(r"[0-9a-f]{64}", token) is not None,
        "gateway invocation identity changed",
    )
    argv = [
        "/usr/bin/nsenter",
        "--target",
        str(gateway_pid),
        "--mount",
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
        str(_INPUT / "adapter" / _PROBE),
    ]
    environment = {
        "HOME": str(p37b._GATEWAY_HOME),
        "ARAGORN_GATEWAY_PID": str(gateway_pid),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "NO_PROXY": "127.0.0.1,localhost",
        "OPENCLAW_CONFIG_PATH": "/run/credentials/aragorn-agent-gateway.service/openclaw-config",
        "OPENCLAW_STATE_DIR": str(p37b._GATEWAY_STATE),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TZ": "UTC",
        "OPENCLAW_GATEWAY_TOKEN": token,
    }
    result = subprocess.run(
        argv,
        cwd=str(p37b._GATEWAY_WORKSPACE),
        env=environment,
        check=False,
        capture_output=True,
        timeout=120,
    )
    if result.returncode == 126 and not result.stderr:
        diagnostic = _decode_diagnostic(result.stdout, token)
        failure = PluginFixtureError(
            "adapter " + diagnostic["phase"] + "/" + diagnostic["reason"]
        )
        failure.add_note(json.dumps(diagnostic, sort_keys=True, separators=(",", ":")))
        raise failure
    _expect(
        result.returncode == 0
        and len(result.stdout) <= 2 * 1024 * 1024
        and not result.stderr
        and token.encode("ascii") not in result.stdout,
        "fixed plugin package adapter refused or output unsafe",
    )
    document = json.loads(
        result.stdout, object_pairs_hook=_unique_pairs, parse_constant=_deny_constant
    )
    canonical = json.dumps(
        document,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")
    _expect(
        result.stdout == canonical + b"\n"
        and document["schema"]
        == "aragorn/native-plugin-package-skill-replacement-denial/v1"
        and document["authority"]
        == "FIXED_INERT_PACKAGE_POLICY_DENIAL_NOT_ADMISSION_OR_CAMPAIGN_QUALIFICATION"
        and document["route_id"] == _ROUTE
        and document["status"] == "OBSERVED"
        and document["implementation_digest"] == _BUNDLE["adapter/" + _PROBE][1]
        and document["decision"]
        and all(value is False for value in document["decision"].values()),
        "adapter observation or proof ceiling changed",
    )
    return {
        "document": document,
        "execution": {
            "argv": argv,
            "exit_code": 0,
            "effective_identity": {"uid": 992, "gid": 992, "groups": [992]},
            "environment_names": sorted(environment),
            "stdout_bytes": len(result.stdout),
            "stdout_digest": _digest(result.stdout),
            "stderr_bytes": 0,
        },
    }


def _native():
    sys.path[:0] = [
        "/usr/lib/aragorn",
        str(Path(__file__).resolve().parent),
        "/src/scripts",
    ]
    spec = importlib.util.spec_from_file_location(
        "native_plugin_fixture_bootstrap",
        "/opt/aragorn/runtime-native-receipt-systemd-check.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run(container: str, copied_owner: tuple[int, int]) -> dict:
    global _PHASE
    native = _native()
    native.setup_prior._require_fixture(container)
    _expect(
        len(copied_owner) == 2
        and all(
            type(value) is int and 0 <= value <= 0xFFFFFFFF for value in copied_owner
        ),
        "invalid input copy owner",
    )
    import runtime_action_worker_openclaw_systemd_probe as p37b
    import runtime_native_cgroup_prerequisite as cgroup

    sources = native._sources(health=True, startup_reserve=True)
    mounted = False
    try:
        _PHASE = "CGROUP_PREREQUISITES"
        prerequisites = cgroup.observe(container)
        if prerequisites["status"] != "READY":
            failure = PluginFixtureError(
                "native PID controller prerequisite unavailable"
            )
            failure.add_note(
                json.dumps(prerequisites, sort_keys=True, separators=(",", ":"))
            )
            raise failure
        _PHASE = "INPUT_CUSTODY"
        staged_bundle = _bundle(copied_owner=copied_owner, staged=True)
        overlay = _mount_input()
        mount = overlay["mounted"]
        mounted = True
        bundle = _bundle()
        baseline = None
        activate = native._activate

        def seed_then_activate(p37c, token):
            nonlocal baseline
            baseline = _seed_baseline(p37b)
            return activate(p37c, token)

        # Reuse fresh provisioning/startup, never the read/create scenario runner.
        _PHASE = "NATIVE_BOOTSTRAP"
        with patch.object(native, "_activate", seed_then_activate):
            setup = native._prepare()
        _PHASE = "NATIVE_STARTUP_IDENTITY"
        budget = native._checked_startup_budget(container, cgroup)
        processes, boot = native.prior._processes(container), native.prior._boot()
        installed = native.setup_prior._installed(setup["skill_digest"])
        _expect(
            installed["denial"] is None and baseline is not None,
            "native baseline not active",
        )
        effects = p37b._snapshot_effects()
        _PHASE = "PLUGIN_PACKAGE_DENIAL"
        invocation = _invoke(
            p37b, processes["gateway"]["process"]["pid"], native._fixture_token(p37b)
        )
        _PHASE = "FINAL_IDENTITIES"
        receipts = native._snapshot(setup["provisioning"]["genesis_digest"], 0)
        _expect(
            receipts == setup["empty_store"]
            and p37b._snapshot_effects() == effects
            and native.prior._processes(container) == processes
            and native.prior._boot() == boot
            and native._sources(health=True, startup_reserve=True) == sources
            and native.setup_prior._installed(setup["skill_digest"]) == installed
            and _bundle() == bundle
            and _bundle(staged=True) == staged_bundle
            and _mount_record() == mount,
            "native identity or protected state changed during plugin denial",
        )
        observation = {
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "status": "OBSERVED",
            "route_id": _ROUTE,
            "fixture_container": container,
            "setup": setup,
            "installed_sources": sources,
            "cgroup_prerequisites": prerequisites,
            "startup_task_budget": budget,
            "startup_task_budget_after": native._checked_startup_budget(
                container, cgroup
            ),
            "processes": processes,
            "boot_id": boot,
            "input_bundle": bundle,
            "input_mount": mount,
            "input_mount_source": str(_STAGED),
            "baseline": baseline,
            "plugin_package": invocation,
            "empty_receipt_store_after": receipts,
            "broker_effects_unchanged": True,
            "phase3_eligible": False,
            "run_conformance_eligible": False,
            "production_activation_eligible": False,
        }
    finally:
        previous_phase = _PHASE
        _PHASE = "CLEANUP_AFTER_" + previous_phase
        try:
            cleanup = native.prior._stop_fixture()
        finally:
            if mounted:
                _mount_command(["/usr/bin/umount", str(_ROOT)])
                _expect(_mount_record() is None, "input mount cleanup unconfirmed")
                inherited_after = _underlying_input()
                _expect(
                    inherited_after == overlay["inherited_input"],
                    "inherited input restoration unconfirmed",
                )
        _PHASE = previous_phase
    observation["fixture_stack_cleanup"] = cleanup
    observation["input_mount_removed"] = True
    observation["inherited_input_restored"] = True
    observation["inherited_input_restoration"] = {
        "authority": "BOUNDED_METADATA_AND_INVENTORY_ONLY_NOT_CONTENT_HASHES",
        "before": overlay["inherited_input"],
        "after": inherited_after,
    }
    return observation


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if (
        len(arguments) != 3
        or re.fullmatch(r"[0-9a-f]{64}", arguments[0]) is None
        or any(re.fullmatch(r"[0-9]{1,10}", value) is None for value in arguments[1:])
    ):
        print(
            "usage: runtime_native_plugin_package_check OWNED_CONTAINER_ID COPY_UID COPY_GID",
            file=sys.stderr,
        )
        return 64
    try:
        result = _run(arguments[0], tuple(int(value) for value in arguments[1:]))
        print(
            json.dumps(
                result,
                sort_keys=True,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            )
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - never forward arbitrary credential-bearing diagnostics
        detail = str(exc) if type(exc) is PluginFixtureError else type(exc).__name__
        print(
            "native plugin package fixture refused: " + _PHASE + ": " + detail,
            file=sys.stderr,
        )
        if type(exc) is PluginFixtureError:
            for note in getattr(exc, "__notes__", ())[:1]:
                print(note, file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main())
