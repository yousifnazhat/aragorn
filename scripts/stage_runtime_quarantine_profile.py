"""Stage the fixed runtime quarantine/startup profile in a new DESTDIR only.

This builds a caller-owned file layout, not a root installation or live runtime.
It never provisions credentials, runs an activator, or enables a service.
Producer release identity and quarantine response deployment are not included.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import materialize_protected_install_quarantine_producers as overlay
from scripts import materialize_runtime_quarantine_activation as activation
from scripts import materialize_runtime_quarantine_services as services

_SCHEMA = "aragorn/runtime-quarantine-staged-profile/v1"
_AUTHORITY = (
    "CALLER_OWNED_DESTDIR_BYTES_ONLY_NOT_ROOT_DEPLOYMENT_OR_STARTUP_ENFORCEMENT"
)
_INSTALLER = "packaging/install-runtime-action-worker-host.sh"
_INSTALLERS = frozenset({_INSTALLER, "packaging/install-runtime-capability-host.sh"})
_BASE_INPUTS = {
    "packaging/activate-runtime-action-worker-host.sh": (
        32271,
        "sha256:dd615a00aacd5f76f52ac60400ea095f9014c2ef29d7793fd3ba35b26ffe3186",
    ),
    "packaging/activate-runtime-capability-host.sh": (
        12420,
        "sha256:b4ad162940d842e93ede73143f607cff4c612716334b66430d71b885f398984c",
    ),
    "packaging/install-runtime-action-worker-host.sh": (
        1240,
        "sha256:885441b628298629cc07d5c68e52b852864c6a755bc10d0e7e5de406f17b4748",
    ),
    "packaging/install-runtime-capability-host.sh": (
        3322,
        "sha256:6a7b4ec084b4dee8d974a0acab183f850be57e0acff30b616040687b307d28d9",
    ),
    "packaging/libexec/aragorn-runtime-action-service-v5.py": (
        349,
        "sha256:9dd8e3836176e3d2a6d2ab8d6a036e078dd868a188f10a74d3808b51290405fc",
    ),
    "packaging/libexec/aragorn-runtime-action-worker-service.py": (
        338,
        "sha256:5274f51d50293ba7559c6348fe79c5eb43753ecb09024525cfd09c368cc360f8",
    ),
    "packaging/libexec/aragorn-runtime-observation-service-v4.py": (
        356,
        "sha256:dba9cf34f9103073f9583f29bf0a83ae7f3162ca511ec2d76ec250ab161167cf",
    ),
    "packaging/libexec/aragorn-runtime-revocation-service.py": (
        352,
        "sha256:42ab2d99c368090be83451ac9b1d99155608fdd8cb2e86a142ef22b22bd26a8a",
    ),
    "packaging/openclaw/aragorn-runtime-action-worker/index.js": (
        23860,
        "sha256:71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b",
    ),
    "packaging/openclaw/aragorn-runtime-action-worker/openclaw.plugin.json": (
        723,
        "sha256:d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036",
    ),
    "packaging/openclaw/aragorn-runtime-action-worker/package.json": (
        134,
        "sha256:0097f2e532b1a5d99e3cfc4990d4bbf83a01c10ee11d567b139bd9144a859ad2",
    ),
    "packaging/systemd/aragorn-agent-gateway.service": (
        3437,
        "sha256:70a0aa0a89aae8bce8b7785b26d73d844c784e85be449363cb739835500de067",
    ),
    "packaging/systemd/aragorn-gateway.sysusers": (
        452,
        "sha256:994234b5d509d33dff4448691591e7f30d965415ad18c8a4c01d1a31ed16bc04",
    ),
    "packaging/systemd/aragorn-runtime-action-worker.service": (
        2573,
        "sha256:e4ef9e3f2229d92ed9dd9ee4896646e646d7171ee585ecba5aecdd87dba5e790",
    ),
    "packaging/systemd/aragorn-runtime-action-worker.sysusers": (
        113,
        "sha256:3fcb0aad46b7b6c5c9a65f0a84909c80c557ceab0a26b015a36cef9359c5c729",
    ),
    "packaging/systemd/aragorn-runtime-action.tmpfiles": (
        485,
        "sha256:8b9c5a97e49bc4c54d7e4d7da518fca5a6dd8dbfa77d591f88400838cf1d58c1",
    ),
    "packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service": (
        2725,
        "sha256:e0273dbeb4ed40a203193a52eb6146f81ecbc6abca605fa0bfff69774676b2db",
    ),
    "packaging/systemd/aragorn-runtime-lineage-capability-observation-publisher.service": (
        2777,
        "sha256:f48258b00213c2c1ff4c5c95d0f1c446f78593d1d04780719cba79bf8dd73d8a",
    ),
    "packaging/systemd/aragorn-runtime-revocation-publisher.service": (
        1852,
        "sha256:edac3cde6f441496320689edb5dd8ba202879c802dc877800cbd308be718e453",
    ),
    "src/aragorn/__init__.py": (
        78,
        "sha256:4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01",
    ),
    "src/aragorn/acquire.py": (
        12755,
        "sha256:56942e7c1b10c58f265615c8b7abf3f199c7f98bf016be50eb6d3a98d2bd0f8c",
    ),
    "src/aragorn/cas.py": (
        19508,
        "sha256:c5642f910ac4b2d6172a59a02105b359cb43d3a2f2e2240368229d3436ad4859",
    ),
    "src/aragorn/oci_worker_protocol.py": (
        22775,
        "sha256:0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b",
    ),
    "src/aragorn/runtime_action_broker.py": (
        79641,
        "sha256:94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21",
    ),
    "src/aragorn/runtime_action_broker_v2.py": (
        18164,
        "sha256:a77d7c5cc2b607b9234f6758283bdff74c73586651e6aa7d5a9e3c3ab48b14e3",
    ),
    "src/aragorn/runtime_action_broker_v3.py": (
        30803,
        "sha256:408f0b5373139c93b13e61fcf4ea6791865841806f0a9aa8a269e095cd0d9f8d",
    ),
    "src/aragorn/runtime_action_broker_v4.py": (
        45748,
        "sha256:ab7d08105229ee3dd58f8dca5c20156d5e260e2b79f0ed2b4c08693c3cf6174a",
    ),
    "src/aragorn/runtime_action_broker_v5.py": (
        10907,
        "sha256:35c17f92cca01ba064058f6d76223a03072138aa61d060538600f6799af7eca5",
    ),
    "src/aragorn/runtime_action_decision.py": (
        17731,
        "sha256:3b3b7beffd331280dfbc8088a1ef28f6b32affe59d0abf75305ff97fe93d459d",
    ),
    "src/aragorn/runtime_action_observation_publisher.py": (
        21163,
        "sha256:288714579b5df19c5b3137caee21ede1a5c8bf69f690e3e9434bd3d646806a90",
    ),
    "src/aragorn/runtime_action_observation_publisher_v2.py": (
        18345,
        "sha256:39b42a466eb248bbc5d176f9a5350a72f88afe85f98ea492bde882f7a3ba5c8e",
    ),
    "src/aragorn/runtime_action_observation_publisher_v3.py": (
        10901,
        "sha256:e74dc65223f84dfe4562ad8aebdde2a6ead1fce3763c8d559c0ce44e6073cde0",
    ),
    "src/aragorn/runtime_action_observation_publisher_v4.py": (
        12107,
        "sha256:2f021264b43d4602842134b9d7422105243fbbf594b474a58a6a5ae8290442ae",
    ),
    "src/aragorn/runtime_action_service.py": (
        8062,
        "sha256:e9b9fd55fc88aa0c9f5916907465ea7f0f4c01e5ec822293ef0ec8e9d32e4e3e",
    ),
    "src/aragorn/runtime_action_service_v2.py": (
        4143,
        "sha256:69100dc7729922bfc980aa10a3666051703c8d1c4d319e28f6abd3128aaf3dd6",
    ),
    "src/aragorn/runtime_action_service_v4.py": (
        3857,
        "sha256:8c3c70dc85dd8eaa8e8a2dcdbc2c8b0571b23f5901eb023cf146a916f49b49a7",
    ),
    "src/aragorn/runtime_action_service_v5.py": (
        4146,
        "sha256:a3e829d2e60f26dd91cbb14967ddf2a747414ce8f125b4f207dbce7a5e1e86c7",
    ),
    "src/aragorn/runtime_action_worker.py": (
        37878,
        "sha256:a0aa80b0870c18ecb380ca6f7a65663e4046e92f55938b84c9e15284ba221873",
    ),
    "src/aragorn/runtime_active_skill_lineage.py": (
        21208,
        "sha256:6d1663d097410838d6c9b69644ffdfb2bd7ace30091d31544f31b04a7f6776d1",
    ),
    "src/aragorn/runtime_capability_grant.py": (
        9741,
        "sha256:058aa743c6bdebffe1660120d88886d465aaaa5192171979e466ba6ce20f5681",
    ),
    "src/aragorn/runtime_lineage_capability_issuer.py": (
        2149,
        "sha256:85c4ec36c163648e3d706e5c7c650642caee8b1f6799fd820bc12fb1486ad0ca",
    ),
    "src/aragorn/runtime_observation_service.py": (
        5876,
        "sha256:ef738d4de1485917906f7fa95353650f007c6f4cdf4d401906abb737ef38e319",
    ),
    "src/aragorn/runtime_observation_service_v2.py": (
        4301,
        "sha256:c2fd548f7d98e34cedba3313e4d477b5c258d127409dc0531e1bd5dc97a4ee1e",
    ),
    "src/aragorn/runtime_observation_service_v3.py": (
        3575,
        "sha256:5dcc0ec212a07ce7fd087c5ea81df02e30d9c22f9a1f5b49dc790fd37b57fbdb",
    ),
    "src/aragorn/runtime_observation_service_v4.py": (
        3575,
        "sha256:fff0ae55827237d9a05c93cfbae17b974e2817d258dcdf1c2cb66630eda619da",
    ),
    "src/aragorn/runtime_process_profile.py": (
        16131,
        "sha256:a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68",
    ),
    "src/aragorn/runtime_revocation_service.py": (
        4012,
        "sha256:20cac61e1e497dec177e16a564e0735e6b5d593b6965fba5a57fa9d715a4c6ca",
    ),
}
# (source identity, installed mode, verified bytes), indexed by DESTDIR-relative path.
_Payload = tuple[str, int, bytes]


class RuntimeQuarantineStageError(ValueError):
    """The bounded staging operation did not produce a verified complete layout."""


def _destination(source: str) -> tuple[str, int]:
    name = Path(source).name
    if source.startswith("src/aragorn/"):
        return "usr/lib/aragorn/aragorn/" + name, 0o644
    if source.startswith(("packaging/libexec/", "packaging/activate-")):
        return "usr/libexec/aragorn/" + name, 0o755
    if source.startswith("packaging/openclaw/aragorn-runtime-action-worker/"):
        return "usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/" + name, 0o644
    if source.startswith("packaging/systemd/"):
        if name.endswith(".service"):
            return "usr/lib/systemd/system/" + name, 0o644
        for suffix, directory in (
            (".sysusers", "sysusers.d"),
            (".tmpfiles", "tmpfiles.d"),
        ):
            if name.endswith(suffix):
                return "usr/lib/" + directory + "/" + name.removesuffix(
                    suffix
                ) + ".conf", 0o644
    raise RuntimeQuarantineStageError("unexpected fixed installation source")


def _verified_payloads() -> tuple[
    dict[str, bytes], dict[str, _Payload], dict[str, _Payload]
]:
    if len(_BASE_INPUTS) != 47 or len(activation._DEPENDENCIES) != 5:
        raise RuntimeQuarantineStageError("fixed source inventory changed")
    inputs = {
        name: overlay._read_pinned(name, size, digest, root=_ROOT)
        for name, (size, digest) in _BASE_INPUTS.items()
    }
    base = {}
    for name, raw in inputs.items():
        if name not in _INSTALLERS:
            destination, mode = _destination(name)
            if destination in base:
                raise RuntimeQuarantineStageError("base destination collision")
            base[destination] = (name, mode, raw)
    replacements = {}
    for name, (size, digest, output_size, output_digest) in services._SERVICES.items():
        if _BASE_INPUTS.get(name) != (size, digest):
            raise RuntimeQuarantineStageError("runtime source pins disagree")
        raw = services._transform(inputs[name])
        if (len(raw), overlay._digest(raw)) != (output_size, output_digest):
            raise RuntimeQuarantineStageError("runtime override identity changed")
        destination, mode = _destination(name)
        replacements[destination] = (name, mode, raw)
    for name, (size, digest) in activation._DEPENDENCIES.items():
        raw = overlay._read_pinned(name, size, digest, root=_ROOT)
        destination, mode = _destination(name)
        if destination in base or destination in replacements:
            raise RuntimeQuarantineStageError("new dependency destination collision")
        replacements[destination] = (name, mode, raw)
    for name, expected in activation._SOURCES.items():
        if _BASE_INPUTS.get(name) != expected:
            raise RuntimeQuarantineStageError("activation source pins disagree")
    rendered = activation._render(
        inputs[activation._UNIT], inputs[activation._ACTIVATOR]
    )
    for name, raw in rendered.items():
        if (len(raw), overlay._digest(raw)) != activation._OUTPUTS[name]:
            raise RuntimeQuarantineStageError("activation override identity changed")
        destination, mode = _destination(name)
        if destination in replacements:
            raise RuntimeQuarantineStageError("activation destination collision")
        replacements[destination] = (name, mode, raw)
    if len(base) != 45 or len(replacements) != 10 or len(base | replacements) != 50:
        raise RuntimeQuarantineStageError("fixed payload inventory changed")
    return inputs, base, replacements


def _directories(paths: dict[str, Any]) -> set[str]:
    return {
        parent.as_posix()
        for name in paths
        for parent in Path(name).parents
        if parent != Path(".")
    }


def _write_new(path: Path, raw: bytes, mode: int) -> None:
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode
    )
    try:
        written = 0
        while written < len(raw):
            count = os.write(fd, raw[written:])
            if count <= 0:
                raise RuntimeQuarantineStageError("staging write made no progress")
            written += count
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def _snapshot(root: Path, inputs: dict[str, bytes]) -> None:
    directories = sorted(_directories(inputs), key=lambda name: (name.count("/"), name))
    for name in directories:
        (root / name).mkdir(mode=0o755)
    for name, raw in inputs.items():
        path = root / name
        _write_new(path, raw, 0o555 if name in _INSTALLERS else 0o444)
        overlay._read_pinned(name, len(raw), overlay._digest(raw), root=root)
    for name in reversed(directories):
        (root / name).chmod(0o555)
    root.chmod(0o555)


def _run_installer(snapshot: Path, output: Path) -> None:
    # Only these already-verified frozen scripts execute. No inherited DESTDIR,
    # PATH, shell startup file, Python path or environment controls the install.
    process = subprocess.Popen(
        ["/bin/sh", str(snapshot / _INSTALLER)],
        cwd=snapshot,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "DESTDIR": str(output)},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        umask=0o022,
    )
    try:
        process.communicate(timeout=20)
    except BaseException as exc:
        # The fixed child shell may still be waiting on an install subprocess.
        # Do not signal a PID after this Popen object has already reaped it.
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.communicate(timeout=5)
        raise RuntimeQuarantineStageError("frozen installer did not complete") from exc
    if process.returncode != 0:
        raise RuntimeQuarantineStageError("frozen installer failed")


def _audit_tree(output: Path, payloads: dict[str, _Payload]) -> None:
    directories = _directories(payloads)
    seen_files: set[str] = set()
    seen_directories: set[str] = set()
    held: list[tuple[int | None, str | Path, int, os.stat_result]] = []
    files: list[tuple[int, str, os.stat_result]] = []
    root_before = output.lstat()
    root_fd = os.open(
        output,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
    )
    held.append((None, output, root_fd, root_before))

    def walk(fd: int, prefix: str) -> None:
        for name in sorted(os.listdir(fd)):
            relative = prefix + name
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if relative in directories:
                child = os.open(
                    name,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_NOFOLLOW
                    | os.O_NONBLOCK
                    | os.O_CLOEXEC,
                    dir_fd=fd,
                )
                held.append((fd, name, child, before))
                seen_directories.add(relative)
                walk(child, relative + "/")
            elif relative in payloads:
                _, mode, raw = payloads[relative]
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.geteuid()
                    or stat.S_IMODE(before.st_mode) != mode
                    or before.st_nlink != 1
                ):
                    raise RuntimeQuarantineStageError("staged file metadata changed")
                files.append((fd, name, before))
                overlay._read_pinned(
                    relative, len(raw), overlay._digest(raw), root=output
                )
                seen_files.add(relative)
            else:
                raise RuntimeQuarantineStageError("unexpected staged path")

    try:
        walk(root_fd, "")
        if seen_files != set(payloads) or seen_directories != directories:
            raise RuntimeQuarantineStageError("staged path inventory changed")
        for parent, name, fd, before in held:
            if (
                not stat.S_ISDIR(before.st_mode)
                or before.st_uid != os.geteuid()
                or stat.S_IMODE(before.st_mode) != 0o755
                or overlay._identity(before) != overlay._identity(os.fstat(fd))
                or overlay._identity(before)
                != overlay._identity(
                    os.stat(name, dir_fd=parent, follow_symlinks=False)
                )
            ):
                raise RuntimeQuarantineStageError("staged directory custody changed")
        for parent, name, before in files:
            if overlay._identity(before) != overlay._identity(
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            ):
                raise RuntimeQuarantineStageError("staged file changed after readback")
    finally:
        close_error = None
        for _, _, fd, _ in reversed(held):
            try:
                os.close(fd)
            except OSError as exc:
                close_error = close_error or exc
        if close_error is not None:
            raise RuntimeQuarantineStageError(
                "staged directory cleanup failed"
            ) from close_error


def _apply_overrides(output: Path, replacements: dict[str, _Payload]) -> None:
    for name, (_, mode, raw) in replacements.items():
        destination = output / name
        temporary = destination.with_name(".aragorn-stage-" + destination.name)
        _write_new(temporary, raw, mode)
        overlay._read_pinned(
            temporary.name, len(raw), overlay._digest(raw), root=temporary.parent
        )
        os.replace(temporary, destination)


def _parent_custody(path: Path) -> tuple[int, ...]:
    before = path.lstat()
    if (
        path.resolve(strict=True) != path
        or not stat.S_ISDIR(before.st_mode)
        or before.st_uid != os.geteuid()
        or stat.S_IMODE(before.st_mode) & 0o022
    ):
        raise RuntimeQuarantineStageError(
            "DESTDIR parent must be canonical and caller-owned"
        )
    return before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid


def stage_runtime_quarantine_profile(output: Path) -> dict[str, Any]:
    """Assemble one fresh absolute DESTDIR; incomplete output may remain on failure."""
    try:
        if (
            not isinstance(output, Path)
            or not output.is_absolute()
            or output.exists()
            or output.is_symlink()
        ):
            raise RuntimeQuarantineStageError("DESTDIR must be an absolute absent Path")
        parent = _parent_custody(output.parent)
        inputs, base, replacements = _verified_payloads()
        with tempfile.TemporaryDirectory(
            prefix=".aragorn-runtime-stage-", dir=output.parent
        ) as temporary:
            snapshot = Path(temporary)
            _snapshot(snapshot, inputs)
            if _parent_custody(output.parent) != parent:
                raise RuntimeQuarantineStageError("DESTDIR parent changed")
            output.mkdir(mode=0o755)
            output.chmod(0o755)
            _run_installer(snapshot, output)
            _audit_tree(output, base)
            _apply_overrides(output, replacements)
        payloads = base | replacements
        _audit_tree(output, payloads)
        if _parent_custody(output.parent) != parent:
            raise RuntimeQuarantineStageError("DESTDIR parent changed")
        return {
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "files": [
                {
                    "path": "/" + name,
                    "source_name": source,
                    "bytes": len(raw),
                    "digest": overlay._digest(raw),
                    "mode": f"{mode:04o}",
                }
                for name, (source, mode, raw) in sorted(payloads.items())
            ],
            "directories": ["/" + name for name in sorted(_directories(payloads))],
            "base_inputs": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in sorted(_BASE_INPUTS.items())
            ],
            "new_dependencies": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in sorted(activation._DEPENDENCIES.items())
            ],
            "gateway_config_digest_required_not_included": "sha256:"
            + activation._CONFIG_DIGEST,
            "root_deployment": False,
            "production_activation_eligible": False,
            "runtime_startup_enforcement": False,
            "quarantine_response_deployed": False,
            "producer_release_included": False,
            "phase3_qualification": False,
            "missing_inputs": [
                "root-owned Linux deployment and actual systemd credential/startup validation",
                "OpenClaw runtime, protected installed skill, credentials and control state",
                "producer release, complete analyzer package and requirements-worker.lock identity",
                "quarantine response entrypoint/deployment and independent campaign qualification",
            ],
        }
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise RuntimeQuarantineStageError(
            f"cannot stage runtime profile: {exc}"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    output = parser.parse_args().output
    try:
        manifest = stage_runtime_quarantine_profile(output)
    except RuntimeQuarantineStageError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
