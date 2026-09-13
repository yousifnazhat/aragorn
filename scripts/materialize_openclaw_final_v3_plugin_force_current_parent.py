"""Render current-parent plugin-force build sources; never build or execute them."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT))

from scripts import materialize_protected_install_quarantine_producers as overlay

_SCHEMA = "aragorn/openclaw-final-v3-plugin-force-current-parent-build-sources/v1"
_AUTHORITY = (
    "PINNED_BUILD_SOURCES_ONLY_NOT_EXECUTION_QUALIFICATION_OR_RELEASE_AUTHORITY"
)
_CASE = "ADM-02/update/plugin-force-reinstall"
_PARENT = "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
_OLD_PARENT = "sha256:21184b7a6a096a8625994b524203bf5b521d749b24e415378a69decd4e78009b"
_BASE = "benchmark/admission/openclaw-v2026.7.1/"
_STEM = "runtime_action_worker_final_combined_v3_plugin_force_reinstall"
_OLD_RECIPE = f"scripts/capture_{_STEM}_systemd.sh"
_OLD_COLLECTOR = f"scripts/{_STEM}_systemd_probe.py"
_RECIPE = f"capture_{_STEM}_current_parent_systemd.sh"
_COLLECTOR = f"{_STEM}_current_parent_systemd_probe.py"
_DOCKER_DIRECTORY = (
    "benchmark/runtime-action-worker-final-combined-v3-"
    "plugin-force-reinstall-current-parent-systemd"
)
_MATERIALIZER = "scripts/materialize_openclaw_final_v3_plugin_force_current_parent.py"
_WRITER = "scripts/materialize_protected_install_quarantine_producers.py"
_BUNDLE = {
    "baseline-source/index.js": (
        "plugin-force-reinstall-baseline-index.js",
        122,
        "sha256:631cc6f036f3cdf2f8fa6c814a27da075bf8c37fd2fe3681a55f7f5e593dd4ea",
    ),
    "baseline-source/openclaw.plugin.json": (
        "plugin-force-reinstall-baseline-openclaw.plugin.json",
        179,
        "sha256:9b93a70d606ec63c32d15dd9021dc603df9bdf680b74789c675f5227c1c6b077",
    ),
    "baseline-source/package.json": (
        "plugin-force-reinstall-baseline-package.json",
        141,
        "sha256:cf817f208ceb1f4bb211d5cc97b190f6ba54cb27f34d7864b9fea5adc74a679e",
    ),
    "candidate-source/index.js": (
        "plugin-force-reinstall-replacement-index.js",
        125,
        "sha256:0d4abd050921ecb1c29c8c97457654184137c65644ca9b3e21a920284ce5178b",
    ),
    "candidate-source/openclaw.plugin.json": (
        "plugin-force-reinstall-replacement-openclaw.plugin.json",
        182,
        "sha256:5579b471618e53e8fd72df36ad0128bb6310c0fc8111be6db31a18c672b5053c",
    ),
    "candidate-source/package.json": (
        "plugin-force-reinstall-replacement-package.json",
        141,
        "sha256:7e73514c5369d1d90524663baff896f41f71e21540d1b0a311a73aaf456ee8de",
    ),
    "protected-plugin-force-reinstall-v3-probe.py": (
        "protected-plugin-force-reinstall-v3-probe.py",
        30_362,
        "sha256:58ba8c44ef474588dd48c8afaca01681c26d8a0b45c153994463c87e719f115a",
    ),
}
_CONTRACTS = {
    _BASE + "protected-final-combined-config-v3.json": (
        2_160,
        "sha256:2855474d8b709654fb8902c0dc69ec1f0a3a378518ec23bfb12c1eb9630824ab",
    ),
    _BASE + "protected-final-combined-profile-v3.json": (
        5_302,
        "sha256:3229bd747088199d8bae074bbc27a415169fa21f86462408434ecdb43c5b2a6c",
    ),
    _BASE + "protected-final-combined-runtime-v3.lock.json": (
        7_620,
        "sha256:3bbcc6568cf713f9e534f84f7a92e313b5aa357065759bd01b5f24a594fb5822",
    ),
}
_HELPERS = {
    "scripts/runtime_action_worker_final_combined_v2_systemd_probe.py": (
        30_093,
        "sha256:03fcf63cd6f68521e261ecb8dc558c2a906b59338ce96a20688098f2066dc550",
    ),
    "scripts/runtime_action_worker_final_route_systemd_probe.py": (
        21_470,
        "sha256:50e96d42459a40d0a87ce2cdd215bace14072a626281a3fc733efb5b22831355",
    ),
}
_INPUTS = {
    _OLD_RECIPE: (
        26_549,
        "sha256:1b06d7f8fa54fe56aaa97cdf2a00cb09838ee0e20172d951a99106b2e033cf54",
    ),
    _OLD_COLLECTOR: (
        28_860,
        "sha256:c9e3e43e4d122575cc362e2ec73b2fc4b57d4ad465a1d49e4b94291d935217ad",
    ),
    _WRITER: (
        8_703,
        "sha256:91cae167762c4aca7527fcd14952990059ebe8e4d37d3e2e64b102843f27e164",
    ),
    **_CONTRACTS,
    **_HELPERS,
    **{_BASE + source: (size, digest) for source, size, digest in _BUNDLE.values()},
}
_ACTIVATOR_DIGEST = (
    "sha256:3b25b462cf7f9c4886cce1b7057fabbaeb95e9d9de83cb33db9c7ca62f15d86c"
)
_INHERITED = {
    **{f"/src/{name}": (*pin, "0444") for name, pin in _CONTRACTS.items()},
    **{f"/src/{name}": (*pin, "0555") for name, pin in _HELPERS.items()},
    f"/src/{_OLD_COLLECTOR}": (*_INPUTS[_OLD_COLLECTOR], "0555"),
    f"/src/{_BASE}protected-plugin-force-reinstall-v3-probe.py": (
        *_INPUTS[_BASE + "protected-plugin-force-reinstall-v3-probe.py"],
        "0444",
    ),
    "/src/packaging/activate-runtime-action-worker-host-v3.sh": (
        30_504,
        _ACTIVATOR_DIGEST,
        "0555",
    ),
    "/usr/libexec/aragorn/activate-runtime-action-worker-host.sh": (
        30_504,
        _ACTIVATOR_DIGEST,
        "0755",
    ),
    "/usr/lib/aragorn/aragorn/runtime_action_worker.py": (
        37_878,
        "sha256:a0aa80b0870c18ecb380ca6f7a65663e4046e92f55938b84c9e15284ba221873",
        "0644",
    ),
    "/opt/aragorn/runtime-profile/template-skill/SKILL.md": (
        140,
        "sha256:eb685d91de039ed864fbd790cddf31684b017fd4a34ee1a55760d8d7cdbadefa",
        "0444",
    ),
    "/usr/bin/printf": (
        68_480,
        "sha256:2c7b0151ee3c1ba4e829209f2ff4336de9d97143e22bf87c7448539112139957",
        "0755",
    ),
    **{
        "/route-input/plugin-force-reinstall/" + name: (size, digest, "0444")
        for name, (_, size, digest) in _BUNDLE.items()
    },
}
# Independent fixed pins are filled from reviewed deterministic rendering, not
# from a Docker build. There is deliberately no fabricated child image identity.
_OUTPUTS = {
    _RECIPE: (
        28_975,
        "sha256:db66524ab3b54a72cb9807241c8d6377ca4eb6b5d81dbf7f59c002e36c2fec6e",
    ),
    _COLLECTOR: (
        28_905,
        "sha256:31d5304939154809ca5a9ac55b55792039f1637db2987386487f01aca9cfafad",
    ),
    "Dockerfile": (
        10_136,
        "sha256:33465786db1de0489d22a4a252f687108b779513828138bafdf66799547a0498",
    ),
}
_BUILD_CLEANUP = """import os
import re
import stat
import sys

context = sys.argv[1]
if re.fullmatch(r"/tmp/aragorn-phase3-final-combined-v3-force-context\\.[A-Za-z0-9_]+", context) is None:
    raise SystemExit("unexpected build-context cleanup path")
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
directory = os.open(context, flags)
try:
    parent = os.fstat(directory)
    if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
        raise SystemExit("unowned build-context cleanup directory")
    try:
        build = os.open("build", flags, dir_fd=directory)
    except FileNotFoundError:
        pass
    else:
        try:
            before = os.fstat(build)
            if before.st_uid != os.geteuid() or before.st_mode & 0o022:
                raise SystemExit("unowned or writable build-context cleanup leaf")
            os.fchmod(build, 0o700)
            after = os.stat("build", dir_fd=directory, follow_symlinks=False)
            if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
                raise SystemExit("build-context cleanup leaf was rebound")
        finally:
            os.close(build)
finally:
    os.close(directory)
"""


class PluginForceBuildSourceError(ValueError):
    """A pinned source, bounded transform, or source publication changed."""


def _replace(raw: bytes, old: str, new: str, count: int = 1) -> bytes:
    before = old.encode("ascii")
    if raw.count(before) != count:
        raise PluginForceBuildSourceError("plugin-force replacement shape changed")
    return raw.replace(before, new.encode("ascii"))


def _recipe(raw: bytes) -> bytes:
    raw = _replace(raw, _OLD_PARENT, _PARENT, 2)
    raw = _replace(
        raw,
        'root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)',
        'if [ "$#" -ne 2 ]; then\n'
        f'    echo "usage: {_RECIPE} SIGNED_CHECKOUT_ROOT ABSENT_OUTPUT_PATH" >&2\n'
        '    exit 64\nfi\nroot=$(CDPATH= cd -- "$1" && pwd)\nshift',
    )
    # Preserve immutable signed-archive custody; do not execute a checkout copy.
    start = 'GIT_NO_REPLACE_OBJECTS=1 git archive --format=tar "$source_commit" -- \\\n'
    end = '    | tar -xf - -C "$context"\n'
    if raw.count(start.encode()) != 1 or raw.count(end.encode()) != 1:
        raise PluginForceBuildSourceError("plugin-force archive shape changed")
    first = raw.index(start.encode())
    last = raw.index(end.encode(), first) + len(end)
    archive_paths = sorted({_MATERIALIZER, *_INPUTS})
    archive = (
        'mkdir "$context/source"\n'
        + start
        + "".join(f"    {name} \\\n" for name in archive_paths)
        + '    | tar -xf - -C "$context/source"\n'
        + f'python3.12 -I -S -B "$context/source/{_MATERIALIZER}" "$context/build"\n'
    )
    raw = raw[:first] + archive.encode("ascii") + raw[last:]
    raw = _replace(
        raw,
        '                rm -rf -- "$context" || cleanup_failed=1',
        "                if python3.12 -I -S -B - \"$context\" <<'PY_CLEANUP'\n"
        + _BUILD_CLEANUP
        + "PY_CLEANUP\n                then\n"
        + '                    rm -rf -- "$context" || cleanup_failed=1\n'
        + "                else\n                    cleanup_failed=1\n                fi",
    )
    for old, new, count in (
        (
            "usage: " + _OLD_RECIPE.removeprefix("scripts/") + " ABSENT_OUTPUT_PATH",
            f"usage: {_RECIPE} SIGNED_CHECKOUT_ROOT ABSENT_OUTPUT_PATH",
            1,
        ),
        ("/src/" + _OLD_COLLECTOR, "/src/scripts/" + _COLLECTOR, 1),
        ('    cd "$context"', '    cd "$context/build"', 1),
        ('        --build-arg "V2_FORCE_BASE=$parent_id" \\\n', "", 1),
        (
            "benchmark/runtime-action-worker-final-combined-v3-plugin-force-reinstall-systemd/Dockerfile",
            "Dockerfile",
            1,
        ),
        ("retained V2 force image", "retained current V3 force-policy image", 2),
        (
            "container=aragorn-phase3-final-combined-v3-force-reinstall-$$",
            "container=aragorn-phase3-final-combined-v3-plugin-force-reinstall-$$",
            1,
        ),
    ):
        raw = _replace(raw, old, new, count)
    return raw


def _collector(raw: bytes) -> bytes:
    for old, new in (
        (_OLD_PARENT, _PARENT),
        (
            '"v3_plugin_force_reinstall_systemd.sh"',
            '"v3_plugin_force_reinstall_current_parent_systemd.sh"',
        ),
        (
            '"plugin-force-reinstall-systemd/Dockerfile"',
            '"plugin-force-reinstall-current-parent-systemd/Dockerfile"',
        ),
        (
            '"plugin_force_reinstall_systemd_probe.py",',
            '"plugin_force_reinstall_current_parent_systemd_probe.py",',
        ),
    ):
        raw = _replace(raw, old, new)
    return raw


def _dockerfile() -> bytes:
    # No route/runtime mutation: only three new provenance sources are copied.
    lines = [
        f"FROM {_PARENT}",
        "",
        f"COPY {_RECIPE} {_COLLECTOR} /src/scripts/",
        f"COPY Dockerfile /src/{_DOCKER_DIRECTORY}/Dockerfile",
        "",
        "# Exact current-parent child sources only; not a qualified deployment.",
        "RUN set -eux; \\",
    ]
    for path, (size, digest, mode) in _INHERITED.items():
        lines.extend(
            [
                f"    test ! -L {path}; \\",
                (
                    f"    test \"$(stat -c '%F:%u:%g:%a:%h:%s' {path})\" = "
                    f"'regular file:0:0:{mode[1:]}:1:{size}'; \\"
                ),
                f"    test \"$(sha256sum {path} | cut -d ' ' -f 1)\" = {digest[7:]}; \\",
            ]
        )
    inventory = ["plugin-force-reinstall:d"]
    # Directory link counts vary across layered filesystems (including 1 on
    # overlayfs); the exact inventory below binds topology independently.
    for name in ("", "/baseline-source", "/candidate-source"):
        path = "/route-input/plugin-force-reinstall" + name
        lines.extend(
            [
                (
                    f"    test ! -L {path}; test \"$(stat -c '%F:%u:%g:%a' {path})\" = "
                    "'directory:0:0:555'; \\"
                ),
                f"    test \"$(stat -c '%h' {path})\" -gt 0; \\",
            ]
        )
        if name:
            inventory.append("plugin-force-reinstall" + name + ":d")
    inventory.extend("plugin-force-reinstall/" + name + ":f" for name in _BUNDLE)
    lines.extend(
        [
            '    test -z "$(find /route-input -mindepth 1 ! -type d ! -type f -print -quit)"; \\',
            "    test \"$(find /route-input -mindepth 1 -printf '%P:%y\\n' | sort)\" = \\",
            "        \"$(printf '%s\\n' "
            + " ".join(f"'{name}'" for name in sorted(inventory))
            + ' | sort)"; \\',
            f"    chmod 0555 /src/scripts/{_RECIPE} /src/scripts/{_COLLECTOR}; \\",
            f"    chmod 0444 /src/{_DOCKER_DIRECTORY}/Dockerfile",
        ]
    )
    return ("\n".join(lines) + "\n").encode("ascii")


def _verified_inputs() -> dict[str, bytes]:
    source = {
        name: overlay._read_pinned(name, size, digest, root=_ROOT)
        for name, (size, digest) in _INPUTS.items()
    }
    rendered = {
        _RECIPE: _recipe(source[_OLD_RECIPE]),
        _COLLECTOR: _collector(source[_OLD_COLLECTOR]),
        "Dockerfile": _dockerfile(),
    }
    for name, raw in rendered.items():
        if (len(raw), overlay._digest(raw)) != _OUTPUTS[name]:
            raise PluginForceBuildSourceError(f"rendered build source changed: {name}")
    return rendered


def materialize_openclaw_final_v3_plugin_force_current_parent(
    output: Path,
) -> dict[str, Any]:
    """Write a new read-only three-file context, not an image or observation.

    The recipe takes a signed checkout root and absent observation path. It
    archives this renderer and its inputs from that commit before materializing
    the build context. No recipe is invoked here; partial writes return no proof.
    """
    try:
        if not isinstance(output, Path) or output.exists() or output.is_symlink():
            raise PluginForceBuildSourceError("output must be a new Path")
        rendered = _verified_inputs()
        overlay._write_overlay(output, rendered, ())
        return {
            "schema": _SCHEMA,
            "authority": _AUTHORITY,
            "case_id": _CASE,
            "parent_image_id": _PARENT,
            "child_image_id": None,
            "files": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in _OUTPUTS.items()
            ],
            "source_inputs": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (size, digest) in _INPUTS.items()
            ],
            "unchanged_inherited_bundle": [
                {"name": name, "bytes": size, "digest": digest}
                for name, (_, size, digest) in _BUNDLE.items()
            ],
            "execution_performed": False,
            "qualification_eligible": False,
            "phase3_exit_eligible": False,
            "release_eligible": False,
            "missing_validation": [
                "signed materializer commit and exact current-parent child build identity",
                "fresh host/parent custody, native capture, cleanup and CAS readback",
                "current-parent backend, semantic adapter and independent qualification",
            ],
        }
    except (OSError, TypeError, ValueError) as exc:
        raise PluginForceBuildSourceError(
            f"cannot materialize plugin-force build sources: {exc}"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    manifest = materialize_openclaw_final_v3_plugin_force_current_parent(
        parser.parse_args().output
    )
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
