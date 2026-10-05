"""Offline prepare/retain/replay of one caller-pinned plugin-update observation.

Operational results use a JSON envelope on stdout; refusals exit 2. ``--help``
prints ordinary argparse usage text. Preparation
does not write and is only a post-observation identity projection, not a prior
commitment or live measurement. Its raw byte fields are displayed as explicit
UTF-8 text wrappers; extract ``result.deployment_raw.text`` without adding a
newline when separately reviewing/supplying deployment bytes to ``retain``.
Only retain writes, exclusively through the supplied CAS. No capture execution,
activation, network, dynamic imports, repair, or qualification is provided.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from contextlib import contextmanager
from pathlib import Path

from aragorn import native_phase3_plugin_update_collection as collection
from aragorn.cas import CAS, CASError

_CAPTURE_LIMIT = 2 * 1024 * 1024
_DEPLOYMENT_LIMIT = 4096
_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_SCHEMA = "aragorn/native-plugin-update-collection-cli/v1"


class CollectionCLIError(ValueError):
    """An explicit input or offline command boundary was refused."""


class _Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, allow_abbrev=False)

    def error(self, message):
        raise CollectionCLIError(message)


def _require(condition, message):
    if not condition:
        raise CollectionCLIError(message)


def _identity(info, *, directory=False):
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
    if not directory:
        fields += ("st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    return tuple(getattr(info, key) for key in fields)


def _absolute(value):
    _require(".." not in Path(value).parts, "parent traversal is not a direct path")
    return Path(os.path.abspath(value))


def _read_bounded(fd, limit):
    os.lseek(fd, 0, os.SEEK_SET)
    result = bytearray()
    while chunk := os.read(fd, min(65536, limit + 1 - len(result))):
        result.extend(chunk)
        _require(len(result) <= limit, "input exceeds its byte bound")
    return bytes(result)


@contextmanager
def _input_bytes(value, *, limit):
    """Hold a no-follow descriptor chain and recheck exact input after use."""
    path = _absolute(value)
    held = []
    links = []
    try:
        held.append(os.open(path.anchor, _FLAGS | os.O_DIRECTORY))
        for name in path.parts[1:-1]:
            parent = held[-1]
            child = os.open(name, _FLAGS | os.O_DIRECTORY, dir_fd=parent)
            held.append(child)
            links.append(
                (parent, name, child, _identity(os.fstat(child), directory=True))
            )
        parent = held[-1]
        leaf = os.open(path.name, _FLAGS | os.O_NONBLOCK, dir_fd=parent)
        held.append(leaf)
        before = os.fstat(leaf)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and 0 < before.st_size <= limit,
            "input is not a bounded direct regular file",
        )
        expected = _identity(before)
        raw = _read_bounded(leaf, limit)

        def guard():
            observed_before = _identity(os.fstat(leaf))
            observed = _read_bounded(leaf, limit)
            for owner, name, child, identity in links:
                _require(
                    _identity(os.fstat(child), directory=True)
                    == identity
                    == _identity(
                        os.stat(name, dir_fd=owner, follow_symlinks=False),
                        directory=True,
                    ),
                    "input directory identity changed",
                )
            _require(
                expected
                == observed_before
                == _identity(os.fstat(leaf))
                == _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
                and len(raw) == before.st_size
                and observed == raw,
                "input bytes or identity changed",
            )

        guard()
        yield raw
        guard()
    finally:
        for descriptor in reversed(held):
            os.close(descriptor)


@contextmanager
def _store(value, *, read_only):
    path = _absolute(value)
    # Require a real existing parent; CAS alone may create its selected root.
    _require(
        path.parent.resolve(strict=True) == path.parent,
        "CAS parent must be direct and contain no symlink",
    )
    _require(path.resolve(strict=False) == path, "CAS root must be direct")
    store = CAS(path, read_only=read_only)
    before = _identity(os.lstat(path), directory=True)
    yield store
    _require(
        path.resolve(strict=True) == path
        and _identity(os.lstat(path), directory=True) == before,
        "CAS root identity changed",
    )


def _pin(value):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise argparse.ArgumentTypeError(
            "expected a sha256: lowercase hexadecimal digest"
        )
    return value


def _commit(value):
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise argparse.ArgumentTypeError(
            "expected a 40-character lowercase source commit"
        )
    return value


def _parser():
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(
        dest="command", required=True, parser_class=_Parser
    )
    for name, help_text in (
        ("prepare", "Read-only reported identity projection for separate review"),
        ("retain", "Retain exact capture and separately reviewed deployment in CAS"),
        ("replay", "Read-only replay of a caller-pinned retained collection"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--expected-capture-digest", type=_pin, required=True)
        command.add_argument("--expected-source-digest", type=_pin, required=True)
        command.add_argument("--expected-source-commit", type=_commit, required=True)
        if name != "replay":
            command.add_argument("--capture", required=True)
        if name != "prepare":
            command.add_argument(
                "--expected-deployment-digest", type=_pin, required=True
            )
            command.add_argument("--cas", required=True)
        if name == "retain":
            command.add_argument("--deployment", required=True)
        if name == "replay":
            command.add_argument(
                "--expected-collection-digest", type=_pin, required=True
            )
    return parser


def _display_preparation(prepared):
    result = dict(prepared)
    for key in ("source_raw", "deployment_raw"):
        result[key] = {"encoding": "utf-8", "text": prepared[key].decode("utf-8")}
    result["identity_artifacts"] = {
        name: {"encoding": "utf-8", "text": raw.decode("utf-8")}
        for name, raw in prepared["identity_artifacts"].items()
    }
    return result


def _run(args):
    pins = {
        "expected_capture_digest": args.expected_capture_digest,
        "expected_source_digest": args.expected_source_digest,
        "expected_source_commit": args.expected_source_commit,
    }
    if args.command == "replay":
        with _store(args.cas, read_only=True) as store:
            result = collection.replay_native_plugin_update_collection(
                **pins,
                expected_collection_digest=args.expected_collection_digest,
                expected_deployment_digest=args.expected_deployment_digest,
                evidence_cas=store,
            )
        return result
    with _input_bytes(args.capture, limit=_CAPTURE_LIMIT) as capture:
        if args.command == "prepare":
            result = _display_preparation(
                collection.prepare_native_plugin_update_collection(capture, **pins)
            )
        else:
            with (
                _input_bytes(args.deployment, limit=_DEPLOYMENT_LIMIT) as deployment,
                _store(args.cas, read_only=False) as store,
            ):
                result = collection.collect_native_plugin_update_observation(
                    capture,
                    **pins,
                    deployment_raw=deployment,
                    expected_deployment_digest=args.expected_deployment_digest,
                    evidence_cas=store,
                )
    return result


def main(argv=None):
    command = None
    try:
        args = _parser().parse_args(argv)
        command = args.command
        result = _run(args)
        output = {
            "schema": _SCHEMA,
            "status": "OK",
            "command": command,
            "result": result,
        }
        encoded = json.dumps(
            output, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        code = 0
    except (OSError, ValueError, CASError) as exc:
        encoded = json.dumps(
            {
                "schema": _SCHEMA,
                "status": "REFUSED",
                "command": command,
                "error": str(exc)[:2048],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        code = 2
    print(encoded)
    return code


if __name__ == "__main__":
    sys.exit(main())
