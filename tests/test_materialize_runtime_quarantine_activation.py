from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import materialize_runtime_quarantine_activation as subject

_ROOT = Path(__file__).resolve().parents[1]
_SOURCES = {
    "packaging/systemd/aragorn-runtime-action-worker.service": (
        2573,
        "sha256:e4ef9e3f2229d92ed9dd9ee4896646e646d7171ee585ecba5aecdd87dba5e790",
    ),
    "packaging/activate-runtime-action-worker-host.sh": (
        32271,
        "sha256:dd615a00aacd5f76f52ac60400ea095f9014c2ef29d7793fd3ba35b26ffe3186",
    ),
}
_OUTPUTS = {
    "packaging/systemd/aragorn-runtime-action-worker.service": (
        2750,
        "sha256:4572460c7d54e29f8608fa16c9d97e645c2b32ea233377b5ae38e130461817d7",
    ),
    "packaging/activate-runtime-action-worker-host.sh": (
        34206,
        "sha256:3d88b892afd373dd30fcc90103b2f6643388e68d944b1b2492e8bcc54e010e88",
    ),
}
_OVERRIDES = {
    "runtime_action_broker_v5.py": "724e6114775450788fcce4ebb1b5d96a5ba35a7ae9ea6d70073114386969c072",
    "runtime_action_observation_publisher_v4.py": "12f8ee9ab6f91503cd1186bf814c640196ab489e1adbe0d26172d2dedb1baeac",
    "runtime_lineage_capability_issuer.py": "371b0e8f54796d11aef40a0f27f72e841987f8e1a4fdd039c6a7c3ad17c16cfd",
}
_WORKER = "aragorn-runtime-action-worker.service"
_GATEWAY = "aragorn-agent-gateway.service"
_BINDING_PAIR = '"worker-binding" "/etc/aragorn/runtime-action-worker.json"'
_CONFIG_PAIR = '"openclaw-config" "/etc/aragorn/agent-gateway/openclaw.json"'
_PRESTART = (
    "{ path=/usr/bin/python3.12 ; argv[]=/usr/bin/python3.12 -I -S -B "
    "/usr/libexec/aragorn/aragorn-runtime-skill-startup-service.py ; ignore_errors=no ; "
    "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
)


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _copy_inputs(root: Path) -> None:
    for name in (*_SOURCES, *subject._DEPENDENCIES, *subject.services._SERVICES):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_ROOT / name, path)


def _render() -> dict[str, bytes]:
    return subject._render(
        (_ROOT / subject._UNIT).read_bytes(),
        (_ROOT / subject._ACTIVATOR).read_bytes(),
    )


def _function(source: str, name: str) -> str:
    marker = "\n" + name + "()\n"
    if source.count(marker) != 1:
        raise AssertionError("shell helper must have exactly one definition")
    return name + "()\n" + source.split(marker, 1)[1].split("\n}\n", 1)[0] + "\n}\n"


def _shell_harness(activator: str, *, unit: str = _WORKER, **changes: str):
    # Only copied function definitions execute. No activation top-level, real
    # systemctl/busctl, source pin, root operation, or service startup is run.
    verification = _function(activator, "verify_unit")
    if verification.count("/usr/bin/busctl") != 1:
        raise AssertionError("expected exactly one inert busctl substitution")
    verification = verification.replace("/usr/bin/busctl", "fake_busctl")
    harness = r"""
set -eu
worker_unit=aragorn-runtime-action-worker.service
gateway_config=/etc/aragorn/agent-gateway/openclaw.json
fail_activation() { printf '%s\n' "$1" >&2; exit 77; }
readlink() {
    [ "$#" = 3 ] && [ "$1" = -f ] && [ "$2" = -- ] || exit 91
    printf '%s' "$3"
}
fake_busctl() {
    [ "$*" = "get-property org.freedesktop.systemd1 /test-object org.freedesktop.systemd1.Service LoadCredential" ] || exit 92
    [ "$TEST_BUS_FAIL" = 0 ] || return 1
    printf '%s' "$TEST_CREDENTIALS"
}
unit_property() {
    case "$2" in
        FragmentPath) printf '/usr/lib/systemd/system/%s' "$1" ;;
        DropInPaths|AmbientCapabilities|CapabilityBoundingSet) printf '' ;;
        User|Group) printf '%s' "$TEST_PRINCIPAL" ;;
        SupplementaryGroups) printf '%s' "$TEST_SUPPLEMENTARY" ;;
        NoNewPrivileges|PrivateMounts) printf yes ;;
        ProtectSystem) printf strict ;;
        ExecStart) printf '%s' "$TEST_EXEC" ;;
        ExecStartPre) printf '%s' "$TEST_PRESTART" ;;
        LimitNOFILE) printf '%s' "$TEST_HARD_LIMIT" ;;
        LimitNOFILESoft) printf '%s' "$TEST_SOFT_LIMIT" ;;
        *) exit 93 ;;
    esac
}
"""
    harness += _function(activator, "require_unit_value")
    harness += verification + _function(activator, "verify_worker_startup")
    if "/usr/bin/systemctl" in harness or "/usr/bin/busctl" in harness:
        raise AssertionError("function harness must contain no live systemd calls")
    harness += r"""
verify_unit "$TEST_UNIT" "$TEST_PRINCIPAL" "$TEST_PRINCIPAL" "$TEST_SUPPLEMENTARY" \
    "$TEST_COMMAND" "$TEST_EXPANDED" "$TEST_CREDENTIAL" /test-object
if [ "$TEST_UNIT" = "$worker_unit" ]; then verify_worker_startup; fi
printf 'verified\n'
"""
    command = next(
        line.removeprefix("ExecStart=")
        for line in (_ROOT / "packaging/systemd" / unit).read_text().splitlines()
        if line.startswith("ExecStart=")
    )
    environment = {
        "PATH": "/usr/bin:/bin",
        "TEST_UNIT": unit,
        "TEST_PRINCIPAL": "aragorn-runtime"
        if unit == _WORKER
        else "aragorn-agent-gateway",
        "TEST_SUPPLEMENTARY": "aragorn-agent-gateway"
        if unit == _WORKER
        else "aragorn-runtime",
        "TEST_COMMAND": command,
        "TEST_EXPANDED": command.replace("%d", "/run/credentials/" + unit),
        "TEST_EXEC": "{ path=/fixed-main ; argv[]="
        + command
        + " ; ignore_errors=no ; status=0/0 }",
        "TEST_PRESTART": _PRESTART,
        "TEST_CREDENTIAL": "worker-binding:/etc/aragorn/runtime-action-worker.json"
        if unit == _WORKER
        else "openclaw-config:/etc/aragorn/agent-gateway/openclaw.json",
        "TEST_CREDENTIALS": "a(ss) 2 " + _BINDING_PAIR + " " + _CONFIG_PAIR
        if unit == _WORKER
        else "a(ss) 1 " + _CONFIG_PAIR,
        "TEST_BUS_FAIL": "0",
        "TEST_HARD_LIMIT": "128",
        "TEST_SOFT_LIMIT": "128",
        **changes,
    }
    return subprocess.run(
        ["/bin/sh", "-c", harness],
        env=environment,
        cwd="/",
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )


class RuntimeQuarantineActivationTests(unittest.TestCase):
    def test_exact_flat_readonly_output_manifest_and_explicit_ceilings(self):
        self.assertEqual(subject._SOURCES, _SOURCES)
        self.assertEqual(subject._OUTPUTS, _OUTPUTS)
        self.assertEqual(len(subject._DEPENDENCIES), 5)
        self.assertEqual(len(subject.services._SERVICES), 3)
        original = {name: (_ROOT / name).read_bytes() for name in _SOURCES}
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "overlay"
            manifest = subject.materialize_runtime_quarantine_activation(output)
            self.assertEqual(
                set(manifest),
                {
                    "schema",
                    "authority",
                    "files",
                    "required_checkout_dependencies_not_included",
                    "required_runtime_overrides_not_included",
                    "gateway_config_digest",
                    "standalone_executable",
                    "production_activation_eligible",
                    "runtime_startup_enforcement",
                    "missing_release_inputs",
                },
            )
            self.assertEqual(
                manifest["schema"], "aragorn/runtime-quarantine-activation-overlay/v1"
            )
            self.assertEqual(
                manifest["authority"],
                "PINNED_ACTIVATION_SOURCE_ONLY_NOT_DEPLOYMENT_OR_PHASE3_QUALIFICATION",
            )
            for key in (
                "standalone_executable",
                "production_activation_eligible",
                "runtime_startup_enforcement",
            ):
                self.assertIs(manifest[key], False)
            self.assertIn("complete package", manifest["missing_release_inputs"][0])
            self.assertIn("real systemd", manifest["missing_release_inputs"][1])
            self.assertIn(
                "independent qualification", manifest["missing_release_inputs"][2]
            )
            config = json.loads(
                (
                    _ROOT
                    / "benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json"
                ).read_bytes()
            )
            canonical = json.dumps(
                config, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
            self.assertEqual(manifest["gateway_config_digest"], _sha(canonical))
            self.assertEqual(
                {p.name for p in output.iterdir()},
                {Path(name).name for name in _OUTPUTS},
            )
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o555)
            self.assertEqual(len(manifest["files"]), 2)
            for item in manifest["files"]:
                name = item["source_name"]
                path = output / Path(name).name
                raw = path.read_bytes()
                self.assertEqual((len(raw), _sha(raw)), _OUTPUTS[name])
                self.assertEqual(
                    item,
                    {
                        "name": Path(name).name,
                        "source_name": name,
                        "source_bytes": _SOURCES[name][0],
                        "source_digest": _SOURCES[name][1],
                        "bytes": _OUTPUTS[name][0],
                        "digest": _OUTPUTS[name][1],
                        "installed_path": (
                            "/usr/lib/systemd/system/"
                            if name == subject._UNIT
                            else "/usr/libexec/aragorn/"
                        )
                        + Path(name).name,
                        "installed_mode": "0644" if name == subject._UNIT else "0755",
                    },
                )
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
                self.assertEqual(path.stat().st_nlink, 1)
                self.assertEqual((_ROOT / name).read_bytes(), original[name])
            self.assertEqual(
                manifest["required_checkout_dependencies_not_included"],
                [
                    {"name": name, "bytes": size, "digest": digest}
                    for name, (size, digest) in subject._DEPENDENCIES.items()
                ],
            )
            self.assertEqual(
                manifest["required_runtime_overrides_not_included"],
                [
                    {"name": name, "bytes": values[2], "digest": values[3]}
                    for name, values in subject.services._SERVICES.items()
                ],
            )
            syntax = subprocess.run(
                ["/bin/sh", "-n", str(output / Path(subject._ACTIVATOR).name)],
                capture_output=True,
                timeout=3,
                check=False,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr.decode())

    def test_all_installed_module_and_unit_pins_match_exact_assembled_inputs(self):
        rendered = _render()
        source = rendered[subject._ACTIVATOR].decode()
        block = source.split("done <<'EOF'\n", 1)[1].split("\nEOF", 1)[0]
        pins = [line.split(" ", 2) for line in block.splitlines()]
        self.assertEqual(len(pins), 43)  # 36 old local pins + 5 dependencies + 2 tools.
        self.assertEqual(len({path for _, _, path in pins}), len(pins))
        for mode, digest, path in pins:
            name = Path(path).name
            if path in {"/usr/local/bin/python3.12", "/usr/local/bin/node"}:
                self.assertEqual(mode, "755")
                continue  # External interpreter pins are preserved, not verified here.
            if path == "/usr/libexec/aragorn/activate-runtime-capability-host.sh":
                candidate = _ROOT / "packaging" / name
            elif path.startswith("/usr/libexec/aragorn/"):
                candidate = _ROOT / "packaging/libexec" / name
            elif path.startswith("/usr/lib/aragorn/aragorn/"):
                candidate = _ROOT / "src/aragorn" / name
            else:
                candidate = (
                    _ROOT / "packaging/openclaw/aragorn-runtime-action-worker" / name
                )
            expected = _OVERRIDES.get(name, _sha(candidate.read_bytes())[7:])
            self.assertEqual(digest, expected, path)
            self.assertEqual(mode, "755" if path.startswith("/usr/libexec/") else "644")
        units = {
            '"$worker_unit"': "aragorn-runtime-action-worker.service",
            '"$gateway_unit"': "aragorn-agent-gateway.service",
            '"$broker_unit"': "aragorn-runtime-lineage-capability-action-broker.service",
            '"$sensor_unit"': "aragorn-runtime-lineage-capability-observation-publisher.service",
            "aragorn-runtime-revocation-publisher.service": "aragorn-runtime-revocation-publisher.service",
        }
        matches = re.findall(
            r"^require_unit_file \\\n    ([^\n]+) \\\n    ([0-9a-f]{64})$",
            source,
            re.MULTILINE,
        )
        self.assertEqual(len(matches), 5)
        for reference, digest in matches:
            name = units[reference]
            raw = (
                rendered[subject._UNIT]
                if reference == '"$worker_unit"'
                else (_ROOT / "packaging/systemd" / name).read_bytes()
            )
            self.assertEqual(digest, _sha(raw)[7:])
        unit = rendered[subject._UNIT].decode()
        expected = (
            (_ROOT / subject._UNIT)
            .read_text()
            .replace(
                "LoadCredential=worker-binding:/etc/aragorn/runtime-action-worker.json\n",
                "LoadCredential=worker-binding:/etc/aragorn/runtime-action-worker.json\n"
                "LoadCredential=openclaw-config:/etc/aragorn/agent-gateway/openclaw.json\n"
                "ExecStartPre=/usr/bin/python3.12 -I -S -B /usr/libexec/aragorn/aragorn-runtime-skill-startup-service.py\n",
            )
            .replace("LimitNOFILE=64\n", "LimitNOFILE=128\n")
        )
        self.assertEqual(unit, expected)
        self.assertLess(
            source.index("\nverify_worker_startup\n"),
            source.index('start "$worker_unit"'),
        )

    def test_each_source_dependency_and_runtime_source_drift_prevents_publication(self):
        for name in (*_SOURCES, *subject._DEPENDENCIES, *subject.services._SERVICES):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _copy_inputs(root)
                path = root / name
                path.write_bytes(b"!" + path.read_bytes()[1:])
                with (
                    mock.patch.object(subject, "_ROOT", root),
                    self.assertRaises(subject.RuntimeQuarantineActivationError),
                ):
                    subject.materialize_runtime_quarantine_activation(root / "overlay")
                self.assertFalse((root / "overlay").exists())

    def test_size_and_digest_pins_are_independently_required(self):
        for attribute in ("_SOURCES", "_OUTPUTS"):
            for dimension in ("size", "digest"):
                with (
                    self.subTest(attribute=attribute, dimension=dimension),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    pins = getattr(subject, attribute).copy()
                    size, digest = pins[subject._UNIT]
                    pins[subject._UNIT] = (
                        (size + 1, digest)
                        if dimension == "size"
                        else (size, "sha256:" + "0" * 64)
                    )
                    output = Path(temporary) / "overlay"
                    with (
                        mock.patch.object(subject, attribute, pins),
                        self.assertRaises(subject.RuntimeQuarantineActivationError),
                    ):
                        subject.materialize_runtime_quarantine_activation(output)
                    self.assertFalse(output.exists())
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "overlay"
            with (
                mock.patch.object(
                    subject.services, "_transform", side_effect=lambda raw: raw
                ),
                self.assertRaisesRegex(
                    subject.RuntimeQuarantineActivationError,
                    "runtime service output changed",
                ),
            ):
                subject.materialize_runtime_quarantine_activation(output)
            self.assertFalse(output.exists())

    def test_replacement_shapes_require_exactly_one_match(self):
        for raw in (b"missing", b"match match"):
            with (
                self.subTest(raw=raw),
                self.assertRaisesRegex(
                    subject.RuntimeQuarantineActivationError, "shape changed"
                ),
            ):
                subject._replace(raw, "match", "replacement")
        self.assertEqual(
            subject._replace(b"match", "match", "replacement"), b"replacement"
        )

    def test_fifo_symlink_and_hardlink_inputs_reject_with_bounded_reader(self):
        for kind in ("fifo", "symlink", "hardlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _copy_inputs(root)
                path = root / subject._UNIT
                if kind == "hardlink":
                    os.link(path, root / "second-link")
                else:
                    path.unlink()
                    os.mkfifo(path, 0o444) if kind == "fifo" else path.symlink_to(
                        _ROOT / subject._UNIT
                    )
                script = "from pathlib import Path\nimport sys\nfrom scripts import materialize_runtime_quarantine_activation as m\nm._ROOT=Path(sys.argv[1])\ntry: m.materialize_runtime_quarantine_activation(m._ROOT/'overlay')\nexcept m.RuntimeQuarantineActivationError: pass\nelse: raise SystemExit(1)\n"
                result = subprocess.run(
                    [sys.executable, "-B", "-c", script, str(root)],
                    cwd=_ROOT,
                    capture_output=True,
                    timeout=3,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertFalse((root / "overlay").exists())

    def test_existing_outputs_and_partial_publication_failures_never_succeed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            alias = root / "alias"
            alias.symlink_to(root)
            dangling = root / "dangling"
            dangling.symlink_to(root / "missing")
            for output in (root, alias, dangling, str(root / "not-Path")):
                with (
                    self.subTest(output=output),
                    self.assertRaises(subject.RuntimeQuarantineActivationError),
                ):
                    subject.materialize_runtime_quarantine_activation(output)
            for phase in ("zero-write", "wrong-bytes", "fsync", "second-file"):
                output = root / phase
                real_write, real_open = os.write, os.open

                def wrong_bytes(fd, raw, real_write=real_write):
                    return real_write(fd, b"x" * len(raw))

                def fail_second(path, flags, *args, real_open=real_open, **kwargs):
                    if (
                        flags & os.O_CREAT
                        and Path(path).name == Path(subject._ACTIVATOR).name
                    ):
                        raise OSError("second file failed")
                    return real_open(path, flags, *args, **kwargs)

                failure = {
                    "zero-write": mock.patch.object(
                        subject.overlay.os, "write", return_value=0
                    ),
                    "wrong-bytes": mock.patch.object(
                        subject.overlay.os, "write", side_effect=wrong_bytes
                    ),
                    "fsync": mock.patch.object(
                        subject.overlay.os, "fsync", side_effect=OSError("sync failed")
                    ),
                    "second-file": mock.patch.object(
                        subject.overlay.os, "open", side_effect=fail_second
                    ),
                }[phase]
                with (
                    self.subTest(phase=phase),
                    failure,
                    self.assertRaises(subject.RuntimeQuarantineActivationError),
                ):
                    subject.materialize_runtime_quarantine_activation(output)
                self.assertTrue(output.exists())

    def test_function_only_harness_accepts_worker_pair_orders_and_gateway_single(self):
        activator = _render()[subject._ACTIVATOR].decode()
        for unit, credentials in (
            (_WORKER, "a(ss) 2 " + _BINDING_PAIR + " " + _CONFIG_PAIR),
            (_WORKER, "a(ss) 2 " + _CONFIG_PAIR + " " + _BINDING_PAIR),
            (_GATEWAY, "a(ss) 1 " + _CONFIG_PAIR),
        ):
            with self.subTest(unit=unit, credentials=credentials):
                result = _shell_harness(
                    activator, unit=unit, TEST_CREDENTIALS=credentials
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "verified\n")

    def test_function_only_harness_rejects_credential_and_query_mutations(self):
        activator = _render()[subject._ACTIVATOR].decode()
        for unit, credentials in (
            (_WORKER, ""),
            (_WORKER, "a(ss) 1 " + _BINDING_PAIR),
            (_WORKER, "a(ss) 2 " + _CONFIG_PAIR + " " + _CONFIG_PAIR),
            (
                _WORKER,
                "a(ss) 2 "
                + _BINDING_PAIR
                + " "
                + _CONFIG_PAIR.replace("/etc/aragorn/", "/tmp/"),
            ),
            (
                _WORKER,
                "a(ss) 3 "
                + _BINDING_PAIR
                + " "
                + _CONFIG_PAIR
                + ' "extra" "/tmp/extra"',
            ),
            (_GATEWAY, "a(ss) 2 " + _BINDING_PAIR + " " + _CONFIG_PAIR),
            (_GATEWAY, "a(ss) 1 " + _BINDING_PAIR),
        ):
            with self.subTest(unit=unit, credentials=credentials):
                result = _shell_harness(
                    activator, unit=unit, TEST_CREDENTIALS=credentials
                )
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn("LoadCredential", result.stderr)
        result = _shell_harness(activator, TEST_BUS_FAIL="1")
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertIn("cannot inspect", result.stderr)

    def test_function_only_harness_preserves_main_command_validation(self):
        activator = _render()[subject._ACTIVATOR].decode()
        expanded = (
            "{ path=/usr/bin/python3.12 ; argv[]=/usr/bin/python3.12 -I -S -B "
            "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py "
            "/run/credentials/aragorn-runtime-action-worker.service/worker-binding "
            "; ignore_errors=no ; status=0/0 }"
        )
        result = _shell_harness(activator, TEST_EXEC=expanded)
        self.assertEqual(result.returncode, 0, result.stderr)
        for command in (
            "",
            expanded + " " + expanded,
            expanded.replace("worker-service.py", "other-service.py"),
        ):
            with self.subTest(command=command):
                result = _shell_harness(activator, TEST_EXEC=command)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn("ExecStart", result.stderr)

    def test_function_only_harness_requires_one_exact_nonignored_prestart_and_limits(
        self,
    ):
        activator = _render()[subject._ACTIVATOR].decode()
        commands = [
            "",
            _PRESTART + " " + _PRESTART,
            _PRESTART.replace("ignore_errors=no", "ignore_errors=yes"),
            _PRESTART.replace("path=/usr/bin/python3.12", "path=/bin/sh"),
            _PRESTART.replace(
                "startup-service.py ;", "startup-service.py /arbitrary ;"
            ),
            _PRESTART.replace("-I -S -B", "-I -B"),
            *[
                _PRESTART.replace("argv[]=/usr/bin/", "argv[]=" + prefix + "/usr/bin/")
                for prefix in ("-", "+", "!", "@", ":")
            ],
        ]
        for command in commands:
            with self.subTest(command=command):
                result = _shell_harness(activator, TEST_PRESTART=command)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertIn("ExecStartPre", result.stderr)
        for key in ("TEST_HARD_LIMIT", "TEST_SOFT_LIMIT"):
            for value in ("64", "", "infinity", "128.0"):
                with self.subTest(key=key, value=value):
                    result = _shell_harness(activator, **{key: value})
                    self.assertEqual(result.returncode, 77, result.stderr)
                    self.assertIn("LimitNOFILE", result.stderr)


if __name__ == "__main__":
    unittest.main()
