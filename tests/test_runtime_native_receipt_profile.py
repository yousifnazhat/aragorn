from __future__ import annotations

import copy
import io
import itertools
import os
import re
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from aragorn import runtime_native_tool_provisioning as provisioning
from aragorn.oci_worker_protocol import canonical_json
from scripts import stage_runtime_native_receipt_profile as subject
from tests.test_materialize_runtime_quarantine_activation import (
    _BINDING_PAIR,
    _CONFIG_PAIR,
    _GATEWAY,
    _PRESTART,
    _WORKER,
    _function,
)

_GENESIS_PAIR = '"native-tool-genesis" "/etc/aragorn/runtime-native-tool-genesis.json"'
_ACTIVATOR_PIN = (
    38837,
    "sha256:d24da2fba266b302da6f633fc0c161513f3e7f2e60f804572a749a3bdce3c1ea",
)


def _activator():
    original, replacements = subject._verified_payloads()
    return (
        replacements[subject._destination(subject._ACTIVATOR)[0]][2].decode(),
        original,
        replacements,
    )


def _shell(activator, unit=_WORKER, **changes):
    # Definitions only: no activator top-level, real busctl/systemctl, root
    # operation, file provisioning, or service process is executed.
    harness = r"""
set -eu
worker_unit=aragorn-runtime-action-worker.service
gateway_unit=aragorn-agent-gateway.service
worker_binding=/etc/aragorn/runtime-action-worker.json
gateway_config=/etc/aragorn/agent-gateway/openclaw.json
fail_activation() { printf '%s\n' "$1" >&2; exit 77; }
readlink() { printf '%s' "$3"; }
fake_busctl() { printf '%s' "$TEST_CREDENTIALS"; }
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
        StateDirectory) printf '%s' "$TEST_STATE" ;;
        StateDirectoryMode) printf '%s' "$TEST_STATE_MODE" ;;
        RuntimeDirectory) printf '%s' "$TEST_RUNTIME" ;;
        RuntimeDirectoryMode) printf '%s' "$TEST_RUNTIME_MODE" ;;
        *) exit 93 ;;
    esac
}
"""
    harness += _function(activator, "require_unit_value")
    harness += _function(activator, "verify_unit").replace(
        "/usr/bin/busctl", "fake_busctl"
    )
    harness += _function(activator, "verify_worker_startup")
    harness += r"""
verify_unit "$TEST_UNIT" "$TEST_PRINCIPAL" "$TEST_PRINCIPAL" "$TEST_SUPPLEMENTARY" \
    "$TEST_COMMAND" "$TEST_COMMAND" "$TEST_CREDENTIAL" /test-object
if [ "$TEST_UNIT" = "$worker_unit" ]; then verify_worker_startup; fi
printf 'verified\n'
"""
    if "/usr/bin/systemctl" in harness or "/usr/bin/busctl" in harness:
        raise AssertionError("unexpected live systemd call in isolated harness")
    environment = {
        "PATH": "/usr/bin:/bin",
        "TEST_UNIT": unit,
        "TEST_PRINCIPAL": "aragorn-runtime"
        if unit == _WORKER
        else "aragorn-agent-gateway",
        "TEST_SUPPLEMENTARY": "aragorn-agent-gateway"
        if unit == _WORKER
        else "aragorn-runtime",
        "TEST_COMMAND": "/fixed-main --fixed",
        "TEST_EXEC": "{ path=/fixed-main ; argv[]=/fixed-main --fixed ; ignore_errors=no ; status=0/0 }",
        "TEST_CREDENTIAL": "worker-binding:/etc/aragorn/runtime-action-worker.json"
        if unit == _WORKER
        else "openclaw-config:/etc/aragorn/agent-gateway/openclaw.json",
        "TEST_CREDENTIALS": f"a(ss) 3 {_BINDING_PAIR} {_CONFIG_PAIR} {_GENESIS_PAIR}"
        if unit == _WORKER
        else f"a(ss) 2 {_CONFIG_PAIR} {_GENESIS_PAIR}",
        "TEST_PRESTART": _PRESTART,
        "TEST_HARD_LIMIT": "128",
        "TEST_SOFT_LIMIT": "128",
        "TEST_STATE": "aragorn-runtime-tool-receipts",
        "TEST_STATE_MODE": "0700",
        "TEST_RUNTIME": "aragorn-runtime-action-worker",
        "TEST_RUNTIME_MODE": "0711",
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


def _binding_values():
    binding = {
        "schema": provisioning.startup.worker._BINDING_SCHEMA,
        "runtime_digest": subject._RUNTIME_TREE["tree_digest"],
        "active_skill_digest": "sha256:" + "1" * 64,
        "policy_digest": "sha256:" + "2" * 64,
        "policy_version": 1,
    }
    genesis = {
        "schema": "aragorn/native-tool-receipt-genesis/v1",
        "authority": "ROOT_PROVISIONED_WORKER_RECEIPT_STREAM_NOT_RUN_AUTHORITY",
        "stream_id": "sha256:" + "3" * 64,
        "runtime_digest": binding["runtime_digest"],
        "policy_digest": binding["policy_digest"],
        "policy_version": binding["policy_version"],
        "worker_uid": 1201,
        "worker_gid": 1202,
    }
    return binding, genesis


class RuntimeNativeReceiptProfileTests(unittest.TestCase):
    def test_exact_60_files_72_inputs_15_dependencies_and_no_authority(self):
        original, replacements = subject._verified_payloads()
        self.assertEqual(
            (len(original), len(replacements), len(original | replacements)),
            (55, 12, 60),
        )
        self.assertEqual(subject._ACTIVATOR_PIN, _ACTIVATOR_PIN)
        self.assertEqual(len(subject._SOURCE_PINS), 72)
        self.assertEqual(len(set(original) - set(replacements)), 48)
        final = original | replacements
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "stage"
            report = subject.stage_runtime_native_receipt_profile(output)
            self.assertEqual(report["schema"], subject._SCHEMA)
            self.assertEqual(report["authority"], subject._AUTHORITY)
            self.assertEqual(len(report["files"]), 60)
            self.assertEqual(len(report["source_inputs"]), 72)
            self.assertEqual(len(report["new_dependencies"]), 15)
            for dependency in report["new_dependencies"]:
                raw = final[subject._destination(dependency["name"])[0]][2]
                self.assertEqual(
                    (dependency["bytes"], dependency["digest"]),
                    (len(raw), subject.base.overlay._digest(raw)),
                )
            self.assertTrue(
                {
                    subject._CORE,
                    subject._PROVISIONER,
                    subject._GATEWAY_HELPER,
                    subject._GATEWAY_SHIM,
                    subject._INTEGRATION,
                }.issubset({row["name"] for row in report["new_dependencies"]}),
            )
            for name, (source, mode, raw) in final.items():
                path = output / name
                self.assertEqual(path.read_bytes(), raw)
                metadata = path.lstat()
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(
                    (
                        stat.S_IMODE(metadata.st_mode),
                        metadata.st_nlink,
                        metadata.st_uid,
                    ),
                    (mode, 1, os.geteuid()),
                )
                row = next(row for row in report["files"] if row["path"] == "/" + name)
                self.assertEqual(
                    row,
                    {
                        "path": "/" + name,
                        "source_name": source,
                        "mode": f"{mode:04o}",
                        "bytes": len(raw),
                        "digest": subject.base.overlay._digest(raw),
                    },
                )
            self.assertEqual(
                set(report["directories"]),
                {"/" + name for name in subject.base._directories(final)},
            )
            self.assertEqual(
                subject.base._directories(final) - subject.base._directories(original),
                {subject._NEW_DIRECTORY},
            )
            self.assertEqual(
                stat.S_IMODE((output / subject._NEW_DIRECTORY).stat().st_mode), 0o755
            )
            self.assertFalse((output / "runtime").exists())
            self.assertFalse(
                (output / "var/lib/aragorn-runtime-tool-receipts").exists()
            )
            self.assertFalse(
                (output / "etc/aragorn/runtime-native-tool-genesis.json").exists()
            )
            for name, value in report.items():
                if type(value) is bool:
                    self.assertIs(value, False, name)
            self.assertEqual(
                report["required_runtime_not_included"]["tree"], subject._RUNTIME_TREE
            )
            self.assertIn(
                "separate absent-only receipt provisioning",
                " ".join(report["missing_inputs"]),
            )
            self.assertEqual({path.name for path in output.parent.iterdir()}, {"stage"})
            shim = output / subject._destination(subject._GATEWAY_SHIM)[0]
            # Only CLI argument refusal; the fixed root credential paths are never read.
            refused = subprocess.run(
                [sys.executable, "-I", "-S", "-B", str(shim), "unexpected"],
                capture_output=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(refused.returncode, 64, refused.stderr)
            self.assertEqual(refused.stdout, b"")

    def test_all_installed_pins_runtime_join_and_prestart_order(self):
        activator, original, replacements = _activator()
        self.assertEqual(
            (len(activator.encode()), subject.base.overlay._digest(activator.encode())),
            _ACTIVATOR_PIN,
        )
        final = original | replacements
        lines = re.findall(
            r"^(644|755) ([0-9a-f]{64}) (/usr/(?:lib|libexec)/aragorn/\S+)$",
            activator,
            re.MULTILINE,
        )
        self.assertGreater(len(lines), 35)
        for mode, digest, absolute in lines:
            source, expected_mode, raw = final[absolute[1:]]
            self.assertEqual(
                (int(mode, 8), "sha256:" + digest),
                (expected_mode, subject.base.overlay._digest(raw)),
                source,
            )
        for name in (subject.receipts._UNIT, subject.credentials._UNIT):
            self.assertEqual(activator.count(subject._OUTPUT_PINS[name][1][7:]), 1)
        self.assertNotIn(subject._OLD_RUNTIME, activator)
        self.assertEqual(activator.count(subject._NEW_RUNTIME), 1)
        self.assertIn(subject._BINDING_CHECK, activator)
        self.assertIn('"$worker_uid" "$worker_gid" <<\'PY\'', activator)
        before = 'require_exact_directory /var/lib/aragorn-runtime-tool-receipts "$worker_uid" "$worker_gid" 700'
        self.assertLess(
            activator.index(before),
            activator.index('ARAGORN_RUNTIME_ACTIVATION_LOCK_HELD=1 "$base_activator"'),
        )
        self.assertNotIn("provision_runtime_native_tool_receipts(", activator)
        self.assertIn(
            "require_root_secret /etc/aragorn/runtime-native-tool-genesis.json 4096",
            activator,
        )
        self.assertEqual(
            final[subject.base._destination(subject.drain._BROKER)[0]],
            original[subject.base._destination(subject.drain._BROKER)[0]],
        )
        syntax = subprocess.run(
            ["/bin/sh", "-n"],
            input=activator,
            text=True,
            capture_output=True,
            timeout=3,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        with self.assertRaises(ValueError):
            subject._render_activator(activator.encode(), original)

    def test_exact_credential_permutations_and_effective_state_startup_rejections(self):
        activator, _, _ = _activator()
        for unit, pairs in (
            (_WORKER, (_BINDING_PAIR, _CONFIG_PAIR, _GENESIS_PAIR)),
            (_GATEWAY, (_CONFIG_PAIR, _GENESIS_PAIR)),
        ):
            for permutation in itertools.permutations(pairs):
                with self.subTest(unit=unit, permutation=permutation):
                    result = _shell(
                        activator,
                        unit,
                        TEST_CREDENTIALS=f"a(ss) {len(pairs)} " + " ".join(permutation),
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, "verified\n")
            valid = f"a(ss) {len(pairs)} " + " ".join(pairs)
            for changed in (
                valid.replace("native-tool-genesis", "other"),
                valid.replace("runtime-native-tool-genesis.json", "different.json"),
                valid + " " + _GENESIS_PAIR,
                valid.replace(_GENESIS_PAIR, _CONFIG_PAIR),
                f"a(ss) {len(pairs) - 1} " + " ".join(pairs[:-1]),
            ):
                with self.subTest(unit=unit, credentials=changed):
                    self.assertEqual(
                        _shell(activator, unit, TEST_CREDENTIALS=changed).returncode, 77
                    )
        for field, values in {
            "TEST_STATE": ("", "other", "aragorn-runtime-tool-receipts extra"),
            "TEST_STATE_MODE": ("700", "0750", "0777"),
            "TEST_RUNTIME": ("", "other"),
            "TEST_RUNTIME_MODE": ("711", "0700", "0777"),
            "TEST_HARD_LIMIT": ("127", "129"),
            "TEST_SOFT_LIMIT": ("127", "129"),
            "TEST_PRESTART": (
                "",
                _PRESTART.replace("ignore_errors=no", "ignore_errors=yes"),
                _PRESTART.replace(" -I ", " -x "),
                _PRESTART + " " + _PRESTART,
            ),
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    result = _shell(activator, **{field: value})
                    self.assertEqual(result.returncode, 77, result.stderr)

    def test_fixed_root_source_binding_join_and_cleanup_fail_closed(self):
        name = "aragorn._native_gateway_source_join_test"
        gateway = types.ModuleType(name)
        gateway.__package__ = "aragorn"
        raw = subject.credentials._verified_inputs()[
            "runtime_native_gateway_credentials.py"
        ]
        with mock.patch.dict(sys.modules, {name: gateway}):
            exec(compile(raw, subject._GATEWAY_HELPER, "exec"), gateway.__dict__)  # noqa: S102 - exact pinned local generated helper
        binding, genesis = _binding_values()
        for change in (
            None,
            "binding-runtime",
            "genesis-runtime",
            "policy",
            "version",
            "bool-version",
            "uid",
            "extra",
            "recheck",
            "close",
        ):
            candidate_binding, candidate_genesis = copy.deepcopy((binding, genesis))
            if change == "binding-runtime":
                candidate_binding["runtime_digest"] = "sha256:" + "4" * 64
                candidate_genesis["runtime_digest"] = candidate_binding[
                    "runtime_digest"
                ]
            elif change == "genesis-runtime":
                candidate_genesis["runtime_digest"] = "sha256:" + "4" * 64
            elif change == "policy":
                candidate_genesis["policy_digest"] = "sha256:" + "4" * 64
            elif change == "version":
                candidate_genesis["policy_version"] = 2
            elif change == "bool-version":
                candidate_genesis["policy_version"] = True
            elif change == "uid":
                candidate_genesis["worker_uid"] = 1203
            elif change == "extra":
                candidate_genesis["extra"] = 1
            proxy = types.SimpleNamespace(
                _require_root=mock.Mock(),
                _root_directory=mock.Mock(return_value=7),
                _hold_file=mock.Mock(
                    side_effect=[
                        types.SimpleNamespace(raw=canonical_json(candidate_binding)),
                        types.SimpleNamespace(raw=canonical_json(candidate_genesis)),
                    ]
                ),
                _recheck=mock.Mock(
                    side_effect=RuntimeError("changed") if change == "recheck" else None
                ),
                _close=mock.Mock(
                    side_effect=RuntimeError("close") if change == "close" else None
                ),
                startup=provisioning.startup,
                broker=provisioning.broker,
            )
            namespace = {
                "provisioning": proxy,
                "gateway_credentials": gateway,
                "Path": Path,
            }
            definition = subject._BINDING_CHECK.rsplit("\nverify_native_sources(", 1)[0]
            exec(compile(definition, "fixed-native-source-check", "exec"), namespace)  # noqa: S102 - fixed local function only, fake all filesystem/identity helpers
            with self.subTest(change=change):
                if change is None:
                    namespace["verify_native_sources"](1201, 1202)
                    self.assertEqual(
                        proxy._root_directory.call_args.args[0], Path("/etc/aragorn")
                    )
                    self.assertEqual(
                        [call.args[:6] for call in proxy._hold_file.call_args_list],
                        [
                            (7, "runtime-action-worker.json", 0, 0, 0o400, 4096),
                            (7, "runtime-native-tool-genesis.json", 0, 0, 0o400, 4096),
                        ],
                    )
                    proxy._recheck.assert_called_once()
                else:
                    with self.assertRaises((RuntimeError, ValueError, SystemExit)):
                        namespace["verify_native_sources"](1201, 1202)
                proxy._require_root.assert_called_once_with()
                proxy._close.assert_called_once()

    def test_source_drift_nonregulars_bad_destination_and_partial_publication(self):
        original, replacements = subject._verified_payloads()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            pins = dict(subject._SOURCE_PINS)
            pins[subject._INTEGRATION] = (1, "sha256:" + "0" * 64)
            with (
                mock.patch.object(subject, "_SOURCE_PINS", pins),
                self.assertRaises(subject.RuntimeNativeReceiptStageError),
            ):
                subject.stage_runtime_native_receipt_profile(root / "drift")
            self.assertFalse((root / "drift").exists())
            with (
                mock.patch.object(subject, "_ACTIVATOR_PIN", (1, "sha256:" + "0" * 64)),
                self.assertRaises(subject.RuntimeNativeReceiptStageError),
            ):
                subject.stage_runtime_native_receipt_profile(root / "bad-render")
            self.assertFalse((root / "bad-render").exists())
            fifo = root / "fifo"
            os.mkfifo(fifo)
            link = root / "link"
            link.symlink_to(fifo)
            for path in (fifo, link):
                with (
                    self.subTest(path=path.name),
                    self.assertRaises((ValueError, OSError)),
                ):
                    subject.base.overlay._read_pinned(
                        path.name, 1, "sha256:" + "0" * 64, root=root
                    )
            existing = root / "existing"
            existing.mkdir()
            for destination in (
                Path("relative"),
                existing,
                link,
                str(root / "wrong-type"),
            ):
                with (
                    self.subTest(destination=destination),
                    self.assertRaises(subject.RuntimeNativeReceiptStageError),
                ):
                    subject.stage_runtime_native_receipt_profile(destination)
            apply = subject.base._apply_overrides

            def partial(output, payloads):
                if len(payloads) == 12:
                    apply(output, dict(list(payloads.items())[:1]))
                    raise OSError("partial publication")
                return apply(output, payloads)

            with (
                mock.patch.object(
                    subject.base, "_apply_overrides", side_effect=partial
                ),
                self.assertRaises(subject.RuntimeNativeReceiptStageError),
            ):
                subject.stage_runtime_native_receipt_profile(root / "partial")
            self.assertTrue((root / "partial" / subject._NEW_DIRECTORY).is_dir())
            with (
                mock.patch.object(
                    subject,
                    "_verified_payloads",
                    side_effect=[(original, replacements), (original, {})],
                ),
                self.assertRaises(subject.RuntimeNativeReceiptStageError),
            ):
                subject.stage_runtime_native_receipt_profile(root / "late-drift")

    def test_new_directory_parent_race_and_descriptor_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve()
            parent = output / Path(subject._NEW_DIRECTORY).parent
            parent.mkdir(parents=True)
            saved = subject.base._parent_custody(parent)
            changed = (saved[0], saved[1] + 1, *saved[2:])
            with (
                mock.patch.object(
                    subject.base, "_parent_custody", return_value=changed
                ),
                self.assertRaises(subject.RuntimeNativeReceiptStageError),
            ):
                subject._add_directory(output)
            self.assertFalse((output / subject._NEW_DIRECTORY).exists())
            subject._add_directory(output)
            with self.assertRaises(FileExistsError):
                subject._add_directory(output)
        for failure_at in ("child", "parent"):
            with tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary).resolve()
                parent = output / Path(subject._NEW_DIRECTORY).parent
                parent.mkdir(parents=True)
                real_close = os.close
                closed = []

                def close(
                    fd, *, failure_at=failure_at, real_close=real_close, closed=closed
                ):
                    real_close(fd)
                    closed.append(fd)
                    if len(closed) == (1 if failure_at == "child" else 2):
                        raise OSError("close uncertainty")

                with (
                    mock.patch.object(subject.os, "close", side_effect=close),
                    self.assertRaises(OSError),
                ):
                    subject._add_directory(output)
                self.assertEqual(len(closed), 2)

    def test_cli_failure_never_prints_success_manifest(self):
        output = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["stage", "/absent"]),
            mock.patch.object(
                subject,
                "stage_runtime_native_receipt_profile",
                side_effect=subject.RuntimeNativeReceiptStageError("fixed refusal"),
            ),
            redirect_stdout(output),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(subject.main(), 1)
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
