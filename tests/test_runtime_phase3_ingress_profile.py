"""Only the new inert profile and fixed provisioning code under OS doubles."""

import ast
from contextlib import contextmanager
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import stage_runtime_phase3_ingress_profile as subject


class _ProvisionOS:
    """No real process, account, directory, service or descriptor is accessed."""

    O_RDONLY = 0
    O_DIRECTORY = 1
    O_NOFOLLOW = 2
    O_CLOEXEC = 4
    O_NONBLOCK = 8

    def __init__(self):
        self.events = []
        self.entries = []
        self.exists = False
        self.fail = None
        self.close_failure = None
        self.altered_leaf = False
        self.records = {
            descriptor: SimpleNamespace(
                st_dev=9,
                st_ino=descriptor,
                st_uid=0,
                st_gid=0,
                st_mode=stat.S_IFDIR | (0o700 if descriptor == 4 else 0o755),
            )
            for descriptor in (1, 2, 3, 4)
        }

    def geteuid(self):
        return 0

    def getegid(self):
        return 0

    def open(self, name, flags, *, dir_fd=None):
        if flags != 15:
            raise AssertionError("missing fixed directory descriptor guards")
        expected = {
            ("/", None): 1,
            ("var", 1): 2,
            ("lib", 2): 3,
            ("aragorn-runtime-worker-measurement", 3): 4,
        }
        result = expected[(name, dir_fd)]
        self.events.append(("open", result))
        return result

    def fstat(self, descriptor):
        return SimpleNamespace(**vars(self.records[descriptor]))

    def lstat(self, path):
        if path != "/":
            raise AssertionError("unexpected root read")
        return self.fstat(1)

    def stat(self, name, *, dir_fd, follow_symlinks):
        if follow_symlinks:
            raise AssertionError("followed untrusted directory link")
        descriptor = {
            ("var", 1): 2,
            ("lib", 2): 3,
            ("aragorn-runtime-worker-measurement", 3): 4,
        }[(name, dir_fd)]
        result = self.fstat(descriptor)
        if self.altered_leaf and descriptor == 4:
            result.st_ino += 1
        return result

    def umask(self, mode):
        if mode != 0o077:
            raise AssertionError("wrong private creation umask")
        self.events.append(("umask", mode))

    def mkdir(self, name, mode, *, dir_fd):
        if (name, mode, dir_fd) != ("aragorn-runtime-worker-measurement", 0o700, 3):
            raise AssertionError("unexpected provisioning target")
        self.events.append(("mkdir", name))
        if self.exists:
            raise FileExistsError("retained existing claim")
        self.exists = True

    def fsync(self, descriptor):
        self.events.append(("fsync", descriptor))
        if self.fail == "sync":
            raise OSError("inert sync failure")

    @contextmanager
    def scandir(self, descriptor):
        if descriptor != 4:
            raise AssertionError("unexpected inventory descriptor")
        yield iter(self.entries)

    def fchown(self, descriptor, uid, gid):
        if descriptor != 4:
            raise AssertionError("changed ancestor ownership")
        self.events.append(("chown", descriptor, uid, gid))
        if self.fail == "chown":
            raise OSError("inert chown failure")
        self.records[descriptor].st_uid = uid
        self.records[descriptor].st_gid = gid

    def fchmod(self, descriptor, mode):
        if (descriptor, mode) != (4, 0o700):
            raise AssertionError("changed ancestor permissions")
        self.events.append(("chmod", descriptor, mode))
        self.records[descriptor].st_mode = stat.S_IFDIR | mode

    def close(self, descriptor):
        self.events.append(("close", descriptor))
        if descriptor == 4 and self.close_failure is not None:
            raise self.close_failure


def _provision(fake, uid="997", gid="997"):
    parsed = ast.parse(subject._PROVISION_PY)
    imported = [
        alias.name
        for node in parsed.body
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    if imported != ["os", "stat", "sys"]:
        raise AssertionError("fixed provisioning import contract changed")
    # Execute only the new inline code, with no filesystem/process implementation.
    parsed.body = [node for node in parsed.body if not isinstance(node, ast.Import)]
    exec(
        compile(parsed, "<inert-ingress-provisioning>", "exec"),
        {
            "os": fake,
            "stat": stat,
            "sys": SimpleNamespace(argv=["-", uid, gid]),
        },
    )


class Phase3IngressProfileTests(unittest.TestCase):
    def test_four_exact_overrides_are_reversible_and_only_one_file_is_added(self):
        original, replacements = subject._verified_payloads()
        expected = {subject._destination(name)[0] for name in subject._OUTPUTS}
        self.assertEqual(set(replacements), expected)
        self.assertEqual(len(original), 73)
        self.assertEqual(len(original | replacements), 74)
        self.assertEqual(len(subject.base._directories(original | replacements)), 16)
        helper = subject._destination(subject._HELPER)[0]
        self.assertEqual(set(replacements) - set(original), {helper})
        unit_path = subject._destination(subject._UNIT)[0]
        worker_path = subject._destination(subject._WORKER)[0]
        activator_path = subject._destination(subject._ACTIVATOR)[0]
        unit = replacements[unit_path][2]
        self.assertEqual(
            unit.replace(subject._UNIT_WRITE_PATH, b""), original[unit_path][2]
        )
        self.assertEqual(unit.count(b"StateDirectory="), 1)
        self.assertIn(b"StateDirectory=aragorn-runtime-tool-receipts\n", unit)
        self.assertIn(b"Restart=no\n", unit)
        self.assertEqual(
            replacements[worker_path][2], subject.renderer._verified_inputs()
        )
        script = replacements[activator_path][2]
        changes = subject._activator_changes(
            original, replacements[worker_path][2], unit, replacements[helper][2]
        )
        restored = script
        for before, after in reversed(changes):
            self.assertEqual(restored.count(after), 1)
            restored = restored.replace(after, before)
        self.assertEqual(restored, original[activator_path][2])
        self.assertLess(
            script.index(subject._LOADED_CHECKS), script.index(subject._PROVISION)
        )
        self.assertLess(
            script.index(subject._PROVISION), script.index(subject._ACTIVATION_ANCHOR)
        )
        self.assertEqual(script.count(b'/usr/bin/systemctl start "$worker_unit"'), 1)
        self.assertIn(
            b'require_unit_value "$ingress_unit" ActiveState inactive', script
        )
        self.assertIn(b'require_unit_value "$ingress_unit" MainPID 0', script)
        self.assertEqual(
            script.count(subject._pin_line(subject._HELPER, replacements[helper][2])), 1
        )

    def test_public_stage_reports_exact_files_sources_and_no_live_authority(self):
        original, replacements = subject._verified_payloads()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "ingress"
            report = subject.stage_runtime_phase3_ingress_profile(output)
            self.assertEqual(report["schema"], subject._SCHEMA)
            self.assertEqual(len(report["files"]), 74)
            self.assertEqual(len(report["directories"]), 16)
            self.assertEqual(len(report["source_inputs"]), 96)
            self.assertEqual(len(report["new_dependencies"]), 30)
            for key in (
                "admission_qualified",
                "common_deployment_activated",
                "decision_measurement_deployed",
                "measurement_binding_provisioned",
                "measurement_collected",
                "phase3_qualification",
                "run_qualification",
                "worker_ingress_deployed",
                "worker_ingress_directory_provisioned",
                "worker_ingress_collected",
                "clock_domain_verified",
                "elapsed_time_derived",
                "metrics_eligible",
            ):
                self.assertIs(report[key], False)
            self.assertFalse((output / subject._MEASUREMENT_ROOT.lstrip("/")).exists())
            self.assertEqual(
                report["worker_ingress_state_directory"], subject._MEASUREMENT_ROOT
            )
            files = {row["path"]: row for row in report["files"]}
            for path, (source, mode, raw) in (original | replacements).items():
                self.assertEqual((output / path).read_bytes(), raw)
                self.assertEqual(
                    files["/" + path],
                    {
                        "path": "/" + path,
                        "source_name": source,
                        "mode": f"{mode:04o}",
                        "bytes": len(raw),
                        "digest": subject.base.overlay._digest(raw),
                    },
                )
            for name, pin in report["binding_source_pins"].items():
                self.assertEqual(
                    next(
                        row["digest"]
                        for row in report["files"]
                        if Path(row["source_name"]).name == name
                    ),
                    pin,
                )
            sources = {
                row["name"]: (row["bytes"], row["digest"])
                for row in report["source_inputs"]
            }
            self.assertEqual(len(sources), len(report["source_inputs"]))
            for name, pin in subject._SOURCE_PINS.items():
                self.assertEqual(sources[name], pin)
            for row in report["new_dependencies"]:
                staged = files["/" + subject._destination(row["name"])[0]]
                self.assertEqual(
                    (row["bytes"], row["digest"]), (staged["bytes"], staged["digest"])
                )
            # Shell syntax only: no service, activation or provisioning executes.
            subprocess.run(
                [
                    "/bin/sh",
                    "-n",
                    str(output / subject._destination(subject._ACTIVATOR)[0]),
                ],
                check=True,
                timeout=10,
                capture_output=True,
            )

    def test_changed_pins_anchors_inventory_and_existing_output_refuse(self):
        with patch.object(
            subject, "_SOURCE_PINS", {subject._PARENT: (1, "sha256:" + "0" * 64)}
        ):
            with self.assertRaises(ValueError):
                subject._verified_payloads()
        with patch.object(subject, "_OUTPUTS", {}):
            with self.assertRaises(subject.Phase3IngressStageError):
                subject._verified_payloads()
        original, replacements = subject.predecessor._verified_payloads()
        common = original | replacements
        for source, old, new in (
            (subject._UNIT, subject._UNIT_ANCHOR, b"StateDirectoryMode=0755\n"),
            (subject._ACTIVATOR, subject._ACTIVATION_ANCHOR, b"# removed activation\n"),
            (subject._WORKER, b"def main(", b"def changed_main("),
        ):
            changed = dict(common)
            path = subject._destination(source)[0]
            name, mode, raw = changed[path]
            self.assertIn(old, raw)
            changed[path] = (name, mode, raw.replace(old, new))
            with patch.object(
                subject.predecessor, "_verified_payloads", return_value=(changed, {})
            ):
                with self.assertRaises(subject.Phase3IngressStageError):
                    subject._verified_payloads()
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(
                subject.predecessor, "stage_runtime_phase3_common_profile"
            ) as stage,
        ):
            with self.assertRaises(subject.Phase3IngressStageError):
                subject.stage_runtime_phase3_ingress_profile(Path(temporary).resolve())
            stage.assert_not_called()

    def test_staging_custody_loss_stops_before_overrides(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "lost"
            with (
                patch.object(
                    subject.base,
                    "_parent_custody",
                    side_effect=[("before",), ("after",)],
                ),
                patch.object(
                    subject.predecessor,
                    "stage_runtime_phase3_common_profile",
                    return_value={},
                ) as stage,
                patch.object(subject.base, "_apply_overrides") as apply,
            ):
                with self.assertRaises(subject.Phase3IngressStageError):
                    subject.stage_runtime_phase3_ingress_profile(output)
                stage.assert_called_once_with(output)
                apply.assert_not_called()

    def test_provisioning_creates_once_private_and_closes_every_descriptor(self):
        fake = _ProvisionOS()
        _provision(fake)
        self.assertTrue(fake.exists)
        self.assertEqual(
            (
                fake.records[4].st_uid,
                fake.records[4].st_gid,
                stat.S_IMODE(fake.records[4].st_mode),
            ),
            (997, 997, 0o700),
        )
        self.assertEqual(
            [event for event in fake.events if event[0] == "close"],
            [("close", 4), ("close", 3), ("close", 2), ("close", 1)],
        )
        self.assertLess(
            fake.events.index(("fsync", 3)), fake.events.index(("chown", 4, 997, 997))
        )
        fake.events.clear()
        with self.assertRaises(FileExistsError):
            _provision(fake)
        self.assertFalse(any(event[0] in {"chown", "chmod"} for event in fake.events))

    def test_provisioning_refuses_existing_or_unsafe_state_without_repair(self):
        for kind in ("existing", "ancestor", "entries", "swapped", "uid", "gid"):
            with self.subTest(kind=kind):
                fake = _ProvisionOS()
                if kind == "existing":
                    fake.exists = True
                if kind == "ancestor":
                    fake.records[2].st_mode = stat.S_IFDIR | 0o777
                if kind == "entries":
                    fake.entries = ["retained.json"]
                if kind == "swapped":
                    fake.altered_leaf = True
                with self.assertRaises((SystemExit, FileExistsError)):
                    _provision(
                        fake,
                        "0" if kind == "uid" else "997",
                        "0" if kind == "gid" else "997",
                    )
                self.assertFalse(
                    any(event[0] in {"chown", "chmod"} for event in fake.events)
                )
                if kind in {"entries", "swapped", "existing"}:
                    self.assertTrue(fake.exists)

    def test_provisioning_retains_failed_claim_and_preserves_primary_error(self):
        for kind in ("sync", "chown", "cleanup"):
            with self.subTest(kind=kind):
                fake = _ProvisionOS()
                fake.fail = kind
                interrupt = KeyboardInterrupt("inert close interruption")
                fake.close_failure = interrupt
                with self.assertRaises(BaseException) as failure:
                    _provision(fake)
                self.assertTrue(fake.exists)
                if kind == "cleanup":
                    self.assertIs(failure.exception, interrupt)
                else:
                    self.assertIsInstance(failure.exception, OSError)
                opened = [event[1] for event in fake.events if event[0] == "open"]
                self.assertEqual(
                    [event[1] for event in fake.events if event[0] == "close"],
                    list(reversed(opened)),
                )


if __name__ == "__main__":
    unittest.main()
