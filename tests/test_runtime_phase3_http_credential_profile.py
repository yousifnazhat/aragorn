"""New credential successor only: inert staging, cold imports and mocked custody."""

from contextlib import contextmanager
import grp
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_json
from scripts import stage_runtime_phase3_http_credential_profile as subject


REPORT = subject._ROOT / "benchmark/evidence/phase3-http-credential-staged-profile-v1.json"
UNITS = {
    "aragorn-runtime-action-worker.service": (1001, 1002),
    "aragorn-runtime-lineage-capability-action-broker.service": (1003, 1002),
    "aragorn-runtime-lineage-capability-observation-publisher.service": (1004, 1004),
}
WORKER, BROKER, SENSOR = UNITS
BINDING = {
    "schema": "aragorn/runtime-http-fixture-binding/v1",
    "fixture": {
        "container_id": "a" * 64,
        "boot_id": "11111111-2222-3333-4444-555555555555",
        "netns_device": 4,
        "netns_inode": 9,
    },
    "expected_broker_uid": 1003,
    "expected_broker_gid": 1002,
}


def _metadata(inode, *, mode=stat.S_IFDIR | 0o755, uid=0, gid=0, size=0):
    return SimpleNamespace(st_dev=7, st_ino=inode, st_mode=mode, st_uid=uid,
                           st_gid=gid, st_nlink=1, st_size=size,
                           st_mtime_ns=12, st_ctime_ns=13)


class _Credentials:
    """No host pathname, descriptor, account or identity operation is performed."""

    def __init__(self, module, unit):
        self.module, self.unit = module, unit
        self.uid, self.gid = UNITS[unit]
        self.pid, self.start, self.thread = 42, 123, 42
        self.resuid, self.resgid = (self.uid,) * 3, (self.gid,) * 3
        self.fsuid, self.fsgid = self.uid, self.gid
        self.status_override = None
        self.boot_override = None
        self.cgroup_override = None
        self.directory_churn = False
        self.raw = canonical_json(BINDING)
        self.read_override = None
        self.readonly = True
        self.named_changed = False
        self.close_failure = False
        self.closed, self.opens, self.named_reads, self.preads = [], [], [], []
        self.nodes = {
            10: _metadata(10), 11: _metadata(11), 12: _metadata(12),
            13: _metadata(13, mode=stat.S_IFDIR | 0o700, uid=self.uid, gid=self.gid),
            14: _metadata(14, mode=stat.S_IFREG | 0o400, uid=self.uid,
                          gid=self.gid, size=len(self.raw)),
            15: _metadata(15, mode=stat.S_IFREG | 0o400, uid=self.uid,
                          gid=self.gid, size=5),
        }
        constants = ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC",
                     "O_DIRECTORY", "ST_RDONLY")
        self.os = SimpleNamespace(
            **{name: getattr(os, name) for name in constants},
            environ={"CREDENTIALS_DIRECTORY": "/run/credentials/" + unit},
            getresuid=lambda: self.resuid, getresgid=lambda: self.resgid,
            getpid=lambda: self.pid, open=self.open, close=self.close,
            stat=self.stat, fstat=lambda fd: self.nodes[fd],
            fstatvfs=lambda fd: SimpleNamespace(f_flag=os.ST_RDONLY if self.readonly else 0),
            pread=self.pread,
        )

    def open(self, name, flags, *, dir_fd=None):
        self.opens.append((str(name), flags, dir_fd))
        lookup = {(None, "/"): 10, (10, "run"): 11,
                  (11, "credentials"): 12, (12, self.unit): 13,
                  (13, "http-fixture"): 14, (13, "http-readiness"): 15}
        return lookup[(dir_fd, str(name))]

    def stat(self, name, *, dir_fd, follow_symlinks):
        self.named_reads.append((str(name), dir_fd, follow_symlinks))
        lookup = {(10, "."): 10, (10, "run"): 11,
                  (11, "credentials"): 12, (12, self.unit): 13,
                  (13, "http-fixture"): 14, (13, "http-readiness"): 15}
        value = self.nodes[lookup[(dir_fd, str(name))]]
        if self.directory_churn and stat.S_ISDIR(value.st_mode):
            return SimpleNamespace(**{**vars(value), "st_size": 99, "st_mtime_ns": 90,
                                      "st_ctime_ns": 91, "st_nlink": 4})
        if self.named_changed and str(name) == "http-fixture":
            return SimpleNamespace(**{**vars(value), "st_ino": 999})
        return value

    def pread(self, descriptor, count, offset):
        self.preads.append((descriptor, count, offset))
        if isinstance(self.read_override, BaseException):
            raise self.read_override
        if self.read_override is not None:
            return self.read_override
        return self.raw if descriptor == 14 else b"ready"

    def close(self, descriptor):
        self.closed.append(descriptor)
        if self.close_failure:
            raise OSError("synthetic credential close failure")

    def read(self, path, limit):
        if path == "/proc/self/status":
            return self.status_override or (
                f"Uid:\t{self.uid}\t{self.uid}\t{self.uid}\t{self.fsuid}\n"
                f"Gid:\t{self.gid}\t{self.gid}\t{self.gid}\t{self.fsgid}\n"
            ).encode()
        if path == "/proc/self/cgroup":
            return self.cgroup_override if self.cgroup_override is not None else f"0::/docker/{BINDING['fixture']['container_id']}/system.slice/{self.unit}\n".encode()
        if path == self.module.BOOT_PATH:
            return self.boot_override if self.boot_override is not None else (BINDING["fixture"]["boot_id"] + "\n").encode()
        raise AssertionError("unexpected proc read " + str(path))


@contextmanager
def _service(module, unit):
    fake = _Credentials(module, unit)
    users = {"aragorn-runtime": 1001, "aragorn-broker": 1003, "aragorn-sensor": 1004}
    groups = {"aragorn-runtime": 1002, "aragorn-sensor": 1004}
    with (
        patch.object(module, "os", fake.os),
        patch.object(module, "sys", SimpleNamespace(platform="linux", exception=sys.exception)),
        patch.object(module, "threading", SimpleNamespace(get_native_id=lambda: fake.thread)),
        patch.object(module, "_read", side_effect=fake.read),
        patch.object(module, "_process_start_time", side_effect=lambda pid: fake.start),
        patch.object(pwd, "getpwnam", side_effect=lambda name: SimpleNamespace(pw_uid=users[name])),
        patch.object(grp, "getgrnam", side_effect=lambda name: SimpleNamespace(gr_gid=groups[name])),
    ):
        yield fake


def _retain_public_report(report):
    """One explicit public artifact; existing/partial output is never replaced."""
    raw = canonical_json(report)
    if REPORT.parent.resolve(strict=True) != REPORT.parent:
        raise AssertionError("public report ancestry is indirect")
    descriptor = os.open(REPORT, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise OSError("short public report write")
            offset += written
        os.fchmod(descriptor, 0o444)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(REPORT.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    if REPORT.read_bytes() != raw:
        raise AssertionError("public report readback changed")
    print(canonical_json({"http_credential_stage_report": {
        "path": str(REPORT), "bytes": len(raw),
        "digest": subject.base.overlay._digest(raw),
    }}).decode())


class HttpCredentialProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original, cls.replacements, cls.inputs = subject._verified_payloads()
        cls.final = cls.original | cls.replacements

    def payload(self, name):
        return self.final[subject._destination(name)[0]][2]

    def test_exact_successor_inventory_credentials_configuration_and_measurement_pins(self):
        self.assertEqual(len(self.original), 94)
        self.assertEqual(set(self.final), set(self.original))
        self.assertEqual(len(self.replacements), 11)
        self.assertEqual(len(subject.base._directories(self.final)), 21)
        expected = set(subject.renderer.SOURCES) | {
            subject.predecessor._ACTIVATOR, subject.predecessor._CAP_ACTIVATOR}
        self.assertEqual({row[0] for row in self.replacements.values()}, expected)
        for path in set(self.original) - set(self.replacements):
            self.assertEqual(self.final[path], self.original[path])
        for name, pin in subject._SOURCE_PINS.items():
            raw = (subject._ROOT / name).read_bytes()
            self.assertEqual((len(raw), subject.base.overlay._digest(raw)), pin)
        for name in (subject.renderer.WORKER_UNIT, subject.renderer.SENSOR_UNIT,
                     subject.renderer.BROKER_UNIT):
            unit = self.payload(name)
            self.assertEqual(unit.count(b"LoadCredential=http-fixture:/etc/aragorn/runtime-http-fixture.json\n"), 1)
            self.assertEqual(unit.count(b"LoadCredential=http-readiness:"),
                             int(name == subject.renderer.BROKER_UNIT))
            self.assertEqual(unit.count(b"BindReadOnlyPaths=/proc/sys/kernel/random/boot_id:/run/aragorn-broker-boot-id\n"), 1)
            self.assertIn(b"ProcSubset=pid\n", unit)
            self.assertNotIn(b"ReadOnlyPaths=/etc/aragorn/runtime-http-fixture.json\n", unit)
        self.assertNotIn(b"ReadOnlyPaths=/etc/aragorn/runtime-http-readiness.json\n",
                         self.payload(subject.renderer.BROKER_UNIT))
        old_config = json.loads(self.original[subject._destination(subject.renderer.GATEWAY_CONFIG)[0]][2])
        config = json.loads(self.payload(subject.renderer.GATEWAY_CONFIG))
        self.assertEqual(config, {**old_config, "logging": {
            "level": "info", "file": subject.renderer.LIFECYCLE_LOG}})
        self.assertEqual(self.payload(subject.renderer.GATEWAY_CONFIG), canonical_json(config))
        self.assertIn(b"Environment=OPENCLAW_NO_RESPAWN=1 HOME=",
                      self.payload(subject.renderer.GATEWAY_UNIT))
        names = set(subject.MEASUREMENT_SOURCE_NAMES)
        self.assertEqual(len(names), 22)
        for name in (subject.predecessor._MEASUREMENT, subject.predecessor._PLAN,
                     subject.predecessor._PRIOR):
            self.assertEqual(subject.predecessor._inventory(self.payload(name)), names)

    def test_new_activator_pins_and_shell_syntax(self):
        cap = self.payload(subject.predecessor._CAP_ACTIVATOR)
        worker = self.payload(subject.predecessor._ACTIVATOR)
        for source, mode, raw in self.replacements.values():
            if source in {subject.predecessor._CAP_ACTIVATOR, subject.predecessor._ACTIVATOR}:
                continue
            path = subject._destination(source)[0]
            row = f"{mode:o} {subject.base.overlay._digest(raw)[7:]} /{path}\n".encode()
            self.assertIn(row, cap)
            self.assertIn(row, worker)
            old_digest = subject.base.overlay._digest(self.original[path][2])[7:].encode()
            self.assertNotIn(old_digest, cap)
            self.assertNotIn(old_digest, worker)
        cap_path, cap_mode = subject._destination(subject.predecessor._CAP_ACTIVATOR)
        self.assertEqual(worker.count(
            f"{cap_mode:o} {subject.base.overlay._digest(cap)[7:]} /{cap_path}\n".encode()), 1)
        for raw in (cap, worker):
            checked = subprocess.run(["/bin/sh", "-n"], input=raw, capture_output=True,
                                     timeout=5, check=False)
            self.assertEqual(checked.returncode, 0, checked.stderr.decode())

    def test_single_inert_stage_cold_imports_and_retained_public_report(self):
        # This is the sole full staging call. The artifact remains even if a
        # later assertion/import fails, so no unchanged automatic retry is safe.
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "credential-profile"
            report = subject.stage_runtime_phase3_http_credential_profile(output)
            _retain_public_report(report)
            self.assertEqual(report["schema"], subject._SCHEMA)
            self.assertEqual(len(report["files"]), 94)
            self.assertEqual(len(report["directories"]), 21)
            for key in ("http_service_credentials_observed", "gateway_lifecycle_log_observed",
                        "http_fixture_provisioned", "http_runtime_activated", "http_collected",
                        "measurement_collected", "phase3_qualification", "run_qualification"):
                self.assertIs(report[key], False)
            self.assertTrue(report["http_service_credentials_staged"])
            self.assertTrue(report["gateway_native_restart_environment_staged"])
            self.assertTrue(report["gateway_lifecycle_logging_staged"])
            self.assertEqual(report["gateway_config_digest_required_not_included"],
                             subject.base.overlay._digest(self.payload(subject.renderer.GATEWAY_CONFIG)))
            self.assertEqual(set(report["binding_source_pins"]), set(subject.MEASUREMENT_SOURCE_NAMES))
            for row in report["files"]:
                path = row["path"].lstrip("/")
                source, mode, raw = self.final[path]
                self.assertEqual((output / path).read_bytes(), raw)
                self.assertEqual((output / path).stat().st_mode & 0o777, mode)
                self.assertEqual((row["source_name"], row["bytes"], row["digest"]),
                                 (source, len(raw), subject.base.overlay._digest(raw)))
            for name, digest in report["binding_source_pins"].items():
                self.assertEqual(digest, subject.base.overlay._digest(self.payload("src/aragorn/" + name)))
            package = (output / subject._destination("src/aragorn/__init__.py")[0]).parent.parent
            code = ("import importlib,pathlib,sys; sys.path.insert(0,sys.argv[1]); "
                    "m=importlib.import_module('aragorn.'+sys.argv[2]); "
                    "assert pathlib.Path(m.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[1]).resolve())")
            for name in ("runtime_action_worker", "runtime_observation_service_v4", "runtime_action_service_v5"):
                with self.subTest(cold_import=name):
                    imported = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", code,
                                               str(package), name], cwd=temporary,
                                              capture_output=True, timeout=10, check=False)
                    self.assertEqual(imported.returncode, 0, imported.stderr.decode())

    def test_existing_destination_or_wrong_source_refuses_before_predecessor(self):
        with tempfile.TemporaryDirectory() as temporary:
            existing = Path(temporary).resolve()
            with patch.object(subject.predecessor, "stage_runtime_phase3_http_ready_profile") as previous:
                with self.assertRaises(subject.Phase3HttpCredentialStageError):
                    subject.stage_runtime_phase3_http_credential_profile(existing)
                previous.assert_not_called()
            name = next(iter(subject._SOURCE_PINS))
            pins = {**subject._SOURCE_PINS, name: (0, "sha256:" + "0" * 64)}
            output = existing / "never-created"
            with patch.object(subject, "_SOURCE_PINS", pins), patch.object(
                    subject.predecessor, "stage_runtime_phase3_http_ready_profile") as previous:
                with self.assertRaises(ValueError):
                    subject.stage_runtime_phase3_http_credential_profile(output)
                previous.assert_not_called()
                self.assertFalse(output.exists())


class HttpServiceCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original, changes, _ = subject._verified_payloads()
        cls.action_raw = (original | changes)[subject._destination(subject.renderer.ACTION)[0]][2]

    def setUp(self):
        self.http = ModuleType("aragorn._http_credential_successor_test")
        self.http.__package__ = "aragorn"
        exec(compile(self.action_raw, "<pinned-http-credential-successor>", "exec"), self.http.__dict__)

    def test_worker_broker_views_and_broker_only_readiness(self):
        for unit in (WORKER, BROKER):
            with self.subTest(unit=unit), _service(self.http, unit) as fake:
                self.assertEqual(self.http.load_fixture_binding(), BINDING)
                self.assertEqual(fake.preads, [(14, 4097, 0)])
                self.assertEqual(fake.closed, [14, 13, 12, 11, 10])
                self.assertEqual(fake.opens[0][0], "/")
                for _name, flags, _parent in fake.opens:
                    self.assertTrue(flags & os.O_NOFOLLOW)
                    self.assertTrue(flags & os.O_CLOEXEC)
                    self.assertTrue(flags & os.O_NONBLOCK)
                self.assertFalse(any("/etc/aragorn" in row[0] for row in fake.opens))
        with _service(self.http, BROKER):
            self.assertEqual(self.http.read_service_credential("http-readiness")[0], b"ready")
        for unit in (WORKER, SENSOR):
            with self.subTest(unit=unit), _service(self.http, unit) as fake:
                with self.assertRaises(self.http.RuntimeHttpActionError):
                    self.http.read_service_credential("http-readiness")
                self.assertEqual(fake.opens, [])

    def test_context_rejects_foreign_path_accounts_thread_and_status_before_open(self):
        cases = ("foreign-path", "uid", "gid", "thread", "fsuid", "duplicate-status", "name")
        for case in cases:
            with self.subTest(case=case), _service(self.http, WORKER) as fake:
                if case == "foreign-path":
                    fake.os.environ["CREDENTIALS_DIRECTORY"] = "/tmp/credentials"
                elif case == "uid":
                    fake.resuid = (0, 0, 0)
                elif case == "gid":
                    fake.resgid = (0, 0, 0)
                elif case == "thread":
                    fake.thread += 1
                elif case == "fsuid":
                    fake.fsuid += 1
                elif case == "duplicate-status":
                    fake.status_override = fake.read("/proc/self/status", 16384) + b"Uid:\t1 1 1 1\n"
                with self.assertRaises(self.http.RuntimeHttpActionError):
                    self.http.read_service_credential("other" if case == "name" else "http-fixture")
                self.assertEqual(fake.opens, [])

    def test_root_or_service_owned_credential_modes_and_groups(self):
        for unit in (WORKER, BROKER):
            for owner, group, mode in ((0, 0, 0o400), (0, 0, 0o440),
                                       (0, UNITS[unit][1], 0o400), (0, UNITS[unit][1], 0o440),
                                       (UNITS[unit][0], 0, 0o400),
                                       (UNITS[unit][0], UNITS[unit][1], 0o400)):
                with self.subTest(unit=unit, owner=owner, group=group, mode=mode), _service(self.http, unit) as fake:
                    fake.nodes[14].st_uid, fake.nodes[14].st_gid = owner, group
                    fake.nodes[14].st_mode = stat.S_IFREG | mode
                    self.assertEqual(self.http.load_fixture_binding(), BINDING)
            for owner, group, mode in ((0, 9999, 0o440), (UNITS[unit][0], 9999, 0o400),
                                       (UNITS[unit][0], UNITS[unit][1], 0o440), (0, 0, 0o444)):
                with self.subTest(unit=unit, owner=owner, group=group, mode=mode), _service(self.http, unit) as fake:
                    fake.nodes[14].st_uid, fake.nodes[14].st_gid = owner, group
                    fake.nodes[14].st_mode = stat.S_IFREG | mode
                    with self.assertRaises(self.http.RuntimeHttpActionError):
                        self.http.load_fixture_binding()

    def test_protected_boot_binding_must_match_exact_fixture(self):
        for field, raw in (("boot_override", b"00000000-0000-0000-0000-000000000000\n"),
                           ("cgroup_override", b"0::/foreign\n")):
            with self.subTest(field=field), _service(self.http, WORKER) as fake:
                setattr(fake, field, raw)
                with self.assertRaises(self.http.RuntimeHttpActionError):
                    self.http.load_fixture_binding()

    def test_unrelated_directory_metadata_churn_preserves_custody(self):
        with _service(self.http, WORKER) as fake:
            fake.directory_churn = True
            self.assertEqual(self.http.load_fixture_binding(), BINDING)

    def test_projection_modes_readonly_ancestry_and_named_substitution_refuse(self):
        for case in ("writable-parent", "symlink", "hardlink", "owner", "mode", "mount", "named"):
            with self.subTest(case=case), _service(self.http, WORKER) as fake:
                if case == "writable-parent":
                    fake.nodes[11].st_mode |= 0o002
                elif case == "symlink":
                    fake.nodes[14].st_mode = stat.S_IFLNK | 0o400
                elif case == "hardlink":
                    fake.nodes[14].st_nlink = 2
                elif case == "owner":
                    fake.nodes[14].st_uid = 9999
                elif case == "mode":
                    fake.nodes[14].st_mode = stat.S_IFREG | 0o600
                elif case == "mount":
                    fake.readonly = False
                else:
                    fake.named_changed = True
                with self.assertRaises(self.http.RuntimeHttpActionError):
                    self.http.read_service_credential("http-fixture")
                self.assertEqual(set(fake.closed), {10, 11} if case == "writable-parent" else {10, 11, 12, 13, 14})

    def test_bounded_reads_and_canonical_binding_fail_closed(self):
        values = (b"", canonical_json(BINDING)[:-1], canonical_json(BINDING) + b"\n", b"x" * 4097)
        for raw in values:
            with self.subTest(bytes=len(raw)), _service(self.http, WORKER) as fake:
                fake.read_override = raw
                with self.assertRaises(self.http.RuntimeHttpActionError):
                    self.http.load_fixture_binding()
                self.assertEqual(fake.closed, [14, 13, 12, 11, 10])
        with _service(self.http, BROKER) as fake:
            fake.raw = canonical_json({**BINDING, "expected_broker_uid": 1999})
            fake.nodes[14].st_size = len(fake.raw)
            with self.assertRaises(self.http.RuntimeHttpActionError):
                self.http.load_fixture_binding()

    def test_sensor_holds_before_fsuid_drop_reuses_fd_and_clears_global(self):
        with _service(self.http, SENSOR) as fake:
            with self.assertRaises(self.http.RuntimeHttpActionError):
                self.http.load_fixture_binding()
            self.assertEqual(fake.opens, [])
            with self.http.hold_service_fixture_binding():
                self.assertIsNotNone(self.http._SENSOR_FIXTURE)
                opened, named = len(fake.opens), len(fake.named_reads)
                fake.fsuid, fake.fsgid = UNITS[WORKER]
                # The held inode remains readable even if its old pathname is
                # inaccessible after adoption; no named lookup occurs now.
                fake.named_changed = True
                self.assertEqual(self.http.load_fixture_binding(), BINDING)
                with self.assertRaises(self.http.RuntimeHttpActionError):
                    self.http.read_service_credential("http-fixture")
                with self.assertRaises(self.http.RuntimeHttpActionError):
                    with self.http.hold_service_fixture_binding():
                        self.fail("nested sensor acquisition must refuse before reopen")
                self.assertEqual(len(fake.opens), opened)
                self.assertEqual(len(fake.named_reads), named)
            self.assertIsNone(self.http._SENSOR_FIXTURE)
            self.assertEqual(fake.closed, [14, 13, 12, 11, 10])

    def test_sensor_late_hold_fork_and_inode_changes_refuse_without_reopen(self):
        with _service(self.http, SENSOR) as fake:
            fake.fsuid, fake.fsgid = UNITS[WORKER]
            with self.assertRaises(self.http.RuntimeHttpActionError):
                with self.http.hold_service_fixture_binding():
                    self.fail("late filesystem adoption must not acquire credentials")
            self.assertEqual(fake.opens, [])
        for change in ("fork", "inode"):
            with self.subTest(change=change), _service(self.http, SENSOR) as fake:
                with self.assertRaises(self.http.RuntimeHttpActionError):
                    with self.http.hold_service_fixture_binding():
                        opened = len(fake.opens)
                        if change == "fork":
                            fake.pid += 1
                            fake.thread = fake.pid
                        else:
                            fake.nodes[14].st_ino += 1
                        self.http.load_fixture_binding()
                self.assertEqual(len(fake.opens), opened)
                self.assertIsNone(self.http._SENSOR_FIXTURE)
                self.assertEqual(fake.closed, [14, 13, 12, 11, 10])

    def test_interrupt_final_guard_and_close_preserve_primary_and_clear_sensor(self):
        with _service(self.http, WORKER) as fake:
            primary = KeyboardInterrupt("synthetic read interruption")
            fake.read_override, fake.close_failure = primary, True
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.http.read_service_credential("http-fixture")
            self.assertIs(caught.exception, primary)
            self.assertIn("HTTP_CREDENTIAL_DESCRIPTOR_CLOSE_FAILED", primary.__notes__)
            self.assertEqual(fake.closed, [14, 13, 12, 11, 10])
        with _service(self.http, SENSOR) as fake:
            primary = KeyboardInterrupt("synthetic sensor interruption")
            with self.assertRaises(KeyboardInterrupt) as caught:
                with self.http.hold_service_fixture_binding():
                    fake.start += 1
                    fake.close_failure = True
                    raise primary
            self.assertIs(caught.exception, primary)
            self.assertIn("HTTP_SENSOR_CREDENTIAL_FINAL_GUARD_FAILED", primary.__notes__)
            self.assertIn("HTTP_CREDENTIAL_DESCRIPTOR_CLOSE_FAILED", primary.__notes__)
            self.assertIsNone(self.http._SENSOR_FIXTURE)
            self.assertEqual(fake.closed, [14, 13, 12, 11, 10])
        with _service(self.http, SENSOR) as fake:
            with self.assertRaises(self.http.RuntimeHttpActionError):
                with self.http.hold_service_fixture_binding():
                    fake.start += 1
            self.assertIsNone(self.http._SENSOR_FIXTURE)
            self.assertEqual(fake.closed, [14, 13, 12, 11, 10])


if __name__ == "__main__":
    unittest.main()
