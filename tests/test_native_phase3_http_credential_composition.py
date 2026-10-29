"""Only the new credential composition: inert bytes and mocked read boundaries."""

from contextlib import ExitStack
import ast
import hashlib
from pathlib import Path
import os
from types import SimpleNamespace
import stat
import unittest
from unittest.mock import patch

from aragorn import native_phase3_plugin_update_live_binding as frozen
from scripts import materialize_native_phase3_http_credential_helpers as helpers
from scripts import materialize_native_phase3_http_credential_capture as capture
from scripts import capture_native_phase3_http_credential_attempt as launcher

ROOT = Path(__file__).resolve().parents[1]
WORKER = "aragorn-runtime-action-worker.service"
UNITS = {"worker": WORKER,
         "sensor": "aragorn-runtime-lineage-capability-observation-publisher.service",
         "broker": "aragorn-runtime-lineage-capability-action-broker.service"}


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _identity(item):
    return tuple(getattr(item, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns"))


def _function(raw, name, namespace):
    """Execute only one reviewed function against fully inert injected values."""
    nodes = [node for node in ast.parse(raw).body
             if isinstance(node, ast.FunctionDef) and node.name == name]
    if len(nodes) != 1:
        raise AssertionError("generated test function inventory changed")
    exec(compile(ast.Module(body=nodes, type_ignores=[]), "<credential-function>", "exec"), namespace)
    return namespace[name]


class _View:
    """Borrowed root plus synthetic credential descriptors; no host OS access."""

    def __init__(self):
        self.raw = b'{"fabricated":"credential"}'
        self.uid, self.gid = 1001, 1002
        def metadata(inode, mode=stat.S_IFDIR | 0o755, uid=0, gid=0, size=0):
            return SimpleNamespace(st_dev=7, st_ino=inode, st_mode=mode, st_uid=uid,
                st_gid=gid, st_nlink=1, st_size=size, st_mtime_ns=12, st_ctime_ns=13)
        self.nodes = {10: metadata(10), 11: metadata(11), 12: metadata(12),
            13: metadata(13, stat.S_IFDIR | 0o700, self.uid, self.gid),
            14: metadata(14, stat.S_IFREG | 0o400, self.uid, self.gid, len(self.raw))}
        self.closed, self.opened, self.preads = [], [], []
        self.read_override = None
        self.readonly_file = self.readonly_directory = True
        self.churn = self.substitute = self.mutate_after_read = False
        self.os = SimpleNamespace(**{name: getattr(os, name) for name in (
            "O_RDONLY", "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "ST_RDONLY")},
            open=self.open, close=self.closed.append, stat=self.stat,
            fstat=lambda fd: self.nodes[fd], fstatvfs=self.fstatvfs, pread=self.pread)

    def open(self, name, flags, *, dir_fd):
        self.opened.append((str(name), flags, dir_fd))
        fd = {(10, "run"): 11, (11, "credentials"): 12,
              (12, WORKER): 13, (13, "http-fixture"): 14}[(dir_fd, str(name))]
        if self.churn and fd != 14:
            self.nodes[fd].st_size += 1
            self.nodes[fd].st_mtime_ns += 1
            self.nodes[fd].st_ctime_ns += 1
        return fd

    def stat(self, name, *, dir_fd, follow_symlinks):
        if follow_symlinks is not False:
            raise AssertionError("named view followed a link")
        fd = {(10, "run"): 11, (11, "credentials"): 12,
              (12, WORKER): 13, (13, "http-fixture"): 14}[(dir_fd, str(name))]
        value = SimpleNamespace(**vars(self.nodes[fd]))
        if self.substitute and fd == 14:
            value.st_ino += 1
        return value

    def fstatvfs(self, fd):
        readonly = self.readonly_file if fd == 14 else self.readonly_directory
        return SimpleNamespace(f_flag=os.ST_RDONLY if readonly else 0)

    def pread(self, fd, count, offset):
        self.preads.append((fd, count, offset))
        if self.mutate_after_read:
            self.nodes[14].st_ino += 1
        if isinstance(self.read_override, BaseException):
            raise self.read_override
        return self.raw if self.read_override is None else self.read_override


class CredentialCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = {name: (ROOT / name).read_bytes() for name in capture.source_paths()}
        cls.generated = capture.compose(cls.original)
        cls.receipt = helpers.report(cls.original[helpers.REPORT])
        cls.reader = cls.generated[helpers.identity.IDENTITY]
        cls.consumer = cls.generated[helpers.identity.VERIFIER]

    def view_function(self, fake):
        prior = SimpleNamespace(_UNITS=UNITS, _digest=_digest,
            broker=SimpleNamespace(_file_identity=_identity))
        return _function(self.reader, "_read_http_credential_view", {
            "_require": _require, "prior": prior, "os": fake.os, "stat": stat,
            "Path": Path, "ExitStack": ExitStack,
            "HTTP_FIXTURE_ROLES": ("worker", "sensor", "broker")})

    def test_actual_report_and_root_writer_configuration_join_without_staging(self):
        self.assertEqual((len(self.original[helpers.REPORT]), _digest(self.original[helpers.REPORT])),
                         helpers.STAGED_PROFILE_PIN)
        self.assertEqual(tuple(len(self.receipt[key]) for key in (
            "files", "source_inputs", "new_dependencies", "directories")), helpers.STAGED_COUNTS)
        template = next(row for row in self.receipt["files"] if row["path"] == helpers.writer.HTTP_TEMPLATE_PATH)
        raw = self.generated[helpers.writer.SOURCE]
        self.assertEqual(raw.count(b"_http.load_provisioned_fixture_binding()"), 2)
        self.assertNotIn(b"_http.load_fixture_binding()", raw)
        self.assertIn(repr((template["bytes"], template["digest"])).encode(), raw)
        self.assertIn(helpers.LIFECYCLE_LOG.encode(), raw)
        preparation = self.generated[helpers.preparation.PREPARATION]
        self.assertIn(repr(helpers.STAGED_PROFILE_PIN).encode(), preparation)
        self.assertIn(repr(helpers.STAGED_COUNTS).encode(), preparation)
        self.assertIn(helpers.HTTP_CONFIG_PIN.encode(), preparation)
        self.assertIn(b"aragorn/native-common-deployment-preparation/v5", preparation)
        for raw in (self.reader, self.consumer):
            self.assertIn(b"aragorn/native-phase3-http-live-identity/v3", raw)
            self.assertIn(helpers.HTTP_CONFIG_PIN.encode(), raw)
            self.assertIn(b"gateway_restart_environment", raw)
        self.assertIn(b"aragorn/native-phase3-http-process-verification/v3", self.consumer)
        for update in (self.original[helpers.REPORT] + b"\n", b"{}"):
            with self.assertRaises(ValueError):
                helpers.report(update)

    def test_assembled_controller_imports_and_exact_signed_source_inventory(self):
        self.assertEqual(set(self.generated), set(capture.generated_paths()))
        self.assertTrue({helpers.REPORT, capture.SELF, capture.LAUNCHER,
                         "scripts/stage_runtime_phase3_http_credential_profile.py"} <= set(self.original))
        self.assertNotIn(helpers.REPORT, capture.generated_paths())
        for name, raw in self.generated.items():
            with self.subTest(source=name):
                ast.parse(raw, filename=name)
        # This loads only reviewed modules/functions. No controller command is
        # invoked, and every full staging entrypoint is prohibited here.
        from scripts import stage_runtime_phase3_http_credential_profile as stage
        private, previous = {}, launcher._staged_private_sources
        def retained_private(original):
            result = previous(original)
            private.update(result)
            return result
        with patch.object(stage, "stage_runtime_phase3_http_credential_profile",
                          side_effect=AssertionError("composition must not stage")), patch.object(
                stage.predecessor, "stage_runtime_phase3_http_ready_profile",
                side_effect=AssertionError("composition must not stage predecessor")), patch.object(
                launcher, "_staged_private_sources", side_effect=retained_private) as observed:
            controller = launcher.build_controller(self.original)
        observed.assert_called_once()
        rows = {row["source_name"]: row for row in self.receipt["files"]}
        self.assertEqual(set(private), set(capture.PRIVATE_STAGED_SOURCES))
        for name, raw in private.items():
            self.assertEqual((len(raw), _digest(raw)), (rows[name]["bytes"], rows[name]["digest"]))
        self.assertEqual(set(controller._SOURCE_PATHS), set(self.original))
        self.assertEqual(set(controller.base._SOURCE_PATHS), set(self.original))
        self.assertNotIn(b"stage_runtime_phase3_http_credential_profile(\n",
                         self.generated["scripts/capture_native_phase3_common_setup.py"].split(b"def _stage_guard(")[0])

    def test_pinned_source_or_report_substitution_refuses(self):
        for name in (helpers.REPORT, helpers.identity.IDENTITY):
            altered = {**self.original, name: self.original[name] + b"\n"}
            with self.subTest(name=name), self.assertRaises(ValueError):
                capture.compose(altered)

    def test_loaded_view_owner_matrix_exact_bytes_readonly_and_borrowed_root(self):
        for uid, gid, mode in ((0, 0, 0o400), (0, 0, 0o440), (0, 1002, 0o400),
                               (0, 1002, 0o440), (1001, 0, 0o400), (1001, 1002, 0o400)):
            fake = _View()
            fake.nodes[14].st_uid, fake.nodes[14].st_gid = uid, gid
            fake.nodes[14].st_mode = stat.S_IFREG | mode
            with self.subTest(uid=uid, gid=gid, mode=mode):
                raw, metadata = self.view_function(fake)(10, f"/run/credentials/{WORKER}/http-fixture", 1001, 1002)
                self.assertEqual(raw, fake.raw)
                self.assertEqual(metadata, {"bytes": len(raw), "digest": _digest(raw),
                                            "identity": list(_identity(fake.nodes[14]))})
                self.assertEqual(fake.closed, [14, 13, 12, 11])
                self.assertEqual(fake.preads, [(14, 4097, 0)])
                self.assertTrue(all(flags & os.O_NOFOLLOW for _, flags, _ in fake.opened))

    def test_loaded_view_refuses_custody_mutations_and_incomplete_read(self):
        for case in ("owner", "gid", "mode", "symlink", "link", "ancestor", "ancestor-owner", "file-mount",
                     "directory-mount", "named", "changed-after-read", "short", "overflow"):
            fake = _View()
            if case == "owner": fake.nodes[14].st_uid = 9999
            elif case == "gid": fake.nodes[14].st_gid = 9999
            elif case == "mode": fake.nodes[14].st_mode = stat.S_IFREG | 0o440
            elif case == "symlink": fake.nodes[14].st_mode = stat.S_IFLNK | 0o400
            elif case == "link": fake.nodes[14].st_nlink = 2
            elif case == "ancestor": fake.nodes[11].st_mode |= 0o002
            elif case == "ancestor-owner": fake.nodes[11].st_uid = 9999
            elif case == "file-mount": fake.readonly_file = False
            elif case == "directory-mount": fake.readonly_directory = False
            elif case == "named": fake.substitute = True
            elif case == "changed-after-read": fake.mutate_after_read = True
            elif case == "short": fake.read_override = fake.raw[:-1]
            else: fake.read_override = fake.raw + b"x"
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.view_function(fake)(10, f"/run/credentials/{WORKER}/http-fixture", 1001, 1002)
            self.assertNotIn(10, fake.closed)
        fake = _View()
        fake.churn = True
        self.assertEqual(self.view_function(fake)(10, f"/run/credentials/{WORKER}/http-fixture", 1001, 1002)[0], fake.raw)
        fake = _View()
        with self.assertRaises(ValueError):
            self.view_function(fake)(10, f"/run/credentials/{WORKER}/http-readiness", 1001, 1002)
        self.assertEqual(fake.opened, [])

    def test_independent_loaded_metadata_accepts_same_matrix_and_refuses_weaker_claims(self):
        verify = _function(self.consumer, "_http_loaded_metadata", {
            "frozen": frozen, "stat": stat, "_require": _require})
        for uid, gid, mode in ((0, 0, 0o400), (0, 0, 0o440), (0, 1002, 0o400),
                               (0, 1002, 0o440), (1001, 0, 0o400), (1001, 1002, 0o400)):
            fake = _View()
            fake.nodes[14].st_uid, fake.nodes[14].st_gid = uid, gid
            fake.nodes[14].st_mode = stat.S_IFREG | mode
            metadata = {"identity": list(_identity(fake.nodes[14])), "bytes": len(fake.raw), "digest": _digest(fake.raw)}
            self.assertEqual(verify(metadata, 1001, 1002,
                expected_bytes=len(fake.raw), expected_digest=_digest(fake.raw)), metadata)
        for case in ("owner", "gid", "mode", "link", "size", "extra", "source-size", "source-digest"):
            fake = _View()
            metadata = {"identity": list(_identity(fake.nodes[14])), "bytes": len(fake.raw), "digest": _digest(fake.raw)}
            if case == "owner": metadata["identity"][3] = 9999
            elif case == "gid": metadata["identity"][4] = 9999
            elif case == "mode": metadata["identity"][2] = stat.S_IFREG | 0o440
            elif case == "link": metadata["identity"][5] = 2
            elif case == "size": metadata["bytes"] = metadata["identity"][6] = 4097
            elif case == "extra": metadata["readonly"] = True
            elif case == "source-size": metadata["bytes"] = metadata["identity"][6] = len(fake.raw) + 1
            else: metadata["digest"] = "sha256:" + "0" * 64
            with self.subTest(case=case), self.assertRaises(ValueError):
                verify(metadata, 1001, 1002,
                    expected_bytes=len(fake.raw), expected_digest=_digest(fake.raw))

    def test_gateway_environment_witness_is_selective_and_refuses_missing_or_duplicate(self):
        for raw in (b"OPENCLAW_NO_RESPAWN=1\0UNRELATED=private-value\0", b"OPENCLAW_NO_RESPAWN=1\0"):
            reads = []
            def read(path, limit):
                reads.append((path, limit))
                return raw
            observe = _function(self.reader, "_gateway_restart_environment", {
                "prior": SimpleNamespace(process=SimpleNamespace(_read_virtual_file=read)),
                "Path": Path, "_require": _require})
            internal, witness = observe(42)
            self.assertEqual(internal, raw)
            self.assertEqual(witness, {"OPENCLAW_NO_RESPAWN": "1"})
            self.assertEqual(reads, [(Path("/proc/42/environ"), 16384)])
        for raw in (b"", b"OPENCLAW_NO_RESPAWN=1", b"OTHER=1\0", b"OPENCLAW_NO_RESPAWN=0\0",
                    b"OPENCLAW_NO_RESPAWN=1\0OPENCLAW_NO_RESPAWN=1\0", b"malformed\0OPENCLAW_NO_RESPAWN=1\0"):
            observe = _function(self.reader, "_gateway_restart_environment", {
                "prior": SimpleNamespace(process=SimpleNamespace(_read_virtual_file=lambda path, limit: raw)),
                "Path": Path, "_require": _require})
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                observe(42)
        self.assertIn(b'"gateway_restart_environment": gateway_environment[1]', self.reader)
        self.assertIn(b'_gateway_restart_environment(records["gateway"]["pid"]) == gateway_environment', self.reader)
        consume = _function(self.consumer, "_http_gateway_environment", {
            "_require": _require, "frozen": frozen,
            "HTTP_CREDENTIAL_CONFIG_PIN": helpers.HTTP_CONFIG_PIN})
        pins = {frozen._CONFIG: helpers.HTTP_CONFIG_PIN}
        consume({"gateway_restart_environment": {"OPENCLAW_NO_RESPAWN": "1"}}, pins)
        for witness in ({}, {"OPENCLAW_NO_RESPAWN": "0"},
                        {"OPENCLAW_NO_RESPAWN": "1", "unrelated": "private"}):
            with self.subTest(witness=witness), self.assertRaises(ValueError):
                consume({"gateway_restart_environment": witness}, pins)
        with self.assertRaises(ValueError):
            consume({"gateway_restart_environment": {"OPENCLAW_NO_RESPAWN": "1"}},
                    {frozen._CONFIG: "sha256:" + "0" * 64})


if __name__ == "__main__":
    unittest.main()
