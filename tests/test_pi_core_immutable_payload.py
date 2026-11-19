"""Only B41's new projection, sealing and static-ABI joins; never execute target bytes."""
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts import prepare_pi_core_immutable_payload as payload
from scripts.build_pi_core_linux import BuildError


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def held(name, expected):
    raw = (payload.WORK / name).read_bytes()
    if digest(raw) != expected:
        raise ValueError("different sealed output: " + name)
    return json.loads(raw)


class GuestPayload(unittest.TestCase):
    def test_join_actual_physical_manifest_logical_host_and_unchanged_custody(self):
        pins = json.loads(payload.PINS.read_bytes())
        summary = json.loads(payload.PINS.with_name("payload-receipts.json").read_bytes())
        manifest = held("payload.json", pins["manifest_sha256"])
        physical = {r["path"]: r for r in manifest["entries"]}
        root = payload.WORK / "root"
        payload.check_physical(root, manifest)
        profile = held("coordinator-host.json", pins["host_profile_sha256"])
        host = {r["path"]: r for r in profile["files"]}
        custody = held("host-preparation.json", summary["host_preparation_sha256"])
        actual = {k: r for k, r in physical.items() if r["type"] == "file"}
        self.assertEqual((len(actual), len(physical)-len(actual)), (794, 59))
        self.assertEqual(actual.pop(payload.PROFILE)["sha256"], pins["host_profile_sha256"])
        self.assertEqual(host, {payload.logical(k): {"path": payload.logical(k), "size": r["size"],
                                                 "digest": "sha256:" + r["sha256"]} for k,r in actual.items()})
        self.assertEqual(list(host), sorted(host, key=Path))
        self.assertEqual(list((root / "lib").iterdir()), [])
        self.assertEqual(actual[payload.LOADER]["sha256"], payload.b40.LOADER_SHA)
        self.assertEqual(actual[payload.MULTI + "libc.so.6"]["sha256"], payload.b40.LIBC_SHA)
        self.assertNotIn(payload.MULTI + payload.b40.LOADER, actual)
        self.assertEqual(custody["declared_search_policy"][payload.PYTHON], "$ORIGIN/../lib")
        self.assertEqual((custody["files"],custody["bytes"],custody["native_files"],
                          len(custody["static_elf_dependencies"])), (793,54401615,102,249))
        self.assertEqual(custody["host_profile_digest"], "sha256:" + pins["host_profile_sha256"])
        for k in ("executed_target_code", "installed_root_protection_verified", "actual_loader_resolution_verified",
                  "phase3_exit_eligible"):
            self.assertIs(custody[k], False)

    def test_static_versioned_edges_bind_to_real_physical_providers_and_prior_evidence(self):
        pins = json.loads(payload.PINS.read_bytes())
        summary = json.loads(payload.PINS.with_name("payload-receipts.json").read_bytes())
        receipt = held("payload-abi.json", summary["payload_abi_sha256"])
        custody = held("host-preparation.json", summary["host_preparation_sha256"])
        declared = {(r["requester"],r["requested"],r["path"]) for r in custody["static_elf_dependencies"]
                    if r["kind"] == "needed"}
        newer = receipt["new_versioned_edges"]
        edges = {(payload.logical(r["requester"]),r["provider_soname"],payload.logical(r["provider_file"]))
                 for r in newer}
        self.assertEqual(len(edges), len(newer))
        self.assertTrue(edges <= declared)
        self.assertEqual((len(edges),sum(r["versioned_symbol_count"] for r in newer)),(213,3831))
        self.assertFalse(any(r["runtime_verified"] or r["phase3_exit_eligible"] for r in newer))
        self.assertEqual(receipt["host_profile_sha256"], pins["host_profile_sha256"])
        self.assertEqual(receipt["b40_report_sha256"], digest(payload.CLIENT_REPORT.read_bytes()))
        self.assertEqual(receipt["reused_b40_edges"], 20)
        self.assertEqual(receipt["reused_b38_edges"], [[payload.PYTHON, "libc.so.6"]])
        self.assertFalse(receipt["runtime_verified"] or receipt["phase3_exit_eligible"])

    def test_refuse_colliding_or_physical_prebind_names(self):
        for path in ("/lib", "/lib/ld-linux-aarch64.so.1", payload.PROFILE):
            with self.subTest(path=path), self.assertRaisesRegex(BuildError, "reserved physical"):
                payload.overlay({path: (b"wrong", 0o555)}, b"profile")
        with self.assertRaisesRegex(BuildError, "collision"):
            payload.overlay({"/foo": (b"a", 0o444), "/foo/bar": (b"b", 0o444)}, b"profile")

    def test_physical_readback_refuses_even_same_size_substitution_and_writable_mode(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            file = base / "x"
            payload.new(file, b"X", 0o444)
            rows = {"entries":[{"path":"/x","type":"file","mode":0o444,"uid":0,"gid":0,
                                "size":1,"sha256":digest(b"Y")}]}
            with self.assertRaisesRegex(BuildError,"staged bytes"):
                payload.check_physical(base, rows)
            rows["entries"][0]["sha256"] = digest(b"X")
            file.chmod(0o644)
            with self.assertRaisesRegex(BuildError,"staging mode"):
                payload.check_physical(base, rows)

    def test_private_projection_refuses_alias_extra_path_and_rewrite(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            file = base / "x"
            payload.new(file, b"a", 0o444)
            with self.assertRaises(FileExistsError):
                payload.new(file, b"b")
            alias = base / "y"
            os.link(file, alias)
            r = {"path":"/x","type":"file","mode":0o444,"uid":0,"gid":0,"size":1,"sha256":digest(b"a")}
            with self.assertRaisesRegex(BuildError,"namespace"):
                payload.check_physical(base, {"entries":[r]})
            with self.assertRaisesRegex(BuildError,"staged bytes"):
                payload.check_physical(base, {"entries":[r,dict(r,path="/y")]})
            alias.unlink()
            alias.symlink_to(file)
            with self.assertRaisesRegex(BuildError,"staging mode"):
                payload.check_physical(base, {"entries":[r,dict(r,path="/y")]})

    def test_keep_every_field_when_normalizing_gnu_large_symbol_size(self):
        row = "  1705: 00000000005cd888 0x70220 OBJECT  GLOBAL DEFAULT   24 _PyRuntime"
        self.assertEqual(payload.decimal_symbol_sizes(row),row.replace("0x70220",str(0x70220)))
        bad = row.replace("0x70220", "0xINVALID")
        self.assertEqual(payload.decimal_symbol_sizes(bad),bad)
        self.assertEqual(payload.decimal_symbol_sizes("invalid version 0x70220"),"invalid version 0x70220")
