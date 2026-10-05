"""Synthetic contract joins only; never run native units or retained captures."""

import copy
import hashlib
import json
import stat
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import native_phase3_plugin_update_binding as reported
from aragorn import native_phase3_plugin_update_live_binding as subject
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from aragorn.phase3_deployment import build_phase3_deployment_identity

_CAPTURE = (
    Path(__file__).resolve().parents[1]
    / "benchmark/evidence/phase3-native-plugin-update-systemd-development-v2-2026-10-01.json"
)
_CAPTURE_PIN = "sha256:42acdf26c128c4d7ecdfd740ac04b17509e9e17e0b799e7d4a870bf5e82a9e12"


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _file(digest, size, owner=(0, 0), mode=0o400, inode=101):
    return {
        "bytes": size,
        "digest": digest,
        "identity": [45, inode, stat.S_IFREG | mode, *owner, 1, size, 1000, 1000],
    }


def _argv(role):
    if role == "gateway":
        return [
            subject._NODE,
            subject._ENTRY,
            "gateway",
            "run",
            "--auth",
            "token",
            "--bind",
            "loopback",
            "--port",
            "18789",
            "--tailscale",
            "off",
        ]
    unit = subject._UNITS[role]
    name = {
        "worker": "worker-binding",
        "sensor": "observation-binding",
        "broker": "runtime-binding",
    }[role]
    argv = [
        "/usr/bin/python3.12",
        "-I",
        "-S",
        "-B",
        subject._SHIMS[role],
        f"/run/credentials/{unit}/{name}",
    ]
    if role in {"sensor", "broker"}:
        argv.append(f"/run/credentials/{unit}/capability-grant")
    return argv


def _fixture(capture):
    """Attach synthetic reader records to authentic old observation structure.

    These records are deliberately not a new live capture and never establish
    source execution or deployment authenticity. They exercise the new joins.
    """
    observation, source_raws = capture["observation"], {}
    capture["live_identity_sources"] = {}
    for path in subject.SOURCE_PATHS:
        raw = ("synthetic non-executable contract source: " + path).encode()
        source_raws[path] = raw
        item = {
            "path": path,
            "bytes": len(raw),
            "digest": _digest(raw),
            "mode": "100644",
            "blob": hashlib.sha1(
                b"blob " + str(len(raw)).encode() + b"\0" + raw
            ).hexdigest(),
        }
        capture["live_identity_sources"][path] = item
        if path in subject._INSTALLED_HELPERS:
            capture["fixture_helpers"][path] = {
                **item,
                "installed_mode": "0444",
                "installed_path": subject._INSTALLED_HELPERS[path],
            }
    accounts = {
        role: (item["process"]["uid"], item["process"]["gid"])
        for role, item in observation["processes"].items()
    }
    processes = {}
    for role, unit in subject._UNITS.items():
        outer = observation["processes"][role]
        pid, uid, gid = outer["process"]["pid"], *accounts[role]
        state = copy.deepcopy(outer["unit"])
        argv = _argv(role)
        state.setdefault("DropInPaths", "")
        state.setdefault("FragmentPath", "/lib/systemd/system/" + unit)
        state.setdefault(
            "ExecStart",
            "{ path="
            + argv[0]
            + " ; argv[]="
            + " ".join(argv)
            + " ; ignore_errors=no ; pid=0 ; }",
        )
        fsuid, fsgid = accounts["worker"] if role == "sensor" else (uid, gid)
        groups = (
            sorted({accounts["worker"][1], accounts["sensor"][1]})
            if role in {"sensor", "broker"}
            else (sorted({gid, accounts["gateway"][1]}) if role == "worker" else [gid])
        )
        processes[role] = {
            "unit": state,
            "pid": pid,
            "start_time_ticks": outer["process"]["start_time_ticks"],
            "uids": [uid, uid, uid, fsuid],
            "gids": [gid, gid, gid, fsgid],
            "groups": groups,
            "cgroup": outer["process"]["cgroup"],
            "cgroup_identity": [
                outer["process"].get("cgroup_device", 30),
                outer["process"].get("cgroup_inode", pid),
            ],
            "root_identity": [40, 1],
            "mount_namespace": {"device": 4, "inode": 400 + pid},
            "argv": ["openclaw-gateway"] if role == "gateway" else argv,
        }
    setup = observation["setup"]
    files = {
        path: copy.deepcopy(observation["installed_sources"][path])
        for path in subject._PROFILE_PATHS
    }
    entry = capture["staged_profile"]["required_runtime_not_included"]
    files[subject._ENTRY] = _file(
        entry["entrypoint_digest"], entry["entrypoint_bytes"], mode=0o644
    )
    files[subject._PYTHON] = _file(
        setup["runtime_profile"]["executable_digest"], 4096, mode=0o755
    )
    files[subject._NODE] = _file(
        _digest(b"operator held synthetic node executable pin"), 8192, mode=0o755
    )
    documents = {
        subject._WORKER: setup["worker_binding"],
        subject._POLICY: setup["policy"],
        subject._GRANT: setup["grant"],
        subject._GENESIS: setup["empty_store"]["genesis"],
        subject._RUNTIME: {
            "schema": "aragorn/runtime-action-runtime-binding/v2",
            "runtime_digest": setup["runtime_digest"],
            "runtime_profile_digest": _digest(canonical_json(setup["runtime_profile"])),
        },
        subject._OBSERVATION: {
            "schema": "aragorn/runtime-observation-binding/v2",
            "sensor_digest": setup["policy"]["sensor_digest"],
            "runtime_profile": setup["runtime_profile"],
        },
    }
    for path, doc in documents.items():
        raw = canonical_json(doc)
        files[path] = _file(
            _digest(raw),
            len(raw),
            accounts["broker"] if path == subject._POLICY else (0, 0),
        )
    config = observation["plugin_update"]["document"]["action"]["before"]["boundary"][
        "config"
    ]["file"]
    files[subject._CONFIG] = _file(setup["configuration_digest"], config["size"])
    loaded = {}
    for role, credentials in subject._CREDENTIALS.items():
        loaded[role] = {}
        for name, path in credentials.items():
            source = files[path]
            loaded[role][name] = _file(
                source["digest"], source["bytes"], (accounts[role][0], 0)
            )
        code = (
            subject._ENTRY
            if role == "gateway"
            else subject._WORKER_CODE
            if role == "worker"
            else subject._SHIMS[role]
        )
        loaded[role]["code_view"] = copy.deepcopy(files[code])
    loaded["gateway"]["openclaw-config"]["identity"] = [
        config["device"],
        config["inode"],
        stat.S_IFREG | int(config["mode"], 8),
        config["uid"],
        config["gid"],
        config["nlink"],
        config["size"],
        1000,
        1000,
    ]
    boot = observation["boot_id"]
    snapshot = {
        "schema": "aragorn/native-phase3-live-identity/v1",
        "authority": "LOCAL_KERNEL_AND_PROTECTED_BYTES_NOT_HOST_ATTESTATION_OR_QUALIFICATION",
        "status": "LOCAL_NATIVE_IDENTITY_MEASURED",
        "container_id": capture["fixture_container"],
        "boot_id": "-".join(
            (boot[:8], boot[8:12], boot[12:16], boot[16:20], boot[20:])
        ),
        "files": files,
        "processes": processes,
        "loaded_process_views": loaded,
        "fixed_python_launcher": {
            "path": "/usr/bin/python3.12",
            "target": subject._PYTHON,
            "identity": [
                45,
                202,
                stat.S_IFLNK | 0o777,
                0,
                0,
                1,
                len(subject._PYTHON),
                1000,
                1000,
            ],
        },
        "fixed_systemd_library_alias": {
            "path": "/lib",
            "target": "usr/lib",
            "canonical_unit_directory": "/usr/lib/systemd/system",
            "identity": [45, 203, stat.S_IFLNK | 0o777, 0, 0, 1, 7, 1000, 1000],
            "target_ancestry_identities": [
                [45, inode, stat.S_IFDIR | 0o755, 0, 0] for inode in range(1, 5)
            ],
        },
        "measured_joins": {
            "configuration_digest": setup["configuration_digest"],
            "worker_binding_digest": _digest(canonical_json(setup["worker_binding"])),
            "policy_digest": _digest(canonical_json(setup["policy"])),
            "declared_runtime_digest_not_whole_tree_measurement": setup[
                "runtime_digest"
            ],
        },
        "unresolved_dimensions": copy.deepcopy(subject._UNRESOLVED),
        "limitations": list(subject._READER_LIMITS),
        **dict.fromkeys(subject._READER_FLAGS, False),
    }
    static = {
        "schema": "aragorn/native-plugin-update-identity-static-pins/v1",
        "file_digests": {path: files[path]["digest"] for path in subject.STATIC_PATHS},
    }
    envelope = {
        "schema": "aragorn/runtime-native-plugin-update-identity-observation/v1",
        "authority": "OWNED_UPDATE_ADAPTER_WITH_LOCAL_LIVE_IDENTITY_NOT_ROUTE_OR_RUN_QUALIFICATION",
        "status": "OBSERVED",
        "route_id": reported.ROUTE,
        "branch": reported.BRANCH,
        "fixture_container": capture["fixture_container"],
        "static_pin_manifest": static,
        "static_pin_manifest_digest": _digest(canonical_json(static)),
        "expected_file_digests": {
            path: files[path]["digest"] for path in subject.FILE_PATHS
        },
        "provisioning_file_digests": {
            path: files[path]["digest"] for path in subject.DYNAMIC_PATHS
        },
        "provisioning_origin": "EXACT_EXISTING_WRITER_INPUT_BYTES_BEFORE_ACTIVATION",
        "pins_frozen_before_activation": True,
        "activation_count": 1,
        "invocation_count": 1,
        "before": snapshot,
        "after": copy.deepcopy(snapshot),
        "comparison": {
            "status": "CALLER_MEASUREMENTS_EQUAL",
            "authority": "COMPARISON_ONLY_NOT_INDEPENDENT_LIVE_READBACK",
            "snapshot_digest": _digest(canonical_json(snapshot)),
            "phase3_eligible": False,
            "route_qualified": False,
            "common_deployment_fully_verified": False,
        },
        "boundaries_monotonic_ns": dict(
            zip(subject._BOUNDARIES, range(1, 7), strict=True)
        ),
        "refusal": None,
        "limitations": list(subject._ENVELOPE_LIMITS),
        **dict.fromkeys(subject._FLAGS, False),
    }
    capture["live_identity"] = envelope
    return source_raws


class NativePluginUpdateLiveBindingTests(unittest.TestCase):
    def setUp(self):
        raw = _CAPTURE.read_bytes()
        self.assertEqual(_digest(raw), _CAPTURE_PIN)
        self.capture = json.loads(raw)
        sources = _fixture(self.capture)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cas = CAS(Path(self.temporary.name) / "cas")
        self.readonly = CAS(self.cas.root, read_only=True)
        self.source_pins = {
            path: self.cas.put(BytesIO(raw), max_bytes=1024 * 1024)
            for path, raw in sources.items()
        }
        self.static_pin = self.cas.put(
            BytesIO(
                canonical_json(self.capture["live_identity"]["static_pin_manifest"])
            ),
            max_bytes=16384,
        )
        self.source_pin = _digest(canonical_json(self.capture["source"]))
        self.commit = self.capture["source"]["commit"]
        capture_raw = canonical_json(self.capture) + b"\n"
        artifacts = reported.native_plugin_update_identity_artifacts(
            capture_raw,
            expected_capture_digest=_digest(capture_raw),
            expected_source_digest=self.source_pin,
            expected_source_commit=self.commit,
        )
        self.deployment_raw = canonical_json(
            build_phase3_deployment_identity(
                {
                    name: self.cas.put(BytesIO(raw), max_bytes=1024 * 1024)
                    for name, raw in artifacts.items()
                }
            )
        )

    def verify(self, capture=None, **overrides):
        capture = self.capture if capture is None else capture
        raw = canonical_json(capture) + b"\n"
        kwargs = {
            "expected_capture_digest": _digest(raw),
            "expected_source_digest": self.source_pin,
            "expected_source_commit": self.commit,
            "deployment_raw": self.deployment_raw,
            "expected_deployment_digest": _digest(self.deployment_raw),
            "expected_live_identity_digest": _digest(
                canonical_json(capture["live_identity"])
            ),
            "expected_live_source_digests": self.source_pins,
            "expected_static_pin_manifest_digest": self.static_pin,
            "evidence_cas": self.readonly,
        }
        kwargs.update(overrides)
        return subject.verify_native_plugin_update_live_binding(raw, **kwargs)

    def test_synthetic_readback_joins_original_report_without_writes_or_promotion(self):
        before = sorted(str(path) for path in self.cas.root.rglob("*"))
        with patch.object(
            CAS, "put_expected", side_effect=AssertionError("unexpected write")
        ):
            result = self.verify()
        self.assertEqual(result["status"], "BOUNDED_LOCAL_READBACK_JOINS_VERIFIED")
        self.assertEqual(len(result["reported_deployment_dimensions_verified"]), 7)
        self.assertEqual(result["live_deployment_dimensions_verified"], [])
        self.assertEqual(len(result["selected_local_readback_joins"]), 7)
        self.assertTrue(all(result[name] is False for name in subject._FLAGS))
        self.assertFalse(result["metrics_eligible"])
        self.assertEqual(before, sorted(str(path) for path in self.cas.root.rglob("*")))

    def test_rehashed_equal_snapshots_cannot_hide_mixed_epochs_files_credentials_or_aliases(
        self,
    ):
        mutations = (
            lambda s: s["processes"]["worker"].update(start_time_ticks=1),
            lambda s: s["files"][subject._WORKER_CODE].update(
                digest="sha256:" + "0" * 64
            ),
            lambda s: s["loaded_process_views"]["worker"]["worker-binding"].update(
                digest="sha256:" + "0" * 64
            ),
            lambda s: s["loaded_process_views"]["gateway"]["openclaw-config"][
                "identity"
            ].__setitem__(1, 1),
            lambda s: s["measured_joins"].update(policy_digest="sha256:" + "0" * 64),
            lambda s: s["fixed_systemd_library_alias"].update(target="other/lib"),
            lambda s: s.pop("fixed_systemd_library_alias"),
            lambda s: s["fixed_python_launcher"].update(target="/usr/local/bin/other"),
            lambda s: s.update(common_deployment_fully_verified=True),
        )
        for mutation in mutations:
            capture = copy.deepcopy(self.capture)
            envelope = capture["live_identity"]
            mutation(envelope["before"])
            envelope["after"] = copy.deepcopy(envelope["before"])
            envelope["comparison"]["snapshot_digest"] = _digest(
                canonical_json(envelope["before"])
            )
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(subject.NativePluginUpdateLiveBindingError),
            ):
                self.verify(capture)
        for mutation in (
            lambda e: e["after"].update(boot_id="0" * 36),
            lambda e: e["boundaries_monotonic_ns"].update(invocation_finished_ns=1),
            lambda e: e.update(status="REFUSED"),
            lambda e: e.update(invocation_count=True),
            lambda e: e["provisioning_file_digests"].update(
                {subject._GRANT: "sha256:" + "0" * 64}
            ),
        ):
            capture = copy.deepcopy(self.capture)
            mutation(capture["live_identity"])
            with (
                self.subTest(envelope_mutation=mutation),
                self.assertRaises(subject.NativePluginUpdateLiveBindingError),
            ):
                self.verify(capture)
        # All reported grant hashes can agree while the grant references a
        # different policy. The independent cross-document join must still fail.
        capture = copy.deepcopy(self.capture)
        capture["observation"]["setup"]["grant"]["policy_digest"] = "sha256:" + "0" * 64
        grant_pin = _digest(canonical_json(capture["observation"]["setup"]["grant"]))
        envelope = capture["live_identity"]
        envelope["provisioning_file_digests"][subject._GRANT] = grant_pin
        envelope["expected_file_digests"][subject._GRANT] = grant_pin
        envelope["before"]["files"][subject._GRANT]["digest"] = grant_pin
        for role in ("sensor", "broker"):
            envelope["before"]["loaded_process_views"][role]["capability-grant"][
                "digest"
            ] = grant_pin
        envelope["after"] = copy.deepcopy(envelope["before"])
        envelope["comparison"]["snapshot_digest"] = _digest(
            canonical_json(envelope["before"])
        )
        with self.assertRaisesRegex(
            subject.NativePluginUpdateLiveBindingError, "bindings disagree"
        ):
            self.verify(capture)

    def test_caller_source_static_capture_and_deployment_pins_are_required(self):
        zero = "sha256:" + "0" * 64
        for override in (
            {"expected_capture_digest": zero},
            {"expected_source_digest": zero},
            {"expected_source_commit": "0" * 40},
            {"expected_deployment_digest": zero},
            {"expected_live_identity_digest": zero},
            {"expected_static_pin_manifest_digest": zero},
            {
                "expected_live_source_digests": {
                    **self.source_pins,
                    subject.SOURCE_PATHS[0]: zero,
                }
            },
        ):
            with (
                self.subTest(override=tuple(override)),
                self.assertRaises(subject.NativePluginUpdateLiveBindingError),
            ):
                self.verify(**override)
        for path in subject.SOURCE_PATHS:
            changed = copy.deepcopy(self.capture)
            changed["live_identity_sources"][path]["blob"] = "0" * 40
            with (
                self.subTest(source=path),
                self.assertRaises(subject.NativePluginUpdateLiveBindingError),
            ):
                self.verify(changed)

    def test_readonly_complete_source_and_static_custody_is_mandatory(self):
        with self.assertRaises(subject.NativePluginUpdateLiveBindingError):
            self.verify(evidence_cas=self.cas)
        original = CAS.read
        for denied in (self.static_pin, *self.source_pins.values()):

            def read(store, digest, *, max_bytes=None):
                if digest == denied:
                    raise OSError("synthetic missing retained child")
                return original(store, digest, max_bytes=max_bytes)

            with (
                self.subTest(denied=denied),
                patch.object(CAS, "read", read),
                self.assertRaises(subject.NativePluginUpdateLiveBindingError),
            ):
                self.verify()
        reads = {}

        def replaced_after_first_read(store, digest, *, max_bytes=None):
            reads[digest] = reads.get(digest, 0) + 1
            if digest == self.static_pin and reads[digest] > 1:
                raise OSError("synthetic end-custody loss")
            return original(store, digest, max_bytes=max_bytes)

        with (
            patch.object(CAS, "read", replaced_after_first_read),
            self.assertRaises(subject.NativePluginUpdateLiveBindingError),
        ):
            self.verify()


if __name__ == "__main__":
    unittest.main()
