"""Stopped-gate composition with inert kernel/probe records and real private-file replay."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn import pi_core_mask_custody as custody
from aragorn import pi_core_node_source_observer as node
from aragorn import pi_core_stopped_mask_capture as cap
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from aragorn.pi_core_state_mounts import verify_mounts
from test_pi_core_state_masks import _PI, _MANAGER, mask_sample, masked_pi_mountinfo
from test_pi_core_state_mounts import sample_mountinfo


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def table(role, raw):
    details = {}
    verify_mounts(role, raw, device="253:7", backing_devices=["259:0"], fs_type="ext4",
                  mount_details=details)
    return details


class StoppedCapture(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name).resolve()
        store, external = base / "private-blobs", base / "private-out-of-store"
        for d in (store, external):
            d.mkdir(mode=0o700)
        CAS(store)
        local = base.stat()
        self.enterContext(patch.object(custody.held.provision, "_ROOT_UID", local.st_uid))
        self.enterContext(patch.object(custody.held.provision, "_ROOT_GID", local.st_gid))
        outer = {(p.stat().st_dev, p.stat().st_ino) for p in base.parents}
        original = custody.held._ancestor
        def ancestor(fd):
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino) not in outer:
                original(fd)
        self.enterContext(patch.object(custody.held, "_ancestor", side_effect=ancestor))
        self.deadline = time.monotonic() + 25
        self.cfg = cap.StoppedMaskCapture(store, external, "c" * 32, sha(b"deployment"), sha(b"profile"),
                                          sha(b"interpreter"), "253:7", ("259:0",), "ext4")
        self.exe = Mock(wraps=os)
        self.exe.O_RDONLY, self.exe.O_CLOEXEC = os.O_RDONLY, os.O_CLOEXEC
        self.exe.open.return_value = 12345
        self.exe.close = Mock()
        self.enterContext(patch.object(cap, "os", self.exe))
        self.enterContext(patch.object(node, "_hash_readonly", return_value=(self.cfg.interpreter_digest, {})))
        self.cfg.preflight(deployment_digest=self.cfg.deployment_digest, profile_digest=self.cfg.profile_digest,
                           deadline=self.deadline)

        # Only a kernel model: the acquired sources and returned mount streams
        # are supplied as original bytes. No guest/process/namespace is opened.
        self.session = s = object.__new__(node._NodeSession)
        s._mask_capture, s.operation_deadline, s.cleanup_deadline = self.cfg, self.deadline, self.deadline + 3
        s.gate_release_seen, s.stopping, s.failure, s.pending_events = False, False, None, []
        s.tasks = {_PI["pid"]: dict(stopped=True, joined=True, start_ticks=_PI["start_ticks"])}
        s._inventory = Mock(return_value=[_PI["pid"]])
        s._guard = Mock()
        s.observer = SimpleNamespace(_thread=threading.get_native_id(), _executed=False,
            _clock={"boot_id": "106046d5-af42-44d5-a740-a9d1739f91ec", "clock_id": "CLOCK_BOOTTIME",
                    "time_namespace_inode": 8401})
        s.owned = SimpleNamespace(pid=_PI["pid"], start_ticks=_PI["start_ticks"], invocation="d" * 32,
            immutable_digest=sha(b"launch"), plan=SimpleNamespace(unit_name="aragorn-pi-" + "d" * 32 + ".service",
                worker_uid=_PI["uid"], worker_gid=_PI["gid"], source_observation_digest=self.cfg.profile_digest,
                prepared=SimpleNamespace(deployment_digest=self.cfg.deployment_digest)))
        self.worker_raw = masked_pi_mountinfo()
        # Sit on a distinct fs coordinate from every Pi mount. Reflect the
        # private test dirs' real st_dev without inspecting the host's mounts.
        self.dev = f"{os.major(local.st_dev)}:{os.minor(local.st_dev)}"
        self.manager_raw = sample_mountinfo("manager", device="253:7") + (
            f"21 1 {self.dev} /private-evidence {base} rw,nosuid,nodev - ext4 /dev/fixture-evidence rw\n"
        ).encode("ascii")
        walk, self.witness = mask_sample(subject=_PI, manager_subject=_MANAGER)
        w = self.witness
        self.names = list(walk["tree"]["/dev"]["before"])
        self.view = dict(schema="aragorn/pi-core-stopped-mask-view/v1", worker=_PI.copy(), manager=_MANAGER.copy(),
            dev_names=self.names, worker_root=walk["root"], worker_dev=walk["tree"]["/dev"]["stat"],
            opened_boottime_ns=9000, closed_boottime_ns=21000, source=w["source"],
            directories={p: {k:v for k,v in r.items() if k != "probe"} for p,r in w["directories"].items()},
            ptmx={k:v for k,v in w["ptmx"].items() if k != "probe"},
            worker_mountinfo_digest=sha(self.worker_raw), manager_mountinfo_digest=sha(self.manager_raw))
        calls = {p[5:]: deepcopy(r["probe"]) for p,r in w["directories"].items()}
        calls["ptmx"] = deepcopy(w["ptmx"]["probe"])
        self.frames = (w["before"], w["after"], list(self.names), list(self.names), calls)
        self.order, self.exit_error = [], None
        @contextmanager
        def opened(*, pid, start_ticks, deadline):
            self.assertEqual((pid, start_ticks, deadline), (_PI["pid"], _PI["start_ticks"], self.deadline))
            self.order.append("open")
            def finish():
                self.order.append("finish")
                return self.view, self.worker_raw, self.manager_raw
            yield SimpleNamespace(worker=_PI.copy(), finish=finish)
            self.order.append("closed")
            if self.exit_error:
                raise self.exit_error
        def probe(_view, *, deadline, cleanup_deadline, interpreter_digest):
            self.assertEqual((deadline, cleanup_deadline, interpreter_digest),
                (self.deadline, self.session.cleanup_deadline, self.cfg.interpreter_digest))
            self.order.append("probe")
            return self.frames
        self.opened = self.enterContext(patch.object(cap, "hold_stopped_mask_view", side_effect=opened))
        self.probe = self.enterContext(patch.object(cap, "observe_mask_denials", side_effect=probe))

    def acquire(self):
        return cap.capture_stopped_masks(self.session, self.cfg, deadline=self.deadline)

    def keys(self, result):
        return dict(store=self.cfg.store, receipt_directory=self.cfg.receipt_directory,
                    capture_digest=result["capture_digest"], receipt_digest=result["receipt_digest"])

    def test_exact_external_receipt_rereads_five_original_members_and_recomputes_b58_offline(self):
        result = self.acquire()
        self.assertEqual(self.order, ["open", "probe", "finish", "closed"])
        self.assertTrue(result["mask_consistent"])
        self.assertFalse(any(result[k] for k in
            ("activation_authorized", "installed_isolation_verified", "phase3_exit_eligible")))
        paths = self.keys(result)
        independent = self.cfg.receipt_directory / ("mask-" + result["capture_digest"][7:] + ".json")
        receipt = independent.read_bytes()
        self.assertEqual(sha(receipt), result["receipt_digest"])
        members = json.loads(receipt)["members"]
        raw = custody.replay_mask_observation(**paths)
        self.assertEqual(raw["worker"], self.worker_raw)
        self.assertEqual(raw["manager"], self.manager_raw)
        self.assertEqual(raw["vantage"], canonical_json(self.view))
        self.assertEqual(raw["proof"], canonical_json({"names_before": self.names, "names_after": self.names,
                                                      "witness": self.witness}))
        self.assertEqual(sha(raw["bindings"]), result["capture_digest"])
        self.assertEqual(members, {k: {"sha256": sha(v), "size": len(v)} for k,v in raw.items()})
        self.opened.side_effect = self.probe.side_effect = AssertionError("offline replay invoked acquisition")
        self.assertEqual(cap.replay_stopped_masks(**paths), result)
        with self.assertRaises((ValueError, OSError)):
            cap.replay_stopped_masks(**(paths | {"receipt_digest": sha(b"wrong receipt")}))
        independent.unlink()
        with self.assertRaises((ValueError, OSError)):
            cap.replay_stopped_masks(**paths)

    def test_negative_observation_retained_and_replayed_without_retry(self):
        self.frames[-1]["ptmx"]["errno"] = 2
        result = self.acquire()
        self.assertFalse(result["mask_consistent"])
        self.assertTrue(result["reason"])
        self.assertEqual(cap.replay_stopped_masks(**self.keys(result)), result)
        with self.assertRaises(ValueError):
            self.acquire()
        self.opened.assert_called_once()
        self.probe.assert_called_once()

    def test_offline_replay_rejects_receipted_but_inconsistent_bindings_bytes_and_types(self):
        initial = self.acquire()
        raw = custody.replay_mask_observation(**self.keys(initial))
        for i, label in enumerate(("clock", "attempt", "unit", "probe source", "worker bytes",
                                   "manager uid type", "source stat uid type"), start=1):
            with self.subTest(label=label):
                binding, view = json.loads(raw["bindings"]), json.loads(raw["vantage"])
                binding["attempt_id"] = f"{i:032x}"  # distinct immutable receipt per case
                worker = raw["worker"]
                if label == "clock":
                    binding["clock"]["clock_id"] = "CLOCK_MONOTONIC"
                elif label == "attempt":
                    binding["attempt_id"] = "0" * 32
                elif label == "unit":
                    binding["unit"] = "other.service"
                elif label == "probe source":
                    binding["probe_source"] = sha(b"different helper")
                elif label == "worker bytes":
                    worker += b"45 1 0:95 / /other ro - tmpfs tmpfs ro\n"
                elif label == "manager uid type":
                    view["manager"]["uid"] = False  # False == 0 under plain dict equality
                else:
                    view["source"]["before"]["uid"] = False
                bindings = canonical_json(binding)
                pin = sha(bindings)
                receipt = custody.retain_mask_observation(store=self.cfg.store,
                    receipt_directory=self.cfg.receipt_directory, capture_digest=pin, bindings_raw=bindings,
                    worker_raw=worker, manager_raw=raw["manager"], proof_raw=raw["proof"],
                    vantage_raw=canonical_json(view), expected_roots=self.cfg._roots, deadline=self.deadline)
                out = cap.replay_stopped_masks(store=self.cfg.store, receipt_directory=self.cfg.receipt_directory,
                                              capture_digest=pin, receipt_digest=receipt)
                self.assertIs(out["mask_consistent"], False)
                self.assertTrue(out["reason"])
        self.probe.assert_called_once()

    def test_failing_view_release_spends_request_and_publishes_nothing(self):
        self.exit_error = ValueError("inert held directory close failed")
        with self.assertRaisesRegex(ValueError, "directory close"):
            self.acquire()
        with self.assertRaises(ValueError):
            self.acquire()
        self.assertEqual(list(self.cfg.receipt_directory.iterdir()), [])
        self.opened.assert_called_once()
        self.probe.assert_called_once()

    def test_replaced_gate_after_collection_disallows_any_publication(self):
        self.session._guard.side_effect = [None, ValueError("inert changed gate")]
        with self.assertRaisesRegex(ValueError, "changed gate"):
            self.acquire()
        self.assertEqual(self.order, ["open", "probe", "finish", "closed"])
        self.assertEqual(list(self.cfg.receipt_directory.iterdir()), [])

    def test_initial_guard_failure_spends_request_without_acquiring(self):
        self.session._guard.side_effect = [ValueError("inert first stop not stable"), None]
        with self.assertRaisesRegex(ValueError, "first stop"):
            self.acquire()
        with self.assertRaises(ValueError):
            self.acquire()
        self.opened.assert_not_called()
        self.probe.assert_not_called()
        self.assertEqual(list(self.cfg.receipt_directory.iterdir()), [])

    def test_spent_preflight_never_renominates_private_paths(self):
        with self.assertRaises(ValueError):
            self.cfg.preflight(deployment_digest=self.cfg.deployment_digest, profile_digest=self.cfg.profile_digest,
                               deadline=self.deadline)
        self.opened.assert_not_called()

    def test_coordinate_guard_refuses_aliases_and_submounts(self):
        pi, mgr = table("pi", self.worker_raw), table("manager", self.manager_raw)
        cap._destination_coordinates(self.cfg, self.cfg._roots, pi, mgr)
        source = str(self.cfg.store)
        for name, location, dev, root in (
                ("Pi sees store", "/alias", self.dev, "/private-evidence/private-blobs"),
                ("Pi sees its ancestor", "/alias", self.dev, "/"),
                ("Pi sees its descendant", "/alias", self.dev, "/private-evidence/private-blobs/sub"),
                ("nested mount in store", source + "/child", "0:97", "/")):
            with self.subTest(name=name):
                worker, manager = deepcopy(pi), deepcopy(mgr)
                target = manager if name.startswith("nested") else worker
                target[location] = dict(mount_id=83, dev=dev, root=root, fs_type="ext4",
                                        options=frozenset({"rw"}))
                with self.assertRaises(ValueError):
                    cap._destination_coordinates(self.cfg, self.cfg._roots, worker, manager)

    def test_coordinate_guard_rejects_volatile_readonly_and_service_state_destinations(self):
        pi, mgr = table("pi", self.worker_raw), table("manager", self.manager_raw)
        for label, dev, fs, options in (("volatile", self.dev, "tmpfs", {"rw"}),
                ("read only", self.dev, "ext4", {"ro"}), ("state", "253:7", "ext4", {"rw"}),
                ("backing", "259:0", "ext4", {"rw"})):
            with self.subTest(label=label):
                manager = deepcopy(mgr)
                manager[str(self.cfg.store.parent)].update(dev=dev, fs_type=fs, options=frozenset(options))
                # Preserve the matching directory-device observation even for
                # forbidden storage: refusal must not rely on a device typo.
                maj, minor = map(int, dev.split(":"))
                # The inert reader models Linux device encoding; a test host
                # may have a smaller native dev_t major-number range.
                self.exe.major.return_value, self.exe.minor.return_value = maj, minor
                with self.assertRaises(ValueError):
                    cap._destination_coordinates(self.cfg, self.cfg._roots, pi, manager)
