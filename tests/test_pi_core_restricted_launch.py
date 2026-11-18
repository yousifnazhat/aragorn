"""Focused restricted-launch contracts, using inert bytes and mocked process views."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn import pi_core_confined_launch as launch
from aragorn import pi_core_node_source_observer as observer
from aragorn import pi_core_node_source_observation_verify as replay
from aragorn import pi_core_restricted_profile as fixed
from aragorn import pi_core_source_inventory_prepare as inventory
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_confined_launch as fixtures
from tests import test_pi_core_preexec_launch as preexec


def profile():
    value = preexec.profile()
    value["schema"] = fixed.PROFILE_SCHEMA
    value["pins"].update(gate_digest="sha256:" + fixed.GATE_SHA256,
                         node_digest="sha256:" + fixed.NODE_SHA256)
    value["sources"] = [dict(path=preexec.ENTRY, digest="sha256:" + fixed.BUNDLE_SHA256)]
    return value


def configured():
    previous = fixtures.configuration()
    shape = dict(previous.compiled_receipt, schema=fixed.RUNTIME_SCHEMA)
    value = profile()
    # Only the config/plan shape is under test; this is not an assembled image.
    return replace(previous, native_request=True, compiled_receipt=shape,
                   compiled_receipt_digest=canonical_digest(shape),
                   source_observation=value, source_observation_digest=canonical_digest(value))


def source_plan():
    value = profile()
    value["schema"] = inventory.RESTRICTED_PLAN_SCHEMA
    for key in ("source_inventory_digest", "loader_inventory_digest"):
        del value["pins"][key]
    return value


def argv_bytes():
    return (preexec.NODE + "\0--disallow-code-generation-from-strings\0" + preexec.ENTRY + "\0").encode("ascii")


class RestrictedLaunchTests(unittest.TestCase):
    def test_the_real_assembly_is_consumable_only_with_its_exact_launch_receipt(self):
        root = Path(__file__).resolve().parents[1]
        checkpoint = json.loads((root / "packaging/pi-core/restricted-runtime-artifact-v1.json").read_bytes())
        directory = root / ".aragorn/pi-core-build/restricted-runtime-b36"
        self.assertEqual(root / checkpoint["output"], directory)
        documents = {}
        for name in ("manifest.json", "build-receipt.json", "outcome.json"):
            path = directory / name
            self.assertEqual(path.resolve(strict=True), path)
            raw = path.read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), checkpoint["files"][name])
            documents[name] = json.loads(raw)
        manifest, receipt = documents["manifest.json"], documents["build-receipt.json"]
        pin = checkpoint["canonical_receipt_digest"]
        self.assertEqual(launch._runtime_inventory(manifest, receipt, pin), fixed.RUNTIME_DIGEST)
        self.assertEqual(launch._source_gate_artifact(manifest, receipt)["digest"], "sha256:" + fixed.GATE_SHA256)
        self.assertEqual(checkpoint["runtime_digest"], documents["outcome.json"]["runtime_tree_digest"])
        for mutation in (dict(manifest, files=manifest["files"][1:]),
                         dict(manifest, files=[dict(manifest["files"][0], executable=False), *manifest["files"][1:]])):
            with self.assertRaises(ValueError):
                launch._runtime_inventory(mutation, receipt, pin)

    def test_exact_gate_command_and_empty_inherited_environment(self):
        config = configured()
        process = fixtures.profile_for(config)
        _, argv = launch._systemd_plan(config, fixtures.prepared_for(process), process)
        self.assertEqual(argv[argv.index("--")+1:], ("/usr/bin/env", "-i", "HOME=/nonexistent",
            "PATH=/opt/aragorn/pi-runtime/node/bin", preexec.GATE, preexec.NODE,
            "--disallow-code-generation-from-strings", preexec.ENTRY))
        self.assertIn("--property=PrivateNetwork=yes", argv)

    def test_restricted_receipt_cannot_pair_with_absent_legacy_or_non_native_profile(self):
        config = configured()
        legacy = preexec.profile()
        for fields in (dict(source_observation=None, source_observation_digest=None),
                       dict(source_observation=legacy, source_observation_digest=canonical_digest(legacy)),
                       dict(native_request=False), dict(compiled_receipt=fixtures.configuration().compiled_receipt)):
            with self.subTest(fields=list(fields)), self.assertRaisesRegex(ValueError, "restricted bundle"):
                replace(config, **fields)

    def test_full_predecessor_with_hidden_restricted_bytes_is_refused(self):
        for digest in (fixed.GATE_SHA256, fixed.BUNDLE_SHA256):
            manifest = fixtures.runtime_manifest()
            manifest["files"].append(dict(path="pi-core/node_modules/extra.js", size=1,
                                          digest="sha256:" + digest, executable=False))
            receipt = fixtures.receipt(manifest)
            with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, "predecessor runtime"):
                launch._runtime_inventory(manifest, receipt, canonical_digest(receipt))

    def test_predecessor_source_profile_cannot_hide_known_gate_or_source_in_loaders(self):
        for mark_gate in (True, False):
            value = preexec.profile()
            if mark_gate:
                value["pins"]["gate_digest"] = "sha256:" + fixed.GATE_SHA256
            else:
                value["loader_files"][0]["digest"] = "sha256:" + fixed.BUNDLE_SHA256
            with self.subTest(mark_gate=mark_gate):
                with self.assertRaisesRegex(ValueError, "restricted artifacts"):
                    launch._source_observation(value, canonical_digest(value))
                with self.assertRaisesRegex(observer.base.PiSourceObserverError, "DOWNGRADE"):
                    observer.validate_node_profile(value)

    def test_installed_plan_requires_independent_opt_in_and_exact_entry(self):
        good = source_plan()
        self.assertEqual(inventory._plan(canonical_json(good), canonical_digest(good)), good)
        for changed in ("schema", "node_digest", "gate_digest", "source"):
            value = source_plan()
            if changed == "schema":
                value["schema"] = inventory.PLAN_SCHEMA
            elif changed == "source":
                value["sources"][0]["digest"] = fixtures.digest("d")
            else:
                value["pins"][changed] = fixtures.digest("d")
            with self.subTest(changed=changed), self.assertRaises(inventory.PiSourceInventoryPreparationError):
                inventory._plan(canonical_json(value), canonical_digest(value))

    def test_independent_replay_validates_retained_profile_not_just_its_hash(self):
        for mutation in ("none", "downgraded", "changed_node", "wrong_tree", "stripped_restricted_tree"):
            value = profile()
            tree = fixed.RUNTIME_DIGEST
            if mutation == "downgraded":
                value["schema"] = observer.PROFILE_SCHEMA
            elif mutation == "changed_node":
                value["pins"]["node_digest"] = fixtures.digest("d")
            elif mutation == "wrong_tree":
                tree = fixtures.digest("e")
            elif mutation == "stripped_restricted_tree":
                value = preexec.profile()
            raw = canonical_json(value)
            args = (raw, dict(value["pins"], runtime_digest=tree, profile_digest=canonical_digest(value)),
                    {row["path"]: row for row in value["sources"]},
                    {row["path"]: row for row in value["loader_files"]}, Mock(read=Mock(return_value=raw)))
            with self.subTest(mutation=mutation):
                if mutation == "none":
                    self.assertEqual(replay._profile(*args), (value, {preexec.ENTRY}))
                else:
                    with self.assertRaises(replay.PiSourceObservationVerificationError):
                        replay._profile(*args)


class StoppedExecTests(unittest.TestCase):
    def setUp(self):
        self.s = object.__new__(observer._NodeSession)
        self.s.owned = SimpleNamespace(pid=91, start_ticks=23)
        self.s.profile = profile()
        self.s.tasks = {91: dict(stopped=True, joined=True, stop_event=4, start_ticks=23, call={"nr": 221})}
        self.s._tid_identity = Mock(return_value=23)
        self.s._budget = Mock()
        self.s.observer = SimpleNamespace(_executed=False, _bindings=self.s.profile["pins"],
                                          _executable_identities={"node": "identity"})
        self.s._event = Mock()

    def handle(self, raw):
        with (patch.object(observer.base.process, "_executable_digest", return_value="sha256:" + fixed.NODE_SHA256),
              patch.object(observer.os, "stat"), patch.object(observer.base, "_file_identity", return_value="identity"),
              patch.object(observer.base.process, "_read_virtual_file", return_value=raw) as read):
            self.s._handle(dict(pid=91, event=4, event_message=91), 2.0)
        return read

    def test_reports_kernel_bytes_for_the_stopped_exec(self):
        raw = argv_bytes()
        read = self.handle(raw)
        read.assert_called_once_with(Path("/proc/91/cmdline"), len(raw))
        self.s._event.assert_called_once_with("EXEC", pid=91, digest="sha256:" + fixed.NODE_SHA256,
                                               raw_cmdline_hex=raw.hex())
        self.assertTrue(self.s.observer._executed)

    def test_missing_flag_trailing_nul_or_extra_argument_never_marks_executed(self):
        raw = argv_bytes()
        for changed in (raw.replace(b"--disallow-code-generation-from-strings\0", b""),
                        raw.rstrip(b"\0"), raw + b"extra\0", raw.replace(b"node\0", b"nope\0")):
            with self.subTest(changed=changed), self.assertRaisesRegex(observer.base.PiSourceObserverError, "ARGV"):
                self.handle(changed)
            self.assertFalse(self.s.observer._executed)
            self.s._event.assert_not_called()

    def test_resumed_task_or_extra_thread_is_not_a_custodied_read(self):
        for extra in (False, True):
            self.s.tasks[91]["stopped"] = extra
            if extra:
                self.s.tasks[99] = {}
            with self.subTest(extra=extra), patch.object(observer.base.process, "_read_virtual_file") as read:
                with self.assertRaisesRegex(observer.base.PiSourceObserverError, "CUSTODY"):
                    self.s._stopped_cmdline(91, 4, fixed.NODE_ARGV, 2.0)
                read.assert_not_called()

    def test_generation_change_while_reading_is_not_evidence(self):
        self.s._tid_identity.side_effect = [23, 24]
        with self.assertRaisesRegex(observer.base.PiSourceObserverError, "ARGV"):
            self.handle(argv_bytes())
        self.s._event.assert_not_called()
        self.assertFalse(self.s.observer._executed)

    def test_replay_requires_exact_raw_bytes_at_same_exec_stop(self):
        stop = {"event": 4}
        digest = "sha256:" + fixed.NODE_SHA256
        event = dict(seq=9, boottime_ns=99, kind="EXEC", pid=91, digest=digest,
                     raw_cmdline_hex=argv_bytes().hex())
        replay._exec_record(event, profile(), 91, digest, stop, stop, False)
        for changed, prior in ((dict(event, raw_cmdline_hex="00"), stop),
                               ({k:v for k,v in event.items() if k != "raw_cmdline_hex"}, stop),
                               (dict(event, pid=92), stop), (event, dict(stop))):
            with self.subTest(changed=changed), self.assertRaises(replay.PiSourceObservationVerificationError):
                replay._exec_record(changed, profile(), 91, digest, stop, prior, False)
        with self.assertRaises(replay.PiSourceObservationVerificationError):
            replay._exec_record(event, preexec.profile(), 91, digest, stop, stop, False)
