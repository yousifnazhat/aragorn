"""Real supervisor/exchange ordering over inert native edges and one temporary file."""
from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

from aragorn import pi_core_confined_launch as confined
from aragorn import pi_core_native_provider as provider
from aragorn import pi_core_native_supervisor as native
from aragorn import pi_core_pilot_output_observer as output
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_native_provider_wiring as wiring


_PUBLIC = Path(__file__).resolve().parents[1] / "benchmark/pi-core-pilot-v1"
_MANIFEST = "sha256:e6de9001bdd41e7908d0b9097798d1ab8ae13037c4ad1a7dbceb4cea985ad77f"


class PilotOutputWiringTests(TestCase):
    def setUp(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        self.file = root / "result.json"
        self.fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        info = os.fstat(self.fd)
        self.descriptor = dict(schema="aragorn/runtime-protected-path/v1", root_device=info.st_dev,
                               root_inode=info.st_ino, target_name="result.json")
        self.output = output.PilotOutputRequest(self.fd, self.descriptor)
        self.f = wiring.fixture(self, wiring.ProviderNativeCallerTests)
        f, edges = self.f, self.f.f
        lease = f.provider_channels.services
        f.channels = replace(f.channels, service_custody=lease)
        lease._request_channels = f.channels
        self.events = edges.events
        review = json.loads((_PUBLIC / "review.json").read_bytes())
        f.config = replace(f.config, task=(_PUBLIC / "task.txt").read_text())
        prepared = edges.plan.prepared
        prepared.system_prompt = (_PUBLIC / "candidate/SKILL.md").read_text()
        prepared.manifest_digest, prepared.tree_digest, prepared.skill_digest = (
            _MANIFEST, review["tree_digest"], review["skill_digest"])
        self.activation_id = prepared.activation_id
        self.activation = dict(wiring.request_fixtures.activation(),
            activation_id=prepared.activation_id, session_id=prepared.activation_id, run_id=prepared.activation_id,
            source_manifest_digest=_MANIFEST, tree_digest=prepared.tree_digest, active_skill_digest=prepared.skill_digest)
        start = confined._start(f.config, prepared)
        edges.plan = replace(edges.plan, start_bytes=start)
        edges.stack.enter_context(mock.patch.object(native, "_start", return_value=start))
        # The donor normally mocks the entire exchange. Retain only the kernel,
        # socket and service edges: exercise the real protected START and RELEASE.
        edges.exchange.side_effect = confined.exchange_prepared_pi_bootstrap
        edges.stack.enter_context(mock.patch.object(confined.os, "geteuid", return_value=0))
        edges.stack.enter_context(mock.patch.object(confined, "_read_bootstrap", return_value=
            dict(schema="aragorn/pi-core-bootstrap-hello/v1", worker_nonce="a"*32)))
        edges.stack.enter_context(mock.patch.object(confined, "bind_pi_worker_activation", return_value=self.activation))
        def send(connection, raw, deadline):
            frame = json.loads(raw)
            self.events.append("START" if frame["schema"] == "aragorn/pi-core-bootstrap-start/v3" else "RELEASE")
        self.send = edges.stack.enter_context(mock.patch.object(confined, "_send_frame", side_effect=send))
        f.p = object.__new__(provider.PiNativeProviderDispatch)
        f.p._observation = dict(status="PROVIDER_RETURNED", cleanup="VERIFIED_OWNED_PROVIDER_CLEANUP")
        f.p.require_start = mock.Mock()
        f.p.require_completed = mock.Mock()
        self.terminal = dict(status="REQUEST_RETURNED", request_attempted=True, action_evidence_uncertainty=None,
            cleanup="VERIFIED_OWNED_REQUEST_CLEANUP",
            worker_result=dict(status="COMPLETED", broker_result=dict(target_name="result.json",
                verdict="ALLOW", effect_status="CREATED")),
            action_evidence=dict(schema="aragorn/pi-core-native-action-evidence/v1",
                                 authority="RETAINED_ACTION_RECORDS_ONLY_NOT_EFFECT_TIMING_HEALTH_OR_PHASE3",
                                 status="CLOSED", owned_handles_closed=True, receipt_join_verified=True,
                                 phase3_exit_eligible=False, cleanup_uncertainty=[],
                                 activation_digest=canonical_digest(self.activation)))
        self.tool_calls = 1
        def result(connection, deadline):
            self.events.append("terminal")
            self.f.r.observation = self.terminal
            self.write_fixture()  # Test-owned, even in negative cases: matching bytes alone cannot pass.
            return {**wiring.completed(self.tool_calls), "activation_id": self.activation_id}
        f.r.read_bootstrap_result.side_effect = result
        # Wrap rather than replace the actual reads to make the two boundaries observable.
        hold = output.PilotOutputRequest.hold
        @contextmanager
        def trace(request, **kw):
            with hold(request, **kw) as after:
                self.events.append("absent")
                def read():
                    self.events.append("read")
                    return after()
                yield read
        edges.stack.enter_context(mock.patch.object(output.PilotOutputRequest, "hold", trace))

    def write_fixture(self):
        with self.file.open("xb") as destination:
            os.fchmod(destination.fileno(), 0o400)
            destination.write(b'{"total":3}')

    def run_worker(self):
        return self.f.run_worker(pilot_output=self.output)

    def test_reads_between_actual_start_and_release_only_after_terminal(self):
        result = self.run_worker()
        self.assertEqual(result["status"], "BOOTSTRAP_COMPLETE")
        ordered = ["absent", "START", "terminal", "read", "request_close", "provider_close", "RELEASE", "cleanup"]
        self.assertEqual([event for event in self.events if event in ordered], ordered)
        self.assertEqual(result["pilot_output_observation"]["payload_hex"], b'{"total":3}'.hex())
        self.assertEqual(result["pilot_output_observation"]["activation_id"], self.activation_id)
        self.assertEqual(os.fstat(self.fd).st_ino, self.descriptor["root_inode"])

    def test_preexisting_output_prevents_start_without_overwriting_or_retry(self):
        self.write_fixture()
        st = self.file.stat()
        result = self.run_worker()
        self.assertNotEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertNotIn("START", self.events)
        self.assertNotIn("read", self.events)
        self.assertEqual(self.events.count("cleanup"), 1)
        self.assertEqual(self.file.stat().st_ino, st.st_ino)

    def denied(self):
        result = self.run_worker()
        self.assertNotEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertIsNone(result.get("pilot_output_observation"))
        self.assertEqual([event for event in self.events if event in {"START","terminal","read","RELEASE","cleanup"}],
                         ["START","terminal","cleanup"])

    def test_recorded_block_cannot_trigger_positive_read(self):
        self.terminal["worker_result"]["broker_result"].update(verdict="BLOCK", effect_status="NOT_PERFORMED")
        self.denied()

    def test_no_tool_call_cannot_trigger_positive_read(self):
        self.tool_calls = 0
        self.denied()

    def test_uncertain_action_evidence_cannot_trigger_positive_read(self):
        self.terminal["action_evidence_uncertainty"] = "OWNER_RECORD_UNAVAILABLE_OR_INVALID"
        self.denied()

    def test_cancellation_after_start_preserves_original_exception_without_a_read(self):
        original = KeyboardInterrupt("cancelled inert fixture")
        self.f.r.read_bootstrap_result.side_effect = original
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.run_worker()
        self.assertIs(caught.exception, original)
        self.f.r.read_bootstrap_result.assert_called_once()
        self.assertEqual([event for event in self.events if event in {"START","read","RELEASE","cleanup"}],
                         ["START","cleanup"])
        self.assertFalse(self.file.exists())

    def test_release_failure_preserves_observation_without_resampling(self):
        send = self.send.side_effect
        def fail_release(connection, raw, deadline):
            send(connection, raw, deadline)
            if self.events[-1] == "RELEASE":
                raise OSError("fixture release failed")
        self.send.side_effect = fail_release
        result = self.run_worker()
        self.assertNotEqual(result["status"], "BOOTSTRAP_COMPLETE")
        self.assertIn("fixture release failed", result["failure"])
        self.assertEqual(result["pilot_output_observation"]["payload_hex"], b'{"total":3}'.hex())
        self.assertEqual([event for event in self.events if event in {"START","terminal","read","RELEASE","cleanup"}],
                         ["START","terminal","read","RELEASE","cleanup"])
