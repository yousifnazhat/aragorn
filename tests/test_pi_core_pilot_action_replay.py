"""Private, inert B31/B77 originals; no worker, broker, device or real effect."""
import base64
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from unittest import TestCase, TestSuite
from unittest.mock import patch

from aragorn import pi_core_action_evidence as producer
from aragorn import runtime_active_skill_lineage as lineage
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import verify_pi_core_retained_action as cli
from tests import test_pi_core_action_boundary_verify as boundaries, test_pi_core_action_evidence as actions
from tests.test_pi_core_service_configuration import configurations


class PilotActionReplay(TestCase):
    def setUp(self):
        boundary = boundaries.ActionBoundaryReplayTests()
        boundary.setUp()
        self.addCleanup(boundary.doCleanups)
        self.node = boundary.f
        self.put = self.node.put
        self.readonly = CAS(self.node.cas.root, read_only=True)
        self.sources = boundary.args["source_expectations"]

    def original(self, outcome="created", *, public_pilot_call_id=None, public_pilot_policy_digest=None):
        fixture = actions.NativeActionEvidenceTests()
        grant, submission = actions.fixtures._grant(), actions.fixtures._submission()
        worker, pins = self.sources["expected_worker"], self.sources["expected_bindings"]
        configs = configurations()
        donor_options = {}
        if public_pilot_call_id is not None:
            review = json.loads((Path(__file__).resolve().parents[1] /
                                 "benchmark/pi-core-pilot-v1/review.json").read_bytes())
            payload = canonical_json({"total":sum(review["inputs"])})
            self.assertEqual((len(payload), "sha256:" + sha256(payload).hexdigest()),
                             (review["expected_payload_bytes"], review["expected_payload_digest"]))
            grant.update(source_manifest_digest="sha256:e6de9001bdd41e7908d0b9097798d1ab8ae13037c4ad1a7dbceb4cea985ad77f",
                         active_skill_digest=review["skill_digest"])
            submission["envelope"]["effect"].update(target_name=review["target_name"],
                                                    payload_base64=base64.b64encode(payload).decode("ascii"))
            submission["runtime_attribution"]["active_skill_digest"] = grant["active_skill_digest"]
            if public_pilot_policy_digest is not None:
                grant["policy_digest"] = submission["envelope"]["request"]["policy_digest"] = public_pilot_policy_digest
            for row in (submission["envelope"]["request"], submission["measured_action"]):
                row["active_skill_digest"] = grant["active_skill_digest"]
            donor_options.update(tool_call_digest="sha256:"+sha256(public_pilot_call_id.encode("utf-8")).hexdigest(),
                                 tree_digest=review["tree_digest"])
        else:
            self.assertIsNone(public_pilot_policy_digest, "a public pilot policy needs the selected call ID")
        process_profile = configs["sensor"]["observation_binding"]["runtime_profile"]
        version = ".aragorn-versions/example/" + "9"*64 + "-" + grant["source_manifest_digest"][7:]
        process_profile.update(runtime_digest=pins["runtime_digest"], executable_digest=pins["node_digest"],
                               cgroup=worker["cgroup"], skill_path="/var/lib/aragorn/admitted/"+version+"/SKILL.md")
        grant.update(runtime_profile_digest=canonical_digest(process_profile), runtime_digest=pins["runtime_digest"])
        submission["runtime_peer"] = {k:worker[k] for k in ("pid","uid","gid")}
        measured = submission["runtime_attribution"]
        measured.update(submission["runtime_peer"], start_time_ticks=worker["start_ticks"],
                        profile_digest=canonical_digest(process_profile),
                        **{k:process_profile[k] for k in ("skill_path","runtime_digest","executable_digest","cgroup")})
        for row in (submission["envelope"]["request"],submission["measured_action"]):
            row["runtime_digest"] = pins["runtime_digest"]
        try:
            with patch.object(actions.fixtures, "_grant", return_value=grant), \
                    patch.object(actions.fixtures, "_submission", return_value=submission):
                fixture.setUp(**donor_options)
            a = fixture.activation
            a.update(boot_id=self.sources["expected_clock"]["boot_id"], deployment_digest=pins["deployment_digest"])
            fixture.custody._activation = deepcopy(a)
            for doc in configs.values():
                doc["identities"].update(action=dict(uid=2201,gid=2202), worker={k:worker[k] for k in ("uid","gid")})
                if "capability_grant" in doc:
                    doc["capability_grant"] = deepcopy(grant)
            configs["action"]["runtime_binding"].update(runtime_digest=grant["runtime_digest"],
                                                       runtime_profile_digest=grant["runtime_profile_digest"])
            fixture.life.configuration.configurations = configs
            fixture.set_receipt(outcome)
            fixture.context.update(measurement=measured, lineage=dict(schema=lineage.VERIFIED_LINEAGE_SCHEMA,
                authority=lineage.VERIFIED_LINEAGE_AUTHORITY, context_digest=a["install_context_digest"],
                manifest_digest=a["source_manifest_digest"], tree_digest=a["tree_digest"],
                active_record_digest=a["active_record_digest"], active_skill_digest=a["active_skill_digest"],
                version_path=version, target_name="example", runtime_skill_path=process_profile["skill_path"],
                root_device=1, root_inode=11, active_link_device=1, active_link_inode=12,
                version_device=1, version_inode=13, skill_device=1, skill_inode=14))
            tick = self.node.record["events"][-1]["boottime_ns"]
            with producer.hold_native_action_evidence(fixture.custody) as owner:
                raw = canonical_json(fixture.request)
                frame = dict(schema="aragorn/pi-core-action-frame/v1",
                    header_base64=base64.b64encode(producer.broker._FRAME_HEADER.pack(len(raw))).decode("ascii"),
                    body_base64=None, body_complete=False, eof_verified=False, parsed=False)
                owner.retain("REQUEST_FRAME", frame)
                owner.retain("REQUEST_FRAME", frame | dict(body_complete=True, body_base64=base64.b64encode(raw).decode("ascii")))
                owner.retain("REQUEST_CONTEXT", fixture.context)
                fields = {k:fixture.done[k] for k in ("nonce","activation_digest","request_digest","deadline_ns")}
                check = producer.handoff._packet("CHECK", terminal_ack=True, sequence=1, **fields)
                current = check | {"kind":"CURRENT"}
                with patch.object(producer, "_time_namespace_inode", return_value=self.sources["expected_clock"]["time_namespace_inode"]), \
                        patch.object(producer,"_boottime_ns", side_effect=[tick+i for i in (1,2,3,4)]), \
                        patch.object(producer.time,"monotonic_ns",return_value=1):
                    owner.retain("CHECK", check)
                    owner.prepare_current(check, current, lambda:self.node.record)
                    owner.before_current_send(current)
                    owner.current_send_returned(current)
                owner.complete(done=fixture.done, sensor_done=fixture.sensor_done, result=fixture.result)
            self.owner = owner.observation
            self.records = deepcopy(fixture.store.values)
            self.activation, self.request = deepcopy(a), deepcopy(fixture.request)
            self.nonce, self.deadline = fields["nonce"], fields["deadline_ns"]
        finally:
            fixture.doCleanups()  # Restore the donor's OS-denial mocks before accessing the temporary CAS.
        self.config_pin = self.put(canonical_json(configs))
        self.assertEqual(self.owner["configuration_digest"], self.config_pin)
        values = dict(self.records)
        self.selection = dict(check_digest=canonical_digest(check), attempt_digest=canonical_digest(values["CURRENT_ATTEMPT"]),
                              observation_digest=self.put(canonical_json(self.node.record)), challenge=dict(self.node.challenge))
        self.summary = canonical_digest(values["CURRENT_SEND_SUMMARY"])

    def nomination(self, *, omit=None):
        header = dict(schema="aragorn/pi-core-action-evidence-index/v1", authority="DURABLE_REFERENCE_PREFIX_ONLY_NOT_COMPLETED_CAPTURE",
                      sequence=0,kind="HEADER",activation_id=self.activation["activation_id"],
                      activation_digest=canonical_digest(self.activation))
        raw = canonical_json(header) + b"\n"
        refs = []
        for seq, (kind, value) in enumerate(self.records, 1):
            blob = canonical_json(value)
            ref = dict(kind=kind, digest=canonical_digest(value) if kind == omit else self.put(blob), bytes=len(blob))
            refs.append(ref)
            raw += canonical_json(dict(schema="aragorn/pi-core-action-evidence-reference/v1", sequence=seq,
                                  previous_prefix_digest="sha256:"+sha256(raw).hexdigest(), **ref)) + b"\n"
        index = self.put(raw)
        owner = deepcopy(self.owner)
        owner["retained_evidence"].update(index_digest=index,index_bytes=len(raw),references=refs)
        sources = dict(self.sources)
        for k in ("expected_profile_raw","loader_inventory_raw","source_inventory_raw"):
            sources[k] = self.put(sources[k])
        return dict(schema="aragorn/pi-core-retained-action-nomination/v1", owner_digest=self.put(canonical_json(owner)),
                    index_digest=index,grant_digest=owner["grant_digest"],configuration_digest=self.config_pin,
                    activation_digest=self.put(canonical_json(self.activation)),request_digest=self.put(canonical_json(self.request)),
                    broker_nonce=self.nonce,deadline_ns=self.deadline,summary_digest=self.summary,
                    selections=[self.selection],source_expectations=sources)

    def replay(self, nomination):
        return cli.replay(self.readonly, self.put(canonical_json(nomination)))

    def test_terminal_create_and_effective_block_stay_recorded_not_physical(self):
        for outcome, expected in (("created",("ALLOW","CREATED")),("effective",("BLOCK","NOT_PERFORMED"))):
            with self.subTest(outcome=outcome):
                self.original(outcome)
                report = self.replay(self.nomination())
                self.assertEqual((report["recorded_verdict"],report["recorded_effect_status"]),expected)
                self.assertIs(report["terminal_records_matched"],True)
                for key in ("effect_verified","timing_verified","sensor_health_verified","phase3_qualified"):
                    self.assertIs(report[key],False)

    def test_resealed_sensor_terminal_from_another_result_refuses(self):
        self.original()
        dict(self.records)["SENSOR_DONE"]["broker_result_digest"] = canonical_digest("different result")
        with self.assertRaises(ValueError):
            self.replay(self.nomination())

    def test_failure_prefix_cannot_claim_created_or_blocked(self):
        self.original()
        self.records = self.records[:3] + [("FAILURE",{"schema":"aragorn/pi-core-action-failure/v1"})]
        with self.assertRaises(ValueError):
            self.replay(self.nomination())

    def test_resealed_owner_and_index_do_not_authorize_a_broken_prefix_link(self):
        self.original()
        nominal = self.nomination()
        lines = self.readonly.read(nominal["index_digest"]).splitlines(keepends=True)
        terminal = json.loads(lines[-1])
        terminal["previous_prefix_digest"] = canonical_digest("foreign prefix")
        raw = b"".join(lines[:-1]) + canonical_json(terminal) + b"\n"
        nominal["index_digest"] = self.put(raw)
        owner = json.loads(self.readonly.read(nominal["owner_digest"]))
        owner["retained_evidence"].update(index_digest=nominal["index_digest"], index_bytes=len(raw))
        nominal["owner_digest"] = self.put(canonical_json(owner))
        with self.assertRaisesRegex(ValueError,"ACTION_INDEX_REFERENCE_CHAIN"):
            self.replay(nominal)

    def test_configured_action_principal_must_own_the_locked_readback(self):
        self.original()
        nominal = self.nomination()
        configs = json.loads(self.readonly.read(nominal["configuration_digest"]))
        for doc in configs.values():
            doc["identities"]["action"]["gid"] += 1
        nominal["configuration_digest"] = self.put(canonical_json(configs))
        owner = json.loads(self.readonly.read(nominal["owner_digest"]))
        owner["configuration_digest"] = nominal["configuration_digest"]
        nominal["owner_digest"] = self.put(canonical_json(owner))
        with self.assertRaises(ValueError):
            self.replay(nominal)

    def test_independently_nominated_current_summary_and_grant_cannot_be_replaced(self):
        self.original()
        good = self.nomination()
        for k in ("grant_digest","index_digest","configuration_digest","summary_digest","owner_digest"):
            with self.subTest(k=k), self.assertRaises((ValueError, CASError)):
                self.replay(good | {k:good["request_digest"]})

    def test_missing_original_result_refuses_despite_valid_index_and_other_receipts(self):
        self.original()
        with self.assertRaises(CASError):
            self.replay(self.nomination(omit="ACTION_RESULT"))


def load_tests(loader, tests, pattern):
    return TestSuite((loader.loadTestsFromTestCase(PilotActionReplay), boundaries.ActionBoundaryReplayTests(
        "test_actual_producer_envelopes_are_accepted_by_independent_reader")))
