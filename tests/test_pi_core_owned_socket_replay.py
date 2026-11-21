"""Inert original-byte CAS fixtures for B81. No processes, sockets or device access."""
from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest

from aragorn import pi_core_restricted_profile as profile
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest as pin, canonical_json
from aragorn.phase3_deployment import BINDING_DIMENSIONS
from aragorn.runtime_process_profile import PROFILE_AUTHORITY, PROFILE_SCHEMA
from scripts import verify_pi_core_owned_socket_directories as readback
from test_pi_core_coordinator_entry import prepared
from test_pi_core_owned_socket_directories import sample_socket_edge


BOOT = "12345678-1234-4234-8234-123456789abc"
INV = "1234567890abcdef1234567890abcdef"
UNIT = "aragorn-pi-" + "3" * 32 + ".service"


class OwnedSocketReplay(unittest.TestCase):
    def put(self, obj, stdout=False):
        raw = canonical_json(obj) + (b"\n" if stdout else b"")
        return self.store.put(BytesIO(raw), max_bytes=len(raw))

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.store = CAS(Path(temp.name) / "private")
        self.archive = CAS(self.store.root, read_only=True)
        self.plan, docs = prepared(protected=True)
        self.launch = docs[self.plan["launch"]["path"]]
        gate = json.loads((Path(__file__).parent / "fixtures/pi_core_b36_gate_receipt.json").read_bytes())
        gate["receipt_digest"] = "sha256:" + profile.GATE_RECEIPT_SHA256
        receipt = profile.runtime_receipt(gate)
        self.launch.update(compiled_receipt=receipt, compiled_receipt_digest=pin(receipt))
        self.launch["worker_gid"] = 1002
        self.profile = self.launch["source_observation"]
        entry = {"path":profile.ENTRY_PATH, "digest":"sha256:"+profile.BUNDLE_SHA256}
        self.profile.update(schema=profile.PROFILE_SCHEMA, sources=[entry], required_sources=[entry["path"]])
        self.profile["pins"].update(gate_digest="sha256:"+profile.GATE_SHA256, node_digest="sha256:"+profile.NODE_SHA256,
            producer_digest=pin("/opt/aragorn/src/aragorn/pi_core_source_observer.py"),
            node_observer_digest=pin("/opt/aragorn/src/aragorn/pi_core_node_source_observer.py"))
        self.profile_pin = self.launch["source_observation_digest"] = pin(self.profile)
        self.plan["launch"]["digest"] = self.put(self.launch)
        self.deployment = self.put({k:profile.RUNTIME_DIGEST if k == "runtime_commit_or_image" else pin(k)
                                    for k in BINDING_DIMENSIONS})
        self.plan["deployment"]["digest"] = self.deployment
        self.configs = {"action":{"identities":{"worker":{"uid":1001,"gid":1002}}},
                        "sensor":{"observation_binding":{"runtime_profile":dict(schema=PROFILE_SCHEMA,
                           authority=PROFILE_AUTHORITY,cgroup="/system.slice/"+UNIT,runtime_digest=profile.RUNTIME_DIGEST,
                           executable_digest="sha256:"+profile.NODE_SHA256,skill_path="/var/lib/aragorn/admitted/test/SKILL.md")}}}
        self.plan["service_configuration"]["configurations"]["digest"] = self.put(self.configs)
        host = readback.host_contract
        names = ["aragorn", *sorted(readback._MODULES)]
        src = ["opt/aragorn/src/" + (n.replace(".", "/") + ("/__init__.py" if i == 0 else ".py"))
               for i,n in enumerate(names)]
        py, std = "/usr/bin/python3.12", "/usr/lib/python3.12"
        all_files = {*(Path("/"+p) for p in src), *host._TOOLS, host._WRAPPER, host._LOADER, Path(py)}
        self.host_pin = self.plan["host_profile_digest"] = self.put(dict(schema="aragorn/pi-core-coordinator-host/v1",
            target="linux-arm64-cpython312",python_executable=py,wrapper_path=str(host._WRAPPER),stdlib_roots=[std],
            sys_path=[std],absent_sys_path=[],files=[dict(path=str(p),digest=pin(str(p)),size=20) for p in sorted(all_files)]))
        hostframe = dict(schema="aragorn/pi-core-coordinator-host-observation/v1",
            authority="PINNED_HOST_TCB_ONLY_NOT_CONSUMED_CODE_OR_PHASE3",host_profile_digest=self.host_pin,pid=123,
            python_executable=py,files=len(all_files),phase3_exit_eligible=False)
        consumed = [dict(module=m,path=p,digest=pin("/"+p)) for m,p in zip(names,src)]
        self.owner = dict(schema="aragorn/pi-core-coordinator-report/v1",authority="MANAGED_RESULT_DIGEST_ONLY_NOT_RAW_EFFECT_EVIDENCE",
            status="MANAGED_BOOTSTRAP_RETURNED_NOT_QUALIFIED",entry_status="MANAGED_CALL_RETURNED_NOT_QUALIFIED",
            wrapper_stage="POST_CALL_CUSTODY",entry_failure_stage=None,phase3_exit_eligible=False,
            entry_call_attempted=True,managed_call_attempted=True,managed_cleanup_complete=True,owned_inputs_closed=True,
            managed_status="BOOTSTRAP_COMPLETE",wrapper_cleanup={"host":"CLOSED","source_loader":"CLOSED"},
            host_before=hostframe,host_after=deepcopy(hostframe),source_before=consumed[:2],source_after=consumed,
            deployment_digest=self.deployment)
        worker = dict(pid=456,start_ticks=77,uid=1001,gid=1002,cgroup="/system.slice/"+UNIT,unit=UNIT,invocation_id=INV)
        clock = dict(boot_id=BOOT,clock_id="CLOCK_BOOTTIME",time_namespace_inode=901)
        self.members = dict(schema="aragorn/pi-core-manager-socket-membership/v1",status="MATCHED_MANAGER_MEMBERSHIP_ONLY",
            deployment_digest=self.deployment,source_profile_digest=self.profile_pin,immutable_launch_digest=pin("launch"),
            worker=worker,clock=clock,before_start=sample_socket_edge(),gate_stop_seq=2,
            stopped=sample_socket_edge(opened_boottime_ns=1030,closed_boottime_ns=1040))
        self.events = [
            dict(kind="ARMED",tasks=[456],options=readback.OPTIONS,
                 gate_identity=dict(device=8,inode=12,mode=0o100555,nlink=1,uid=0,gid=0,size=profile.GATE_BYTES,
                                    mtime_ns=0,ctime_ns=1)),
            dict(kind="STOP",op="NONE",pid=456,start_ticks=77,event=128,status=(128<<16)|(19<<8)|127),
            dict(kind="ALL_STOP",tasks=[dict(pid=456,start_ticks=77)],stop_seqs=[2],epoch=1),
            dict(kind="STDIO",epoch=1), dict(kind="RESUME",pid=456,start_ticks=77,request="SYSCALL"),
            dict(kind="CLEANUP",pid=456,status="EXIT_OBSERVED")]
        for n, (e,t) in enumerate(zip(self.events,(1012,1015,1020,1021,1042,1100)),1):
            e.update(seq=n,boottime_ns=t)
        self.capture = dict(schema="aragorn/pi-core-node-source-observation/v2",architecture="linux-arm64",state="CLOSED",
            worker=deepcopy(worker),clock=deepcopy(clock),events=self.events,bindings=dict(self.profile["pins"],
            deployment_digest=self.deployment,runtime_digest=profile.RUNTIME_DIGEST,profile_digest=self.profile_pin))
        cleanup = {key:True for key in ("unit_absent","process_exit_observed","cgroup_empty_or_absent",
                                         "activation_withdrawn","socket_removed","directory_removed")}
        self.native = dict(schema="aragorn/pi-core-native-supervisor-result/v1",
            authority="BOOTSTRAP_AND_OWNED_CLEANUP_ONLY_NOT_EFFECT_RUN_OR_PHASE3_QUALIFICATION",status="BOOTSTRAP_COMPLETE",
            pid=456,start_time_ticks=77,unit=UNIT,invocation_id=INV,immutable_launch_digest=pin("launch"),failure=None,
            cleanup=dict(status="VERIFIED_OWNED_CLEANUP",**cleanup),request_channel=dict(cleanup="VERIFIED_OWNED_REQUEST_CLEANUP"),
            provider_channel=dict(cleanup="VERIFIED_OWNED_PROVIDER_CLEANUP"),identity_registration=dict(status="REVOKED"),
            activation_digest=pin("activation"),bootstrap=dict(schema="aragorn/pi-core-bootstrap-observation/v1",
                activation_digest=pin("activation"),authority="BOOTSTRAP_STATUS_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY",
                release_sent=True,result={"schema":"aragorn/pi-core-bootstrap-result/v2"}),
            source_observation=dict(closed=True,capture=self.capture,profile_digest=self.profile_pin,
                authority="SOURCE_ACQUISITION_ONLY_NOT_V8_EXECUTION_OR_PHASE3_QUALIFICATION"),
            owned_socket_directories=self.members)
        self.managed = dict(schema="aragorn/pi-core-managed-bootstrap-result/v1",
            authority="SERVICE_AND_WORKER_BOOTSTRAP_ONLY_NOT_USEFUL_TASK_OR_PHASE3",status="BOOTSTRAP_COMPLETE",
            provider_configured=True,provider_available=False,useful_task_verified=False,loaded_code_verified=False,
            phase3_exit_eligible=False,worker=self.native,services=dict(schema="aragorn/pi-core-service-lifecycle/v1",
                status="CLOSED",provider_mode="CONTROLLED_CREDENTIAL_FIXED_ADDRESS",
                phase3_exit_eligible=False,cleanup=dict(status="VERIFIED_OWNED_CLEANUP")))

    def args(self):
        plan, managed = self.put(self.plan), self.put(self.managed)
        self.owner.update(plan_digest=plan, managed_result_digest=managed)
        return dict(plan_pin=plan,owner_pin=self.put(self.owner,True),managed_pin=managed,
                    boot_id=BOOT,invocation_id=INV,deployment_pin=self.deployment)

    def read(self, **changes):
        return readback.verify_socket_directories(self.archive, **(self.args() | changes))

    def test_verified_originals_report_only_manager_membership(self):
        finding = self.read()
        self.assertTrue(finding["manager_socket_membership_observed"] and finding["stopped_window_joined"])
        for k in ("worker_lookup_observed","worker_listing_observed","listener_readiness_observed",
                  "worker_connection_verified","local_full_namespace_walk_observed","activation_authorized","phase3_exit_eligible"):
            self.assertIs(finding[k], False, k)

    def test_independent_attempt_and_deployment_pins_cannot_be_replaced(self):
        for field,value in (("boot_id",BOOT.replace("8","9")),("invocation_id","9"*32),("deployment_pin",pin("other"))):
            with self.subTest(field=field), self.assertRaises((ValueError,RuntimeError)):
                self.read(**{field:value})

    def test_self_consistent_but_changed_gate_build_is_not_the_frozen_runtime(self):
        receipt = self.launch["compiled_receipt"]
        receipt["inputs"]["source_gate"]["elf_sha256"] = "0"*64
        self.launch["compiled_receipt_digest"] = pin(receipt)
        self.plan["launch"]["digest"] = self.put(self.launch)
        with self.assertRaisesRegex(ValueError, "unapproved gate"):
            self.read()

    def test_public_digest_summary_or_missing_private_original_is_not_evidence(self):
        with self.assertRaises(CASError):
            self.read(managed_pin=pin("not retained"))
        with self.assertRaises((ValueError,RuntimeError)):
            self.read(managed_pin=self.put({"manager_socket_membership_observed":True}))

    def test_legacy_missing_locally_captured_directory_evidence_refuses(self):
        self.native.pop("owned_socket_directories")
        with self.assertRaises((ValueError,KeyError)):
            self.read()

    def test_clean_wrapper_cannot_hide_native_or_service_cleanup_hold(self):
        for obj,key in ((self.managed["services"],"status"),(self.native["provider_channel"],"cleanup"),
                        (self.native["request_channel"],"cleanup"),(self.owner["wrapper_cleanup"],"host")):
            original = obj[key]
            with self.subTest(key=key), self.assertRaises((ValueError,RuntimeError)):
                obj[key] = "CLEANUP_HOLD"
                self.read()
            obj[key] = original

    def test_replaced_host_source_registration_refuses(self):
        self.owner["source_after"][-1]["digest"] = pin("foreign module")
        with self.assertRaises((ValueError, RuntimeError)):
            self.read()

    def test_valid_record_bound_to_other_configured_cgroup_refuses(self):
        self.configs["sensor"]["observation_binding"]["runtime_profile"]["cgroup"] = "/system.slice/other.service"
        self.plan["service_configuration"]["configurations"]["digest"] = self.put(self.configs)
        with self.assertRaises((ValueError,RuntimeError)):
            self.read()

    def test_principal_or_process_cannot_be_swapped(self):
        self.members["worker"]["gid"] += 1
        with self.assertRaises((ValueError,RuntimeError)):
            self.read()
        self.members["worker"]["gid"] -= 1
        self.capture["worker"]["start_ticks"] += 1
        with self.assertRaises((ValueError,RuntimeError)):
            self.read()

    def test_forged_or_later_gate_stop_and_sampling_outside_stop_refuse(self):
        for obj,key,value in ((self.members,"gate_stop_seq",3),(self.events[1],"event",0),
                              (self.events[0]["gate_identity"],"size",1),(self.events[3],"epoch",2),
                              (self.events[4],"boottime_ns",1039),(self.events[2],"stop_seqs",[3])):
            old = obj[key]
            with self.subTest(key=key), self.assertRaises((ValueError,RuntimeError)):
                obj[key] = value
                self.read()
            obj[key] = old

    def test_both_manager_edges_must_come_from_outer_host_and_worker_clock(self):
        for field,v in (("manager_pid",124),("time_namespace_inode",902),("boot_id",BOOT.replace("8","9"))):
            self.members["before_start"] = sample_socket_edge(**{field:v})
            self.members["stopped"] = sample_socket_edge(opened_boottime_ns=1030,closed_boottime_ns=1040,**{field:v})
            with self.subTest(field=field), self.assertRaises((ValueError,RuntimeError)):
                self.read()

    def test_corrupt_stopped_directory_or_unconfirmed_outcome_refuses(self):
        self.members["stopped"]["directories"]["request"]["names"].append("other")
        with self.assertRaises((ValueError,RuntimeError)):
            self.read()
        self.members["status"] = "INCOMPLETE_OR_UNVERIFIED_LIFETIME"
        self.members["stopped"] = sample_socket_edge(opened_boottime_ns=1030,closed_boottime_ns=1040)
        with self.assertRaises((ValueError,RuntimeError)):
            self.read()
