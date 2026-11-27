"""Retained release bytes; inert syscall records. No worker, VM or live evidence."""
from copy import deepcopy
from functools import cache
import json
from pathlib import Path
import signal
from unittest import TestCase, mock

from aragorn import pi_core_task_entry_replay as replay
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_node_source_replay as fixture
from tests import test_pi_core_task_exec_event as producer


@cache
def entrypoint():
    build = Path(__file__).resolve().parents[1] / "packaging/pi-core/task-worker-v1/build.json"
    raw = (Path.home() / "Library/Application Support/Aragorn-Task-Guest-v1-Offline/root/var/lib/aragorn/"
          "pi-task-runtime/pi-core/entrypoint.js").read_bytes()
    return raw,json.loads(build.read_bytes())["outputs"]


class StaticEntryReplayTests(TestCase):
    def setUp(self):
        f = self.f = fixture.NodeReplayTests()
        self.addCleanup(f.doCleanups)
        f.setUp()
        r,b = f.record,f.record["bindings"]
        raw,outputs = entrypoint()
        size = len(raw)
        f.source["digest"],f.source["identity"]["size"] = f.put(raw),size
        self.assertEqual(outputs["entrypoint.js"],dict(bytes=size,sha256=f.source["digest"][7:]))
        b["node_digest"] = "sha256:b4855de8c4781130b722ceaec9718fed77cca3eed2e5cfc5455e267c0b9ee3b0"
        b["gate_digest"] = "sha256:"+outputs["source-gate"]["sha256"]
        w,events = r["worker"],r["events"]
        w.update(unit="aragorn-pi-task-worker.service",cgroup="/system.slice/aragorn-pi-task-worker.service")
        f.arguments["expected_worker"] = deepcopy(w)
        events[8]["digest"] = b["node_digest"]
        events[12]["args"][2] = events[14]["count"] = events[16]["result"] = events[18]["result"] = size
        events[14]["digest"] = f.source["digest"]
        f.repin_inventories()
        f.recount()
        gate_path,node_path,entry = "/opt/aragorn/pi-runtime/observer/source-gate", "/opt/aragorn/pi-runtime/node/bin/node", f.source["path"]
        argv = b"\0".join((node_path.encode(),b"--disallow-code-generation-from-strings",entry.encode(),b""))
        gate = dict(identity=f.arguments["expected_gate_identity"],digest=b["gate_digest"])
        node = dict(identity=f.identity(5,524288,0o100555),digest=b["node_digest"])
        unit = "/usr/lib/systemd/system/"+w["unit"]
        self.binding = dict(schema="aragorn/static-task-source-binding/v1", observation="STOPPED_BINDING_ONLY",
             claim_digest=canonical_digest("claim"),ticket_digest=canonical_digest("ticket"),
             worker=deepcopy(w),clock=r["clock"],node_argv_hex=argv.hex(),gate_argv_hex=(gate_path.encode()+b"\0"+argv).hex(),
             files={gate_path:gate,node_path:node,entry:{k:f.source[k] for k in ("identity","digest")},
                    unit:dict(identity=f.identity(8,200),digest="sha256:136338c6b771a8081a26fb5098a3551ae73b6537bf29971d75bec60cd2540618")})
        def site(name,phase):
            pc = 0x210524 if name=="first" else 0x21054c
            return dict(site=name,phase=phase,worker=deepcopy(w),clock=r["clock"],gate_digest=gate["digest"],
                       gate_identity=gate["identity"],instruction_pointer=pc,file_offset=pc-0x210000,syscall_number=-1,
                       mapping_raw_hex=b"00210000-00211000 r-xp 00000000 00:01 2 /gate\n".hex(),
                       syscall_raw_hex=f"-1 0xfff0 {pc:#x}\n".encode().hex())
        self.auth = dict(schema="aragorn/static-task-gate-order/v1", claim_digest=self.binding["claim_digest"],
             binding_digest=canonical_digest(self.binding),node_argv_hex=argv.hex(),first=site("first","stopped"),
             after_publication=site("first","stopped"),final=site("final","stopped"),pre_exec=site("final","traced-gate"))
        self.exec = dict(schema="aragorn/static-task-node-exec/v1",authorization_digest=canonical_digest(self.auth),
             wait=dict(signo=17,code=4,status=1029,pid=w["pid"],uid=w["uid"],former_tid=w["pid"]),
             node=dict(worker=deepcopy(w),clock=r["clock"],tracer_tid=790,node_argv_hex=argv.hex(),
                       node_digest=node["digest"],node_identity=node["identity"]))
        self.link = dict(schema="aragorn/static-task-consumed-exec/v1",exec_digest=canonical_digest(self.exec),
                         stop_seq=events[7]["seq"],stop_digest=canonical_digest(events[7]))

    def verify(self):
        f = self.f
        raw = canonical_json(f.record)
        pins = {k:f.put(canonical_json(v)) for k,v in zip(
            ("binding_digest","authorization_digest","exec_digest","transition_digest"),
            (self.binding,self.auth,self.exec,self.link))}
        return replay.verify_task_entry_read(raw,expected_observation_digest=f.put(raw),**pins,**f.arguments)

    def test_complete_recorded_read_of_pinned_static_entry(self):
        # Use the actual protected wait adapter and original event emitter at the replay boundary.
        p = producer.TaskExecEventTests()
        self.addCleanup(p.doCleanups)
        p.setUp()
        w,events = self.binding["worker"],self.f.record["events"]
        p.pid,p.uid,p.ticks = w["pid"],w["uid"],w["start_ticks"]
        p.held._record["worker"] = {k:v for k,v in w.items() if k!="cgroup"}
        p.s.tasks = {p.pid:dict(joined=True,stopped=False,start_ticks=p.ticks)}
        p.o._worker,p.o._events = p.held.worker,deepcopy(events[:7])
        p.o._kernel.message.return_value = p.pid
        p.receipt = self.exec
        with mock.patch.object(signal,"SIGCHLD",17),mock.patch.object(producer.base,"_tick",return_value=80):
            handler = producer.fixed.install_task_exec_handler(p.task,p.o)
            self.assertTrue(p.s._wait_one(p.pid))
            self.link = handler.consumed(p.o)
        self.assertEqual(p.order,["peek","check","take"])
        events[7] = p.o._events[-1]
        result = self.verify()
        self.assertEqual(result["status"],"CONSISTENT_RECORDED_STATIC_ENTRY_DELIVERY")
        self.assertEqual(result["entrypoint_digest"],self.f.source["digest"])
        self.assertEqual(result["entrypoint_bytes"],398741)
        self.assertFalse(result["phase3_qualified"])
        self.assertFalse(result["acquisition_authenticity_verified"])

    def test_one_byte_gap_refuses_despite_matching_syscall_counts(self):
        f = self.f
        start,enter,end,exit_ = (f.record["events"][i] for i in (12,14,16,18))
        start["args"][3] = enter["offset"] = 1
        start["args"][2] = enter["count"] = end["result"] = exit_["result"] = enter["count"]-1
        f.recount()
        with self.assertRaisesRegex(ValueError,"GAP|INCOMPLETE"): self.verify()

    def test_same_bytes_read_from_substituted_file_refuse_even_if_trace_is_consistent(self):
        f = self.f
        old = f.source["identity"]
        f.source["identity"] = old | {"inode":old["inode"]+100}
        for i in (14,18): f.record["events"][i]["identity"] = f.source["identity"]
        f.repin_inventories()
        with self.assertRaisesRegex(ValueError,"ENTRY_IDENTITY"): self.verify()

    def test_same_pid_in_different_invocation_and_swapped_consumed_stop_refuse(self):
        f = self.f
        f.record["worker"]["invocation_id"] = "9"*32
        f.arguments["expected_worker"] = deepcopy(f.record["worker"])
        with self.assertRaisesRegex(ValueError,"WORKER"): self.verify()
        f.record["worker"] = deepcopy(self.binding["worker"])
        f.arguments["expected_worker"] = deepcopy(f.record["worker"])
        self.link["stop_digest"] = canonical_digest(f.record["events"][1])
        with self.assertRaisesRegex(ValueError,"EXEC_STOP"): self.verify()

    def test_summary_or_duplicate_consumed_event_cannot_replace_raw_read_evidence(self):
        f = self.f
        original = f.record
        f.record = dict(status="PASS",bytes_read=398741)
        with self.assertRaises(ValueError): self.verify()
        f.record = original
        f.record["events"].insert(8,deepcopy(f.record["events"][7]))
        with self.assertRaises(ValueError): self.verify()
