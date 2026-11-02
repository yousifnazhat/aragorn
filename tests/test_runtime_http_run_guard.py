"""Finite renderer/caller tests; no installed-closure or native-operation claim.

Only seven frozen originals, the actual report and the explicitly listed source
fixtures are read. Generated definitions run with named boundary mocks. The
synthetic dependency map is NOT Root's pending final installation inventory.
No historical test or materializer is imported/executed.
"""

import ast
import copy
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace as NS
import unittest

from scripts import materialize_runtime_http_run_guard as renderer


ROOT = Path(__file__).resolve().parents[1]
EXTRA_INPUTS = (
    "src/aragorn/runtime_http_action.py",
    "scripts/materialize_runtime_http_credentials.py",
    "src/aragorn/native_phase3_http_canary_contract.py",
    "src/aragorn/runtime_broker_effective_receipt_verify.py",
)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def require(value, message="refused"):
    if not value:
        raise ValueError(message)


def fixture_change(raw, before, after):
    a, b = before.encode("ascii"), after.encode("ascii")
    require(raw.count(a) == 1 and b not in raw)
    result = raw.replace(a, b)
    require(result.replace(b, a) == raw)
    return result


def repaired_action(original, constants_raw, report):
    """Read one literal constant as data; never import/call the old renderer."""
    literals = [node.value for node in ast.parse(constants_raw).body
                if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "_SERVICE_READER"
                        for target in node.targets)]
    require(len(literals) == 1)
    service_reader = ast.literal_eval(literals[0])
    raw = fixture_change(original, "from . import runtime_process_profile as process\n",
                         "from contextlib import contextmanager\n")
    raw = fixture_change(raw, "def load_fixture_binding():\n",
                         service_reader + "def load_provisioned_fixture_binding():\n")
    for name, before, after in (
        ("load_provisioned_fixture_binding", "    descriptor = -1\n",
         '    _require(os.getresuid() == (0, 0, 0), "HTTP_BINDING_REFUSED")\n    descriptor = -1\n'),
        ("_read", "    return process._read_virtual_file(Path(path), limit)",
         "    from . import runtime_process_profile as process\n    return process._read_virtual_file(Path(path), limit)"),
    ):
        marker = ("def " + name + "(").encode()
        start = raw.index(marker)
        end = raw.find(b"\n\ndef ", start + len(marker))
        end = len(raw) if end < 0 else end
        part = raw[start:end]
        raw = fixture_change(raw, part.decode(), fixture_change(part, before, after).decode())
    raw = fixture_change(raw, "            self.start = process._process_start_time(self.pid)",
                         "            self.start = _process_start_time(self.pid)")
    raw = fixture_change(raw, "and process._process_start_time(self.pid) == self.start,",
                         "and _process_start_time(self.pid) == self.start,")
    row = next(item for item in report["files"] if item["source_name"] == renderer.PREFIX + "runtime_http_action.py")
    require(len(raw) == 30923 == row["bytes"] and renderer._pin(raw) == row["digest"]
            == "sha256:c9b8ba087dd9f302c648e7b1b68ea291ff29d7df88c54ac6eb603f4b7d1b68ad")
    return raw


class NoImports(ast.NodeTransformer):
    """Dependencies are explicit test boundaries, never silently project-imported."""

    def visit_Import(self, node):
        return None

    def visit_ImportFrom(self, node):
        return node if node.module == "__future__" else None


def definitions(raw, namespace, names=None):
    tree = ast.parse(raw)
    if names is not None:
        tree.body = [node for node in tree.body if
                     isinstance(node, ast.ImportFrom) and node.module == "__future__"
                     or isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
    else:
        tree.body = [node for node in tree.body if not isinstance(node, ast.If)]
    tree = NoImports().visit(tree)
    ast.fix_missing_locations(tree)
    namespace.setdefault("__name__", __name__)
    exec(compile(tree, "<reviewed-generated-unit-boundary>", "exec"), namespace)
    return namespace


class BrokerFailure(ValueError):
    pass


class Indeterminate(BrokerFailure):
    pass


class HttpFailure(ValueError):
    def __init__(self, reason, observation):
        self.reason, self.observation = reason, observation


class HttpIndeterminate(HttpFailure):
    pass


class ClientFailure(ValueError):
    def __init__(self, code="LOSS_UNAVAILABLE", *, cleanup=(), unresolved=None):
        self.failure_code = code
        self.cleanup_failures, self.unresolved_owner = cleanup, unresolved
        self.observed = {"actual_prefix": b"partial"}


class Caller:
    """Actual generated mediation; low-level policy/native/client boundaries fake."""

    def __init__(self, raw, *, begin_error=None, check_error=None, finish_error=None,
                 close_error=None, lock_error=None, codes=None, initial_block=False,
                 late_block=False, transport_cleanup_error=False):
        self.events, self.borrowed = [], (10, 13)
        self.request = {"policy_digest": "sha256:" + "1" * 64, "policy_version": 1}
        self.effect = {"schema": "aragorn/runtime-http-canary-effect/v1",
                       "operation": "http_canary_post", "attempt_id": "p3-lab-a001"}
        self.binding = dict(expected_broker_uid=901, expected_broker_gid=902)
        self.state = {"consumed": []}
        self.decision = dict(schema="aragorn/runtime-action-decision/v1",
                             authority="RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
                             request_digest=digest(self.request), verdict="ALLOW", reason_codes=[])
        self.observation = "sha256:" + "3" * 64
        self.policy_calls = 0
        self.transport = dict(status="NOT_PERFORMED", connect_attempted=False,
                              sent_bytes=0, response_bytes=0,
                              error_code="HTTP_AUTHORIZATION_REFUSED")
        self.guard = NS()
        self.guard.opening_result = {"ipc_raw": b"opening", "observed": {"raw": b"actual"}}

        def check():
            self.events.append("check")
            if check_error:
                raise check_error
            return dict(request_raw=b"request", response_raw=canonical(dict(status="REFUSED",
                        error_codes=codes if codes is not None else ["LOSS_UNAVAILABLE"])),
                        ipc_raw=b"checked", observed={"actual": b"response"})

        def finish(**kwargs):
            self.events.append(("finish", kwargs))
            if finish_error:
                raise finish_error
            return {"ipc_raw": b"finished", "observed": kwargs}

        def close():
            self.events.append("close")
            if close_error:
                raise close_error
            return {"ipc_raw": b"closed", "observed": {}}

        def begin(control, lock, config, **kwargs):
            self.events.append(("begin", control, lock, kwargs))
            require((control, lock) == self.borrowed)
            if begin_error:
                raise begin_error
            return self.guard

        self.guard.before_connect, self.guard.finish, self.guard.close = check, finish, close

        def evaluate(*args, **kwargs):
            self.policy_calls += 1
            self.events.append("policy")
            decision = dict(self.decision)
            if initial_block or late_block and self.policy_calls > 1:
                decision.update(verdict="BLOCK", reason_codes=["POLICY_REFUSED"])
            return self.state, self.observation, decision, []

        def release(*args):
            self.events.append("unlock")
            return lock_error

        def execute(effect, *, fixture_binding, deadline_monotonic, authorize_effect):
            self.events.append("http-execution-guard")
            try:
                allowed = authorize_effect()
            except BaseException as error:
                # Match the frozen transport's ordinary-exception replacement.
                if isinstance(error, Exception):
                    raise HttpFailure("HTTP_TRANSPORT_FAILED", self.transport) from None
                error.http_action_observation = self.transport
                raise
            self.events.append(("authorization", allowed))
            if not allowed:
                raise HttpFailure("HTTP_SOCKET_CLOSE_FAILED" if transport_cleanup_error else
                                  "HTTP_AUTHORIZATION_REFUSED", self.transport)
            self.events.append("CONNECT")
            raise AssertionError("refusal profile reached connect")

        broker = NS(RuntimeActionBrokerError=BrokerFailure, RuntimeActionEffectIndeterminate=Indeterminate,
                    _MAX_CONSUMED=128, _MAX_OBSERVATION_LIFETIME_SECONDS=10,
                    _validate_config=lambda c: None, _open_broker_roots=lambda c: (10, 11, 12),
                    _open_lock_file=lambda fd, c: 13, _acquire_lock=lambda *a: None,
                    _recover_effect_journal=lambda *a: None, _clock_value=lambda c: c(),
                    _evaluate_snapshot=evaluate, _commit_state=lambda *a: self.events.append("consumed"),
                    _release_lock_and_close=release)
        http = NS(MAX_SECONDS=0.5, load_fixture_binding=lambda: self.binding,
                  action_digests=lambda *a: {}, execute_http_effect=execute,
                  validate_result=lambda value, **kw: value,
                  RuntimeHttpActionError=HttpFailure, RuntimeHttpActionIndeterminate=HttpIndeterminate)
        self.os = NS(getpid=lambda: 701, getegid=lambda: 902)
        self.thread = NS(main_thread=lambda: NS(ident=11), get_ident=lambda: 11)
        self.module = definitions(raw, dict(os=self.os, threading=self.thread, json=json,
                         math=__import__("math"), sys=sys, time=NS(monotonic=lambda: 10.0),
                         broker=broker, http=http, _run_client=NS(begin_http_guard_locked=begin),
                         canonical_json=canonical, canonical_digest=digest,
                         measurement=NS(final_decision=lambda *args: self.events.append(("finalize", args)))))
        self.module.update(observed_submission=lambda s: {"envelope": {}},
                           request_effect=lambda e: (self.request, self.effect),
                           _publish_observation_locked=lambda *a: None)

    def call(self):
        return self.module["mediate_observed_http"]({}, NS(expected_broker_uid=901),
                                                     deadline_monotonic=10.5, clock=lambda: 100)

    def observed(self):
        return self.module["retained_http_guard_observation"]()


class TestRuntimeHttpRunGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = {name: (ROOT / name).read_bytes() for name in renderer.INPUTS}
        cls.report_raw = (ROOT / "benchmark/evidence/phase3-http-credential-staged-profile-v1.json").read_bytes()
        cls.report = json.loads(cls.report_raw)
        cls.extra = {name: (ROOT / name).read_bytes() for name in EXTRA_INPUTS}
        cls.action = repaired_action(cls.extra[EXTRA_INPUTS[0]], cls.extra[EXTRA_INPUTS[1]], cls.report)
        # Deliberate unit-boundary mapping, never an installed source closure.
        cls.dependencies = {
            "runtime_http_action.py": cls.action,
            "native_phase3_broker_reader_client.py": b'"""explicit mocked client boundary"""\n',
            "native_phase3_broker_reader_bootstrap.py": b'"""explicit mocked bootstrap boundary"""\n',
            "__init__.py": b'"""isolated test package"""\n',
        }
        cls.pins = {name: renderer._pin(raw) for name, raw in cls.dependencies.items()}
        cls.outputs = renderer.render(cls.original, predecessor_report_raw=cls.report_raw,
                                      dependency_sources=cls.dependencies, expected_dependency_pins=cls.pins)

    def render(self, original=None, report=None, dependencies=None, pins=None):
        return renderer.render(self.original if original is None else original,
                               predecessor_report_raw=self.report_raw if report is None else report,
                               dependency_sources=self.dependencies if dependencies is None else dependencies,
                               expected_dependency_pins=self.pins if pins is None else pins)

    def test_exact_seven_predecessors_match_actual_report(self):
        predecessors = renderer._predecessors(self.original)
        for name, raw in predecessors.items():
            row = next(row for row in self.report["files"] if row["source_name"] == name)
            self.assertEqual((len(raw), renderer._pin(raw)), (row["bytes"], row["digest"]))
        self.assertEqual(set(self.outputs), set(self.original))
        self.assertTrue(all(self.outputs[name] != predecessors[name] for name in self.outputs))

    def test_changed_original_or_report_refuses(self):
        for name in self.original:
            changed = dict(self.original, **{name: self.original[name] + b" "})
            with self.subTest(name=name), self.assertRaises(renderer.HttpRunGuardRenderError):
                self.render(original=changed)
        with self.assertRaises(renderer.HttpRunGuardRenderError):
            self.render(report=self.report_raw[:-1] + b"!")

    def test_exact_keys_and_finite_reversible_anchors(self):
        with self.assertRaises(renderer.HttpRunGuardRenderError):
            self.render(original={})
        for before, after, raw in (("a", "b", b"aa"), ("a", "b", b"ab"), ("a", "a", b"a")):
            with self.subTest(raw=raw), self.assertRaises(renderer.HttpRunGuardRenderError):
                renderer._change(raw, before, after)
        self.assertEqual(renderer._change(b"one a end", "a", "bbb"), b"one bbb end")

    def test_dependency_pin_key_and_name_fail_closed(self):
        with self.assertRaises(renderer.HttpRunGuardRenderError):
            self.render(pins={})
        for name in ("../x.py", "x/y.py", "runtime_http_broker.py"):
            deps = dict(self.dependencies, **{name: b"x"})
            pins = {key: renderer._pin(value) for key, value in deps.items()}
            with self.subTest(name=name), self.assertRaises(renderer.HttpRunGuardRenderError):
                self.render(dependencies=deps, pins=pins)
        pins = dict(self.pins, **{"__init__.py": "sha256:" + "0" * 64})
        with self.assertRaises(renderer.HttpRunGuardRenderError):
            self.render(pins=pins)

    def test_dependency_bounds_and_original_action_substitute_refuse(self):
        for raw in (b"", b"x" * (16777216 + 1), self.extra[EXTRA_INPUTS[0]]):
            name = "runtime_http_action.py" if raw == self.extra[EXTRA_INPUTS[0]] else "extra.py"
            deps = dict(self.dependencies, **{name: raw})
            pins = {key: renderer._pin(value) for key, value in deps.items()}
            with self.subTest(size=len(raw)), self.assertRaises(renderer.HttpRunGuardRenderError):
                self.render(dependencies=deps, pins=pins)

    def test_three_equal_source_sets_and_binding_limit_remain_explicit(self):
        inventories = []
        for name in (renderer.MEASUREMENT, renderer.PLAN, renderer.VERIFY):
            tree = ast.parse(self.outputs[name])
            values = [node.value for node in tree.body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "_SOURCES" for target in node.targets)]
            self.assertEqual(len(values), 1)
            inventories.append(ast.literal_eval(values[0]))
        self.assertEqual(inventories, [inventories[0]] * 3)
        self.assertEqual(inventories[0], {name.removeprefix(renderer.PREFIX) for name in renderer.INPUTS} | set(self.dependencies))
        self.assertIn(b"len(binding_raw) <= 8192", self.outputs[renderer.PLAN])
        self.assertIn(b"len(raw) <= 8192", self.outputs[renderer.MEASUREMENT])

    def test_lazy_refusal_finalizes_after_guard_before_connect(self):
        caller = Caller(self.outputs[renderer.HTTP])
        result = caller.call()
        events = caller.events
        begin = next(i for i, item in enumerate(events) if isinstance(item, tuple) and item[0] == "begin")
        finalize = next(i for i, item in enumerate(events) if isinstance(item, tuple) and item[0] == "finalize")
        self.assertLess(events.index("http-execution-guard"), begin)
        self.assertLess(events.index("policy", events.index("http-execution-guard")), begin)
        self.assertLess(events.index("check"), finalize)
        self.assertNotIn("CONNECT", events)
        self.assertEqual(result["reason_codes"], ["BROKER_RUN_LOSS_UNAVAILABLE"])
        self.assertEqual((result["verdict"], result["effect_status"]), ("BLOCK", "NOT_PERFORMED"))
        self.assertEqual(result["decision"]["verdict"], "ALLOW")
        self.assertEqual(events[-2:], ["close", "unlock"])
        args = events[begin][3]
        self.assertEqual(args, dict(request_raw=canonical(caller.request), effect_raw=canonical(caller.effect), deadline_monotonic=10.5))

    def test_early_and_latest_policy_blocks_never_construct_guard(self):
        for option in ("initial_block", "late_block"):
            caller = Caller(self.outputs[renderer.HTTP], **{option: True})
            result = caller.call()
            self.assertEqual(result["reason_codes"], ["POLICY_REFUSED"])
            self.assertFalse(any(isinstance(item, tuple) and item[0] == "begin" for item in caller.events))
            self.assertIsNone(caller.observed()["opening"])

    def test_full_refusal_vector_retained_single_terminal_code(self):
        codes = ["CHECKPOINT_UNAVAILABLE", "LOSS_UNAVAILABLE"]
        caller = Caller(self.outputs[renderer.HTTP], codes=codes)
        result = caller.call()
        self.assertEqual(result["reason_codes"], ["BROKER_RUN_" + code for code in codes])
        finish = next(item[1] for item in caller.events if isinstance(item, tuple) and item[0] == "finish")
        self.assertEqual(finish["failure_code"], codes[0])
        self.assertEqual(finish["transport_raw"], canonical(result["transport"]))
        self.assertEqual(json.loads(caller.observed()["check"]["response_raw"])["error_codes"], codes)

    def test_unknown_or_noncanonical_response_cannot_authorize(self):
        for codes in (["UNKNOWN"], [], ["LOSS_UNAVAILABLE", "CHECKPOINT_UNAVAILABLE"], ["LOSS_UNAVAILABLE"] * 2):
            caller = Caller(self.outputs[renderer.HTTP], codes=codes)
            result = caller.call()
            self.assertEqual(result["reason_codes"], ["BROKER_RUN_INTERNAL_REFUSAL"])
            self.assertNotIn("CONNECT", caller.events)
            self.assertIsInstance(caller.observed()["error"], BrokerFailure)

    def test_begin_error_observation_survives_normal_block(self):
        error = ClientFailure("IDENTITY_CHANGED")
        caller = Caller(self.outputs[renderer.HTTP], begin_error=error)
        result = caller.call()
        self.assertEqual(result["reason_codes"], ["BROKER_RUN_IDENTITY_CHANGED"])
        self.assertIs(caller.observed()["error"], error)
        self.assertIsNone(caller.observed()["opening"])
        self.assertEqual(caller.observed()["transport"], canonical(result["transport"]))

    def test_begin_cleanup_failure_invalidates_block(self):
        error = ClientFailure(cleanup=(OSError("fabricated cleanup"),), unresolved=object())
        caller = Caller(self.outputs[renderer.HTTP], begin_error=error)
        with self.assertRaises(ClientFailure) as raised:
            caller.call()
        self.assertIs(raised.exception, error)
        self.assertEqual(caller.events[-1], "unlock")

    def test_interrupt_and_memory_error_identity_after_transport_unwind(self):
        for kind in (KeyboardInterrupt, SystemExit, MemoryError):
            error = kind("fabricated original")
            caller = Caller(self.outputs[renderer.HTTP], check_error=error)
            with self.subTest(kind=kind), self.assertRaises(kind) as raised:
                caller.call()
            self.assertIs(raised.exception, error)
            self.assertIs(error.http_action_observation, caller.transport)
            self.assertIs(caller.observed()["error"], error)
            self.assertEqual(caller.events[-2:], ["close", "unlock"])

    def test_terminal_and_lock_failures_do_not_hide_memory_error(self):
        error = MemoryError("original")
        caller = Caller(self.outputs[renderer.HTTP], check_error=error,
                        finish_error=ClientFailure("RETENTION_FAILED"),
                        close_error=OSError("close"), lock_error=OSError("lock"))
        with self.assertRaises(MemoryError) as raised:
            caller.call()
        self.assertIs(raised.exception, error)
        self.assertEqual(caller.events[-2:], ["close", "unlock"])
        self.assertEqual(len(caller.observed()["cleanup_errors"]), 3)

    def test_terminal_failure_attempts_close_and_prevents_completed_block(self):
        for option in ("finish_error", "close_error"):
            error = ClientFailure("RETENTION_FAILED")
            caller = Caller(self.outputs[renderer.HTTP], **{option: error})
            with self.subTest(option=option), self.assertRaises(ClientFailure) as raised:
                caller.call()
            self.assertIs(raised.exception, error)
            self.assertEqual(caller.events[-2:], ["close", "unlock"])

    def test_public_getter_detaches_containers_and_preserves_owner_identity(self):
        error = ClientFailure()
        caller = Caller(self.outputs[renderer.HTTP], begin_error=error)
        empty = caller.observed()
        self.assertEqual(set(empty), {"opening", "check", "finish", "close", "error", "cleanup_errors", "transport"})
        caller.call()
        first = caller.observed()
        first["error"] = None
        self.assertIs(caller.observed()["error"], error)
        self.assertEqual(caller.observed()["cleanup_errors"], ())
        caller.thread.get_ident = lambda: 12
        with self.assertRaises(BrokerFailure):
            caller.observed()

    def test_second_attempt_does_not_overwrite_or_reclose_first_guard(self):
        caller = Caller(self.outputs[renderer.HTTP])
        caller.call()
        prior = caller.observed()
        caller.state["consumed"].clear()
        with self.assertRaises(BrokerFailure):
            caller.call()
        self.assertEqual(caller.observed(), prior)
        self.assertEqual(caller.events.count("close"), 1)

    def measurement(self):
        main = object()
        owner = NS(get_ident=lambda: 11, get_native_id=lambda: 701,
                   current_thread=lambda: main, main_thread=lambda: main)
        process = dict(pid=701, uid=901, gid=902, boot_id="boot", start_time_ticks=9, mount_namespace=[1, 2])
        keys = {"schema", "boot_id", "attempt_id", "source_pins", "grant_digest",
                "scheduled_measurement_request_digest", "deployment_identity_digest",
                "measurement_schedule_digest", "collection_commitment_digest", "runtime_profile_digest",
                "sensor_digest", "runtime_digest", "active_skill_digest", "policy_digest",
                "operation_digest", "path_digest", "payload_digest"}
        plan = {key: "sha256:" + "1" * 64 for key in keys}
        plan.update(schema="aragorn/runtime-broker-decision-measurement-binding/v1",
                    boot_id="boot", attempt_id="p3-lab-a001", source_pins={})
        trace_class = type("Trace", (), {})
        ns = dict(os=NS(getpid=lambda: 701, path=NS(lexists=lambda p: False)),
                  threading=owner, canonical_json=canonical, _require=require,
                  _digest=lambda value: require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value)),
                  broker=NS(RuntimeActionBrokerError=BrokerFailure, _parse_canonical_document=lambda raw, label: json.loads(raw)),
                  _PLAN=None, _PROCESS=None, _GUARD_OWNER=None, _GUARD_PLAN_RAW=None,
                  _GUARD_PROCESS_RAW=None, _identity=lambda: copy.deepcopy(process),
                  _sources=lambda value: None, _inputs=lambda value: None, _BINDING_KEYS=keys,
                  _ROOT=Path("/fabricated"), _PENDING="pending", _COMPLETE="complete", _OUTPUT=Path("/fabricated/output"),
                  re=re, Trace=trace_class)
        definitions(self.outputs[renderer.MEASUREMENT], ns, {"configure", "current_http_guard_pending"})
        ns["configure"](canonical(plan), 901)
        trace = trace_class()
        trace.final = None
        trace.pending = dict(binding=ns["_PLAN"], process=ns["_PROCESS"],
                             action_request_digest="sha256:" + "2" * 64, accepted_boottime_ns=77)
        trace.guard_pending_raw = canonical(trace.pending)
        ns["_CURRENT"] = NS(get=lambda: trace)
        return ns, trace, owner

    def test_accessor_returns_original_pre_final_bytes(self):
        ns, trace, _ = self.measurement()
        raw = ns["current_http_guard_pending"](expected_request_digest=trace.pending["action_request_digest"], expected_grant_digest=ns["_PLAN"]["grant_digest"])
        self.assertEqual(raw, trace.guard_pending_raw)
        decoded = json.loads(raw)
        decoded["accepted_boottime_ns"] = 999
        self.assertEqual(trace.pending["accepted_boottime_ns"], 77)

    def test_accessor_rejects_shared_plan_alias_and_pending_rewrite(self):
        for change in ("binding", "acceptance", "process"):
            ns, trace, _ = self.measurement()
            if change == "binding":
                ns["_PLAN"]["source_pins"]["substituted.py"] = "sha256:" + "4" * 64
            elif change == "acceptance":
                trace.pending["accepted_boottime_ns"] += 1
            else:
                ns["_PROCESS"]["start_time_ticks"] += 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                ns["current_http_guard_pending"](expected_request_digest=trace.pending["action_request_digest"], expected_grant_digest=ns["_PLAN"]["grant_digest"])

    def test_accessor_rejects_final_foreign_owner_and_pin_mismatch(self):
        for change in ("final", "pid", "thread", "native", "request", "grant"):
            ns, trace, owner = self.measurement()
            request, grant = trace.pending["action_request_digest"], ns["_PLAN"]["grant_digest"]
            if change == "final": trace.final = {}
            elif change == "pid": ns["os"].getpid = lambda: 702
            elif change == "thread": owner.get_ident = lambda: 12
            elif change == "native": owner.get_native_id = lambda: 702
            elif change == "request": request = "sha256:" + "5" * 64
            else: grant = "sha256:" + "5" * 64
            with self.subTest(change=change), self.assertRaises(ValueError):
                ns["current_http_guard_pending"](expected_request_digest=request, expected_grant_digest=grant)

    def service(self, *, configure_error=None, take_error=None, close_error=None, expired=False):
        events = []
        config = dict(provision_raw=b"p", expected_provision_digest="p-pin",
                      source_inventory_raw=b"s", expected_source_inventory_digest="s-pin",
                      measurement_binding_raw=b"measurement", expected_measurement_binding_digest="m-pin",
                      fixture_binding_raw=b"fixture", expected_fixture_binding_digest="f-pin",
                      ipc_cancel_read_fd=31, supervisor_pidfd=32, bootstrap_raw=b"actual-bootstrap")
        def take():
            events.append("take")
            if take_error: raise take_error
            return dict(config)
        def configure(**kwargs):
            events.append(("configure", kwargs))
            if configure_error: raise configure_error
            return {"ipc_raw": b"configured", "observed": {"actual": b"bytes"}}
        def close():
            events.append("close")
            if close_error: raise close_error
            return {"observation_raw": b"actual-close"}
        def receive(**kwargs):
            events.append(("receive", kwargs))
            return NS(take_configuration=take, close=close)
        def read(path, uid, **kwargs):
            events.append(("credential", path, kwargs))
            return b"measurement" if "measurement" in kwargs["label"] else b"grant"
        ns = dict(os=NS(getpid=lambda: 701), threading=NS(main_thread=lambda: NS(ident=11), get_ident=lambda: 11),
                  sys=NS(platform="linux"), hashlib=hashlib, time=NS(CLOCK_BOOTTIME=7, clock_gettime_ns=lambda c: 100),
                  Path=Path, RuntimeActionServiceError=BrokerFailure, RuntimeActionBrokerError=BrokerFailure,
                  _measurement=NS(configure=lambda raw, uid: events.append(("measurement", raw))),
                  _run_http=NS(read_service_credential=lambda name: (events.append(("fixture", name)) or (b"fixture", {}))),
                  _run_client=NS(configure_broker_reader_guard=configure),
                  _run_bootstrap=NS(receive_broker_reader_bootstrap=receive),
                  _service_identities=lambda: (901, 902, 903, 904, 905),
                  _credential_path=lambda path, uid, **kwargs: path,
                  _read_credential_bytes=read, _read_runtime_binding=lambda *a: ("runtime", "profile"),
                  _CONTROL_ROOT=Path("/fabricated/control"), _PROTECTED_ROOT=Path("/fabricated/protected"),
                  _STAGING_ROOT=Path("/fabricated/staging"), DEFAULT_PROTECTED_INSTALL_ROOT=Path("/fabricated/install"),
                  initialize_runtime_capability_grant=lambda c: {"status": "EXPIRED" if expired else "AVAILABLE"},
                  run_startup_readiness=lambda: events.append("readiness"),
                  serve_runtime_action_broker_v5=lambda c: events.append("serve"))
        for name in ("RuntimeActionBrokerConfig", "RuntimeActionBrokerV2Config", "RuntimeActionBrokerV4Config", "RuntimeActionBrokerV5Config"):
            ns[name] = lambda **kwargs: NS(**kwargs)
        definitions(self.outputs[renderer.SERVICE], ns)
        return ns, events, config

    def test_actual_service_raw_credentials_bootstrap_then_readiness(self):
        ns, events, config = self.service()
        ns["_run"](Path("runtime"), Path("grant"), Path("measurement"))
        receive = next(item[1] for item in events if isinstance(item, tuple) and item[0] == "receive")
        self.assertEqual(receive["capability_grant_raw"], b"grant")
        self.assertEqual(receive["measurement_binding_raw"], b"measurement")
        self.assertEqual(receive["fixture_binding_raw"], b"fixture")
        self.assertEqual(receive["startup_deadline_ns"], 4000000100)
        self.assertEqual(receive["expected_fixture_binding_digest"], renderer._pin(b"fixture"))
        configure = next(item[1] for item in events if isinstance(item, tuple) and item[0] == "configure")
        self.assertEqual(configure, {key: value for key, value in config.items() if key != "bootstrap_raw"})
        self.assertEqual(events[-3:], ["close", "readiness", "serve"])
        observed = ns["retained_broker_reader_bootstrap_observation"]()
        self.assertEqual(observed["bootstrap_raw"], b"actual-bootstrap")
        self.assertEqual(observed["transfer_close_result"], {"observation_raw": b"actual-close"})
        observed["configuration_result"]["observed"].clear()
        self.assertEqual(ns["retained_broker_reader_bootstrap_observation"]()["configuration_result"]["observed"], {"actual": b"bytes"})

    def test_expired_grant_never_bootstraps(self):
        ns, events, _ = self.service(expired=True)
        ns["_run"](Path("runtime"), Path("grant"), Path("measurement"))
        self.assertNotIn("take", events)
        self.assertNotIn("readiness", events)
        self.assertIsNone(ns["retained_broker_reader_bootstrap_observation"]()["bootstrap_raw"])

    def test_post_take_configure_failure_still_closes_transfer_once(self):
        error = MemoryError("original configuration")
        cleanup = OSError("original transfer cleanup")
        ns, events, _ = self.service(configure_error=error, close_error=cleanup)
        with self.assertRaises(MemoryError) as raised:
            ns["_run"](Path("runtime"), Path("grant"), Path("measurement"))
        self.assertIs(raised.exception, error)
        self.assertEqual(events[-1], "close")
        self.assertNotIn("readiness", events)
        observed = ns["retained_broker_reader_bootstrap_observation"]()
        self.assertIs(observed["error"], error)
        self.assertEqual(observed["cleanup_errors"], (cleanup,))

    def test_take_failure_is_not_closed_twice_or_retried(self):
        error = ClientFailure()
        ns, events, _ = self.service(take_error=error)
        with self.assertRaises(ClientFailure):
            ns["_run"](Path("runtime"), Path("grant"), Path("measurement"))
        self.assertNotIn("close", events)
        with self.assertRaises(BrokerFailure):
            ns["_bootstrap_reader"](b"grant", b"measurement")
        self.assertEqual(events.count("take"), 1)

    def test_service_transfer_close_failure_blocks_readiness(self):
        error = ClientFailure("CLEANUP_FAILED")
        ns, events, _ = self.service(close_error=error)
        with self.assertRaises(ClientFailure) as raised:
            ns["_run"](Path("runtime"), Path("grant"), Path("measurement"))
        self.assertIs(raised.exception, error)
        self.assertNotIn("readiness", events)
        self.assertEqual(ns["retained_broker_reader_bootstrap_observation"]()["cleanup_errors"], (error,))

    def consumers(self):
        canary = definitions(self.extra[EXTRA_INPUTS[2]], dict(hashlib=hashlib, json=json, re=re, canonical_json=canonical))
        ns = definitions(self.outputs[renderer.COLLECTION], dict(json=json, re=re,
                         canary=NS(**canary), canonical_json=canonical, canonical_digest=digest))
        prior = NS(_exact=ns["_exact"], _pin=ns["_pin"], _integer=ns["_uint"])
        effective = definitions(self.extra[EXTRA_INPUTS[3]], dict(re=re, prior=prior,
                                canonical_digest=digest, _require=require), {"_reasons", "_policy"})
        # Existing sets are read as literal source data, not copied from a producer.
        for node in ast.parse(self.extra[EXTRA_INPUTS[3]]).body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in {"_MISMATCH_REASONS", "_SINGLE_REASONS"}:
                        effective[target.id] = ast.literal_eval(node.value)
        ns["effective"] = NS(**effective)
        action = definitions(self.action, dict(re=re, json=json, Path=Path, contextmanager=contextmanager,
                             canary=NS(**canary), canonical_json=canonical, canonical_digest=digest))
        broker = NS(RuntimeActionBrokerError=BrokerFailure,
                    _exact=lambda value, fields, label: ns["_exact"](value, fields),
                    _require_digest=lambda value, label: ns["_pin"](value))
        runtime = definitions(self.outputs[renderer.CAPABILITY], dict(re=re, broker=broker,
                              canary=NS(**canary), http=NS(**action),
                              mediation=NS(RESULT_SCHEMA="aragorn/runtime-http-broker-result/v1",
                                           RESULT_AUTHORITY="BROKER_HTTP_DECISION_ONLY_NOT_SINK_OR_RUN_QUALIFICATION"),
                              canonical_json=canonical, canonical_digest=digest))
        # The already validated outer grant/claim is an explicit unit boundary.
        # Actual result/policy/transport validators below remain unmodified.
        runtime["validate_claim"] = lambda value, pin: value
        return ns, runtime

    def receipt(self, consumer, reasons=None):
        pin = "sha256:" + "1" * 64
        request = dict(policy_digest=pin, policy_version=1)
        effect = consumer["effect_for_attempt"]("p3-lab-a001")
        decision = dict(schema="aragorn/runtime-action-decision/v1",
                        authority="RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
                        request_digest=digest(request), active_context_digest=None, measured_action_digest=None,
                        policy_digest=pin, policy_version=1, evaluated_at_unix=5,
                        revocation_snapshot_digest=pin, revocation_generation=1, minimum_revocation_generation=1,
                        mediator_health_digest=pin, mediator_health_epoch=1, minimum_mediator_health_epoch=1,
                        verdict="ALLOW", reason_codes=[])
        result = dict(schema="aragorn/runtime-http-broker-result/v1",
                      authority="BROKER_HTTP_DECISION_ONLY_NOT_SINK_OR_RUN_QUALIFICATION",
                      request_digest=digest(request), effect_digest=digest(effect), attempt_id="p3-lab-a001",
                      observation_digest=pin, verdict="BLOCK", reason_codes=reasons or ["BROKER_RUN_LOSS_UNAVAILABLE"],
                      effect_status="NOT_PERFORMED", decision=decision, payload_decision=None, transport=None,
                      run_conformance_eligible=False, phase3_eligible=False, production_activation_eligible=False)
        profile = dict(submission_digest=pin, runtime_attribution_digest=digest({}),
                       profile_pending={"runtime_attribution": {}}, request_digest=digest(request),
                       effect_digest=digest(effect), attempt_id="p3-lab-a001", lease_digest=pin)
        claim = dict(profile_claim=profile, grant_digest=pin, lease_digest=pin)
        receipt = dict(schema="aragorn/runtime-process-profile-receipt/v1",
                       authority="BROKER_PROFILE_RECEIPT_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY",
                       submission_digest=pin, runtime_attribution={}, runtime_attribution_digest=digest({}),
                       broker_result=result, broker_result_digest=digest(result))
        return claim, receipt, result, request

    def test_actual_runtime_and_independent_consumer_accept_only_bound_refusal(self):
        consumer, runtime = self.consumers()
        for code in renderer._CODES:
            claim, receipt, result, request = self.receipt(consumer, ["BROKER_RUN_" + code])
            self.assertTrue(runtime["_recorded_decision"](result["decision"], result, digest(request)))
            replay = consumer["result_record"](claim, receipt, result, request)
            self.assertEqual(replay["profile_result"]["effect_status"], "NOT_PERFORMED")

    def test_actual_consumers_reject_unknown_mixed_and_noncanonical_reasons(self):
        consumer, runtime = self.consumers()
        for reasons in (["BROKER_RUN_UNKNOWN"], ["BROKER_CLOCK_ROLLBACK", "BROKER_RUN_LOSS_UNAVAILABLE"],
                        ["BROKER_RUN_LOSS_UNAVAILABLE"] * 2,
                        ["BROKER_RUN_LOSS_UNAVAILABLE", "BROKER_RUN_CHECKPOINT_UNAVAILABLE"]):
            claim, receipt, result, request = self.receipt(consumer, reasons)
            self.assertFalse(runtime["_recorded_decision"](result["decision"], result, digest(request)))
            with self.assertRaises(ValueError):
                consumer["result_record"](claim, receipt, result, request)

    def test_actual_consumers_reject_positive_missing_policy_and_changed_receipt(self):
        consumer, runtime = self.consumers()
        for change in ("positive", "missing", "request", "transport"):
            claim, receipt, result, request = self.receipt(consumer)
            if change == "positive": result.update(verdict="ALLOW", effect_status="SENT")
            elif change == "missing": result["decision"] = None
            elif change == "request": result["decision"]["request_digest"] = "sha256:" + "2" * 64
            else: result["transport"] = {"status": "SENT"}
            receipt["broker_result_digest"] = digest(result)
            if change != "transport":
                self.assertFalse(runtime["_recorded_decision"](result["decision"], result, digest(request)))
            with self.subTest(change=change), self.assertRaises(ValueError):
                consumer["result_record"](claim, receipt, result, request)

    def test_actual_runtime_and_independent_transport_joins_remain_enforced(self):
        consumer, runtime = self.consumers()
        claim, receipt, result, request = self.receipt(consumer)
        fixture = dict(container_id="1" * 64, boot_id="11111111-1111-1111-1111-111111111111",
                       netns_device=7, netns_inode=9)
        binding = dict(schema="aragorn/runtime-http-fixture-binding/v1", fixture=fixture,
                       expected_broker_uid=901, expected_broker_gid=902)
        actions = consumer["action_digests"](result["attempt_id"], binding)
        request.update(actions)
        result["request_digest"] = result["decision"]["request_digest"] = digest(request)
        profile = claim["profile_claim"]
        profile["request_digest"] = digest(request)
        profile["profile_pending"]["measured_action"] = actions
        result["transport"] = dict(schema="aragorn/runtime-http-action-result/v1",
                                   authority="CREDENTIAL_BOUND_LAB_HTTP_TRANSPORT_ONLY_NOT_POLICY_AUTHORITY",
                                   attempt_id=result["attempt_id"], fixture_binding_digest=digest(binding),
                                   effect_digest=result["effect_digest"], action_digests=actions,
                                   connect_attempted=False, sent_bytes=0, response_bytes=0,
                                   response_digest=renderer._pin(b""), status="NOT_PERFORMED",
                                   error_code="HTTP_AUTHORIZATION_REFUSED",
                                   identity=dict(fixture=fixture, pid=701, start_time_ticks=9, uid=901, gid=902),
                                   **dict.fromkeys(consumer["canary"].FALSE_FLAGS, False))
        receipt["broker_result_digest"] = digest(result)
        self.assertEqual(runtime["validate_broker_result"](result, profile), result)
        self.assertEqual(consumer["result_record"](claim, receipt, result, request)["profile_result"]["verdict"], "BLOCK")
        for key, value in (("connect_attempted", True), ("sent_bytes", 1), ("fixture_binding_digest", "sha256:" + "2" * 64)):
            forged = copy.deepcopy(result)
            forged["transport"][key] = value
            forged_receipt = {**receipt, "broker_result": forged, "broker_result_digest": digest(forged)}
            with self.subTest(key=key), self.assertRaises(ValueError):
                runtime["validate_broker_result"](forged, profile)
            with self.subTest(independent=key), self.assertRaises(ValueError):
                consumer["result_record"](claim, forged_receipt, forged, request)


if __name__ == "__main__":
    unittest.main()
