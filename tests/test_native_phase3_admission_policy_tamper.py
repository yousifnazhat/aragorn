"""Inert, independently authored callback records; never native execution."""
import base64
import copy
import hashlib
import json
from pathlib import PurePosixPath
import unittest

from aragorn.native_phase3_admission_policy_tamper import (
    PolicyTamperRecordingError, record_policy_tamper,
)
from aragorn.native_phase3_admission_policy_tamper_verify import (
    PolicyTamperVerificationError, verify_policy_tamper,
)


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def pin(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64(value):
    return base64.b64encode(value).decode("ascii")


SCHEMA = "aragorn/native-admission-policy-tamper-"
OPS = ("OVERWRITE", "CHMOD", "UNLINK", "REPLACE_RENAME", "ADJACENT_SYMLINK", "PARENT_RETARGET")
RESOURCE_PATHS = {
    "config": "/run/credentials/aragorn-agent-gateway.service/openclaw-config",
    "policy_executable": "/usr/bin/printf",
}
CLI_ARGV = ["/usr/local/bin/node", "/runtime/lib/node_modules/openclaw/openclaw.mjs",
            "plugins", "install", "/route-input/plugin-package-skill-replacement/candidate-source",
            "--force"]
CLI_ERROR = b"blocked by install policy: plugin installs disabled by Aragorn protected profile\n"
CLI_OUTPUT = (b"Install policy target=plugin:aragorn-plugin-skill-replacement-fixture "
              b"request=plugin-dir/update origin=plugin-package pathKind=directory "
              b"source=local-path/user: blocked by install policy: "
              b"plugin installs disabled by Aragorn protected profile\n")


class Fixture:
    def __init__(self):
        # Inert byte stand-ins, not deployed executable/config identities.
        self.content = {"config": raw({"security": {"installPolicy": {
            "enabled": True, "targets": ["plugin"], "exec": {"source": "exec",
            "command": "/usr/bin/printf", "trustedDirs": ["/usr/bin"],
            "args": ["%s", '{"protocolVersion":1,"decision":"block","reason":"plugin installs disabled by Aragorn protected profile"}']}}}}),
            "policy_executable": b"inert printf identity bytes\n"}
        self.bindings = {name: pin(name.encode()) for name in (
            "deployment", "config", "policy_executable", "node", "runtime_tree",
            "candidate", "baseline", "observer_source")}
        self.bindings.update({name: pin(value) for name, value in self.content.items()})
        resources = {}
        for name, path in RESOURCE_PATHS.items():
            resources[name] = {
                "path": path, "digest": self.bindings[name],
                "identity": {"device": 2, "inode": 12, "mode": 0o100444,
                             "uid": 0, "gid": 0, "nlink": 1, "size": len(self.content[name]),
                             "mtime_ns": 100, "ctime_ns": 101},
                "ancestry": [{"path": str(parent), "device": 2, "inode": i + 1,
                              "mode": 0o40755, "uid": 0, "gid": 0}
                             for i, parent in enumerate(reversed(PurePosixPath(path).parents))],
            }
        boot = "12345678-1234-1234-1234-123456789abc"
        self.context = {
            "schema": SCHEMA + "context/v1", "nonce": "a" * 64,
            "fixture": {"container_id": "b" * 64, "boot_id": boot, "netns_device": 4, "netns_inode": 5},
            "gateway": {"pid": 120, "start_time_ticks": 50, "uid": 992, "gid": 992},
            "clock": {"boot_id": boot, "clock_id": "CLOCK_BOOTTIME",
                      "time_namespace_device": 4, "time_namespace_inode": 6},
            "bindings": dict(self.bindings), "resources": resources, "argv": list(CLI_ARGV),
            "cwd": "/var/lib/aragorn-agent-gateway", "environment": {"TZ": "UTC"},
            "subject": {"plugin_id": "aragorn-plugin-skill-replacement-fixture",
                        "candidate_path": CLI_ARGV[4],
                        "target_path": "/var/lib/aragorn-agent-gateway/state/extensions/aragorn-plugin-skill-replacement-fixture",
                        "candidate_digest": self.bindings["candidate"],
                        "baseline_digest": self.bindings["baseline"]},
        }
        self.bindings["context"] = pin(raw(self.context))
        self.observation = pin(b"separately retained protected observation stand-in")
        self.catalog = pin(b"unchanged catalog stand-in")
        self.events = []
        self.tick = 0

    def joined(self, kind):
        return {"schema": SCHEMA + kind + "/v1", "context_digest": self.bindings["context"],
                "nonce": self.context["nonce"]}

    def snapshot(self, timestamp):
        resources = copy.deepcopy(self.context["resources"])
        for name in resources:
            resources[name]["raw_base64"] = b64(self.content[name])
        return {**self.joined("snapshot"), "observed_ns": timestamp, "resources": resources,
                "baseline_digest": self.bindings["baseline"], "catalog_digest": self.catalog,
                "candidate_installed": False}

    def mutation(self, resource, operation, start):
        structural = operation in ("REPLACE_RENAME", "PARENT_RETARGET")
        return {**self.joined("operation"), "resource": resource, "operation": operation,
                "started_ns": start, "finished_ns": start + 1,
                "result": "STRUCTURAL_REFUSAL" if structural else "DENIED",
                "errno": "EXDEV" if structural else "EROFS"}

    def invocation(self, start):
        return {**self.joined("invocation"), "started_ns": start, "finished_ns": start + 1,
                "argv": list(CLI_ARGV), "exit_code": 1, "stdout_base64": b64(CLI_OUTPUT),
                "stderr_base64": b64(CLI_ERROR), "policy_observation_digest": self.observation}

    def record(self):
        attempts = []
        tick = 0
        for name in RESOURCE_PATHS:
            for operation in OPS:
                attempts.append({"operation_base64": b64(raw(self.mutation(name, operation, tick + 1))),
                                 "snapshot_base64": b64(raw(self.snapshot(tick + 3)))})
                tick += 3
        return {"schema": SCHEMA + "record/v1", "context_digest": self.bindings["context"],
                "before": b64(raw(self.snapshot(0))), "attempts": attempts,
                "invocation": b64(raw(self.invocation(tick + 1))),
                "after": b64(raw(self.snapshot(tick + 3))), "policy_execution_verified": False,
                "admission_qualified": False, "phase3_qualified": False}

    def read(self):
        self.events.append("snapshot")
        value = raw(self.snapshot(self.tick))
        self.tick += 1
        return value

    def attempt(self, name, operation):
        self.events.append((name, operation))
        value = raw(self.mutation(name, operation, self.tick))
        self.tick += 2
        return value

    def invoke(self):
        self.events.append("invoke")
        value = raw(self.invocation(self.tick))
        self.tick += 2
        return value


class PolicyTamperTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()

    def verify(self, value, **kwargs):
        payload = raw(value) if type(value) is dict else value
        arguments = {"expected_digest": pin(payload), "context_raw": raw(self.f.context),
                     "bindings": self.f.bindings, "expected_policy_observation_digest": self.f.observation}
        arguments.update(kwargs)
        return verify_policy_tamper(payload, **arguments)

    def produce(self, **kwargs):
        arguments = {"context_raw": raw(self.f.context), "bindings": self.f.bindings,
                     "read_snapshot": self.f.read, "attempt_mutation": self.f.attempt,
                     "invoke_policy": self.f.invoke}
        arguments.update(kwargs)
        return record_policy_tamper(**arguments)

    def edit_nested(self, record, field, transform, row=None):
        owner = record if row is None else record["attempts"][row]
        value = json.loads(base64.b64decode(owner[field]))
        transform(value)
        owner[field] = b64(raw(value))

    def test_independently_authored_record_and_claim_ceiling(self):
        result = self.verify(self.f.record())
        self.assertEqual(result["status"], "CONSISTENT_POLICY_TAMPER_RECORD")
        self.assertEqual((result["operations"], result["protective_denials"], result["structural_refusals"]), (12, 8, 4))
        self.assertFalse(result["policy_execution_verified"])
        self.assertFalse(result["admission_qualified"])
        self.assertFalse(result["phase3_qualified"])
        self.assertEqual(len(result["limitations"]), 5)

    def test_recorder_exact_callbacks_and_independent_replay(self):
        payload = self.produce()
        self.assertEqual(self.verify(payload)["operations"], 12)
        expected = ["snapshot"]
        for name in RESOURCE_PATHS:
            for operation in OPS:
                expected.extend(((name, operation), "snapshot"))
        expected.extend(("invoke", "snapshot"))
        self.assertEqual(self.f.events, expected)
        self.assertEqual(payload, raw(self.f.record()))

    def test_all_protective_errno_variants(self):
        for errno in ("EACCES", "EPERM", "EROFS"):
            record = self.f.record()
            for i in range(12):
                self.edit_nested(record, "operation_base64", lambda v: v.update(result="DENIED", errno=errno), i)
            self.assertEqual(self.verify(record)["protective_denials"], 12)

    def test_structural_ebusy_is_not_protective(self):
        record = self.f.record()
        self.edit_nested(record, "operation_base64", lambda v: v.update(errno="EBUSY"), 3)
        self.assertEqual(self.verify(record)["structural_refusals"], 4)

    def test_substituted_external_bindings(self):
        for key in self.f.bindings:
            with self.subTest(key=key), self.assertRaises(PolicyTamperVerificationError):
                self.verify(self.f.record(), bindings={**self.f.bindings, key: pin(b"substituted")})

    def test_substituted_held_context_identities(self):
        variants = [("gateway", "pid", 121), ("clock", "time_namespace_inode", 7),
                    ("fixture", "netns_inode", 9), ("environment", "TZ", "other")]
        for group, key, value in variants:
            context = copy.deepcopy(self.f.context)
            context[group][key] = value
            with self.subTest(group=group), self.assertRaises(PolicyTamperVerificationError):
                self.verify(self.f.record(), context_raw=raw(context))

    def test_wrong_record_or_post_retention_observation_pin(self):
        for key in ("expected_digest", "expected_policy_observation_digest"):
            with self.subTest(key=key), self.assertRaises(PolicyTamperVerificationError):
                self.verify(self.f.record(), **{key: pin(b"other")})

    def test_resource_bytes_metadata_and_ancestry_substitution(self):
        changes = [lambda r: r.update(raw_base64=b64(b"changed")),
                   lambda r: r["identity"].update(inode=99),
                   lambda r: r["identity"].update(nlink=True),
                   lambda r: r["ancestry"][0].update(inode=99),
                   lambda r: r.update(digest=pin(b"different"))]
        for name in RESOURCE_PATHS:
            for change in changes:
                record = self.f.record()
                self.edit_nested(record, "snapshot_base64", lambda v: change(v["resources"][name]), 5)
                with self.subTest(name=name, change=change), self.assertRaises(PolicyTamperVerificationError):
                    self.verify(record)

    def test_baseline_catalog_and_candidate_changes(self):
        for field, value in (("baseline_digest", pin(b"different")),
                             ("catalog_digest", pin(b"different")), ("candidate_installed", True),
                             ("candidate_installed", 0)):
            record = self.f.record()
            self.edit_nested(record, "after", lambda v: v.update({field: value}))
            with self.subTest(field=field, value=value), self.assertRaises(PolicyTamperVerificationError):
                self.verify(record)

    def test_operation_order_count_and_unknown_fields(self):
        records = []
        r = self.f.record(); r["attempts"].reverse(); records.append(r)
        r = self.f.record(); r["attempts"].pop(); records.append(r)
        r = self.f.record(); r["target_absent"] = True; records.append(r)
        r = self.f.record(); r["attempts"][0]["extra"] = 1; records.append(r)
        for record in records:
            with self.assertRaises(PolicyTamperVerificationError):
                self.verify(record)

    def test_structural_misclassification_and_success_refused(self):
        for result, errno in (("DENIED", "EXDEV"), ("STRUCTURAL_REFUSAL", "EROFS"),
                              ("STRUCTURAL_REFUSAL", "EBUSY"), ("SUCCESS", "EPERM"), ("UNKNOWN", "EPERM")):
            record = self.f.record()
            self.edit_nested(record, "operation_base64", lambda v: v.update(result=result, errno=errno), 0)
            with self.subTest(result=result, errno=errno), self.assertRaises(PolicyTamperVerificationError):
                self.verify(record)

    def test_chronology_and_strict_integers(self):
        for field, value in (("started_ns", -1), ("started_ns", True), ("started_ns", 1.0),
                             ("finished_ns", 2**63), ("finished_ns", 4), ("started_ns", 3)):
            record = self.f.record()
            self.edit_nested(record, "operation_base64", lambda v: v.update({field: value}), 0)
            with self.subTest(field=field, value=value), self.assertRaises(PolicyTamperVerificationError):
                self.verify(record)
        for field, row in (("snapshot_base64", 2), ("after", None)):
            record = self.f.record()
            self.edit_nested(record, field, lambda v: v.update(observed_ns=0), row)
            with self.assertRaises(PolicyTamperVerificationError):
                self.verify(record)

    def test_cli_output_is_exact_and_exit_one_not_bool(self):
        changes = [("exit_code", 0), ("exit_code", True), ("argv", CLI_ARGV[:-1]),
                   ("stdout_base64", b64(CLI_OUTPUT + b"diagnostic\n")),
                   ("stderr_base64", b64(CLI_ERROR.rstrip(b"\n"))),
                   ("stdout_base64", b64(b'{"decision":"block"}'))]
        for field, value in changes:
            record = self.f.record()
            self.edit_nested(record, "invocation", lambda v: v.update({field: value}))
            with self.subTest(field=field), self.assertRaises(PolicyTamperVerificationError):
                self.verify(record)

    def test_flags_cannot_be_promoted_or_numeric(self):
        for field in ("policy_execution_verified", "admission_qualified", "phase3_qualified"):
            for value in (True, 0, None):
                record = self.f.record(); record[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(PolicyTamperVerificationError):
                    self.verify(record)

    def test_join_substitution_at_each_record_type(self):
        for field, row in (("before", None), ("operation_base64", 0), ("invocation", None)):
            for key, value in (("nonce", "c" * 64), ("context_digest", pin(b"other")), ("schema", "other")):
                record = self.f.record()
                self.edit_nested(record, field, lambda v: v.update({key: value}), row)
                with self.subTest(field=field, key=key), self.assertRaises(PolicyTamperVerificationError):
                    self.verify(record)

    def test_noncanonical_json_duplicates_nonfinite_and_bounds(self):
        valid = raw(self.f.record())
        for payload in (valid + b"\n", b'{"schema":1,"schema":2}', b'{"x":NaN}',
                        b"\xff", b" " * (4194304 + 1)):
            with self.subTest(size=len(payload)), self.assertRaises(PolicyTamperVerificationError):
                self.verify(payload)

    def test_nested_base64_and_json_bounds(self):
        for encoded in ("%%%", b64(b" " * (262144 + 1)), b64(raw(self.f.snapshot(0)) + b"\n")):
            record = self.f.record(); record["before"] = encoded
            with self.assertRaises(PolicyTamperVerificationError):
                self.verify(record)

    def test_invalid_context_refuses_before_callbacks(self):
        transforms = [lambda c: c["gateway"].update(uid=True),
                      lambda c: c["clock"].update(clock_id="CLOCK_MONOTONIC"),
                      lambda c: c["resources"]["config"]["identity"].update(mode=0o100666),
                      lambda c: c["resources"]["config"]["identity"].update(nlink=2),
                      lambda c: c["resources"]["config"]["ancestry"].reverse(),
                      lambda c: c["subject"].update(target_path="/untrusted"),
                      lambda c: c.update(cwd="/a/../b"),
                      lambda c: c["environment"].update(TZ=1)]
        for change in transforms:
            context = copy.deepcopy(self.f.context); change(context)
            bindings = {**self.f.bindings, "context": pin(raw(context))}
            with self.assertRaises(PolicyTamperRecordingError):
                self.produce(context_raw=raw(context), bindings=bindings)
            self.assertEqual(self.f.events, [])

    def test_missing_any_callback_refuses_before_mutation(self):
        for name in ("read_snapshot", "attempt_mutation", "invoke_policy"):
            with self.assertRaises(PolicyTamperRecordingError) as caught:
                self.produce(**{name: None})
            self.assertEqual(self.f.events, [])
            self.assertEqual(json.loads(caught.exception.partial)["phase"], "PRECONDITIONS")

    def test_unexpected_mutation_stops_and_retains_returned_bytes(self):
        result = raw({**self.f.mutation("config", "OVERWRITE", 1), "result": "SUCCESS"})
        with self.assertRaises(PolicyTamperRecordingError) as caught:
            self.produce(attempt_mutation=lambda *_: result)
        self.assertEqual(self.f.events, ["snapshot"])
        partial = json.loads(caught.exception.partial)
        self.assertEqual(base64.b64decode(partial["events"][-1]["raw_base64"]), result)
        self.assertFalse(partial["policy_execution_verified"])

    def test_changed_snapshot_stops_before_next_mutation(self):
        def read():
            value = json.loads(self.f.read())
            if len(self.f.events) > 1:
                value["catalog_digest"] = pin(b"changed")
            return raw(value)
        with self.assertRaises(PolicyTamperRecordingError):
            self.produce(read_snapshot=read)
        self.assertEqual(self.f.events, ["snapshot", ("config", "OVERWRITE"), "snapshot"])

    def test_callback_exceptions_and_final_partial_are_retained(self):
        for failure_index in (0, 1, 2, 25, 26):
            self.f = Fixture()
            count = 0
            def wrap(callback):
                def call(*args):
                    nonlocal count
                    index = count; count += 1
                    if index == failure_index:
                        raise RuntimeError("secret diagnostics must not be retained")
                    return callback(*args)
                return call
            with self.assertRaises(PolicyTamperRecordingError) as caught:
                self.produce(read_snapshot=wrap(self.f.read), attempt_mutation=wrap(self.f.attempt),
                             invoke_policy=wrap(self.f.invoke))
            self.assertEqual(count, failure_index + 1)
            self.assertNotIn(b"secret diagnostics", caught.exception.partial)
            self.assertLessEqual(len(caught.exception.partial), 4194304)
            with self.assertRaises(PolicyTamperVerificationError):
                self.verify(caught.exception.partial)

    def test_oversized_callback_retains_bounded_prefix_not_success(self):
        oversized = b"x" * 300000
        with self.assertRaises(PolicyTamperRecordingError) as caught:
            self.produce(read_snapshot=lambda: oversized)
        partial = json.loads(caught.exception.partial)
        last = partial["events"][-1]
        self.assertEqual(last["bytes"], len(oversized))
        self.assertEqual(last["digest"], pin(oversized))
        self.assertTrue(last["truncated"])
        self.assertLessEqual(len(caught.exception.partial), 4194304)
        self.assertEqual(self.f.events, [])

    def test_callback_cannot_mutate_held_bindings(self):
        def attempt(*args):
            result = self.f.attempt(*args)
            self.f.bindings["baseline"] = pin(b"changed")
            return result
        with self.assertRaises(PolicyTamperRecordingError):
            self.produce(attempt_mutation=attempt)
        self.assertNotIn("invoke", self.f.events)

    def test_callback_supplied_partial_bytes_preserved(self):
        def failed(*_):
            error = RuntimeError("private error text")
            error.partial_bytes = b"incomplete observation fragment"
            raise error
        with self.assertRaises(PolicyTamperRecordingError) as caught:
            self.produce(attempt_mutation=failed)
        event = json.loads(caught.exception.partial)["events"][-1]
        self.assertEqual(base64.b64decode(event["raw_base64"]), b"incomplete observation fragment")
        self.assertFalse(event["truncated"])
        self.assertEqual(self.f.events, ["snapshot"])

    def test_source_confirmed_cli_byte_pins(self):
        self.assertEqual(len(CLI_OUTPUT), 242)
        self.assertEqual(pin(CLI_OUTPUT), "sha256:8c0265e48856ba50083bb6f92bc0e12f54fe99940af3b62aed289f39d5701e11")
        self.assertEqual(len(CLI_ERROR), 81)
        self.assertEqual(pin(CLI_ERROR), "sha256:a149f38f8d60b58e495961982b80d56c9ac4cac151e0a7698945b3e45dd2eb32")


if __name__ == "__main__":
    unittest.main()
