"""Inert fixed-case tests only; these dictionaries are never execution evidence."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
import ast
import errno
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

from aragorn import native_phase3_admission_path_mutation as consumer
from aragorn.oci_worker_protocol import canonical_json
from scripts import runtime_native_admission_path_mutation as guest
from test_native_admission_direct_write import _fixture as direct_fixture, _file, _pin


def _fixture(case_id):
    """Data only for this leaf and outer-consumer unit joins, not qualification."""
    old, old_bindings = direct_fixture()
    bindings = {
        "expected_case_id": case_id,
        **{
            name: old_bindings[name]
            for name in (
                "expected_container",
                "expected_gateway_pid",
                "expected_admitted_digest",
            )
        },
        "expected_probe_digest": _pin("path-probe"),
        "expected_verifier_digest": _pin("path-verifier"),
        "expected_shared_probe_digest": old_bindings["expected_probe_digest"],
        "expected_shared_verifier_digest": old_bindings["expected_verifier_digest"],
    }
    source_pins = {
        consumer.PROBE: bindings["expected_probe_digest"],
        consumer.VERIFIER: bindings["expected_verifier_digest"],
    }
    size = len(consumer.payload(case_id))
    entries = []
    for i, _ in enumerate(consumer.sources(case_id)):
        entries.extend(
            (
                {
                    "path": f"source-{i}",
                    "kind": "directory",
                    "identity": [1, 1000 + i * 2, 0o40700, 992, 992, 2, 4096, 8, 9],
                    "bytes": None,
                    "digest": None,
                },
                {
                    "path": f"source-{i}/SKILL.md",
                    "kind": "file",
                    "identity": [1, 1001 + i * 2, 0o100600, 992, 992, 1, size, 8, 9],
                    "bytes": size,
                    "digest": consumer.digest(consumer.payload(case_id)),
                },
            )
        )
    boundary = {
        "scratch": {
            "identity": [1, 999, 0o40700, 992, 992, 2, 4096, 8, 9],
            "read_only": False,
            "entries": entries,
            "candidate_absent": True,
        },
        "destinations": {
            row["destination"]: {
                "path": row["destination"],
                "exists": False,
                "identity": None,
                "link_target": None,
            }
            for row in consumer.operations(case_id)
        },
        "retargets": {
            path: {
                "path": path,
                "identity": deepcopy(old["before"]["roots"][path]["identity"])
                if path in consumer.shared.ROOTS
                else [1, 2000 + i, 0o40700, 992, 992, 2, 4096, 8, 9],
                "read_only": True,
            }
            for i, path in enumerate(
                consumer.RETARGET_ROOTS if case_id == consumer.CASES[0] else ()
            )
        },
        "adapter_sources": {path: _file(pin) for path, pin in source_pins.items()},
    }
    attempts = []
    for operation in consumer.operations(case_id):
        source = consumer.source_entry(boundary, case_id, operation["source"])
        destination = boundary["destinations"][operation["destination"]]
        code = (
            errno.EXDEV
            if operation["operation"] == "rename-into-root"
            else (
                errno.EBUSY
                if operation["operation"] == "retarget-mount"
                else errno.EROFS
            )
        )
        attempts.append(
            {
                **operation,
                "attempted": True,
                "completed": False,
                "errno": code,
                "outcome": consumer.outcome(operation["operation"], False, code),
                "source_before": deepcopy(source),
                "source_after": deepcopy(source),
                "destination_before": deepcopy(destination),
                "destination_after": deepcopy(destination),
                "readback_failures": [],
            }
        )
    value = {
        "schema": consumer.SCHEMA,
        "authority": consumer.AUTHORITY,
        "case_id": case_id,
        "status": "OBSERVED",
        "fixture_container": old["fixture_container"],
        "gateway_pid": old["gateway_pid"],
        "admitted_digest": old["admitted_digest"],
        "source_pins": source_pins,
        "shared_source_pins": old["source_pins"],
        "before": old["before"],
        "after": old["after"],
        "commands_before": old["commands_before"],
        "commands_after": old["commands_after"],
        "scratch_preparation": consumer.preparation(case_id),
        "mutation_before": boundary,
        "mutation_after": deepcopy(boundary),
        "attempts": attempts,
        "postcondition_failures": [],
        "refusal": None,
        "limitations": list(consumer.LIMITATIONS),
        **dict.fromkeys(consumer.FALSE_FLAGS, False),
    }
    return value, bindings


def _verify(value, bindings):
    raw = canonical_json(value)
    return consumer.verify_native_admission_path_mutation(
        raw, expected_raw_digest=consumer.digest(raw), **bindings
    )


class NativePathMutationTests(unittest.TestCase):
    def test_scratch_syscall_contract_is_exclusive_and_retains_short_writes(self):
        directory_flags = (
            guest.os.O_RDONLY
            | guest.os.O_DIRECTORY
            | guest.os.O_NOFOLLOW
            | guest.os.O_CLOEXEC
        )
        file_flags = (
            guest.os.O_WRONLY
            | guest.os.O_CREAT
            | guest.os.O_EXCL
            | guest.os.O_NOFOLLOW
            | guest.os.O_CLOEXEC
        )
        for case_id in consumer.CASES:
            raw = consumer.payload(case_id)
            for mode in ("existing", "short", "complete"):
                record = {
                    "root": consumer.SCRATCH[case_id],
                    "created": [],
                    "completed": False,
                }
                with (
                    self.subTest(case=case_id, mode=mode),
                    patch.object(guest.readers, "_open", return_value=10) as workspace,
                    patch.object(
                        guest.os,
                        "fstat",
                        return_value=SimpleNamespace(
                            st_mode=0o40700, st_uid=992, st_gid=992
                        ),
                    ),
                    patch.object(
                        guest.os, "fstatvfs", return_value=SimpleNamespace(f_flag=0)
                    ),
                    patch.object(
                        guest, "_entry", return_value={"exists": mode == "existing"}
                    ),
                    patch.object(guest.os, "mkdir") as mkdir,
                    patch.object(guest.os, "open", side_effect=range(20, 40)) as opened,
                    patch.object(
                        guest.os, "write", return_value=len(raw) - (mode == "short")
                    ) as write,
                    patch.object(guest.os, "fsync") as fsync,
                    patch.object(guest.os, "close") as close,
                ):
                    if mode == "complete":
                        guest._prepare_scratch(case_id, record)
                    else:
                        with self.assertRaisesRegex(
                            consumer.NativePathMutationError,
                            "SCRATCH_NOT_FRESH"
                            if mode == "existing"
                            else "SCRATCH_WRITE_INCOMPLETE",
                        ):
                            guest._prepare_scratch(case_id, record)
                workspace.assert_called_once()
                self.assertEqual(workspace.call_args.args[0], consumer.WORKSPACE)
                if mode == "existing":
                    mkdir.assert_not_called()
                    opened.assert_not_called()
                    write.assert_not_called()
                    fsync.assert_not_called()
                    close.assert_not_called()
                    self.assertEqual(record["created"], [])
                    self.assertFalse(record["completed"])
                    continue
                count = 1 if mode == "short" else len(consumer.sources(case_id))
                expected_mkdir = [
                    call(Path(consumer.SCRATCH[case_id]).name, mode=0o700, dir_fd=10)
                ]
                expected_open = [
                    call(
                        Path(consumer.SCRATCH[case_id]).name, directory_flags, dir_fd=10
                    )
                ]
                expected_write = []
                for index in range(count):
                    expected_mkdir.append(
                        call(f"source-{index}", mode=0o700, dir_fd=20)
                    )
                    expected_open.extend(
                        (
                            call(f"source-{index}", directory_flags, dir_fd=20),
                            call("SKILL.md", file_flags, 0o600, dir_fd=21 + 2 * index),
                        )
                    )
                    expected_write.append(call(22 + 2 * index, raw))
                self.assertEqual(mkdir.call_args_list, expected_mkdir)
                self.assertEqual(opened.call_args_list, expected_open)
                self.assertEqual(write.call_args_list, expected_write)
                self.assertEqual(close.call_count, 1 + count * 2)
                if mode == "short":
                    self.assertEqual(len(record["created"]), 3)
                    self.assertEqual(
                        record["created"][-1]["bytes_written"], len(raw) - 1
                    )
                    self.assertFalse(record["completed"])
                    fsync.assert_not_called()
                else:
                    self.assertEqual(record, consumer.preparation(case_id))
                    self.assertEqual(
                        fsync.call_args_list, [call(22 + 2 * i) for i in range(count)]
                    )

    def test_fixed_cases_replay_with_distinct_structural_errno_outcomes(self):
        for case_id, count in zip(consumer.CASES, (11, 6), strict=True):
            value, bindings = _fixture(case_id)
            before = deepcopy(value)
            with self.subTest(case_id=case_id):
                result = _verify(value, bindings)
                self.assertEqual(
                    result["status"], "BOUNDED_PATH_MUTATION_JOINS_VERIFIED"
                )
                self.assertEqual(result["attempts"], count)
                self.assertTrue(
                    all(result[name] is False for name in consumer.FALSE_FLAGS)
                )
                self.assertEqual(value, before)
        self.assertEqual(result["outcomes"], ["PERMISSION_OR_READONLY_DENIAL"] * 6)
        value, bindings = _fixture(consumer.CASES[0])
        self.assertEqual(
            _verify(value, bindings)["outcomes"],
            ["CROSS_MOUNT_RENAME_REFUSED"] * 6 + ["MOUNTPOINT_BUSY"] * 5,
        )
        self.assertEqual(
            consumer.RETARGET_ROOTS[1:3],
            (
                consumer.WORKSPACE + "/.agents",
                "/var/lib/aragorn-agent-gateway/home/.agents",
            ),
        )
        self.assertNotIn("/runtime", consumer.RETARGET_ROOTS)

    def test_success_missing_operands_unexpected_errno_and_partial_cases_refuse(self):
        for case_id in consumer.CASES:
            value, bindings = _fixture(case_id)
            for patch_values in (
                {"attempted": False},
                {"completed": True},
                {"errno": errno.ENOENT},
                {"errno": errno.EINVAL},
                {"errno": True},
                {"readback_failures": ["source_after"]},
                {"source_after": None},
                {"outcome": "POLICY_DENIED"},
            ):
                changed = deepcopy(value)
                changed["attempts"][0].update(patch_values)
                with (
                    self.subTest(case_id=case_id, change=patch_values),
                    self.assertRaises(consumer.NativePathMutationError),
                ):
                    _verify(changed, bindings)
            changed = deepcopy(value)
            changed["attempts"].pop()
            with self.assertRaises(consumer.NativePathMutationError):
                _verify(changed, bindings)
        value, bindings = _fixture(consumer.CASES[1])
        value["attempts"][0].update(
            errno=errno.EXDEV, outcome="CROSS_MOUNT_RENAME_REFUSED"
        )
        with self.assertRaises(consumer.NativePathMutationError):
            _verify(value, bindings)

    def test_payload_source_pins_target_inventory_and_proof_ceilings_fail_closed(self):
        value, bindings = _fixture(consumer.CASES[0])
        for field in consumer.FALSE_FLAGS:
            changed = deepcopy(value)
            changed[field] = True
            with (
                self.subTest(field=field),
                self.assertRaises(consumer.NativePathMutationError),
            ):
                _verify(changed, bindings)
        for field in bindings:
            if field.endswith("digest"):
                with (
                    self.subTest(pin=field),
                    self.assertRaises(consumer.NativePathMutationError),
                ):
                    _verify(value, bindings | {field: _pin("substitution")})
        for change in (
            "payload",
            "retarget",
            "destination",
            "scratch",
            "preparation",
            "old-source",
            "new-source",
        ):
            changed = deepcopy(value)
            for side in ("before", "after"):
                boundary = changed["mutation_" + side]
                if change == "payload":
                    boundary["scratch"]["entries"][1]["digest"] = _pin("wrong-bytes")
                elif change == "retarget":
                    boundary["retargets"].pop(consumer.RETARGET_ROOTS[1])
                elif change == "destination":
                    boundary["destinations"][next(iter(boundary["destinations"]))][
                        "exists"
                    ] = True
                elif change == "scratch":
                    boundary["scratch"]["identity"][3] = 0
                elif change == "old-source":
                    changed[side]["sources"][consumer.shared.PROBE]["digest"] = _pin(
                        "wrong-source"
                    )
                elif change == "new-source":
                    boundary["adapter_sources"][consumer.PROBE]["digest"] = _pin(
                        "wrong-source"
                    )
            if change == "preparation":
                changed["scratch_preparation"]["completed"] = False
            with (
                self.subTest(change=change),
                self.assertRaises(consumer.NativePathMutationError),
            ):
                _verify(changed, bindings)

    def test_one_syscall_preserves_errno_and_independent_operand_postreads(self):
        for case_id, syscall, code in (
            (consumer.CASES[0], "rename", errno.EXDEV),
            (consumer.CASES[1], "symlink", errno.EROFS),
        ):
            value, _ = _fixture(case_id)
            expected = value["attempts"][0]
            operation = consumer.operations(case_id)[0]
            for post_error in (False, True):
                entries = [
                    expected["source_before"],
                    expected["destination_before"],
                    OSError("inert read failure")
                    if post_error
                    else expected["source_after"],
                    expected["destination_after"],
                ]
                with (
                    self.subTest(case=case_id, post_error=post_error),
                    patch.object(guest.readers, "_open", side_effect=[41, 42]),
                    patch.object(guest, "_entry", side_effect=entries) as read,
                    patch.object(
                        guest.os, syscall, side_effect=OSError(code, "inert denial")
                    ) as mutate,
                ):
                    result = guest._attempt(
                        operation,
                        expected["source_before"],
                        expected["destination_before"],
                    )
                mutate.assert_called_once()
                self.assertEqual(read.call_count, 4)
                self.assertEqual(result["errno"], code)
                self.assertFalse(result["completed"])
                self.assertTrue(result["attempted"])
                self.assertEqual(
                    result["destination_after"], expected["destination_after"]
                )
                self.assertEqual(
                    result["readback_failures"], ["source_after"] if post_error else []
                )
                if syscall == "symlink":
                    self.assertEqual(mutate.call_args.args[0], operation["source"])

    def test_same_new_candidate_in_both_catalogues_is_rejected(self):
        for case_id in consumer.CASES:
            for kind in ("skill-info", "skill-list", "gateway-skills"):
                value, bindings = _fixture(case_id)
                for side in ("before", "after"):
                    command = next(
                        row for row in value["commands_" + side] if row["kind"] == kind
                    )
                    response = consumer.parse(command["stdout"].encode())
                    if kind == "skill-info":
                        response["name"] = consumer.NAMES[case_id]
                    else:
                        response["skills"].append({"name": consumer.NAMES[case_id]})
                    raw = canonical_json(response) + b"\n"
                    command.update(
                        stdout=raw.decode(),
                        stdout_bytes=len(raw),
                        stdout_digest=consumer.digest(raw),
                    )
                with (
                    self.subTest(case=case_id, kind=kind),
                    self.assertRaises(consumer.NativePathMutationError),
                ):
                    _verify(value, bindings)

    def test_retarget_snapshot_must_join_each_shared_discovery_root_identity(self):
        for path in set(consumer.RETARGET_ROOTS) & set(consumer.shared.ROOTS):
            value, bindings = _fixture(consumer.CASES[0])
            for side in ("before", "after"):
                value["mutation_" + side]["retargets"][path]["identity"][1] += 100
            attempt = next(row for row in value["attempts"] if row["source"] == path)
            attempt["source_before"]["identity"][1] += 100
            attempt["source_after"]["identity"][1] += 100
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(
                    consumer.NativePathMutationError,
                    "RETARGET_SHARED_ROOT_JOIN_CHANGED",
                ),
            ):
                _verify(value, bindings)

    def test_standalone_isolated_bootstrap_uses_fixed_module_roots(self):
        # Parse source only; never execute the guest's isolated entry point.
        tree = ast.parse(Path(guest.__file__).read_text())
        branch = next(
            node
            for node in tree.body
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Name)
            and node.test.id == "__package__"
        )
        assignment = next(
            node for node in branch.orelse if isinstance(node, ast.Assign)
        )
        self.assertEqual(
            ast.literal_eval(assignment.value), ["/usr/lib/aragorn", "/opt/aragorn"]
        )
        imported = next(node for node in branch.orelse if isinstance(node, ast.Import))
        self.assertEqual(
            imported.names[0].name, "runtime_native_admission_direct_write"
        )
        self.assertLess(branch.orelse.index(assignment), branch.orelse.index(imported))

    def test_failed_guard_prevents_scratch_creation_and_all_mutations(self):
        _, bindings = _fixture(consumer.CASES[0])
        with (
            patch.object(
                guest,
                "_guard",
                side_effect=consumer.NativePathMutationError("INERT_GUARD"),
            ),
            patch.object(guest, "_prepare_scratch") as prepare,
            patch.object(guest, "_attempt") as attempt,
            patch.object(guest.os, "pidfd_open", create=True) as pidfd,
        ):
            result = guest.run_path_mutation_probe(**bindings)
        self.assertEqual(result["status"], "REFUSED")
        prepare.assert_not_called()
        attempt.assert_not_called()
        pidfd.assert_not_called()

    def test_operand_drift_prevents_the_syscall_entirely(self):
        value, _ = _fixture(consumer.CASES[0])
        expected = value["attempts"][0]
        with (
            patch.object(guest.readers, "_open", side_effect=[41, 42]),
            patch.object(guest, "_entry", return_value=expected["destination_before"]),
            patch.object(guest.os, "rename") as mutate,
        ):
            result = guest._attempt(
                consumer.operations(consumer.CASES[0])[0],
                expected["source_before"],
                expected["destination_before"],
            )
        mutate.assert_not_called()
        self.assertFalse(result["attempted"])
        self.assertEqual(result["readback_failures"], ["PRE_MUTATION_OPERANDS"])

    @contextmanager
    def orchestration(
        self, value, *, stop=False, preparation_error=False, post_error=False
    ):
        events, command_index = [], 0
        poller = Mock()
        poller.poll.return_value = []
        boundary = value["mutation_before"]

        def prepare(case_id, record):
            events.append("prepare")
            record.update(deepcopy(value["scratch_preparation"]))
            if preparation_error:
                record["completed"] = False
                raise consumer.NativePathMutationError("INERT_PREPARATION_FAILURE")

        def attempt(*args):
            index = sum(item == "attempt" for item in events)
            events.append("attempt")
            result = deepcopy(value["attempts"][index])
            if stop:
                result.update(completed=True, errno=None, outcome="UNEXPECTED_SUCCESS")
            return result

        def command(*args):
            nonlocal command_index
            index = command_index
            command_index += 1
            events.append("command")
            if post_error and index == 5:
                raise RuntimeError("inert postcommand failure")
            return deepcopy(value["commands_before"][index % 4])

        with ExitStack() as stack:
            for target, name, replacement in (
                (guest, "_guard", {"return_value": "f" * 64}),
                (guest.os, "pidfd_open", {"return_value": 70, "create": True}),
                (guest.os, "close", {}),
                (guest.select, "poll", {"return_value": poller, "create": True}),
                (
                    guest.readers,
                    "_boundary",
                    {"return_value": deepcopy(value["before"])},
                ),
                (
                    guest,
                    "_sources",
                    {"return_value": deepcopy(boundary["adapter_sources"])},
                ),
                (guest, "_scratch", {"return_value": deepcopy(boundary["scratch"])}),
                (
                    guest,
                    "_destinations",
                    {"return_value": deepcopy(boundary["destinations"])},
                ),
                (
                    guest,
                    "_retargets",
                    {"return_value": deepcopy(boundary["retargets"])},
                ),
                (guest, "_prepare_scratch", {"side_effect": prepare}),
                (guest, "_attempt", {"side_effect": attempt}),
                (guest.readers, "_command", {"side_effect": command}),
                (guest.os, "mkdir", {"side_effect": AssertionError("unmocked write")}),
                (
                    guest.os,
                    "rename",
                    {"side_effect": AssertionError("unmocked rename")},
                ),
                (
                    guest.os,
                    "symlink",
                    {"side_effect": AssertionError("unmocked symlink")},
                ),
            ):
                stack.enter_context(patch.object(target, name, **replacement))
            yield events

    def test_orchestration_runs_fixed_case_once_and_keeps_consumer_readbacks(self):
        for case_id in consumer.CASES:
            value, bindings = _fixture(case_id)
            with self.subTest(case=case_id), self.orchestration(value) as events:
                result = guest.run_path_mutation_probe(**bindings)
            self.assertEqual(result["status"], "OBSERVED")
            self.assertEqual(events.count("prepare"), 1)
            self.assertEqual(events.count("attempt"), len(value["attempts"]))
            self.assertEqual(events.count("command"), 8)
            self.assertEqual(result["mutation_before"], result["mutation_after"])
            self.assertTrue(all(result[name] is False for name in consumer.FALSE_FLAGS))

    def test_unexpected_success_stops_later_effects_and_still_retains_after_reads(self):
        value, bindings = _fixture(consumer.CASES[0])
        with self.orchestration(value, stop=True, post_error=True) as events:
            result = guest.run_path_mutation_probe(**bindings)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(events.count("attempt"), 1)
        self.assertEqual(events.count("command"), 8)
        self.assertEqual(len(result["attempts"]), 1)
        self.assertTrue(result["attempts"][0]["completed"])
        self.assertEqual(len(result["commands_after"]), 3)
        self.assertIn("COMMAND_skill-info", result["postcondition_failures"])
        self.assertEqual(result["mutation_after"], value["mutation_after"])
        self.assertEqual(result["after"], value["after"])

    def test_preparation_failure_keeps_original_reason_and_never_attempts_mutation(
        self,
    ):
        value, bindings = _fixture(consumer.CASES[1])
        with self.orchestration(value, preparation_error=True) as events:
            result = guest.run_path_mutation_probe(**bindings)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(
            result["refusal"],
            {"phase": "SCRATCH_PREPARATION", "reason": "INERT_PREPARATION_FAILURE"},
        )
        self.assertEqual(events.count("attempt"), 0)
        self.assertFalse(result["scratch_preparation"]["completed"])
        self.assertEqual(result["mutation_after"], value["mutation_after"])


if __name__ == "__main__":
    unittest.main()
