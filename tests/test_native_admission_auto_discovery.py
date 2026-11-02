"""Inert leaf checks; fabricated records are never live admission evidence."""

import ast
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

from aragorn import native_phase3_admission_auto_discovery as consumer
from aragorn.oci_worker_protocol import canonical_json
from scripts import runtime_native_admission_auto_discovery as guest
from tests.test_native_admission_direct_write import (
    _fixture as direct_fixture,
    _file,
    _pin,
)


def _fixture():
    """Data-only composition of the existing direct boundary and new candidates."""
    old, old_arguments = direct_fixture()
    arguments = {
        key: old_arguments[key]
        for key in (
            "expected_container",
            "expected_gateway_pid",
            "expected_admitted_digest",
        )
    }
    arguments.update(
        expected_probe_digest=_pin("auto-discovery-probe"),
        expected_verifier_digest=_pin("auto-discovery-verifier"),
        expected_shared_probe_digest=old_arguments["expected_probe_digest"],
        expected_shared_verifier_digest=old_arguments["expected_verifier_digest"],
    )
    own = {
        consumer.PROBE: arguments["expected_probe_digest"],
        consumer.VERIFIER: arguments["expected_verifier_digest"],
    }
    parents = {
        path: {
            "identity": [1, 800 + index, 0o40000 | mode, uid, gid],
            "read_only": False,
        }
        for index, (path, (uid, gid, mode)) in enumerate(consumer.PARENTS.items())
    }
    candidates = {}
    for index, path in enumerate(consumer.CANDIDATES):
        raw = consumer.payload(path)
        candidates[path] = {
            "identity": [1, 900 + index * 2, 0o40700, 992, 992, 2, 4096, 8, 9],
            "read_only": False,
            "candidate_absent": True,
            "entries": [
                {
                    "path": "SKILL.md",
                    "kind": "file",
                    "identity": [
                        1,
                        901 + index * 2,
                        0o100600,
                        992,
                        992,
                        1,
                        len(raw),
                        8,
                        9,
                    ],
                    "bytes": len(raw),
                    "digest": consumer.digest(raw),
                }
            ],
        }
    value = {
        "schema": consumer.SCHEMA,
        "authority": consumer.AUTHORITY,
        "case_id": consumer.CASE_ID,
        "status": "OBSERVED",
        "fixture_container": old["fixture_container"],
        "gateway_pid": old["gateway_pid"],
        "admitted_digest": old["admitted_digest"],
        "source_pins": own,
        "shared_source_pins": old["source_pins"],
        "before": old["before"],
        "after": old["after"],
        "sources_before": {path: _file(pin) for path, pin in own.items()},
        "sources_after": {path: _file(pin) for path, pin in own.items()},
        "parents_before": parents,
        "parents_after": deepcopy(parents),
        "candidates_before": {
            path: {"path": path, "exists": False, "identity": None}
            for path in consumer.CANDIDATES
        },
        "creation_attempts": [
            deepcopy(consumer.creation(path, candidates[path]))
            for path in consumer.CANDIDATES
        ],
        "candidates_ready": candidates,
        "candidates_after": deepcopy(candidates),
        "commands_before": old["commands_before"],
        "commands_after": old["commands_after"],
        "refusal": None,
        "postcondition_failures": [],
        "cleanup_failures": [],
        "limitations": list(consumer.LIMITATIONS),
        **dict.fromkeys(consumer.FALSE_FLAGS, False),
    }
    return value, arguments


def _verify(value, arguments):
    raw = canonical_json(value)
    return consumer.verify_native_admission_auto_discovery(
        raw, expected_raw_digest=consumer.digest(raw), **arguments
    )


class NativeAutoDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.value, self.arguments = _fixture()

    def test_exact_complete_inert_observation_and_false_authority_ceilings(self):
        before = deepcopy(self.value)
        result = _verify(self.value, self.arguments)
        self.assertEqual(result["status"], "BOUNDED_AUTO_DISCOVERY_JOINS_VERIFIED")
        self.assertEqual(result["outside_root_candidates"], 2)
        self.assertTrue(all(result[key] is False for key in consumer.FALSE_FLAGS))
        self.assertEqual(self.value, before)
        for path, name in consumer.CANDIDATES.items():
            self.assertNotIn(path, consumer.shared.ROOTS)
            self.assertTrue(
                consumer.payload(path).startswith(
                    ("---\nname: " + name + "\n").encode()
                )
            )

    def test_rehashed_schema_claim_and_scalar_changes_are_refused(self):
        for change in (
            "schema",
            "case",
            "flag",
            "extra",
            "pid_bool",
            "missing_after",
            "partial",
            "cleanup",
        ):
            value = deepcopy(self.value)
            if change == "schema":
                value["schema"] = consumer.shared.SCHEMA
            elif change == "case":
                value["case_id"] = "ADM-02/install"
            elif change == "flag":
                value[consumer.FALSE_FLAGS[0]] = True
            elif change == "extra":
                value["admission_passed"] = True
            elif change == "pid_bool":
                value["gateway_pid"] = True
            elif change == "missing_after":
                value["commands_after"].pop()
            elif change == "partial":
                value["creation_attempts"][0]["bytes_written"] -= 1
            else:
                value["cleanup_failures"] = ["OWNED_DESCRIPTOR_CLOSE_REFUSED"]
            with (
                self.subTest(change=change),
                self.assertRaises(consumer.NativeAutoDiscoveryError),
            ):
                _verify(value, self.arguments)
        with self.assertRaises(consumer.NativeAutoDiscoveryError):
            _verify(self.value, self.arguments | {"expected_gateway_pid": True})

    def test_actual_candidate_bytes_inventory_custody_and_creation_join_are_required(
        self,
    ):
        path = next(iter(consumer.CANDIDATES))
        for change in (
            "bytes",
            "mode",
            "owner",
            "link",
            "extra",
            "replacement",
            "freshness",
            "parent",
        ):
            value = deepcopy(self.value)
            for side in ("ready", "after"):
                candidate = value["candidates_" + side][path]
                item = candidate["entries"][0]
                if change == "bytes":
                    item["digest"] = _pin("substituted valid skill")
                elif change == "mode":
                    item["identity"][2] = 0o100666
                elif change == "owner":
                    candidate["identity"][3] = 0
                elif change == "link":
                    item["identity"][5] = 2
                elif change == "extra":
                    candidate["entries"].append(deepcopy(item))
                elif change == "replacement":
                    candidate["identity"][1] += 20
            if change == "freshness":
                value["candidates_before"][path]["exists"] = True
            elif change == "parent":
                for side in ("before", "after"):
                    value["parents_" + side]["/tmp"]["identity"][2] = 0o40777
            with (
                self.subTest(change=change),
                self.assertRaises(consumer.NativeAutoDiscoveryError),
            ):
                _verify(value, self.arguments)

    def test_coherent_candidate_catalog_substitution_and_shared_boundary_drift_refused(
        self,
    ):
        for kind in ("skill-list", "gateway-skills"):
            for name in consumer.CANDIDATES.values():
                value = deepcopy(self.value)
                for side in ("before", "after"):
                    row = next(
                        row for row in value["commands_" + side] if row["kind"] == kind
                    )
                    document = consumer.parse(row["stdout"].encode())
                    document["skills"].append({"name": name, "eligible": False})
                    raw = canonical_json(document) + b"\n"
                    row.update(
                        stdout=raw.decode(),
                        stdout_bytes=len(raw),
                        stdout_digest=consumer.digest(raw),
                    )
                with (
                    self.subTest(kind=kind, name=name),
                    self.assertRaisesRegex(
                        consumer.NativeAutoDiscoveryError, "CANDIDATE_DISCOVERED"
                    ),
                ):
                    _verify(value, self.arguments)
        for key in ("config", "admitted"):
            value = deepcopy(self.value)
            value["after"][key]["digest"] = _pin("different")
            with (
                self.subTest(key=key),
                self.assertRaises(consumer.NativeAutoDiscoveryError),
            ):
                _verify(value, self.arguments)
        value = deepcopy(self.value)
        value["sources_after"][consumer.PROBE]["identity"][1] += 1
        with self.assertRaises(consumer.NativeAutoDiscoveryError):
            _verify(value, self.arguments)

    @contextmanager
    def orchestration(self, *, create_error=None, after_command_error=False):
        events, created, command_calls = [], [], []
        with ExitStack() as stack:
            stack.enter_context(patch.object(guest, "_guard", return_value="a" * 64))
            stack.enter_context(
                patch.object(guest.os, "pidfd_open", return_value=90, create=True)
            )
            stack.enter_context(patch.object(guest.os, "close"))
            poller = Mock()
            poller.poll.return_value = []
            stack.enter_context(
                patch.object(guest.select, "poll", return_value=poller, create=True)
            )
            stack.enter_context(
                patch.object(
                    guest.readers,
                    "_open",
                    side_effect=lambda path, *_, **__: (
                        10 if path == consumer.WORKSPACE else 11
                    ),
                )
            )
            stack.enter_context(
                patch.object(
                    guest.readers,
                    "_file",
                    side_effect=lambda path, _: deepcopy(
                        self.value["sources_before"][path]
                    ),
                )
            )
            stack.enter_context(
                patch.object(
                    guest,
                    "_parent",
                    side_effect=lambda _, path: deepcopy(
                        self.value["parents_before"][path]
                    ),
                )
            )
            stack.enter_context(
                patch.object(
                    guest,
                    "_absent",
                    side_effect=lambda _, path: deepcopy(
                        self.value["candidates_before"][path]
                    ),
                )
            )

            def boundary(*_):
                events.append("boundary")
                return deepcopy(self.value["before"])

            stack.enter_context(
                patch.object(guest.readers, "_boundary", side_effect=boundary)
            )

            def command(kind, args, token):
                command_calls.append(kind)
                events.append("command-" + kind)
                if after_command_error and len(command_calls) == 6:
                    raise ValueError("inert second postcommand failure")
                return deepcopy(
                    next(
                        row
                        for row in self.value["commands_before"]
                        if row["kind"] == kind
                    )
                )

            stack.enter_context(
                patch.object(guest.readers, "_command", side_effect=command)
            )

            def create(parent, path, expected, record, failures):
                created.append(path)
                events.append("create")
                if create_error:
                    record.update(
                        directory_created=True, file_created=True, bytes_written=1
                    )
                    raise create_error
                record.update(
                    deepcopy(
                        consumer.creation(path, self.value["candidates_ready"][path])
                    )
                )

            creator = stack.enter_context(
                patch.object(guest, "_create", side_effect=create)
            )

            def candidate(path):
                events.append("candidate")
                if create_error and path not in created:
                    raise FileNotFoundError()
                return deepcopy(self.value["candidates_ready"][path])

            stack.enter_context(
                patch.object(guest, "_candidate", side_effect=candidate)
            )
            yield events, created, command_calls, creator

    def test_orchestration_orders_two_creations_between_complete_catalog_snapshots(
        self,
    ):
        with self.orchestration() as (events, created, commands, creator):
            result = guest.run_auto_discovery_probe(**self.arguments)
        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(created, list(consumer.CANDIDATES))
        self.assertEqual(creator.call_count, 2)
        self.assertEqual(commands, [kind for kind, _ in consumer.shared.COMMANDS] * 2)
        self.assertEqual(
            events[: events.index("create")].count("command-gateway-skills"), 1
        )
        self.assertGreater(
            len(events) - 1,
            max(i for i, event in enumerate(events) if event.startswith("command-")),
        )
        self.assertEqual(events[-1], "boundary")
        _verify(result, self.arguments)

    def test_partial_creation_stops_effects_but_reads_all_remaining_catalogs_and_preserves_interrupt(
        self,
    ):
        for error in (OSError("inert short-write failure"), KeyboardInterrupt()):
            with (
                self.subTest(error=type(error).__name__),
                self.orchestration(create_error=error) as (
                    _,
                    created,
                    commands,
                    creator,
                ),
            ):
                if isinstance(error, Exception):
                    result = guest.run_auto_discovery_probe(**self.arguments)
                else:
                    with self.assertRaises(KeyboardInterrupt) as caught:
                        guest.run_auto_discovery_probe(**self.arguments)
                    self.assertIs(caught.exception, error)
                    result = error._native_auto_discovery_observation
            self.assertEqual(creator.call_count, 1)
            self.assertEqual(len(created), 1)
            self.assertEqual(len(commands), 8)
            self.assertEqual(result["status"], "REFUSED")
            self.assertEqual(result["refusal"]["phase"], "CANDIDATE_CREATION")
            self.assertEqual(result["creation_attempts"][0]["bytes_written"], 1)
            self.assertIsNotNone(result["after"])

    def test_later_catalog_failure_keeps_prior_records_and_final_readbacks(self):
        with self.orchestration(after_command_error=True) as (_, _, commands, creator):
            result = guest.run_auto_discovery_probe(**self.arguments)
        self.assertEqual(creator.call_count, 2)
        self.assertEqual(len(commands), 8)
        self.assertEqual(
            [row["kind"] for row in result["commands_after"]],
            ["system-info", "skill-list", "gateway-skills"],
        )
        self.assertEqual(set(result["candidates_after"]), set(consumer.CANDIDATES))
        self.assertIsNotNone(result["after"])
        self.assertIn("COMMAND_AFTER_skill-info", result["postcondition_failures"])
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["refusal"]["phase"], "POSTCONDITIONS")

    def test_parent_and_creation_syscall_custody_is_exclusive_with_no_short_write_retry(
        self,
    ):
        path = next(iter(consumer.CANDIDATES))
        raw = consumer.payload(path)
        fields = guest.readers._FIELDS

        def metadata(mode, inode, size=0):
            return SimpleNamespace(
                **dict(zip(fields, [1, inode, mode, 992, 992, 1, size, 8, 9]))
            )

        directory = metadata(0o40700, 12, 4096)
        file = metadata(0o100600, 13, len(raw))
        for mode in ("existing", "short", "success", "closefailure"):
            row = {
                "path": path,
                "directory_created": False,
                "file_created": False,
                "bytes_written": 0,
                "completed": False,
                "directory_identity": None,
                "file_identity": None,
            }
            failures = []
            with (
                self.subTest(mode=mode),
                patch.object(guest, "_parent", return_value={"expected": True}),
                patch.object(
                    guest, "_absent", return_value={"exists": mode == "existing"}
                ),
                patch.object(guest.os, "mkdir") as mkdir,
                patch.object(guest.os, "open", side_effect=[20, 21]) as opened,
                patch.object(
                    guest.os,
                    "fstat",
                    side_effect=lambda fd: directory if fd == 20 else file,
                ),
                patch.object(
                    guest.os,
                    "stat",
                    side_effect=lambda name, **_: (
                        file if name == "SKILL.md" else directory
                    ),
                ),
                patch.object(
                    guest.os, "write", return_value=1 if mode == "short" else len(raw)
                ) as write,
                patch.object(guest.os, "fsync"),
                patch.object(
                    guest.os,
                    "close",
                    side_effect=[OSError("inert close"), None]
                    if mode == "closefailure"
                    else None,
                ) as close,
            ):
                if mode == "success":
                    guest._create(10, path, {"expected": True}, row, failures)
                else:
                    with self.assertRaises(
                        OSError
                        if mode == "closefailure"
                        else consumer.NativeAutoDiscoveryError
                    ):
                        guest._create(10, path, {"expected": True}, row, failures)
                if mode == "existing":
                    mkdir.assert_not_called()
                    write.assert_not_called()
                    opened.assert_not_called()
                else:
                    mkdir.assert_called_once_with(Path(path).name, 0o700, dir_fd=10)
                    write.assert_called_once_with(21, raw)
                    self.assertEqual(close.call_args_list, [call(21), call(20)])
                    file_open = opened.call_args_list[1]
                    self.assertEqual(file_open.args[0], "SKILL.md")
                    self.assertTrue(file_open.args[1] & guest.os.O_EXCL)
                    self.assertTrue(file_open.args[1] & guest.os.O_NOFOLLOW)
                    self.assertEqual(file_open.args[2], 0o600)
                    self.assertEqual(file_open.kwargs["dir_fd"], 20)
            self.assertEqual(row["completed"], mode in {"success", "closefailure"})
            self.assertEqual(
                row["bytes_written"],
                0 if mode == "existing" else 1 if mode == "short" else len(raw),
            )
            self.assertEqual(
                failures,
                ["CANDIDATE_DESCRIPTOR_CLOSE_REFUSED"]
                if mode == "closefailure"
                else [],
            )

    def test_interrupted_creation_retains_unknown_outcomes_and_acquired_identities(
        self,
    ):
        path = next(iter(consumer.CANDIDATES))
        fields = guest.readers._FIELDS

        def metadata(mode, inode):
            return SimpleNamespace(
                **dict(zip(fields, [1, inode, mode, 992, 992, 1, 0, 8, 9]))
            )

        directory, file = metadata(0o40700, 12), metadata(0o100600, 13)
        for failure in (
            "mkdir",
            "file-open",
            "write",
            "write-interrupt",
            "close-interrupt",
        ):
            row = {
                "path": path,
                "directory_created": False,
                "file_created": False,
                "bytes_written": 0,
                "completed": False,
                "directory_identity": None,
                "file_identity": None,
            }
            failures = []
            interrupted = KeyboardInterrupt()
            write_error = (
                interrupted
                if failure == "write-interrupt"
                else OSError("inert write outcome unknown")
            )
            with (
                self.subTest(failure=failure),
                patch.object(guest, "_parent", return_value={"expected": True}),
                patch.object(guest, "_absent", return_value={"exists": False}),
                patch.object(
                    guest.os,
                    "mkdir",
                    side_effect=OSError("inert mkdir outcome unknown")
                    if failure == "mkdir"
                    else None,
                ) as mkdir,
                patch.object(
                    guest.os,
                    "open",
                    side_effect=[20, OSError("inert create outcome unknown")]
                    if failure == "file-open"
                    else [20, 21],
                ) as opened,
                patch.object(
                    guest.os,
                    "fstat",
                    side_effect=lambda fd: directory if fd == 20 else file,
                ),
                patch.object(guest.os, "stat", return_value=directory),
                patch.object(guest.os, "write", side_effect=write_error) as write,
                patch.object(guest.os, "fsync") as fsync,
                patch.object(
                    guest.os,
                    "close",
                    side_effect=[interrupted, None]
                    if failure == "close-interrupt"
                    else None,
                ) as close,
            ):
                with self.assertRaises(
                    KeyboardInterrupt if failure.endswith("interrupt") else OSError
                ) as caught:
                    guest._create(10, path, {"expected": True}, row, failures)
                mkdir.assert_called_once()
                fsync.assert_not_called()
                self.assertFalse(row["completed"])
                if failure == "mkdir":
                    self.assertIsNone(row["directory_created"])
                    self.assertFalse(row["file_created"])
                    self.assertEqual(row["bytes_written"], 0)
                    opened.assert_not_called()
                    write.assert_not_called()
                    close.assert_not_called()
                elif failure == "file-open":
                    self.assertTrue(row["directory_created"])
                    self.assertIsNone(row["file_created"])
                    self.assertEqual(
                        row["directory_identity"], guest.readers._identity(directory)
                    )
                    self.assertIsNone(row["file_identity"])
                    self.assertEqual(row["bytes_written"], 0)
                    write.assert_not_called()
                    self.assertEqual(close.call_args_list, [call(20)])
                else:
                    self.assertTrue(row["directory_created"])
                    self.assertTrue(row["file_created"])
                    self.assertIsNone(row["bytes_written"])
                    self.assertEqual(
                        row["directory_identity"], guest.readers._identity(directory)
                    )
                    self.assertEqual(
                        row["file_identity"], guest.readers._identity(file)
                    )
                    write.assert_called_once_with(21, consumer.payload(path))
                    self.assertEqual(close.call_args_list, [call(21), call(20)])
                if failure.endswith("interrupt"):
                    self.assertIs(caught.exception, interrupted)
            self.assertEqual(
                failures,
                ["CANDIDATE_DESCRIPTOR_CLOSE_REFUSED"]
                if failure == "close-interrupt"
                else [],
            )

    def test_unregistered_creation_path_is_refused_before_any_filesystem_call(self):
        with (
            patch.object(guest, "_parent") as parent,
            patch.object(guest, "_absent") as absent,
            patch.object(guest.os, "mkdir") as mkdir,
            patch.object(guest.os, "open") as opened,
        ):
            with self.assertRaisesRegex(
                consumer.NativeAutoDiscoveryError, "FIXED_CANDIDATE_REQUIRED"
            ):
                guest._create(10, "/tmp/not-the-held-fixture", {}, {}, [])
        for operation in (parent, absent, mkdir, opened):
            operation.assert_not_called()

    def test_postwrite_object_custody_change_refuses_before_completion(self):
        path = next(iter(consumer.CANDIDATES))
        raw = consumer.payload(path)

        def metadata(mode, inode, size=0):
            return SimpleNamespace(
                **dict(
                    zip(
                        guest.readers._FIELDS, [1, inode, mode, 992, 992, 1, size, 8, 9]
                    )
                )
            )

        for changed in ("directory", "file"):
            directory = metadata(0o40700, 12)
            file = metadata(0o100600, 13)
            after_directory = metadata(
                0o40777 if changed == "directory" else 0o40700, 12
            )
            after_file = metadata(
                0o100666 if changed == "file" else 0o100600, 13, len(raw)
            )
            row = {
                "path": path,
                "directory_created": False,
                "file_created": False,
                "bytes_written": 0,
                "completed": False,
                "directory_identity": None,
                "file_identity": None,
            }
            with (
                self.subTest(changed=changed),
                patch.object(guest, "_parent", return_value={"expected": True}),
                patch.object(guest, "_absent", return_value={"exists": False}),
                patch.object(guest.os, "mkdir"),
                patch.object(guest.os, "open", side_effect=[20, 21]),
                patch.object(
                    guest.os,
                    "fstat",
                    side_effect=[directory, file, after_directory, after_file],
                ),
                patch.object(guest.os, "stat", return_value=directory),
                patch.object(guest.os, "write", return_value=len(raw)) as write,
                patch.object(guest.os, "fsync"),
                patch.object(guest.os, "close") as close,
            ):
                with self.assertRaisesRegex(
                    consumer.NativeAutoDiscoveryError, "CREATED_OBJECT_CUSTODY_CHANGED"
                ):
                    guest._create(10, path, {"expected": True}, row, [])
                self.assertFalse(row["completed"])
                self.assertEqual(row["bytes_written"], len(raw))
                write.assert_called_once()
                self.assertEqual(close.call_args_list, [call(21), call(20)])

    def test_consumer_rejects_unknown_creation_and_coherent_filesystem_substitution(
        self,
    ):
        path = next(iter(consumer.CANDIDATES))
        for change in (
            "directory_created",
            "file_created",
            "bytes_written",
            "file_device",
            "candidate_device",
            "zero_inode",
        ):
            value = deepcopy(self.value)
            if change in {"directory_created", "file_created", "bytes_written"}:
                value["creation_attempts"][0][change] = None
            else:
                for side in ("ready", "after"):
                    candidate = value["candidates_" + side][path]
                    if change == "file_device":
                        candidate["entries"][0]["identity"][0] += 1
                    elif change == "candidate_device":
                        candidate["identity"][0] += 1
                        candidate["entries"][0]["identity"][0] += 1
                    else:
                        candidate["identity"][1] = 0
                value["creation_attempts"][0] = consumer.creation(
                    path, value["candidates_ready"][path]
                )
            with (
                self.subTest(change=change),
                self.assertRaises(consumer.NativeAutoDiscoveryError),
            ):
                _verify(value, self.arguments)

    def test_descriptor_close_interrupt_survives_an_earlier_failure(self):
        failures = []
        interrupt = KeyboardInterrupt()
        try:
            raise ValueError("inert prior failure")
        except ValueError:
            with patch.object(guest.os, "close", side_effect=interrupt) as close:
                with self.assertRaises(KeyboardInterrupt) as caught:
                    guest._close(90, failures)
        self.assertIs(caught.exception, interrupt)
        close.assert_called_once_with(90)
        self.assertEqual(failures, ["OWNED_DESCRIPTOR_CLOSE_REFUSED"])

    def test_parent_modes_and_nonroot_prerequisites_refuse_before_mutation(self):
        for path, (uid, gid, mode) in consumer.PARENTS.items():
            metadata = SimpleNamespace(
                st_dev=1, st_ino=2, st_mode=0o40000 | mode, st_uid=uid, st_gid=gid
            )
            with (
                patch.object(guest.os, "fstat", return_value=metadata),
                patch.object(guest.os, "stat", return_value=metadata),
                patch.object(
                    guest.os, "fstatvfs", return_value=SimpleNamespace(f_flag=0)
                ),
            ):
                self.assertEqual(
                    guest._parent(10, path)["identity"],
                    [1, 2, 0o40000 | mode, uid, gid],
                )
                metadata.st_mode = 0o40777
                with self.assertRaises(consumer.NativeAutoDiscoveryError):
                    guest._parent(10, path)
        with (
            patch.object(guest.sys, "platform", "not-linux"),
            patch.object(guest, "_create") as create,
            patch.object(guest.os, "pidfd_open", create=True) as pidfd,
        ):
            result = guest.run_auto_discovery_probe(**self.arguments)
        create.assert_not_called()
        pidfd.assert_not_called()
        self.assertEqual(result["refusal"]["phase"], "PREREQUISITES")
        for change in (None, "uids", "groups", "caps", "cgroup", "token"):
            status = dict.fromkeys(
                ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"), "0000000000000000"
            )
            status["NoNewPrivs"] = "1"
            if change == "caps":
                status["CapBnd"] = "0000000000000001"
            with (
                self.subTest(guard=change),
                patch.object(guest.sys, "platform", "linux"),
                patch.object(
                    guest.os,
                    "getresuid",
                    return_value=(0, 0, 0) if change == "uids" else (992, 992, 992),
                    create=True,
                ),
                patch.object(
                    guest.os, "getresgid", return_value=(992, 992, 992), create=True
                ),
                patch.object(
                    guest.os,
                    "getgroups",
                    return_value=[992, 997] if change == "groups" else [992],
                ),
                patch.object(guest, "__file__", consumer.PROBE),
                patch.object(consumer, "__file__", consumer.VERIFIER),
                patch.object(guest.readers, "__file__", consumer.shared.PROBE),
                patch.object(consumer.shared, "__file__", consumer.shared.VERIFIER),
                patch.object(guest.readers, "_status", return_value=status),
                patch.object(
                    guest.readers,
                    "_read_proc",
                    return_value=b"0::/other\n"
                    if change == "cgroup"
                    else (
                        "0::/docker/"
                        + self.arguments["expected_container"]
                        + "/init.scope\n"
                    ).encode(),
                ),
                patch.dict(
                    guest.os.environ,
                    {
                        "OPENCLAW_GATEWAY_TOKEN": "secret"
                        if change == "token"
                        else "a" * 64
                    },
                ),
            ):
                if change is None:
                    self.assertEqual(guest._guard(self.arguments), "a" * 64)
                else:
                    with self.assertRaises(consumer.NativeAutoDiscoveryError):
                        guest._guard(self.arguments)

    def test_standalone_bootstrap_and_consumer_have_no_producer_import_or_effects(self):
        source = Path(guest.__file__).read_text()
        tree = ast.parse(source)
        self.assertIn('sys.path[:0] = ["/usr/lib/aragorn", "/opt/aragorn"]', source)
        forbidden = {"unlink", "rmdir", "remove", "rename", "system"}
        self.assertFalse(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in forbidden
                for node in ast.walk(tree)
            )
        )
        consumer_tree = ast.parse(Path(consumer.__file__).read_text())
        imports = [
            node.module or ""
            for node in ast.walk(consumer_tree)
            if isinstance(node, ast.ImportFrom)
        ]
        self.assertFalse(any(name.startswith("scripts") for name in imports))
        self.assertFalse(
            any(
                isinstance(node, ast.Import)
                and any(alias.name in {"os", "subprocess"} for alias in node.names)
                for node in ast.walk(consumer_tree)
            )
        )


if __name__ == "__main__":
    unittest.main()
