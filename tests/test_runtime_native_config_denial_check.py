"""Inert consistency checks only; synthetic records are not captured evidence."""

import copy
import hashlib
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aragorn import runtime_action_broker as broker
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import runtime_native_config_denial_check as subject


def _example():
    grant = {"status": "CONSUMED", "version": 1}
    effects = {
        "target_digest": "sha256:" + "2" * 64,
        "receipt_digest": "sha256:" + "3" * 64,
        "grant_state": {"document": grant},
        "controls": {"health.json": {"epoch": 3}},
    }
    before = {
        "configuration": {"digest": "sha256:" + "4" * 64, "identity": [1, 7]},
        "processes": {"gateway": {"process": {"pid": 42}}},
        "boot_id": "a" * 32,
        "installed": {"skill_digest": "sha256:" + "5" * 64, "denial": None},
        "receipts": {"receipts": [{"sequence": index} for index in range(1, 5)]},
        "effects": effects,
    }
    predecessor = {
        "status": "OBSERVED",
        "fixture_container": "b" * 64,
        "phase3_eligible": False,
        "run_conformance_eligible": False,
        "setup": {
            "configuration_digest": before["configuration"]["digest"],
            "skill_digest": before["installed"]["skill_digest"],
        },
        "processes": copy.deepcopy(before["processes"]),
        "boot_id": before["boot_id"],
        "receipt_store_after_create": copy.deepcopy(before["receipts"]),
        "effect_proof": {
            "target_digest": effects["target_digest"],
            "receipt_digest": effects["receipt_digest"],
            "grant_state_digest": canonical_digest(grant),
        },
    }
    commands = []
    arguments = (
        subject._INFO,
        subject._DISCOVERY,
        subject._UPDATE,
        subject._DISCOVERY,
        subject._INFO,
    )
    for index, args in enumerate(arguments):
        expected = (
            subject._DENIAL
            if index == 2
            else subject._EXPECTED_DISCOVERY
            if index in (1, 3)
            else {"pid": 42}
        )
        commands.append(
            {
                "argv": subject._CLI + args,
                "exit_code": 1 if index == 2 else 0,
                "stdout_bytes": 100,
                "stderr_bytes": 0,
                "started_boottime_ns": 10 * index + 1,
                "completed_boottime_ns": 10 * index + 2,
                "response": copy.deepcopy(expected),
            }
        )
    return {
        "schema": subject._SCHEMA,
        "authority": subject._AUTHORITY,
        "status": "OBSERVED",
        "fixture_container": predecessor["fixture_container"],
        "before": before,
        "after": copy.deepcopy(before),
        "commands": commands,
        **subject._LIMITS,
    }, predecessor


def _set(document, path, value):
    for key in path[:-1]:
        document = document[key]
    document[path[-1]] = value


class NativeConfigDenialCheckTests(unittest.TestCase):
    def test_valid_replay_and_exact_disable_request(self):
        value, predecessor = _example()
        subject.validate(value, predecessor)
        self.assertEqual(
            value["commands"][2]["argv"][-1],
            '{"enabled":false,"skillKey":"template-skill"}',
        )

    def test_rejects_ceiling_state_command_and_chronology_mutations(self):
        mutations = [
            (("authority",), "ADMISSION_QUALIFIED"),
            (("fixture_container",), "c" * 64),
            (("after", "configuration", "identity", 0), True),
            (("after", "effects", "controls", "health.json", "epoch"), 4),
            (("commands",), []),
            (("commands", 2, "exit_code"), True),
            (("commands", 0, "exit_code"), False),
            (("commands", 0, "stderr_bytes"), False),
            (("commands", 0, "stderr_bytes"), 1),
            (("commands", 0, "stdout_bytes"), True),
            (("commands", 0, "stdout_bytes"), 0),
            (("commands", 0, "stdout_bytes"), 65537),
            (("commands", 0, "started_boottime_ns"), True),
            (("commands", 0, "completed_boottime_ns"), 0),
            (("commands", 1, "started_boottime_ns"), 2),
            (("commands", 1, "argv"), subject._CLI + subject._INFO),
            (
                ("commands", 2, "argv", -1),
                '{"enabled":true,"skillKey":"template-skill"}',
            ),
            (("commands", 2, "response", "error", "retryable"), 0),
            (("commands", 2, "response", "error", "message"), "EACCES"),
            (("commands", 4, "response", "pid"), 43),
        ]
        mutations.extend(((key,), True) for key in subject._LIMITS)
        mutations.extend(((key,), 0) for key in subject._LIMITS)
        for path, replacement in mutations:
            with self.subTest(path=path, replacement=replacement):
                value, predecessor = _example()
                _set(value, path, replacement)
                with self.assertRaises(RuntimeError):
                    subject.validate(value, predecessor)

    def test_matching_snapshots_still_require_native_predecessor_joins(self):
        mutations = [
            (("configuration", "digest"), "sha256:" + "9" * 64),
            (("processes", "gateway", "process", "pid"), 43),
            (("boot_id",), "c" * 32),
            (("receipts", "receipts", 0, "sequence"), True),
            (("installed", "skill_digest"), "sha256:" + "9" * 64),
            (("installed", "denial"), {}),
            (("effects", "target_digest"), "sha256:" + "9" * 64),
            (("effects", "receipt_digest"), "sha256:" + "9" * 64),
            (("effects", "grant_state", "document", "version"), True),
        ]
        for path, replacement in mutations:
            with self.subTest(path=path):
                value, predecessor = _example()
                for snapshot in ("before", "after"):
                    _set(value[snapshot], path, replacement)
                with self.assertRaises(RuntimeError):
                    subject.validate(value, predecessor)

    def test_owned_fixture_guard_precedes_imports_and_commands(self):
        guard = Mock(side_effect=RuntimeError("unowned fixture"))
        native = SimpleNamespace(setup_prior=SimpleNamespace(_require_fixture=guard))
        with (
            patch.object(subject.subprocess, "run") as command,
            self.assertRaisesRegex(RuntimeError, "^unowned fixture$"),
        ):
            subject.run_after_native("not-an-owned-fixture", {}, native)
        guard.assert_called_once_with("not-an-owned-fixture")
        command.assert_not_called()

    def test_inert_transport_projects_responses_and_keeps_token_out_of_evidence(self):
        value, predecessor = _example()
        before, secret = value["before"], "INERT-FIXTURE-TOKEN"
        config = {"skills": {"entries": {"template-skill": {"enabled": True}}}}
        predecessor["setup"]["configuration_digest"] = canonical_digest(config)
        predecessor["setup"]["provisioning"] = {"genesis_digest": "sha256:" + "6" * 64}
        module = SimpleNamespace(
            _GATEWAY_CONFIG=Path("/etc/aragorn/agent-gateway/openclaw.json"),
            _GATEWAY_HOME=Path("/fixture/home"),
            _GATEWAY_STATE=Path("/fixture/state"),
            _GATEWAY_WORKSPACE=Path("/fixture/workspace"),
            _TARGET="inert.txt",
            lineage=SimpleNamespace(
                _PROTECTED=Path("/fixture/protected"), _RECEIPT=Path("/fixture/receipt")
            ),
            _snapshot_effects=lambda: copy.deepcopy(before["effects"]),
        )
        contents = {
            module.lineage._PROTECTED / module._TARGET: b"target",
            module.lineage._RECEIPT: b"receipt",
        }
        digest = lambda raw: "sha256:" + hashlib.sha256(raw).hexdigest()
        predecessor["effect_proof"]["target_digest"] = digest(b"target")
        predecessor["effect_proof"]["receipt_digest"] = digest(b"receipt")
        native = Mock()
        native.provision._hold_file.return_value = SimpleNamespace(
            raw=canonical_json(config), identity=(1, 7)
        )
        native.response.broker = broker
        native.response._identities.return_value = (100,)
        native.response._read_regular.side_effect = lambda path, *_: contents[path]
        native.setup_prior._installed.return_value = before["installed"]
        native.prior._processes.return_value = before["processes"]
        native.prior._boot.return_value = before["boot_id"]
        native.prior._digest.side_effect = digest
        native._snapshot.return_value = before["receipts"]
        native._fixture_token.return_value = secret
        outputs = []
        for index, command in enumerate(value["commands"]):
            response = copy.deepcopy(command["response"])
            if index != 2:
                response["not_retained"] = secret
            outputs.append(
                SimpleNamespace(
                    returncode=command["exit_code"],
                    stdout=canonical_json(response),
                    stderr=b"",
                )
            )
        with (
            patch.dict(
                sys.modules, {"runtime_action_worker_openclaw_systemd_probe": module}
            ),
            patch.object(subject.os.path, "lexists", return_value=False),
            patch.object(subject.time, "CLOCK_BOOTTIME", 7, create=True),
            patch.object(subject.time, "clock_gettime_ns", side_effect=range(1, 11)),
            patch.object(subject.subprocess, "run", side_effect=outputs) as run,
        ):
            observed = subject.run_after_native(
                predecessor["fixture_container"], predecessor, native
            )
        subject.validate(observed, predecessor)
        self.assertNotIn(secret, canonical_json(observed).decode())
        self.assertEqual(run.call_count, 5)
        for call, expected in zip(run.call_args_list, value["commands"], strict=True):
            self.assertEqual(call.args[0], expected["argv"])
            self.assertEqual(call.kwargs["env"]["OPENCLAW_GATEWAY_TOKEN"], secret)
            self.assertEqual(
                call.kwargs["env"]["OPENCLAW_CONFIG_PATH"], str(module._GATEWAY_CONFIG)
            )
            self.assertEqual(call.kwargs["cwd"], module._GATEWAY_WORKSPACE)
            self.assertEqual(call.kwargs["timeout"], 15)
            self.assertNotIn(secret, repr(call.args))
        self.assertEqual(native.provision._close.call_count, 2)


if __name__ == "__main__":
    unittest.main()
