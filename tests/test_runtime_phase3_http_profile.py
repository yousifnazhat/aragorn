"""Only new HTTP successor composition and measurement branches; no activation."""

import ast
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import stage_runtime_phase3_http_profile as subject
from test_runtime_http_capability import fixture


class HttpProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original, cls.replacements, cls.inputs = subject._verified_payloads()
        cls.final = cls.original | cls.replacements

    def payload(self, name):
        return self.final[subject._destination(name)[0]][2]

    def test_exact_closure_preserves_frozen_sources_and_only_adds_helpers(self):
        self.assertEqual(len(self.original), 74)
        for name, pin in subject._SOURCE_PINS.items():
            raw = (subject._ROOT / name).read_bytes()
            self.assertEqual((len(raw), subject.base.overlay._digest(raw)), pin)
        self.assertEqual(
            set(self.final) - set(self.original),
            {subject._destination(name)[0] for name in subject._RUNTIME_HELPERS},
        )

    def test_all_successor_python_payloads_compile(self):
        for source, _mode, raw in self.replacements.values():
            if source.endswith(".py"):
                compile(raw, source, "exec")

    def test_generated_native_driver_has_valid_module_syntax_without_execution(self):
        value = subprocess.run(
            ["/opt/homebrew/bin/node", "--input-type=module", "--check"],
            input=self.payload(subject.native_collection.NATIVE_SOURCE),
            capture_output=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(value.returncode, 0, value.stderr.decode())

    def test_units_limit_http_to_owned_broker_loopback(self):
        broker = self.payload(subject._BROKER_UNIT)
        worker = self.payload(subject._WORKER_UNIT)
        self.assertIn(b"PrivateNetwork=no\n", broker)
        self.assertIn(b"RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK\n", broker)
        self.assertIn(b"IPAddressDeny=any\nIPAddressAllow=127.0.0.1/32\n", broker)
        self.assertIn(b"CapabilityBoundingSet=\n", broker)
        self.assertIn(b"PrivateNetwork=yes\n", worker)
        self.assertIn(b"RestrictAddressFamilies=AF_UNIX\n", worker)
        for raw in (worker, broker):
            self.assertIn(
                b"ReadOnlyPaths=/etc/aragorn/runtime-http-fixture.json\n", raw
            )
            self.assertIn(
                b"ConditionPathExists=/etc/aragorn/runtime-http-fixture.json\n", raw
            )
            self.assertIn(b"Restart=no\n", raw)

    def test_activation_guard_precedes_first_service_start_and_all_hashes_match(self):
        raw = self.payload(subject._ACTIVATOR)
        self.assertLess(
            raw.index(subject._EARLY_GUARD), raw.index(b"trap rollback EXIT")
        )
        self.assertLess(raw.index(subject._EARLY_GUARD), raw.index(b"armed=1"))
        self.assertIn(
            b"require_root_secret /etc/aragorn/runtime-broker-decision-measurement.json 8192\n",
            raw,
        )
        self.assertLess(
            raw.index(subject._ACTIVATION_GUARD),
            raw.index(subject.predecessor._ACTIVATION_ANCHOR),
        )
        for name in subject._RUNTIME_HELPERS:
            destination, mode = subject._destination(name)
            pin = subject.base.overlay._digest(self.payload(name))[7:]
            self.assertEqual(raw.count(f"{mode:o} {pin} /{destination}\n".encode()), 1)
        for name, _mode, payload in self.replacements.values():
            if name == subject._ACTIVATOR:
                continue
            if name in {value[0] for value in self.original.values()}:
                old = next(
                    value[2] for value in self.original.values() if value[0] == name
                )
                old_pin = subject.base.overlay._digest(old)[7:].encode()
                self.assertNotIn(old_pin, raw)
        self.assertEqual(
            subprocess.run(
                ["/bin/sh", "-n"],
                input=raw,
                capture_output=True,
                timeout=5,
                check=False,
            ).returncode,
            0,
        )

    def test_writer_planner_and_verifier_have_identical_extended_source_inventory(self):
        inventories = []
        for name in (
            subject._MEASUREMENT,
            subject.collection.PLAN,
            subject.collection.PRIOR,
        ):
            parsed = ast.parse(self.payload(name))
            assignment = next(
                node
                for node in parsed.body
                if isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "_SOURCES"
                    for target in node.targets
                )
            )
            inventories.append(ast.literal_eval(assignment.value))
        self.assertEqual(inventories[0], inventories[1])
        self.assertEqual(inventories[1], inventories[2])
        self.assertEqual(len(inventories[0]), 21)

    def test_only_measurement_role_can_use_extended_credential_bound(self):
        module = ModuleType("aragorn._http_credential_reader_test")
        module.__package__ = "aragorn"
        exec(
            compile(
                self.payload(subject._CREDENTIAL_READER),
                subject._CREDENTIAL_READER,
                "exec",
            ),
            module.__dict__,
        )
        raw = b"x" * 5000
        metadata = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o400,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_size=len(raw),
        )
        fake = SimpleNamespace(
            O_RDONLY=0,
            O_NOFOLLOW=1,
            O_CLOEXEC=2,
            open=Mock(return_value=10),
            read=Mock(return_value=raw),
            fstat=Mock(return_value=metadata),
            close=Mock(),
        )
        with (
            patch.object(module, "os", fake),
            patch.object(module, "_file_identity", return_value=(1,)),
        ):
            with self.assertRaises(module.RuntimeActionServiceError):
                module._read_credential_bytes(
                    Path("/inert"), 997, label="runtime binding"
                )
            fake.read.assert_not_called()
            self.assertEqual(
                module._read_credential_bytes(
                    Path("/inert"),
                    997,
                    label="decision measurement binding",
                    max_bytes=8192,
                ),
                raw,
            )
            with self.assertRaises(module.RuntimeActionServiceError):
                module._read_credential_bytes(
                    Path("/inert"), 997, label="runtime binding", max_bytes=8192
                )
        self.assertIn(
            b'label="decision measurement binding", max_bytes=8192',
            self.payload(subject._MEASUREMENT_SERVICE),
        )

    def test_measurement_begin_retains_real_http_profiled_submission(self):
        from aragorn import runtime_action_broker_v4 as v4

        name = "aragorn._http_measurement_writer_test"
        module = ModuleType(name)
        module.__package__ = "aragorn"
        self.enterContext(patch.dict(sys.modules, {name: module}))
        exec(
            compile(self.payload(subject._MEASUREMENT), subject._MEASUREMENT, "exec"),
            module.__dict__,
        )
        _binding, profiled, grant = fixture()
        request = profiled["envelope"]["request"]
        plan = {
            **{key: request[key] for key in module._MATCH},
            "boot_id": "held-boot",
            "grant_digest": canonical_digest(grant),
            "runtime_profile_digest": profiled["runtime_attribution"]["profile_digest"],
            "sensor_digest": profiled["sensor_digest"],
        }
        module._PLAN = plan
        module._PROCESS = {"boot_id": "held-boot"}
        self.enterContext(
            patch.object(module, "_identity", return_value=module._PROCESS)
        )
        self.enterContext(patch.object(module, "_stamp", return_value=10))
        self.enterContext(patch.object(module, "_sources"))
        self.enterContext(patch.object(module, "_inputs"))
        self.enterContext(patch.object(v4, "_with_profile_lock"))
        config = SimpleNamespace(
            broker=SimpleNamespace(
                broker=SimpleNamespace(
                    control_root=module._ROOT,
                    expected_runtime_digest=request["runtime_digest"],
                ),
                expected_runtime_profile_digest=plan["runtime_profile_digest"],
            )
        )
        legacy = {**profiled, "schema": "aragorn/runtime-observed-http-submission/v1"}
        legacy.pop("runtime_attribution")
        trace = module.begin(
            config,
            grant,
            legacy,
            profiled["runtime_attribution"],
            canonical_digest(profiled),
            {"lease": "inert"},
            1.0,
        )
        self.assertEqual(trace.profiled_submission_raw, canonical_json(profiled))
        self.assertEqual(trace.pending["submission_digest"], canonical_digest(profiled))
        module._CURRENT.reset(trace.token)

    def test_pin_tamper_refuses_before_staging(self):
        name = next(iter(subject._SOURCE_PINS))
        pins = {**subject._SOURCE_PINS, name: (0, "sha256:" + "0" * 64)}
        with patch.object(subject, "_SOURCE_PINS", pins):
            with self.assertRaises(ValueError):
                subject._verified_payloads()

    def test_inert_stage_audits_new_inventory_without_claiming_activation(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "http"
            report = subject.stage_runtime_phase3_http_profile(output)
            self.assertEqual(report["schema"], subject._SCHEMA)
            self.assertTrue(report["http_paths_staged"])
            for flag in (
                "http_fixture_provisioned",
                "http_runtime_activated",
                "http_collected",
                "phase3_qualification",
                "measurement_collected",
                "run_qualification",
            ):
                self.assertIs(report[flag], False)
            self.assertEqual(len(report["files"]), len(self.final))
            self.assertEqual(
                report["directories"], sorted(subject.base._directories(self.final))
            )
            for path, (_source, mode, raw) in self.final.items():
                self.assertEqual((output / path).read_bytes(), raw)
                self.assertEqual((output / path).stat().st_mode & 0o777, mode)
            self.assertEqual(len(report["binding_source_pins"]), 21)
            configuration = self.payload(subject.ingress.GATEWAY_CONFIG)
            self.assertEqual(
                canonical_json(__import__("json").loads(configuration)), configuration
            )
            self.assertEqual(
                report["gateway_config_digest_required_not_included"],
                subject.base.overlay._digest(configuration),
            )
            with self.assertRaises(subject.Phase3HttpStageError):
                subject.stage_runtime_phase3_http_profile(output)


if __name__ == "__main__":
    unittest.main()
