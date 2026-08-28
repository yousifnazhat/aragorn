from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from scripts import materialize_fixed_admission_probes as probe_materializer

_ROOT = Path(__file__).resolve().parents[1]
_SHIM = _ROOT / "packaging/libexec/aragorn-runtime-action-worker-service.py"
_UNIT = _ROOT / "packaging/systemd/aragorn-runtime-action-worker.service"
_SYSUSERS = _ROOT / "packaging/systemd/aragorn-runtime-action-worker.sysusers"
_DRIVER = (
    _ROOT
    / "benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs"
)
_DOCKERFILE = _ROOT / "benchmark/runtime-action-worker-openclaw-systemd/Dockerfile"
_CAPTURE = _ROOT / "scripts/capture_runtime_action_worker_openclaw_systemd.sh"
_PROBE = _ROOT / "scripts/runtime_action_worker_openclaw_systemd_probe.py"
_ACTIVATOR = _ROOT / "packaging/activate-runtime-action-worker-host.sh"
_FINAL_PROFILES = _ROOT / "benchmark/admission/openclaw-v2026.7.1"
_FINAL_V3_DOCKERFILE = (
    _ROOT
    / "benchmark/runtime-action-worker-final-combined-v3-plugin-force-reinstall-systemd/Dockerfile"
)
_FINAL_V3_PLUGIN_ENABLE_DOCKERFILE = (
    _ROOT
    / "benchmark/runtime-action-worker-final-combined-v3-plugin-enable-systemd/Dockerfile"
)
_FINAL_V3_CONFIG_ENTRY_ACTIVATION_DOCKERFILE = (
    _ROOT
    / "benchmark/runtime-action-worker-final-combined-v3-config-entry-activation-systemd/Dockerfile"
)
_FINAL_V3_WORKSHOP_PROPOSAL_APPLY_DOCKERFILE = (
    _ROOT
    / "benchmark/runtime-action-worker-final-combined-v3-workshop-proposal-apply-systemd/Dockerfile"
)


class RuntimeActionWorkerPackagingTests(unittest.TestCase):
    def test_final_v2_profile_is_canonical_and_unqualified(self) -> None:
        expected = {
            "protected-final-combined-config-v2.json": (
                1881,
                "d145feb4e935e6f86c7e2bfdeefcaec5fa4ebf8f044ffa472bd7589b03bf4fe8",
            ),
            "protected-final-combined-profile-v2.json": (
                4951,
                "615928c74bb467ed1422aa19c0ca3266fec21e6a9b195ff32e7e2fae86f966fc",
            ),
            "protected-final-combined-runtime-v2.lock.json": (
                6742,
                "4832dc99c016bd8c0f6d97133dbb7d3681d4ad18c1c225c94f10a51d6df839c1",
            ),
        }
        documents = {}
        for name, (size, digest) in expected.items():
            raw = (_FINAL_PROFILES / name).read_bytes()
            document = json.loads(raw)
            canonical = json.dumps(
                document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
            self.assertEqual(raw, canonical + b"\n")
            self.assertEqual(
                (len(raw), hashlib.sha256(raw).hexdigest()), (size, digest)
            )
            documents[name] = document

        config, profile, lock = documents.values()
        self.assertEqual(config["skills"]["allowBundled"], ["template-skill"])
        self.assertEqual(
            config["tools"],
            {
                "alsoAllow": ["aragorn_runtime_create", "read"],
                "deny": ["session_status"],
                "fs": {"workspaceOnly": True},
                "profile": "minimal",
            },
        )
        self.assertEqual(len(profile["routes"]), 21)
        self.assertTrue(
            all(route["outcome"] == "NOT_TESTED" for route in profile["routes"])
        )
        self.assertTrue(
            all(
                value is False
                for key, value in profile["decision"].items()
                if key.endswith("_eligible")
            )
        )
        self.assertTrue(
            all(
                value is False
                for key, value in lock["decision"].items()
                if key.endswith("_eligible")
            )
        )
        activation = lock["deployment_bindings"]["activation_contract"]
        self.assertEqual(
            activation["activator"]["digest"],
            "sha256:" + hashlib.sha256(_ACTIVATOR.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            activation["preflight"]["digest"],
            "sha256:"
            + hashlib.sha256(
                (_ROOT / "src/aragorn/runtime_action_worker.py").read_bytes()
            ).hexdigest(),
        )
        self.assertEqual(
            activation["tool_policy"],
            {
                "also_allow": ["aragorn_runtime_create", "read"],
                "deny": ["session_status"],
                "filesystem_workspace_only": True,
                "profile": "minimal",
            },
        )

    def test_final_v3_profile_adds_only_the_native_plugin_install_block(self) -> None:
        expected = {
            "protected-final-combined-config-v3.json": (
                2160,
                "2855474d8b709654fb8902c0dc69ec1f0a3a378518ec23bfb12c1eb9630824ab",
            ),
            "protected-final-combined-profile-v3.json": (
                5302,
                "3229bd747088199d8bae074bbc27a415169fa21f86462408434ecdb43c5b2a6c",
            ),
            "protected-final-combined-runtime-v3.lock.json": (
                7620,
                "3bbcc6568cf713f9e534f84f7a92e313b5aa357065759bd01b5f24a594fb5822",
            ),
        }
        documents = {}
        for name, identity in expected.items():
            raw = (_FINAL_PROFILES / name).read_bytes()
            document = json.loads(raw)
            canonical = json.dumps(
                document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
            self.assertEqual(raw, canonical + b"\n")
            self.assertEqual(
                (len(raw), hashlib.sha256(raw).hexdigest()), identity
            )
            documents[name] = document

        config, profile, lock = documents.values()
        policy = {
            "enabled": True,
            "exec": {
                "args": [
                    "%s",
                    '{"protocolVersion":1,"decision":"block","reason":'
                    '"plugin installs disabled by Aragorn protected profile"}',
                ],
                "command": "/usr/bin/printf",
                "source": "exec",
                "trustedDirs": ["/usr/bin"],
            },
            "targets": ["plugin"],
        }
        self.assertEqual(config["security"]["installPolicy"], policy)
        self.assertEqual(len(profile["routes"]), 21)
        self.assertTrue(
            all(route["outcome"] == "NOT_TESTED" for route in profile["routes"])
        )
        self.assertTrue(
            all(
                value is False
                for key, value in profile["decision"].items()
                if key.endswith("_eligible")
            )
        )
        binding = lock["deployment_bindings"]
        self.assertIs(binding["plugin_install_policy"]["enabled"], True)
        self.assertEqual(binding["plugin_install_policy"]["exec"], policy["exec"])
        self.assertEqual(binding["plugin_install_policy"]["targets"], ["plugin"])
        self.assertEqual(
            binding["activation_contract"]["activator"]["digest"],
            "sha256:3b25b462cf7f9c4886cce1b7057fabbaeb95e9d9de83cb33db9c7ca62f15d86c",
        )
        self.assertEqual(
            binding["configuration"]["canonical_digest"],
            "sha256:dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c",
        )
        old = b"b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e"
        new = b"dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c"
        activator = _ACTIVATOR.read_bytes()
        self.assertEqual(activator.count(old), 1)
        self.assertEqual(activator.count(new), 0)
        transformed = activator.replace(old, new)
        self.assertEqual(len(transformed), 30_504)
        self.assertEqual(
            hashlib.sha256(transformed).hexdigest(),
            "3b25b462cf7f9c4886cce1b7057fabbaeb95e9d9de83cb33db9c7ca62f15d86c",
        )
        dockerfile = _FINAL_V3_DOCKERFILE.read_text(encoding="utf-8")
        pins = (old.decode(), new.decode(), hashlib.sha256(transformed).hexdigest())
        for pin in pins:
            self.assertIn(pin, dockerfile)
        self.assertEqual(lock["decision"]["status"], "BUILD_LOCKED_NOT_QUALIFIED")
        self.assertTrue(
            all(
                value is False
                for key, value in lock["decision"].items()
                if key.endswith("_eligible")
            )
        )

    def test_final_v3_plugin_enable_image_transforms_one_exact_probe(self) -> None:
        source = (_FINAL_PROFILES / "protected-plugin-enable-probe.mjs").read_bytes()
        old_digest = b"b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e"
        new_digest = b"dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c"
        replacements = (
            (old_digest, new_digest, 2, 0),
            (b"file.size === 1880", b"file.size === 2159", 1, 0),
            (
                b"current_v2_configuration_pinned",
                b"current_v3_configuration_pinned",
                1,
                0,
            ),
        )
        self.assertEqual(
            (len(source), hashlib.sha256(source).hexdigest()),
            (
                23_594,
                "b31dc052d9eaffb4712de2a716f958afeb54399452aaaf47a714ee216da1ed92",
            ),
        )
        transformed = source
        for old, new, old_count, new_count in replacements:
            self.assertEqual(
                (source.count(old), source.count(new)), (old_count, new_count)
            )
            transformed = transformed.replace(old, new)
        self.assertEqual(
            (len(transformed), hashlib.sha256(transformed).hexdigest()),
            (
                23_594,
                "5b4f38b55770f51071f467072f186a316feb8ea0373c5621a6ceb3e7edb4489a",
            ),
        )
        for old, new, old_count, _new_count in replacements:
            self.assertEqual(
                (transformed.count(old), transformed.count(new)), (0, old_count)
            )

        dockerfile = _FINAL_V3_PLUGIN_ENABLE_DOCKERFILE.read_text(encoding="utf-8")
        self.assertEqual(dockerfile.count("0:0:600:1:23594"), 1)
        self.assertEqual(
            dockerfile.count(
                'test "$V3_FORCE_BASE" = \\\n'
                '        "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f";'
            ),
            1,
        )
        self.assertEqual(dockerfile.count("FROM ${V3_FORCE_BASE}"), 1)
        for name, size, digest in (
            (
                "protected-final-combined-config-v3.json",
                2_160,
                "2855474d8b709654fb8902c0dc69ec1f0a3a378518ec23bfb12c1eb9630824ab",
            ),
            (
                "protected-final-combined-profile-v3.json",
                5_302,
                "3229bd747088199d8bae074bbc27a415169fa21f86462408434ecdb43c5b2a6c",
            ),
            (
                "protected-final-combined-runtime-v3.lock.json",
                7_620,
                "3bbcc6568cf713f9e534f84f7a92e313b5aa357065759bd01b5f24a594fb5822",
            ),
        ):
            self.assertEqual(dockerfile.count(digest), 1)
            self.assertEqual(dockerfile.count(f"/{name})\" = {size};"), 1)
        self.assertEqual(
            dockerfile.count(
                "2c7b0151ee3c1ba4e829209f2ff4336de9d97143e22bf87c7448539112139957"
            ),
            1,
        )
        self.assertEqual(dockerfile.count("'regular file:0:0:755:1:68480'"), 1)
        self.assertEqual(
            dockerfile.count(
                "5b4f38b55770f51071f467072f186a316feb8ea0373c5621a6ceb3e7edb4489a"
            ),
            2,
        )
        for check in (
            'test "$(grep -F -o "$old" "$source" | wc -l)" = 2;',
            'test "$(grep -F -o "$new" "$source" | wc -l)" = 0;',
            'test "$(grep -F -o \'file.size === 1880\' "$source" | wc -l)" = 1;',
            'test "$(grep -F -o \'file.size === 2159\' "$source" | wc -l)" = 0;',
            'test "$(grep -F -o \'current_v2_configuration_pinned\' "$source" | wc -l)" = 1;',
            'test "$(grep -F -o \'current_v3_configuration_pinned\' "$source" | wc -l)" = 0;',
            "find /route-input -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +;",
            "install -d -m 0555 /route-input/plugin-enable-activation;",
            "'plugin-enable-activation:d'",
            "'plugin-enable-activation/protected-plugin-enable-v3-probe.mjs:f'",
        ):
            self.assertEqual(dockerfile.count(check), 1)
        self.assertEqual(
            dockerfile.count(
                'install -m 0444 "$target" \\\n'
                "        /route-input/plugin-enable-activation/"
                "protected-plugin-enable-v3-probe.mjs;"
            ),
            1,
        )
        self.assertNotIn("/route-input/plugin-force-reinstall", dockerfile)

    def test_final_v3_config_activation_materializes_then_rebinds_one_probe(
        self,
    ) -> None:
        name = "protected-config-activation-probe.mjs"
        source = (_FINAL_PROFILES / name).read_bytes()
        self.assertEqual(
            (len(source), hashlib.sha256(source).hexdigest()),
            (
                20_622,
                "49c9c173cf6214a16e77e6cf5084c7cb91f8fd5c2e0b8555612d8c1174de2234",
            ),
        )
        materialized = probe_materializer.transformed_final_combined_v2_probe(name)
        self.assertEqual(
            (len(materialized), hashlib.sha256(materialized).hexdigest()),
            (
                23_366,
                "69a2c203e566128a2968b35b85b130cd50107b3ba9367512a50e56e73e65ca93",
            ),
        )
        old = b"b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e"
        new = b"dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c"
        old_size = b"configuration.file?.size === 1880"
        new_size = b"configuration.file?.size === 2159"
        self.assertEqual(
            (materialized.count(old), materialized.count(new)),
            (3, 0),
        )
        self.assertEqual(
            (materialized.count(old_size), materialized.count(new_size)),
            (1, 0),
        )
        transformed = materialized.replace(old, new).replace(old_size, new_size)
        self.assertEqual(
            (len(transformed), hashlib.sha256(transformed).hexdigest()),
            (
                23_366,
                "e577e5e6cd769bc24886b976792499f06fd6c279f3df24b7f17b652a08e66db5",
            ),
        )
        self.assertEqual(
            (
                transformed.count(old),
                transformed.count(new),
                transformed.count(old_size),
                transformed.count(new_size),
            ),
            (0, 3, 0, 1),
        )

        dockerfile = _FINAL_V3_CONFIG_ENTRY_ACTIVATION_DOCKERFILE.read_text(
            encoding="utf-8"
        )
        self.assertEqual(dockerfile.count("FROM ${V3_FORCE_BASE}"), 1)
        self.assertEqual(
            dockerfile.count(
                'test "$V3_FORCE_BASE" = \\\n'
                '        "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f";'
            ),
            1,
        )
        for value in (
            "49c9c173cf6214a16e77e6cf5084c7cb91f8fd5c2e0b8555612d8c1174de2234",
            "0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec",
            "69a2c203e566128a2968b35b85b130cd50107b3ba9367512a50e56e73e65ca93",
            "e577e5e6cd769bc24886b976792499f06fd6c279f3df24b7f17b652a08e66db5",
            "configuration.file?.size === 1880",
            "configuration.file?.size === 2159",
            "/route-input/config-entry-activation/protected-config-activation-v3-probe.mjs",
        ):
            self.assertIn(value, dockerfile)
        for check in (
            'test "$(grep -F -o "$old" "$v2" | wc -l)" = 3;',
            'test "$(grep -F -o "$new" "$v2" | wc -l)" = 0;',
            (
                "-e 's/configuration.file?.size === 1880/"
                "configuration.file?.size === 2159/'"
            ),
            "'config-entry-activation:d'",
            "'config-entry-activation/protected-config-activation-v3-probe.mjs:f'",
        ):
            self.assertEqual(dockerfile.count(check), 1)
        self.assertNotIn("config-entry-activation-activation", dockerfile)
        self.assertNotIn("protected-config-entry-activation", dockerfile)

    def test_final_v3_workshop_materializes_then_rebinds_exact_bundle(self) -> None:
        name = "protected-route-probe.mjs"
        source = (_FINAL_PROFILES / name).read_bytes()
        proposal = (
            _ROOT / "benchmark/fixtures/phase1-protected-workshop/PROPOSAL.md"
        ).read_bytes()
        self.assertEqual(
            (len(source), hashlib.sha256(source).hexdigest()),
            (
                34_185,
                "3d9615bbfae6c86b272c862de2faaf55f24cc7018a5e77f912f2b4f527162504",
            ),
        )
        self.assertEqual(
            (len(proposal), hashlib.sha256(proposal).hexdigest()),
            (
                84,
                "a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a",
            ),
        )
        materialized = probe_materializer.transformed_final_combined_v2_probe(
            name, workshop=True
        )
        self.assertEqual(
            (len(materialized), hashlib.sha256(materialized).hexdigest()),
            (
                50_175,
                "07676570b96d8c0c54f40bd44f4132a2cdb06cb36002dd6f6c406f49afc3a705",
            ),
        )
        old = b"b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e"
        new = b"dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c"
        old_size = b"configuration.file?.size === 1880"
        new_size = b"configuration.file?.size === 2159"
        self.assertEqual(
            (
                materialized.count(old),
                materialized.count(new),
                materialized.count(old_size),
                materialized.count(new_size),
            ),
            (2, 0, 1, 0),
        )
        transformed = materialized.replace(old, new).replace(old_size, new_size)
        self.assertEqual(
            (len(transformed), hashlib.sha256(transformed).hexdigest()),
            (
                50_175,
                "667dec03c90ff0df1567e8dcca9d4137f66d0de8e3f7f302f6fc279f311b2780",
            ),
        )
        self.assertEqual(
            (
                transformed.count(old),
                transformed.count(new),
                transformed.count(old_size),
                transformed.count(new_size),
            ),
            (0, 2, 0, 1),
        )

        dockerfile = _FINAL_V3_WORKSHOP_PROPOSAL_APPLY_DOCKERFILE.read_text(
            encoding="utf-8"
        )
        self.assertEqual(dockerfile.count("FROM ${V3_FORCE_BASE}"), 1)
        self.assertEqual(
            dockerfile.count(
                'test "$V3_FORCE_BASE" = \\\n'
                '        "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f";'
            ),
            1,
        )
        for value in (
            "3d9615bbfae6c86b272c862de2faaf55f24cc7018a5e77f912f2b4f527162504",
            "a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a",
            "07676570b96d8c0c54f40bd44f4132a2cdb06cb36002dd6f6c406f49afc3a705",
            "667dec03c90ff0df1567e8dcca9d4137f66d0de8e3f7f302f6fc279f311b2780",
            "/route-input/workshop-proposal-apply/PROPOSAL.md",
            "/route-input/workshop-proposal-apply/protected-route-probe.mjs",
        ):
            self.assertIn(value, dockerfile)
        for check in (
            'test "$(grep -F -o "$old" "$v2" | wc -l)" = 2;',
            'test "$(grep -F -o "$new" "$v3" | wc -l)" = 2;',
            "PROPOSAL.md protected-route-probe.mjs;",
            "'workshop-proposal-apply/PROPOSAL.md:f'",
            "'workshop-proposal-apply/protected-route-probe.mjs:f'",
        ):
            self.assertEqual(dockerfile.count(check), 1)

    def test_worker_activator_local_digest_pins_match_sources(self) -> None:
        source = _ACTIVATOR.read_text(encoding="utf-8")
        block = source.split("done <<'EOF'\n", 1)[1].split("\nEOF", 1)[0]
        pins = {
            installed: digest
            for _mode, digest, installed in (
                line.split(" ", 2) for line in block.splitlines()
            )
            if installed not in {"/usr/local/bin/node", "/usr/local/bin/python3.12"}
        }
        self.assertEqual(len(pins), 36)
        for installed, expected in pins.items():
            name = Path(installed).name
            if installed == "/usr/libexec/aragorn/activate-runtime-capability-host.sh":
                candidate = _ROOT / "packaging/activate-runtime-capability-host.sh"
            elif installed.startswith("/usr/libexec/aragorn/"):
                candidate = _ROOT / "packaging/libexec" / name
            elif installed.startswith("/usr/lib/aragorn/aragorn/"):
                candidate = _ROOT / "src/aragorn" / name
            else:
                candidate = (
                    _ROOT / "packaging/openclaw/aragorn-runtime-action-worker" / name
                )
            self.assertEqual(
                hashlib.sha256(candidate.read_bytes()).hexdigest(), expected
            )

    def test_shim_and_identity_are_additive_and_fixed(self) -> None:
        shim = _SHIM.read_text(encoding="utf-8")
        self.assertIn('import_module("aragorn.runtime_action_worker").main()', shim)
        self.assertEqual(
            _SYSUSERS.read_text(encoding="utf-8"),
            "g aragorn-agent-gateway -\n"
            'u aragorn-agent-gateway - "Aragorn agent gateway state" '
            "/nonexistent /usr/sbin/nologin\n",
        )

    def test_worker_unit_has_only_the_bounded_relay_authority(self) -> None:
        unit = _UNIT.read_text(encoding="utf-8")
        for directive in (
            (
                "After=local-fs.target nss-user-lookup.target "
                "aragorn-runtime-lineage-capability-observation-publisher.service"
            ),
            "Requires=aragorn-runtime-lineage-capability-observation-publisher.service",
            "User=aragorn-runtime",
            "Group=aragorn-runtime",
            "SupplementaryGroups=aragorn-agent-gateway",
            "RuntimeDirectory=aragorn-runtime-action-worker",
            "RuntimeDirectoryMode=0711",
            "LoadCredential=worker-binding:/etc/aragorn/runtime-action-worker.json",
            (
                "ExecStart=/usr/bin/python3.12 -I -S -B "
                "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py "
                "%d/worker-binding"
            ),
            "NoNewPrivileges=yes",
            "AmbientCapabilities=\n",
            "CapabilityBoundingSet=\n",
            "PrivateNetwork=yes",
            "RestrictAddressFamilies=AF_UNIX",
            "ProtectSystem=strict",
            "PrivateMounts=yes",
            (
                "ReadOnlyPaths=/var/lib/aragorn-runtime-action/protected "
                "/var/lib/aragorn-protected/skills"
            ),
            "/var/lib/aragorn-runtime-action/control",
            "/var/lib/aragorn-runtime-action/staging",
            "/etc/aragorn/runtime-action-observation.json",
            "/etc/aragorn/runtime-capability-grant.json",
            "/var/lib/aragorn-openclaw-profile",
            "InaccessiblePaths=-/profile/config -/profile/state -/profile/workspace",
            "ReadOnlyPaths=-/opt/aragorn/runtime-profile",
        ):
            self.assertIn(directive, unit)
        self.assertEqual(
            [line for line in unit.splitlines() if line.startswith("LoadCredential=")],
            ["LoadCredential=worker-binding:/etc/aragorn/runtime-action-worker.json"],
        )
        self.assertEqual(
            [
                line
                for line in unit.splitlines()
                if line.startswith("InaccessiblePaths=")
            ],
            [
                (
                    "InaccessiblePaths=/etc/aragorn/runtime-action-worker.json "
                    "/etc/aragorn/runtime-action-runtime.json "
                    "/etc/aragorn/runtime-action-observation.json "
                    "/etc/aragorn/runtime-capability-grant.json "
                    "/var/lib/aragorn-runtime-action/control "
                    "/var/lib/aragorn-runtime-action/staging"
                ),
                (
                    "InaccessiblePaths=-/etc/aragorn/agent-gateway "
                    "-/etc/aragorn/openclaw-profile "
                    "-/var/lib/aragorn-agent-gateway "
                    "-/var/lib/aragorn-openclaw-profile "
                    "-/var/lib/aragorn-gateway"
                ),
                "InaccessiblePaths=-/profile/config -/profile/state -/profile/workspace",
            ],
        )
        self.assertNotIn("SupplementaryGroups=aragorn-sensor", unit)
        self.assertNotIn("LoadCredential=observation-binding:", unit)
        self.assertNotIn("LoadCredential=capability-grant:", unit)
        self.assertNotIn("ReadWritePaths=/var/lib/aragorn-runtime-action", unit)

    def test_openclaw_driver_uses_replay_stable_ids_and_nested_result_authority(
        self,
    ) -> None:
        driver = _DRIVER.read_text(encoding="utf-8")
        for claim in (
            "const value = `aragorn${digest.slice(0, 32)}`;",
            "value.length <= 40",
            "const transportToolCallId = toolCallId;",
            "exact_gateway_session_key:",
            "exact_tool_call_id_identity:",
            "exact_wait_run_id:",
            "exact_worker_request_digest:",
            "expected_nested_relay_outcome:",
            'const OPENCLAW_DETAILS_SCHEMA = "aragorn/runtime-action-worker-openclaw-details/v1";',
            "const MAX_TRANSCRIPT_BYTES = 16 * 1024 * 1024;",
            "function transcriptToolResult(sessionId, rpcToolResult)",
            '!Object.hasOwn(rpcToolResult, "details")',
            "session transcript is not one bounded regular file",
            "matches.length === 1",
            "canonicalJson(message.content) === canonicalJson(rpcToolResult.content)",
            'exactKeys(details, ["schema", "source_result", "status"]',
            "canonicalJson(details.source_result) === canonicalJson(sourceResult)",
            "exact_rpc_history_shape_without_details:",
            "exact_transcript_rpc_tool_result_join:",
            "transcript_regular_nonsymlink_bounded:",
            "exact_openclaw_history_error_classification:",
            (
                "toolResult.isError === "
                '(transcript.message.details.status !== "completed")'
            ),
        ):
            self.assertIn(claim, driver)
        self.assertNotIn('toolCallId.replaceAll("_", "")', driver)
        self.assertNotIn("expectedToolResultError", driver)
        self.assertNotIn("exact_gateway_session_run_tool_correlation", driver)
        self.assertNotIn(
            "pinned_openclaw_resolved_execute_history_is_error_false_"
            "not_nested_relay_result_authority",
            driver,
        )
        dockerfile = _DOCKERFILE.read_text(encoding="utf-8")
        for digest in (
            "e6e1803e9593d8c1bcb1ad4a3fdf2cb5c3657f1b4bd06e65470b8ad16e9e0140",
            "71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b",
        ):
            self.assertIn(digest, dockerfile)

    def test_capture_binds_installers_and_publishes_atomically(self) -> None:
        dockerfile = _DOCKERFILE.read_text(encoding="utf-8")
        capture = _CAPTURE.read_text(encoding="utf-8")
        probe = _PROBE.read_text(encoding="utf-8")
        for path in (
            "packaging/install-runtime-capability-host.sh",
            "packaging/install-runtime-action-worker-host.sh",
        ):
            self.assertIn(path, dockerfile)
            self.assertEqual(capture.count(path), 2)
            self.assertIn(f"/src/{path}", probe)
        self.assertIn("os.link(source, destination, follow_symlinks=False)", capture)
        self.assertIn("source_stat.st_nlink != 1", capture)
        self.assertIn("os.fchmod(descriptor, 0o644)", capture)
        self.assertNotIn("os.open(\n    destination,", capture)

    def test_worker_activator_reuses_capability_route_and_fails_stop(self) -> None:
        activator = _ACTIVATOR.read_text(encoding="utf-8")
        self.assertIn(
            "base_activator=/usr/libexec/aragorn/activate-runtime-capability-host.sh",
            activator,
        )
        self.assertEqual(
            activator.count('"$base_activator"'),
            2,
        )
        for required in (
            "flock -n 9",
            "aragorn-runtime-capability-activation.lock",
            "ARAGORN_RUNTIME_ACTIVATION_LOCK_HELD=1",
            "armed=1",
            "trap rollback EXIT",
            "OPENCLAW_GATEWAY_TOKEN=*)",
            "gateway environment is not one canonical ASCII assignment",
            "gateway activation configuration digest changed",
            "b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e",
            "runtime worker NSS group membership is unsafe",
            '"$gateway_uid" -eq 0',
            "installed unit digest changed",
            "e231978207dd27b71ef43449cf603ac424f6129f64c8a03dd0851ddf32503723",
            "32dea7dfdf5ccb9914c46ea2aadfc88a491d6eadba5bdb8b4982d473af1a0ebe",
            '"$gateway_unit" "$worker_unit" "$sensor_unit" "$broker_unit"',
            "previous runtime worker route remained active",
            "previous runtime worker endpoint remained present",
            'disable "$worker_unit" "$sensor_unit" "$broker_unit"',
            'start "$worker_unit"',
            'start "$gateway_unit"',
            'worker-binding:"$worker_binding"',
            'openclaw-config:"$gateway_config"',
            "EnvironmentFiles",
            "PrivateNetwork yes",
            "PrivateNetwork no",
            "runtime worker endpoint metadata is unsafe",
            'verify_process "$worker_unit"',
            'verify_process "$gateway_unit"',
            "CapEff:",
            "NoNewPrivs:",
            "gateway listener is not owned by its MainPID",
            "gateway retained boot authority",
            "--activation-preflight",
            "config validate --json",
            "aragorn-runtime-action-worker-preflight.XXXXXX",
            'chown "0:$gateway_gid" "$preflight_root"',
            'chmod 0710 "$preflight_root"',
            'install -o 0 -g "$gateway_gid" -m 0440',
            'mask "$gateway_unit" "$worker_unit"',
            "Aragorn runtime worker fail-stop verification failed",
            "/usr/bin/setpriv",
            "--clear-groups",
            "5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154",
            "c43a81b394e0b96b0950af94b937a79e777d7e0c815a0104f1ab45871f4afa64",
            "d0f433abba94a4560c26cb99017f56543b432e2fc3aa74e3374ee4e04addeeaf",
            'wait_socket "$broker_socket"',
            'wait_socket "$sensor_socket"',
            (
                '"/usr/lib/systemd/system/$checked_unit"|'
                '"/lib/systemd/system/$checked_unit"'
            ),
            'RestrictAddressFamilies "AF_INET AF_INET6 AF_UNIX"',
        ):
            self.assertIn(required, activator)
        self.assertEqual(activator.count("\nverify_unit \\"), 2)
        stop_route = (
            "/usr/bin/systemctl stop \\\n"
            '    "$gateway_unit" "$worker_unit" "$sensor_unit" "$broker_unit"'
        )
        self.assertLess(
            activator.index(stop_route),
            activator.index('require_root_secret "$gateway_config"'),
        )
        self.assertLess(
            activator.index(stop_route),
            activator.index("--activation-preflight"),
        )
        self.assertLess(
            activator.index(
                "b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e"
            ),
            activator.index("--activation-preflight"),
        )
        self.assertLess(
            activator.index("--activation-preflight"),
            activator.index('ARAGORN_RUNTIME_ACTIVATION_LOCK_HELD=1 "$base_activator"'),
        )
        self.assertLess(
            activator.index('"$base_activator"'),
            activator.index('start "$worker_unit"'),
        )
        self.assertLess(
            activator.index('start "$worker_unit"'),
            activator.index('start "$gateway_unit"'),
        )
        self.assertNotIn("enable --now", activator)
        self.assertNotIn("WantedBy=", activator)


if __name__ == "__main__":
    unittest.main()
