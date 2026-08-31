from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts import materialize_fixed_admission_probes as probe_materializer

_ROOT = Path(__file__).resolve().parents[1]
_SHIM = _ROOT / "packaging/libexec/aragorn-runtime-action-worker-service.py"
_UNIT = _ROOT / "packaging/systemd/aragorn-runtime-action-worker.service"
_SYSUSERS = _ROOT / "packaging/systemd/aragorn-runtime-action-worker.sysusers"
_CURRENT_ACTIVATOR_IDENTITY = (
    32_271,
    "dd615a00aacd5f76f52ac60400ea095f9014c2ef29d7793fd3ba35b26ffe3186",
)
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
_FINAL_V3_FRESH_SESSION_RESET_DOCKERFILE = (
    _ROOT
    / "benchmark/runtime-action-worker-final-combined-v3-fresh-session-reset-systemd/Dockerfile"
)
_FINAL_V3_FRESH_SESSION_RESET_CAPTURE = (
    _ROOT
    / "scripts/capture_runtime_action_worker_final_combined_v3_fresh_session_reset_systemd.sh"
)
_FINAL_V3_CRON_RESCAN_DOCKERFILE = (
    _ROOT
    / "benchmark/runtime-action-worker-final-combined-v3-cron-rescan-systemd/Dockerfile"
)
_FINAL_V3_CRON_RESCAN_CAPTURE = (
    _ROOT
    / "scripts/capture_runtime_action_worker_final_combined_v3_cron_rescan_systemd.sh"
)
_FINAL_V3_CRON_RESCAN_COLLECTOR = (
    _ROOT
    / "scripts/runtime_action_worker_final_combined_v3_cron_rescan_systemd_probe.py"
)
_FINAL_V3_PROMPT_REBUILD_DOCKERFILE = (
    _ROOT
    / "benchmark/runtime-action-worker-final-combined-v3-prompt-rebuild-systemd/Dockerfile"
)
_FINAL_V3_PROMPT_REBUILD_CAPTURE = (
    _ROOT
    / "scripts/capture_runtime_action_worker_final_combined_v3_prompt_rebuild_systemd.sh"
)
_FINAL_V3_PROMPT_REBUILD_COLLECTOR = (
    _ROOT
    / "scripts/runtime_action_worker_final_combined_v3_prompt_rebuild_systemd_probe.py"
)
_FINAL_V3_CURATOR_RESTORE_DOCKERFILE = (
    _ROOT
    / "benchmark/runtime-action-worker-final-combined-v3-curator-restore-systemd/Dockerfile"
)
_FINAL_V3_CURATOR_RESTORE_CAPTURE = (
    _ROOT
    / "scripts/capture_runtime_action_worker_final_combined_v3_curator_restore_systemd.sh"
)
_FINAL_V3_CURATOR_RESTORE_COLLECTOR = (
    _ROOT
    / "scripts/runtime_action_worker_final_combined_v3_curator_restore_systemd_probe.py"
)
_FINAL_V3_SESSION_SNAPSHOT_CONSUMER_DOCKERFILE = (
    _ROOT
    / "benchmark/runtime-action-worker-final-combined-v3-session-snapshot-consumer-systemd/Dockerfile"
)
_FINAL_V3_SESSION_SNAPSHOT_CONSUMER_CAPTURE = (
    _ROOT
    / "scripts/capture_runtime_action_worker_final_combined_v3_session_snapshot_consumer_systemd.sh"
)
_FINAL_V3_SESSION_SNAPSHOT_CONSUMER_COLLECTOR = (
    _ROOT
    / "scripts/runtime_action_worker_final_combined_v3_session_snapshot_consumer_systemd_probe.py"
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
            "sha256:52dbdae05a0a394b7314d87337b1a536ba3cf9a0b999d95432341daa068ca5cf",
        )
        current_activator = _ACTIVATOR.read_bytes()
        self.assertEqual(
            (len(current_activator), hashlib.sha256(current_activator).hexdigest()),
            _CURRENT_ACTIVATOR_IDENTITY,
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
                    (
                        '{"protocolVersion":1,"decision":"block","reason":'
                        '"plugin installs disabled by Aragorn protected profile"}'
                    ),
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
        self.assertEqual(
            (len(activator), hashlib.sha256(activator).hexdigest()),
            _CURRENT_ACTIVATOR_IDENTITY,
        )
        self.assertEqual(activator.count(old), 1)
        self.assertEqual(activator.count(new), 0)
        transformed = activator.replace(old, new)
        self.assertEqual(len(transformed), 32_271)
        self.assertEqual(
            hashlib.sha256(transformed).hexdigest(),
            "7d0eff0b1d06d9ade38c7e68366ad59731a475c5db52243d597ba14cd9c7e25c",
        )
        dockerfile = _FINAL_V3_DOCKERFILE.read_text(encoding="utf-8")
        pins = (
            old.decode(),
            new.decode(),
            "52dbdae05a0a394b7314d87337b1a536ba3cf9a0b999d95432341daa068ca5cf",
            "3b25b462cf7f9c4886cce1b7057fabbaeb95e9d9de83cb33db9c7ca62f15d86c",
        )
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

    def test_final_v3_fresh_session_materializes_then_rebinds_one_probe(
        self,
    ) -> None:
        name = "protected-route-probe.mjs"
        source = (_FINAL_PROFILES / name).read_bytes()
        self.assertEqual(
            (len(source), hashlib.sha256(source).hexdigest()),
            (
                34_185,
                "3d9615bbfae6c86b272c862de2faaf55f24cc7018a5e77f912f2b4f527162504",
            ),
        )
        materialized = probe_materializer.transformed_final_combined_v2_probe(
            name, workshop=False
        )
        self.assertEqual(
            (len(materialized), hashlib.sha256(materialized).hexdigest()),
            (
                44_825,
                "65fda9d7406b9813017002cd7b6cde449475685b4410e45bca5b7aeed00ae7c1",
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
                44_825,
                "4687054e9d7ea264c6772de4e0560fafb195ebbbfc7397333297abd6cc4347ff",
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

        dockerfile = _FINAL_V3_FRESH_SESSION_RESET_DOCKERFILE.read_text(
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
            "0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec",
            "65fda9d7406b9813017002cd7b6cde449475685b4410e45bca5b7aeed00ae7c1",
            "4687054e9d7ea264c6772de4e0560fafb195ebbbfc7397333297abd6cc4347ff",
            "/route-input/fresh-session-reset/protected-route-probe.mjs",
        ):
            self.assertIn(value, dockerfile)
        for check in (
            'test "$(grep -F -o "$old" "$v2" | wc -l)" = 2;',
            'test "$(grep -F -o "$new" "$v3" | wc -l)" = 2;',
            "        protected-route-probe.mjs;",
            "'fresh-session-reset:d'",
            "'fresh-session-reset/protected-route-probe.mjs:f'",
        ):
            self.assertEqual(dockerfile.count(check), 1)
        self.assertNotIn("PROPOSAL.md", dockerfile)
        self.assertNotIn("/route-input/workshop-proposal-apply", dockerfile)

    def test_final_v3_fresh_session_publication_rejects_claim_aliases(
        self,
    ) -> None:
        capture = _FINAL_V3_FRESH_SESSION_RESET_CAPTURE.read_text(encoding="utf-8")
        marker = 'python3.12 - "$temp_output" "$output" <<\'PY\'\n'
        publication = capture.split(marker, 1)[1].split("\nPY\n", 1)[0]
        claims = {
            "admission_profile_eligible": False,
            "aggregate_admission_eligible": False,
            "edr_eligible": False,
            "installer_work_eligible": False,
            "phase3_exit_eligible": False,
            "release_eligible": False,
            "run_01_eligible": False,
            "run_02_eligible": False,
            "run_eligible": False,
        }
        document = {
            "schema": "aragorn/runtime-action-worker-final-combined-v3-fresh-session-reset-systemd-observation/v1",
            "authority": (
                "BOUND_FINAL_COMBINED_V3_RAW_FRESH_SESSION_RESET_OBSERVATION_ONLY_"
                "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
            ),
            "recorded_at": "2026-08-28T00:00:00Z",
            "route_id": "ADM-02/reload/fresh-session-reset",
            "route_observation": {},
            "composition": {},
            "harness": {},
            "source_artifacts": {},
            "decision": {
                "status": (
                    "FINAL_COMBINED_V3_FRESH_SESSION_RESET_"
                    "OBSERVED_PROFILE_NOT_TESTED"
                ),
                "route_observation_status": "OBSERVED",
                "route_pass_count": 0,
                "route_fail_count": 0,
                "route_not_tested_count": 21,
                **claims,
            },
            "limitations": [],
        }
        cases = (
            ("boolean pass count", "decision", "route_pass_count", False),
            ("float fail count", "decision", "route_fail_count", 0.0),
            ("float not-tested count", "decision", "route_not_tested_count", 21.0),
            ("extra decision claim", "decision", "admission_granted", True),
            ("extra top-level failure", "document", "failure", {"code": "x"}),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid_source = root / "valid.tmp"
            valid_destination = root / "valid.json"
            valid_raw = (
                json.dumps(
                    document,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            )
            valid_source.write_text(valid_raw, encoding="ascii")
            valid = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    publication,
                    str(valid_source),
                    str(valid_destination),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(valid.returncode, 0, valid.stderr)
            self.assertEqual(valid_destination.read_text(encoding="ascii"), valid_raw)
            for label, scope, key, value in cases:
                with self.subTest(label=label):
                    candidate = json.loads(json.dumps(document))
                    target = candidate["decision"] if scope == "decision" else candidate
                    target[key] = value
                    source = root / f"{key}.tmp"
                    destination = root / f"{key}.json"
                    source.write_text(
                        json.dumps(
                            candidate,
                            allow_nan=False,
                            ensure_ascii=True,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        + "\n",
                        encoding="ascii",
                    )
                    result = subprocess.run(
                        [sys.executable, "-c", publication, str(source), str(destination)],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertFalse(destination.exists())

    def test_final_v3_cron_rescan_capture_binds_exact_authority(self) -> None:
        dockerfile = _FINAL_V3_CRON_RESCAN_DOCKERFILE.read_text(encoding="utf-8")
        capture = _FINAL_V3_CRON_RESCAN_CAPTURE.read_text(encoding="utf-8")
        collector = _FINAL_V3_CRON_RESCAN_COLLECTOR.read_text(encoding="utf-8")
        materializers = {
            "scripts/materialize_openclaw_final_v3_rebound_probes.py": (
                7_691,
                "8321a6c423b03c283d175185de6886ca12aaa08c244f81b67be3a73a47279a1c",
            ),
            "scripts/materialize_fixed_admission_probes.py": (
                87_912,
                "0771f973c7d544e0cf66bc2a2b3d8120041a38ce244f331a7e7b5698660281ec",
            ),
        }
        for path, identity in materializers.items():
            raw = (_ROOT / path).read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), identity)
            self.assertIn(path, dockerfile)
            self.assertIn(path, capture)
            self.assertIn(f"/src/{path}", collector)
            self.assertIn(identity[1], dockerfile)
            self.assertIn(identity[1], collector)

        parent = (
            "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
        )
        route = "ADM-02/reload/cron-rescan"
        authority = (
            "BOUND_FINAL_COMBINED_V3_RAW_CRON_RESCAN_OBSERVATION_ONLY_"
            "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        for source in (dockerfile, capture, collector):
            self.assertIn(parent, source)
            self.assertIn(route, source)
        self.assertIn(
            "/src/scripts/materialize_openclaw_final_v3_rebound_probes.py \\\n"
            "        ADM-02/reload/cron-rescan /route-input/cron-rescan;",
            dockerfile,
        )
        self.assertIn("'directory:0:0:555:2';", dockerfile)
        marker = 'python3.12 - "$temp_output" "$output" <<\'PY\'\n'
        publication = capture.split(marker, 1)[1].split("\nPY\n", 1)[0]
        for source in (publication, collector):
            strings = {
                node.value
                for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            }
            self.assertIn(authority, strings)

        eligibility = {
            "admission_profile_eligible",
            "aggregate_admission_eligible",
            "edr_eligible",
            "installer_work_eligible",
            "phase3_exit_eligible",
            "release_eligible",
            "run_01_eligible",
            "run_02_eligible",
            "run_eligible",
        }
        self.assertIn("**{key: False for key in sorted(_ELIGIBILITY_KEYS)}", collector)
        self.assertIn(
            "or any(decision[key] is not False for key in expected_claims)",
            publication,
        )
        for key in eligibility:
            self.assertIn(key, publication)

    def test_final_v3_prompt_rebuild_capture_binds_exact_authority(self) -> None:
        dockerfile = _FINAL_V3_PROMPT_REBUILD_DOCKERFILE.read_text(encoding="utf-8")
        capture = _FINAL_V3_PROMPT_REBUILD_CAPTURE.read_text(encoding="utf-8")
        collector = _FINAL_V3_PROMPT_REBUILD_COLLECTOR.read_text(encoding="utf-8")
        parent = (
            "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
        )
        route = "ADM-02/reload/missing-prompt-blob-rebuild"
        authority = (
            "BOUND_FINAL_COMBINED_V3_RAW_PROMPT_REBUILD_OBSERVATION_ONLY_"
            "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        for source in (dockerfile, capture, collector):
            self.assertIn(parent, source)
            self.assertIn(route, source)
        for digest in (
            "9d6eb33127e5e7fd2439adfc1e6bb5fc87286ed03b3b2717cdaf55df54227dd7",
            "672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
        ):
            self.assertIn(digest, dockerfile)
            self.assertIn(digest, collector)
        self.assertIn(
            "ADM-02/reload/missing-prompt-blob-rebuild \\\n"
            "        /route-input/missing-prompt-blob-rebuild;",
            dockerfile,
        )
        self.assertIn("'directory:0:0:555:2';", dockerfile)
        for required in (
            'git status --porcelain=v1',
            'git verify-commit --raw "$source_commit"',
            'git archive --format=tar "$source_commit"',
            "remove_created_container",
            'docker volume rm "$route_input_volume"',
            "trap cleanup EXIT",
        ):
            self.assertIn(required, capture)
        marker = 'python3.12 - "$temp_output" "$output" <<\'PY\'\n'
        publication = capture.split(marker, 1)[1].split("\nPY\n", 1)[0]
        for source in (publication, collector):
            strings = {
                node.value
                for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            }
            self.assertIn(authority, strings)
        self.assertIn("**{key: False for key in sorted(_ELIGIBILITY_KEYS)}", collector)
        self.assertIn(
            "or any(decision[key] is not False for key in expected_claims)",
            publication,
        )

    def test_final_v3_curator_restore_capture_binds_exact_authority(self) -> None:
        dockerfile = _FINAL_V3_CURATOR_RESTORE_DOCKERFILE.read_text(encoding="utf-8")
        capture = _FINAL_V3_CURATOR_RESTORE_CAPTURE.read_text(encoding="utf-8")
        collector = _FINAL_V3_CURATOR_RESTORE_COLLECTOR.read_text(encoding="utf-8")
        parent = (
            "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
        )
        route = "ADM-02/update/curator-restore-activation"
        route_schema = (
            "aragorn/openclaw-protected-curator-restore-denial-observation/v1"
        )
        authority = (
            "BOUND_FINAL_COMBINED_V3_RAW_CURATOR_RESTORE_OBSERVATION_ONLY_"
            "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        for source in (dockerfile, capture, collector):
            self.assertIn(parent, source)
            self.assertIn(route, source)
        for digest in (
            "fd3fa9ec7dce5b626eb1243c3391279093d08555e7c81f67d1b4549160fca089",
            "672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
        ):
            self.assertIn(digest, dockerfile)
            self.assertIn(digest, collector)
        self.assertIn(route_schema, collector)
        self.assertIn(
            "ADM-02/update/curator-restore-activation \\\n"
            "        /route-input/curator-restore-activation;",
            dockerfile,
        )
        self.assertIn("'directory:0:0:555:2';", dockerfile)
        for required in (
            'git status --porcelain=v1',
            'git verify-commit --raw "$source_commit"',
            'git archive --format=tar "$source_commit"',
            "remove_created_container",
            'docker volume rm "$route_input_volume"',
            "trap cleanup EXIT",
        ):
            self.assertIn(required, capture)
        marker = 'python3.12 - "$temp_output" "$output" <<\'PY\'\n'
        publication = capture.split(marker, 1)[1].split("\nPY\n", 1)[0]
        for source in (publication, collector):
            strings = {
                node.value
                for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            }
            self.assertIn(authority, strings)
        self.assertIn("**{key: False for key in sorted(_ELIGIBILITY_KEYS)}", collector)
        self.assertIn(
            "or any(decision[key] is not False for key in expected_claims)",
            publication,
        )

    def test_final_v3_session_snapshot_capture_binds_exact_authority(self) -> None:
        dockerfile = _FINAL_V3_SESSION_SNAPSHOT_CONSUMER_DOCKERFILE.read_text(
            encoding="utf-8"
        )
        capture = _FINAL_V3_SESSION_SNAPSHOT_CONSUMER_CAPTURE.read_text(
            encoding="utf-8"
        )
        collector = _FINAL_V3_SESSION_SNAPSHOT_CONSUMER_COLLECTOR.read_text(
            encoding="utf-8"
        )
        parent = (
            "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
        )
        route = "ADM-02/reload/session-snapshot-consumer"
        route_schema = (
            "aragorn/openclaw-protected-session-snapshot-fixed-observation/v1"
        )
        authority = (
            "BOUND_FINAL_COMBINED_V3_RAW_SESSION_SNAPSHOT_CONSUMER_OBSERVATION_ONLY_"
            "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        for source in (dockerfile, capture, collector):
            self.assertIn(parent, source)
            self.assertIn(route, source)
            self.assertNotIn("session-snapshot-consumer-activation", source)
            self.assertNotIn("session-snapshot-consumer-denial-probe", source)
        for digest in (
            "1efe13c3beb3ac2ff6fc1293aa64875c95424f1576a10b12943f0b875af223e2",
            "9ab66a23f17b85caed2593cb0300df8a71201b9f12f6ecb28fcde6b165eccd11",
            "44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b",
            "672ef56e3e2d7e39dbba09eb49e388e4b8522c29d84dd5f610ca1427445ff13f",
        ):
            self.assertIn(digest, dockerfile)
            self.assertIn(digest, collector)
        self.assertIn(route_schema, collector)
        self.assertIn(
            "ADM-02/reload/session-snapshot-consumer \\\n"
            "        /route-input/session-snapshot-consumer;",
            dockerfile,
        )
        self.assertIn("'directory:0:0:555:2';", dockerfile)
        for required in (
            'git status --porcelain=v1',
            'git verify-commit --raw "$source_commit"',
            'git archive --format=tar "$source_commit"',
            "remove_created_container",
            'docker volume rm "$route_input_volume"',
            "trap cleanup EXIT",
        ):
            self.assertIn(required, capture)
        marker = 'python3.12 - "$temp_output" "$output" <<\'PY\'\n'
        publication = capture.split(marker, 1)[1].split("\nPY\n", 1)[0]
        for source in (publication, collector):
            strings = {
                node.value
                for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            }
            self.assertIn(authority, strings)
        self.assertIn("**{key: False for key in sorted(_ELIGIBILITY_KEYS)}", collector)
        self.assertIn(
            "or any(decision[key] is not False for key in expected_claims)",
            publication,
        )

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
            "BindsTo=aragorn-runtime-lineage-capability-observation-publisher.service",
            "Restart=no",
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
        self.assertNotIn(
            "Requires=aragorn-runtime-lineage-capability-observation-publisher.service",
            unit,
        )
        self.assertEqual(unit.count("Restart=no"), 1)
        self.assertNotIn("Restart=on-failure", unit)
        self.assertNotIn("RestartSec=", unit)
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
            "e4ef9e3f2229d92ed9dd9ee4896646e646d7171ee585ecba5aecdd87dba5e790",
            "70a0aa0a89aae8bce8b7785b26d73d844c784e85be449363cb739835500de067",
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
            "b4ad162940d842e93ede73143f607cff4c612716334b66430d71b885f398984c",
            "e0273dbeb4ed40a203193a52eb6146f81ecbc6abca605fa0bfff69774676b2db",
            "f48258b00213c2c1ff4c5c95d0f1c446f78593d1d04780719cba79bf8dd73d8a",
            'wait_socket "$broker_socket"',
            'wait_socket "$sensor_socket"',
            (
                '"/usr/lib/systemd/system/$checked_unit"|'
                '"/lib/systemd/system/$checked_unit"'
            ),
            'RestrictAddressFamilies "AF_INET AF_INET6 AF_UNIX"',
            'gateway_binds_to=$(unit_property "$gateway_unit" BindsTo)',
            'if [ "$#" -ne 3 ]',
            'require_unit_member "$gateway_unit" BindsTo "$dependency"',
            'require_unit_member "$gateway_unit" After "$dependency"',
            'require_unit_value "$gateway_unit" KillMode control-group',
        ):
            self.assertIn(required, activator)
        self.assertIn(
            'for unit in "$worker_unit" "$sensor_unit" "$broker_unit"\n'
            "do\n"
            '    require_unit_value "$unit" Restart no\n'
            "done",
            activator,
        )
        for effective_dependency in (
            'require_unit_value "$worker_unit" BindsTo "$sensor_unit"',
            'require_only_aragorn_service_after "$worker_unit" "$sensor_unit"',
            'require_unit_value "$sensor_unit" BindsTo "$broker_unit"',
            'require_only_aragorn_service_after "$sensor_unit" "$broker_unit"',
        ):
            self.assertIn(effective_dependency, activator)
        self.assertIn("aragorn-*.service)", activator)
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
