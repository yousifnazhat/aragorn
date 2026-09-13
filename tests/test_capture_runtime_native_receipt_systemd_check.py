"""Inert host orchestration checks: every Docker boundary is replaced."""

import json
import unittest
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from unittest.mock import patch

from scripts import capture_runtime_native_receipt_systemd_check as subject

OWNER, CONTAINER, COMMIT = "a" * 64, "c" * 64, "b" * 40
NAME = "aragorn-native-receipt-check-" + OWNER[:16]


def _content():
    return {
        "helper": subject.acquisition._helper_input()[1],
        "runtime_tree_before": dict(subject.stage._RUNTIME_TREE),
        "runtime_tree_after": dict(subject.stage._RUNTIME_TREE),
        "mount": {
            "path": "/runtime",
            "ready": True,
            "read_only": True,
            "explicit": True,
            "error": None,
            "records": [
                {
                    "mount_point": "/runtime",
                    "mount_options": ["ro"],
                    "root": f"/docker/volumes/{subject._VOLUME}/_data",
                }
            ],
        },
    }


def _fixture():
    return {
        "Id": CONTAINER,
        "Name": "/" + NAME,
        "Image": subject._IMAGE,
        "Config": {
            "Image": subject._IMAGE,
            "Labels": {
                "dev.aragorn.snapshot-owner": OWNER,
                "dev.aragorn.source-commit": COMMIT,
            },
        },
        "HostConfig": {
            "NetworkMode": "none",
            "Privileged": True,
            "CgroupnsMode": "host",
            "Binds": ["/sys/fs/cgroup:/sys/fs/cgroup:rw"],
            "Mounts": [
                {
                    "Type": "volume",
                    "Source": subject._VOLUME,
                    "Target": "/runtime",
                    "ReadOnly": True,
                }
            ],
            "Tmpfs": {
                "/run": "rw,nosuid,nodev,noexec,mode=755",
                "/run/lock": "rw,nosuid,nodev,noexec,mode=755",
            },
            "SecurityOpt": ["label=disable"],
            "IpcMode": "private",
            "UsernsMode": "",
            "Runtime": "runc",
        },
        "Mounts": [
            {
                "Destination": "/runtime",
                "Type": "volume",
                "Name": subject._VOLUME,
                "RW": False,
            },
            {
                "Destination": "/sys/fs/cgroup",
                "Type": "bind",
                "Source": "/sys/fs/cgroup",
                "RW": True,
            },
        ],
    }


class NativeReceiptCaptureTests(unittest.TestCase):
    def test_runtime_binding_and_snapshot_cleanup_without_native_execution(self):
        content = _content()
        subject._validate_runtime(content)
        for mutation in (
            "old_tree",
            "wrong_volume",
            "writable",
            "helper",
            "numeric_type",
        ):
            bad = deepcopy(content)
            if mutation == "old_tree":
                bad["runtime_tree_before"] = bad["runtime_tree_after"] = (
                    subject.acquisition._RUNTIME_TREE
                )
            elif mutation == "wrong_volume":
                bad["mount"]["records"][0]["root"] = "/docker/volumes/old/_data"
            elif mutation == "writable":
                bad["mount"]["records"][0]["mount_options"] = ["ro", "rw"]
            elif mutation == "helper":
                bad["helper"]["digest"] = "sha256:" + "0" * 64
            else:
                bad["runtime_tree_before"]["entry_count"] = 31987.0
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                subject._validate_runtime(bad)
        for malformed in (False, True):
            calls = []

            def docker(*argv, calls=calls, malformed=malformed):
                calls.append(argv)
                if argv[0] == "ps":
                    return b""
                self.assertEqual(argv[0], "run")
                for flag in (
                    "--network=none",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--user=1000:1000",
                ):
                    self.assertIn(flag, argv)
                self.assertIn(
                    f"type=volume,src={subject._VOLUME},dst=/runtime,readonly", argv
                )
                self.assertNotIn("const stat = s =>", argv[-1])
                return b"{}" if malformed else json.dumps(content).encode()

            with (
                patch.object(
                    subject, "_inspect", return_value=dict(subject._VOLUME_POLICY)
                ),
                patch.object(subject.existing, "_docker", side_effect=docker),
                patch.object(
                    subject.snapshot,
                    "_cleanup_snapshot",
                    return_value={"container_name_absent": True},
                ) as cleanup,
            ):
                if malformed:
                    with self.assertRaises(RuntimeError):
                        subject._snapshot_runtime()
                else:
                    result = subject._snapshot_runtime()
                    self.assertEqual(result["content"], content)
                    self.assertEqual([c[0] for c in calls], ["ps", "run", "ps"])
                cleanup.assert_called_once()
                self.assertEqual(cleanup.call_args.args[2], subject._IMAGE)

    def test_exact_fixture_identity_isolation_and_no_old_runtime_substitution(self):
        item = _fixture()
        subject._verify_fixture(item, CONTAINER, NAME, OWNER, COMMIT)
        for section, key, value in (
            ("Config", "Image", "wrong"),
            ("HostConfig", "NetworkMode", "host"),
            ("HostConfig", "Privileged", 1),
            ("HostConfig", "Binds", ["/Users/example:/host"]),
            ("HostConfig", "Mounts", []),
            ("HostConfig", "CgroupnsMode", "private"),
        ):
            bad = deepcopy(item)
            bad[section][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                subject._verify_fixture(bad, CONTAINER, NAME, OWNER, COMMIT)
        for mutate in ("owner", "volume", "extra"):
            bad = deepcopy(item)
            if mutate == "owner":
                bad["Config"]["Labels"]["dev.aragorn.snapshot-owner"] = "other"
            elif mutate == "volume":
                bad["Mounts"][0]["Name"] = "old-runtime"
            else:
                bad["Mounts"].append({"Destination": "/host"})
            with self.subTest(mutate=mutate), self.assertRaises(RuntimeError):
                subject._verify_fixture(bad, CONTAINER, NAME, OWNER, COMMIT)

    @contextmanager
    def capture_fixture(self, failure=None):
        source = {"commit": COMMIT}
        parent = {
            "image_inspect": {"RootFS": {"Layers": ["base"]}},
            "volume_inspect": {},
            "content": {
                "runtime_tree_before": {},
                "runtime_tree_after": {},
                "contract_files": {},
            },
        }
        image = {
            "Id": subject._IMAGE,
            "RootFS": {"Type": "layers", "Layers": ["base", "child"]},
        }
        observation = {
            "schema": "aragorn/runtime-native-receipt-systemd-integration-observation/v1",
            "fixture_container": CONTAINER,
            "status": "OBSERVED",
            "phase3_eligible": False,
            "run_conformance_eligible": False,
        }
        calls = []

        def docker(*argv):
            calls.append(argv)
            if argv[0] == "create":
                return CONTAINER.encode()
            if subject._FILES[subject._CHECKER] in argv:
                if failure == "checker":
                    raise RuntimeError("checker failed")
                return subject.acquisition._canonical(observation) + b"\n"
            self.assertIn(argv[0], ("cp", "start", "exec"))
            return b""

        with ExitStack() as stack:
            bindings = (
                (
                    subject.existing.existing,
                    "_source_identity",
                    {
                        "side_effect": [
                            source,
                            {"commit": "changed"} if failure == "source" else source,
                        ]
                    },
                ),
                (
                    subject,
                    "_build_binding",
                    {"return_value": {"digest": subject._BUILD_PIN[1]}},
                ),
                (
                    subject.acquisition,
                    "_tree_file",
                    {"return_value": {"bytes": 1, "digest": "sha256:" + "d" * 64}},
                ),
                (subject.snapshot, "snapshot_parent", {"return_value": parent}),
                (
                    subject,
                    "_snapshot_runtime",
                    {"return_value": {"volume_inspect": dict(subject._VOLUME_POLICY)}},
                ),
                (subject, "_inspect", {"side_effect": [image, _fixture()]}),
                (subject.secrets, "token_hex", {"return_value": OWNER}),
                (subject.existing, "_docker", {"side_effect": docker}),
                (
                    subject.previous,
                    "_journal_check",
                    {"wraps": subject.previous._journal_check},
                ),
            )
            mocks = {
                name: stack.enter_context(patch.object(module, name, **kwargs))
                for module, name, kwargs in bindings
            }
            cleanup = stack.enter_context(
                patch.object(
                    subject.snapshot,
                    "_cleanup_snapshot",
                    return_value={
                        "container_name_absent": True,
                        "removed_id_absent": failure != "cleanup",
                    },
                )
            )
            # Also prevent an accidentally introduced direct runner from making
            # this inert orchestration test reach a daemon.
            stack.enter_context(
                patch.object(
                    subject.acquisition,
                    "_run",
                    side_effect=AssertionError("unexpected Docker runner"),
                )
            )
            yield calls, cleanup, mocks

    def test_real_stage_whole_tree_copy_and_failure_cleanup(self):
        for failure in (None, "checker", "cleanup", "source"):
            with (
                self.subTest(failure=failure),
                self.capture_fixture(failure) as (calls, cleanup, mocks),
            ):
                if failure:
                    with self.assertRaises(RuntimeError):
                        subject._capture()
                else:
                    result = subject._capture()
                    self.assertEqual(len(result["staged_profile"]["files"]), 60)
                    self.assertIs(result["production_activation_eligible"], False)
                    self.assertEqual(mocks["_snapshot_runtime"].call_count, 2)
                    self.assertEqual(mocks["snapshot_parent"].call_count, 2)
                cleanup.assert_called_once_with(NAME, OWNER, subject._IMAGE)
                mocks["_journal_check"].assert_called_once()
                self.assertEqual(
                    mocks["_journal_check"].call_args.args[0][-2:],
                    [subject._FILES[subject._CHECKER], CONTAINER],
                )
                copies = [argv for argv in calls if argv[0] == "cp"]
                self.assertEqual(len(copies), 1 + len(subject._FILES))
                self.assertTrue(copies[0][1].endswith("/stage/."))
                self.assertEqual(copies[0][2], CONTAINER + ":/")
                create = calls[0]
                self.assertIn(
                    f"type=volume,src={subject._VOLUME},dst=/runtime,readonly", create
                )
                verify = next(argv for argv in calls if subject._VERIFY in argv)
                self.assertEqual(len(json.loads(verify[-3])), 60 + len(subject._FILES))
                self.assertIn(
                    "/" + subject.stage._NEW_DIRECTORY, json.loads(verify[-1])
                )


if __name__ == "__main__":
    unittest.main()
