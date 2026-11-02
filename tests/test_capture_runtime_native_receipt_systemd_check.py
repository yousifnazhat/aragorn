"""Inert host orchestration checks: every Docker boundary is replaced."""

import json
import os
import stat
import subprocess
import sys
import unittest
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
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
    def test_exact_directory_owner_handoff_preserves_modes_and_closes_all_fds(self):
        original, replacements = subject.stage._verified_payloads()
        expected = {
            name: {"installed_path": "/" + name} for name in original | replacements
        }
        directories = [
            "/" + name
            for name in subject.stage.base._directories(original | replacements)
        ]
        self.assertLess(
            subject._VERIFY.index(subject._DIRECTORY_HANDOFF),
            subject._VERIFY.index(subject._DIRECTORY_ANCHOR),
        )
        for failure in (
            None,
            "already_root",
            "mode",
            "owner",
            "symlink",
            "swap",
            "fsync",
            "close",
        ):
            records = {
                name: SimpleNamespace(
                    st_dev=1,
                    st_ino=index + 1,
                    st_mode=stat.S_IFDIR | 0o755,
                    st_uid=0 if name == "/" or failure == "already_root" else 501,
                    st_gid=0 if name == "/" or failure == "already_root" else 20,
                    st_nlink=2,
                    st_size=100,
                    st_mtime_ns=1,
                    st_ctime_ns=1,
                )
                for index, name in enumerate(["/", *sorted(directories)])
            }
            if failure == "mode":
                records["/usr"].st_mode = stat.S_IFDIR | 0o700
            if failure == "owner":
                records["/usr"].st_uid = 999
            if failure == "symlink":
                records["/usr"].st_mode = stat.S_IFLNK | 0o755
            opened, closed, handoffs, stats = {}, [], [], {}

            def named(leaf, parent, opened=opened):
                return str(Path(opened[parent]) / leaf) if parent is not None else leaf

            def read_stat(
                leaf,
                *,
                dir_fd,
                follow_symlinks,
                failure=failure,
                stats=stats,
                records=records,
            ):
                self.assertIs(follow_symlinks, False)
                name = named(leaf, dir_fd)
                stats[name] = stats.get(name, 0) + 1
                result = deepcopy(records[name])
                if failure == "swap" and name == "/usr" and stats[name] > 1:
                    result.st_ino += 100
                return result

            def open_dir(leaf, flags, *, dir_fd, opened=opened):
                self.assertTrue(flags & os.O_DIRECTORY and flags & os.O_NOFOLLOW)
                fd = len(opened) + 1
                opened[fd] = named(leaf, dir_fd)
                return fd

            def chown(fd, uid, gid, opened=opened, handoffs=handoffs, records=records):
                self.assertEqual((uid, gid), (0, 0))
                name = opened[fd]
                self.assertIn(name, directories)
                handoffs.append(name)
                records[name].st_uid = records[name].st_gid = 0
                records[name].st_ctime_ns += 1

            def sync(fd, failure=failure):
                if failure == "fsync":
                    raise OSError("injected fsync")

            def close(fd, failure=failure, closed=closed):
                closed.append(fd)
                if failure == "close":
                    raise OSError("injected close")

            fake = SimpleNamespace(
                **{
                    key: getattr(os, key)
                    for key in (
                        "O_RDONLY",
                        "O_DIRECTORY",
                        "O_NOFOLLOW",
                        "O_NONBLOCK",
                        "O_CLOEXEC",
                    )
                },
                stat=read_stat,
                open=open_dir,
                fstat=lambda fd, records=records, opened=opened: deepcopy(
                    records[opened[fd]]
                ),
                fchown=chown,
                fsync=sync,
                close=close,
            )
            context = {
                "os": fake,
                "stat": stat,
                "Path": Path,
                "json": json,
                "expected": expected,
                "sys": SimpleNamespace(
                    argv=["", "", "", json.dumps(directories), "[501,20]"]
                ),
            }
            with self.subTest(failure=failure):
                if failure in (None, "already_root"):
                    exec(subject._DIRECTORY_HANDOFF, context)  # noqa: S102 - fixed source, fake OS only
                    self.assertEqual(set(handoffs), set(directories))
                    self.assertTrue(
                        all(
                            (s.st_uid, s.st_gid, stat.S_IMODE(s.st_mode))
                            == (0, 0, 0o755)
                            for s in records.values()
                        )
                    )
                else:
                    with self.assertRaises((RuntimeError, OSError)):
                        exec(subject._DIRECTORY_HANDOFF, context)  # noqa: S102 - fixed source, fake OS only
                self.assertEqual(closed, list(reversed(opened)))

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
                bad["runtime_tree_before"]["entry_count"] = 31988.0
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
    def capture_fixture(self, failure=None, *, health=False, config_denial=False):
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
        if config_denial:
            from tests.test_runtime_native_config_denial_check import _example

            config, predecessor = _example()
            observation.update(predecessor, fixture_container=CONTAINER)
            config["fixture_container"] = CONTAINER
            observation["config_denial"] = config
            if failure == "config_authority":
                config["successful_reload_observed"] = True
        if health:
            observation["health_response"] = {
                "schema": "aragorn/native-health-systemd-observation/v1",
                "status": "OBSERVED",
                "fixture_container": CONTAINER,
                "authority": "OWNED_ACCEPTED_HEALTH_RESPONSE_ONLY_NOT_SENSOR_LOSS_OR_RUN_QUALIFICATION",
                "phase3_eligible": False,
                "run_conformance_eligible": False,
                "production_activation_eligible": False,
                "sensor_loss_detection": False,
                "watchdog_or_stale_health_coverage": False,
                "durable_dispatch_queue": False,
            }
            if failure == "authority":
                observation["health_response"]["phase3_eligible"] = True
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
                self.assertEqual(len(json.loads(verify[-4])), 60 + len(subject._FILES))
                self.assertIn(
                    "/" + subject.stage._NEW_DIRECTORY, json.loads(verify[-2])
                )
                self.assertEqual(json.loads(verify[-1]), [os.geteuid(), os.getegid()])

    def test_health_opt_in_preserves_default_verifier_and_owns_cleanup(self):
        self.assertEqual(
            subject._HEALTH_VERIFY.replace(
                "len(directories)!=16", "len(directories)!=13"
            ).replace("len(set(directories))!=16", "len(set(directories))!=13"),
            subject._VERIFY,
        )
        for value in (1, "yes", None):
            with self.assertRaises(RuntimeError):
                subject._capture(health=value)
        for failure in (None, "checker", "cleanup", "source", "authority"):
            with (
                self.subTest(failure=failure),
                self.capture_fixture(failure, health=True) as (calls, cleanup, mocks),
            ):
                if failure:
                    with self.assertRaises(RuntimeError):
                        subject._capture(health=True)
                else:
                    result = subject._capture(health=True)
                    self.assertEqual(
                        result["schema"],
                        "aragorn/runtime-native-health-systemd-capture/v1",
                    )
                    self.assertEqual(len(result["staged_profile"]["files"]), 66)
                    self.assertIs(result["production_activation_eligible"], False)
                cleanup.assert_called_once_with(NAME, OWNER, subject._IMAGE)
                self.assertEqual(
                    mocks["_journal_check"].call_args.args[0][-3:],
                    [subject._FILES[subject._CHECKER], CONTAINER, "--health"],
                )
                copies = [argv for argv in calls if argv[0] == "cp"]
                self.assertEqual(len(copies), 1 + len(subject._HEALTH_FILES))
                verify = next(argv for argv in calls if subject._HEALTH_VERIFY in argv)
                self.assertEqual(
                    len(json.loads(verify[-4])), 66 + len(subject._HEALTH_FILES)
                )
                self.assertEqual(len(json.loads(verify[-2])), 16)

    def test_config_denial_opt_in_replays_joins_and_preserves_cleanup(self):
        for value in (1, "yes", None):
            with self.assertRaises(RuntimeError):
                subject._capture(config_denial=value)
        for health in (False, True):
            for failure in (None, "checker", "cleanup", "source", "config_authority"):
                with (
                    self.subTest(health=health, failure=failure),
                    self.capture_fixture(
                        failure, health=health, config_denial=True
                    ) as (calls, cleanup, mocks),
                ):
                    if failure:
                        with self.assertRaises(RuntimeError):
                            subject._capture(health=health, config_denial=True)
                    else:
                        result = subject._capture(health=health, config_denial=True)
                        self.assertEqual(
                            result["schema"],
                            "aragorn/runtime-native-config-denial-systemd-capture/v1",
                        )
                        self.assertEqual(
                            len(result["staged_profile"]["files"]), 66 if health else 60
                        )
                    cleanup.assert_called_once_with(NAME, OWNER, subject._IMAGE)
                    self.assertEqual(
                        mocks["_journal_check"].call_args.args[0][-1], "--config-denial"
                    )
                    copies = [argv for argv in calls if argv[0] == "cp"]
                    self.assertEqual(
                        len(copies),
                        1
                        + len(subject._HEALTH_FILES if health else subject._FILES)
                        + len(subject._CONFIG_FILES),
                    )

    def test_cold_config_helper_loads_before_signed_source_identity(self):
        program = """
import sys
from pathlib import Path
from unittest.mock import patch
root = Path(sys.argv[1])
sys.path[:0] = [str(root / "src"), str(root)]
from scripts import capture_runtime_native_receipt_systemd_check as subject
helper = "scripts.runtime_native_config_denial_check"
assert helper not in sys.modules, "test host must start without the config helper"
class IdentityReached(Exception):
    pass
def freeze_identity():
    assert helper in sys.modules, "config helper imported after source identity"
    raise IdentityReached
with (
    patch.object(subject.existing.existing, "_source_identity", side_effect=freeze_identity) as identity,
    patch.object(subject.existing, "_docker", side_effect=AssertionError("Docker must not run")) as docker,
):
    try:
        subject._capture(config_denial=True)
    except IdentityReached:
        pass
    else:
        raise AssertionError("source identity boundary was not reached")
    identity.assert_called_once_with()
    docker.assert_not_called()
"""
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                "-c",
                program,
                str(Path(__file__).resolve().parents[1]),
            ],
            capture_output=True,
            check=False,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stdout, b"")


if __name__ == "__main__":
    unittest.main()
