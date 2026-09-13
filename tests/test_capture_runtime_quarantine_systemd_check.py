from __future__ import annotations

import json
import os
import stat
import subprocess
import unittest
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts import capture_runtime_quarantine_systemd_check as subject

_CONTAINER = "c" * 64
_OWNER = "a" * 64
_NAME = "aragorn-runtime-quarantine-check-" + _OWNER[:16]
_SOURCE = {"commit": "b" * 40, "files": []}
_CHECKER = "/opt/aragorn/runtime-quarantine-systemd-check.py"


class RuntimeQuarantineCaptureTests(unittest.TestCase):
    def test_journal_diagnostics_preserve_frozen_runner_checks_and_full_safe_error(
        self,
    ):
        acquisition = subject.existing.existing.acquisition
        argv = ["exec", _CONTAINER, "/fixed-checker"]
        for status, output, error in (
            (0, b"safe", b""),
            (1, b"", b"safe diagnostic " + b"x" * 2000 + b" decisive tail"),
            (0, b"safe", b"stderr still refuses"),
            (1, b"", b""),
            (1, b"", b"x" * 16385),
            (1, b"x" * (2 * 1024 * 1024 + 1), b"unsafe output bound"),
        ):
            completed = subprocess.CompletedProcess(argv, status, output, error)
            original = SimpleNamespace(run=Mock(return_value=completed))
            with patch.object(acquisition, "subprocess", original):
                if status == 0 and not error:
                    self.assertEqual(subject._journal_check(argv), output)
                else:
                    with self.assertRaises(acquisition.CaptureError) as caught:
                        subject._journal_check(argv)
                    if len(error) > 16384 or len(output) > 2 * 1024 * 1024:
                        self.assertEqual(
                            str(caught.exception),
                            "acquisition command output exceeded limit",
                        )
                    elif error:
                        self.assertTrue(str(caught.exception).endswith(error.decode()))
                    else:
                        self.assertEqual(
                            str(caught.exception), "acquisition command failed: "
                        )
                self.assertIs(acquisition.subprocess, original)
            original.run.assert_called_once_with(
                [*acquisition._DOCKER, *argv],
                capture_output=True,
                check=False,
                timeout=120,
            )
        failure = subprocess.TimeoutExpired("fixed", 120)
        original = SimpleNamespace(run=Mock(side_effect=failure))
        with patch.object(acquisition, "subprocess", original):
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                subject._journal_check(argv)
            self.assertIs(caught.exception, failure)
            self.assertIs(acquisition.subprocess, original)

    @contextmanager
    def fixture(self, failure: str | None = None, *, endpoint_journal: bool = False):
        """Exercise host orchestration with every Docker entry point mocked."""
        profile = "endpoint-journal" if endpoint_journal else "quarantine"
        name = f"aragorn-runtime-{profile}-check-" + _OWNER[:16]
        files = subject._JOURNAL_FILES if endpoint_journal else subject._FILES
        checker = (
            "/opt/aragorn/runtime-endpoint-journal-systemd-check.py"
            if endpoint_journal
            else _CHECKER
        )
        stage_module = subject.journal_stage if endpoint_journal else subject.stage
        stage_name = (
            "stage_runtime_endpoint_journal_profile"
            if endpoint_journal
            else "stage_runtime_quarantine_profile"
        )
        parent = subject.campaign.current_v3_parent_identity()
        before = {
            "image_inspect": {"id": parent["image_id"]},
            "volume_inspect": {"name": parent["runtime_volume"]},
            "content": {
                "runtime_tree_before": {"digest": "fixed"},
                "runtime_tree_after": {"digest": "fixed"},
                "contract_files": {"config": {"content_base64": "e30="}},
            },
        }
        after = deepcopy(before)
        if failure == "parent_image":
            after["image_inspect"]["id"] = "changed"
        elif failure == "parent_volume":
            after["volume_inspect"]["name"] = "changed"
        elif failure == "parent_tree":
            after["content"]["runtime_tree_after"]["digest"] = "changed"
        elif failure == "parent_contract":
            after["content"]["contract_files"]["config"]["content_base64"] = "e30K"
        observation = {
            "schema": f"aragorn/runtime-{profile}-systemd-integration-observation/v1",
            "fixture_container": _CONTAINER,
            "status": "OBSERVED",
            "phase3_eligible": False,
            "run_conformance_eligible": False,
        }
        state = {"calls": [], "copies": {}, "stage_paths": [], "source_calls": 0}
        real_stage = getattr(stage_module, stage_name)

        def source():
            state["source_calls"] += 1
            if failure == "source_initial":
                raise RuntimeError("unsigned or dirty source")
            result = deepcopy(_SOURCE)
            if failure == "source_after" and state["source_calls"] > 1:
                result["commit"] = "d" * 40
            return result

        def tree_file(commit, path):
            self.assertEqual(commit, _SOURCE["commit"])
            self.assertIn(path.as_posix(), files)
            if failure == "helper_source":
                raise RuntimeError("helper differs from signed source")
            raw = (subject._ROOT / path).read_bytes()
            return {
                "path": path.as_posix(),
                "bytes": len(raw),
                "digest": subject.campaign._digest(raw),
                "mode": "100644",
                "blob": "e" * 40,
            }

        def stage(output):
            state["stage_paths"].append(output)
            if failure == "stage":
                raise RuntimeError("staging failed")
            manifest = real_stage(output)
            if failure == "stage_count":
                manifest["files"].pop()
            elif failure == "stage_duplicate":
                manifest["files"][-1] = deepcopy(manifest["files"][0])
            elif failure == "stage_authority":
                manifest["root_deployment"] = True
            elif failure == "journal_sources":
                manifest["source_inputs"].pop()
            elif failure in (
                "runtime_journal_deployed",
                "durable_event_retention",
                "run_qualification",
            ):
                manifest[failure] = True
            state["manifest"] = deepcopy(manifest)
            return manifest

        def docker(*argv):
            state["calls"].append(argv)
            if argv[:2] == ("image", "inspect"):
                child = argv[2] == subject._IMAGE
                result = {
                    "Id": argv[2],
                    "RootFS": {"Layers": ["base", "child"] if child else ["base"]},
                }
                if child and failure == "image_id":
                    result["Id"] = "sha256:" + "0" * 64
                elif child and failure == "image_ancestry":
                    result["RootFS"]["Layers"] = ["different", "child"]
                elif child and failure == "image_not_child":
                    result["RootFS"]["Layers"] = ["base"]
                return json.dumps([result]).encode()
            if argv[0] == "create":
                if failure == "create":
                    raise RuntimeError("create failed after an uncertain daemon result")
                return b"invalid" if failure == "container_id" else _CONTAINER.encode()
            if argv[:2] == ("container", "inspect"):
                if failure == "inspect":
                    raise RuntimeError("inspect failed")
                inspected = {
                    "Id": _CONTAINER,
                    "Name": "/" + name,
                    "Image": subject._IMAGE,
                    "Config": {
                        "Image": subject._IMAGE,
                        "Labels": {
                            "dev.aragorn.snapshot-owner": _OWNER,
                            "dev.aragorn.source-commit": _SOURCE["commit"],
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
                                "Source": parent["runtime_volume"],
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
                            "Name": parent["runtime_volume"],
                            "RW": False,
                        }
                    ],
                }
                if failure in ("inspect_id", "inspect_name", "inspect_image"):
                    inspected[
                        {
                            "inspect_id": "Id",
                            "inspect_name": "Name",
                            "inspect_image": "Image",
                        }[failure]
                    ] = "unbound"
                elif failure in ("owner", "source_label"):
                    inspected["Config"]["Labels"][
                        "dev.aragorn.snapshot-owner"
                        if failure == "owner"
                        else "dev.aragorn.source-commit"
                    ] = "unbound"
                elif failure in ("network", "privileged", "cgroupns"):
                    key, value = {
                        "network": ("NetworkMode", "host"),
                        "privileged": ("Privileged", False),
                        "cgroupns": ("CgroupnsMode", "private"),
                    }[failure]
                    inspected["HostConfig"][key] = value
                elif failure == "configured_image":
                    inspected["Config"]["Image"] = "unbound"
                elif failure in (
                    "binds",
                    "mount_spec",
                    "tmpfs",
                    "security",
                    "ipc",
                    "userns",
                    "runtime",
                ):
                    key, value = {
                        "binds": ("Binds", ["/tmp:/extra:rw"]),
                        "mount_spec": ("Mounts", []),
                        "tmpfs": ("Tmpfs", {"/run": "rw,exec"}),
                        "security": ("SecurityOpt", ["seccomp=unconfined"]),
                        "ipc": ("IpcMode", "host"),
                        "userns": ("UsernsMode", "host"),
                        "runtime": ("Runtime", "unbound"),
                    }[failure]
                    inspected["HostConfig"][key] = value
                elif failure == "runtime_name":
                    inspected["Mounts"][0]["Name"] = "unbound"
                elif failure == "runtime_rw":
                    inspected["Mounts"][0]["RW"] = True
                elif failure == "runtime_duplicate":
                    inspected["Mounts"].append(deepcopy(inspected["Mounts"][0]))
                elif failure == "runtime_absent":
                    inspected["Mounts"] = []
                return json.dumps([inspected]).encode()
            if argv[0] == "cp":
                if failure == "copy":
                    raise RuntimeError("copy failed")
                path = Path(argv[1])
                self.assertTrue(path.is_file())
                self.assertFalse(path.is_symlink())
                raw = path.read_bytes()
                self.assertNotIn(argv[2], state["copies"])
                state["copies"][argv[2]] = (len(raw), subject.campaign._digest(raw))
                return b""
            if argv[0] == "start":
                if failure == "start":
                    raise RuntimeError("start failed")
                return b""
            if argv[0] == "exec" and "-c" in argv:
                self.assertEqual(
                    argv[1:8],
                    (
                        _CONTAINER,
                        "/usr/bin/python3.12",
                        "-I",
                        "-S",
                        "-B",
                        "-c",
                        subject._VERIFY,
                    ),
                )
                self.assertEqual(argv[-1], _CONTAINER)
                state["verify_inputs"] = json.loads(argv[-2])
                if failure == "verify":
                    raise RuntimeError("root custody verification failed")
                return b""
            if argv[0] == "exec" and checker in argv:
                self.assertEqual(
                    argv,
                    (
                        "exec",
                        _CONTAINER,
                        "/usr/bin/python3.12",
                        "-I",
                        "-S",
                        "-B",
                        checker,
                        _CONTAINER,
                    ),
                )
                if failure == "check":
                    raise RuntimeError("checker failed")
                value = deepcopy(observation)
                if failure == "observation_schema":
                    value["schema"] = "unbound"
                elif failure == "observation_container":
                    value["fixture_container"] = "d" * 64
                elif failure == "observation_status":
                    value["status"] = "PASS"
                elif failure in ("phase3", "run"):
                    value[
                        "phase3_eligible"
                        if failure == "phase3"
                        else "run_conformance_eligible"
                    ] = True
                elif failure == "bad_json":
                    return b"not json\n"
                if failure == "raw_format":
                    return (json.dumps(value, indent=2) + "\n").encode()
                return subject.campaign._canonical(value) + b"\n"
            raise AssertionError(f"unexpected mocked Docker call: {argv}")

        def cleanup(cleanup_name, owner, image):
            self.assertEqual(
                (cleanup_name, owner, image), (name, _OWNER, subject._IMAGE)
            )
            if failure == "cleanup":
                raise RuntimeError("owned cleanup failed")
            return {
                "name": cleanup_name,
                "owner": owner,
                "image": image,
                "container_name_absent": failure != "cleanup_name",
                "removed_id_absent": failure != "cleanup_id",
            }

        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    subject.existing.existing.acquisition,
                    "_run",
                    side_effect=AssertionError(
                        "live acquisition forbidden in unit tests"
                    ),
                )
            )
            stack.enter_context(
                patch.object(
                    subject.existing.existing, "_source_identity", side_effect=source
                )
            )
            stack.enter_context(
                patch.object(
                    subject.existing.existing.acquisition,
                    "_tree_file",
                    side_effect=tree_file,
                )
            )
            stack.enter_context(
                patch.object(subject.secrets, "token_hex", return_value=_OWNER)
            )
            state["snapshots"] = stack.enter_context(
                patch.object(
                    subject.existing.parent_snapshot,
                    "snapshot_parent",
                    side_effect=[before, after],
                )
            )
            state["cleanup"] = stack.enter_context(
                patch.object(
                    subject.existing.parent_snapshot,
                    "_cleanup_snapshot",
                    side_effect=cleanup,
                )
            )
            stack.enter_context(
                patch.object(stage_module, stage_name, side_effect=stage)
            )
            stack.enter_context(
                patch.object(subject.existing, "_docker", side_effect=docker)
            )
            yield state

    def test_journal_profile_reuses_capture_with_exact_55_files_and_three_helpers(self):
        with self.fixture(endpoint_journal=True) as state:
            result = subject._capture(endpoint_journal=True)
        self.assertEqual(
            result["schema"], "aragorn/runtime-endpoint-journal-systemd-capture/v1"
        )
        self.assertEqual(len(state["copies"]), 58)
        self.assertEqual(len(state["verify_inputs"]), 58)
        self.assertEqual(set(result["fixture_helpers"]), set(subject._JOURNAL_FILES))
        self.assertEqual(len(result["staged_profile"]["files"]), 55)
        self.assertEqual(len(result["staged_profile"]["new_dependencies"]), 10)
        for item in state["verify_inputs"].values():
            self.assertEqual(
                state["copies"][_CONTAINER + ":" + item["installed_path"]],
                (item["bytes"], item["digest"]),
            )
        self.assertEqual(state["source_calls"], 2)
        self.assertEqual(state["snapshots"].call_count, 2)
        self.assertIs(result["phase3_eligible"], False)
        self.assertIs(result["run_conformance_eligible"], False)
        state["cleanup"].assert_called_once_with(
            "aragorn-runtime-endpoint-journal-check-" + _OWNER[:16],
            _OWNER,
            subject._IMAGE,
        )
        self.assertTrue(all(not path.parent.exists() for path in state["stage_paths"]))

    def test_journal_profile_rejects_source_authority_execution_and_cleanup_failures(
        self,
    ):
        before_create = {
            "source_initial",
            "helper_source",
            "stage_count",
            "stage_duplicate",
            "journal_sources",
            "runtime_journal_deployed",
            "durable_event_retention",
            "run_qualification",
        }
        for failure in sorted(before_create) + [
            "verify",
            "check",
            "observation_schema",
            "phase3",
            "run",
            "cleanup_id",
            "parent_tree",
            "source_after",
        ]:
            with (
                self.subTest(failure=failure),
                self.fixture(failure, endpoint_journal=True) as state,
            ):
                with self.assertRaises(RuntimeError):
                    subject._capture(endpoint_journal=True)
                if failure in before_create:
                    self.assertFalse(
                        any(argv[0] == "create" for argv in state["calls"])
                    )
                    state["cleanup"].assert_not_called()
                else:
                    state["cleanup"].assert_called_once()
        for value in (0, 1, None, "true"):
            with (
                self.subTest(value=value),
                patch.object(subject.existing.existing, "_source_identity") as source,
            ):
                with self.assertRaises(RuntimeError):
                    subject._capture(endpoint_journal=value)
                source.assert_not_called()

    def test_fixed_successor_copies_exact_fifty_four_payloads_and_two_helpers(self):
        with self.fixture() as state:
            result = subject._capture()
        self.assertEqual(
            subject._IMAGE,
            "sha256:1c75f0c37070aa5b702e134e6e6c830690f596891ce0f4fa389ea7515300ea17",
        )
        self.assertEqual(
            result["schema"], "aragorn/runtime-quarantine-systemd-capture/v1"
        )
        self.assertEqual(
            result["authority"],
            "LOCAL_SUCCESSOR_FIXTURE_NOT_RUN_OR_PHASE3_QUALIFICATION",
        )
        self.assertEqual(result["staged_profile"], state["manifest"])
        self.assertEqual(len(state["copies"]), 56)
        self.assertEqual(len(state["verify_inputs"]), 56)
        self.assertEqual(set(result["fixture_helpers"]), set(subject._FILES))
        for item in state["verify_inputs"].values():
            self.assertEqual(
                state["copies"][_CONTAINER + ":" + item["installed_path"]],
                (item["bytes"], item["digest"]),
            )
            self.assertIn(item["installed_mode"], ("0444", "0644", "0755"))
        create = next(argv for argv in state["calls"] if argv[0] == "create")
        for value in (
            "--pull=never",
            "--privileged",
            "--cgroupns=host",
            "--network=none",
            "label=disable",
            "dev.aragorn.snapshot-owner=" + _OWNER,
            "dev.aragorn.source-commit=" + _SOURCE["commit"],
        ):
            self.assertIn(value, create)
        self.assertEqual(create[-1], subject._IMAGE)
        self.assertEqual(result["fixture_container"], _CONTAINER)
        self.assertEqual(result["source"], _SOURCE)
        self.assertEqual(state["source_calls"], 2)
        self.assertEqual(state["snapshots"].call_count, 2)
        state["cleanup"].assert_called_once_with(_NAME, _OWNER, subject._IMAGE)
        for value in (result, result["observation"]):
            self.assertIs(value["phase3_eligible"], False)
            self.assertIs(value["run_conformance_eligible"], False)
        self.assertTrue(all(not path.parent.exists() for path in state["stage_paths"]))

    def test_owned_cleanup_runs_on_create_copy_start_verify_and_check_failures(self):
        for failure in (
            "create",
            "container_id",
            "inspect",
            "copy",
            "start",
            "verify",
            "check",
            "cleanup",
            "cleanup_name",
            "cleanup_id",
        ):
            with self.subTest(failure=failure), self.fixture(failure) as state:
                with self.assertRaises(RuntimeError):
                    subject._capture()
                state["cleanup"].assert_called_once_with(_NAME, _OWNER, subject._IMAGE)
                self.assertTrue(
                    all(not path.parent.exists() for path in state["stage_paths"])
                )

    def test_pre_creation_source_image_and_staging_failures_never_create(self):
        for failure in (
            "source_initial",
            "helper_source",
            "image_id",
            "image_ancestry",
            "image_not_child",
            "stage",
            "stage_count",
            "stage_duplicate",
            "stage_authority",
        ):
            with self.subTest(failure=failure), self.fixture(failure) as state:
                with self.assertRaises(RuntimeError):
                    subject._capture()
                self.assertFalse(any(argv[0] == "create" for argv in state["calls"]))
                state["cleanup"].assert_not_called()
                self.assertTrue(
                    all(not path.parent.exists() for path in state["stage_paths"])
                )

    def test_created_identity_network_privilege_and_runtime_mount_are_bound(self):
        for failure in (
            "inspect_id",
            "inspect_name",
            "inspect_image",
            "owner",
            "source_label",
            "network",
            "privileged",
            "cgroupns",
            "configured_image",
            "binds",
            "mount_spec",
            "tmpfs",
            "security",
            "ipc",
            "userns",
            "runtime",
            "runtime_name",
            "runtime_rw",
            "runtime_duplicate",
            "runtime_absent",
        ):
            with self.subTest(failure=failure), self.fixture(failure) as state:
                with self.assertRaises(RuntimeError):
                    subject._capture()
                state["cleanup"].assert_called_once()
                self.assertFalse(
                    any(argv[0] in ("cp", "start", "exec") for argv in state["calls"])
                )

    def test_raw_observation_identity_and_claim_ceiling_fail_closed(self):
        for failure in (
            "observation_schema",
            "observation_container",
            "observation_status",
            "phase3",
            "run",
            "bad_json",
            "raw_format",
        ):
            with self.subTest(failure=failure), self.fixture(failure) as state:
                with self.assertRaises((RuntimeError, ValueError)):
                    subject._capture()
                state["cleanup"].assert_called_once()

    def test_parent_and_source_changes_refuse_observed_result_after_cleanup(self):
        for failure in (
            "parent_image",
            "parent_volume",
            "parent_tree",
            "parent_contract",
            "source_after",
        ):
            with self.subTest(failure=failure), self.fixture(failure) as state:
                with self.assertRaises(RuntimeError):
                    subject._capture()
                state["cleanup"].assert_called_once()
                self.assertEqual(state["snapshots"].call_count, 2)

    def test_root_custody_script_uses_same_fd_and_refuses_identity_or_byte_drift(self):
        # Execute only the fixed verifier with entirely fake paths and descriptors:
        # no Linux namespaces, real root operations, or filesystem writes occur.
        raw = b"data"
        expected = {
            "fixture": {
                "installed_path": "/usr/lib/aragorn/fixture.py",
                "installed_mode": "0644",
                "bytes": len(raw),
                "digest": subject.campaign._digest(raw),
            }
        }
        for failure in (
            None,
            "uid",
            "container",
            "cgroup",
            "parent_symlink",
            "file_type",
            "nlink",
            "size",
            "first_read",
            "owner",
            "mode",
            "named_metadata",
            "second_read",
            "fd_metadata",
        ):
            with self.subTest(failure=failure):
                current = {
                    "st_dev": 1,
                    "st_ino": 2,
                    "st_mode": stat.S_IFREG | 0o600,
                    "st_uid": 500,
                    "st_gid": 500,
                    "st_nlink": 1,
                    "st_size": len(raw),
                    "st_mtime_ns": 1,
                    "st_ctime_ns": 2,
                }
                if failure == "file_type":
                    current["st_mode"] = stat.S_IFLNK | 0o777
                elif failure == "nlink":
                    current["st_nlink"] = 2
                elif failure == "size":
                    current["st_size"] += 1
                counts = {"reads": 0, "stats": 0}

                class FakePath:
                    def __init__(self, path):
                        self.path = path

                    def resolve(self, *, strict, failure=failure):
                        return (
                            FakePath("/elsewhere")
                            if failure == "parent_symlink"
                            else self
                        )

                    def read_text(self, failure=failure):
                        return (
                            "0::/init.scope\n"
                            if failure == "cgroup"
                            else f"0::/docker/{_CONTAINER}/init.scope\n"
                        )

                    def lstat(self, current=current, failure=failure):
                        values = dict(current)
                        if failure == "named_metadata":
                            values["st_ino"] += 1
                        return SimpleNamespace(**values)

                    def exists(self):
                        return True

                    def is_dir(self):
                        return True

                def fstat(fd, counts=counts, current=current, failure=failure):
                    self.assertEqual(fd, 99)
                    counts["stats"] += 1
                    values = dict(current)
                    if failure == "fd_metadata" and counts["stats"] >= 3:
                        values["st_ino"] += 1
                    return SimpleNamespace(**values)

                def read(fd, size, counts=counts, failure=failure):
                    self.assertEqual((fd, size), (99, len(raw) + 1))
                    counts["reads"] += 1
                    if (
                        failure == "first_read"
                        or failure == "second_read"
                        and counts["reads"] >= 2
                    ):
                        return b"evil"
                    return raw

                def chown(fd, uid, gid, current=current, failure=failure):
                    self.assertEqual((fd, uid, gid), (99, 0, 0))
                    if failure != "owner":
                        current.update(st_uid=0, st_gid=0)

                def chmod(fd, mode, current=current, failure=failure):
                    self.assertEqual((fd, mode), (99, 0o644))
                    current["st_mode"] = stat.S_IFREG | (
                        0o666 if failure == "mode" else mode
                    )

                with (
                    patch("pathlib.Path", FakePath),
                    patch.object(
                        subject.sys,
                        "argv",
                        [
                            "-c",
                            json.dumps(expected),
                            "invalid" if failure == "container" else _CONTAINER,
                        ],
                    ),
                    patch.object(
                        os, "geteuid", return_value=500 if failure == "uid" else 0
                    ),
                    patch.object(os, "open", return_value=99) as opened,
                    patch.object(os, "fstat", side_effect=fstat),
                    patch.object(os, "read", side_effect=read),
                    patch.object(os, "fchown", side_effect=chown) as owned,
                    patch.object(os, "fchmod", side_effect=chmod),
                    patch.object(os, "lseek", return_value=0) as seek,
                    patch.object(os, "close") as closed,
                ):
                    if failure is None:
                        exec(subject._VERIFY, {})  # noqa: S102 - fixed verifier, mocked OS
                        self.assertEqual(counts["reads"], 2)
                        seek.assert_called_once_with(99, 0, os.SEEK_SET)
                    else:
                        with self.assertRaises(RuntimeError):
                            exec(subject._VERIFY, {})  # noqa: S102 - fixed verifier, mocked OS
                    if opened.called:
                        flags = opened.call_args.args[1]
                        self.assertEqual(
                            flags,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                        )
                        closed.assert_called_once_with(99)
                    else:
                        closed.assert_not_called()
                    if failure in (
                        "uid",
                        "container",
                        "cgroup",
                        "parent_symlink",
                        "file_type",
                        "nlink",
                        "size",
                        "first_read",
                    ):
                        owned.assert_not_called()

    def test_main_requires_absent_absolute_output_and_never_overwrites(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            result = {
                "status": "OBSERVED",
                "phase3_eligible": False,
                "run_conformance_eligible": False,
            }
            with patch.object(subject, "_capture", return_value=result) as capture:
                with redirect_stderr(StringIO()):
                    self.assertEqual(subject.main([]), 64)
                    self.assertEqual(subject.main(["a", "b"]), 64)
                    self.assertEqual(subject.main(["--endpoint-journal"]), 64)
                    self.assertEqual(subject.main(["--unknown"]), 64)
                existing = root / "existing.json"
                existing.write_bytes(b"untouched")
                linked = root / "linked.json"
                linked.symlink_to(root / "absent.json")
                for output in ("relative.json", str(existing), str(root), str(linked)):
                    with self.subTest(output=output), self.assertRaises(RuntimeError):
                        subject.main([output])
                capture.assert_not_called()
                output = root / "capture.json"
                stdout = StringIO()
                with redirect_stdout(stdout):
                    self.assertEqual(subject.main([str(output)]), 0)
                raw = output.read_bytes()
                self.assertEqual(raw, subject.campaign._canonical(result))
                self.assertEqual(
                    json.loads(stdout.getvalue()),
                    {
                        "status": "OBSERVED",
                        "path": str(output),
                        "digest": subject.campaign._digest(raw),
                    },
                )
                self.assertEqual(existing.read_bytes(), b"untouched")
                capture.assert_called_once_with()
                capture.reset_mock()
                journal_output = root / "journal.json"
                with redirect_stdout(StringIO()):
                    self.assertEqual(
                        subject.main(["--endpoint-journal", str(journal_output)]), 0
                    )
                capture.assert_called_once_with(endpoint_journal=True)
                self.assertEqual(journal_output.read_bytes(), raw)
            failed = root / "failed.json"
            with (
                patch.object(
                    subject, "_capture", side_effect=RuntimeError("capture failed")
                ),
                self.assertRaises(RuntimeError),
            ):
                subject.main([str(failed)])
            self.assertFalse(failed.exists())
            raced = root / "raced.json"

            def race():
                raced.write_bytes(b"other caller")
                return result

            with (
                patch.object(subject, "_capture", side_effect=race),
                self.assertRaises(FileExistsError),
            ):
                subject.main([str(raced)])
            self.assertEqual(raced.read_bytes(), b"other caller")


if __name__ == "__main__":
    unittest.main()
