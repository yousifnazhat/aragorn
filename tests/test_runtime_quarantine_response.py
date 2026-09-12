from __future__ import annotations

import copy
import fcntl
import json
import os
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from types import SimpleNamespace
from unittest import TestCase, main, mock

from aragorn import protected_skill_quarantine as quarantine
from aragorn import runtime_quarantine_response as subject
from aragorn import runtime_response_service as response
from aragorn import runtime_skill_startup as startup
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_runtime_response_service as response_tests
from tests.test_runtime_action_broker import _Fixture, _write_control
from tests.test_runtime_skill_startup import (
    _fixture as _installed_fixture,
)
from tests.test_runtime_skill_startup import (
    _require_unlocked,
    _sha,
    _write,
)


@contextmanager
def _fixture():
    uid = os.geteuid()
    with _installed_fixture() as installed:
        broker_root = installed["root"].parent / "runtime"
        broker_root.mkdir(mode=0o700)
        broker = _Fixture(broker_root)
        digest = _sha(installed["raw"])
        broker.policy["allow"][0]["active_skill_digest"] = digest
        _write_control(broker.paths["policy"], broker.policy)
        with mock.patch.object(response_tests, "_SKILL", digest):
            accepted = response_tests._accepted(broker)
            with (
                response_tests._environment(broker) as (binding, events, stop),
                mock.patch.object(os, "geteuid", return_value=uid),
                mock.patch.object(subject, "_require_root"),
                mock.patch.object(
                    response,
                    "_mask_future_starts",
                    return_value={"status": "FIXED_PROFILE_MASKED"},
                ) as mask,
                mock.patch.object(
                    response,
                    "_retain_result",
                    side_effect=lambda result: {"response": result, "retained": True},
                ) as retain,
                mock.patch.object(
                    response,
                    "_command",
                    side_effect=AssertionError(
                        "live commands are forbidden in these tests"
                    ),
                ),
            ):
                yield {
                    **installed,
                    "broker": broker,
                    "binding": binding,
                    "accepted": accepted,
                    "digest": digest,
                    "snapshot": canonical_digest(accepted),
                    "events": events,
                    "stop": stop,
                    "mask": mask,
                    "retain": retain,
                }


def _run(fixture):
    return subject._quarantine_fixed_runtime_profile(
        fixture["digest"], fixture["snapshot"]
    )


def _marker_path(fixture):
    return fixture["root"] / (
        ".aragorn-quarantined-skill-" + fixture["digest"][7:] + ".json"
    )


def _marker(fixture):
    return json.loads(_marker_path(fixture).read_bytes())


def _check_install_ex(test, root):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with test.assertRaises(BlockingIOError):
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    finally:
        os.close(fd)


class RuntimeQuarantineResponseTests(TestCase):
    def test_publication_root_refresh_allows_only_portable_expected_link_delta(self):
        cases = (
            (True, 0, None, True),
            (True, 1, None, True),
            (False, 0, None, True),
            (False, 1, None, False),
            (True, 2, None, False),
            (True, -1, None, False),
            (False, -1, None, False),
            (True, 1, "mode", False),
            (True, 1, "owner", False),
            (True, 1, "inode", False),
            (True, 1, "named-fd", False),
            (True, 1, "names", False),
        )
        with _fixture() as fixture:
            fd = startup._open_protected_root(fixture["root"], os.geteuid())
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                before = os.fstat(fd)
                baseline = startup._HeldEntry(None, fixture["root"], fd, before)
                values = {
                    name: getattr(before, name)
                    for name in dir(before)
                    if name.startswith("st_")
                }
                for new_record, delta, mutation, allowed in cases:
                    with self.subTest(
                        new_record=new_record, delta=delta, mutation=mutation
                    ):
                        fields = {**values, "st_nlink": before.st_nlink + delta}
                        if mutation == "mode":
                            fields["st_mode"] ^= 0o200
                        elif mutation == "owner":
                            fields["st_uid"] += 1
                        elif mutation == "inode":
                            fields["st_ino"] += 1
                        current = SimpleNamespace(**fields)
                        named = SimpleNamespace(
                            **{
                                **fields,
                                "st_ino": fields["st_ino"]
                                + int(mutation == "named-fd"),
                            }
                        )
                        names = set(os.listdir(fd))
                        if mutation == "names":
                            names.add("unexpected-name")
                        entries = [baseline]
                        with (
                            mock.patch.object(
                                subject.os, "fstat", return_value=current
                            ),
                            mock.patch.object(subject.os, "lstat", return_value=named),
                        ):
                            if allowed:
                                subject._refresh_published_root(
                                    fd, entries, names, new_record=new_record
                                )
                                self.assertIs(entries[0].before, current)
                            else:
                                with self.assertRaisesRegex(
                                    subject.RuntimeQuarantineError, "root changed"
                                ):
                                    subject._refresh_published_root(
                                        fd, entries, names, new_record=new_record
                                    )
                                self.assertIs(entries[0], baseline)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)

    def test_actual_root_gate_is_linux_root_only_without_invoking_effects(self):
        for platform, uid in (("darwin", 0), ("linux", 1)):
            with (
                self.subTest(platform=platform, uid=uid),
                mock.patch.object(subject.sys, "platform", platform),
                mock.patch.object(subject.os, "geteuid", return_value=uid),
                self.assertRaisesRegex(subject.RuntimeQuarantineError, "root Linux"),
            ):
                subject._require_root()
        with (
            mock.patch.object(subject.sys, "platform", "linux"),
            mock.patch.object(subject.os, "geteuid", return_value=0),
        ):
            self.assertIsNone(subject._require_root())

    def test_real_digest_denial_precedes_mocked_stop_and_is_retained(self):
        with _fixture() as fixture:
            original_stop = fixture["stop"].side_effect

            def stop():
                self.assertEqual(_marker(fixture)["skill_digest"], fixture["digest"])
                self.assertEqual(
                    _marker(fixture)["revocation_snapshot_digest"], fixture["snapshot"]
                )
                _check_install_ex(self, fixture["root"])
                original_stop()

            fixture["stop"].side_effect = stop
            result = _run(fixture)
            self.assertTrue(result["retained"])
            fixture["stop"].assert_called_once_with()
            fixture["mask"].assert_called_once_with()
            fixture["retain"].assert_called_once()
            self.assertEqual(
                fixture["events"], ["activation-lock", "stop", "activation-unlock"]
            )
            self.assertEqual(_marker_path(fixture).stat().st_mode & 0o777, 0o444)
            self.assertEqual(_marker_path(fixture).stat().st_nlink, 1)
            self.assertEqual(_marker_path(fixture).stat().st_uid, os.geteuid())
            _require_unlocked(fixture["root"])

    def test_request_digest_and_root_gate_fail_before_authority_or_effects(self):
        invalid = (
            None,
            True,
            1,
            "sha256:" + "A" * 64,
            "sha256:+" + "1" * 63,
            "sha256:" + "1_" * 32,
            "sha256:" + " " + "1" * 63,
            "sha256:" + "a" * 64 + "\n",
        )
        for value in invalid:
            for index in (0, 1):
                with self.subTest(value=value, index=index), _fixture() as fixture:
                    arguments = [fixture["digest"], fixture["snapshot"]]
                    arguments[index] = value
                    with self.assertRaises(subject.RuntimeQuarantineError):
                        subject._quarantine_fixed_runtime_profile(*arguments)
                    self.assertEqual(fixture["events"], [])
                    fixture["stop"].assert_not_called()
                    fixture["mask"].assert_not_called()
                    fixture["retain"].assert_not_called()
                    self.assertFalse(_marker_path(fixture).exists())
        with _fixture() as fixture:
            with (
                mock.patch.object(
                    subject,
                    "_require_root",
                    side_effect=subject.RuntimeQuarantineError("root Linux required"),
                ),
                self.assertRaises(subject.RuntimeQuarantineError),
            ):
                _run(fixture)
            self.assertEqual(fixture["events"], [])
            self.assertFalse(_marker_path(fixture).exists())

    def test_installed_requested_and_running_binding_digests_must_agree(self):
        for mutation in (
            "binding",
            "requested",
            "binding-and-request",
            "installed-bytes",
            "installed-record",
        ):
            with self.subTest(mutation=mutation), _fixture() as fixture:
                other = "sha256:" + "9" * 64
                if mutation in {"binding", "binding-and-request"}:
                    response._read_bindings.return_value = replace(
                        fixture["binding"], active_skill_digest=other
                    )
                if mutation in {"requested", "binding-and-request"}:
                    fixture["digest"] = other
                if mutation == "installed-bytes":
                    _write(fixture["skill"], b"changed installed bytes")
                if mutation == "installed-record":
                    _write(fixture["root"] / startup.ACTIVE_RUNTIME_RECORD, b"{")
                with self.assertRaises(subject.RuntimeQuarantineError) as caught:
                    _run(fixture)
                self.assertNotIsInstance(
                    caught.exception, subject.RuntimeQuarantineIndeterminate
                )
                fixture["stop"].assert_not_called()
                fixture["mask"].assert_not_called()
                fixture["retain"].assert_not_called()
                self.assertFalse(
                    any(fixture["root"].glob(".aragorn-quarantined-skill-*.json"))
                )
                _require_unlocked(fixture["root"])

    def test_revocation_must_be_accepted_bound_current_and_revoke_actual_digest(self):
        mutations = (
            {"generation": 3},
            {"generation": 5},
            {"generation": True},
            {"source_digest": "sha256:" + "9" * 64},
            {"observed_at_unix": 80, "expires_at_unix": 90},
            {"observed_at_unix": 101, "expires_at_unix": 110},
            {"skill_digests": []},
            {"extra": "field"},
            "malformed",
            "missing",
            "policy",
            "expected-snapshot",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), _fixture() as fixture:
                broker = fixture["broker"]
                if isinstance(mutation, dict):
                    document = {**fixture["accepted"], **mutation}
                    _write_control(broker.paths["revocations"], document)
                    fixture["snapshot"] = canonical_digest(document)
                elif mutation == "malformed":
                    _write(broker.paths["revocations"], b"{", 0o400)
                elif mutation == "missing":
                    broker.paths["revocations"].unlink()
                elif mutation == "policy":
                    _write_control(
                        broker.paths["policy"], {**broker.policy, "version": 2}
                    )
                else:
                    fixture["snapshot"] = "sha256:" + "9" * 64
                with self.assertRaises(subject.RuntimeQuarantineError) as caught:
                    _run(fixture)
                self.assertNotIsInstance(
                    caught.exception, subject.RuntimeQuarantineIndeterminate
                )
                fixture["stop"].assert_not_called()
                fixture["mask"].assert_not_called()
                fixture["retain"].assert_not_called()
                self.assertFalse(_marker_path(fixture).exists())
                _require_unlocked(fixture["root"])

    def test_lock_order_and_exclusion_extend_through_publication_effects_and_retention(
        self,
    ):
        with _fixture() as fixture:
            real_guard = response._broker_guard
            real_publish = subject.publish_quarantine_at
            original_stop = fixture["stop"].side_effect
            observations = []

            def require_locks(stage):
                self.assertEqual(fixture["events"][0], "activation-lock")
                self.assertNotIn("activation-unlock", fixture["events"])
                _check_install_ex(self, fixture["root"])
                with (
                    fixture["broker"].lock_path.open("rb") as other,
                    self.assertRaises(BlockingIOError),
                ):
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                observations.append(stage)

            @contextmanager
            def broker_guard(config):
                self.assertEqual(fixture["events"], ["activation-lock"])
                _check_install_ex(self, fixture["root"])
                with real_guard(config) as fd:
                    require_locks("broker")
                    yield fd

            def publish(*args, **kwargs):
                require_locks("publish")
                return real_publish(*args, **kwargs)

            def stop():
                require_locks("stop")
                self.assertTrue(_marker_path(fixture).exists())
                original_stop()

            def mask():
                require_locks("mask")
                self.assertIn("stop", fixture["events"])
                return {"status": "FIXED_PROFILE_MASKED"}

            def retain(result):
                require_locks("retain")
                self.assertEqual(result["denial_record"], _marker(fixture))
                return {"response": result}

            fixture["stop"].side_effect = stop
            fixture["mask"].side_effect = mask
            fixture["retain"].side_effect = retain
            with (
                mock.patch.object(response, "_broker_guard", side_effect=broker_guard),
                mock.patch.object(
                    subject, "publish_quarantine_at", side_effect=publish
                ),
            ):
                result = _run(fixture)["response"]
            self.assertEqual(
                observations, ["broker", "publish", "stop", "mask", "retain"]
            )
            self.assertEqual(
                result["denial_record_digest"], canonical_digest(_marker(fixture))
            )
            self.assertEqual(result["expected_skill_digest"], fixture["digest"])
            self.assertEqual(result["revocation_snapshot_digest"], fixture["snapshot"])
            for ceiling in (
                "PRIVATE_COMPOSITION_NOT_DEPLOYED_OR_AUTOMATIC_DISPATCH",
                "DIGEST_ENFORCEMENT_REQUIRES_SUCCESSOR_PRODUCERS_RUNTIME_AND_STARTUP_GATE",
                "RUNNING_BINDING_AND_INSTALLED_BYTES_NOT_PROCESS_BYTE_CONSUMPTION",
                "NO_INDEPENDENT_RUN_PHASE3_EDR_OR_RELEASE_QUALIFICATION",
            ):
                self.assertIn(ceiling, result["limitations"])
            _require_unlocked(fixture["root"])

    def test_install_and_activation_contention_refuse_before_publication(self):
        for kind in ("install-SH", "install-EX", "activation"):
            with self.subTest(kind=kind), _fixture() as fixture, ExitStack() as patches:
                if kind == "activation":
                    patches.enter_context(
                        mock.patch.object(
                            response,
                            "_activation_guard",
                            side_effect=BlockingIOError("busy"),
                        )
                    )
                else:
                    fd = os.open(fixture["root"], os.O_RDONLY | os.O_DIRECTORY)
                    patches.callback(os.close, fd)
                    fcntl.flock(
                        fd,
                        (fcntl.LOCK_SH if kind == "install-SH" else fcntl.LOCK_EX)
                        | fcntl.LOCK_NB,
                    )
                    patches.callback(fcntl.flock, fd, fcntl.LOCK_UN)
                with self.assertRaises(subject.RuntimeQuarantineError) as caught:
                    _run(fixture)
                self.assertNotIsInstance(
                    caught.exception, subject.RuntimeQuarantineIndeterminate
                )
                fixture["stop"].assert_not_called()
                fixture["mask"].assert_not_called()
                fixture["retain"].assert_not_called()
                self.assertFalse(_marker_path(fixture).exists())

    def test_snapshot_binding_process_and_installed_state_are_rechecked_before_publication(
        self,
    ):
        for change in ("time", "snapshot", "binding", "process", "installed"):
            with (
                self.subTest(change=change),
                _fixture() as fixture,
                ExitStack() as patches,
            ):
                if change == "time":
                    patches.enter_context(
                        mock.patch.object(response.time, "time", side_effect=[100, 106])
                    )
                elif change == "binding":
                    wrong = replace(
                        fixture["binding"], active_skill_digest="sha256:" + "9" * 64
                    )
                    response._read_bindings.side_effect = [fixture["binding"], wrong]
                elif change == "process":
                    initial = copy.deepcopy(response._process_identity.return_value)
                    response._process_identity.side_effect = [
                        initial,
                        initial,
                        {**initial, "start_time_ticks": 999},
                    ]
                else:
                    original = response._locked_revocations

                    def after_read(
                        *args,
                        original=original,
                        fixture=fixture,
                        change=change,
                        **kwargs,
                    ):
                        result = original(*args, **kwargs)
                        if change == "snapshot":
                            _write_control(
                                fixture["broker"].paths["revocations"],
                                {**fixture["accepted"], "skill_digests": []},
                            )
                        else:
                            _write(fixture["skill"], fixture["raw"])
                        return result

                    patches.enter_context(
                        mock.patch.object(
                            response, "_locked_revocations", side_effect=after_read
                        )
                    )
                with self.assertRaises(subject.RuntimeQuarantineError) as caught:
                    _run(fixture)
                self.assertNotIsInstance(
                    caught.exception, subject.RuntimeQuarantineIndeterminate
                )
                fixture["stop"].assert_not_called()
                self.assertFalse(_marker_path(fixture).exists())
                _require_unlocked(fixture["root"])

    def test_any_publication_attempt_failure_is_indeterminate_without_rollback(self):
        for write_first in (False, True):
            for failure in (
                OSError("write failed"),
                KeyboardInterrupt(),
                SystemExit(2),
            ):
                with (
                    self.subTest(write_first=write_first, failure=type(failure)),
                    _fixture() as fixture,
                ):
                    original = subject.publish_quarantine_at

                    def fail(
                        *args,
                        original=original,
                        write_first=write_first,
                        failure=failure,
                        **kwargs,
                    ):
                        if write_first:
                            original(*args, **kwargs)
                        raise failure

                    with (
                        mock.patch.object(
                            subject, "publish_quarantine_at", side_effect=fail
                        ),
                        self.assertRaises(subject.RuntimeQuarantineIndeterminate),
                    ):
                        _run(fixture)
                    self.assertIs(_marker_path(fixture).exists(), write_first)
                    if write_first:
                        self.assertEqual(
                            _marker(fixture)["skill_digest"], fixture["digest"]
                        )
                    fixture["stop"].assert_not_called()
                    fixture["mask"].assert_not_called()
                    fixture["retain"].assert_not_called()
                    _require_unlocked(fixture["root"])

    def test_marker_publication_does_not_reset_immutable_or_root_custody_baselines(
        self,
    ):
        for change in (
            "root-rebind",
            "root-mode",
            "extra-name",
            "record",
            "skill",
            "active-link",
        ):
            with self.subTest(change=change), _fixture() as fixture:
                original = subject.publish_quarantine_at
                marker_path = _marker_path(fixture)
                retained_paths = []

                def mutate(
                    *args,
                    original=original,
                    fixture=fixture,
                    change=change,
                    marker_path=marker_path,
                    retained_paths=retained_paths,
                    **kwargs,
                ):
                    record = original(*args, **kwargs)
                    retained_paths.append(marker_path)
                    if change == "root-rebind":
                        moved = fixture["root"].with_name("moved-root")
                        fixture["root"].rename(moved)
                        fixture["root"].mkdir(mode=0o700)
                        retained_paths[-1] = moved / marker_path.name
                    elif change == "root-mode":
                        fixture["root"].chmod(0o755)
                    elif change == "extra-name":
                        _write(fixture["root"] / "unexpected", b"new entry")
                    elif change == "record":
                        path = fixture["root"] / startup.ACTIVE_RUNTIME_RECORD
                        _write(path, path.read_bytes())
                    elif change == "skill":
                        _write(fixture["skill"], fixture["raw"])
                    else:
                        transaction = fixture["transaction"]
                        active = (
                            fixture["root"] / transaction["destination"]["target_name"]
                        )
                        active.unlink()
                        active.symlink_to(transaction["version_path"])
                    return record

                with (
                    mock.patch.object(
                        subject, "publish_quarantine_at", side_effect=mutate
                    ),
                    self.assertRaises(subject.RuntimeQuarantineIndeterminate),
                ):
                    _run(fixture)
                self.assertEqual(len(retained_paths), 1)
                self.assertTrue(retained_paths[0].exists())
                fixture["stop"].assert_not_called()
                fixture["mask"].assert_not_called()
                fixture["retain"].assert_not_called()
                _require_unlocked(fixture["root"])

    def test_partial_stop_mask_or_retention_failure_preserves_denial_and_is_indeterminate(
        self,
    ):
        for stage in (
            "stop",
            "unit-still-active",
            "cgroup",
            "cgroup-identity",
            "mask",
            "retain",
            "retain-interrupt",
        ):
            with (
                self.subTest(stage=stage),
                _fixture() as fixture,
                ExitStack() as patches,
            ):
                if stage == "stop":
                    fixture["stop"].side_effect = OSError("stop failed")
                elif stage == "unit-still-active":
                    fixture["stop"].side_effect = None
                elif stage == "cgroup":
                    patches.enter_context(
                        mock.patch.object(
                            response,
                            "_cgroup_empty",
                            side_effect=response.RuntimeResponseError("populated"),
                        )
                    )
                elif stage == "cgroup-identity":
                    response._cgroup_empty.return_value = {
                        "status": "EMPTY",
                        "device": 999,
                        "inode": 999,
                    }
                elif stage == "mask":
                    fixture["mask"].side_effect = OSError("mask failed")
                elif stage == "retain":
                    fixture["retain"].side_effect = response.CASError(
                        "retention failed"
                    )
                else:
                    fixture["retain"].side_effect = KeyboardInterrupt()
                with self.assertRaises(subject.RuntimeQuarantineIndeterminate):
                    _run(fixture)
                self.assertEqual(
                    _marker(fixture)["revocation_snapshot_digest"], fixture["snapshot"]
                )
                fixture["stop"].assert_called_once_with()
                if stage not in {"mask", "retain", "retain-interrupt"}:
                    fixture["mask"].assert_not_called()
                if stage not in {"retain", "retain-interrupt"}:
                    fixture["retain"].assert_not_called()
                _require_unlocked(fixture["root"])

    def test_existing_marker_is_permanent_and_new_accepted_snapshot_does_not_overwrite(
        self,
    ):
        with _fixture() as fixture:
            original_snapshot = "sha256:" + "f" * 64
            fd = os.open(fixture["root"], os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                original = quarantine.publish_quarantine_at(
                    fd, fixture["digest"], original_snapshot, expected_uid=os.geteuid()
                )
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            raw = _marker_path(fixture).read_bytes()
            result = _run(fixture)["response"]
            self.assertEqual(result["revocation_snapshot_digest"], fixture["snapshot"])
            self.assertNotEqual(fixture["snapshot"], original_snapshot)
            self.assertEqual(result["denial_record"], original)
            self.assertEqual(result["denial_record_digest"], canonical_digest(original))
            self.assertEqual(_marker_path(fixture).read_bytes(), raw)

    def test_malformed_existing_marker_is_never_overwritten_or_removed(self):
        with _fixture() as fixture:
            path = _marker_path(fixture)
            _write(path, b"{")
            with self.assertRaises(subject.RuntimeQuarantineIndeterminate):
                _run(fixture)
            self.assertEqual(path.read_bytes(), b"{")
            fixture["stop"].assert_not_called()
            fixture["mask"].assert_not_called()
            fixture["retain"].assert_not_called()
            _require_unlocked(fixture["root"])

    def test_cleanup_failure_after_effects_is_indeterminate_and_keeps_denial(self):
        with _fixture() as fixture:
            original = response.broker._release_lock_and_close
            root_inode = fixture["root"].stat().st_ino

            def failed_cleanup(lock_fd, locked, *descriptors):
                is_install = lock_fd >= 0 and os.fstat(lock_fd).st_ino == root_inode
                result = original(lock_fd, locked, *descriptors)
                self.assertIsNone(result)
                return (
                    OSError("injected installed-root cleanup failure")
                    if is_install
                    else None
                )

            with (
                mock.patch.object(
                    response.broker,
                    "_release_lock_and_close",
                    side_effect=failed_cleanup,
                ),
                self.assertRaises(subject.RuntimeQuarantineIndeterminate),
            ):
                _run(fixture)
            fixture["stop"].assert_called_once_with()
            fixture["mask"].assert_called_once_with()
            fixture["retain"].assert_called_once()
            self.assertEqual(_marker(fixture)["skill_digest"], fixture["digest"])
            _require_unlocked(fixture["root"])

    def test_open_descriptors_close_on_success_and_before_or_after_effect_failure(self):
        for failure in ("none", "before", "after"):
            with self.subTest(failure=failure), _fixture() as fixture:
                original = os.open
                opened = []

                def track(*args, original=original, opened=opened, **kwargs):
                    fd = original(*args, **kwargs)
                    opened.append(fd)
                    return fd

                if failure == "before":
                    _write(fixture["skill"], b"changed installed bytes")
                elif failure == "after":
                    fixture["stop"].side_effect = OSError("stop failed")
                with mock.patch.object(subject.os, "open", side_effect=track):
                    if failure == "none":
                        _run(fixture)
                    else:
                        expected = (
                            subject.RuntimeQuarantineError
                            if failure == "before"
                            else subject.RuntimeQuarantineIndeterminate
                        )
                        with self.assertRaises(expected):
                            _run(fixture)
                self.assertGreater(len(opened), 0)
                for fd in opened:
                    with self.assertRaises(OSError):
                        os.fstat(fd)
                _require_unlocked(fixture["root"])


if __name__ == "__main__":
    main()
