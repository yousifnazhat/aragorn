from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest import mock

from aragorn import runtime_skill_startup as subject
from aragorn.acquire import inventory_open_directory
from aragorn.oci_worker_protocol import canonical_digest
from aragorn.protected_skill_quarantine import publish_quarantine_at
from aragorn.runtime_action_broker import RuntimeActionBrokerError
from aragorn.runtime_action_worker import RuntimeActionWorkerBinding
from aragorn.runtime_active_skill_lineage import ACTIVE_RUNTIME_RECORD
from tests.test_runtime_active_skill_lineage import (
    _activate,
    _digest,
    _materialize,
    _publish_record,
    _transaction,
)

_PROFILE = (
    Path(__file__).resolve().parents[1]
    / "benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json"
)


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _write(path: Path, raw: bytes, mode: int = 0o444) -> None:
    if path.exists():
        path.chmod(0o644)
    path.write_bytes(raw)
    path.chmod(mode)


@contextmanager
def _fixture():
    with tempfile.TemporaryDirectory(dir=Path.home().resolve()) as temporary:
        base = Path(temporary).resolve()
        root = base / "protected"
        root.mkdir(mode=0o700)
        raw = b"# inert protected skill\n"
        transaction = _transaction(
            root,
            context_id=_digest("a"),
            context_digest=_digest("b"),
            manifest_digest=_digest("c"),
            skill_raw=raw,
        )
        version = _materialize(root, transaction, raw)
        _activate(root, transaction)
        _publish_record(root, transaction)
        external = base / "template-skill/SKILL.md"
        external.parent.mkdir(mode=0o755)
        _write(external, raw)
        external.parent.chmod(0o555)
        config = json.loads(_PROFILE.read_bytes())
        config["skills"]["activation"]["sources"][0].update(
            filePath=str(external), sha256=_sha(raw)[7:]
        )
        config["skills"]["load"]["extraDirs"] = [str(external.parent)]
        fixture = {
            "root": root,
            "version": version,
            "skill": version / "SKILL.md",
            "external": external,
            "transaction": transaction,
            "raw": raw,
            "config": config,
            "binding": RuntimeActionWorkerBinding(
                _digest("d"), _sha(raw), _digest("e"), 1
            ),
        }
        with (
            mock.patch.object(subject, "_PROTECTED_ROOT", root),
            mock.patch.object(subject, "_EXTERNAL_SOURCE", external),
            mock.patch.object(subject, "_EXPECTED_INSTALL_UID", os.geteuid()),
        ):
            yield fixture


def _verify(fixture):
    return subject._verify_runtime_skill_startup(fixture["binding"], fixture["config"])


def _publish(fixture, digest=None):
    fd = os.open(fixture["root"], os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return publish_quarantine_at(
            fd, digest or _sha(fixture["raw"]), _digest("f"), expected_uid=os.geteuid()
        )
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _require_unlocked(root):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


class RuntimeSkillStartupTests(unittest.TestCase):
    def test_installed_snapshot_preserves_caller_ex_and_owns_no_lock_or_cleanup(self):
        with _fixture() as fixture:
            # A response retry must still measure bytes that are already denied.
            _publish(fixture)
            _write(fixture["external"], b"different external bytes")
            root_fd = subject._open_protected_root(fixture["root"], os.geteuid())
            entries = []
            locked = False
            try:
                fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                entries.append(
                    subject._HeldEntry(
                        None, fixture["root"], root_fd, os.fstat(root_fd)
                    )
                )
                with (
                    mock.patch.object(
                        fcntl,
                        "flock",
                        side_effect=AssertionError("helper changed caller lock"),
                    ),
                    mock.patch.object(
                        subject,
                        "_release_lock_and_close",
                        side_effect=AssertionError("helper cleaned caller descriptors"),
                    ),
                ):
                    record, tree, skill, active = subject._installed_snapshot(
                        root_fd, entries
                    )
                self.assertEqual(record["transaction"], fixture["transaction"])
                self.assertEqual(tree, fixture["transaction"]["tree_digest"])
                self.assertEqual(skill, _sha(fixture["raw"]))
                self.assertEqual(
                    active.st_ino,
                    (
                        fixture["root"]
                        / fixture["transaction"]["destination"]["target_name"]
                    )
                    .lstat()
                    .st_ino,
                )
                self.assertGreater(len(entries), 1)
                subject._check_entries(entries)
                observer = os.open(fixture["root"], os.O_RDONLY | os.O_DIRECTORY)
                try:
                    # A second SH would succeed if the helper had downgraded EX.
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(observer, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(observer, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(observer)
            finally:
                self.assertIsNone(
                    subject._release_lock_and_close(
                        root_fd,
                        locked,
                        *(entry.fd for entry in entries if entry.fd != root_fd),
                    )
                )
            for entry in entries:
                with self.assertRaises(OSError):
                    os.fstat(entry.fd)
            _require_unlocked(fixture["root"])

    def test_installed_snapshot_failures_retain_caller_ex_and_all_open_descriptors(
        self,
    ):
        for mutation in ("record", "no-skill", "unbound-tree"):
            with self.subTest(mutation=mutation), _fixture() as fixture:
                if mutation == "record":
                    _write(fixture["root"] / ACTIVE_RUNTIME_RECORD, b"{")
                elif mutation == "no-skill":
                    fixture["version"].chmod(0o755)
                    fixture["skill"].rename(fixture["version"] / "NOT-SKILL.md")
                    fixture["version"].chmod(0o555)
                else:
                    _write(fixture["skill"], b"changed installed bytes")
                root_fd = subject._open_protected_root(fixture["root"], os.geteuid())
                entries = []
                locked = False
                try:
                    fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    entries.append(
                        subject._HeldEntry(
                            None, fixture["root"], root_fd, os.fstat(root_fd)
                        )
                    )
                    with self.assertRaises(
                        (subject.RuntimeSkillStartupError, RuntimeActionBrokerError)
                    ):
                        subject._installed_snapshot(root_fd, entries)
                    self.assertGreater(len(entries), 1)
                    for entry in entries:
                        os.fstat(entry.fd)
                    observer = os.open(fixture["root"], os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(observer, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    finally:
                        os.close(observer)
                finally:
                    self.assertIsNone(
                        subject._release_lock_and_close(
                            root_fd,
                            locked,
                            *(entry.fd for entry in entries if entry.fd != root_fd),
                        )
                    )
                for entry in entries:
                    with self.assertRaises(OSError):
                        os.fstat(entry.fd)
                _require_unlocked(fixture["root"])

    def test_installed_snapshot_requires_one_fixed_root_named_fd_baseline(self):
        with _fixture() as fixture:
            root_fd = subject._open_protected_root(fixture["root"], os.geteuid())
            try:
                fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                entry = subject._HeldEntry(
                    None, fixture["root"], root_fd, os.fstat(root_fd)
                )
                for entries in (
                    [],
                    [entry, entry],
                    [replace(entry, name=fixture["external"].parent)],
                    [replace(entry, parent_fd=root_fd)],
                ):
                    with (
                        self.subTest(entries=entries),
                        self.assertRaisesRegex(
                            subject.RuntimeSkillStartupError,
                            "root baseline is missing or unbound",
                        ),
                    ):
                        subject._installed_snapshot(root_fd, entries)
                for invalid_fd in (True, -1, str(root_fd)):
                    with (
                        self.subTest(root_fd=invalid_fd),
                        self.assertRaisesRegex(
                            subject.RuntimeSkillStartupError,
                            "root descriptor is invalid",
                        ),
                    ):
                        subject._installed_snapshot(invalid_fd, [entry])
                os.fstat(root_fd)
            finally:
                fcntl.flock(root_fd, fcntl.LOCK_UN)
                os.close(root_fd)
            _require_unlocked(fixture["root"])

    def test_fixed_parent_selection_and_byte_snapshot_have_no_process_authority(self):
        config = json.loads(_PROFILE.read_bytes())
        _, digest = subject._configuration(config)
        self.assertEqual(
            digest[7:], config["skills"]["activation"]["sources"][0]["sha256"]
        )
        evidence_path = _PROFILE.parents[3] / (
            "benchmark/evidence/runtime-action-worker-final-combined-v3-route-"
            "config-entry-activation-systemd-p3-final-2026-08-28.json"
        )
        retained = json.loads(evidence_path.read_bytes())
        external = retained["composition"]["action"]["artifacts"][
            "final_combined_v3_config_entry_activation"
        ]["skill"]
        self.assertEqual(
            external["parents"][-1],
            {
                "path": str(subject._EXTERNAL_SOURCE.parent),
                "mode": "0555",
                "uid": 0,
                "gid": 0,
            },
        )
        with _fixture() as fixture:
            result = _verify(fixture)
            self.assertEqual(result["schema"], subject._SCHEMA)
            self.assertEqual(result["authority"], subject._AUTHORITY)
            self.assertEqual(result["active_skill_digest"], _sha(fixture["raw"]))
            self.assertEqual(
                result["tree_digest"], fixture["transaction"]["tree_digest"]
            )
            self.assertEqual(
                result["gateway_config_digest"], canonical_digest(fixture["config"])
            )
            self.assertEqual(result["source_path"], str(fixture["external"]))
            self.assertEqual(
                set(result),
                {
                    "schema",
                    "authority",
                    "active_record_digest",
                    "tree_digest",
                    "active_skill_digest",
                    "source_name",
                    "source_path",
                    "gateway_config_digest",
                    "worker_binding_digest",
                },
            )
            self.assertNotIn("pid", result)
            self.assertIn(
                "NOT_STARTUP_ENFORCEMENT_OR_PROCESS_CONSUMPTION", result["authority"]
            )
            _require_unlocked(fixture["root"])

    def test_target_is_record_selected_byte_identity_not_target_grant_authority(self):
        with _fixture() as fixture:
            _verify(fixture)
            alternate = copy.deepcopy(fixture["transaction"])
            old_target = alternate["destination"]["target_name"]
            alternate["destination"]["target_name"] = "another-installed-target"
            alternate["version_path"] = alternate["version_path"].replace(
                "/" + old_target + "/", "/another-installed-target/"
            )
            _materialize(fixture["root"], alternate, fixture["raw"])
            _activate(fixture["root"], alternate)
            _publish_record(fixture["root"], alternate)
            result = _verify(fixture)
            self.assertEqual(result["active_skill_digest"], _sha(fixture["raw"]))
            self.assertNotIn("target_name", result)
            _publish(fixture)
            with self.assertRaisesRegex(
                subject.RuntimeSkillStartupError,
                "installed skill digest is quarantined",
            ):
                _verify(fixture)

    def test_valid_nested_tree_matches_existing_canonical_inventory(self):
        with _fixture() as fixture:
            version = fixture["version"]
            version.chmod(0o755)
            nested = version / "references"
            nested.mkdir(mode=0o755)
            _write(nested / "guide.md", b"inert companion\n")
            _write(version / "inert.txt", b"executable metadata fixture\n", 0o555)
            nested.chmod(0o555)
            version.chmod(0o555)
            fd = os.open(version, os.O_RDONLY | os.O_DIRECTORY)
            try:
                manifest, directories = inventory_open_directory(
                    fd,
                    max_depth=1,
                    max_files=64,
                    max_file_size=1024 * 1024,
                    max_total_bytes=1024 * 1024,
                )
            finally:
                os.close(fd)
            self.assertEqual(directories, ("references",))
            fixture["transaction"]["tree_digest"] = manifest["tree_digest"]
            _publish_record(fixture["root"], fixture["transaction"])
            self.assertEqual(_verify(fixture)["tree_digest"], manifest["tree_digest"])
            _write(nested / "guide.md", b"changed companion\n")
            with self.assertRaisesRegex(
                subject.RuntimeSkillStartupError, "tree is unbound"
            ):
                _verify(fixture)

    def test_all_four_skill_identities_must_agree(self):
        for mutation in (
            "binding-B",
            "external-B",
            "installed-B",
            "configured-B",
            "empty-external",
        ):
            with self.subTest(mutation=mutation), _fixture() as fixture:
                other = b"# different clean skill\n"
                if mutation == "binding-B":
                    fixture["binding"] = replace(
                        fixture["binding"], active_skill_digest=_sha(other)
                    )
                    _publish(
                        fixture
                    )  # A is actually installed; a clean B binding cannot evade it.
                elif mutation == "external-B":
                    _write(fixture["external"], other)
                elif mutation == "installed-B":
                    _write(fixture["skill"], other)
                    fixture["transaction"]["tree_digest"] = canonical_digest(
                        [
                            {
                                "path": "SKILL.md",
                                "size": len(other),
                                "digest": _sha(other),
                                "executable": False,
                            }
                        ]
                    )
                    _publish_record(fixture["root"], fixture["transaction"])
                    fixture["binding"] = replace(
                        fixture["binding"], active_skill_digest=_sha(other)
                    )
                    fixture["config"]["skills"]["activation"]["sources"][0][
                        "sha256"
                    ] = _sha(other)[7:]
                elif mutation == "configured-B":
                    fixture["config"]["skills"]["activation"]["sources"][0][
                        "sha256"
                    ] = _sha(other)[7:]
                else:
                    _write(fixture["external"], b"")
                with self.assertRaisesRegex(
                    subject.RuntimeSkillStartupError, "bytes disagree"
                ):
                    _verify(fixture)
                _require_unlocked(fixture["root"])

    def test_matching_denial_and_malformed_record_reject_but_other_digest_is_allowed(
        self,
    ):
        for malformed in (False, True):
            with self.subTest(malformed=malformed), _fixture() as fixture:
                _publish(fixture, _digest("0"))
                _verify(fixture)
                _publish(fixture)
                record = fixture["root"] / (
                    ".aragorn-quarantined-skill-" + _sha(fixture["raw"])[7:] + ".json"
                )
                if malformed:
                    _write(record, b"{")
                with self.assertRaisesRegex(
                    subject.RuntimeSkillStartupError,
                    "cannot verify skill denial"
                    if malformed
                    else "installed skill digest is quarantined",
                ):
                    _verify(fixture)
                _require_unlocked(fixture["root"])

    def test_exact_skill_and_agent_selection_rejects_alternate_or_extra_sources(self):
        mutations = {
            "path": lambda c: c["skills"]["activation"]["sources"][0].update(
                filePath="/tmp/SKILL.md"
            ),
            "name": lambda c: c["skills"]["activation"]["sources"][0].update(
                name="other"
            ),
            "extra-source": lambda c: c["skills"]["activation"]["sources"].append({}),
            "empty-source": lambda c: c["skills"]["activation"].update(sources=[]),
            "authority": lambda c: c["skills"]["activation"].update(authority="local"),
            "watch": lambda c: c["skills"]["load"].update(watch=True),
            "watch-int": lambda c: c["skills"]["load"].update(watch=0),
            "extra-dir": lambda c: c["skills"]["load"]["extraDirs"].append("/tmp"),
            "symlink-allow": lambda c: c["skills"]["load"][
                "allowSymlinkTargets"
            ].append("/tmp"),
            "extra-field": lambda c: c["skills"].update(entries={}),
            "bundled": lambda c: c["skills"]["allowBundled"].append("other"),
            "workshop": lambda c: c["skills"]["workshop"].update(
                restoreAuthority="local"
            ),
            "main-skills": lambda c: c["agents"]["list"][0].update(skills=["other"]),
            "default-skills": lambda c: c["agents"]["defaults"].update(
                skills=["other"]
            ),
            "runtime": lambda c: c["agents"]["list"][0].update(
                runtime={"type": "other"}
            ),
            "extra-agent": lambda c: c["agents"]["list"].append(
                copy.deepcopy(c["agents"]["list"][0])
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), _fixture() as fixture:
                mutate(fixture["config"])
                with self.assertRaises(subject.RuntimeSkillStartupError):
                    _verify(fixture)

    def test_digest_types_and_canonical_forms_are_strict(self):
        invalid = (
            None,
            True,
            1,
            "sha256:" + "A" * 64,
            "sha256:" + "+" + "1" * 63,
            "sha256:" + "1_" * 32,
            "sha256:" + " " + "1" * 63,
            _digest("a") + "\n",
        )
        for value in invalid:
            for field in ("runtime_digest", "active_skill_digest", "policy_digest"):
                with self.subTest(value=value, field=field), _fixture() as fixture:
                    fixture["binding"] = replace(fixture["binding"], **{field: value})
                    with self.assertRaises(subject.RuntimeSkillStartupError):
                        _verify(fixture)
            with self.subTest(value=value, field="config"), _fixture() as fixture:
                fixture["config"]["skills"]["activation"]["sources"][0]["sha256"] = (
                    value
                )
                with self.assertRaises(subject.RuntimeSkillStartupError):
                    _verify(fixture)
        for value in (True, 0, -1, 1.0, "1"):
            with self.subTest(policy_version=value), _fixture() as fixture:
                fixture["binding"] = replace(fixture["binding"], policy_version=value)
                with self.assertRaises(subject.RuntimeSkillStartupError):
                    _verify(fixture)

    def test_active_record_must_be_canonical_strict_and_bound_to_actual_root_version(
        self,
    ):
        for mutation in (
            "json",
            "duplicate",
            "root-inode",
            "root-device",
            "bool-inode",
            "context",
            "predecessor",
            "version",
            "tree",
        ):
            with self.subTest(mutation=mutation), _fixture() as fixture:
                transaction = fixture["transaction"]
                if mutation == "root-inode":
                    transaction["destination"]["root_inode"] += 1
                elif mutation == "root-device":
                    transaction["destination"]["root_device"] += 1
                elif mutation == "bool-inode":
                    transaction["destination"]["root_inode"] = True
                elif mutation == "context":
                    transaction["context_digest"] = "sha256:+" + "1" * 63
                elif mutation == "predecessor":
                    transaction.update(
                        operation="update",
                        expected_active={
                            "context_id": "sha256:+" + "1" * 63,
                            "manifest_digest": _digest("a"),
                        },
                    )
                elif mutation == "version":
                    transaction["version_path"] += "-different"
                elif mutation == "tree":
                    transaction["tree_digest"] = _digest("a")
                raw = _publish_record(fixture["root"], transaction)
                if mutation in {"json", "duplicate"}:
                    _write(
                        fixture["root"] / ACTIVE_RUNTIME_RECORD,
                        raw + b"\n"
                        if mutation == "json"
                        else b'{"schema":1,"schema":2}',
                    )
                with self.assertRaises(subject.RuntimeSkillStartupError):
                    _verify(fixture)
                _require_unlocked(fixture["root"])

    def test_immutable_files_and_external_custody_fail_closed(self):
        for which in ("skill", "external", "record"):
            for mutation in ("mode", "symlink", "hardlink", "fifo", "oversize"):
                with (
                    self.subTest(which=which, mutation=mutation),
                    _fixture() as fixture,
                ):
                    path = (
                        fixture[which]
                        if which != "record"
                        else fixture["root"] / ACTIVE_RUNTIME_RECORD
                    )
                    path.parent.chmod(0o755)
                    if mutation == "mode":
                        path.chmod(0o644)
                    elif mutation == "hardlink":
                        os.link(path, path.parent / "second-link")
                    elif mutation == "oversize":
                        _write(path, b"x" * (subject._MAX_SKILL_BYTES + 1))
                    else:
                        path.unlink()
                        if mutation == "symlink":
                            path.symlink_to(
                                fixture["external"]
                                if which != "external"
                                else fixture["skill"]
                            )
                        else:
                            os.mkfifo(path, 0o444)
                    if which != "record":
                        path.parent.chmod(0o555)
                    with self.assertRaises(subject.RuntimeSkillStartupError):
                        _verify(fixture)

    def test_unsafe_directory_layout_mode_owner_and_canonical_paths_reject(self):
        for mutation in (
            "empty-dir",
            "deep-dir",
            "two-dirs",
            "version-mode",
            "external-mode",
            "wrong-owner",
            "root-symlink",
            "external-parent-symlink",
        ):
            with self.subTest(mutation=mutation), _fixture() as fixture:
                version = fixture["version"]
                if mutation in {"empty-dir", "deep-dir", "two-dirs"}:
                    version.chmod(0o755)
                    nested = version / "references"
                    nested.mkdir(mode=0o755)
                    if mutation != "empty-dir":
                        _write(nested / "guide.md", b"guide")
                    if mutation == "deep-dir":
                        (nested / "deeper").mkdir(mode=0o555)
                    if mutation == "two-dirs":
                        other = version / "other"
                        other.mkdir(mode=0o755)
                        _write(other / "guide.md", b"guide")
                        other.chmod(0o555)
                    nested.chmod(0o555)
                    version.chmod(0o555)
                elif mutation == "version-mode":
                    version.chmod(0o755)
                elif mutation == "external-mode":
                    fixture["external"].parent.chmod(0o755)
                elif mutation == "wrong-owner":
                    subject._EXPECTED_INSTALL_UID = os.geteuid() + 1
                elif mutation == "root-symlink":
                    alias = fixture["root"].parent / "alias"
                    alias.symlink_to(fixture["root"])
                    subject._PROTECTED_ROOT = alias
                else:
                    parent = fixture["external"].parent
                    moved = parent.with_name("moved-external")
                    parent.rename(moved)
                    parent.symlink_to(moved)
                with self.assertRaises(subject.RuntimeSkillStartupError):
                    _verify(fixture)

    def test_shared_lock_covers_tree_external_denial_and_final_checks(self):
        with _fixture() as fixture:
            observations = []
            real_read = subject._read_file
            real_deny = subject.require_not_quarantined_at
            real_check = subject._check_entries

            def require_locked():
                fd = os.open(fixture["root"], os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(fd)

            def read(*args, **kwargs):
                require_locked()
                observations.append(args[1])
                return real_read(*args, **kwargs)

            def deny(*args, **kwargs):
                require_locked()
                observations.append("denial")
                return real_deny(*args, **kwargs)

            def check(entries):
                require_locked()
                return real_check(entries)

            with (
                mock.patch.object(subject, "_read_file", side_effect=read),
                mock.patch.object(
                    subject, "require_not_quarantined_at", side_effect=deny
                ),
                mock.patch.object(subject, "_check_entries", side_effect=check),
            ):
                _verify(fixture)
            self.assertEqual(
                observations, [ACTIVE_RUNTIME_RECORD, "SKILL.md", "SKILL.md", "denial"]
            )
            _require_unlocked(fixture["root"])
            fd = os.open(fixture["root"], os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(
                    subject.RuntimeSkillStartupError, "root is busy"
                ):
                    _verify(fixture)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            _require_unlocked(fixture["root"])

    def test_named_fd_and_input_changes_after_measurement_are_rejected(self):
        for mutation in (
            "root-rebind",
            "version-rebind",
            "external-parent-rebind",
            "active-link",
            "skill-write",
            "external-write",
            "record-write",
            "config",
            "binding",
        ):
            with self.subTest(mutation=mutation), _fixture() as fixture:
                real_deny = subject.require_not_quarantined_at

                def deny(*args, real_deny=real_deny, mutation=mutation, **kwargs):
                    real_deny(*args, **kwargs)
                    if mutation in {
                        "root-rebind",
                        "version-rebind",
                        "external-parent-rebind",
                    }:
                        path = {
                            "root-rebind": fixture["root"],
                            "version-rebind": fixture["version"],
                            "external-parent-rebind": fixture["external"].parent,
                        }[mutation]
                        mode = path.stat().st_mode & 0o777
                        path.rename(path.with_name(path.name + "-moved"))
                        path.mkdir(mode=mode)
                    elif mutation == "active-link":
                        _activate(fixture["root"], fixture["transaction"])
                    elif mutation in {"skill-write", "external-write"}:
                        _write(fixture[mutation.split("-")[0]], fixture["raw"])
                    elif mutation == "record-write":
                        _publish_record(fixture["root"], fixture["transaction"])
                    elif mutation == "config":
                        fixture["config"]["skills"]["load"]["watch"] = True
                    else:
                        object.__setattr__(
                            fixture["binding"], "active_skill_digest", _digest("0")
                        )

                with (
                    mock.patch.object(
                        subject, "require_not_quarantined_at", side_effect=deny
                    ),
                    self.assertRaises(subject.RuntimeSkillStartupError),
                ):
                    _verify(fixture)
                _require_unlocked(fixture["root"])

    def test_fifo_substitution_between_stat_and_open_is_nonblocking(self):
        for which in ("skill", "external", "record"):
            with self.subTest(which=which), _fixture() as fixture:
                path = (
                    fixture[which]
                    if which != "record"
                    else fixture["root"] / ACTIVE_RUNTIME_RECORD
                )
                parent_inode = path.parent.stat().st_ino
                real_open = os.open
                substituted = []

                def raced_open(
                    name,
                    flags,
                    *args,
                    path=path,
                    parent_inode=parent_inode,
                    real_open=real_open,
                    substituted=substituted,
                    **kwargs,
                ):
                    if (
                        name == path.name
                        and kwargs.get("dir_fd") is not None
                        and os.fstat(kwargs["dir_fd"]).st_ino == parent_inode
                    ):
                        self.assertTrue(flags & os.O_NONBLOCK)
                        path.parent.chmod(0o755)
                        path.unlink()
                        os.mkfifo(path, 0o444)
                        substituted.append(True)
                    return real_open(name, flags, *args, **kwargs)

                with (
                    mock.patch.object(subject.os, "open", side_effect=raced_open),
                    self.assertRaises(subject.RuntimeSkillStartupError),
                ):
                    _verify(fixture)
                self.assertEqual(substituted, [True])
                _require_unlocked(fixture["root"])

    def test_entry_byte_bounds_and_short_reads(self):
        with _fixture() as fixture:
            real_read = os.read
            with mock.patch.object(
                subject.os,
                "read",
                side_effect=lambda fd, size: real_read(fd, min(size, 3)),
            ):
                _verify(fixture)
        for bound, value in (
            ("_MAX_TREE_ENTRIES", 0),
            ("_MAX_SKILL_BYTES", 1),
            ("_MAX_CONFIG_BYTES", 1),
            ("_MAX_RECORD_BYTES", 1),
        ):
            with self.subTest(bound=bound), _fixture() as fixture:
                with (
                    mock.patch.object(subject, bound, value),
                    self.assertRaises(subject.RuntimeSkillStartupError),
                ):
                    _verify(fixture)
                _require_unlocked(fixture["root"])

    def test_all_open_descriptors_release_on_success_and_failure(self):
        for fail in (False, True):
            with self.subTest(fail=fail), _fixture() as fixture:
                real_open = os.open
                opened = []

                def track(*args, real_open=real_open, opened=opened, **kwargs):
                    fd = real_open(*args, **kwargs)
                    opened.append(fd)
                    return fd

                if fail:
                    _write(fixture["external"], b"other")
                with mock.patch.object(subject.os, "open", side_effect=track):
                    if fail:
                        with self.assertRaises(subject.RuntimeSkillStartupError):
                            _verify(fixture)
                    else:
                        _verify(fixture)
                for fd in opened:
                    with self.assertRaises(OSError):
                        os.fstat(fd)
                _require_unlocked(fixture["root"])
        with _fixture() as fixture:
            real_release = subject._release_lock_and_close

            def release(*args):
                self.assertIsNone(real_release(*args))
                return OSError("injected cleanup failure after close")

            with (
                mock.patch.object(
                    subject, "_release_lock_and_close", side_effect=release
                ),
                self.assertRaisesRegex(
                    subject.RuntimeSkillStartupError, "cleanup failed"
                ),
            ):
                _verify(fixture)
            _require_unlocked(fixture["root"])


if __name__ == "__main__":
    unittest.main()
