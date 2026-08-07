from __future__ import annotations

import fcntl
import hashlib
import os
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_action_observation_publisher import (
    RuntimeActionObservationPublisherError,
)
from aragorn.runtime_active_skill_lineage import (
    ACTIVE_RUNTIME_AUTHORITY,
    ACTIVE_RUNTIME_RECORD,
    ACTIVE_RUNTIME_SCHEMA,
    VERIFIED_LINEAGE_AUTHORITY,
    VERIFIED_LINEAGE_SCHEMA,
    hold_runtime_active_skill_lineage,
    parse_active_runtime_record,
    verify_runtime_active_skill_lineage,
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _tree_digest(raw: bytes) -> str:
    return canonical_digest(
        [
            {
                "path": "SKILL.md",
                "size": len(raw),
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                "executable": False,
            }
        ]
    )


def _transaction(
    root: Path,
    *,
    context_id: str,
    context_digest: str,
    manifest_digest: str,
    skill_raw: bytes,
) -> dict[str, object]:
    root_state = root.stat()
    target = "aragorn-admitted"
    return {
        "schema": "aragorn/protected-install-transaction/v1",
        "authority": "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
        "context_digest": context_digest,
        "context_id": context_id,
        "operation": "install",
        "expected_active": None,
        "manifest_digest": manifest_digest,
        "tree_digest": _tree_digest(skill_raw),
        "destination": {
            "root_device": root_state.st_dev,
            "root_inode": root_state.st_ino,
            "target_name": target,
        },
        "version_path": (
            f".aragorn-versions/{target}/{context_id[7:]}-{manifest_digest[7:]}"
        ),
    }


def _materialize(root: Path, transaction: dict[str, object], raw: bytes) -> Path:
    version = root / str(transaction["version_path"])
    version.mkdir(parents=True)
    (root / ".aragorn-versions").chmod(0o755)
    version.parent.chmod(0o755)
    skill = version / "SKILL.md"
    skill.write_bytes(raw)
    skill.chmod(0o444)
    version.chmod(0o555)
    return version


def _publish_record(root: Path, transaction: dict[str, object]) -> bytes:
    raw = canonical_json(
        {
            "schema": ACTIVE_RUNTIME_SCHEMA,
            "authority": ACTIVE_RUNTIME_AUTHORITY,
            "transaction": transaction,
        }
    )
    record = root / ACTIVE_RUNTIME_RECORD
    if record.exists():
        record.chmod(0o644)
    record.write_bytes(raw)
    record.chmod(0o444)
    return raw


def _activate(root: Path, transaction: dict[str, object]) -> None:
    target = str(transaction["destination"]["target_name"])  # type: ignore[index]
    active = root / target
    active.unlink(missing_ok=True)
    active.symlink_to(str(transaction["version_path"]))


@contextmanager
def _fixture() -> Iterator[dict[str, object]]:
    with tempfile.TemporaryDirectory(dir=Path.home().resolve()) as temporary:
        root = Path(temporary).resolve() / "protected"
        root.mkdir(mode=0o700)
        skill_raw = b"# protected skill\n"
        transaction = _transaction(
            root,
            context_id=_digest("a"),
            context_digest=_digest("b"),
            manifest_digest=_digest("c"),
            skill_raw=skill_raw,
        )
        version = _materialize(root, transaction, skill_raw)
        _activate(root, transaction)
        record_raw = _publish_record(root, transaction)
        skill_digest = "sha256:" + hashlib.sha256(skill_raw).hexdigest()
        yield {
            "root": root,
            "skill_raw": skill_raw,
            "skill": version / "SKILL.md",
            "transaction": transaction,
            "record_raw": record_raw,
            "attribution": {
                "pid": os.getpid(),
                "skill_path": str(version / "SKILL.md"),
                "active_skill_digest": skill_digest,
            },
            "grant": {
                "install_context_digest": transaction["context_digest"],
                "source_manifest_digest": transaction["manifest_digest"],
                "active_skill_digest": skill_digest,
            },
        }


def _verify(fixture: dict[str, object]) -> dict[str, object]:
    return verify_runtime_active_skill_lineage(
        os.getpid(),
        fixture["attribution"],  # type: ignore[arg-type]
        fixture["grant"],  # type: ignore[arg-type]
        protected_root=fixture["root"],  # type: ignore[arg-type]
        expected_install_uid=os.geteuid(),
    )


def _alternate(fixture: dict[str, object]) -> dict[str, object]:
    root = fixture["root"]
    skill_raw = fixture["skill_raw"]
    transaction = fixture["transaction"]
    assert isinstance(root, Path)
    assert isinstance(skill_raw, bytes)
    assert isinstance(transaction, dict)
    alternate = _transaction(
        root,
        context_id=_digest("d"),
        context_digest=str(transaction["context_digest"]),
        manifest_digest=str(transaction["manifest_digest"]),
        skill_raw=skill_raw,
    )
    _materialize(root, alternate, skill_raw)
    return alternate


class RuntimeActiveSkillLineageTests(unittest.TestCase):
    def test_live_record_active_link_and_immutable_skill_are_bound(self) -> None:
        with _fixture() as fixture:
            self.assertEqual(
                parse_active_runtime_record(fixture["record_raw"]),  # type: ignore[arg-type]
                {
                    "schema": ACTIVE_RUNTIME_SCHEMA,
                    "authority": ACTIVE_RUNTIME_AUTHORITY,
                    "transaction": fixture["transaction"],
                },
            )
            verified = _verify(fixture)

            self.assertEqual(verified["schema"], VERIFIED_LINEAGE_SCHEMA)
            self.assertEqual(verified["authority"], VERIFIED_LINEAGE_AUTHORITY)
            self.assertEqual(
                verified["active_record_digest"],
                canonical_digest(parse_active_runtime_record(fixture["record_raw"])),  # type: ignore[arg-type]
            )
            self.assertEqual(
                verified["context_digest"],
                fixture["grant"]["install_context_digest"],  # type: ignore[index]
            )
            self.assertEqual(
                verified["manifest_digest"],
                fixture["grant"]["source_manifest_digest"],  # type: ignore[index]
            )
            self.assertEqual(
                verified["active_skill_digest"],
                fixture["grant"]["active_skill_digest"],  # type: ignore[index]
            )

    def test_mutated_or_missing_live_state_is_rejected(self) -> None:
        def mutate_record(fixture: dict[str, object]) -> None:
            transaction = dict(fixture["transaction"])  # type: ignore[arg-type]
            transaction["context_digest"] = _digest("e")
            _publish_record(fixture["root"], transaction)  # type: ignore[arg-type]

        def mutate_skill(fixture: dict[str, object]) -> None:
            skill = fixture["skill"]
            assert isinstance(skill, Path)
            skill.chmod(0o644)
            skill.write_bytes(b"mutated\n")
            skill.chmod(0o444)

        def remove_record(fixture: dict[str, object]) -> None:
            root = fixture["root"]
            assert isinstance(root, Path)
            (root / ACTIVE_RUNTIME_RECORD).unlink()

        for label, mutate in {
            "record": mutate_record,
            "skill": mutate_skill,
            "missing record": remove_record,
        }.items():
            with self.subTest(label=label), _fixture() as fixture:
                mutate(fixture)
                with self.assertRaises(RuntimeActionObservationPublisherError):
                    _verify(fixture)

    def test_coherent_repin_is_visible_to_the_snapshot_gate(self) -> None:
        with _fixture() as fixture:
            original = _verify(fixture)
            alternate = _alternate(fixture)
            _activate(fixture["root"], alternate)  # type: ignore[arg-type]
            _publish_record(fixture["root"], alternate)  # type: ignore[arg-type]

            repinned = _verify(fixture)

        self.assertNotEqual(repinned, original)
        self.assertNotEqual(
            repinned["active_record_digest"], original["active_record_digest"]
        )
        self.assertNotEqual(repinned["version_inode"], original["version_inode"])

    def test_stale_record_or_active_link_is_rejected(self) -> None:
        for stale in ("record", "link"):
            with self.subTest(stale=stale), _fixture() as fixture:
                alternate = _alternate(fixture)
                if stale == "record":
                    _activate(fixture["root"], alternate)  # type: ignore[arg-type]
                else:
                    _publish_record(fixture["root"], alternate)  # type: ignore[arg-type]
                with self.assertRaises(RuntimeActionObservationPublisherError):
                    _verify(fixture)

    def test_shared_lineage_hold_excludes_an_installer_lock(self) -> None:
        with _fixture() as fixture:
            root = fixture["root"]
            assert isinstance(root, Path)
            with hold_runtime_active_skill_lineage(
                os.getpid(),
                fixture["attribution"],  # type: ignore[arg-type]
                fixture["grant"],  # type: ignore[arg-type]
                protected_root=root,
                expected_install_uid=os.geteuid(),
            ):
                installer_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(installer_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(installer_fd)

            installer_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(installer_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(installer_fd, fcntl.LOCK_UN)
            finally:
                os.close(installer_fd)


if __name__ == "__main__":
    unittest.main()
