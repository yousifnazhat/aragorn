"""Verify only the signed B94 inventory delta and inert staging; do not run target code."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from scripts import prepare_pi_core_b104_sources as subject
from scripts.build_pi_core_linux import BuildError


PREFIX = "opt/aragorn/src/aragorn/pi_core_"
SHARED = {PREFIX + name + ".py" for name in (
    "bundle_launch", "request_recovery", "service_lifecycle", "state_admission", "state_exposure",
)}
HOST_ONLY = PREFIX + "bundle_install_entry.py"


def changed_files(old_raw, new_raw):
    before, after = ({row["path"]: row for row in json.loads(raw)["files"]} for raw in (old_raw, new_raw))
    if before.keys() != after.keys():
        raise AssertionError("source delta adds or removes an inventory member")
    return {name for name in before if before[name] != after[name]}


class B104SignedSources(TestCase):
    def test_retain_only_reviewed_changes_and_refuse_to_replace_existing_output(self):
        host, manifest, binding = subject.original_inventories()
        with TemporaryDirectory(dir=Path.home().resolve()) as root, patch.object(subject, "OUT", Path(root) / "pins"):
            self.assertEqual(subject.retain(), subject.PINS)
            self.assertEqual({p.name for p in subject.OUT.iterdir()}, set(subject.PINS))
            docs = {n: subject.managed.image.read(subject.OUT / n, h, 2 << 20) for n, h in subject.PINS.items()}
            self.assertEqual(changed_files(host, docs["coordinator-host.json"]), {"/" + p for p in SHARED | {HOST_ONLY}})
            self.assertEqual(changed_files(manifest, docs["manifest.json"]), SHARED | {
                "opt/aragorn/bin/" + name + ".py" for name in ("action", "provider", "sensor")
            })
            old, new = (json.loads(raw)["source_digests"] for raw in (binding, docs["runtime-binding.json"]))
            self.assertEqual(old.keys(), new.keys())
            self.assertEqual({p for p in old if old[p] != new[p]}, SHARED)
            for field in ("activation_performed", "loaded_code_attested", "service_ready", "phase3_exit_eligible"):
                self.assertIs(json.loads(docs["service-runtime-receipt.json"])[field], False)
            with patch.object(subject, "prepare", side_effect=AssertionError("existing outputs are not retried")):
                with self.assertRaisesRegex(BuildError, "output already present"):
                    subject.retain()
            self.assertEqual({n: (subject.OUT / n).read_bytes() for n in docs}, docs)

    def test_foreign_predecessor_fails_before_reading_git_objects(self):
        host, manifest, binding = subject.original_inventories()
        with patch.object(subject.sources, "_git", side_effect=AssertionError("wrong predecessor reached Git")):
            with self.assertRaisesRegex(ValueError, "foreign predecessor document"):
                subject.prepare(host, manifest, binding + b"\n")
