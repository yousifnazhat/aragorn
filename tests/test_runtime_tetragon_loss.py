"""New offline parser cases; synthetic windows are not live coverage evidence."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_tetragon_loss as subject
from aragorn import runtime_tetragon_process as process

_ROOT = Path(__file__).resolve().parents[1]
_BPF = process.LOSS_METRICS[0]


def _synthetic(*, value="0", labels="", missing=False):
    return "".join(
        f"# HELP {name} Synthetic unit fixture\n# TYPE {name} counter\n"
        f"{name}{labels if name == _BPF else ''} {value if name == _BPF else '0'}\n"
        for name in process.LOSS_METRICS
        if not (missing and name == _BPF)
    ).encode()


class TetragonLossTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock = (
            _ROOT / "benchmark/tetragon-candidate-source-v1.lock.json"
        ).read_bytes()

    def analyze(self, before, after=None):
        return subject.analyze_tetragon_loss_window(
            before, before if after is None else after, source_lock=self.lock
        )

    def test_new_supplemental_source_slice_custody(self):
        manifest_path = _ROOT / "benchmark/tetragon-loss-source-v1.lock.json"
        with manifest_path.open("rb") as stream:
            raw = stream.read(65537)
        self.assertLessEqual(len(raw), 65536)
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "6a25d7073f597e4aa9c6c654057cee3f8e03d44a198893f90dcfbc89e5bd91e7",
        )
        manifest = json.loads(raw)
        self.assertEqual(manifest["schema"], "aragorn/tetragon-loss-source-slice/v1")
        self.assertEqual(manifest["commit"], process.SOURCE_COMMIT)
        self.assertEqual(
            manifest["parent_source_lock_digest"], process.SOURCE_LOCK_DIGEST
        )
        self.assertEqual(len(manifest["files"]), 6)
        self.assertEqual(len({row["local_path"] for row in manifest["files"]}), 6)
        for row in manifest["files"]:
            with self.subTest(source=row["path"]):
                self.assertEqual(
                    row["local_path"],
                    "benchmark/tetragon-loss-source-v1/" + row["path"],
                )
                path = _ROOT / row["local_path"]
                self.assertEqual(path.resolve(strict=True), path)
                with path.open("rb") as stream:
                    content = stream.read(row["bytes"] + 1)
                self.assertEqual(len(content), row["bytes"])
                self.assertEqual(
                    "sha256:" + hashlib.sha256(content).hexdigest(), row["digest"]
                )
                self.assertEqual(
                    hashlib.sha1(
                        b"blob " + str(len(content)).encode() + b"\0" + content
                    ).hexdigest(),
                    row["git_blob"],
                )

    def test_retained_smoke_missing_family_is_unknown_without_substitution(self):
        raw = (
            _ROOT
            / "benchmark/evidence/tetragon-isolated-exec-exit-smoke-v1-2026-09-13.json"
        ).read_bytes()
        self.assertEqual(len(raw), 189925)
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "3f64362ab12391e5d44c7ce781e4963c8b37262707ec89095d83e719d1bf17de",
        )
        retained = json.loads(raw)
        before = retained["before"]["metrics"]["stdout"].encode()
        after = retained["final"]["metrics"]["stdout"].encode()
        result = self.analyze(before, after)
        self.assertEqual(result["profile"], subject.PROFILE)
        self.assertEqual(result["candidate_process_profile"], process.PROFILE)
        self.assertEqual(result["source_lock_digest"], process.SOURCE_LOCK_DIGEST)
        self.assertIn(
            "SPARSE_BPF_COUNTER_ABSENCE_DOES_NOT_PROVE_ZERO", result["limitations"]
        )
        self.assertEqual(result["status"], "UNRESOLVED")
        self.assertEqual(result["missing_metrics"], [_BPF])
        self.assertIsNone(result["families"][_BPF]["delta"])
        self.assertIsNone(result["before"]["families"][_BPF]["series"])
        self.assertEqual(
            sum(len(v["series"] or []) for v in result["before"]["families"].values()),
            32,
        )
        self.assertIn(b"tetragon_missed_link_probes_total", before)
        self.assertIn(b"tetragon_missed_prog_probes_total", before)
        for side, original in (("before", before), ("after", after)):
            self.assertEqual(result[side]["raw_bytes"], len(original))
            self.assertEqual(
                result[side]["raw_digest"],
                "sha256:" + hashlib.sha256(original).hexdigest(),
            )
        for name in subject._FALSE:
            self.assertIs(result[name], False)

    def test_exact_integer_deltas_labels_and_nonzero_baseline(self):
        labels = '{z="comma,brace}quote\\"slash\\\\line\\n",a="one"}'
        before = _synthetic(value="1e1", labels=labels)
        after = _synthetic(value="13.0", labels=labels)
        result = self.analyze(before, after)
        self.assertEqual(result["status"], "LOSS_OBSERVED")
        row = result["families"][_BPF]["series"][0]
        self.assertEqual((row["before"], row["after"], row["delta"]), (10, 13, 3))
        self.assertEqual(
            row["labels"], {"a": "one", "z": 'comma,brace}quote"slash\\line\n'}
        )
        stable = self.analyze(before)
        self.assertEqual(stable["status"], "NO_SELECTED_COUNTER_INCREASE_REPORTED")
        self.assertEqual(stable["before"]["families"][_BPF]["total"], 10)
        self.assertFalse(stable["sensor_health_verified"])
        reordered = before.replace(b'a="one"}', b"}").replace(b"{z=", b'{a="one",z=')
        # A trailing comma is intentionally outside this restricted profile.
        reordered = reordered.replace(b",}", b"}")
        self.assertEqual(self.analyze(before, reordered)["families"][_BPF]["delta"], 0)

    def test_missing_metadata_only_is_not_zero_and_known_increase_stays_visible(self):
        before = (
            _synthetic(missing=True)
            + f"# HELP {_BPF} Not exposed\n# TYPE {_BPF} counter\n".encode()
        )
        after = before.replace(
            (process.LOSS_METRICS[1] + " 0\n").encode(),
            (process.LOSS_METRICS[1] + " 2\n").encode(),
        )
        result = self.analyze(before, after)
        self.assertEqual(result["status"], "UNRESOLVED")
        self.assertTrue(result["selected_counter_increase_observed"])
        self.assertIsNone(result["before"]["families"][_BPF]["total"])

    def test_duplicate_malformed_and_unbounded_inputs_refuse(self):
        good = _synthetic()
        invalid = [
            None,
            bytearray(good),
            b"",
            good[:-1],
            good + b"\xff\n",
            good + b"\0\n",
            good.replace(b"\n", b"\r\n"),
            b"x" * (subject.MAX_SCRAPE_BYTES + 1),
            good + f"{_BPF} 0\n".encode(),
            good + f"# TYPE {_BPF} counter\n".encode(),
            good.replace(f"# TYPE {_BPF} counter\n".encode(), b""),
            good.replace(
                f"# TYPE {_BPF} counter".encode(), f"# TYPE {_BPF} gauge".encode()
            ),
            *[
                _synthetic(value=v)
                for v in (
                    "-1",
                    "NaN",
                    "+Inf",
                    "0.5",
                    str(1 << 64),
                    "1e9999999",
                    "0 12",
                    "0 extra",
                )
            ],
            *[
                _synthetic(labels=v)
                for v in (
                    '{a="1",a="2"}',
                    '{a="bad\\t"}',
                    '{a="noend}',
                    '{a="1",}',
                    '{a="1"',
                )
            ],
            good + ("# " + "x" * subject.MAX_LINE_BYTES + "\n").encode(),
        ]
        for raw in invalid:
            with (
                self.subTest(raw=repr(raw)[:100]),
                self.assertRaises(subject.TetragonLossError),
            ):
                self.analyze(raw)
        duplicate = (
            _synthetic(labels='{a="one",b="two"}')
            + f'{_BPF}{{b="two",a="one"}} 0\n'.encode()
        )
        with self.assertRaisesRegex(subject.TetragonLossError, "duplicate"):
            self.analyze(duplicate)

    def test_series_family_metadata_changes_and_hidden_reset_refuse(self):
        before = (
            _synthetic(value="10", labels='{slot="a"}')
            + f'{_BPF}{{slot="b"}} 0\n'.encode()
        )
        after = (
            _synthetic(value="9", labels='{slot="a"}')
            + f'{_BPF}{{slot="b"}} 2\n'.encode()
        )
        with self.assertRaisesRegex(subject.TetragonLossError, "reset"):
            self.analyze(before, after)
        cases = (
            (_synthetic(), _synthetic(missing=True)),
            (_synthetic(missing=True), _synthetic()),
            (_synthetic(), _synthetic(labels='{new="label"}')),
            (before, _synthetic(value="10", labels='{slot="a"}')),
            (
                _synthetic(),
                _synthetic().replace(b"Synthetic unit fixture", b"Changed metadata"),
            ),
        )
        for first, last in cases:
            with (
                self.subTest(first=first[:40], last=last[:40]),
                self.assertRaises(subject.TetragonLossError),
            ):
                self.analyze(first, last)

    def test_source_lock_refusal_precedes_scrape_parsing(self):
        with patch.object(
            subject, "_parse", side_effect=AssertionError("parsed")
        ) as parsed:
            with self.assertRaisesRegex(subject.TetragonLossError, "source lock"):
                subject.analyze_tetragon_loss_window(
                    _synthetic(), _synthetic(), source_lock=self.lock + b" "
                )
            parsed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
