"""Read back B109's offline delta: one payload, four signed sources, no duplicate staging."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from scripts import prepare_pi_core_b105_payload as b105
from scripts import prepare_pi_core_b109_payload as subject
from scripts.build_pi_core_linux import BuildError, canonical, sha256


# Independent SHA-256 readback of the four Git blobs at merge 9db4643.
MODULE_PINS = {
    "coordinator_entry": "49477dc3438c4537442acee85a8c2ac28cc10980a1b0de340876fa50af9b8d83",
    "managed_bootstrap": "7f94de4fa10104dd6eaa7877e4a8a6e244b84278549f76f6370009bac8e09d6b",
    "native_supervisor": "c95143585fae1cbaf534ba8cfeff7a1178c524ccf15473cfa46361496e1ed9d6",
    "pilot_output_observer": "932d2585f5757c4c2ead987c7d54f9f147efc048a71aead0b785384beb1d4dbd",
}
SOURCE = "/opt/aragorn/src/aragorn/pi_core_"
SERVICE_ROOT = "/var/lib/aragorn/pi-service-runtime/root"
HOST = "/etc/aragorn/coordinator-host.json"
MANIFEST = "/etc/aragorn/service-runtime-inputs/manifest.json"
BINDING = "/etc/aragorn/service-runtime-inputs/runtime-binding.json"
RECEIPT = "/var/lib/aragorn/pi-service-runtime/service-runtime-receipt.json"


class B109CommonRepinTests(TestCase):
    def test_only_the_four_bound_sources_and_their_dependents_change(self):
        payload, changes, outcome = subject.readback()
        old = json.loads(b105.image.read(b105.OUT / "payload.json", b105.PAYLOAD_PIN, 2 << 20))
        before, after = (b105.split._index(doc["entries"]) for doc in (old, payload))
        self.assertEqual({k: v for k, v in old.items() if k != "entries"},
                         {k: v for k, v in payload.items() if k != "entries"})
        modules = {SOURCE + name + ".py": digest for name, digest in MODULE_PINS.items()}
        wrappers = {SERVICE_ROOT + "/opt/aragorn/bin/" + role + ".py" for role in ("action", "sensor", "provider")}
        expected = set(modules) | {SERVICE_ROOT + p for p in modules} | wrappers | {HOST, MANIFEST, BINDING, RECEIPT}
        self.assertEqual(changes.keys(), expected)
        self.assertEqual({p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}, expected)
        reader = SOURCE + "pilot_output_observer.py"
        self.assertEqual(after.keys() - before.keys(), {reader, SERVICE_ROOT + reader})
        self.assertFalse(before.keys() - after.keys())
        for p, raw in changes.items():
            with self.subTest(path=p):
                row = after[p]
                self.assertEqual((row["type"], row["size"], row["sha256"]), ("file", len(raw), sha256(raw)))
                attrs = ("mode", "uid", "gid")
                self.assertEqual(tuple(row[k] for k in attrs),
                                 tuple(before[p][k] for k in attrs) if p in before else (0o444, 0, 0))
        host, service = ({r["path"]: r for r in json.loads(changes[p])["files"]} for p in (HOST, MANIFEST))
        binding = json.loads(changes[BINDING])["source_digests"]
        for p, digest in modules.items():
            with self.subTest(module=p):
                self.assertEqual(changes[p], changes[SERVICE_ROOT + p])
                self.assertEqual(sha256(changes[p]), digest)
                self.assertEqual((host[p]["digest"], service[p[1:]]["digest"], binding[p[1:]]),
                                 ("sha256:" + digest,) * 3)
                self.assertIs(service[p[1:]]["executable"], False)
        self.assertEqual(outcome["payload_sha256"], sha256(canonical(payload)))
        for flag in ("image_assembled", "installed_identity_verified", "activation_performed", "phase3_exit_eligible"):
            self.assertIs(outcome[flag], False)

    def test_substituted_predecessor_payload_is_refused(self):
        with TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            out = base / "successor"
            (base / "outcome.json").write_bytes(b105.image.read(b105.OUT / "outcome.json", b105.OUTCOME_PIN, 65536))
            (base / "payload.json").write_bytes(b'{"entries":[]}\n')
            with patch.object(subject, "BASE", base), patch.object(subject, "OUT", out), patch.object(
                    subject.sources, "prepare", side_effect=AssertionError("foreign payload reached source preparation")):
                with self.assertRaisesRegex(BuildError, "payload input digest differs"):
                    subject.prepare()
            self.assertFalse(out.exists())
            self.assertEqual({p.name for p in base.iterdir()}, {"payload.json", "outcome.json"})

    def test_altered_staged_bytes_refuse_readback_without_retry(self):
        with patch.object(b105.prior, "_retained", side_effect=lambda root, name, row: bytes(row["size"])) as retained:
            with self.assertRaisesRegex(BuildError, "staged successor bytes differ"):
                subject.readback()
        retained.assert_called_once()

    def test_existing_destination_is_refused_before_source_preparation(self):
        with TemporaryDirectory() as temp:
            path = Path(temp).resolve()
            marker = path / "retained"
            marker.write_bytes(b"do not replace")
            with patch.object(subject, "OUT", path), patch.object(subject.sources, "prepare", side_effect=AssertionError("retry")):
                with self.assertRaisesRegex(BuildError, "output already present"):
                    subject.prepare()
            self.assertEqual(list(path.iterdir()), [marker])
            self.assertEqual(marker.read_bytes(), b"do not replace")
