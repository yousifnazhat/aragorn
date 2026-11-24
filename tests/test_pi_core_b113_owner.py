"""New B113 artifact/assembly only. Never invoke the signed executable, start a watchdog or open a VM."""
import json
from unittest import TestCase, mock

from scripts import prepare_pi_core_b113_owner as owner
from scripts.build_pi_core_linux import BuildError, canonical


class TestB113Owner(TestCase):
    def test_published_held_code_matches_native_signature_and_compiled_bindings(self):
        pin = json.loads(owner.host.source_bytes(owner.PIN), object_pairs_hook=owner.unique)
        path = owner.verified_binary(pin)
        self.assertEqual(path.name, "vm-owner")
        self.assertIs(pin["boot_authorized"], False)
        self.assertIsNone(pin["approval_commit"])

    def test_schema_substitution_and_singleton_grant_are_not_buildable(self):
        for src in ({"schema":"aragorn/b50-single-use-release/v1","approved_attempts":[]},
                    {"schema":owner.HELD["schema"],"approved_attempts":[{"attempt_uuid":"unused"}]},
                    dict(owner.HELD, boot_authorized=True)):
            with self.subTest(src=src), self.assertRaisesRegex(BuildError, "B113 is held"):
                owner.held(canonical(src) + b"\n")

    def test_generated_native_path_binds_disk_firmware_same_pipe_and_refuses_before_resources(self):
        files, inputs = owner.snapshots()
        media, src = inputs["media"], files["owner-runner.m"]
        self.assertEqual(files["serial-recorder.m"], owner.host.source_bytes(owner.host.PACK/"serial-recorder.m"))
        refusal = src.index(b"B113 held: no approved boot attempt")
        self.assertLess(src.index(b"bound=B50Select("), refusal)
        for op in (b"observedHost=hostDigest()", b"B50Consume(r,session)", b"Held d=hold(dp,B113_DISK_BYTES",
                   b"initWithURL:url", b"B47OwnMachine(cfg,serial,a,session,stop,arm,began)"):
            self.assertLess(refusal, src.index(op))
        self.assertIn(b'@"aragorn/b113-owner-terminal/v1",@"media":media',src)
        self.assertIn(media["authenticode_sha256"].encode(), files["b45-binding.inc"])
        self.assertNotIn(b".aragorn/host-preflight/build-b44", files["b45-binding.inc"])
        self.assertIn(b"fileHandleForWriting:pipe.fileHandleForWriting", files["b45-binding.inc"])
        supervised = files["supervised-owner.m"]
        sites = [supervised.index(op) for op in (
            b"B45RecordSerialArmed(serial.fileHandleForReading.fileDescriptor", b'@"recorder-armed"',
            b"grant(arm,ctl,uid,startupCutoff,readerAlive)", b"!machine.canStart || !B50PreStart()",
            b"[machine startWithCompletionHandler:")]
        self.assertEqual(sites, sorted(sites))
        self.assertEqual(supervised.count(b"[machine startWithCompletionHandler:"), 1)

    def test_wrong_build_authority_rejected_before_private_artifact_lookup(self):
        pin = json.loads(owner.host.source_bytes(owner.PIN))
        with mock.patch.object(owner, "identity", side_effect=AssertionError("private read before pin check")):
            for wrong in (dict(pin, boot_authorized=True), dict(pin, directory="../old"),
                          dict(pin, inputs_sha256="1"*64), dict(pin, schema="aragorn/b50-single-use-owner/v1")):
                with self.subTest(pin=wrong), self.assertRaisesRegex(BuildError,"foreign or authorized"):
                    owner.verified_binary(wrong)
