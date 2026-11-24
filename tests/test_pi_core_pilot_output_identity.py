"""Only the changed directory/file inode comparison; no producer fixtures."""
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import verify_pi_core_pilot_output as verifier


class OutputIdentityTest(TestCase):
    def test_distinct_inode_required_before_reading_any_action_or_provider_original(self):
        root = Path(self.enterContext(TemporaryDirectory())) / "cas"
        writable = CAS(root)
        reader = CAS(root, read_only=True)
        path = dict(schema="aragorn/runtime-protected-path/v1", root_device=3, root_inode=17, target_name="result.json")
        output = dict(schema="aragorn/pi-core-pilot-output-observation/v1", path_descriptor=path,
                      activation_id="1" * 32, before="ABSENT", after="PRESENT", file_device=3,
                      payload_bytes=11, payload_hex=b'{"total":3}'.hex(), payload_digest=canonical_digest({"total": 3}))
        pin = canonical_digest(path)
        # Stop at the handover to existing action replay. Neither arm executes a producer.
        class ReachedReplay(Exception):
            pass
        with patch.object(verifier, "replay", side_effect=ReachedReplay) as downstream:
            for inode, expected in ((17, ValueError), (18, ReachedReplay)):
                raw = canonical_json(dict(output, file_inode=inode))
                output_pin = writable.put(BytesIO(raw), max_bytes=len(raw))
                with self.subTest(inode=inode), self.assertRaises(expected) as raised:
                    verifier.verify_pilot_output(reader, action_pin=pin, provider_archive=reader, provider_pin=pin,
                        deployment_pin=pin, output_archive=reader, output_pin=output_pin, expected_path_digest=pin)
                if inode == 17:
                    self.assertEqual(str(raised.exception), "PILOT_OUTPUT_DIRECTORY_IS_NOT_FILE")
                    downstream.assert_not_called()
            downstream.assert_called_once()
