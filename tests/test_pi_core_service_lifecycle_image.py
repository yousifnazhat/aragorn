"""Assemble only the changed service-image successor; never recapture v1."""

import unittest
from tests import test_pi_core_service_assemble as previous


class ServiceLifecycleImageTests(previous.PiCoreServiceAssemblyTests):
    input_record_name = "service-assembly-inputs-v2.json"


if __name__ == "__main__":
    unittest.main()
