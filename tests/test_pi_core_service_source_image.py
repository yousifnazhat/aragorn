"""Only the source-loading image successor; no target execution or activation."""

import unittest
from tests import test_pi_core_service_assemble as previous


class ServiceSourceImageTests(previous.PiCoreServiceAssemblyTests):
    input_record_name = "service-assembly-inputs-v3.json"
    wrapper_root_name = "packaging/pi-core/services-v2"


if __name__ == "__main__":
    unittest.main()
