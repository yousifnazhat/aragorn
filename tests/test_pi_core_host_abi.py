"""Only the new per-provider ELF symbol comparison; no target code executes."""
import unittest

from scripts import check_pi_core_host_abi as abi


REQUEST = """ 0x1 (NEEDED)  Shared library: [liba.so.1]
 0x1 (NEEDED)  Shared library: [libb.so.1]
Symbol table for image contains 3 entries:
  0: 0000 0 NOTYPE LOCAL DEFAULT UND
  1: 0000 0 FUNC GLOBAL DEFAULT UND convert@SHARED_1 (2)
  2: 0000 0 FUNC GLOBAL DEFAULT UND foreign@SHARED_1 (3)

Version symbols section '.gnu.version' contains 3 entries:
 000: 0 (*local*)  2 (SHARED_1)  3 (SHARED_1)

Version needs section '.gnu.version_r' contains 2 entries:
 000000: Version: 1  File: liba.so.1  Cnt: 1
 0x10: Name: SHARED_1  Flags: none  Version: 2
 0x20: Version: 1  File: libb.so.1  Cnt: 1
 0x30: Name: SHARED_1  Flags: none  Version: 3
"""

PROVIDER = """ 0xe (SONAME)  Library soname: [liba.so.1]
Symbol table for image contains 2 entries:
  0: 0000 0 NOTYPE LOCAL DEFAULT UND
  1: 0123 4 IFUNC GLOBAL DEFAULT 10 convert@@SHARED_1

Version symbols section '.gnu.version' contains 2 entries:
 000: 0 (*local*)  2 (SHARED_1)

Version definition section '.gnu.version_d' contains 2 entries:
 000000: Rev: 1  Flags: BASE  Index: 1  Cnt: 1  Name: liba.so.1
 0x10: Rev: 1  Flags: none  Index: 2  Cnt: 1  Name: SHARED_1
"""


class PiHostVersionedABI(unittest.TestCase):
    def test_only_selected_provider_receives_its_attributed_requirements(self):
        result = abi._edge(REQUEST, PROVIDER, "liba.so.1")
        self.assertEqual(result["versioned_symbol_count"], 1)
        self.assertEqual(result["required_versions"], ["SHARED_1"])
        self.assertFalse(result["runtime_verified"])
        self.assertFalse(result["phase3_exit_eligible"])

    def test_version_label_or_wrong_symbol_is_not_a_matching_export(self):
        for wrong in ("other@@SHARED_1", "SHARED_1"):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                abi._edge(REQUEST, PROVIDER.replace("convert@@SHARED_1", wrong), "liba.so.1")

    def test_wrong_soname_type_or_nonexported_definition_refused(self):
        for old, new in (("liba.so.1", "libb.so.1"), ("IFUNC", "OBJECT"),
                         ("GLOBAL DEFAULT 10", "GLOBAL HIDDEN 10")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                abi._edge(REQUEST, PROVIDER.replace(old, new), "liba.so.1")

    def test_mismatched_indexes_and_incomplete_tables_refused(self):
        for old, new in (("(2)", "(3)"), ("Version: 3", "Version: 2"),
                         ("3 (SHARED_1)", "1 (*global*)"), ("Cnt: 1", "Cnt: 2"),
                         ("Symbol table for image contains 3", "Symbol table for image contains 4")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                abi._edge(REQUEST.replace(old, new), PROVIDER, "liba.so.1")

    def test_invalid_target_input_refused_before_any_tool_executes(self):
        with self.assertRaisesRegex(ValueError, "arm64 ELF"):
            abi._readelf(b"not an ELF")
