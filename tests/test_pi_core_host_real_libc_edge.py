"""Check selected real libc edges only. This is not a boot or ABI qualification."""
import json
from pathlib import Path
import unittest

from scripts import check_pi_core_host_abi as abi
from scripts.build_pi_core_linux import regular_bytes, sha256


ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".aragorn"


def pinned(path, expected):
    if path.resolve(strict=True) != path:
        raise ValueError("linked input")
    raw = regular_bytes(path, 16 << 20)
    if sha256(raw) != expected:
        raise ValueError("unapproved ELF input: " + path.name)
    return raw


class RealHostLibcEdge(unittest.TestCase):
    def test_vendor_client_and_retained_host_python_libc_edges(self):
        preflight = STATE / "host-preflight"
        # Ubuntu payloads were independently extracted from release-index-authenticated
        # systemd and libc6 packages. The systemctl bytes also match the signed ISO.
        client = pinned(preflight / "ubuntu-26.04-arm64-CgB4PZMa/systemctl.elf",
                        "d31bba3ea090b5d0b1a6c6b4f88ef0a2113bf43ea2ca23c522fb71f07b692470")
        ubuntu = pinned(preflight / "build-b38/ubuntu-libc.elf",
                        "4306bea54c5862911d6ed2ee19adc0cdcb092cd1948ceb14a9c1e3592e8487d7")
        old = pinned(STATE / "pi-core-os-inputs/assembled-10294d3f619e45508051f04f5fd58d52/root/lib/aarch64-linux-gnu/libc.so.6",
                     "e4ac8ae1d81e4865e3aadedb962879cf9415903b3f2ba81ec75e9962b86ab8b0")
        python = pinned(STATE / "pi-core-build/host-python-c03a2cacf42161b94c730948e4d1c1dcfd58aede8d003a16312fef0663f3a46e"
                        / "root/opt/aragorn-cpython/bin/python3.12",
                        "7863a4d5e03fde7791c7f8c2c304cf3522f435e19745364ad18a6b7a0458af57")
        with self.assertRaisesRegex(ValueError, r"__isoc23_strtol@GLIBC_2\.38"):
            abi.check_versioned_provider(client, old, "libc.so.6")
        results = {}
        for name, requester in (("stock-systemctl", client), ("retained-python", python)):
            results[name] = abi.check_versioned_provider(requester, ubuntu, "libc.so.6")
            self.assertGreater(results[name]["versioned_symbol_count"], 0)
            self.assertFalse(results[name]["runtime_verified"])
        self.assertIn("GLIBC_2.38", results["stock-systemctl"]["required_versions"])
        print(json.dumps(results, sort_keys=True), flush=True)
