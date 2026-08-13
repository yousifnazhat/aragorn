"""Materialize frozen OpenClaw probes for the private fixed runtime."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "benchmark/admission/openclaw-v2026.7.1"

SOURCE_DIGESTS = {
    "adm03-probe.mjs": "1ac42c2baf9af313c99b5327b6c075fecd10a12e06f7dfb55d15f33b40ebb77e",
    "contained-probe.mjs": "da45089c199c5f749c94c88d19858fcb1b2c41236d965961782496b57fafe985",
    "model-activation-probe.mjs": "15b7eef1895e1f6ac85c9d944f17069cf680844122d355f1ca8828deaf9b2769",
    "probe.mjs": "e27481d19e8490d0bffe5dfe300431e2233ed16f52fc9c0c21cbf425e4e75fd9",
    "protected-archive-replacement-probe.mjs": "90bf211226365ede1cf781fa3faa45217b1ed72fd636cc48824c4b39e5ac7c22",
    "protected-config-activation-probe.mjs": "49c9c173cf6214a16e77e6cf5084c7cb91f8fd5c2e0b8555612d8c1174de2234",
    "protected-cron-rescan-probe.mjs": "db9c038d41735f9dfb16973e293a007abfadd35340b6425dbd7a95a6ea08c27c",
    "protected-observation-v1.mjs": "44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b",
    "protected-prompt-rebuild-probe.mjs": "f8fcfe8af1243c558ad071f7a001f84dca5cd219cdb069e64af6d48aac32d7eb",
    "protected-route-probe.mjs": "3d9615bbfae6c86b272c862de2faaf55f24cc7018a5e77f912f2b4f527162504",
    "restart-probe.mjs": "6a6b83079c391e7baf87092366a910a4786132e7a0446ef1ba28029859318d1f",
}

REPLACEMENTS = (
    (
        b"2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4",
        b"4b198dafbcca1788bfe22c0abb1f8bf16064be03",
    ),
    (b"OpenClaw 2026.7.1 (2d2ddc4)", b"OpenClaw 2026.7.1 (4b198da)"),
    (b"45_856", b"45_860"),
    (b"45856", b"45860"),
    (b"45_837", b"45_841"),
    (b"45837", b"45841"),
    (b"369_317_461", b"369_417_908"),
    (b"369317461", b"369417908"),
    (
        b"475772bbb9896a9be9b41a96f073b58eb39a4187305a83a46fad6517f86cdb2c",
        b"4e866a250429632f5796d977554acbaabe6f30dbf837457e32022eacdb9152c1",
    ),
)

EXPECTED_COUNTS = {
    "adm03-probe.mjs": (),
    "contained-probe.mjs": (0, 1, 0, 0, 0, 0, 0, 0, 0),
    "model-activation-probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0, 1),
    "probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0, 0),
    "protected-archive-replacement-probe.mjs": (1, 1, 0, 1, 0, 1, 0, 1, 1),
    "protected-config-activation-probe.mjs": (1, 1, 1, 0, 1, 0, 1, 0, 1),
    "protected-cron-rescan-probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0, 0),
    "protected-observation-v1.mjs": (0, 0, 1, 0, 1, 0, 1, 0, 1),
    "protected-prompt-rebuild-probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0, 0),
    "protected-route-probe.mjs": (1, 1, 0, 0, 0, 0, 0, 0, 0),
    "restart-probe.mjs": (),
}

CRON_REPLACEMENTS = (
    (
        b"15050c3de10192ae1190d0aa596d34c2163897948a360fe0494929e171a01967",
        b"df116fac9813317fd04eb9d3721c9be094563e3b1ac3af66720c15842d021385",
    ),
    (b"cron-snapshot.runtime-xn4WDHsg.js", b"cron-snapshot.runtime-DzbSus3I.js"),
    (
        b"fb9c29ca637b42389355d627c5e8a209a8d1ebb51b14432a462d9734f00e3665",
        b"b2803dc20246abadfe5284abbbda8ae69dee1684794746baa592cd3eacacbdb0",
    ),
    (b"isolated-agent-wBFsap3y.js", b"isolated-agent-DNWCmOH_.js"),
    (
        b"7330ff0387ffde3117c50752d5c656a522b2f32a5110cb494bdc1af2c106eb11",
        b"ef244fb7e2b31039e0d14035cba99650e2baf06eb6369bff3f66f42607a72b21",
    ),
    (b"3_163", b"3_661"),
    (b"session-snapshot-mFoFiIO4.js", b"session-snapshot-CMKRWMg1.js"),
    (
        b"0d93f74fca9a9f8a062d9e03953eda42419ceab49b296e194fd2ed510eb29eec",
        b"e9046199b43de587dbf1f184b2e4738b4b772491266baff8eeeab90f21a50d7c",
    ),
)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def transformed_probe(name: str) -> bytes:
    if name not in SOURCE_DIGESTS:
        raise ValueError(f"unsupported probe: {name}")
    raw = (SOURCE_ROOT / name).read_bytes()
    if _sha256(raw) != SOURCE_DIGESTS[name]:
        raise ValueError(f"frozen probe changed: {name}")
    expected = EXPECTED_COUNTS[name]
    counts = tuple(raw.count(old) for old, _new in REPLACEMENTS)
    if expected and counts != expected:
        raise ValueError(f"probe replacement shape changed: {name}")
    if not expected and any(counts):
        raise ValueError(f"unexpected runtime literal in {name}")
    for old, new in REPLACEMENTS:
        raw = raw.replace(old, new)
    if any(old in raw for old, _new in REPLACEMENTS):
        raise ValueError(f"stale runtime literal remains in {name}")
    if name == "protected-cron-rescan-probe.mjs":
        if any(raw.count(old) != 1 for old, _new in CRON_REPLACEMENTS):
            raise ValueError("fixed cron replay closure shape changed")
        for old, new in CRON_REPLACEMENTS:
            raw = raw.replace(old, new)
    return raw


def materialize(output: Path, names: list[str]) -> None:
    output.mkdir(mode=0o755, parents=True, exist_ok=False)
    for name in names:
        path = output / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        try:
            raw = transformed_probe(name)
            written = 0
            while written < len(raw):
                written += os.write(fd, raw[written:])
            os.fsync(fd)
        finally:
            os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("names", nargs="+", choices=sorted(SOURCE_DIGESTS))
    args = parser.parse_args()
    materialize(args.output, args.names)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
