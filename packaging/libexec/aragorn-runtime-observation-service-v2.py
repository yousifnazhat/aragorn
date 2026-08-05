#!/usr/bin/python3.12
"""Isolated launcher for the Aragorn profile-attributing sensor."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lib" / "aragorn"))

from aragorn.runtime_observation_service_v2 import main


if __name__ == "__main__":
    raise SystemExit(main())
