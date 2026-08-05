"""Fixed import shim for the profile-attributing runtime action service."""

from __future__ import annotations

import sys
from importlib import import_module
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2] / "lib" / "aragorn"),
)

raise SystemExit(import_module("aragorn.runtime_action_service_v2").main())
