"""Fixed import shim for the isolated runtime observation service."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2] / "lib" / "aragorn"),
)

from aragorn.runtime_observation_service import main  # noqa: E402


raise SystemExit(main())
