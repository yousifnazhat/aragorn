#!/usr/bin/env python3
"""Verify local baseline image candidates against the checked-in lock."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aragorn.oci_runtime import (  # noqa: E402, F401
    VerificationError,
    _digest_reference,
    _load,
    _read_file_bounded,
    _verify_oci_graph,
    main,
)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.SubprocessError, VerificationError) as exc:
        print(f"baseline verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
