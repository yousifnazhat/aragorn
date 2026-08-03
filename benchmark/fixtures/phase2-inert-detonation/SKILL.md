# Phase 2 inert detonation fixture

This fixture exercises digest-bound, network-disabled gVisor artifact paths.
Each profile pins either `run.sh` or `scripts/check.sh` before mounting only the
selected script as read-only bytes.
