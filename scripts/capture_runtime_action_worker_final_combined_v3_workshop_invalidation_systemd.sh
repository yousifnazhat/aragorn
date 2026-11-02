#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_recipe=$root/scripts/capture_runtime_action_worker_final_combined_v3_workshop_proposal_apply_systemd.sh
temporary=

cleanup()
{
    status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$temporary" ] && { [ -e "$temporary" ] || [ -L "$temporary" ]; }; then
        rm -f -- "$temporary" || status=74
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if [ ! -f "$source_recipe" ] \
    || [ "$(wc -c <"$source_recipe" | tr -d ' ')" != 26603 ] \
    || [ "$(shasum -a 256 "$source_recipe" | awk '{print $1}')" \
        != a4f03cf2788f097d556be2b6ef93d758d6b12622a292a530784599d20b00ae96 ]
then
    echo "pinned V3 workshop-proposal capture recipe changed" >&2
    exit 66
fi

temporary=$(mktemp "${TMPDIR:-/tmp}/aragorn-v3-workshop-invalidation-capture.XXXXXX")
python3.12 - "$source_recipe" "$temporary" <<'PY'
import os
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_bytes()
destination = Path(sys.argv[2])
replacements = (
    (
        b'root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)',
        b'root=${ARAGORN_CAPTURE_ROOT:?missing capture root}',
        1,
    ),
    (
        b"    scripts/materialize_fixed_admission_probes.py \\\n",
        b"    scripts/materialize_fixed_admission_probes.py \\\n"
        b"    scripts/materialize_openclaw_final_v3_workshop_invalidation_probe.py \\\n",
        1,
    ),
    (b"workshop-proposal-apply", b"workshop-invalidation", 42),
    (b"workshop_proposal_apply", b"workshop_invalidation", 4),
    (b"WORKSHOP_PROPOSAL_APPLY", b"WORKSHOP_INVALIDATION", 3),
    (
        b"ADM-02/update/workshop-invalidation",
        b"ADM-02/reload/workshop-invalidation",
        1,
    ),
    (
        b"NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY",
        b"NOT_PASS_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
        1,
    ),
)
for old, new, count in replacements:
    if source.count(old) != count:
        raise SystemExit("pinned workshop-invalidation capture transform changed")
    source = source.replace(old, new)
if any(
    stale in source
    for stale in (
        b"workshop-proposal-apply",
        b"workshop_proposal_apply",
        b"WORKSHOP_PROPOSAL_APPLY",
    )
):
    raise SystemExit("stale proposal capture identity remains")
descriptor = os.open(destination, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    os.ftruncate(descriptor, 0)
    written = 0
    while written < len(source):
        count = os.write(descriptor, source[written:])
        if count <= 0:
            raise SystemExit("capture recipe write made no progress")
        written += count
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
chmod 0700 "$temporary"
ARAGORN_CAPTURE_ROOT=$root "$temporary" "$@"
