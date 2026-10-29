#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_recipe=$root/scripts/capture_runtime_action_worker_final_combined_v3_workshop_proposal_apply_systemd.sh
docker_context=colima-aragorn-bakeoff
git_source=sha256:8530f76a96d88820d288761f022e318970dda93d01536919fbc16076b7983e63
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
if [ "$#" -eq 1 ] \
    && [ "$(docker --context "$docker_context" image inspect --format '{{.Id}}' \
        "$git_source" 2>/dev/null || :)" != "$git_source" ]
then
    echo "missing exact local Git source image" >&2
    exit 66
fi

temporary=$(mktemp "${TMPDIR:-/tmp}/aragorn-v3-core-updater-capture.XXXXXX")
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
        b'    if [ -n "$removal_id" ]; then\n',
        b'    if [ -z "$removal_id" ]; then\n'
        b'        removal_id=$(docker container inspect --format \'{{.Id}}\' "$container" 2>/dev/null || :)\n'
        b'        container_id=$removal_id\n'
        b'    fi\n'
        b'    if [ -n "$removal_id" ]; then\n',
        1,
    ),
    (
        b'            current_image=$(docker container inspect --format \'{{.Image}}\' "$removal_id")\n',
        b'            current_image=$(docker container inspect --format \'{{.Image}}\' "$removal_id" 2>/dev/null || :)\n',
        1,
    ),
    (
        b'            current_owner=$(docker container inspect \\\n'
        b'                --format \'{{index .Config.Labels "dev.aragorn.capture-owner"}}\' \\\n'
        b'                "$removal_id")\n',
        b'            current_owner=$(docker container inspect \\\n'
        b'                --format \'{{index .Config.Labels "dev.aragorn.capture-owner"}}\' \\\n'
        b'                "$removal_id" 2>/dev/null || :)\n',
        1,
    ),
    (
        b'    if [ "$route_input_volume_created" -eq 1 ]; then\n'
        b'        current_owner=$(docker volume inspect \\\n'
        b'            --format \'{{index .Labels "dev.aragorn.capture-owner"}}\' \\\n'
        b'            "$route_input_volume" 2>/dev/null || :)\n'
        b'        if [ "$current_owner" != "$owner_token" ]; then\n'
        b'            echo "refusing to remove an unowned V3 workshop-proposal-apply route volume" >&2\n'
        b'            cleanup_failed=1\n'
        b'        elif ! docker volume rm "$route_input_volume" >/dev/null; then\n'
        b'            cleanup_failed=1\n'
        b'        elif docker volume inspect "$route_input_volume" >/dev/null 2>&1; then\n'
        b'            echo "V3 workshop-proposal-apply route volume remained after cleanup" >&2\n'
        b'            cleanup_failed=1\n'
        b'        else\n'
        b'            route_input_volume_created=0\n'
        b'        fi\n'
        b'    fi\n',
        b'    if [ "$route_input_volume_created" -eq 1 ]; then\n'
        b'        if ! docker volume inspect "$route_input_volume" >/dev/null 2>&1; then\n'
        b'            route_input_volume_created=0\n'
        b'        else\n'
        b'            current_owner=$(docker volume inspect \\\n'
        b'                --format \'{{index .Labels "dev.aragorn.capture-owner"}}\' \\\n'
        b'                "$route_input_volume" 2>/dev/null || :)\n'
        b'            current_source=$(docker volume inspect \\\n'
        b'                --format \'{{index .Labels "dev.aragorn.source-commit"}}\' \\\n'
        b'                "$route_input_volume" 2>/dev/null || :)\n'
        b'            current_role=$(docker volume inspect \\\n'
        b'                --format \'{{index .Labels "dev.aragorn.role"}}\' \\\n'
        b'                "$route_input_volume" 2>/dev/null || :)\n'
        b'            if [ "$current_owner" != "$owner_token" ] \\\n'
        b'                || [ "$current_source" != "$source_commit" ] \\\n'
        b'                || [ "$current_role" != final-combined-v3-workshop-proposal-apply-route-input ]\n'
        b'            then\n'
        b'                echo "refusing to remove an unowned V3 workshop-proposal-apply route volume" >&2\n'
        b'                cleanup_failed=1\n'
        b'            elif ! docker volume rm "$route_input_volume" >/dev/null; then\n'
        b'                cleanup_failed=1\n'
        b'            elif docker volume inspect "$route_input_volume" >/dev/null 2>&1; then\n'
        b'                echo "V3 workshop-proposal-apply route volume remained after cleanup" >&2\n'
        b'                cleanup_failed=1\n'
        b'            else\n'
        b'                route_input_volume_created=0\n'
        b'            fi\n'
        b'        fi\n'
        b'    fi\n',
        1,
    ),
    (
        b'created_volume=$(docker volume create \\\n',
        b'route_input_volume_created=1\ncreated_volume=$(docker volume create \\\n',
        1,
    ),
    (
        b'    "$route_input_volume")\nroute_input_volume_created=1\nif [ "$created_volume"',
        b'    "$route_input_volume")\nif [ "$created_volume"',
        1,
    ),
    (
        b"    benchmark/admission/openclaw-v2026.7.1/protected-route-probe.mjs \\\n"
        b"    benchmark/fixtures/phase1-protected-workshop/PROPOSAL.md \\\n",
        b"    benchmark/admission/openclaw-v2026.7.1/protected-route-probe.mjs \\\n"
        b"    benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-audit-listener.mjs \\\n"
        b"    benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-index.js \\\n"
        b"    benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-openclaw.plugin.json \\\n"
        b"    benchmark/admission/openclaw-v2026.7.1/core-updater-plugin-replacement-package.json \\\n"
        b"    benchmark/admission/openclaw-v2026.7.1/protected-core-updater-plugin-replacement-v3-probe.mjs \\\n"
        b"    src/aragorn/admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture.py \\\n",
        1,
    ),
    (
        b"    scripts/materialize_fixed_admission_probes.py \\\n",
        b"    scripts/materialize_fixed_admission_probes.py \\\n"
        b"    scripts/materialize_openclaw_final_v3_core_updater_plugin_replacement.py \\\n"
        b"    scripts/materialize_openclaw_final_v3_rebound_probes.py \\\n",
        1,
    ),
    (b"workshop-proposal-apply", b"core-updater-plugin-replacement", 43),
    (b"workshop_proposal_apply", b"core_updater_plugin_replacement", 4),
    (b"WORKSHOP_PROPOSAL_APPLY", b"CORE_UPDATER_PLUGIN_REPLACEMENT", 3),
    (
        b"NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY",
        b"NOT_PASS_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
        1,
    ),
)
for old, new, count in replacements:
    if source.count(old) != count:
        raise SystemExit("pinned core-updater capture transform changed")
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
