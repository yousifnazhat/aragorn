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

temporary=$(mktemp "${TMPDIR:-/tmp}/aragorn-v3-det01-capture.XXXXXX")
python3.12 - "$source_recipe" "$temporary" <<'PY'
import os
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_bytes()
destination = Path(sys.argv[2])


def replace(old: bytes, new: bytes, count: int) -> None:
    global source
    if source.count(old) != count:
        raise SystemExit(f"pinned DET-01 capture transform changed: {old!r}")
    source = source.replace(old, new)


replace(
    b'root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)',
    b'root=${ARAGORN_CAPTURE_ROOT:?missing capture root}',
    1,
)
replace(
    b'    if [ -n "$removal_id" ]; then\n',
    b'    if [ -z "$removal_id" ]; then\n'
    b'        removal_id=$(docker container inspect --format \'{{.Id}}\' "$container" 2>/dev/null || :)\n'
    b'        container_id=$removal_id\n'
    b'    fi\n'
    b'    if [ -n "$removal_id" ]; then\n',
    1,
)
replace(
    b'            current_image=$(docker container inspect --format \'{{.Image}}\' "$removal_id")\n',
    b'            current_image=$(docker container inspect --format \'{{.Image}}\' "$removal_id" 2>/dev/null || :)\n',
    1,
)
replace(
    b'            current_owner=$(docker container inspect \\\n'
    b'                --format \'{{index .Config.Labels "dev.aragorn.capture-owner"}}\' \\\n'
    b'                "$removal_id")\n',
    b'            current_owner=$(docker container inspect \\\n'
    b'                --format \'{{index .Config.Labels "dev.aragorn.capture-owner"}}\' \\\n'
    b'                "$removal_id" 2>/dev/null || :)\n',
    1,
)
replace(
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
)
replace(
    b'created_volume=$(docker volume create \\\n',
    b'route_input_volume_created=1\ncreated_volume=$(docker volume create \\\n',
    1,
)
replace(
    b'    "$route_input_volume")\nroute_input_volume_created=1\nif [ "$created_volume"',
    b'    "$route_input_volume")\nif [ "$created_volume"',
    1,
)
archive = (
    b"    benchmark/admission/openclaw-v2026.7.1/protected-route-probe.mjs \\\n"
    b"    benchmark/fixtures/phase1-protected-workshop/PROPOSAL.md \\\n"
    b"    benchmark/runtime-action-worker-final-combined-v3-workshop-proposal-apply-systemd \\\n"
    b"    scripts/capture_runtime_action_worker_final_combined_v3_workshop_proposal_apply_systemd.sh \\\n"
    b"    scripts/materialize_fixed_admission_probes.py \\\n"
    b"    scripts/runtime_action_worker_final_combined_v3_workshop_proposal_apply_systemd_probe.py \\\n"
)
replacement_archive = (
    b"    benchmark/admission/openclaw-v2026.7.1/deterministic-authority-vectors-v1.json \\\n"
    b"    benchmark/runtime-action-worker-final-combined-v3-det01-systemd \\\n"
    b"    scripts/capture_runtime_action_worker_final_combined_v3_det01_systemd.sh \\\n"
    b"    scripts/materialize_openclaw_final_v3_det01.py \\\n"
    b"    scripts/run_admission_authority_replay.py \\\n"
    b"    scripts/runtime_action_worker_final_combined_v3_det01_systemd_probe.py \\\n"
    b"    src/aragorn/__init__.py \\\n"
    b"    src/aragorn/admission_decision.py \\\n"
    b"    src/aragorn/analyze.py \\\n"
    b"    src/aragorn/oci_worker_protocol.py \\\n"
    b"    src/aragorn/policy.py \\\n"
)
replace(archive, replacement_archive, 1)
replace(b"workshop-proposal-apply", b"det01", 42)
replace(b"workshop_proposal_apply", b"det01", 2)
replace(b"WORKSHOP_PROPOSAL_APPLY", b"DET01", 3)
replace(b"workshop-proposal", b"det01", 12)
replace(b"route_input_volume", b"subfixture_volume", 26)
replace(b"route_volume_inspect", b"subfixture_volume_inspect", 5)
replace(b"route_volume", b"subfixture_volume_document", 10)
replace(b"route_mount", b"subfixture_mount", 15)
replace(b"route_identity", b"subfixture_identity", 5)
replace(b"route_input_mount", b"subfixture_mount", 1)
replace(b"/route-input", b"/campaign", 4)
replace(b"route-input", b"subfixture", 7)
replace(b"route-volume", b"subfixture-volume", 1)
replace(b"route volume", b"subfixture volume", 7)
replace(b"route_status", b"det01_status", 2)
replace(b"route_observation_status", b"det01_observation_status", 1)
replace(b"route_pass_count", b"det01_pass_count", 1)
replace(b"route_fail_count", b"det01_fail_count", 1)
replace(b"route_not_tested_count", b"det01_not_tested_count", 1)
replace(b'document.get("route_id")', b'document.get("case_id")', 1)
replace(b'"ADM-02/update/det01"', b'"DET-01"', 1)
replace(
    b'or decision.get("det01_not_tested_count") != 21',
    b'or decision.get("det01_not_tested_count") != 1',
    1,
)
replace(
    b'        "aggregate_admission_eligible",\n',
    b'        "aggregate_admission_eligible",\n        "det_01_eligible",\n',
    1,
)
replace(
    b'    -v "$subfixture_volume:/campaign:ro" \\\n',
    b'    -v "$subfixture_volume:/campaign:rw" \\\n',
    1,
)
replace(
    b'    "mode": "ro",\n    "rw": False,\n    "source": subfixture_volume_document["Name"],',
    b'    "mode": "rw",\n    "rw": True,\n    "source": subfixture_volume_document["Name"],',
    1,
)
replace(
    b'f"{subfixture_volume_document[\'Name\']}:/campaign:ro",',
    b'f"{subfixture_volume_document[\'Name\']}:/campaign:rw",',
    1,
)
readiness = (
    b"    test -S /run/systemd/private \\\n"
    b"        && test \"$(stat -c \"%u:%g:%a\" /run/aragorn-protected-install 2>/dev/null)\" = 0:0:700 \\\n"
    b"        && test -z \"$(find /run/aragorn-protected-install -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)\"\n"
)
replace(
    readiness,
    b"    test -S /run/systemd/private \\\n"
    b"        && test \"$(stat -c \"%u:%g:%a\" /campaign 2>/dev/null)\" = 0:0:755 \\\n"
    b"        && test -z \"$(find /campaign -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)\"\n",
    1,
)
replace(
    b"        echo \"systemd and protected-install tmpfiles did not become ready\" >&2\n",
    b"        echo \"systemd or empty DET-01 subfixture volume did not become ready\" >&2\n",
    1,
)
replace(
    b'docker cp "$container_id:$evidence_path" "$temp_output"\nif ! remove_created_container; then',
    b'docker cp "$container_id:$evidence_path" "$temp_output"\n'
    b"if ! docker exec \"$container_id\" sh -c '\n"
    b"    test -z \"$(find /campaign -mindepth 1 -maxdepth 1 -print -quit)\"\n"
    b"'; then\n"
    b'    echo "DET-01 subfixture path remained after collector return" >&2\n'
    b"    exit 74\n"
    b"fi\n"
    b"if ! remove_created_container; then",
    1,
)
replace(
    b"NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY",
    b"NOT_PASS_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
    1,
)
if any(
    stale in source
    for stale in (
        b"workshop-proposal-apply",
        b"workshop_proposal_apply",
        b"WORKSHOP_PROPOSAL_APPLY",
        b"workshop-proposal",
        b"route_input_volume",
        b"route_input_mount",
        b"route_observation_status",
        b'document.get("route_id")',
        b"ADM-02/update/det01",
    )
):
    raise SystemExit("stale workshop or route capture identity remains")
descriptor = os.open(destination, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    os.ftruncate(descriptor, 0)
    written = 0
    while written < len(source):
        count = os.write(descriptor, source[written:])
        if count <= 0:
            raise SystemExit("DET-01 capture recipe write made no progress")
        written += count
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
chmod 0700 "$temporary"
ARAGORN_CAPTURE_ROOT=$root "$temporary" "$@"
