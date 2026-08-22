#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
parent=sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c
image=aragorn-phase3-final-combined-v2-systemd
runtime_volume=aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1
capture_lock=/tmp/aragorn-phase3-final-combined-v2-capture.lock
umask 077

mode=bootstrap
route=ADM-02/reload/fresh-session-reset
if [ "$#" -eq 1 ]; then
    output=$1
elif [ "$#" -eq 2 ]; then
    mode=route
    case "$1" in
        --archive-source-force-replacement)
            route=ADM-02/update/archive-source-force-replacement ;;
        --config-entry-activation)
            route=ADM-02/update/config-entry-activation ;;
        --cron-rescan) route=ADM-02/reload/cron-rescan ;;
        --fresh-session-reset) route=ADM-02/reload/fresh-session-reset ;;
        --missing-prompt-blob-rebuild)
            route=ADM-02/reload/missing-prompt-blob-rebuild ;;
        --session-snapshot-consumer)
            route=ADM-02/reload/session-snapshot-consumer ;;
        *)
            echo "unsupported final combined v2 route: $1" >&2
            exit 64 ;;
    esac
    output=$2
else
    echo "usage: capture_runtime_action_worker_final_combined_v2_systemd.sh [--archive-source-force-replacement|--config-entry-activation|--cron-rescan|--fresh-session-reset|--missing-prompt-blob-rebuild|--session-snapshot-consumer] ABSENT_OUTPUT_PATH" >&2
    exit 64
fi
case "$output" in
    /*) ;;
    *) output=$PWD/$output ;;
esac
output_dir=$(CDPATH= cd -- "$(dirname -- "$output")" && pwd)
output=$output_dir/$(basename -- "$output")
if [ -e "$output" ] || [ -L "$output" ]; then
    echo "refusing to replace output: $output" >&2
    exit 73
fi

cd "$root"
if [ -n "$(git status --porcelain=v1)" ]; then
    echo "final combined v2 capture requires one clean signed source commit" >&2
    exit 66
fi
source_commit=$(GIT_NO_REPLACE_OBJECTS=1 git rev-parse --verify 'HEAD^{commit}')
case "$source_commit" in
    ""|*[!0-9a-f]*) echo "invalid source commit identity" >&2; exit 66 ;;
esac
if [ "${#source_commit}" -ne 40 ]; then
    echo "invalid source commit identity" >&2
    exit 66
fi

container=aragorn-phase3-final-combined-v2-$$
owner_token=$source_commit:$$
route_input_volume=aragorn-phase3-final-combined-v2-route-input-$$
archive_source_volume=aragorn-phase3-final-combined-v2-archive-source-$$
cidfile=$capture_lock/container.id
lock_held=0
create_attempted=0
route_input_volume_created=0
archive_source_volume_created=0
container_id=
child_id=
context=
inspect=
parent_inspect=
child_inspect=
volume_inspect=
route_volume_inspect=
archive_source_volume_inspect=
harness=
commit_object=
commit_stdout=
commit_stderr=
iidfile=
temp_output=

remove_created_container()
{
    if [ "$create_attempted" -ne 1 ]; then
        return 0
    fi
    removal_id=$container_id
    if [ -z "$removal_id" ] && [ -f "$cidfile" ]; then
        removal_id=$(tr -d '\n' <"$cidfile")
        container_id=$removal_id
    fi
    if [ -n "$removal_id" ]; then
        current_id=$(docker container inspect --format '{{.Id}}' "$removal_id" 2>/dev/null || :)
        if [ -n "$current_id" ]; then
            current_image=$(docker container inspect --format '{{.Image}}' "$removal_id")
            current_owner=$(docker container inspect \
                --format '{{index .Config.Labels "dev.aragorn.capture-owner"}}' \
                "$removal_id")
            if [ "$current_id" != "$removal_id" ] \
                || [ "$current_image" != "$child_id" ] \
                || [ "$current_owner" != "$owner_token" ]
            then
                echo "refusing to remove an unowned final combined v2 container" >&2
                return 1
            fi
            docker rm -f "$removal_id" >/dev/null 2>&1 || :
        fi
    fi
    if ! docker info >/dev/null 2>&1; then
        echo "cannot verify final combined v2 container removal" >&2
        return 1
    fi
    if [ -n "$removal_id" ] \
        && docker container inspect "$removal_id" >/dev/null 2>&1
    then
        echo "privileged final combined v2 container remained after removal" >&2
        return 1
    fi
    if docker container inspect "$container" >/dev/null 2>&1; then
        echo "final combined v2 container name was rebound before publication" >&2
        return 1
    fi
    rm -f -- "$cidfile"
    create_attempted=0
}

cleanup()
{
    status=$?
    trap - EXIT HUP INT TERM
    cleanup_failed=0
    if ! remove_created_container; then
        cleanup_failed=1
    fi
    if [ "$route_input_volume_created" -eq 1 ]; then
        current_owner=$(docker volume inspect \
            --format '{{index .Labels "dev.aragorn.capture-owner"}}' \
            "$route_input_volume" 2>/dev/null || :)
        if [ "$current_owner" != "$owner_token" ]; then
            echo "refusing to remove an unowned final combined v2 route volume" >&2
            cleanup_failed=1
        elif ! docker volume rm "$route_input_volume" >/dev/null; then
            cleanup_failed=1
        else
            route_input_volume_created=0
        fi
    fi
    if [ "$archive_source_volume_created" -eq 1 ]; then
        current_owner=$(docker volume inspect \
            --format '{{index .Labels "dev.aragorn.capture-owner"}}' \
            "$archive_source_volume" 2>/dev/null || :)
        if [ "$current_owner" != "$owner_token" ]; then
            echo "refusing to remove an unowned final combined v2 archive source volume" >&2
            cleanup_failed=1
        elif ! docker volume rm "$archive_source_volume" >/dev/null; then
            cleanup_failed=1
        else
            archive_source_volume_created=0
        fi
    fi
    for path in \
        "$inspect" "$parent_inspect" "$child_inspect" "$volume_inspect" \
        "$route_volume_inspect" "$archive_source_volume_inspect" \
        "$harness" "$commit_object" "$commit_stdout" "$commit_stderr" \
        "$iidfile" "$temp_output"
    do
        if [ -n "$path" ] \
            && { [ -e "$path" ] || [ -L "$path" ]; } \
            && ! rm -f -- "$path"
        then
            cleanup_failed=1
        fi
    done
    if [ -n "$context" ] && [ -d "$context" ]; then
        case "$context" in
            /tmp/aragorn-phase3-final-combined-v2-context.*)
                rm -rf -- "$context" || cleanup_failed=1
                ;;
            *)
                echo "refusing to remove an unexpected capture context" >&2
                cleanup_failed=1
                ;;
        esac
    fi
    if [ "$lock_held" -eq 1 ]; then
        rmdir "$capture_lock" || cleanup_failed=1
        lock_held=0
    fi
    if [ "$cleanup_failed" -ne 0 ] && [ "$status" -eq 0 ]; then
        status=74
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if ! mkdir "$capture_lock"; then
    echo "another final combined v2 capture owns the host lock: $capture_lock" >&2
    exit 75
fi
lock_held=1

parent_id=$(docker image inspect --format '{{.Id}}' "$parent" 2>/dev/null || :)
if [ "$parent_id" != "$parent" ]; then
    echo "missing exact local V1 final child image: $parent" >&2
    exit 66
fi
if ! docker volume inspect "$runtime_volume" >/dev/null 2>&1; then
    echo "missing final OpenClaw runtime volume: $runtime_volume" >&2
    exit 66
fi
if docker container inspect "$container" >/dev/null 2>&1; then
    echo "refusing to replace existing container: $container" >&2
    exit 73
fi

inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-inspect.XXXXXX")
parent_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-parent.XXXXXX")
child_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-child.XXXXXX")
volume_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-volume.XXXXXX")
route_volume_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-route-volume.XXXXXX")
archive_source_volume_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-archive-source-volume.XXXXXX")
harness=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-harness.XXXXXX")
commit_object=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-commit.XXXXXX")
commit_stdout=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-verify-out.XXXXXX")
commit_stderr=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-verify-err.XXXXXX")
iidfile=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-iid.XXXXXX")
context=$(mktemp -d /tmp/aragorn-phase3-final-combined-v2-context.XXXXXX)
temp_output=$(mktemp "${output}.tmp.XXXXXX")

if ! GIT_NO_REPLACE_OBJECTS=1 git verify-commit --raw "$source_commit" \
    >"$commit_stdout" 2>"$commit_stderr"
then
    echo "final combined v2 source commit signature verification failed" >&2
    exit 66
fi
GIT_NO_REPLACE_OBJECTS=1 git cat-file commit "$source_commit" >"$commit_object"
GIT_NO_REPLACE_OBJECTS=1 git archive --format=tar "$source_commit" -- \
    benchmark/admission/openclaw-v2026.7.1/protected-archive-replacement-probe.mjs \
    benchmark/admission/openclaw-v2026.7.1/protected-config-activation-probe.mjs \
    benchmark/admission/openclaw-v2026.7.1/protected-cron-rescan-probe.mjs \
    benchmark/admission/openclaw-v2026.7.1/protected-cron-rescan-v2-probe.mjs \
    benchmark/admission/openclaw-v2026.7.1/protected-observation-v1.mjs \
    benchmark/admission/openclaw-v2026.7.1/protected-prompt-rebuild-probe.mjs \
    benchmark/admission/openclaw-v2026.7.1/protected-route-probe.mjs \
    benchmark/admission/openclaw-v2026.7.1/protected-session-snapshot-fixed-probe.mjs \
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v2.json \
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v2.json \
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v2.lock.json \
    benchmark/fixtures/phase3-protected-archive-replacement/SKILL.md \
    benchmark/runtime-action-worker-final-combined-v2-systemd \
    packaging/activate-runtime-action-worker-host.sh \
    src/aragorn/runtime_action_worker.py \
    scripts/capture_runtime_action_worker_final_combined_v2_systemd.sh \
    scripts/materialize_fixed_admission_probes.py \
    scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py \
    scripts/runtime_action_worker_final_combined_v2_systemd_probe.py \
    scripts/runtime_action_worker_final_route_systemd_probe.py \
    | tar -xf - -C "$context"
python3.12 "$context/scripts/materialize_fixed_admission_probes.py" \
    --final-combined-v2 "$context/route-input/archive-source-force-replacement" \
    protected-archive-replacement-probe.mjs
python3.12 "$context/scripts/materialize_fixed_admission_probes.py" \
    --final-combined-v2 "$context/route-input/config-entry-activation" \
    protected-config-activation-probe.mjs
python3.12 "$context/scripts/materialize_fixed_admission_probes.py" \
    --final-combined-v2 "$context/route-input/cron-rescan" \
    protected-observation-v1.mjs protected-cron-rescan-probe.mjs
python3.12 "$context/scripts/materialize_fixed_admission_probes.py" \
    --final-combined-v2 "$context/route-input/fresh-session-reset" \
    protected-route-probe.mjs
python3.12 "$context/scripts/materialize_fixed_admission_probes.py" \
    --final-combined-v2 "$context/route-input/missing-prompt-blob-rebuild" \
    protected-observation-v1.mjs protected-prompt-rebuild-probe.mjs
python3.12 "$context/scripts/materialize_fixed_admission_probes.py" \
    --final-combined-v2 "$context/route-input/session-snapshot-consumer" \
    protected-observation-v1.mjs protected-session-snapshot-fixed-probe.mjs
(
    cd "$context"
    docker build --pull=false --network=none \
        --iidfile "$iidfile" \
        --build-arg "V1_FINAL_BASE=$parent_id" \
        -t "$image" \
        -f benchmark/runtime-action-worker-final-combined-v2-systemd/Dockerfile \
        .
)
child_id=$(tr -d '\n' <"$iidfile")
child_id_hex=${child_id#sha256:}
case "$child_id" in
    sha256:*) ;;
    *) echo "Docker did not return one immutable child image ID" >&2; exit 69 ;;
esac
case "$child_id_hex" in
    ""|*[!0-9a-f]*) echo "Docker returned an invalid child image ID" >&2; exit 69 ;;
esac
if [ "${#child_id_hex}" -ne 64 ] \
    || [ "$child_id" = "$parent_id" ] \
    || [ "$(docker image inspect --format '{{.Id}}' "$child_id")" != "$child_id" ]
then
    echo "final image did not extend the exact V1 final child" >&2
    exit 69
fi

if docker volume inspect "$route_input_volume" >/dev/null 2>&1; then
    echo "refusing to reuse an existing final combined v2 route volume" >&2
    exit 73
fi
created_volume=$(docker volume create \
    --label dev.aragorn.role=final-combined-v2-route-input \
    --label "dev.aragorn.source-commit=$source_commit" \
    --label "dev.aragorn.capture-owner=$owner_token" \
    "$route_input_volume")
route_input_volume_created=1
if [ "$created_volume" != "$route_input_volume" ] \
    || [ "$(docker volume inspect --format '{{.Driver}}' "$route_input_volume")" != local ] \
    || [ "$(docker volume inspect --format '{{index .Labels "dev.aragorn.role"}}' "$route_input_volume")" != final-combined-v2-route-input ] \
    || [ "$(docker volume inspect --format '{{index .Labels "dev.aragorn.source-commit"}}' "$route_input_volume")" != "$source_commit" ] \
    || [ "$(docker volume inspect --format '{{index .Labels "dev.aragorn.capture-owner"}}' "$route_input_volume")" != "$owner_token" ]
then
    echo "final combined v2 route volume identity changed" >&2
    exit 69
fi

if [ "$route" = ADM-02/update/archive-source-force-replacement ]; then
    archive_source_fixture=$context/benchmark/fixtures/phase3-protected-archive-replacement/SKILL.md
    if [ "$(wc -c <"$archive_source_fixture")" -ne 144 ] \
        || [ "$(shasum -a 256 "$archive_source_fixture" | cut -d ' ' -f 1)" \
            != d30e0a2e568941e37c5f9427b920917a9edf694beadb41f8a5469e820c0dfdf1 ]
    then
        echo "final combined v2 archive source fixture changed" >&2
        exit 69
    fi
    if docker volume inspect "$archive_source_volume" >/dev/null 2>&1; then
        echo "refusing to reuse an existing final combined v2 archive source volume" >&2
        exit 73
    fi
    created_volume=$(docker volume create \
        --label dev.aragorn.role=final-combined-v2-archive-source \
        --label "dev.aragorn.route=$route" \
        --label "dev.aragorn.source-commit=$source_commit" \
        --label "dev.aragorn.capture-owner=$owner_token" \
        "$archive_source_volume")
    archive_source_volume_created=1
    if [ "$created_volume" != "$archive_source_volume" ] \
        || [ "$(docker volume inspect --format '{{.Driver}}' "$archive_source_volume")" != local ] \
        || [ "$(docker volume inspect --format '{{index .Labels "dev.aragorn.role"}}' "$archive_source_volume")" != final-combined-v2-archive-source ] \
        || [ "$(docker volume inspect --format '{{index .Labels "dev.aragorn.route"}}' "$archive_source_volume")" != "$route" ] \
        || [ "$(docker volume inspect --format '{{index .Labels "dev.aragorn.source-commit"}}' "$archive_source_volume")" != "$source_commit" ] \
        || [ "$(docker volume inspect --format '{{index .Labels "dev.aragorn.capture-owner"}}' "$archive_source_volume")" != "$owner_token" ]
    then
        echo "final combined v2 archive source volume identity changed" >&2
        exit 69
    fi
    docker run --rm -i --pull=never --network=none --cap-drop=ALL \
        --security-opt no-new-privileges:true --read-only --user 0:992 \
        --label "dev.aragorn.capture-owner=$owner_token" \
        -v "$archive_source_volume:/sources:rw" \
        --entrypoint /bin/sh "$child_id" -eu -c '
            test -z "$(find /sources -mindepth 1 -print -quit)"
            chgrp 992 /sources
            chmod 0750 /sources
            mkdir -m 0750 /sources/replacement
            umask 077
            cat > /sources/replacement/SKILL.md
            chmod 0440 /sources/replacement/SKILL.md
            test "$(find /sources -mindepth 1 -printf "%P:%y\n" | sort)" = "$(printf "%s\n" replacement:d replacement/SKILL.md:f | sort)"
            test "$(stat -c "%u:%g:%a" /sources)" = 0:992:750
            test "$(stat -c "%u:%g:%a" /sources/replacement)" = 0:992:750
            test "$(stat -c "%u:%g:%a:%h:%s" /sources/replacement/SKILL.md)" = 0:992:440:1:144
            test "$(sha256sum /sources/replacement/SKILL.md | cut -d " " -f 1)" = d30e0a2e568941e37c5f9427b920917a9edf694beadb41f8a5469e820c0dfdf1
        ' <"$archive_source_fixture"
fi

create_final_container()
{
    docker create --name "$container" --cidfile "$cidfile" --pull=never \
        --privileged --cgroupns=host --network=none \
        --security-opt label=disable \
        --label dev.aragorn.profile=phase3-final-combined-v2 \
        --label "dev.aragorn.capture-owner=$owner_token" \
        --tmpfs /run:rw,nosuid,nodev,noexec,mode=755 \
        --tmpfs /run/lock:rw,nosuid,nodev,noexec,mode=755 \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        -v "$runtime_volume:/runtime:ro" \
        -v "$route_input_volume:/route-input:ro" \
        "$@" "$child_id"
}

create_attempted=1
if [ "$archive_source_volume_created" -eq 1 ]; then
    container_id=$(create_final_container \
        -v "$archive_source_volume:/sources:ro")
else
    container_id=$(create_final_container)
fi
docker start "$container_id" >/dev/null

i=0
while ! docker exec "$container_id" sh -c '
    test -S /run/systemd/private \
        && test "$(stat -c "%u:%g:%a" /run/aragorn-protected-install 2>/dev/null)" = 0:0:700 \
        && test -z "$(find /run/aragorn-protected-install -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)"
'; do
    i=$((i + 1))
    if [ "$i" -ge 100 ]; then
        echo "systemd and protected-install tmpfiles did not become ready" >&2
        exit 70
    fi
    sleep 0.1
done

docker inspect "$container_id" >"$inspect"
docker image inspect "$parent_id" >"$parent_inspect"
docker image inspect "$child_id" >"$child_inspect"
docker volume inspect "$runtime_volume" >"$volume_inspect"
docker volume inspect "$route_input_volume" >"$route_volume_inspect"
if [ "$archive_source_volume_created" -eq 1 ]; then
    docker volume inspect "$archive_source_volume" \
        >"$archive_source_volume_inspect"
fi
python3.12 - \
    "$inspect" "$parent_inspect" "$child_inspect" "$volume_inspect" \
    "$route_volume_inspect" "$archive_source_volume_inspect" \
    "$context/benchmark/fixtures/phase3-protected-archive-replacement/SKILL.md" \
    "$harness" "$source_commit" "$commit_object" "$commit_stdout" \
    "$commit_stderr" <<'PY'
import base64
import hashlib
import json
import re
import sys
from pathlib import Path


def one(path: str) -> dict:
    value = json.loads(Path(path).read_bytes())
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise SystemExit(f"expected one inspect object: {path}")
    return value[0]


def raw_record(path: str) -> dict:
    raw = Path(path).read_bytes()
    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "bytes": len(raw),
        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }


source, parent, child, volume, route_volume = map(one, sys.argv[1:6])
archive_volume = one(sys.argv[6]) if Path(sys.argv[6]).stat().st_size else None
archive_fixture = raw_record(sys.argv[7])
archive_fixture["path"] = (
    "benchmark/fixtures/phase3-protected-archive-replacement/SKILL.md"
)
parent_id = "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
runtime_volume = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
commit = sys.argv[9]
commit_object = raw_record(sys.argv[10])
commit_raw = base64.b64decode(commit_object["base64"], validate=True)
commit_identity = hashlib.sha1(
    f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
).hexdigest()
verification_stdout = raw_record(sys.argv[11])
verification_stderr = raw_record(sys.argv[12])
if (
    parent["Id"] != parent_id
    or re.fullmatch(r"[0-9a-f]{40}", commit) is None
    or commit_identity != commit
    or not commit_raw.startswith(b"tree ")
    or b"\ngpgsig " not in commit_raw
    or verification_stdout["bytes"] + verification_stderr["bytes"] == 0
):
    raise SystemExit("final parent or signed source identity changed")

parent_layers = parent["RootFS"]["Layers"]
child_layers = child["RootFS"]["Layers"]
if (
    parent["RootFS"]["Type"] != "layers"
    or child["RootFS"]["Type"] != "layers"
    or len(child_layers) <= len(parent_layers)
    or child_layers[: len(parent_layers)] != parent_layers
):
    raise SystemExit("final image is not an additive V1 final child layer")
child_id = child["Id"]
if source["Image"] != child_id or source["Config"]["Image"] != child_id:
    raise SystemExit("container was not created from the final child ID")

mounts = [item for item in source["Mounts"] if item["Destination"] == "/runtime"]
if len(mounts) != 1:
    raise SystemExit("expected exactly one /runtime mount")
mount = mounts[0]
runtime_mount = {
    "destination": mount["Destination"],
    "driver": mount["Driver"],
    "mode": mount["Mode"],
    "rw": mount["RW"],
    "source": mount["Name"],
    "type": mount["Type"],
}
expected_mount = {
    "destination": "/runtime",
    "driver": "local",
    "mode": "ro",
    "rw": False,
    "source": runtime_volume,
    "type": "volume",
}
volume_identity = {
    "driver": volume["Driver"],
    "labels": volume.get("Labels"),
    "name": volume["Name"],
    "options": volume.get("Options"),
    "scope": volume["Scope"],
}
expected_volume = {
    "driver": "local",
    "labels": {
        "io.aragorn.phase": "phase3-final",
        "io.aragorn.role": "installed-runtime",
        "io.aragorn.source-commit": (
            "7fa98d8e21b6d5937f25a7f19445ff683bb980bf"
        ),
        "io.aragorn.source-tree": "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44",
    },
    "name": runtime_volume,
    "options": None,
    "scope": "local",
}
if runtime_mount != expected_mount or volume_identity != expected_volume:
    raise SystemExit("final OpenClaw runtime volume identity changed")

route_mounts = [
    item for item in source["Mounts"] if item["Destination"] == "/route-input"
]
if len(route_mounts) != 1:
    raise SystemExit("expected exactly one /route-input mount")
route_mount = route_mounts[0]
route_input_mount = {
    "destination": route_mount["Destination"],
    "driver": route_mount["Driver"],
    "mode": route_mount["Mode"],
    "rw": route_mount["RW"],
    "source": route_mount["Name"],
    "type": route_mount["Type"],
}
capture_owner = source["Config"]["Labels"].get("dev.aragorn.capture-owner")
route_volume_identity = {
    "driver": route_volume["Driver"],
    "labels": route_volume.get("Labels"),
    "name": route_volume["Name"],
    "options": route_volume.get("Options"),
    "scope": route_volume["Scope"],
}
expected_route_volume = {
    "driver": "local",
    "labels": {
        "dev.aragorn.capture-owner": capture_owner,
        "dev.aragorn.role": "final-combined-v2-route-input",
        "dev.aragorn.source-commit": commit,
    },
    "name": route_volume["Name"],
    "options": None,
    "scope": "local",
}
expected_route_mount = {
    "destination": "/route-input",
    "driver": "local",
    "mode": "ro",
    "rw": False,
    "source": route_volume["Name"],
    "type": "volume",
}
if (
    re.fullmatch(
        r"aragorn-phase3-final-combined-v2-route-input-[1-9][0-9]*",
        route_volume["Name"],
    )
    is None
    or re.fullmatch(re.escape(commit) + r":[1-9][0-9]*", capture_owner or "")
    is None
    or route_volume_identity != expected_route_volume
    or route_input_mount != expected_route_mount
):
    raise SystemExit("final combined v2 route input volume identity changed")

archive_mounts = [
    item for item in source["Mounts"] if item["Destination"] == "/sources"
]
archive_source_mount = None
archive_source_volume_identity = None
if archive_volume is None:
    if archive_mounts:
        raise SystemExit("unexpected final combined v2 archive source mount")
elif len(archive_mounts) != 1:
    raise SystemExit("expected exactly one /sources mount")
else:
    archive_mount = archive_mounts[0]
    archive_source_mount = {
        "destination": archive_mount["Destination"],
        "driver": archive_mount["Driver"],
        "mode": archive_mount["Mode"],
        "rw": archive_mount["RW"],
        "source": archive_mount["Name"],
        "type": archive_mount["Type"],
    }
    archive_source_volume_identity = {
        "driver": archive_volume["Driver"],
        "labels": archive_volume.get("Labels"),
        "name": archive_volume["Name"],
        "options": archive_volume.get("Options"),
        "scope": archive_volume["Scope"],
    }
    expected_archive_volume = {
        "driver": "local",
        "labels": {
            "dev.aragorn.capture-owner": capture_owner,
            "dev.aragorn.role": "final-combined-v2-archive-source",
            "dev.aragorn.route": "ADM-02/update/archive-source-force-replacement",
            "dev.aragorn.source-commit": commit,
        },
        "name": archive_volume["Name"],
        "options": None,
        "scope": "local",
    }
    expected_archive_mount = {
        "destination": "/sources",
        "driver": "local",
        "mode": "ro",
        "rw": False,
        "source": archive_volume["Name"],
        "type": "volume",
    }
    match = re.fullmatch(
        r"aragorn-phase3-final-combined-v2-archive-source-([1-9][0-9]*)",
        archive_volume["Name"],
    )
    if (
        match is None
        or capture_owner != f"{commit}:{match.group(1)}"
        or archive_source_volume_identity != expected_archive_volume
        or archive_source_mount != expected_archive_mount
        or archive_fixture["bytes"] != 144
        or archive_fixture["digest"]
        != "sha256:d30e0a2e568941e37c5f9427b920917a9edf694beadb41f8a5469e820c0dfdf1"
    ):
        raise SystemExit("final combined v2 archive source identity changed")

host = source["HostConfig"]
host_config = {
    "binds": sorted(host["Binds"]),
    "cgroupns_mode": host["CgroupnsMode"],
    "ipc_mode": host["IpcMode"],
    "network_mode": host["NetworkMode"],
    "privileged": host["Privileged"],
    "readonly_rootfs": host["ReadonlyRootfs"],
    "runtime": host["Runtime"],
    "security_opt": host["SecurityOpt"],
    "tmpfs": host["Tmpfs"],
    "userns_mode": host["UsernsMode"],
}
expected_binds = [
    "/sys/fs/cgroup:/sys/fs/cgroup:rw",
    f"{runtime_volume}:/runtime:ro",
    f"{route_volume['Name']}:/route-input:ro",
]
if archive_source_mount is not None:
    expected_binds.append(f"{archive_volume['Name']}:/sources:ro")
expected_host = {
    "binds": sorted(expected_binds),
    "cgroupns_mode": "host",
    "ipc_mode": "private",
    "network_mode": "none",
    "privileged": True,
    "readonly_rootfs": False,
    "runtime": "runc",
    "security_opt": ["label=disable"],
    "tmpfs": {
        "/run": "rw,nosuid,nodev,noexec,mode=755",
        "/run/lock": "rw,nosuid,nodev,noexec,mode=755",
    },
    "userns_mode": "",
}
if host_config != expected_host:
    raise SystemExit("final outer host profile changed")
if source["Platform"] != "linux":
    raise SystemExit("final container platform changed")
if source["Config"]["Labels"].get("dev.aragorn.profile") != "phase3-final-combined-v2":
    raise SystemExit("final container label changed")

document = {
    "schema": "aragorn/runtime-action-worker-final-combined-v2-systemd-harness/v1",
    "capture_disposition": "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE",
    "source_commit": commit,
    "source_commit_verification": {
        "command": ["git", "verify-commit", "--raw", commit],
        "exit_code": 0,
        "commit_object": commit_object,
        "stdout": verification_stdout,
        "stderr": verification_stderr,
    },
    "container_id": source["Id"],
    "image_id": child_id,
    "image_reference": "aragorn-phase3-final-combined-v2-systemd",
    "run_image_reference": source["Config"]["Image"],
    "parent_image_id": parent_id,
    "image_lineage": {
        "parent": {"id": parent_id, "rootfs_type": "layers", "layers": parent_layers},
        "child": {"id": child_id, "rootfs_type": "layers", "layers": child_layers},
        "added_layers": child_layers[len(parent_layers) :],
    },
    "platform": source["Platform"],
    "profile_label": source["Config"]["Labels"]["dev.aragorn.profile"],
    "openclaw_runtime_volume": mount["Name"],
    "openclaw_runtime_volume_identity": volume_identity,
    "openclaw_runtime_mount": runtime_mount,
    "route_input_volume_identity": route_volume_identity,
    "route_input_mount": route_input_mount,
    "host_config": host_config,
}
if archive_source_mount is not None:
    document.update(
        {
            "archive_source_fixture": archive_fixture,
            "archive_source_mount": archive_source_mount,
            "archive_source_volume_identity": archive_source_volume_identity,
        }
    )
Path(sys.argv[8]).write_text(
    json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ),
    encoding="ascii",
)
PY

docker exec -i "$container_id" /bin/sh -c \
    'umask 077; cat > /run/aragorn-harness.json' <"$harness"
docker exec "$container_id" install -d -m 0700 /evidence
probe_path=/src/scripts/runtime_action_worker_final_combined_v2_systemd_probe.py
evidence_path=/evidence/runtime-action-worker-final-combined-v2-systemd.json
if [ "$mode" = route ]; then
    probe_path=/src/scripts/runtime_action_worker_final_combined_v2_route_systemd_probe.py
    evidence_path=/evidence/runtime-action-worker-final-combined-v2-route-systemd.json
fi
probe_status=0
if [ "$mode" = route ]; then
    docker exec "$container_id" /usr/local/bin/python3.12 -I -S -B \
        "$probe_path" "$route" \
        || probe_status=$?
else
    docker exec "$container_id" /usr/local/bin/python3.12 -I -S -B \
        "$probe_path" \
        || probe_status=$?
fi
if [ "$probe_status" -ne 0 ]; then
    docker exec "$container_id" cat "$evidence_path" >&2 || :
    exit "$probe_status"
fi
docker cp "$container_id:$evidence_path" "$temp_output"
if ! remove_created_container; then
    echo "cannot remove and verify the privileged final combined v2 container" >&2
    exit 74
fi

python3.12 - "$temp_output" "$output" "$mode" "$route" <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
mode = sys.argv[3]
route = sys.argv[4]
if source.parent != destination.parent or source.name == destination.name:
    raise SystemExit("temporary and final observation paths are not co-located")


def read_descriptor(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    while chunk := os.read(descriptor, 1024 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
directory = os.open(destination.parent, directory_flags)
descriptor = -1
destination_descriptor = -1
linked = False
published_identity = None
try:
    descriptor = os.open(source.name, file_flags, dir_fd=directory)
    opened = os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
        raise SystemExit("captured observation is not one regular temporary file")
    raw = read_descriptor(descriptor)
    after_read = os.fstat(descriptor)
    if (
        (after_read.st_dev, after_read.st_ino) != (opened.st_dev, opened.st_ino)
        or after_read.st_size != len(raw)
    ):
        raise SystemExit("captured observation changed while reading")
    document = json.loads(
        raw,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )
    canonical = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"
    decision = document.get("decision", {})
    false_claims = {key for key in decision if key.endswith("_eligible")}
    expected_false_claims = {
        "admission_profile_eligible",
        "aggregate_admission_eligible",
        "edr_eligible",
        "installer_work_eligible",
        "phase3_exit_eligible",
        "release_eligible",
        "run_01_eligible",
        "run_02_eligible",
        "run_eligible",
    }
    invalid = (
        raw != canonical
        or decision.get("route_pass_count") != 0
        or decision.get("route_fail_count") != 0
        or decision.get("route_not_tested_count") != 21
        or false_claims != expected_false_claims
        or any(decision[key] is not False for key in false_claims)
    )
    if mode == "bootstrap":
        invalid = invalid or (
            document.get("schema")
            != "aragorn/runtime-action-worker-final-combined-v2-systemd-observation/v1"
            or document.get("authority")
            != (
                "BOUNDED_FINAL_COMBINED_V2_P3_7C_ACTION_OBSERVATION_ONLY_"
                "PROFILE_ROUTES_REMAIN_NOT_TESTED_NOT_RUN_PHASE3_EDR_"
                "INSTALLER_RELEASE_AUTHORITY"
            )
            or decision.get("status")
            != "FINAL_COMBINED_V2_ACTION_OBSERVED_PROFILE_NOT_TESTED"
            or decision.get("p3_7c_activation_action_observed") is not True
        )
    elif mode == "route":
        route_status = decision.get("route_observation_status")
        expected_status = {
            "NOT_TESTED": "FINAL_COMBINED_V2_ROUTE_NOT_TESTED_PROFILE_NOT_TESTED",
            "OBSERVED": "FINAL_COMBINED_V2_ROUTE_OBSERVED_PROFILE_NOT_TESTED",
        }.get(route_status)
        invalid = invalid or (
            document.get("schema")
            != (
                "aragorn/runtime-action-worker-final-combined-v2-route-"
                "systemd-observation/v1"
            )
            or document.get("authority")
            != (
                "BOUND_FINAL_COMBINED_V2_RAW_ROUTE_OBSERVATION_ONLY_"
                "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
            )
            or document.get("route_id") != route
            or expected_status is None
            or decision.get("status") != expected_status
        )
    else:
        invalid = True
    if invalid:
        raise SystemExit("final probe output is not exact observation-only material")

    os.fchmod(descriptor, 0o644)
    os.fsync(descriptor)
    prepared = os.fstat(descriptor)
    published_identity = (prepared.st_dev, prepared.st_ino)
    if (
        not stat.S_ISREG(prepared.st_mode)
        or stat.S_IMODE(prepared.st_mode) != 0o644
        or prepared.st_nlink != 1
        or prepared.st_size != len(raw)
    ):
        raise SystemExit("temporary observation metadata changed before publication")
    try:
        os.link(
            source.name,
            destination.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
    except FileExistsError as exc:
        raise SystemExit(f"refusing to replace output: {destination}") from exc
    linked = True
    destination_descriptor = os.open(destination.name, file_flags, dir_fd=directory)
    destination_stat = os.fstat(destination_descriptor)
    if (
        (destination_stat.st_dev, destination_stat.st_ino) != published_identity
        or destination_stat.st_nlink != 2
        or read_descriptor(destination_descriptor) != raw
    ):
        raise SystemExit("linked observation identity or content changed")
    os.fsync(destination_descriptor)
    os.fsync(directory)
    os.unlink(source.name, dir_fd=directory)
    final_source = os.fstat(descriptor)
    final_destination = os.stat(
        destination.name, dir_fd=directory, follow_symlinks=False
    )
    if (
        (final_source.st_dev, final_source.st_ino) != published_identity
        or (final_destination.st_dev, final_destination.st_ino) != published_identity
        or final_source.st_nlink != 1
        or final_destination.st_nlink != 1
        or stat.S_IMODE(final_destination.st_mode) != 0o644
        or final_destination.st_size != len(raw)
        or read_descriptor(destination_descriptor) != raw
    ):
        raise SystemExit("published observation changed after temporary unlink")
    os.fsync(destination_descriptor)
    os.fsync(directory)
except BaseException:
    if linked and published_identity is not None:
        try:
            current = os.stat(
                destination.name, dir_fd=directory, follow_symlinks=False
            )
            if (current.st_dev, current.st_ino) == published_identity:
                os.unlink(destination.name, dir_fd=directory)
                os.fsync(directory)
        except FileNotFoundError:
            pass
    raise
finally:
    if destination_descriptor >= 0:
        os.close(destination_descriptor)
    if descriptor >= 0:
        os.close(descriptor)
    os.close(directory)
PY
shasum -a 256 "$output"
