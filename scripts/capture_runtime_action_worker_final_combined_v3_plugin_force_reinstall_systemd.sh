#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
parent=sha256:21184b7a6a096a8625994b524203bf5b521d749b24e415378a69decd4e78009b
runtime_volume=aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1
capture_lock=/tmp/aragorn-phase3-final-combined-v3-force-reinstall-capture.lock
DOCKER_CONTEXT=colima-aragorn-bakeoff
COPYFILE_DISABLE=1
export COPYFILE_DISABLE DOCKER_CONTEXT
umask 077

if [ "$#" -ne 1 ]; then
    echo "usage: capture_runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd.sh ABSENT_OUTPUT_PATH" >&2
    exit 64
fi
output=$1
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
    echo "V3 force-reinstall capture requires one clean signed source commit" >&2
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

container=aragorn-phase3-final-combined-v3-force-reinstall-$$
owner_token=$source_commit:$$
route_input_volume=aragorn-phase3-final-combined-v3-plugin-force-reinstall-route-input-$$
cidfile=$capture_lock/container.id
lock_held=0
create_attempted=0
route_input_volume_created=0
container_id=
child_id=
context=
inspect=
parent_inspect=
child_inspect=
runtime_volume_inspect=
route_volume_inspect=
harness=
commit_object=
commit_stdout=
commit_stderr=
iidfile=
temp_output=

remove_created_container()
{
    [ "$create_attempted" -eq 1 ] || return 0
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
                echo "refusing to remove an unowned V3 force-reinstall container" >&2
                return 1
            fi
            docker rm -f "$removal_id" >/dev/null 2>&1 || :
        fi
    fi
    if ! docker info >/dev/null 2>&1; then
        echo "cannot verify V3 force-reinstall container removal" >&2
        return 1
    fi
    if [ -n "$removal_id" ] \
        && docker container inspect "$removal_id" >/dev/null 2>&1
    then
        echo "privileged V3 force-reinstall container remained" >&2
        return 1
    fi
    if docker container inspect "$container" >/dev/null 2>&1; then
        echo "V3 force-reinstall container name was rebound" >&2
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
    remove_created_container || cleanup_failed=1
    if [ "$route_input_volume_created" -eq 1 ]; then
        current_owner=$(docker volume inspect \
            --format '{{index .Labels "dev.aragorn.capture-owner"}}' \
            "$route_input_volume" 2>/dev/null || :)
        if [ "$current_owner" != "$owner_token" ]; then
            echo "refusing to remove an unowned V3 force-reinstall route volume" >&2
            cleanup_failed=1
        elif ! docker volume rm "$route_input_volume" >/dev/null; then
            cleanup_failed=1
        else
            route_input_volume_created=0
        fi
    fi
    for path in \
        "$inspect" "$parent_inspect" "$child_inspect" \
        "$runtime_volume_inspect" "$route_volume_inspect" "$harness" \
        "$commit_object" "$commit_stdout" "$commit_stderr" "$iidfile" \
        "$temp_output"
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
            /tmp/aragorn-phase3-final-combined-v3-force-context.*)
                rm -rf -- "$context" || cleanup_failed=1
                ;;
            *)
                echo "refusing to remove an unexpected V3 capture context" >&2
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
    echo "another V3 force-reinstall capture owns $capture_lock" >&2
    exit 75
fi
lock_held=1
if [ "$(docker context show)" != "$DOCKER_CONTEXT" ]; then
    echo "V3 force-reinstall Docker context changed" >&2
    exit 66
fi
parent_id=$(docker image inspect --format '{{.Id}}' "$parent" 2>/dev/null || :)
if [ "$parent_id" != "$parent" ]; then
    echo "missing exact retained V2 force image: $parent" >&2
    exit 66
fi
if ! docker volume inspect "$runtime_volume" >/dev/null 2>&1; then
    echo "missing exact final OpenClaw runtime volume: $runtime_volume" >&2
    exit 66
fi
if docker container inspect "$container" >/dev/null 2>&1; then
    echo "refusing to replace existing container: $container" >&2
    exit 73
fi
if docker volume inspect "$route_input_volume" >/dev/null 2>&1; then
    echo "refusing to reuse an existing V3 force-reinstall route volume" >&2
    exit 73
fi

inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-v3-force-inspect.XXXXXX")
parent_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-v3-force-parent.XXXXXX")
child_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-v3-force-child.XXXXXX")
runtime_volume_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-v3-force-runtime-volume.XXXXXX")
route_volume_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-v3-force-route-volume.XXXXXX")
harness=$(mktemp "${TMPDIR:-/tmp}/aragorn-v3-force-harness.XXXXXX")
commit_object=$(mktemp "${TMPDIR:-/tmp}/aragorn-v3-force-commit.XXXXXX")
commit_stdout=$(mktemp "${TMPDIR:-/tmp}/aragorn-v3-force-verify-out.XXXXXX")
commit_stderr=$(mktemp "${TMPDIR:-/tmp}/aragorn-v3-force-verify-err.XXXXXX")
iidfile=$(mktemp "${TMPDIR:-/tmp}/aragorn-v3-force-iid.XXXXXX")
context=$(mktemp -d /tmp/aragorn-phase3-final-combined-v3-force-context.XXXXXX)
temp_output=$(mktemp "${output}.tmp.XXXXXX")

if ! GIT_NO_REPLACE_OBJECTS=1 git verify-commit --raw "$source_commit" \
    >"$commit_stdout" 2>"$commit_stderr"
then
    echo "V3 force-reinstall source commit signature verification failed" >&2
    exit 66
fi
GIT_NO_REPLACE_OBJECTS=1 git cat-file commit "$source_commit" >"$commit_object"
GIT_NO_REPLACE_OBJECTS=1 git archive --format=tar "$source_commit" -- \
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json \
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v3.json \
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v3.lock.json \
    benchmark/admission/openclaw-v2026.7.1/protected-plugin-force-reinstall-v3-probe.py \
    benchmark/runtime-action-worker-final-combined-v3-plugin-force-reinstall-systemd \
    scripts/capture_runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd.sh \
    scripts/runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe.py \
    | tar -xf - -C "$context"

(
    cd "$context"
    docker build --pull=false --network=none \
        --iidfile "$iidfile" \
        --build-arg "V2_FORCE_BASE=$parent_id" \
        -f benchmark/runtime-action-worker-final-combined-v3-plugin-force-reinstall-systemd/Dockerfile \
        .
)
child_id=$(tr -d '\n' <"$iidfile")
child_hex=${child_id#sha256:}
case "$child_id" in
    sha256:*) ;;
    *) echo "Docker did not return one immutable V3 child image ID" >&2; exit 69 ;;
esac
case "$child_hex" in
    ""|*[!0-9a-f]*) echo "Docker returned an invalid V3 child image ID" >&2; exit 69 ;;
esac
if [ "${#child_hex}" -ne 64 ] \
    || [ "$child_id" = "$parent_id" ] \
    || [ "$(docker image inspect --format '{{.Id}}' "$child_id")" != "$child_id" ]
then
    echo "V3 image did not extend the exact retained V2 force image" >&2
    exit 69
fi

created_volume=$(docker volume create \
    --label dev.aragorn.role=final-combined-v3-plugin-force-reinstall-route-input \
    --label "dev.aragorn.source-commit=$source_commit" \
    --label "dev.aragorn.capture-owner=$owner_token" \
    "$route_input_volume")
route_input_volume_created=1
if [ "$created_volume" != "$route_input_volume" ] \
    || [ "$(docker volume inspect --format '{{.Driver}}' "$route_input_volume")" != local ] \
    || [ "$(docker volume inspect --format '{{index .Labels "dev.aragorn.role"}}' "$route_input_volume")" != final-combined-v3-plugin-force-reinstall-route-input ] \
    || [ "$(docker volume inspect --format '{{index .Labels "dev.aragorn.source-commit"}}' "$route_input_volume")" != "$source_commit" ] \
    || [ "$(docker volume inspect --format '{{index .Labels "dev.aragorn.capture-owner"}}' "$route_input_volume")" != "$owner_token" ]
then
    echo "V3 force-reinstall route volume identity changed" >&2
    exit 69
fi

create_attempted=1
container_id=$(docker create --name "$container" --cidfile "$cidfile" --pull=never \
    --privileged --cgroupns=host --network=none \
    --security-opt label=disable \
    --label dev.aragorn.profile=phase3-final-combined-v3-plugin-force-reinstall \
    --label "dev.aragorn.capture-owner=$owner_token" \
    --tmpfs /run:rw,nosuid,nodev,noexec,mode=755 \
    --tmpfs /run/lock:rw,nosuid,nodev,noexec,mode=755 \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$runtime_volume:/runtime:ro" \
    -v "$route_input_volume:/route-input:ro" \
    "$child_id")
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
docker volume inspect "$runtime_volume" >"$runtime_volume_inspect"
docker volume inspect "$route_input_volume" >"$route_volume_inspect"
python3.12 - \
    "$inspect" "$parent_inspect" "$child_inspect" \
    "$runtime_volume_inspect" "$route_volume_inspect" "$harness" \
    "$source_commit" "$commit_object" "$commit_stdout" "$commit_stderr" <<'PY'
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


source, parent, child, runtime_volume, route_volume = map(one, sys.argv[1:6])
output = Path(sys.argv[6])
commit = sys.argv[7]
commit_object = raw_record(sys.argv[8])
commit_raw = base64.b64decode(commit_object["base64"], validate=True)
commit_identity = hashlib.sha1(
    f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
).hexdigest()
verification_stdout = raw_record(sys.argv[9])
verification_stderr = raw_record(sys.argv[10])
parent_id = "sha256:21184b7a6a096a8625994b524203bf5b521d749b24e415378a69decd4e78009b"
runtime_name = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
if (
    parent["Id"] != parent_id
    or re.fullmatch(r"[0-9a-f]{40}", commit) is None
    or commit_identity != commit
    or not commit_raw.startswith(b"tree ")
    or b"\ngpgsig " not in commit_raw
    or verification_stdout["bytes"] + verification_stderr["bytes"] == 0
):
    raise SystemExit("V3 parent or signed source identity changed")

parent_layers = parent["RootFS"]["Layers"]
child_layers = child["RootFS"]["Layers"]
if (
    parent["RootFS"]["Type"] != "layers"
    or child["RootFS"]["Type"] != "layers"
    or len(child_layers) <= len(parent_layers)
    or child_layers[: len(parent_layers)] != parent_layers
):
    raise SystemExit("V3 image is not an additive exact-parent child")
child_id = child["Id"]
if source["Image"] != child_id or source["Config"]["Image"] != child_id:
    raise SystemExit("container was not created from the V3 child ID")

runtime_mounts = [item for item in source["Mounts"] if item["Destination"] == "/runtime"]
route_mounts = [item for item in source["Mounts"] if item["Destination"] == "/route-input"]
if len(runtime_mounts) != 1 or len(route_mounts) != 1:
    raise SystemExit("expected exact runtime and route-input mounts")
runtime_mount_raw = runtime_mounts[0]
route_mount_raw = route_mounts[0]
runtime_mount = {
    "destination": runtime_mount_raw["Destination"],
    "driver": runtime_mount_raw["Driver"],
    "mode": runtime_mount_raw["Mode"],
    "rw": runtime_mount_raw["RW"],
    "source": runtime_mount_raw["Name"],
    "type": runtime_mount_raw["Type"],
}
route_mount = {
    "destination": route_mount_raw["Destination"],
    "driver": route_mount_raw["Driver"],
    "mode": route_mount_raw["Mode"],
    "rw": route_mount_raw["RW"],
    "source": route_mount_raw["Name"],
    "type": route_mount_raw["Type"],
}
runtime_identity = {
    "driver": runtime_volume["Driver"],
    "labels": runtime_volume.get("Labels"),
    "name": runtime_volume["Name"],
    "options": runtime_volume.get("Options"),
    "scope": runtime_volume["Scope"],
}
expected_runtime_identity = {
    "driver": "local",
    "labels": {
        "io.aragorn.phase": "phase3-final",
        "io.aragorn.role": "installed-runtime",
        "io.aragorn.source-commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
        "io.aragorn.source-tree": "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44",
    },
    "name": runtime_name,
    "options": None,
    "scope": "local",
}
expected_runtime_mount = {
    "destination": "/runtime",
    "driver": "local",
    "mode": "ro",
    "rw": False,
    "source": runtime_name,
    "type": "volume",
}
if runtime_identity != expected_runtime_identity or runtime_mount != expected_runtime_mount:
    raise SystemExit("V3 runtime volume identity changed")

capture_owner = source["Config"]["Labels"].get("dev.aragorn.capture-owner")
route_identity = {
    "driver": route_volume["Driver"],
    "labels": route_volume.get("Labels"),
    "name": route_volume["Name"],
    "options": route_volume.get("Options"),
    "scope": route_volume["Scope"],
}
match = re.fullmatch(
    r"aragorn-phase3-final-combined-v3-plugin-force-reinstall-route-input-([1-9][0-9]*)",
    route_volume["Name"],
)
expected_owner = f"{commit}:{match.group(1)}" if match else None
expected_route_identity = {
    "driver": "local",
    "labels": {
        "dev.aragorn.capture-owner": expected_owner,
        "dev.aragorn.role": "final-combined-v3-plugin-force-reinstall-route-input",
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
    match is None
    or capture_owner != expected_owner
    or route_identity != expected_route_identity
    or route_mount != expected_route_mount
):
    raise SystemExit("V3 force-reinstall route volume identity changed")

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
expected_host = {
    "binds": sorted(
        [
            "/sys/fs/cgroup:/sys/fs/cgroup:rw",
            f"{runtime_name}:/runtime:ro",
            f"{route_volume['Name']}:/route-input:ro",
        ]
    ),
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
profile = source["Config"]["Labels"].get("dev.aragorn.profile")
if (
    host_config != expected_host
    or source["Platform"] != "linux"
    or profile != "phase3-final-combined-v3-plugin-force-reinstall"
):
    raise SystemExit("V3 outer host profile changed")

document = {
    "schema": (
        "aragorn/runtime-action-worker-final-combined-v3-"
        "plugin-force-reinstall-systemd-harness/v1"
    ),
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
    "image_reference": (
        "aragorn-phase3-final-combined-v3-plugin-force-reinstall-systemd"
    ),
    "run_image_reference": source["Config"]["Image"],
    "parent_image_id": parent_id,
    "image_lineage": {
        "parent": {
            "id": parent_id,
            "rootfs_type": "layers",
            "layers": parent_layers,
        },
        "child": {
            "id": child_id,
            "rootfs_type": "layers",
            "layers": child_layers,
        },
        "added_layers": child_layers[len(parent_layers) :],
    },
    "platform": source["Platform"],
    "profile_label": profile,
    "openclaw_runtime_volume": runtime_mount_raw["Name"],
    "openclaw_runtime_volume_identity": runtime_identity,
    "openclaw_runtime_mount": runtime_mount,
    "route_input_volume_identity": route_identity,
    "route_input_mount": route_mount,
    "host_config": host_config,
}
output.write_text(
    json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ),
    encoding="ascii",
)
PY

docker exec -i "$container_id" /bin/sh -c \
    'umask 077; cat > /run/aragorn-harness.json' <"$harness"
docker exec "$container_id" install -d -m 0700 /evidence
probe_status=0
docker exec "$container_id" /usr/local/bin/python3.12 -I -S -B \
    /src/scripts/runtime_action_worker_final_combined_v3_plugin_force_reinstall_systemd_probe.py \
    || probe_status=$?
evidence_path=/evidence/runtime-action-worker-final-combined-v3-plugin-force-reinstall-systemd.json
if [ "$probe_status" -ne 0 ]; then
    docker exec "$container_id" cat "$evidence_path" >&2 || :
    exit "$probe_status"
fi
docker cp "$container_id:$evidence_path" "$temp_output"
if ! remove_created_container; then
    echo "cannot remove and verify the privileged V3 force-reinstall container" >&2
    exit 74
fi
current_owner=$(docker volume inspect \
    --format '{{index .Labels "dev.aragorn.capture-owner"}}' \
    "$route_input_volume")
if [ "$current_owner" != "$owner_token" ]; then
    echo "V3 force-reinstall route volume ownership changed" >&2
    exit 74
fi
docker volume rm "$route_input_volume" >/dev/null
route_input_volume_created=0

python3.12 - "$temp_output" "$output" <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
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
    route_status = decision.get("route_observation_status")
    expected_status = {
        "NOT_TESTED": (
            "FINAL_COMBINED_V3_PLUGIN_FORCE_REINSTALL_NOT_TESTED_"
            "PROFILE_NOT_TESTED"
        ),
        "OBSERVED": (
            "FINAL_COMBINED_V3_PLUGIN_FORCE_REINSTALL_OBSERVED_PROFILE_NOT_TESTED"
        ),
    }.get(route_status)
    invalid = (
        raw != canonical
        or document.get("schema")
        != (
            "aragorn/runtime-action-worker-final-combined-v3-"
            "plugin-force-reinstall-systemd-observation/v1"
        )
        or document.get("authority")
        != (
            "BOUND_FINAL_COMBINED_V3_RAW_PLUGIN_FORCE_REINSTALL_OBSERVATION_ONLY_"
            "NOT_ADMISSION_RUN_PHASE3_EDR_INSTALLER_RELEASE_AUTHORITY"
        )
        or document.get("route_id") != "ADM-02/update/plugin-force-reinstall"
        or expected_status is None
        or decision.get("status") != expected_status
        or decision.get("route_pass_count") != 0
        or decision.get("route_fail_count") != 0
        or decision.get("route_not_tested_count") != 21
        or false_claims != expected_false_claims
        or any(decision[key] is not False for key in false_claims)
    )
    if invalid:
        raise SystemExit("V3 force probe output is not exact observation-only material")

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
