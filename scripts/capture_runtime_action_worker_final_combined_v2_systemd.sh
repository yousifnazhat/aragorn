#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
parent=sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c
image=aragorn-phase3-final-combined-v2-systemd
runtime_volume=aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1
capture_lock=/tmp/aragorn-phase3-final-combined-v2-capture.lock
umask 077

if [ "$#" -ne 1 ]; then
    echo "usage: capture_runtime_action_worker_final_combined_v2_systemd.sh ABSENT_OUTPUT_PATH" >&2
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
cidfile=$capture_lock/container.id
lock_held=0
create_attempted=0
container_id=
child_id=
context=
inspect=
parent_inspect=
child_inspect=
volume_inspect=
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
    for path in \
        "$inspect" "$parent_inspect" "$child_inspect" "$volume_inspect" \
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
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v2.json \
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-profile-v2.json \
    benchmark/admission/openclaw-v2026.7.1/protected-final-combined-runtime-v2.lock.json \
    benchmark/runtime-action-worker-final-combined-v2-systemd \
    packaging/activate-runtime-action-worker-host.sh \
    src/aragorn/runtime_action_worker.py \
    scripts/capture_runtime_action_worker_final_combined_v2_systemd.sh \
    scripts/runtime_action_worker_final_combined_v2_systemd_probe.py \
    | tar -xf - -C "$context"
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

create_attempted=1
container_id=$(docker create --name "$container" --cidfile "$cidfile" --pull=never \
    --privileged --cgroupns=host --network=none \
    --security-opt label=disable \
    --label dev.aragorn.profile=phase3-final-combined-v2 \
    --label "dev.aragorn.capture-owner=$owner_token" \
    --tmpfs /run:rw,nosuid,nodev,noexec,mode=755 \
    --tmpfs /run/lock:rw,nosuid,nodev,noexec,mode=755 \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$runtime_volume:/runtime:ro" \
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
docker volume inspect "$runtime_volume" >"$volume_inspect"
python3.12 - \
    "$inspect" "$parent_inspect" "$child_inspect" "$volume_inspect" \
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


source, parent, child, volume = map(one, sys.argv[1:5])
parent_id = "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
runtime_volume = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
commit = sys.argv[6]
commit_object = raw_record(sys.argv[7])
commit_raw = base64.b64decode(commit_object["base64"], validate=True)
commit_identity = hashlib.sha1(
    f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
).hexdigest()
verification_stdout = raw_record(sys.argv[8])
verification_stderr = raw_record(sys.argv[9])
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
            f"{runtime_volume}:/runtime:ro",
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
    "host_config": host_config,
}
Path(sys.argv[5]).write_text(
    json.dumps(document, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
    encoding="ascii",
)
PY

docker exec -i "$container_id" /bin/sh -c \
    'umask 077; cat > /run/aragorn-harness.json' <"$harness"
docker exec "$container_id" install -d -m 0700 /evidence
probe_status=0
docker exec "$container_id" /usr/local/bin/python3.12 -I -S -B \
    /src/scripts/runtime_action_worker_final_combined_v2_systemd_probe.py \
    || probe_status=$?
if [ "$probe_status" -ne 0 ]; then
    docker exec "$container_id" \
        cat /evidence/runtime-action-worker-final-combined-v2-systemd.json >&2 || :
    exit "$probe_status"
fi
docker cp \
    "$container_id:/evidence/runtime-action-worker-final-combined-v2-systemd.json" \
    "$temp_output"
if ! remove_created_container; then
    echo "cannot remove and verify the privileged final combined v2 container" >&2
    exit 74
fi

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
        parse_float=lambda value: (_ for _ in ()).throw(ValueError(value)),
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
    if (
        raw != canonical
        or document.get("schema")
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
        or decision.get("route_pass_count") != 0
        or decision.get("route_fail_count") != 0
        or decision.get("route_not_tested_count") != 21
        or false_claims != expected_false_claims
        or any(decision[key] is not False for key in false_claims)
    ):
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
