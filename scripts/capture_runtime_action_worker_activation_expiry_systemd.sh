#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
parent=sha256:1afab032375efbe87ac938c0993880e164d6dace2e37239a27c6def8e320e1db
image=aragorn-p37c-runtime-action-worker-activation-expiry-systemd
runtime_volume=aragorn-openclaw-2026-7-1-runtime
capture_lock=/tmp/aragorn-p37c-runtime-action-worker-capture.lock
umask 077

if [ "$#" -ne 1 ]; then
    echo "usage: capture_runtime_action_worker_activation_expiry_systemd.sh ABSENT_OUTPUT_PATH" >&2
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
    echo "P3.7c capture requires one clean signed source commit" >&2
    exit 66
fi
source_commit=$(GIT_NO_REPLACE_OBJECTS=1 git rev-parse --verify 'HEAD^{commit}')
source_commit_hex=$source_commit
case "$source_commit_hex" in
    ""|*[!0-9a-f]*)
        echo "invalid source commit identity" >&2
        exit 66
        ;;
esac
if [ "${#source_commit_hex}" -ne 40 ]; then
    echo "invalid source commit identity" >&2
    exit 66
fi
container=aragorn-p37c-runtime-action-worker-$$
owner_token=$source_commit_hex:$$
cidfile=$capture_lock/container.id
lock_held=0
inspect=
parent_inspect=
child_inspect=
volume_inspect=
harness=
context=
commit_stdout=
commit_stderr=
commit_object=
iidfile=
temp_output=
child_id=
create_attempted=0
container_id=

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
        current_id=$(
            docker container inspect --format '{{.Id}}' "$removal_id" \
                2>/dev/null || :
        )
        if [ -n "$current_id" ]; then
            if [ "$current_id" != "$removal_id" ]; then
                echo "P3.7c container identity changed before removal" >&2
                return 1
            fi
            current_image=$(docker container inspect --format '{{.Image}}' "$removal_id")
            current_owner=$(
                docker container inspect \
                    --format '{{index .Config.Labels "dev.aragorn.capture-owner"}}' \
                    "$removal_id"
            )
            if [ "$current_image" != "$child_id" ] \
                || [ "$current_owner" != "$owner_token" ]
            then
                echo "refusing to remove an unowned P3.7c container" >&2
                return 1
            fi
            docker rm -f "$removal_id" >/dev/null 2>&1 || :
        fi
    fi

    if ! docker info >/dev/null 2>&1; then
        echo "cannot verify P3.7c container removal" >&2
        return 1
    fi
    if [ -n "$removal_id" ] \
        && docker container inspect "$removal_id" >/dev/null 2>&1
    then
        echo "privileged P3.7c container remained after removal" >&2
        return 1
    fi
    if docker container inspect "$container" >/dev/null 2>&1; then
        echo "P3.7c container name was rebound before publication" >&2
        return 1
    fi
    if [ -f "$cidfile" ]; then
        rm -f -- "$cidfile" || return 1
    fi
    create_attempted=0
    return 0
}

cleanup()
{
    status=$?
    trap - EXIT HUP INT TERM
    cleanup_failed=0
    if ! remove_created_container; then
        cleanup_failed=1
    fi
    for cleanup_path in \
        "$inspect" "$parent_inspect" "$child_inspect" \
        "$volume_inspect" "$harness" \
        "$commit_stdout" "$commit_stderr" "$commit_object" \
        "$iidfile" "$temp_output"
    do
        if [ -n "$cleanup_path" ] \
            && { [ -e "$cleanup_path" ] || [ -L "$cleanup_path" ]; } \
            && ! rm -f -- "$cleanup_path"
        then
            cleanup_failed=1
        fi
    done
    if [ -n "$context" ] && [ -d "$context" ]; then
        case "$context" in
            /tmp/aragorn-p3-7c-context.*)
                rm -rf -- "$context" || cleanup_failed=1
                ;;
            *)
                echo "refusing to remove an unexpected capture context" >&2
                cleanup_failed=1
                ;;
        esac
    fi
    if [ "$lock_held" -eq 1 ]; then
        if ! rmdir "$capture_lock"; then
            cleanup_failed=1
        fi
        lock_held=0
    fi
    if [ "$cleanup_failed" -ne 0 ] && [ "$status" -eq 0 ]; then
        echo "P3.7c capture cleanup failed closed" >&2
        status=74
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
if ! mkdir "$capture_lock"; then
    echo "another P3.7c capture owns the host lock: $capture_lock" >&2
    exit 75
fi
lock_held=1

parent_id=$(docker image inspect --format '{{.Id}}' "$parent" 2>/dev/null || :)
if [ "$parent_id" != "$parent" ]; then
    echo "missing exact local P3.7b image: $parent" >&2
    exit 66
fi
if ! docker volume inspect "$runtime_volume" >/dev/null 2>&1; then
    echo "missing pinned OpenClaw runtime volume: $runtime_volume" >&2
    exit 66
fi
if docker container inspect "$container" >/dev/null 2>&1; then
    echo "refusing to replace existing container: $container" >&2
    exit 73
fi

inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-7c-inspect.XXXXXX")
parent_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-7c-parent.XXXXXX")
child_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-7c-child.XXXXXX")
volume_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-7c-volume.XXXXXX")
harness=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-7c-harness.XXXXXX")
context=$(mktemp -d /tmp/aragorn-p3-7c-context.XXXXXX)
commit_stdout=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-7c-commit-out.XXXXXX")
commit_stderr=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-7c-commit-err.XXXXXX")
commit_object=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-7c-commit-object.XXXXXX")
iidfile=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-7c-image-id.XXXXXX")
temp_output=$(mktemp "${output}.tmp.XXXXXX")

if ! GIT_NO_REPLACE_OBJECTS=1 git verify-commit --raw "$source_commit" \
    >"$commit_stdout" 2>"$commit_stderr"
then
    echo "P3.7c source commit signature verification failed" >&2
    exit 66
fi
GIT_NO_REPLACE_OBJECTS=1 git cat-file commit "$source_commit" >"$commit_object"
GIT_NO_REPLACE_OBJECTS=1 git archive --format=tar "$source_commit" -- \
    benchmark/runtime-action-worker-activation-expiry-systemd \
    packaging/activate-runtime-capability-host.sh \
    packaging/activate-runtime-action-worker-host.sh \
    packaging/install-runtime-action-worker-host.sh \
    scripts/capture_runtime_action_worker_activation_expiry_systemd.sh \
    scripts/runtime_action_worker_activation_expiry_systemd_probe.py \
    src/aragorn/runtime_action_broker_v4.py \
    src/aragorn/runtime_action_broker_v5.py \
    src/aragorn/runtime_action_service_v4.py \
    src/aragorn/runtime_action_service_v5.py \
    src/aragorn/runtime_action_worker.py \
    | tar -xf - -C "$context"
(
    cd "$context"
    docker build --pull=false --network=none \
        --iidfile "$iidfile" \
        --build-arg "P37B_BASE=$parent_id" \
        -t "$image" \
        -f benchmark/runtime-action-worker-activation-expiry-systemd/Dockerfile \
        .
)
child_id=$(tr -d '\n' <"$iidfile")
child_id_hex=${child_id#sha256:}
case "$child_id" in
    sha256:*) ;;
    *) echo "Docker did not return one immutable child image ID" >&2; exit 69 ;;
esac
case "$child_id_hex" in
    ""|*[!0-9a-f]*)
        echo "Docker did not return one immutable child image ID" >&2
        exit 69
        ;;
esac
if [ "${#child_id_hex}" -ne 64 ]; then
    echo "Docker did not return one immutable child image ID" >&2
    exit 69
fi
if [ "$child_id" = "$parent_id" ] \
    || [ "$(docker image inspect --format '{{.Id}}' "$child_id")" != "$child_id" ]
then
    echo "P3.7c image did not extend the exact P3.7b parent" >&2
    exit 69
fi

create_attempted=1
container_id=$(docker create --name "$container" --cidfile "$cidfile" --pull=never \
    --privileged --cgroupns=host --network=none \
    --security-opt label=disable \
    --label dev.aragorn.profile=p3.7c \
    --label "dev.aragorn.capture-owner=$owner_token" \
    --tmpfs /run:rw,nosuid,nodev,noexec,mode=755 \
    --tmpfs /run/lock:rw,nosuid,nodev,noexec,mode=755 \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$runtime_volume:/runtime:ro" \
    "$child_id")
docker start "$container_id" >/dev/null

i=0
while ! docker exec "$container_id" test -S /run/systemd/private; do
    i=$((i + 1))
    if [ "$i" -ge 100 ]; then
        echo "systemd did not become ready" >&2
        exit 70
    fi
    sleep 0.1
done

docker inspect "$container_id" >"$inspect"
docker image inspect "$parent_id" >"$parent_inspect"
docker image inspect "$child_id" >"$child_inspect"
docker volume inspect "$runtime_volume" >"$volume_inspect"
python3.12 - \
    "$inspect" "$parent_inspect" "$child_inspect" \
    "$volume_inspect" "$harness" "$source_commit" \
    "$commit_object" "$commit_stdout" "$commit_stderr" <<'PY'
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
parent_id = "sha256:1afab032375efbe87ac938c0993880e164d6dace2e37239a27c6def8e320e1db"
commit = sys.argv[6]
if parent["Id"] != parent_id or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
    raise SystemExit("P3.7c parent or source commit identity drifted")
commit_object = raw_record(sys.argv[7])
commit_raw = base64.b64decode(commit_object["base64"], validate=True)
commit_identity = hashlib.sha1(
    f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
).hexdigest()
verification_stdout = raw_record(sys.argv[8])
verification_stderr = raw_record(sys.argv[9])
if (
    commit_identity != commit
    or not commit_raw.startswith(b"tree ")
    or b"\ngpgsig " not in commit_raw
    or verification_stdout["bytes"] + verification_stderr["bytes"] == 0
):
    raise SystemExit("retained source commit verification receipt is invalid")
parent_layers = parent["RootFS"]["Layers"]
child_layers = child["RootFS"]["Layers"]
if (
    parent["RootFS"]["Type"] != "layers"
    or child["RootFS"]["Type"] != "layers"
    or len(child_layers) <= len(parent_layers)
    or child_layers[: len(parent_layers)] != parent_layers
):
    raise SystemExit("P3.7c child is not an additive P3.7b layer")
child_id = child["Id"]
if source["Image"] != child_id or source["Config"]["Image"] != child_id:
    raise SystemExit("container was not created from the captured child ID")
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
volume_identity = {
    "driver": volume["Driver"],
    "labels": volume.get("Labels"),
    "name": volume["Name"],
    "options": volume.get("Options"),
    "scope": volume["Scope"],
}
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
expected_mount = {
    "destination": "/runtime",
    "driver": "local",
    "mode": "ro",
    "rw": False,
    "source": "aragorn-openclaw-2026-7-1-runtime",
    "type": "volume",
}
expected_volume = {
    "driver": "local",
    "labels": None,
    "name": "aragorn-openclaw-2026-7-1-runtime",
    "options": None,
    "scope": "local",
}
expected_host = {
    "binds": sorted([
        "/sys/fs/cgroup:/sys/fs/cgroup:rw",
        "aragorn-openclaw-2026-7-1-runtime:/runtime:ro",
    ]),
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
if runtime_mount != expected_mount or volume_identity != expected_volume:
    raise SystemExit("OpenClaw runtime mount identity drifted")
if host_config != expected_host:
    raise SystemExit("P3.7c outer host profile drifted")
if source["Platform"] != "linux":
    raise SystemExit("P3.7c container platform changed")
if source["Config"]["Labels"].get("dev.aragorn.profile") != "p3.7c":
    raise SystemExit("P3.7c container label changed")
document = {
    "schema": "aragorn/runtime-action-worker-activation-expiry-systemd-harness/v1",
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
    "image_reference": "aragorn-p37c-runtime-action-worker-activation-expiry-systemd",
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
    encoding="utf-8",
)
PY

docker exec -i "$container_id" /bin/sh -c \
    'umask 077; cat > /run/aragorn-harness.json' <"$harness"
docker exec "$container_id" install -d -m 0700 /observation
probe_status=0
docker exec "$container_id" /usr/local/bin/python3.12 -I -S -B \
    /src/scripts/runtime_action_worker_activation_expiry_systemd_probe.py \
    --output /observation/runtime-action-worker-activation-expiry-systemd.json \
    || probe_status=$?
if [ "$probe_status" -ne 0 ]; then
    docker exec "$container_id" \
        cat /observation/runtime-action-worker-activation-expiry-systemd.json >&2 || :
    exit "$probe_status"
fi
docker cp \
    "$container_id:/observation/runtime-action-worker-activation-expiry-systemd.json" \
    "$temp_output"
if ! remove_created_container; then
    echo "cannot remove and verify the privileged P3.7c container" >&2
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
    opened_stat = os.fstat(descriptor)
    if not stat.S_ISREG(opened_stat.st_mode) or opened_stat.st_nlink != 1:
        raise SystemExit("captured observation is not one regular temporary file")
    raw = read_descriptor(descriptor)
    after_read = os.fstat(descriptor)
    if (
        (after_read.st_dev, after_read.st_ino)
        != (opened_stat.st_dev, opened_stat.st_ino)
        or after_read.st_size != len(raw)
    ):
        raise SystemExit("captured observation changed while reading")
    document = json.loads(
        raw,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        parse_float=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )
    expected = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii") + b"\n"
    if raw != expected:
        raise SystemExit("captured observation is not canonical JSON")
    decision = document.get("decision", {})
    false_ceilings = (
        "retained_evidence_eligible",
        "aggregate_gate_eligible",
        "run_01_eligible",
        "run_02_eligible",
        "phase3_exit_eligible",
        "edr_claim_eligible",
        "installer_authority_eligible",
        "public_release_eligible",
    )
    if (
        document.get("schema")
        != "aragorn/runtime-action-worker-activation-expiry-systemd-observation/v1"
        or document.get("authority")
        != "BOUNDED_ACTIVATION_EXPIRY_ROTATION_OBSERVATION_ONLY_NOT_VERIFIED_RUN_EDR_INSTALLER_RELEASE_AUTHORITY"
        or decision.get("status") != "P3_7C_ACTIVATION_EXPIRY_OBSERVED"
        or decision.get("verifier_status") != "NOT_TESTED"
        or any(decision.get(name) is not False for name in false_ceilings)
    ):
        raise SystemExit("probe output is not publication-ready observation-only material")

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

    source_link = os.stat(source.name, dir_fd=directory, follow_symlinks=False)
    destination_link = os.stat(
        destination.name, dir_fd=directory, follow_symlinks=False
    )
    for retained in (os.fstat(descriptor), source_link, destination_link):
        if (
            (retained.st_dev, retained.st_ino) != published_identity
            or not stat.S_ISREG(retained.st_mode)
            or stat.S_IMODE(retained.st_mode) != 0o644
            or retained.st_nlink != 2
            or retained.st_size != len(raw)
        ):
            raise SystemExit("linked observation identity or metadata changed")

    destination_descriptor = os.open(
        destination.name, file_flags, dir_fd=directory
    )
    destination_opened = os.fstat(destination_descriptor)
    if (
        (destination_opened.st_dev, destination_opened.st_ino) != published_identity
        or read_descriptor(destination_descriptor) != raw
    ):
        raise SystemExit("linked observation content changed")
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
