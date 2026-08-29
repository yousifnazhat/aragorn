#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
parent=sha256:21184b7a6a096a8625994b524203bf5b521d749b24e415378a69decd4e78009b
image=aragorn-phase3-runtime-action-worker-sensor-loss-systemd
runtime_volume=aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1
capture_lock=/tmp/aragorn-phase3-runtime-action-worker-sensor-loss-capture.lock
umask 077

if [ "$#" -ne 1 ]; then
    echo "usage: capture_runtime_action_worker_sensor_loss_systemd.sh ABSENT_OUTPUT_PATH" >&2
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
    echo "sensor-loss capture requires one clean signed source commit" >&2
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

container=aragorn-phase3-runtime-action-worker-sensor-loss-$$
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
                echo "refusing to remove an unowned sensor-loss container" >&2
                return 1
            fi
            docker rm -f "$removal_id" >/dev/null 2>&1 || :
        fi
    fi
    if ! docker info >/dev/null 2>&1; then
        echo "cannot verify sensor-loss container removal" >&2
        return 1
    fi
    if [ -n "$removal_id" ] \
        && docker container inspect "$removal_id" >/dev/null 2>&1
    then
        echo "privileged sensor-loss container remained after removal" >&2
        return 1
    fi
    if docker container inspect "$container" >/dev/null 2>&1; then
        echo "sensor-loss container name was rebound before publication" >&2
        return 1
    fi
    if [ -f "$cidfile" ]; then
        rm -f -- "$cidfile" || return 1
    fi
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
            /tmp/aragorn-phase3-runtime-action-worker-sensor-loss-context.*)
                rm -rf -- "$context" || cleanup_failed=1
                ;;
            *)
                echo "refusing to remove an unexpected sensor-loss context" >&2
                cleanup_failed=1
                ;;
        esac
    fi
    if [ "$lock_held" -eq 1 ]; then
        rmdir "$capture_lock" || cleanup_failed=1
        lock_held=0
    fi
    if [ "$cleanup_failed" -ne 0 ] && [ "$status" -eq 0 ]; then
        echo "sensor-loss capture cleanup failed closed" >&2
        status=74
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

if ! mkdir "$capture_lock"; then
    echo "another sensor-loss capture owns the host lock: $capture_lock" >&2
    exit 75
fi
lock_held=1

parent_id=$(docker image inspect --format '{{.Id}}' "$parent" 2>/dev/null || :)
if [ "$parent_id" != "$parent" ]; then
    echo "missing exact local final combined v2 image: $parent" >&2
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

inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-sensor-loss-inspect.XXXXXX")
parent_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-sensor-loss-parent.XXXXXX")
child_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-sensor-loss-child.XXXXXX")
volume_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-sensor-loss-volume.XXXXXX")
harness=$(mktemp "${TMPDIR:-/tmp}/aragorn-sensor-loss-harness.XXXXXX")
commit_object=$(mktemp "${TMPDIR:-/tmp}/aragorn-sensor-loss-commit.XXXXXX")
commit_stdout=$(mktemp "${TMPDIR:-/tmp}/aragorn-sensor-loss-verify-out.XXXXXX")
commit_stderr=$(mktemp "${TMPDIR:-/tmp}/aragorn-sensor-loss-verify-err.XXXXXX")
iidfile=$(mktemp "${TMPDIR:-/tmp}/aragorn-sensor-loss-image-id.XXXXXX")
context=$(mktemp -d /tmp/aragorn-phase3-runtime-action-worker-sensor-loss-context.XXXXXX)
temp_output=$(mktemp "${output}.tmp.XXXXXX")

if ! GIT_NO_REPLACE_OBJECTS=1 git verify-commit --raw "$source_commit" \
    >"$commit_stdout" 2>"$commit_stderr"
then
    echo "sensor-loss source commit signature verification failed" >&2
    exit 66
fi
GIT_NO_REPLACE_OBJECTS=1 git cat-file commit "$source_commit" >"$commit_object"
GIT_NO_REPLACE_OBJECTS=1 git archive --format=tar "$source_commit" -- \
    benchmark/runtime-action-worker-sensor-loss-systemd/Dockerfile \
    packaging/activate-runtime-action-worker-host.sh \
    packaging/systemd/aragorn-agent-gateway.service \
    | tar -xf - -C "$context"

(
    cd "$context"
    docker build --pull=false --network=none \
        --iidfile "$iidfile" \
        -t "$image" \
        -f benchmark/runtime-action-worker-sensor-loss-systemd/Dockerfile \
        .
)
# Keep the networkless child context limited to its Dockerfile and two copied
# production files. The exact committed collector/verifier closure follows.
GIT_NO_REPLACE_OBJECTS=1 git archive --format=tar "$source_commit" -- \
    scripts/capture_runtime_action_worker_sensor_loss_systemd.sh \
    scripts/runtime_action_worker_sensor_loss_systemd_probe.py \
    src/aragorn \
    | tar -xf - -C "$context"
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
    echo "sensor-loss image did not extend the exact final combined v2 parent" >&2
    exit 69
fi

create_attempted=1
container_id=$(docker create --name "$container" --cidfile "$cidfile" --pull=never \
    --privileged --cgroupns=private --network=none \
    --security-opt label=disable \
    --label dev.aragorn.profile=phase3-runtime-action-worker-sensor-loss \
    --label "dev.aragorn.capture-owner=$owner_token" \
    --tmpfs /run:rw,nosuid,nodev,noexec,mode=755 \
    --tmpfs /run/lock:rw,nosuid,nodev,noexec,mode=755 \
    -v "$runtime_volume:/runtime:ro" \
    "$child_id")
docker start "$container_id" >/dev/null

i=0
while ! docker exec "$container_id" sh -c '
    test -S /run/systemd/private \
        && test "$(cat /proc/1/comm)" = systemd \
        && test "$(cat /proc/1/cgroup)" = "0::/init.scope"
'; do
    i=$((i + 1))
    if [ "$i" -ge 100 ]; then
        echo "private-cgroup systemd did not become ready" >&2
        exit 70
    fi
    sleep 0.1
done

docker exec "$container_id" install -d -o 0 -g 0 -m 0700 \
    /run/aragorn-sensor-loss-collector /observation
docker cp \
    "$context/benchmark/runtime-action-worker-sensor-loss-systemd/Dockerfile" \
    "$container_id:/run/aragorn-sensor-loss-collector/Dockerfile"
docker cp \
    "$context/scripts/capture_runtime_action_worker_sensor_loss_systemd.sh" \
    "$container_id:/run/aragorn-sensor-loss-collector/capture_runtime_action_worker_sensor_loss_systemd.sh"
docker cp \
    "$context/scripts/runtime_action_worker_sensor_loss_systemd_probe.py" \
    "$container_id:/run/aragorn-sensor-loss-collector/runtime_action_worker_sensor_loss_systemd_probe.py"
docker exec "$container_id" sh -eu -c '
    chown 0:0 \
        /run/aragorn-sensor-loss-collector/Dockerfile \
        /run/aragorn-sensor-loss-collector/capture_runtime_action_worker_sensor_loss_systemd.sh \
        /run/aragorn-sensor-loss-collector/runtime_action_worker_sensor_loss_systemd_probe.py
    chmod 0644 /run/aragorn-sensor-loss-collector/Dockerfile
    chmod 0755 \
        /run/aragorn-sensor-loss-collector/capture_runtime_action_worker_sensor_loss_systemd.sh \
        /run/aragorn-sensor-loss-collector/runtime_action_worker_sensor_loss_systemd_probe.py
'

docker inspect "$container_id" >"$inspect"
docker image inspect "$parent_id" >"$parent_inspect"
docker image inspect "$child_id" >"$child_inspect"
docker volume inspect "$runtime_volume" >"$volume_inspect"
python3.12 - \
    "$inspect" "$parent_inspect" "$child_inspect" "$volume_inspect" \
    "$harness" "$source_commit" "$commit_object" "$commit_stdout" \
    "$commit_stderr" \
    "$context/packaging/activate-runtime-action-worker-host.sh" \
    "$context/scripts/capture_runtime_action_worker_sensor_loss_systemd.sh" \
    "$context/benchmark/runtime-action-worker-sensor-loss-systemd/Dockerfile" \
    "$context/packaging/systemd/aragorn-agent-gateway.service" \
    "$context/scripts/runtime_action_worker_sensor_loss_systemd_probe.py" <<'PY'
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


container, parent, child, volume = map(one, sys.argv[1:5])
harness_path = Path(sys.argv[5])
commit = sys.argv[6]
parent_id = "sha256:21184b7a6a096a8625994b524203bf5b521d749b24e415378a69decd4e78009b"
runtime_volume = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
source_artifact_paths = {
    "activator": sys.argv[10],
    "capture_recipe": sys.argv[11],
    "dockerfile": sys.argv[12],
    "gateway_unit": sys.argv[13],
    "probe": sys.argv[14],
}
source_artifacts = {
    name: raw_record(path) for name, path in source_artifact_paths.items()
}
if (
    source_artifacts["activator"]["digest"]
    != "sha256:47d03e4600813cb32b536a267608f8d7eb97219c2421ba944426444693fee009"
    or source_artifacts["activator"]["bytes"] != 31_295
    or source_artifacts["gateway_unit"]["digest"]
    != "sha256:70a0aa0a89aae8bce8b7785b26d73d844c784e85be449363cb739835500de067"
    or source_artifacts["gateway_unit"]["bytes"] != 3_437
):
    raise SystemExit("current sensor-loss enforcement artifacts changed")

commit_object = raw_record(sys.argv[7])
commit_raw = base64.b64decode(commit_object["base64"], validate=True)
commit_identity = hashlib.sha1(
    f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
).hexdigest()
verification_stdout = raw_record(sys.argv[8])
verification_stderr = raw_record(sys.argv[9])
verification_stdout_raw = base64.b64decode(
    verification_stdout["base64"], validate=True
)
verification_stderr_raw = base64.b64decode(
    verification_stderr["base64"], validate=True
)
expected_signature = (
    b'Good "git" signature for yousif.snazhat@gmail.com with ED25519 key '
    b"SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk\n"
)
if (
    re.fullmatch(r"[0-9a-f]{40}", commit) is None
    or commit_identity != commit
    or not commit_raw.startswith(b"tree ")
    or b"\ngpgsig " not in commit_raw
    or verification_stdout_raw != b""
    or verification_stderr_raw != expected_signature
):
    raise SystemExit("signed sensor-loss source receipt changed")

parent_layers = parent["RootFS"]["Layers"]
child_layers = child["RootFS"]["Layers"]
if (
    parent["Id"] != parent_id
    or parent["RootFS"]["Type"] != "layers"
    or child["RootFS"]["Type"] != "layers"
    or len(child_layers) <= len(parent_layers)
    or child_layers[: len(parent_layers)] != parent_layers
):
    raise SystemExit("sensor-loss image is not an additive exact-parent child")
child_id = child["Id"]
if container["Image"] != child_id or container["Config"]["Image"] != child_id:
    raise SystemExit("sensor-loss container was not created from the child image ID")

mounts = [item for item in container["Mounts"] if item["Destination"] == "/runtime"]
if len(mounts) != 1 or len(container["Mounts"]) != 1:
    raise SystemExit("expected exactly one runtime mount")
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
expected_mount = {
    "destination": "/runtime",
    "driver": "local",
    "mode": "ro",
    "rw": False,
    "source": runtime_volume,
    "type": "volume",
}
expected_volume = {
    "driver": "local",
    "labels": {
        "io.aragorn.phase": "phase3-final",
        "io.aragorn.role": "installed-runtime",
        "io.aragorn.source-commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
        "io.aragorn.source-tree": "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44",
    },
    "name": runtime_volume,
    "options": None,
    "scope": "local",
}
if runtime_mount != expected_mount or volume_identity != expected_volume:
    raise SystemExit("exact final OpenClaw runtime volume identity changed")

host = container["HostConfig"]
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
    "binds": [f"{runtime_volume}:/runtime:ro"],
    "cgroupns_mode": "private",
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
labels = container["Config"].get("Labels") or {}
if (
    host_config != expected_host
    or container["Platform"] != "linux"
    or labels.get("dev.aragorn.profile")
    != "phase3-runtime-action-worker-sensor-loss"
    or re.fullmatch(
        re.escape(commit) + r":[1-9][0-9]*",
        labels.get("dev.aragorn.capture-owner", ""),
    )
    is None
):
    raise SystemExit("sensor-loss private-cgroup container profile changed")

bindings = {
    "source_commit": commit,
    "parent_image_id": parent_id,
    "child_image_id": child_id,
    "artifacts": {
        name: value["digest"] for name, value in source_artifacts.items()
    },
}
document = {
    "schema": "aragorn/runtime-action-worker-sensor-loss-systemd-harness/v1",
    "capture_disposition": "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE",
    "bindings": bindings,
    "container_id": container["Id"],
    "image_id": child_id,
    "image_reference": "aragorn-phase3-runtime-action-worker-sensor-loss-systemd",
    "run_image_reference": container["Config"]["Image"],
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
    "platform": container["Platform"],
    "profile_label": labels["dev.aragorn.profile"],
    "openclaw_runtime_volume": mount["Name"],
    "openclaw_runtime_volume_identity": volume_identity,
    "openclaw_runtime_mount": runtime_mount,
    "host_config": host_config,
    "source_commit_verification": {
        "command": ["git", "verify-commit", "--raw", commit],
        "exit_code": 0,
        "commit_object": commit_object,
        "stdout": verification_stdout,
        "stderr": verification_stderr,
    },
    "raw_records": {
        "container_inspect": raw_record(sys.argv[1]),
        "parent_image_inspect": raw_record(sys.argv[2]),
        "child_image_inspect": raw_record(sys.argv[3]),
        "runtime_volume_inspect": raw_record(sys.argv[4]),
    },
    "source_artifacts": source_artifacts,
}
harness_path.write_text(
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
probe_path=/run/aragorn-sensor-loss-collector/runtime_action_worker_sensor_loss_systemd_probe.py
observation_path=/observation/runtime-action-worker-sensor-loss-systemd.json
probe_status=0
docker exec "$container_id" /usr/local/bin/python3.12 -I -S -B \
    "$probe_path" --output "$observation_path" \
    || probe_status=$?
if [ "$probe_status" -ne 0 ]; then
    docker exec "$container_id" cat "$observation_path" >&2 || :
    exit "$probe_status"
fi
docker cp "$container_id:$observation_path" "$temp_output"
if ! remove_created_container; then
    echo "cannot remove and verify the privileged sensor-loss container" >&2
    exit 74
fi

python3.12 -I -S -B - \
    "$temp_output" "$output" "$context" "$source_commit" \
    "$parent_id" "$child_id" <<'PY'
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[3]) / "src"))

from aragorn.oci_worker_protocol import canonical_digest
from aragorn.runtime_action_worker_sensor_loss_systemd_evidence import (
    verify_runtime_action_worker_sensor_loss_systemd_evidence,
)


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
    false_claims = {
        "aggregate_gate_eligible",
        "edr_claim_eligible",
        "installer_authority_eligible",
        "phase3_exit_eligible",
        "public_release_eligible",
        "retained_evidence_eligible",
        "run_01_eligible",
        "run_02_eligible",
    }
    if (
        raw != canonical
        or set(document)
        != {
            "after",
            "artifacts",
            "authority",
            "before",
            "bindings",
            "checks",
            "decision",
            "harness",
            "limitations",
            "recorded_at",
            "schema",
            "secret_checks",
            "loss",
        }
        or document.get("schema")
        != "aragorn/runtime-action-worker-sensor-loss-systemd-observation/v1"
        or document.get("authority")
        != (
            "BOUNDED_LOCAL_SYSTEMD_SENSOR_PROCESS_LOSS_OBSERVATION_ONLY_"
            "NOT_RUN_02_PHASE3_EDR_OR_RELEASE_AUTHORITY"
        )
        or decision.get("status")
        != "SENSOR_PROCESS_LOSS_GATEWAY_FAIL_STOP_OBSERVED"
        or decision.get("verifier_status") != "NOT_TESTED"
        or {key for key in decision if key.endswith("_eligible")} != false_claims
        or any(decision[key] is not False for key in false_claims)
        or any(value is not True for value in document.get("checks", {}).values())
        or document.get("secret_checks") != {"gateway_token_retained": False}
    ):
        raise SystemExit("probe output is not exact observation-only material")

    artifact_paths = {
        "activator": (
            Path(sys.argv[3])
            / "packaging/activate-runtime-action-worker-host.sh"
        ),
        "capture_recipe": (
            Path(sys.argv[3])
            / "scripts/capture_runtime_action_worker_sensor_loss_systemd.sh"
        ),
        "dockerfile": (
            Path(sys.argv[3])
            / "benchmark/runtime-action-worker-sensor-loss-systemd/Dockerfile"
        ),
        "gateway_unit": (
            Path(sys.argv[3])
            / "packaging/systemd/aragorn-agent-gateway.service"
        ),
        "probe": (
            Path(sys.argv[3])
            / "scripts/runtime_action_worker_sensor_loss_systemd_probe.py"
        ),
    }
    expected_bindings = {
        "source_commit": sys.argv[4],
        "parent_image_id": sys.argv[5],
        "child_image_id": sys.argv[6],
        "artifacts": {
            name: "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in artifact_paths.items()
        },
    }
    verify_runtime_action_worker_sensor_loss_systemd_evidence(
        document,
        expected_digest=canonical_digest(document),
        expected_bindings=expected_bindings,
    )

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
