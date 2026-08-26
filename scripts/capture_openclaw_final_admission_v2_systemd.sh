#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
v1_parent=sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c
runtime_volume=aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1
image=aragorn-openclaw-final-admission-v2-systemd
capture_lock=/tmp/aragorn-openclaw-final-admission-v2-capture.lock
umask 077

if [ "$#" -ne 1 ]; then
    echo "usage: capture_openclaw_final_admission_v2_systemd.sh ABSENT_OUTPUT_PATH" >&2
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
    echo "final admission v2 capture requires one clean signed source commit" >&2
    exit 66
fi
source_commit=$(GIT_NO_REPLACE_OBJECTS=1 git rev-parse --verify 'HEAD^{commit}')
source_tree=$(GIT_NO_REPLACE_OBJECTS=1 git rev-parse --verify 'HEAD^{tree}')
case "$source_commit:$source_tree" in
    *[!0-9a-f:]*) echo "invalid source identity" >&2; exit 66 ;;
esac
if [ "${#source_commit}" -ne 40 ] || [ "${#source_tree}" -ne 40 ]; then
    echo "invalid source identity" >&2
    exit 66
fi

container=aragorn-openclaw-final-admission-v2-$$
owner_token=$source_commit:$$
cidfile=$capture_lock/container.id
lock_held=0
create_attempted=0
container_id=
v2_id=
child_id=
context=
container_inspect=
v1_inspect=
v2_inspect=
child_inspect=
volume_inspect=
harness=
commit_object=
commit_stdout=
commit_stderr=
v2_iidfile=
child_iidfile=
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
                echo "refusing to remove an unowned final admission v2 container" >&2
                return 1
            fi
            docker rm -f "$removal_id" >/dev/null 2>&1 || :
        fi
    fi
    if ! docker info >/dev/null 2>&1; then
        echo "cannot verify final admission v2 container removal" >&2
        return 1
    fi
    if [ -n "$removal_id" ] \
        && docker container inspect "$removal_id" >/dev/null 2>&1
    then
        echo "final admission v2 container remained after removal" >&2
        return 1
    fi
    if docker container inspect "$container" >/dev/null 2>&1; then
        echo "final admission v2 container name was rebound before publication" >&2
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
        "$container_inspect" "$v1_inspect" "$v2_inspect" "$child_inspect" \
        "$volume_inspect" "$harness" "$commit_object" "$commit_stdout" \
        "$commit_stderr" "$v2_iidfile" "$child_iidfile" "$temp_output"
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
            /tmp/aragorn-openclaw-final-admission-v2-context.*)
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
    echo "another final admission v2 capture owns the host lock: $capture_lock" >&2
    exit 75
fi
lock_held=1

if [ "$(docker image inspect --format '{{.Id}}' "$v1_parent" 2>/dev/null || :)" != "$v1_parent" ]; then
    echo "missing exact local V1 final child image: $v1_parent" >&2
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

container_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-admission-v2-container.XXXXXX")
v1_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-admission-v2-v1.XXXXXX")
v2_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-admission-v2-v2.XXXXXX")
child_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-admission-v2-child.XXXXXX")
volume_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-admission-v2-volume.XXXXXX")
harness=$(mktemp "${TMPDIR:-/tmp}/aragorn-admission-v2-harness.XXXXXX")
commit_object=$(mktemp "${TMPDIR:-/tmp}/aragorn-admission-v2-commit.XXXXXX")
commit_stdout=$(mktemp "${TMPDIR:-/tmp}/aragorn-admission-v2-verify-out.XXXXXX")
commit_stderr=$(mktemp "${TMPDIR:-/tmp}/aragorn-admission-v2-verify-err.XXXXXX")
v2_iidfile=$(mktemp "${TMPDIR:-/tmp}/aragorn-admission-v2-base-iid.XXXXXX")
child_iidfile=$(mktemp "${TMPDIR:-/tmp}/aragorn-admission-v2-child-iid.XXXXXX")
context=$(mktemp -d /tmp/aragorn-openclaw-final-admission-v2-context.XXXXXX)
temp_output=$(mktemp "${output}.tmp.XXXXXX")

if ! GIT_NO_REPLACE_OBJECTS=1 git verify-commit --raw "$source_commit" \
    >"$commit_stdout" 2>"$commit_stderr"
then
    echo "final admission v2 source signature verification failed" >&2
    exit 66
fi
GIT_NO_REPLACE_OBJECTS=1 git cat-file commit "$source_commit" >"$commit_object"
GIT_NO_REPLACE_OBJECTS=1 git archive --format=tar "$source_commit" -- \
    benchmark/admission/openclaw-v2026.7.1 \
    benchmark/fixtures/phase1-protected-workshop/PROPOSAL.md \
    benchmark/runtime-action-worker-final-combined-v2-systemd \
    packaging/activate-runtime-action-worker-host.sh \
    src/aragorn/runtime_action_worker.py \
    scripts/capture_openclaw_final_admission_v2_systemd.sh \
    scripts/capture_runtime_action_worker_final_combined_v2_systemd.sh \
    scripts/materialize_fixed_admission_probes.py \
    scripts/openclaw_final_admission_v2_systemd_probe.py \
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
    --final-combined-v2 "$context/route-input/curator-restore-activation" \
    protected-curator-restore-denial-probe.mjs protected-observation-v1.mjs
python3.12 "$context/scripts/materialize_fixed_admission_probes.py" \
    --final-combined-v2 "$context/route-input/fresh-session-reset" \
    protected-route-probe.mjs
python3.12 "$context/scripts/materialize_fixed_admission_probes.py" \
    --final-combined-v2 "$context/route-input/missing-prompt-blob-rebuild" \
    protected-observation-v1.mjs protected-prompt-rebuild-probe.mjs
python3.12 "$context/scripts/materialize_fixed_admission_probes.py" \
    --final-combined-v2 "$context/route-input/session-snapshot-consumer" \
    protected-observation-v1.mjs protected-session-snapshot-fixed-probe.mjs
python3.12 "$context/scripts/materialize_fixed_admission_probes.py" \
    --final-combined-v2 "$context/route-input/workshop-proposal-apply" \
    PROPOSAL.md protected-route-probe.mjs

(
    cd "$context"
    docker build --pull=false --network=none \
        --iidfile "$v2_iidfile" \
        --build-arg "V1_FINAL_BASE=$v1_parent" \
        -f benchmark/runtime-action-worker-final-combined-v2-systemd/Dockerfile \
        .
)
v2_id=$(tr -d '\n' <"$v2_iidfile")
v2_hex=${v2_id#sha256:}
case "$v2_id" in
    sha256:????????????????????????????????????????????????????????????????) ;;
    *) echo "Docker did not return one immutable V2 base image ID" >&2; exit 69 ;;
esac
case "$v2_hex" in
    *[!0-9a-f]*) echo "Docker returned an invalid V2 base image ID" >&2; exit 69 ;;
esac

python3.12 - "$context/Dockerfile.admission-v2" <<'PY'
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
raw = b"""ARG V2_BASE
FROM ${V2_BASE}
COPY benchmark/admission/openclaw-v2026.7.1/ /src/benchmark/admission/openclaw-v2026.7.1/
COPY scripts/capture_openclaw_final_admission_v2_systemd.sh scripts/openclaw_final_admission_v2_systemd_probe.py /src/scripts/
RUN find /src/benchmark/admission/openclaw-v2026.7.1 -type f -exec chmod 0444 {} + && chmod 0555 /src/scripts/capture_openclaw_final_admission_v2_systemd.sh /src/scripts/openclaw_final_admission_v2_systemd_probe.py
"""
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(descriptor, raw)
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
(
    cd "$context"
    docker build --pull=false --network=none \
        --iidfile "$child_iidfile" \
        --build-arg "V2_BASE=$v2_id" \
        -t "$image" \
        -f Dockerfile.admission-v2 \
        .
)
child_id=$(tr -d '\n' <"$child_iidfile")
child_hex=${child_id#sha256:}
case "$child_id" in
    sha256:????????????????????????????????????????????????????????????????) ;;
    *) echo "Docker did not return one immutable admission image ID" >&2; exit 69 ;;
esac
case "$child_hex" in
    *[!0-9a-f]*) echo "Docker returned an invalid admission image ID" >&2; exit 69 ;;
esac
if [ "$child_id" = "$v2_id" ] \
    || [ "$(docker image inspect --format '{{.Id}}' "$child_id")" != "$child_id" ]
then
    echo "final admission image did not extend the exact V2 base" >&2
    exit 69
fi

create_attempted=1
container_id=$(docker create --name "$container" --cidfile "$cidfile" --pull=never \
    --network=none --cap-drop=ALL --security-opt no-new-privileges:true \
    --security-opt label=disable \
    --label dev.aragorn.profile=openclaw-final-admission-v2 \
    --label "dev.aragorn.capture-owner=$owner_token" \
    --tmpfs /run:rw,nosuid,nodev,noexec,mode=755 \
    -v "$runtime_volume:/runtime:ro" \
    "$child_id" /bin/sh -c 'while :; do sleep 3600; done')
docker start "$container_id" >/dev/null

docker inspect "$container_id" >"$container_inspect"
docker image inspect "$v1_parent" >"$v1_inspect"
docker image inspect "$v2_id" >"$v2_inspect"
docker image inspect "$child_id" >"$child_inspect"
docker volume inspect "$runtime_volume" >"$volume_inspect"
python3.12 - \
    "$container_inspect" "$v1_inspect" "$v2_inspect" "$child_inspect" \
    "$volume_inspect" "$harness" "$source_commit" "$source_tree" \
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


container, v1, v2, child, volume = map(one, sys.argv[1:6])
commit, tree = sys.argv[7:9]
commit_object = raw_record(sys.argv[9])
commit_raw = base64.b64decode(commit_object["base64"], validate=True)
commit_identity = hashlib.sha1(
    f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
).hexdigest()
verify_stdout = raw_record(sys.argv[10])
verify_stderr = raw_record(sys.argv[11])
v1_id = "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
runtime_volume = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
if (
    v1["Id"] != v1_id
    or re.fullmatch(r"[0-9a-f]{40}", commit) is None
    or re.fullmatch(r"[0-9a-f]{40}", tree) is None
    or commit_identity != commit
    or not commit_raw.startswith(f"tree {tree}\n".encode("ascii"))
    or b"\ngpgsig " not in commit_raw
    or verify_stdout["bytes"] + verify_stderr["bytes"] == 0
):
    raise SystemExit("signed source identity changed")

v1_layers = v1["RootFS"]["Layers"]
v2_layers = v2["RootFS"]["Layers"]
child_layers = child["RootFS"]["Layers"]
if (
    v1["RootFS"]["Type"] != v2["RootFS"]["Type"]
    or v2["RootFS"]["Type"] != child["RootFS"]["Type"]
    or v2_layers[: len(v1_layers)] != v1_layers
    or child_layers[: len(v2_layers)] != v2_layers
    or len(v2_layers) <= len(v1_layers)
    or len(child_layers) <= len(v2_layers)
    or container["Image"] != child["Id"]
    or container["Config"]["Image"] != child["Id"]
):
    raise SystemExit("admission image lineage changed")

mounts = [item for item in container["Mounts"] if item["Destination"] == "/runtime"]
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
        "io.aragorn.source-commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
        "io.aragorn.source-tree": "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44",
    },
    "name": runtime_volume,
    "options": None,
    "scope": "local",
}
host = container["HostConfig"]
host_profile = {
    "cap_drop": host.get("CapDrop"),
    "network_mode": host["NetworkMode"],
    "privileged": host["Privileged"],
    "readonly_rootfs": host["ReadonlyRootfs"],
    "security_opt": sorted(host["SecurityOpt"]),
    "tmpfs": host["Tmpfs"],
}
expected_host = {
    "cap_drop": ["ALL"],
    "network_mode": "none",
    "privileged": False,
    "readonly_rootfs": False,
    "security_opt": sorted(["label=disable", "no-new-privileges:true"]),
    "tmpfs": {"/run": "rw,nosuid,nodev,noexec,mode=755"},
}
if (
    runtime_mount != expected_mount
    or volume_identity != expected_volume
    or host_profile != expected_host
    or container["Platform"] != "linux"
    or container["Config"]["Labels"].get("dev.aragorn.profile")
    != "openclaw-final-admission-v2"
):
    raise SystemExit("final admission container profile changed")

document = {
    "schema": "aragorn/openclaw-final-admission-v2-systemd-harness/v1",
    "capture_disposition": "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE",
    "source": {
        "commit": commit,
        "tree": tree,
        "verification": {
            "command": ["git", "verify-commit", "--raw", commit],
            "exit_code": 0,
            "commit_object": commit_object,
            "stdout": verify_stdout,
            "stderr": verify_stderr,
        },
    },
    "container": {
        "id": container["Id"],
        "image_id": child["Id"],
        "image_reference": "aragorn-openclaw-final-admission-v2-systemd",
        "platform": container["Platform"],
        "profile_label": container["Config"]["Labels"]["dev.aragorn.profile"],
        "host_profile": host_profile,
    },
    "image_lineage": {
        "v1": {"id": v1_id, "layers": v1_layers},
        "v2": {"id": v2["Id"], "layers": v2_layers},
        "admission": {"id": child["Id"], "layers": child_layers},
        "v2_added_layers": v2_layers[len(v1_layers) :],
        "admission_added_layers": child_layers[len(v2_layers) :],
    },
    "runtime_volume": {
        "identity": volume_identity,
        "mount": runtime_mount,
    },
}
Path(sys.argv[6]).write_text(
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
    'umask 077; cat > /run/aragorn-final-admission-v2-harness.json' <"$harness"
docker exec "$container_id" install -d -m 0700 /evidence
probe_status=0
docker exec "$container_id" /usr/local/bin/python3.12 -I -S -B \
    /src/scripts/openclaw_final_admission_v2_systemd_probe.py \
    || probe_status=$?
if [ "$probe_status" -ne 0 ]; then
    docker exec "$container_id" \
        cat /evidence/openclaw-final-admission-v2-systemd.json >&2 || :
    exit "$probe_status"
fi
docker cp \
    "$container_id:/evidence/openclaw-final-admission-v2-systemd.json" \
    "$temp_output"
if ! remove_created_container; then
    echo "cannot remove and verify the final admission v2 container" >&2
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
    raise SystemExit("temporary and final paths are not co-located")
directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
source_descriptor = os.open(
    source.name,
    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    dir_fd=directory,
)
try:
    source_before = os.fstat(source_descriptor)
    if not stat.S_ISREG(source_before.st_mode) or source_before.st_nlink != 1:
        raise SystemExit("captured output is not one regular temporary file")
    chunks = []
    while chunk := os.read(source_descriptor, 1024 * 1024):
        chunks.append(chunk)
    raw = b"".join(chunks)
    source_after = os.fstat(source_descriptor)
    if (
        (source_after.st_dev, source_after.st_ino)
        != (source_before.st_dev, source_before.st_ino)
        or source_after.st_size != len(raw)
    ):
        raise SystemExit("captured output changed while reading")
finally:
    os.close(source_descriptor)
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
expected_decision = {
    "status": "NOT_TESTED",
    "semantic_pass_verified": False,
    "property_not_tested_count": 2,
    "formal_category_not_tested_count": 8,
    "route_observed_count": 0,
    "route_fail_count": 0,
    "route_not_tested_count": 21,
    "adm03_not_tested_count": 2,
    "admission_profile_eligible": False,
    "aggregate_admission_eligible": False,
    "edr_eligible": False,
    "installer_work_eligible": False,
    "phase3_exit_eligible": False,
    "release_eligible": False,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "run_eligible": False,
}
if (
    raw != canonical
    or document.get("schema")
    != "aragorn/openclaw-final-admission-v2-systemd-capture/v1"
    or document.get("authority")
    != (
        "BOUND_V2_ADMISSION_RAW_OBSERVATION_AGGREGATION_ONLY_"
        "SEMANTIC_CONFORMANCE_NOT_VERIFIED_NO_INSTALLER_RUN_PHASE3_EDR_"
        "RELEASE_AUTHORITY"
    )
    or decision != expected_decision
):
    raise SystemExit("final admission v2 output is not conservative canonical material")

flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
descriptor = os.open(destination.name, flags, 0o644, dir_fd=directory)
created = os.fstat(descriptor)
published_identity = (created.st_dev, created.st_ino)
try:
    view = memoryview(raw)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short output write")
        view = view[written:]
    os.fchmod(descriptor, 0o644)
    os.fsync(descriptor)
    published = os.fstat(descriptor)
    linked = os.stat(destination.name, dir_fd=directory, follow_symlinks=False)
    if (
        not stat.S_ISREG(published.st_mode)
        or published.st_nlink != 1
        or stat.S_IMODE(published.st_mode) != 0o644
        or published.st_size != len(raw)
        or (linked.st_dev, linked.st_ino) != published_identity
    ):
        raise OSError("published output metadata changed")
    os.fsync(directory)
except BaseException:
    os.close(descriptor)
    try:
        linked = os.stat(destination.name, dir_fd=directory, follow_symlinks=False)
        if (linked.st_dev, linked.st_ino) == published_identity:
            os.unlink(destination.name, dir_fd=directory)
            os.fsync(directory)
    except FileNotFoundError:
        pass
    os.close(directory)
    raise
else:
    os.close(descriptor)
    os.close(directory)
PY
shasum -a 256 "$output"
