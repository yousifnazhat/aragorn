#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-$root/benchmark/evidence/runtime-action-openclaw-live-revocation-p3-3d-2026-08-05.json}
base=aragorn-p33c-openclaw-systemd
expected_base=sha256:7e2f3812883d952c931abb30f2ed7dc1d0c0e89cc4ef43c1bdf683d5f9323e1c
image=aragorn-p33d-openclaw-systemd
container=aragorn-p33d-openclaw-systemd-run
runtime_volume=aragorn-openclaw-2026-7-1-runtime
baseline=$root/benchmark/evidence/runtime-action-openclaw-systemd-composition-p3-3c-2026-08-04.json

case "$output" in
    /*) ;;
    *) output=$PWD/$output ;;
esac
output_dir=$(CDPATH= cd -- "$(dirname -- "$output")" && pwd)
output=$output_dir/$(basename -- "$output")

if [ "$#" -gt 1 ] || [ -e "$output" ]; then
    echo "usage: capture_runtime_action_openclaw_revocation.sh [ABSENT_OUTPUT_PATH]" >&2
    exit 64
fi
base_id=$(docker image inspect --format '{{.Id}}' "$base" 2>/dev/null || :)
if [ "$base_id" != "$expected_base" ]; then
    echo "missing exact retained P3.3c image: $expected_base" >&2
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

inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-3d-inspect.XXXXXX")
parent_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-3d-parent.XXXXXX")
child_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-3d-child.XXXXXX")
harness=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-3d-harness.XXXXXX")
context=$(mktemp -d "${TMPDIR:-/tmp}/aragorn-p3-3d-context.XXXXXX")
temp_output=$(mktemp "${output}.tmp.XXXXXX")
created=0
container_id=
cleanup() {
    rm -f "$inspect" "$parent_inspect" "$child_inspect" "$harness" "$temp_output"
    rm -rf "$context"
    if [ "$created" -eq 1 ]; then
        docker rm -f "$container_id" >/dev/null 2>&1 || :
    fi
}
trap cleanup EXIT HUP INT TERM

cd "$root"
for source in \
    scripts/runtime_action_openclaw_revocation_probe.py \
    scripts/capture_runtime_action_openclaw_revocation.sh \
    benchmark/runtime-action-openclaw-revocation/Dockerfile
do
    test -f "$source" && test ! -L "$source"
    mkdir -p "$context/$(dirname -- "$source")"
    cp "$source" "$context/$source"
done
docker build --pull=false --network=none -t "$image" \
    --build-arg "OPENCLAW_BASE=$base_id" \
    -f "$context/benchmark/runtime-action-openclaw-revocation/Dockerfile" \
    "$context"
child_id=$(docker image inspect --format '{{.Id}}' "$image")
test "$child_id" != "$base_id"

container_id=$(docker run -d --name "$container" --pull=never \
    --privileged --cgroupns=host --network=none \
    --security-opt label=disable --label dev.aragorn.profile=p3.3d \
    --tmpfs /run:rw,nosuid,nodev,noexec,mode=755 \
    --tmpfs /run/lock:rw,nosuid,nodev,noexec,mode=755 \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$runtime_volume:/runtime:ro" \
    "$child_id")
created=1

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
docker image inspect "$base_id" >"$parent_inspect"
docker image inspect "$child_id" >"$child_inspect"
python3.12 - \
    "$inspect" "$parent_inspect" "$child_inspect" "$baseline" "$harness" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

source = json.loads(Path(sys.argv[1]).read_bytes())[0]
parent = json.loads(Path(sys.argv[2]).read_bytes())[0]
child = json.loads(Path(sys.argv[3]).read_bytes())[0]
baseline_path = Path(sys.argv[4])
raw = baseline_path.read_bytes()
baseline = json.loads(raw)
canonical = json.dumps(
    baseline, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
).encode("ascii")
raw_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
canonical_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
if raw_digest != "sha256:023103ddc4189da4275e4123b720e9f600d514f17734a62f1b2130e54b30488e":
    raise SystemExit("retained P3.3c evidence bytes changed")
if canonical_digest != "sha256:5ac0a675ac9e123eca28069693a9de118cff13745cc46e16f18d4c6980deb78f":
    raise SystemExit("retained P3.3c canonical evidence changed")
parent_id, child_id = parent["Id"], child["Id"]
if source["Image"] != child_id or source["Config"]["Image"] != child_id:
    raise SystemExit("container was not started by captured child image ID")
parent_layers = parent["RootFS"]["Layers"]
child_layers = child["RootFS"]["Layers"]
if (
    parent_id != "sha256:7e2f3812883d952c931abb30f2ed7dc1d0c0e89cc4ef43c1bdf683d5f9323e1c"
    or parent["RootFS"]["Type"] != "layers"
    or child["RootFS"]["Type"] != "layers"
    or len(child_layers) <= len(parent_layers)
    or child_layers[: len(parent_layers)] != parent_layers
):
    raise SystemExit("child image does not extend the exact retained P3.3c layers")
host = source["HostConfig"]
mounts = [item for item in source["Mounts"] if item["Destination"] == "/runtime"]
if len(mounts) != 1:
    raise SystemExit("expected exactly one /runtime mount")
mount = mounts[0]
retained_harness = baseline["harness"]["document"]
document = {
    "schema": "aragorn/runtime-action-openclaw-revocation-harness/v1",
    "container_id": source["Id"],
    "image_id": source["Image"],
    "image_reference": "aragorn-p33d-openclaw-systemd",
    "run_image_reference": source["Config"]["Image"],
    "parent_image_id": parent_id,
    "image_lineage": {
        "parent": {"id": parent_id, "rootfs_type": "layers", "layers": parent_layers},
        "child": {"id": child_id, "rootfs_type": "layers", "layers": child_layers},
        "added_layers": child_layers[len(parent_layers) :],
    },
    "systemd_base_image_id": retained_harness["systemd_base_image_id"],
    "node_image": retained_harness["node_image"],
    "platform": source["Platform"],
    "profile_label": source["Config"]["Labels"]["dev.aragorn.profile"],
    "openclaw_runtime_volume": mount["Name"],
    "openclaw_runtime_mount": {
        "destination": mount["Destination"],
        "driver": mount["Driver"],
        "mode": mount["Mode"],
        "rw": mount["RW"],
        "source": mount["Name"],
        "type": mount["Type"],
    },
    "host_config": {
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
    },
    "retained_p3c": {
        "path": "benchmark/evidence/runtime-action-openclaw-systemd-composition-p3-3c-2026-08-04.json",
        "raw_digest": raw_digest,
        "canonical_digest": canonical_digest,
        "image_id": retained_harness["image_id"],
    },
}
Path(sys.argv[5]).write_text(
    json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8"
)
PY

docker exec -i "$container_id" /bin/sh -c \
    'umask 077; cat > /run/aragorn-harness.json' <"$harness"
docker exec "$container_id" install -d -m 0700 /evidence
docker exec "$container_id" /usr/bin/python3.12 -I -S -B \
    /src/scripts/runtime_action_openclaw_revocation_probe.py \
    --output /evidence/runtime-action-openclaw-live-revocation.json
docker cp \
    "$container_id:/evidence/runtime-action-openclaw-live-revocation.json" \
    "$temp_output"
python3.12 - "$temp_output" "$output" <<'PY'
import json
import os
import sys
from pathlib import Path

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
raw = source.read_bytes()
document = json.loads(
    raw,
    parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
    parse_float=lambda value: (_ for _ in ()).throw(ValueError(value)),
)
expected = json.dumps(
    document, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
).encode("ascii") + b"\n"
if raw != expected:
    raise SystemExit("captured evidence is not canonical JSON")
descriptor = os.open(
    destination,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
    0o644,
)
try:
    remaining = memoryview(raw)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("evidence publication made no progress")
        remaining = remaining[written:]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
source.unlink()
PY
shasum -a 256 "$output"
