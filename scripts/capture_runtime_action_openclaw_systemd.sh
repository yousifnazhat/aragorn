#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-$root/benchmark/evidence/runtime-action-openclaw-systemd-composition-p3-3c-2026-08-04.json}
base=aragorn-p33b-systemd
image=aragorn-p33c-openclaw-systemd
container=aragorn-p33c-openclaw-systemd-run
runtime_volume=aragorn-openclaw-2026-7-1-runtime
node_image=node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf

case "$output" in
    /*) ;;
    *) output=$PWD/$output ;;
esac
output_dir=$(CDPATH= cd -- "$(dirname -- "$output")" && pwd)
output=$output_dir/$(basename -- "$output")

if [ "$#" -gt 1 ] || [ -e "$output" ]; then
    echo "usage: capture_runtime_action_openclaw_systemd.sh [ABSENT_OUTPUT_PATH]" >&2
    exit 64
fi
if docker container inspect "$container" >/dev/null 2>&1; then
    echo "refusing to replace existing container: $container" >&2
    exit 73
fi
if ! docker volume inspect "$runtime_volume" >/dev/null 2>&1; then
    echo "missing pinned OpenClaw runtime volume: $runtime_volume" >&2
    exit 66
fi

inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-3c-inspect.XXXXXX")
base_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-3c-base.XXXXXX")
node_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-3c-node.XXXXXX")
harness=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-3c-harness.XXXXXX")
child_context=$(mktemp -d "${TMPDIR:-/tmp}/aragorn-p3-3c-context.XXXXXX")
temp_output=$(mktemp "${output}.tmp.XXXXXX")
created=0
container_id=
cleanup() {
    rm -f "$inspect" "$base_inspect" "$node_inspect" "$harness" "$temp_output"
    rm -rf "$child_context"
    if [ "$created" -eq 1 ]; then
        current_id=$(docker inspect --format '{{.Id}}' "$container" 2>/dev/null || :)
        if [ "$current_id" = "$container_id" ]; then
            docker rm -f "$container" >/dev/null 2>&1 || :
        fi
    fi
}
trap cleanup EXIT HUP INT TERM

cd "$root"
docker build --pull=false -t "$base" \
    -f benchmark/runtime-action-systemd/Dockerfile .
systemd_base=$(docker image inspect --format '{{.Id}}' "$base")
for source in \
    packaging/openclaw/aragorn-runtime-action/index.js \
    packaging/openclaw/aragorn-runtime-action/openclaw.plugin.json \
    packaging/openclaw/aragorn-runtime-action/package.json \
    scripts/runtime_action_openclaw_systemd_probe.py \
    scripts/capture_runtime_action_openclaw_systemd.sh \
    benchmark/runtime-action-openclaw-systemd/openclaw-probe.mjs \
    benchmark/runtime-action-openclaw-systemd/Dockerfile
do
    test -f "$source" && test ! -L "$source"
    mkdir -p "$child_context/$(dirname -- "$source")"
    cp "$source" "$child_context/$source"
done
cp .dockerignore "$child_context/root.dockerignore"
docker build --pull=false -t "$image" \
    --build-arg "SYSTEMD_BASE=$systemd_base" \
    -f "$child_context/benchmark/runtime-action-openclaw-systemd/Dockerfile" \
    "$child_context"
docker run -d --name "$container" --pull=never \
    --privileged --cgroupns=host --network=none \
    --security-opt label=disable --label dev.aragorn.profile=p3.3c \
    --tmpfs /run:rw,nosuid,nodev,noexec,mode=755 \
    --tmpfs /run/lock:rw,nosuid,nodev,noexec,mode=755 \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$runtime_volume:/runtime:ro" \
    "$image" >/dev/null
container_id=$(docker inspect --format '{{.Id}}' "$container")
created=1

i=0
while ! docker exec "$container" test -S /run/systemd/private; do
    i=$((i + 1))
    if [ "$i" -ge 100 ]; then
        echo "systemd did not become ready" >&2
        exit 70
    fi
    sleep 0.1
done

docker inspect "$container" >"$inspect"
docker image inspect "$systemd_base" >"$base_inspect"
docker image inspect "$node_image" >"$node_inspect"
python3.12 - "$inspect" "$base_inspect" "$node_inspect" "$harness" <<'PY'
import json
import sys
from pathlib import Path

source = json.loads(Path(sys.argv[1]).read_bytes())[0]
base = json.loads(Path(sys.argv[2]).read_bytes())[0]
node = json.loads(Path(sys.argv[3]).read_bytes())[0]
host = source["HostConfig"]
mounts = [item for item in source["Mounts"] if item["Destination"] == "/runtime"]
if len(mounts) != 1:
    raise SystemExit("expected exactly one /runtime mount")
mount = mounts[0]
document = {
    "schema": "aragorn/runtime-action-openclaw-systemd-harness/v1",
    "container_id": source["Id"],
    "image_id": source["Image"],
    "image_reference": source["Config"]["Image"],
    "systemd_base_image_id": base["Id"],
    "node_image": {
        "architecture": node["Architecture"],
        "id": node["Id"],
        "os": node["Os"],
        "reference": "node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf",
        "variant": node.get("Variant", ""),
    },
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
}
Path(sys.argv[4]).write_text(
    json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8"
)
PY

docker exec -i "$container" /bin/sh -c \
    'umask 077; cat > /run/aragorn-harness.json' <"$harness"
docker exec "$container" install -d -m 0700 /evidence
docker exec -i "$container" /usr/bin/python3.12 -I -S -B \
    /src/scripts/runtime_action_openclaw_systemd_probe.py \
    --output /evidence/runtime-action-openclaw-systemd-composition.json
docker cp \
    "$container:/evidence/runtime-action-openclaw-systemd-composition.json" \
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
expected = (
    json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    + b"\n"
)
if raw != expected:
    raise SystemExit("captured evidence is not canonical JSON")
descriptor = os.open(
    destination,
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0),
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
