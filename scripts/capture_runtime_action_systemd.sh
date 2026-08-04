#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-$root/benchmark/evidence/runtime-action-systemd-composition-p3-3b-2026-08-04.json}
image=aragorn-p33b-systemd
container=aragorn-p33b-systemd-run

if [ "$#" -gt 1 ] || [ -e "$output" ]; then
    echo "usage: capture_runtime_action_systemd.sh [ABSENT_OUTPUT_PATH]" >&2
    exit 64
fi
if docker container inspect "$container" >/dev/null 2>&1; then
    echo "refusing to replace existing container: $container" >&2
    exit 73
fi

inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-3b-inspect.XXXXXX")
harness=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-3b-harness.XXXXXX")
cleanup() {
    rm -f "$inspect" "$harness"
    docker rm -f "$container" >/dev/null 2>&1 || :
}
trap cleanup EXIT HUP INT TERM

cd "$root"
docker build --pull=false -t "$image" \
    -f benchmark/runtime-action-systemd/Dockerfile .
docker run -d --name "$container" --pull=never \
    --privileged --cgroupns=host --network=none \
    --security-opt label=disable --label dev.aragorn.profile=p3.3b \
    --tmpfs /run:rw,nosuid,nodev,noexec,mode=755 \
    --tmpfs /run/lock:rw,nosuid,nodev,noexec,mode=755 \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    "$image" >/dev/null

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
python3.12 - "$inspect" "$harness" <<'PY'
import json
import sys
from pathlib import Path

source = json.loads(Path(sys.argv[1]).read_bytes())[0]
host = source["HostConfig"]
document = {
    "schema": "aragorn/runtime-action-systemd-harness/v1",
    "container_id": source["Id"],
    "image_id": source["Image"],
    "image_reference": source["Config"]["Image"],
    "platform": source["Platform"],
    "profile_label": source["Config"]["Labels"]["dev.aragorn.profile"],
    "host_config": {
        "binds": host["Binds"],
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
Path(sys.argv[2]).write_text(
    json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8"
)
PY

docker exec -i "$container" /bin/sh -c \
    'umask 077; cat > /run/aragorn-harness.json' <"$harness"
docker exec "$container" install -d -m 0700 /evidence
docker exec -i "$container" /usr/bin/python3.12 -I -S -B \
    /src/scripts/runtime_action_systemd_probe.py \
    --output /evidence/runtime-action-systemd-composition.json
docker cp \
    "${container}:/evidence/runtime-action-systemd-composition.json" \
    "$output"
chmod 0644 "$output"
shasum -a 256 "$output"
