#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-$root/benchmark/evidence/runtime-process-profile-systemd-composition-p3-4a-2026-08-05.json}
base=aragorn-p33b-systemd
expected_base=sha256:1a4fe98562882fca13e0349f84d9eb4c38b5361a1289da2a0bfa8852ccfdbc56
image=aragorn-p34a-runtime-profile-systemd
container=aragorn-p34a-runtime-profile-systemd-run

if [ "$#" -gt 1 ] || [ -e "$output" ]; then
    echo "usage: capture_runtime_process_profile_systemd.sh [ABSENT_OUTPUT_PATH]" >&2
    exit 64
fi
if docker container inspect "$container" >/dev/null 2>&1; then
    echo "refusing to replace existing container: $container" >&2
    exit 73
fi

inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-4a-inspect.XXXXXX")
base_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-4a-base.XXXXXX")
harness=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-4a-harness.XXXXXX")
cleanup() {
    rm -f "$inspect" "$base_inspect" "$harness"
    docker rm -f "$container" >/dev/null 2>&1 || :
}
trap cleanup EXIT HUP INT TERM

cd "$root"
base_id=$(docker image inspect --format '{{.Id}}' "$base")
if [ "$base_id" != "$expected_base" ]; then
    echo "P3.3b base image does not match the retained image ID" >&2
    exit 69
fi
# P3.3 evidence freezes .dockerignore, so admit the additive slice explicitly.
COPYFILE_DISABLE=1 tar --no-xattrs -cf - \
    benchmark/runtime-process-profile-systemd \
    packaging/install-runtime-profile-host.sh \
    packaging/libexec/aragorn-runtime-action-service-v2.py \
    packaging/libexec/aragorn-runtime-observation-service-v2.py \
    packaging/systemd/aragorn-runtime-profile-action-broker.service \
    packaging/systemd/aragorn-runtime-profile-observation-publisher.service \
    scripts/capture_runtime_process_profile_systemd.sh \
    scripts/runtime_process_profile_systemd_probe.py \
    src/aragorn/runtime_action_broker_v2.py \
    src/aragorn/runtime_action_observation_publisher_v2.py \
    src/aragorn/runtime_action_service_v2.py \
    src/aragorn/runtime_observation_service_v2.py \
    src/aragorn/runtime_process_profile.py \
    | docker build --pull=false \
        --build-arg "SYSTEMD_BASE=$base_id" \
        -t "$image" \
        -f benchmark/runtime-process-profile-systemd/Dockerfile -

docker run -d --name "$container" --pull=never \
    --privileged --cgroupns=host --network=none \
    --security-opt label=disable --label dev.aragorn.profile=p3.4a \
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
docker image inspect "$base_id" >"$base_inspect"
python3.12 - "$inspect" "$base_inspect" "$harness" <<'PY'
import json
import sys
from pathlib import Path

source = json.loads(Path(sys.argv[1]).read_bytes())[0]
base = json.loads(Path(sys.argv[2]).read_bytes())[0]
host = source["HostConfig"]
document = {
    "schema": "aragorn/runtime-process-profile-systemd-harness/v1",
    "container_id": source["Id"],
    "image_id": source["Image"],
    "image_reference": source["Config"]["Image"],
    "systemd_base_image_id": base["Id"],
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
Path(sys.argv[3]).write_text(
    json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8"
)
PY

docker exec -i "$container" /bin/sh -c \
    'umask 077; cat > /run/aragorn-harness.json' <"$harness"
docker exec "$container" install -d -m 0700 /evidence
docker exec "$container" /usr/bin/python3.12 -I -S -B \
    /src/scripts/runtime_process_profile_systemd_probe.py \
    --output /evidence/runtime-process-profile-systemd-composition.json
docker cp \
    "${container}:/evidence/runtime-process-profile-systemd-composition.json" \
    "$output"
chmod 0644 "$output"
shasum -a 256 "$output"
