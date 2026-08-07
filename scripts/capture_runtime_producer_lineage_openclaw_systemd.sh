#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-$root/benchmark/evidence/runtime-producer-lineage-openclaw-systemd-composition-p3-6b-2026-08-07.json}
base=aragorn-p36a-runtime-active-lineage-openclaw-systemd
expected_base=sha256:5059135af5a9b0799be878814abe293f921fd55ea680bc2298330aff56198972
image=aragorn-p36b-runtime-producer-lineage-openclaw-systemd
container=aragorn-p36b-runtime-producer-lineage-openclaw-systemd-run
runtime_volume=aragorn-openclaw-2026-7-1-runtime

if [ "$#" -gt 1 ]; then
    echo "usage: capture_runtime_producer_lineage_openclaw_systemd.sh [ABSENT_OUTPUT_PATH]" >&2
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

base_id=$(docker image inspect --format '{{.Id}}' "$base" 2>/dev/null || :)
if [ "$base_id" != "$expected_base" ]; then
    echo "missing exact retained P3.6a image: $expected_base" >&2
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

inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-6b-inspect.XXXXXX")
parent_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-6b-parent.XXXXXX")
child_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-6b-child.XXXXXX")
volume_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-6b-volume.XXXXXX")
harness=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-6b-harness.XXXXXX")
context=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-6b-context.XXXXXX")
temp_output=$(mktemp "${output}.tmp.XXXXXX")
created=0
container_id=
cleanup() {
    rm -f \
        "$inspect" "$parent_inspect" "$child_inspect" \
        "$volume_inspect" "$harness" "$context" "$temp_output"
    if [ "$created" -eq 1 ]; then
        current_id=$(docker container inspect --format '{{.Id}}' "$container" 2>/dev/null || :)
        if [ "$current_id" = "$container_id" ]; then
            docker rm -f "$container" >/dev/null 2>&1 || :
        fi
    fi
}
trap cleanup EXIT HUP INT TERM

cd "$root"
for source in \
    benchmark/admission/openclaw-v2026.7.1/protected-install-broker-recursive-v3.py \
    benchmark/evidence/phase1-protected-recursive-v4-live-0307946e55d9-2026-07-29.tar.xz \
    benchmark/evidence/runtime-active-lineage-openclaw-systemd-composition-p3-6a-2026-08-07.json \
    benchmark/runtime-producer-lineage-openclaw-systemd \
    packaging/libexec/aragorn-protected-install-launcher.py \
    packaging/systemd/aragorn-protected-install.service \
    scripts/capture_runtime_producer_lineage_openclaw_systemd.sh \
    scripts/runtime_producer_lineage_openclaw_systemd_probe.py \
    src/aragorn/github_quarantine_receipt.py \
    src/aragorn/protected_install.py
do
    test -e "$source" && test ! -L "$source"
done
COPYFILE_DISABLE=1 tar --no-xattrs -cf "$context" \
    benchmark/admission/openclaw-v2026.7.1/protected-install-broker-recursive-v3.py \
    benchmark/evidence/phase1-protected-recursive-v4-live-0307946e55d9-2026-07-29.tar.xz \
    benchmark/evidence/runtime-active-lineage-openclaw-systemd-composition-p3-6a-2026-08-07.json \
    benchmark/runtime-producer-lineage-openclaw-systemd \
    packaging/libexec/aragorn-protected-install-launcher.py \
    packaging/systemd/aragorn-protected-install.service \
    scripts/capture_runtime_producer_lineage_openclaw_systemd.sh \
    scripts/runtime_producer_lineage_openclaw_systemd_probe.py \
    src/aragorn/github_quarantine_receipt.py \
    src/aragorn/protected_install.py
docker build --pull=false --network=none \
    --build-arg "LINEAGE_BASE=$base_id" \
    -t "$image" \
    -f benchmark/runtime-producer-lineage-openclaw-systemd/Dockerfile \
    - <"$context"
child_id=$(docker image inspect --format '{{.Id}}' "$image")
if [ "$child_id" = "$base_id" ]; then
    echo "P3.6b image did not extend the exact P3.6a parent" >&2
    exit 69
fi

container_id=$(docker create --name "$container" --pull=never \
    --privileged --cgroupns=host --network=none \
    --security-opt label=disable --label dev.aragorn.profile=p3.6b \
    --tmpfs /run:rw,nosuid,nodev,noexec,mode=755 \
    --tmpfs /run/lock:rw,nosuid,nodev,noexec,mode=755 \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$runtime_volume:/runtime:ro" \
    "$child_id")
created=1
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
docker image inspect "$base_id" >"$parent_inspect"
docker image inspect "$child_id" >"$child_inspect"
docker volume inspect "$runtime_volume" >"$volume_inspect"
python3.12 - \
    "$inspect" "$parent_inspect" "$child_inspect" \
    "$volume_inspect" "$harness" <<'PY'
import json
import sys
from pathlib import Path


def one(path: str) -> dict:
    value = json.loads(Path(path).read_bytes())
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise SystemExit(f"expected one inspect object: {path}")
    return value[0]


source, parent, child, volume = map(one, sys.argv[1:5])
parent_id = "sha256:5059135af5a9b0799be878814abe293f921fd55ea680bc2298330aff56198972"
child_id = child["Id"]
if parent["Id"] != parent_id:
    raise SystemExit("P3.6a parent identity drifted")
parent_layers = parent["RootFS"]["Layers"]
child_layers = child["RootFS"]["Layers"]
if (
    parent["RootFS"]["Type"] != "layers"
    or child["RootFS"]["Type"] != "layers"
    or len(child_layers) <= len(parent_layers)
    or child_layers[: len(parent_layers)] != parent_layers
):
    raise SystemExit("P3.6b child is not an additive P3.6a layer")
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
    raise SystemExit("P3.6b outer host profile drifted")
if source["Platform"] != "linux":
    raise SystemExit("P3.6b container platform changed")
if source["Config"]["Labels"].get("dev.aragorn.profile") != "p3.6b":
    raise SystemExit("P3.6b container label changed")
document = {
    "schema": "aragorn/runtime-producer-lineage-openclaw-systemd-harness/v1",
    "container_id": source["Id"],
    "image_id": child_id,
    "image_reference": "aragorn-p36b-runtime-producer-lineage-openclaw-systemd",
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
docker exec "$container_id" install -d -m 0700 /evidence
probe_status=0
docker exec "$container_id" /usr/local/bin/python3.12 -I -S -B \
    /src/scripts/runtime_producer_lineage_openclaw_systemd_probe.py \
    --output /evidence/runtime-producer-lineage-openclaw-systemd.json \
    || probe_status=$?
case "$probe_status" in
    0|2) ;;
    *) exit "$probe_status" ;;
esac
docker cp \
    "$container_id:/evidence/runtime-producer-lineage-openclaw-systemd.json" \
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
if [ "$probe_status" -eq 2 ]; then
    exit 2
fi
