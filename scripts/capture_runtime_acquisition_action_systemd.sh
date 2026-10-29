#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
parent=sha256:3c8321a7118684b8358876179406da6f12fb814dcfc3a1731a923c8bb5b3fe07
image=aragorn-p38b-runtime-acquisition-action-systemd
runtime_volume=aragorn-openclaw-2026-7-1-runtime
capture_lock=/tmp/aragorn-p38b-runtime-acquisition-action-capture.lock
umask 077

if [ "$#" -ne 1 ]; then
    echo "usage: capture_runtime_acquisition_action_systemd.sh ABSENT_OUTPUT_PATH" >&2
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
    echo "P3.8b capture requires one clean signed source commit" >&2
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

container=aragorn-p38b-runtime-acquisition-action-$$
network=aragorn-p38b-acquisition-$$
owner_token=$source_commit_hex:$$
cidfile=$capture_lock/container.id
lock_held=0
inspect=
parent_inspect=
child_inspect=
volume_inspect=
network_inspect=
disconnected_inspect=
disconnected_network_inspect=
acquisition_marker=
harness=
context=
commit_stdout=
commit_stderr=
commit_object=
iidfile=
probe_stdout=
probe_stderr=
temp_output=
child_id=
container_id=
network_id=
create_attempted=0
network_create_attempted=0
probe_pid=
probe_waited=0

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
                echo "refusing to remove an unowned P3.8b container" >&2
                return 1
            fi
            docker rm -f "$removal_id" >/dev/null 2>&1 || :
        fi
    fi

    if ! docker info >/dev/null 2>&1; then
        echo "cannot verify P3.8b container removal" >&2
        return 1
    fi
    if [ -n "$removal_id" ] \
        && docker container inspect "$removal_id" >/dev/null 2>&1
    then
        echo "privileged P3.8b container remained after removal" >&2
        return 1
    fi
    if docker container inspect "$container" >/dev/null 2>&1; then
        echo "P3.8b container name was rebound before publication" >&2
        return 1
    fi
    if [ -f "$cidfile" ]; then
        rm -f -- "$cidfile" || return 1
    fi
    create_attempted=0
    return 0
}

reap_probe()
{
    if [ -n "$probe_pid" ] && [ "$probe_waited" -ne 1 ]; then
        wait "$probe_pid" >/dev/null 2>&1 || :
        probe_waited=1
    fi
}

remove_created_network()
{
    if [ "$network_create_attempted" -ne 1 ]; then
        return 0
    fi
    current_id=$(docker network inspect --format '{{.Id}}' "$network" 2>/dev/null || :)
    if [ -z "$current_id" ]; then
        echo "owned P3.8b network disappeared before removal" >&2
        return 1
    fi
    current_owner=$(docker network inspect \
        --format '{{index .Labels "dev.aragorn.capture-owner"}}' "$current_id")
    current_profile=$(docker network inspect \
        --format '{{index .Labels "dev.aragorn.profile"}}' "$current_id")
    attached=$(docker network inspect --format '{{len .Containers}}' "$current_id")
    if [ "$current_id" != "$network_id" ] \
        || [ "$current_owner" != "$owner_token" ] \
        || [ "$current_profile" != "p3.8b" ] \
        || [ "$attached" -ne 0 ]
    then
        echo "refusing to remove an unowned or attached P3.8b network" >&2
        return 1
    fi
    docker network rm "$current_id" >/dev/null 2>&1 || :
    if ! docker info >/dev/null 2>&1; then
        echo "cannot verify P3.8b network removal" >&2
        return 1
    fi
    if docker network inspect "$current_id" >/dev/null 2>&1 \
        || docker network inspect "$network" >/dev/null 2>&1
    then
        echo "P3.8b network remained or its name was rebound before publication" >&2
        return 1
    fi
    network_create_attempted=0
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
    reap_probe
    if ! remove_created_network; then
        cleanup_failed=1
    fi
    for cleanup_path in \
        "$inspect" "$parent_inspect" "$child_inspect" "$volume_inspect" \
        "$network_inspect" "$disconnected_inspect" \
        "$disconnected_network_inspect" "$acquisition_marker" "$harness" \
        "$commit_stdout" "$commit_stderr" "$commit_object" "$iidfile" \
        "$probe_stdout" "$probe_stderr" "$temp_output"
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
            /tmp/aragorn-p3-8b-context.*) rm -rf -- "$context" || cleanup_failed=1 ;;
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
        echo "P3.8b capture cleanup failed closed" >&2
        status=74
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
if ! mkdir "$capture_lock"; then
    echo "another P3.8b capture owns the host lock: $capture_lock" >&2
    exit 75
fi
lock_held=1

parent_id=$(docker image inspect --format '{{.Id}}' "$parent" 2>/dev/null || :)
if [ "$parent_id" != "$parent" ]; then
    echo "missing exact local P3.7c image: $parent" >&2
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
if docker network inspect "$network" >/dev/null 2>&1; then
    echo "refusing to replace existing network: $network" >&2
    exit 73
fi

inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-inspect.XXXXXX")
parent_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-parent.XXXXXX")
child_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-child.XXXXXX")
volume_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-volume.XXXXXX")
network_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-network.XXXXXX")
disconnected_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-disconnected.XXXXXX")
disconnected_network_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-network-disconnected.XXXXXX")
acquisition_marker=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-acquisition-marker.XXXXXX")
harness=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-harness.XXXXXX")
context=$(mktemp -d /tmp/aragorn-p3-8b-context.XXXXXX)
commit_stdout=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-commit-out.XXXXXX")
commit_stderr=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-commit-err.XXXXXX")
commit_object=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-commit-object.XXXXXX")
iidfile=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-image-id.XXXXXX")
probe_stdout=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-probe-out.XXXXXX")
probe_stderr=$(mktemp "${TMPDIR:-/tmp}/aragorn-p3-8b-probe-err.XXXXXX")
temp_output=$(mktemp "${output}.tmp.XXXXXX")

if ! GIT_NO_REPLACE_OBJECTS=1 git verify-commit --raw "$source_commit" \
    >"$commit_stdout" 2>"$commit_stderr"
then
    echo "P3.8b source commit signature verification failed" >&2
    exit 66
fi
GIT_NO_REPLACE_OBJECTS=1 git cat-file commit "$source_commit" >"$commit_object"
GIT_NO_REPLACE_OBJECTS=1 git archive --format=tar "$source_commit" -- \
    benchmark/runtime-acquisition-action-systemd \
    packaging/libexec/aragorn-protected-install-coordinator.py \
    packaging/systemd/aragorn-gateway.tmpfiles \
    'packaging/systemd/var-lib-aragorn\x2dgateway.mount' \
    packaging/systemd/aragorn-protected-install-coordinator.path \
    packaging/systemd/aragorn-protected-install-coordinator.service \
    scripts/capture_runtime_acquisition_action_systemd.sh \
    scripts/runtime_acquisition_action_systemd_probe.py \
    src/aragorn/protected_install_coordinator.py \
    | tar -xf - -C "$context"
(
    cd "$context"
    docker build --pull=false --network=none \
        --iidfile "$iidfile" \
        --build-arg "P37C_BASE=$parent_id" \
        -t "$image" \
        -f benchmark/runtime-acquisition-action-systemd/Dockerfile \
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
    echo "P3.8b image did not extend the exact P3.7c parent" >&2
    exit 69
fi

network_create_attempted=1
network_id=$(docker network create --driver bridge \
    --label dev.aragorn.profile=p3.8b \
    --label "dev.aragorn.capture-owner=$owner_token" \
    "$network")
case "$network_id" in
    ""|*[!0-9a-f]*)
        echo "Docker did not return one immutable network ID" >&2
        exit 69
        ;;
esac
if [ "${#network_id}" -ne 64 ] \
    || [ "$(docker network inspect --format '{{.Id}}' "$network")" != "$network_id" ]
then
    echo "P3.8b transient network identity changed" >&2
    exit 69
fi

create_attempted=1
container_id=$(docker create --name "$container" --cidfile "$cidfile" --pull=never \
    --privileged --cgroupns=host --network="$network" \
    --security-opt label=disable \
    --label dev.aragorn.profile=p3.8b \
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
docker network inspect "$network_id" >"$network_inspect"
python3.12 - \
    "$inspect" "$parent_inspect" "$child_inspect" "$volume_inspect" \
    "$network_inspect" "$harness" "$source_commit" "$network" \
    "$network_id" "$owner_token" \
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


source, parent, child, volume, network = map(one, sys.argv[1:6])
commit, network_name, network_id, owner_token = sys.argv[7:11]
parent_id = "sha256:3c8321a7118684b8358876179406da6f12fb814dcfc3a1731a923c8bb5b3fe07"
if parent["Id"] != parent_id or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
    raise SystemExit("P3.8b parent or source commit identity drifted")
commit_object = raw_record(sys.argv[11])
commit_raw = base64.b64decode(commit_object["base64"], validate=True)
commit_identity = hashlib.sha1(
    f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
).hexdigest()
verification_stdout = raw_record(sys.argv[12])
verification_stderr = raw_record(sys.argv[13])
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
    raise SystemExit("P3.8b child is not an additive P3.7c layer")
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
if runtime_mount != expected_mount or volume_identity != expected_volume:
    raise SystemExit("OpenClaw runtime mount identity drifted")

host = source["HostConfig"]
host_config = {
    "binds": sorted(host["Binds"]),
    "cgroupns_mode": host["CgroupnsMode"],
    "ipc_mode": host["IpcMode"],
    "network_mode": host["NetworkMode"],
    "port_bindings": host.get("PortBindings") or {},
    "privileged": host["Privileged"],
    "publish_all_ports": host["PublishAllPorts"],
    "readonly_rootfs": host["ReadonlyRootfs"],
    "runtime": host["Runtime"],
    "security_opt": host["SecurityOpt"],
    "tmpfs": host["Tmpfs"],
    "userns_mode": host["UsernsMode"],
}
expected_host = {
    "binds": sorted([
        "/sys/fs/cgroup:/sys/fs/cgroup:rw",
        "aragorn-openclaw-2026-7-1-runtime:/runtime:ro",
    ]),
    "cgroupns_mode": "host",
    "ipc_mode": "private",
    "network_mode": network_name,
    "port_bindings": {},
    "privileged": True,
    "publish_all_ports": False,
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
    raise SystemExit("P3.8b outer host profile drifted")
published_ports = source["NetworkSettings"].get("Ports") or {}
if any(bindings for bindings in published_ports.values()):
    raise SystemExit("P3.8b capture must not publish ports")

networks = source["NetworkSettings"]["Networks"]
if set(networks) != {network_name}:
    raise SystemExit("P3.8b container network attachment drifted")
attachment = networks[network_name]
labels = network.get("Labels") or {}
containers = network.get("Containers") or {}
if (
    network["Id"] != network_id
    or network["Name"] != network_name
    or network["Driver"] != "bridge"
    or network["Scope"] != "local"
    or network["Internal"] is not False
    or network["Attachable"] is not False
    or network["Ingress"] is not False
    or labels.get("dev.aragorn.profile") != "p3.8b"
    or labels.get("dev.aragorn.capture-owner") != owner_token
    or set(containers) != {source["Id"]}
    or containers[source["Id"]]["Name"] != source["Name"].lstrip("/")
    or attachment["NetworkID"] != network_id
):
    raise SystemExit("owned P3.8b bridge identity or attachment drifted")

network_config = {
    "attachable": network["Attachable"],
    "config_from": network.get("ConfigFrom"),
    "config_only": network.get("ConfigOnly", False),
    "driver": network["Driver"],
    "enable_ipv4": network.get("EnableIPv4"),
    "enable_ipv6": network["EnableIPv6"],
    "id": network["Id"],
    "ingress": network["Ingress"],
    "internal": network["Internal"],
    "ipam": network["IPAM"],
    "labels": labels,
    "name": network["Name"],
    "options": network.get("Options"),
    "scope": network["Scope"],
}
network_attachment = {
    "aliases": attachment.get("Aliases"),
    "dns_names": attachment.get("DNSNames"),
    "endpoint_id": attachment["EndpointID"],
    "gateway": attachment["Gateway"],
    "global_ipv6_address": attachment["GlobalIPv6Address"],
    "global_ipv6_prefix_len": attachment["GlobalIPv6PrefixLen"],
    "ip_address": attachment["IPAddress"],
    "ip_prefix_len": attachment["IPPrefixLen"],
    "ipv6_gateway": attachment["IPv6Gateway"],
    "links": attachment.get("Links"),
    "mac_address": attachment["MacAddress"],
    "network_id": attachment["NetworkID"],
}
if source["Platform"] != "linux":
    raise SystemExit("P3.8b container platform changed")
if source["Config"]["Labels"].get("dev.aragorn.profile") != "p3.8b":
    raise SystemExit("P3.8b container label changed")

document = {
    "schema": "aragorn/runtime-acquisition-action-systemd-harness/v1",
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
    "image_reference": "aragorn-p38b-runtime-acquisition-action-systemd",
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
    "published_ports": published_ports,
    "capture_network": network_config,
    "capture_network_attachment": network_attachment,
    "capture_network_inspect": raw_record(sys.argv[5]),
}
Path(sys.argv[6]).write_text(
    json.dumps(document, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
    encoding="utf-8",
)
PY

docker exec -i "$container_id" /bin/sh -c \
    'umask 077; cat > /run/aragorn-harness.json' <"$harness"
docker exec "$container_id" install -d -m 0700 /evidence
docker exec "$container_id" /usr/local/bin/python3.12 -I -S -B \
    /src/scripts/runtime_acquisition_action_systemd_probe.py \
    >"$probe_stdout" 2>"$probe_stderr" &
probe_pid=$!

i=0
while ! docker exec "$container_id" \
    /usr/local/bin/python3.12 -I -S -B -c \
    'from pathlib import Path; expected=b"{\"schema\":\"aragorn/p38b-acquisition-complete-marker/v1\",\"status\":\"ACQUISITION_COMPLETE\"}\n"; raise SystemExit(0 if Path("/run/aragorn-p38b-acquisition-complete").read_bytes() == expected else 1)' \
    2>/dev/null
do
    if ! kill -0 "$probe_pid" 2>/dev/null; then
        probe_status=0
        wait "$probe_pid" || probe_status=$?
        probe_waited=1
        cat "$probe_stdout" >&2 || :
        cat "$probe_stderr" >&2 || :
        docker exec "$container_id" \
            cat /evidence/runtime-acquisition-action-systemd.json >&2 || :
        if [ "$probe_status" -eq 0 ]; then
            probe_status=70
        fi
        exit "$probe_status"
    fi
    i=$((i + 1))
    if [ "$i" -ge 1200 ]; then
        echo "P3.8b acquisition marker did not arrive" >&2
        exit 70
    fi
    sleep 0.1
done
docker exec "$container_id" \
    cat /run/aragorn-p38b-acquisition-complete >"$acquisition_marker"
python3.12 - "$acquisition_marker" <<'PY'
import json
import sys
from pathlib import Path

expected = {
    "schema": "aragorn/p38b-acquisition-complete-marker/v1",
    "status": "ACQUISITION_COMPLETE",
}
raw = Path(sys.argv[1]).read_bytes()
canonical = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
if raw != canonical:
    raise SystemExit("P3.8b acquisition marker is not exact canonical JSON")
PY

docker network disconnect "$network_id" "$container_id"
docker inspect "$container_id" >"$disconnected_inspect"
docker network inspect "$network_id" >"$disconnected_network_inspect"
python3.12 - "$disconnected_inspect" "$disconnected_network_inspect" \
    "$container_id" "$network_id" <<'PY'
import json
import sys
from pathlib import Path


def one(path: str) -> dict:
    value = json.loads(Path(path).read_bytes())
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise SystemExit(f"expected one inspect object: {path}")
    return value[0]


container, network = map(one, sys.argv[1:3])
if container["Id"] != sys.argv[3] or network["Id"] != sys.argv[4]:
    raise SystemExit("P3.8b identity changed during network disconnect")
if container["NetworkSettings"].get("Networks") or network.get("Containers"):
    raise SystemExit("P3.8b capture network remained attached")
PY
printf '%s\n' \
    '{"disconnected":true,"schema":"aragorn/p38b-network-disconnected-marker/v1"}' \
    | docker exec -i "$container_id" /bin/sh -c \
        'umask 077; set -C; cat > /run/aragorn-p38b-network-disconnected'

probe_status=0
wait "$probe_pid" || probe_status=$?
probe_waited=1
if [ "$probe_status" -ne 0 ]; then
    cat "$probe_stdout" >&2 || :
    cat "$probe_stderr" >&2 || :
    docker exec "$container_id" \
        cat /evidence/runtime-acquisition-action-systemd.json >&2 || :
    exit "$probe_status"
fi
docker cp "$container_id:/evidence/runtime-acquisition-action-systemd.json" \
    "$temp_output"
if ! remove_created_container; then
    echo "cannot remove and verify the privileged P3.8b container" >&2
    exit 74
fi
if ! remove_created_network; then
    echo "cannot remove and verify the transient P3.8b network" >&2
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
    expected_decision = {
        "status": "P3_8B_OBSERVED_NOT_VERIFIED",
        "live_same_custody_install_to_action_observed": True,
        "retained_evidence_eligible": False,
        "same_phase1_release_identity": False,
        "semantic_skill_causation_established": False,
        "run_01_eligible": False,
        "run_02_eligible": False,
        "phase3_exit_eligible": False,
        "edr_claim_eligible": False,
        "installer_authority_eligible": False,
        "public_release_eligible": False,
    }
    if (
        document.get("schema")
        != "aragorn/runtime-acquisition-action-systemd-observation/v1"
        or document.get("authority")
        != "BOUNDED_LIVE_COORDINATOR_ACQUISITION_TO_RUNTIME_ACTION_OBSERVATION_ONLY_NOT_VERIFIED_RUN_EDR_INSTALLER_RELEASE_AUTHORITY"
        or document.get("decision") != expected_decision
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
    destination_link = os.stat(destination.name, dir_fd=directory, follow_symlinks=False)
    for retained in (os.fstat(descriptor), source_link, destination_link):
        if (
            (retained.st_dev, retained.st_ino) != published_identity
            or not stat.S_ISREG(retained.st_mode)
            or stat.S_IMODE(retained.st_mode) != 0o644
            or retained.st_nlink != 2
            or retained.st_size != len(raw)
        ):
            raise SystemExit("linked observation identity or metadata changed")

    destination_descriptor = os.open(destination.name, file_flags, dir_fd=directory)
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
    final_destination = os.stat(destination.name, dir_fd=directory, follow_symlinks=False)
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
            current = os.stat(destination.name, dir_fd=directory, follow_symlinks=False)
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
