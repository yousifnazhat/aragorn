#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
child=sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c
parent=sha256:fb4794e886c2bef6ab450d28fc59ee3347ed2c2426d116c81781dc1d4bf09847
runtime_volume=aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1
composition_source=c59154968b2cd637d88a5a17d5b1100873df7563
composition_path=benchmark/evidence/runtime-action-worker-final-combined-systemd-composition-p3-final-2026-08-13.json
lock=/tmp/aragorn-phase3-final-route-capture.lock
DOCKER_CONTEXT=colima-aragorn-bakeoff
COPYFILE_DISABLE=1
export COPYFILE_DISABLE DOCKER_CONTEXT
umask 077

if [ "$#" -ne 2 ]; then
    echo "usage: capture_runtime_action_worker_final_route_systemd.sh ROUTE_ID ABSENT_OUTPUT_PATH" >&2
    exit 64
fi
route=$1
case "$route" in
    ADM-02/reload/cron-rescan)
        probe=protected-cron-rescan-probe.mjs
        bundle="protected-observation-v1.mjs $probe" ;;
    ADM-02/reload/fresh-session-reset)
        probe=protected-route-probe.mjs
        bundle=$probe ;;
    ADM-02/reload/missing-prompt-blob-rebuild)
        probe=protected-prompt-rebuild-probe.mjs
        bundle="protected-observation-v1.mjs $probe" ;;
    ADM-02/reload/session-snapshot-consumer)
        probe=protected-session-snapshot-fixed-probe.mjs
        bundle="protected-observation-v1.mjs $probe" ;;
    *) echo "unsupported final route: $route" >&2; exit 64 ;;
esac
output=$2
case "$output" in /*) ;; *) output=$PWD/$output ;; esac
output_dir=$(CDPATH= cd -- "$(dirname -- "$output")" && pwd)
output=$output_dir/$(basename -- "$output")
if [ -e "$output" ] || [ -L "$output" ]; then
    echo "refusing to replace output: $output" >&2
    exit 73
fi

cd "$root"
if [ -n "$(git status --porcelain=v1)" ]; then
    echo "final route capture requires one clean signed source commit" >&2
    exit 66
fi
source_commit=$(GIT_NO_REPLACE_OBJECTS=1 git rev-parse --verify 'HEAD^{commit}')
case "$source_commit" in ""|*[!0-9a-f]*) exit 66 ;; esac
if [ "${#source_commit}" -ne 40 ] || [ "$source_commit" = "$composition_source" ]; then
    echo "invalid or stale route source commit" >&2
    exit 66
fi

container=aragorn-phase3-final-route-$$
owner=$source_commit:$$
cidfile=$lock/container.id
held=0
created=0
container_id=
input_volume=aragorn-phase3-final-route-input-${source_commit%????????????????????????????????}-$$
volume_created=0
context=
harness=
final_harness=
inspect=
parent_inspect=
child_inspect=
volume_inspect=
commit_object=
commit_stdout=
commit_stderr=
temp_output=

remove_container()
{
    [ "$created" -eq 1 ] || return 0
    removal=$container_id
    [ -n "$removal" ] || [ ! -f "$cidfile" ] || removal=$(tr -d '\n' <"$cidfile")
    if [ -n "$removal" ] && docker container inspect "$removal" >/dev/null 2>&1; then
        current_id=$(docker container inspect --format '{{.Id}}' "$removal")
        current_image=$(docker container inspect --format '{{.Image}}' "$removal")
        current_owner=$(docker container inspect --format '{{index .Config.Labels "dev.aragorn.capture-owner"}}' "$removal")
        if [ "$current_id" != "$removal" ] || [ "$current_image" != "$child" ] || [ "$current_owner" != "$owner" ]; then
            echo "refusing to remove an unowned final route container" >&2
            return 1
        fi
        docker rm -f "$removal" >/dev/null
        container_id=
    fi
    if ! docker info >/dev/null 2>&1; then
        echo "cannot verify final route container removal" >&2
        return 1
    fi
    if [ -n "$removal" ] && docker container inspect "$removal" >/dev/null 2>&1; then
        echo "privileged final route container remained" >&2
        return 1
    fi
    rm -f -- "$cidfile"
    created=0
}

cleanup()
{
    status=$?
    trap - EXIT HUP INT TERM
    failed=0
    remove_container || failed=1
    if [ "$volume_created" -eq 1 ]; then
        current_owner=$(docker volume inspect --format '{{index .Labels "dev.aragorn.capture-owner"}}' "$input_volume" 2>/dev/null || :)
        if [ "$current_owner" != "$owner" ]; then
            echo "refusing to remove an unowned final route input volume" >&2
            failed=1
        elif ! docker volume rm "$input_volume" >/dev/null; then
            failed=1
        else
            volume_created=0
        fi
    fi
    for path in "$harness" "$final_harness" "$inspect" "$parent_inspect" "$child_inspect" "$volume_inspect" "$commit_object" "$commit_stdout" "$commit_stderr" "$temp_output"; do
        [ -z "$path" ] || { [ ! -e "$path" ] && [ ! -L "$path" ]; } || rm -f -- "$path" || failed=1
    done
    if [ -n "$context" ] && [ -d "$context" ]; then
        case "$context" in /tmp/aragorn-phase3-final-route-context.*) rm -rf -- "$context" || failed=1 ;; *) failed=1 ;; esac
    fi
    if [ "$held" -eq 1 ]; then rmdir "$lock" || failed=1; fi
    [ "$failed" -eq 0 ] || [ "$status" -ne 0 ] || status=74
    exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

mkdir "$lock" || { echo "another final route capture owns $lock" >&2; exit 75; }
held=1
if [ "$(docker context show)" != "$DOCKER_CONTEXT" ]; then
    echo "final route Docker context changed" >&2
    exit 66
fi
if [ "$(docker image inspect --format '{{.Id}}' "$child" 2>/dev/null || :)" != "$child" ]; then
    echo "missing exact final child image: $child" >&2
    exit 66
fi
if [ "$(docker image inspect --format '{{.Id}}' "$parent" 2>/dev/null || :)" != "$parent" ]; then
    echo "missing exact final parent image: $parent" >&2
    exit 66
fi
docker volume inspect "$runtime_volume" >/dev/null 2>&1 || { echo "missing final runtime volume" >&2; exit 66; }

context=$(mktemp -d /tmp/aragorn-phase3-final-route-context.XXXXXX)
harness=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-route-harness.XXXXXX")
final_harness=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-composition-harness.XXXXXX")
inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-route-inspect.XXXXXX")
parent_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-route-parent.XXXXXX")
child_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-route-child.XXXXXX")
volume_inspect=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-route-volume.XXXXXX")
commit_object=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-route-commit.XXXXXX")
commit_stdout=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-route-out.XXXXXX")
commit_stderr=$(mktemp "${TMPDIR:-/tmp}/aragorn-phase3-final-route-err.XXXXXX")
temp_output=$(mktemp "${output}.tmp.XXXXXX")
if ! GIT_NO_REPLACE_OBJECTS=1 git verify-commit --raw "$source_commit" >"$commit_stdout" 2>"$commit_stderr"; then
    echo "route source signature verification failed" >&2
    exit 66
fi
GIT_NO_REPLACE_OBJECTS=1 git cat-file commit "$source_commit" >"$commit_object"
GIT_NO_REPLACE_OBJECTS=1 git archive --format=tar "$source_commit" -- \
    benchmark/admission/openclaw-v2026.7.1/protected-cron-rescan-probe.mjs \
    benchmark/admission/openclaw-v2026.7.1/protected-observation-v1.mjs \
    benchmark/admission/openclaw-v2026.7.1/protected-prompt-rebuild-probe.mjs \
    benchmark/admission/openclaw-v2026.7.1/protected-route-probe.mjs \
    benchmark/admission/openclaw-v2026.7.1/protected-session-snapshot-fixed-probe.mjs \
    scripts/capture_runtime_action_worker_final_route_systemd.sh \
    scripts/materialize_fixed_admission_probes.py \
    scripts/runtime_action_worker_final_route_systemd_probe.py \
    "$composition_path" | tar -xf - -C "$context"
# shellcheck disable=SC2086
python3 "$context/scripts/materialize_fixed_admission_probes.py" --final-combined \
    "$context/probe" $bundle

if docker volume inspect "$input_volume" >/dev/null 2>&1; then
    echo "refusing to reuse an existing final route input volume" >&2
    exit 73
fi
docker volume create \
    --label dev.aragorn.role=final-route-input \
    --label "dev.aragorn.route=$route" \
    --label "dev.aragorn.source-commit=$source_commit" \
    --label "dev.aragorn.capture-owner=$owner" \
    "$input_volume" >/dev/null
volume_created=1
if [ "$(docker volume inspect --format '{{json .Labels}}' "$input_volume")" != \
    "{\"dev.aragorn.capture-owner\":\"$owner\",\"dev.aragorn.role\":\"final-route-input\",\"dev.aragorn.route\":\"$route\",\"dev.aragorn.source-commit\":\"$source_commit\"}" ]; then
    echo "final route input volume labels changed" >&2
    exit 69
fi
(cd "$context" && tar -cf - \
    scripts/capture_runtime_action_worker_final_route_systemd.sh \
    scripts/materialize_fixed_admission_probes.py \
    scripts/runtime_action_worker_final_route_systemd_probe.py \
    probe) | docker run --rm -i --network=none --entrypoint /bin/sh \
    -v "$input_volume:/route-input" "$child" -c '
        set -eu
        tar -xf - -C /route-input
        chown -R 0:0 /route-input
        chmod 0555 /route-input /route-input/scripts /route-input/probe /route-input/scripts/*
        chmod 0444 /route-input/probe/*
    '

created=1
if ! container_id=$(docker create --name "$container" --cidfile "$cidfile" --pull=never \
    --privileged --cgroupns=host --network=none --security-opt label=disable \
    --label dev.aragorn.profile=phase3-final-combined \
    --label "dev.aragorn.route=$route" --label "dev.aragorn.capture-owner=$owner" \
    --tmpfs /run:rw,nosuid,nodev,noexec,mode=755 \
    --tmpfs /run/lock:rw,nosuid,nodev,noexec,mode=755 \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$runtime_volume:/runtime:ro" \
    -v "$input_volume:/route-input:ro" "$child"); then
    container_id=$(tr -d '\n' <"$cidfile" 2>/dev/null || :)
    exit 69
fi
docker start "$container_id" >/dev/null
i=0
while ! docker exec "$container_id" test -S /run/systemd/private; do i=$((i + 1)); [ "$i" -lt 100 ] || exit 70; sleep 0.1; done
i=0
while ! docker exec "$container_id" test -d /run/aragorn-protected-install; do i=$((i + 1)); [ "$i" -lt 100 ] || exit 70; sleep 0.1; done

docker inspect "$container_id" >"$inspect"
docker image inspect "$parent" >"$parent_inspect"
docker image inspect "$child" >"$child_inspect"
docker volume inspect "$runtime_volume" >"$volume_inspect"
python3 - "$context" "$inspect" "$parent_inspect" "$child_inspect" \
    "$volume_inspect" "$route" "$harness" "$final_harness" \
    "$source_commit" "$commit_object" "$commit_stdout" "$commit_stderr" \
    "$input_volume" <<'PY'
import base64, hashlib, json, sys
from pathlib import Path

root, inspect_path, parent_path, child_path, volume_path, route, route_output, final_output, commit, commit_object, stdout, stderr, input_volume = sys.argv[1:]
root = Path(root)
value = json.load(open(inspect_path))
if len(value) != 1:
    raise SystemExit("expected one container inspect")
item = value[0]
parent_value = json.load(open(parent_path))[0]
child_value = json.load(open(child_path))[0]
volume_value = json.load(open(volume_path))[0]
host = item["HostConfig"]
child = "sha256:3ccea364258c367342e585113d784b7ce00642c63918e0a6f0a6594019d3121c"
parent = "sha256:fb4794e886c2bef6ab450d28fc59ee3347ed2c2426d116c81781dc1d4bf09847"
runtime_volume = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
parent_layers = parent_value["RootFS"]["Layers"]
child_layers = child_value["RootFS"]["Layers"]
expected_volume = {"Driver": "local", "Labels": {"io.aragorn.phase": "phase3-final", "io.aragorn.role": "installed-runtime", "io.aragorn.source-commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf", "io.aragorn.source-tree": "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44"}, "Name": "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1", "Options": None, "Scope": "local"}
volume_identity = {key: volume_value.get(key) for key in expected_volume}
host_projection = {
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
    "binds": sorted([
        "/sys/fs/cgroup:/sys/fs/cgroup:rw",
        f"{runtime_volume}:/runtime:ro",
        f"{input_volume}:/route-input:ro",
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
mounts = sorted(
    [
        {
            "destination": mount["Destination"],
            "driver": mount.get("Driver", ""),
            "mode": mount["Mode"],
            "name": mount.get("Name", ""),
            "propagation": mount["Propagation"],
            "rw": mount["RW"],
            "source": mount["Source"] if mount["Type"] == "bind" else "",
            "type": mount["Type"],
        }
        for mount in item["Mounts"]
    ],
    key=lambda mount: mount["destination"],
)
expected_mounts = [
    {"destination": "/route-input", "driver": "local", "mode": "ro", "name": input_volume, "propagation": "", "rw": False, "source": "", "type": "volume"},
    {"destination": "/runtime", "driver": "local", "mode": "ro", "name": runtime_volume, "propagation": "", "rw": False, "source": "", "type": "volume"},
    {"destination": "/sys/fs/cgroup", "driver": "", "mode": "rw", "name": "", "propagation": "rprivate", "rw": True, "source": "/sys/fs/cgroup", "type": "bind"},
]
if not (item["Image"] == child == item["Config"]["Image"] == child_value["Id"] and parent_value["Id"] == parent and child_layers[:len(parent_layers)] == parent_layers and child_layers[len(parent_layers):] and volume_identity == expected_volume and host_projection == expected_host and mounts == expected_mounts and item["Config"]["Labels"].get("dev.aragorn.route") == route and item["Config"]["Labels"].get("dev.aragorn.profile") == "phase3-final-combined"):
    raise SystemExit("final route containment changed")

def raw_record(path):
    raw = Path(path).read_bytes()
    return {"base64": base64.b64encode(raw).decode("ascii"), "bytes": len(raw), "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}

def file_record(path, source_path, runtime_path):
    raw = Path(path).read_bytes()
    return {"source_path": source_path, "runtime_path": runtime_path, "bytes": len(raw), "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}

composition_path = "benchmark/evidence/runtime-action-worker-final-combined-systemd-composition-p3-final-2026-08-13.json"
composition = root / composition_path
expected_composition = {"path": composition_path, "bytes": 347400, "digest": "sha256:281c2de033ed033cc8df71a2e45a4e058005eb4764dd926d8b5422280ed8a029"}
composition_record = {"path": composition_path, "bytes": composition.stat().st_size, "digest": "sha256:" + hashlib.sha256(composition.read_bytes()).hexdigest()}
if composition_record != expected_composition:
    raise SystemExit("retained final composition changed")
baseline = json.loads(composition.read_bytes())
final_harness = baseline["action"]["harness"]["document"]
final_harness["container_id"] = item["Id"]
final_harness["host_config"] = host_projection
final_harness["image_lineage"] = {"parent": {"id": parent, "rootfs_type": parent_value["RootFS"]["Type"], "layers": parent_layers}, "child": {"id": child, "rootfs_type": child_value["RootFS"]["Type"], "layers": child_layers}, "added_layers": child_layers[len(parent_layers):]}
final_harness["openclaw_runtime_volume_identity"] = {"driver": volume_value["Driver"], "labels": volume_value.get("Labels"), "name": volume_value["Name"], "options": volume_value.get("Options"), "scope": volume_value["Scope"]}
runtime_mounts = [mount for mount in item["Mounts"] if mount["Destination"] == "/runtime"]
if len(runtime_mounts) != 1:
    raise SystemExit("installed runtime mount changed")
runtime_mount = runtime_mounts[0]
final_harness["openclaw_runtime_mount"] = {
    "destination": runtime_mount["Destination"],
    "driver": runtime_mount["Driver"],
    "mode": runtime_mount["Mode"],
    "rw": runtime_mount["RW"],
    "source": runtime_mount["Name"],
    "type": runtime_mount["Type"],
}
final_raw = json.dumps(final_harness, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
Path(final_output).write_bytes(final_raw)

bundle = [{"name": path.name, "bytes": path.stat().st_size, "digest": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted((root / "probe").iterdir())]
support = "/route-input/scripts"
collectors = {
    "capture_recipe": ("scripts/capture_runtime_action_worker_final_route_systemd.sh", f"{support}/capture_runtime_action_worker_final_route_systemd.sh"),
    "materializer": ("scripts/materialize_fixed_admission_probes.py", f"{support}/materialize_fixed_admission_probes.py"),
    "probe": ("scripts/runtime_action_worker_final_route_systemd_probe.py", f"{support}/runtime_action_worker_final_route_systemd_probe.py"),
}
route_harness = {
    "schema": "aragorn/runtime-action-worker-final-route-systemd-harness/v1",
    "capture_disposition": "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE",
    "route_source_commit": commit,
    "route_source_commit_verification": {"command": ["git", "verify-commit", "--raw", commit], "exit_code": 0, "commit_object": raw_record(commit_object), "stdout": raw_record(stdout), "stderr": raw_record(stderr)},
    "image_source_commit": "c59154968b2cd637d88a5a17d5b1100873df7563",
    "route_id": route,
    "child_image_id": child,
    "composition_harness_digest": "sha256:" + hashlib.sha256(final_raw).hexdigest(),
    "baseline_composition": expected_composition,
    "probe_bundle": bundle,
    "collector": {key: file_record(root / source, source, runtime) for key, (source, runtime) in collectors.items()},
}
Path(route_output).write_text(json.dumps(route_harness, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True), encoding="ascii")
PY

docker exec -i "$container_id" /bin/sh -c 'umask 077; cat > /run/aragorn-harness.json' <"$final_harness"
docker exec -i "$container_id" /bin/sh -c 'umask 077; cat > /run/aragorn-route-harness.json' <"$harness"
docker exec "$container_id" install -d -m 0700 /evidence
status=0
docker exec "$container_id" /usr/local/bin/python3.12 -I -S -B \
    /route-input/scripts/runtime_action_worker_final_route_systemd_probe.py "$route" || status=$?
if [ "$status" -ne 0 ]; then
    docker exec "$container_id" cat /evidence/runtime-action-worker-final-route-systemd.json >&2 || :
    exit "$status"
fi
docker cp "$container_id:/evidence/runtime-action-worker-final-route-systemd.json" "$temp_output"
remove_container || exit 74
if [ "$(docker volume inspect --format '{{index .Labels "dev.aragorn.capture-owner"}}' "$input_volume")" != "$owner" ]; then
    echo "final route input volume ownership changed" >&2
    exit 74
fi
docker volume rm "$input_volume" >/dev/null
volume_created=0

python3 - "$temp_output" "$output" "$route" <<'PY'
import json, os, stat, sys
from pathlib import Path
source = Path(sys.argv[1])
destination = Path(sys.argv[2])
route = sys.argv[3]
raw = source.read_bytes()
document = json.loads(raw, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)), parse_float=lambda value: (_ for _ in ()).throw(ValueError(value)))
canonical = json.dumps(document, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii") + b"\n"
decision = document.get("decision", {})
claims = {key for key in decision if key.endswith("_eligible")}
expected = {"admission_profile_eligible", "aggregate_admission_eligible", "edr_eligible", "installer_work_eligible", "phase3_exit_eligible", "release_eligible", "run_01_eligible", "run_02_eligible", "run_eligible"}
if raw != canonical or document.get("schema") != "aragorn/runtime-action-worker-final-route-systemd-observation/v1" or document.get("route_id") != route or claims != expected or any(decision[key] is not False for key in claims) or decision.get("route_pass_count") != 0 or decision.get("route_fail_count") != 0 or decision.get("route_not_tested_count") != 21:
    raise SystemExit("final route output claim ceiling changed")
os.chmod(source, 0o644)
try:
    os.link(source, destination, follow_symlinks=False)
except FileExistsError as exc:
    raise SystemExit(f"refusing to replace output: {destination}") from exc
os.unlink(source)
published = destination.stat(follow_symlinks=False)
if not stat.S_ISREG(published.st_mode) or stat.S_IMODE(published.st_mode) != 0o644 or published.st_nlink != 1 or destination.read_bytes() != raw:
    destination.unlink(missing_ok=True)
    raise SystemExit("published route observation changed")
PY
shasum -a 256 "$output"
