#!/bin/sh
set -eu

PATH=/usr/bin:/bin
LANG=C
LC_ALL=C
TZ=UTC
export PATH LANG LC_ALL TZ

base_activator=/usr/libexec/aragorn/activate-runtime-capability-host.sh
activation_lock=/run/lock/aragorn-runtime-capability-activation.lock
gateway_unit=aragorn-agent-gateway.service
worker_unit=aragorn-runtime-action-worker.service
sensor_unit=aragorn-runtime-lineage-capability-observation-publisher.service
broker_unit=aragorn-runtime-lineage-capability-action-broker.service
gateway_user=aragorn-agent-gateway
worker_user=aragorn-runtime
sensor_user=aragorn-sensor
broker_user=aragorn-broker
gateway_config=/etc/aragorn/agent-gateway/openclaw.json
gateway_environment=/etc/aragorn/agent-gateway/environment
worker_binding=/etc/aragorn/runtime-action-worker.json
worker_runtime=/run/aragorn-runtime-action-worker
worker_socket=$worker_runtime/worker.sock
sensor_socket=/run/aragorn-runtime-observation/sensor.sock
broker_socket=/var/lib/aragorn-runtime-action/control/broker.sock
preflight_root=
armed=0

fail_activation()
{
    echo "$1" >&2
    exit 1
}

cleanup_preflight()
{
    case "$preflight_root" in
        /run/aragorn-runtime-action-worker-preflight.*)
            rm -rf -- "$preflight_root"
            ;;
        "")
            ;;
    esac
    preflight_root=
}

rollback()
{
    status=$?
    trap - EXIT
    cleanup_preflight
    if [ "$armed" -eq 1 ]; then
        rollback_failed=0
        /usr/bin/systemctl stop \
            "$gateway_unit" "$worker_unit" "$sensor_unit" "$broker_unit" \
            >/dev/null 2>&1 || rollback_failed=1
        /usr/bin/systemctl disable \
            "$worker_unit" "$sensor_unit" "$broker_unit" \
            >/dev/null 2>&1 || rollback_failed=1
        /usr/bin/systemctl mask "$gateway_unit" "$worker_unit" \
            >/dev/null 2>&1 || rollback_failed=1
        for rollback_unit in \
            "$gateway_unit" "$worker_unit" "$sensor_unit" "$broker_unit"
        do
            if /usr/bin/systemctl is-active --quiet "$rollback_unit"; then
                rollback_failed=1
            fi
        done
        for rollback_path in "$worker_socket" "$sensor_socket" "$broker_socket"
        do
            if [ -e "$rollback_path" ] || [ -L "$rollback_path" ]; then
                rollback_failed=1
            fi
        done
        if [ "$(/usr/bin/systemctl is-enabled "$gateway_unit" 2>/dev/null || :)" \
            != masked ] \
            || [ "$(/usr/bin/systemctl is-enabled "$worker_unit" 2>/dev/null || :)" \
            != masked ] \
            || [ "$(/usr/bin/systemctl is-enabled "$sensor_unit" 2>/dev/null || :)" \
            != disabled ] \
            || [ "$(/usr/bin/systemctl is-enabled "$broker_unit" 2>/dev/null || :)" \
            != disabled ]
        then
            rollback_failed=1
        fi
        if [ "$rollback_failed" -ne 0 ]; then
            echo "Aragorn runtime worker fail-stop verification failed" >&2
        fi
    fi
    exit "$status"
}

trap rollback EXIT
trap 'exit 1' HUP INT TERM

if [ "$(id -u)" -ne 0 ] \
    || [ ! -x /usr/bin/systemctl ] \
    || [ ! -x /usr/bin/flock ]
then
    fail_activation "Aragorn runtime worker activation requires root and systemd"
fi

exec 9>"$activation_lock"
if ! /usr/bin/flock -n 9; then
    fail_activation "another Aragorn runtime worker activation is in progress"
fi
armed=1

if [ ! -x /usr/bin/busctl ] \
    || [ ! -x /usr/bin/setpriv ] \
    || [ ! -x /usr/bin/python3.12 ] \
    || [ ! -x /usr/local/bin/node ] \
    || [ ! -x "$base_activator" ]
then
    fail_activation "Aragorn runtime worker activation tools are unavailable"
fi

/usr/bin/systemctl stop \
    "$gateway_unit" "$worker_unit" "$sensor_unit" "$broker_unit"
for unit in "$gateway_unit" "$worker_unit" "$sensor_unit" "$broker_unit"
do
    if /usr/bin/systemctl is-active --quiet "$unit"; then
        fail_activation "previous runtime worker route remained active: $unit"
    fi
done
for path in "$worker_socket" "$sensor_socket" "$broker_socket"
do
    if [ -e "$path" ] || [ -L "$path" ]; then
        fail_activation "previous runtime worker endpoint remained present: $path"
    fi
done
if [ "$(/usr/bin/systemctl is-enabled "$gateway_unit" 2>/dev/null || :)" \
    != static ]
then
    fail_activation "gateway retained boot authority"
fi

require_safe_root_directory()
{
    authority_path=$1
    authority_group=$2
    if [ -L "$authority_path" ] || [ ! -d "$authority_path" ]; then
        fail_activation "runtime worker authority ancestry is unsafe: $authority_path"
    fi
    if ! authority_metadata=$(stat -c '%u:%G:%a' -- "$authority_path"); then
        fail_activation "runtime worker authority ancestry cannot be inspected: $authority_path"
    fi
    authority_uid=${authority_metadata%%:*}
    authority_remainder=${authority_metadata#*:}
    authority_gid=${authority_remainder%%:*}
    authority_mode=${authority_remainder##*:}
    if [ "$authority_uid" != 0 ] || [ "$authority_gid" != "$authority_group" ]; then
        fail_activation "runtime worker authority ancestry is not root-owned: $authority_path"
    fi
    case "$authority_mode" in
        *[2367][0-7]|*[2367])
            fail_activation "runtime worker authority ancestry is writable: $authority_path"
            ;;
    esac
}

require_safe_root_directory / root
require_safe_root_directory /etc root
require_safe_root_directory /etc/aragorn root
require_safe_root_directory /var root
require_safe_root_directory /var/lib root

require_root_secret()
{
    checked_path=$1
    checked_limit=$2
    if [ -L "$checked_path" ] || [ ! -f "$checked_path" ]; then
        fail_activation "runtime worker activation input is unsafe: $checked_path"
    fi
    if ! checked_metadata=$(stat -c '%u:%g:%a:%h' -- "$checked_path"); then
        fail_activation "runtime worker activation input cannot be inspected: $checked_path"
    fi
    if [ "$checked_metadata" != "0:0:400:1" ]; then
        fail_activation "runtime worker activation input metadata is unsafe: $checked_path"
    fi
    if ! checked_size=$(stat -c '%s' -- "$checked_path") \
        || [ "$checked_size" -gt "$checked_limit" ]
    then
        fail_activation "runtime worker activation input exceeds its byte limit: $checked_path"
    fi
}

require_exact_directory()
{
    checked_path=$1
    checked_uid=$2
    checked_gid=$3
    checked_mode=$4
    if [ -L "$checked_path" ] || [ ! -d "$checked_path" ]; then
        fail_activation "runtime worker directory is unsafe: $checked_path"
    fi
    if ! checked_metadata=$(stat -c '%u:%g:%a' -- "$checked_path"); then
        fail_activation "runtime worker directory cannot be inspected: $checked_path"
    fi
    if [ "$checked_metadata" != "$checked_uid:$checked_gid:$checked_mode" ]; then
        fail_activation "runtime worker directory metadata is unsafe: $checked_path"
    fi
}

require_pinned_file()
{
    checked_mode=$1
    checked_digest=$2
    checked_path=$3
    if [ -L "$checked_path" ] || [ ! -f "$checked_path" ] \
        || [ "$(stat -c '%u:%g:%a:%h' -- "$checked_path")" \
            != "0:0:$checked_mode:1" ]
    then
        fail_activation "runtime worker implementation metadata is unsafe: $checked_path"
    fi
    checked_actual=$(sha256sum -- "$checked_path")
    if [ "${checked_actual%% *}" != "$checked_digest" ]; then
        fail_activation "runtime worker implementation digest changed: $checked_path"
    fi
}

if [ "$(readlink /usr/bin/python3.12 2>/dev/null || :)" \
    != /usr/local/bin/python3.12 ]
then
    fail_activation "runtime worker Python entrypoint changed"
fi
while read -r pinned_mode pinned_digest pinned_path
do
    require_pinned_file "$pinned_mode" "$pinned_digest" "$pinned_path"
done <<'EOF'
755 7863a4d5e03fde7791c7f8c2c304cf3522f435e19745364ad18a6b7a0458af57 /usr/local/bin/python3.12
755 3a988781edde7f1c76751f771cf402e0866fb4a81fbcd0852a2ce2f5bd2ccd37 /usr/local/bin/node
755 6d8925e6195b1218d7dd81452707e88b89e1b68e41d3afa1d6211981a3bb203a /usr/libexec/aragorn/activate-runtime-capability-host.sh
755 9dd8e3836176e3d2a6d2ab8d6a036e078dd868a188f10a74d3808b51290405fc /usr/libexec/aragorn/aragorn-runtime-action-service-v5.py
755 dba9cf34f9103073f9583f29bf0a83ae7f3162ca511ec2d76ec250ab161167cf /usr/libexec/aragorn/aragorn-runtime-observation-service-v4.py
755 42ab2d99c368090be83451ac9b1d99155608fdd8cb2e86a142ef22b22bd26a8a /usr/libexec/aragorn/aragorn-runtime-revocation-service.py
755 5274f51d50293ba7559c6348fe79c5eb43753ecb09024525cfd09c368cc360f8 /usr/libexec/aragorn/aragorn-runtime-action-worker-service.py
644 4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01 /usr/lib/aragorn/aragorn/__init__.py
644 56942e7c1b10c58f265615c8b7abf3f199c7f98bf016be50eb6d3a98d2bd0f8c /usr/lib/aragorn/aragorn/acquire.py
644 c5642f910ac4b2d6172a59a02105b359cb43d3a2f2e2240368229d3436ad4859 /usr/lib/aragorn/aragorn/cas.py
644 0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b /usr/lib/aragorn/aragorn/oci_worker_protocol.py
644 3b3b7beffd331280dfbc8088a1ef28f6b32affe59d0abf75305ff97fe93d459d /usr/lib/aragorn/aragorn/runtime_action_decision.py
644 94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21 /usr/lib/aragorn/aragorn/runtime_action_broker.py
644 288714579b5df19c5b3137caee21ede1a5c8bf69f690e3e9434bd3d646806a90 /usr/lib/aragorn/aragorn/runtime_action_observation_publisher.py
644 e9b9fd55fc88aa0c9f5916907465ea7f0f4c01e5ec822293ef0ec8e9d32e4e3e /usr/lib/aragorn/aragorn/runtime_action_service.py
644 ef738d4de1485917906f7fa95353650f007c6f4cdf4d401906abb737ef38e319 /usr/lib/aragorn/aragorn/runtime_observation_service.py
644 a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68 /usr/lib/aragorn/aragorn/runtime_process_profile.py
644 a77d7c5cc2b607b9234f6758283bdff74c73586651e6aa7d5a9e3c3ab48b14e3 /usr/lib/aragorn/aragorn/runtime_action_broker_v2.py
644 39b42a466eb248bbc5d176f9a5350a72f88afe85f98ea492bde882f7a3ba5c8e /usr/lib/aragorn/aragorn/runtime_action_observation_publisher_v2.py
644 69100dc7729922bfc980aa10a3666051703c8d1c4d319e28f6abd3128aaf3dd6 /usr/lib/aragorn/aragorn/runtime_action_service_v2.py
644 c2fd548f7d98e34cedba3313e4d477b5c258d127409dc0531e1bd5dc97a4ee1e /usr/lib/aragorn/aragorn/runtime_observation_service_v2.py
644 408f0b5373139c93b13e61fcf4ea6791865841806f0a9aa8a269e095cd0d9f8d /usr/lib/aragorn/aragorn/runtime_action_broker_v3.py
644 6d1663d097410838d6c9b69644ffdfb2bd7ace30091d31544f31b04a7f6776d1 /usr/lib/aragorn/aragorn/runtime_active_skill_lineage.py
644 85c4ec36c163648e3d706e5c7c650642caee8b1f6799fd820bc12fb1486ad0ca /usr/lib/aragorn/aragorn/runtime_lineage_capability_issuer.py
644 058aa743c6bdebffe1660120d88886d465aaaa5192171979e466ba6ce20f5681 /usr/lib/aragorn/aragorn/runtime_capability_grant.py
644 e74dc65223f84dfe4562ad8aebdde2a6ead1fce3763c8d559c0ce44e6073cde0 /usr/lib/aragorn/aragorn/runtime_action_observation_publisher_v3.py
644 ab7d08105229ee3dd58f8dca5c20156d5e260e2b79f0ed2b4c08693c3cf6174a /usr/lib/aragorn/aragorn/runtime_action_broker_v4.py
644 8c3c70dc85dd8eaa8e8a2dcdbc2c8b0571b23f5901eb023cf146a916f49b49a7 /usr/lib/aragorn/aragorn/runtime_action_service_v4.py
644 5dcc0ec212a07ce7fd087c5ea81df02e30d9c22f9a1f5b49dc790fd37b57fbdb /usr/lib/aragorn/aragorn/runtime_observation_service_v3.py
644 2f021264b43d4602842134b9d7422105243fbbf594b474a58a6a5ae8290442ae /usr/lib/aragorn/aragorn/runtime_action_observation_publisher_v4.py
644 35c17f92cca01ba064058f6d76223a03072138aa61d060538600f6799af7eca5 /usr/lib/aragorn/aragorn/runtime_action_broker_v5.py
644 a3e829d2e60f26dd91cbb14967ddf2a747414ce8f125b4f207dbce7a5e1e86c7 /usr/lib/aragorn/aragorn/runtime_action_service_v5.py
644 fff0ae55827237d9a05c93cfbae17b974e2817d258dcdf1c2cb66630eda619da /usr/lib/aragorn/aragorn/runtime_observation_service_v4.py
644 20cac61e1e497dec177e16a564e0735e6b5d593b6965fba5a57fa9d715a4c6ca /usr/lib/aragorn/aragorn/runtime_revocation_service.py
644 16e77024f715d1b7f2c600df16e5878e23f584753444fef998cf9b4742603d60 /usr/lib/aragorn/aragorn/runtime_action_worker.py
644 71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b /usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/index.js
644 d90c95c23da3de4a32b8088a69d927bf10a45ed4e116e3ccece491ee3c766036 /usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/openclaw.plugin.json
644 0097f2e532b1a5d99e3cfc4990d4bbf83a01c10ee11d567b139bd9144a859ad2 /usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/package.json
EOF

require_root_secret "$gateway_config" 4096
require_root_secret "$gateway_environment" 8192
require_root_secret "$worker_binding" 4096
require_exact_directory /etc/aragorn/agent-gateway 0 0 700

if [ "$(wc -l < "$gateway_environment")" -ne 1 ]; then
    fail_activation "gateway environment must contain one canonical assignment"
fi
IFS= read -r environment_line < "$gateway_environment"
case "$environment_line" in
    OPENCLAW_GATEWAY_TOKEN=*)
        gateway_token=${environment_line#OPENCLAW_GATEWAY_TOKEN=}
        ;;
    *)
        fail_activation "gateway environment contains an unauthorized assignment"
        ;;
esac
case "$gateway_token" in
    ""|*[!A-Za-z0-9._~-]*)
        fail_activation "gateway token contains unsafe environment syntax"
        ;;
esac
if [ "${#gateway_token}" -lt 32 ] || [ "${#gateway_token}" -gt 4096 ]; then
    fail_activation "gateway token length is unsafe"
fi
if [ "$(wc -c < "$gateway_environment")" -ne $((24 + ${#gateway_token})) ]; then
    fail_activation "gateway environment is not one canonical ASCII assignment"
fi
unset gateway_token environment_line

if ! gateway_uid=$(id -u "$gateway_user") \
    || ! gateway_gid=$(id -g "$gateway_user") \
    || ! worker_uid=$(id -u "$worker_user") \
    || ! worker_gid=$(id -g "$worker_user") \
    || ! sensor_uid=$(id -u "$sensor_user") \
    || ! sensor_gid=$(id -g "$sensor_user") \
    || ! broker_uid=$(id -u "$broker_user")
then
    fail_activation "runtime worker service identities are absent"
fi
if [ "$gateway_uid" -eq 0 ] \
    || [ "$worker_uid" -eq 0 ] \
    || [ "$sensor_uid" -eq 0 ] \
    || [ "$broker_uid" -eq 0 ] \
    || [ "$gateway_gid" -eq 0 ] \
    || [ "$worker_gid" -eq 0 ] \
    || [ "$sensor_gid" -eq 0 ] \
    || [ "$gateway_uid" = "$worker_uid" ] \
    || [ "$gateway_uid" = "$sensor_uid" ] \
    || [ "$gateway_uid" = "$broker_uid" ] \
    || [ "$worker_uid" = "$sensor_uid" ] \
    || [ "$worker_uid" = "$broker_uid" ] \
    || [ "$sensor_uid" = "$broker_uid" ] \
    || [ "$gateway_gid" = "$worker_gid" ] \
    || [ "$gateway_gid" = "$sensor_gid" ] \
    || [ "$worker_gid" = "$sensor_gid" ]
then
    fail_activation "runtime worker service identities overlap"
fi
if [ "$(id -G "$gateway_user")" != "$gateway_gid" ] \
    || [ "$(id -G "$worker_user")" != "$worker_gid" ]
then
    fail_activation "runtime worker NSS group membership is unsafe"
fi

runtime_identity=$(/usr/bin/python3.12 -I -S -B - <<'PY'
import hashlib
import json
import os
from pathlib import Path

root = Path("/runtime")
entrypoint = root / "lib/node_modules/openclaw/openclaw.mjs"
if root.is_symlink() or not root.is_dir() or entrypoint.is_symlink():
    raise SystemExit(1)
entries = []
file_count = 0
symlink_count = 0
total_bytes = 0


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return "sha256:" + value.hexdigest()


def walk(directory, parts=()):
    global file_count, symlink_count, total_bytes
    for item in sorted(os.scandir(directory), key=lambda candidate: candidate.name):
        if not item.name.isascii() or len(entries) >= 100_000:
            raise SystemExit(1)
        relative_parts = (*parts, item.name)
        relative = "/".join(relative_parts)
        metadata = item.stat(follow_symlinks=False)
        if item.is_dir(follow_symlinks=False):
            walk(Path(item.path), relative_parts)
        elif item.is_symlink():
            target = os.readlink(item.path)
            if not target.isascii():
                raise SystemExit(1)
            entries.append({"kind": "symlink", "path": relative, "target": target})
            symlink_count += 1
        elif item.is_file(follow_symlinks=False) and metadata.st_size <= 128 << 20:
            total_bytes += metadata.st_size
            if total_bytes > 1 << 30:
                raise SystemExit(1)
            entries.append(
                {
                    "digest": digest(Path(item.path)),
                    "executable": bool(metadata.st_mode & 0o111),
                    "kind": "file",
                    "links": metadata.st_nlink,
                    "path": relative,
                    "size": metadata.st_size,
                }
            )
            file_count += 1
        else:
            raise SystemExit(1)


walk(root)
encoded = json.dumps(
    entries,
    ensure_ascii=True,
    sort_keys=True,
    separators=(",", ":"),
).encode()
print(
    f"{len(entries)}:{file_count}:{symlink_count}:{total_bytes}:"
    f"sha256:{hashlib.sha256(encoded).hexdigest()}:{digest(entrypoint)}"
)
PY
)
if [ "$runtime_identity" != \
    "45860:45841:19:369443243:sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154:sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188" ]
then
    fail_activation "pinned OpenClaw runtime inventory changed"
fi

/usr/bin/python3.12 -I -S -B \
    /usr/libexec/aragorn/aragorn-runtime-action-worker-service.py \
    --activation-preflight \
    "$gateway_config" "$worker_binding" \
    "$gateway_uid" "$gateway_gid" "$worker_uid"
preflight_root=$(mktemp -d /run/aragorn-runtime-action-worker-preflight.XXXXXX)
chown "0:$gateway_gid" "$preflight_root"
chmod 0710 "$preflight_root"
install -d -o "$gateway_uid" -g "$gateway_gid" -m 0700 \
    "$preflight_root/home" "$preflight_root/state" "$preflight_root/tmp"
install -o 0 -g "$gateway_gid" -m 0440 \
    "$gateway_config" "$preflight_root/openclaw.json"
if ! /usr/bin/setpriv \
    --reuid="$gateway_uid" \
    --regid="$gateway_gid" \
    --clear-groups \
    --no-new-privs \
    /usr/bin/env -i \
    HOME="$preflight_root/home" \
    LANG=C \
    LC_ALL=C \
    NO_PROXY=127.0.0.1,localhost \
    OPENCLAW_CONFIG_PATH="$preflight_root/openclaw.json" \
    OPENCLAW_GATEWAY_TOKEN=00000000000000000000000000000000 \
    OPENCLAW_STATE_DIR="$preflight_root/state" \
    PATH=/usr/local/bin:/usr/bin:/bin \
    TMPDIR="$preflight_root/tmp" \
    TZ=UTC \
    /usr/local/bin/node \
    /runtime/lib/node_modules/openclaw/openclaw.mjs \
    config validate --json >/dev/null 2>&1
then
    fail_activation "gateway configuration failed OpenClaw validation"
fi
cleanup_preflight

gateway_root=/var/lib/aragorn-agent-gateway
if [ ! -e "$gateway_root" ] && [ ! -L "$gateway_root" ]; then
    install -d -o "$gateway_uid" -g "$gateway_gid" -m 0700 "$gateway_root"
fi
require_exact_directory "$gateway_root" "$gateway_uid" "$gateway_gid" 700
for directory in home state workspace
do
    path=$gateway_root/$directory
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        install -d -o "$gateway_uid" -g "$gateway_gid" -m 0700 "$path"
    fi
    require_exact_directory "$path" "$gateway_uid" "$gateway_gid" 700
done

unit_property()
{
    if ! property_value=$(/usr/bin/systemctl show "$1" --property="$2" --value); then
        fail_activation "cannot inspect effective $2 for $1"
    fi
    printf '%s' "$property_value"
}

require_unit_value()
{
    checked_unit=$1
    checked_property=$2
    checked_expected=$3
    if [ "$(unit_property "$checked_unit" "$checked_property")" != "$checked_expected" ]; then
        fail_activation "effective $checked_property is unsafe for $checked_unit"
    fi
}

require_unit_file()
{
    checked_unit=$1
    checked_digest=$2
    checked_path=$(unit_property "$checked_unit" FragmentPath)
    case "$checked_path" in
        "/usr/lib/systemd/system/$checked_unit"|"/lib/systemd/system/$checked_unit")
            ;;
        *)
            fail_activation "installed unit path is unsafe: $checked_unit"
            ;;
    esac
    checked_resolved=$(readlink -f -- "$checked_path" 2>/dev/null || :)
    if [ "$checked_resolved" != "/usr/lib/systemd/system/$checked_unit" ]; then
        fail_activation "installed unit path is unsafe: $checked_unit"
    fi
    if [ -L "$checked_path" ] || [ ! -f "$checked_path" ] \
        || [ "$(stat -c '%u:%g:%a:%h' -- "$checked_path")" != 0:0:644:1 ]
    then
        fail_activation "installed unit metadata is unsafe: $checked_unit"
    fi
    checked_actual=$(sha256sum -- "$checked_path")
    if [ "${checked_actual%% *}" != "$checked_digest" ]; then
        fail_activation "installed unit digest changed: $checked_unit"
    fi
}

verify_unit()
{
    verified_unit=$1
    verified_user=$2
    verified_group=$3
    verified_supplementary=$4
    verified_raw_command=$5
    verified_expanded_command=$6
    verified_credential=$7
    verified_object=$8

    verified_fragment=$(unit_property "$verified_unit" FragmentPath)
    case "$verified_fragment" in
        "/usr/lib/systemd/system/$verified_unit"|"/lib/systemd/system/$verified_unit")
            ;;
        *)
            fail_activation "effective FragmentPath is unsafe for $verified_unit"
            ;;
    esac
    verified_resolved=$(readlink -f -- "$verified_fragment" 2>/dev/null || :)
    if [ "$verified_resolved" != "/usr/lib/systemd/system/$verified_unit" ]; then
        fail_activation "effective FragmentPath is unsafe for $verified_unit"
    fi
    require_unit_value "$verified_unit" DropInPaths ""
    require_unit_value "$verified_unit" User "$verified_user"
    require_unit_value "$verified_unit" Group "$verified_group"
    require_unit_value "$verified_unit" SupplementaryGroups "$verified_supplementary"
    require_unit_value "$verified_unit" NoNewPrivileges yes
    require_unit_value "$verified_unit" AmbientCapabilities ""
    require_unit_value "$verified_unit" CapabilityBoundingSet ""
    require_unit_value "$verified_unit" PrivateMounts yes
    require_unit_value "$verified_unit" ProtectSystem strict

    verified_exec=$(unit_property "$verified_unit" ExecStart)
    verified_after_argv=${verified_exec#*"argv[]="}
    if [ "$verified_after_argv" = "$verified_exec" ]; then
        fail_activation "effective ExecStart is unsafe for $verified_unit"
    fi
    case "$verified_after_argv" in
        *"argv[]="*)
            fail_activation "multiple effective ExecStart commands exist for $verified_unit"
            ;;
    esac
    verified_argv=${verified_after_argv%% ; *}
    if [ "$verified_argv" != "$verified_raw_command" ] \
        && [ "$verified_argv" != "$verified_expanded_command" ]
    then
        fail_activation "effective ExecStart is unsafe for $verified_unit"
    fi

    if ! verified_credentials=$(
        /usr/bin/busctl get-property \
            org.freedesktop.systemd1 \
            "$verified_object" \
            org.freedesktop.systemd1.Service \
            LoadCredential
    ); then
        fail_activation "cannot inspect effective LoadCredential for $verified_unit"
    fi
    verified_name=${verified_credential%%:*}
    verified_source=${verified_credential#*:}
    if [ "$verified_credentials" != "a(ss) 1 \"$verified_name\" \"$verified_source\"" ]; then
        fail_activation "effective LoadCredential is unsafe for $verified_unit"
    fi
}

verify_process()
{
    verified_unit=$1
    verified_uid=$2
    verified_gid=$3
    verified_groups=$4
    verified_pid=$(unit_property "$verified_unit" MainPID)
    case "$verified_pid" in
        ""|0|*[!0-9]*)
            fail_activation "runtime worker service PID is invalid: $verified_unit"
            ;;
    esac
    status_path=/proc/$verified_pid/status
    if [ ! -r "$status_path" ]; then
        fail_activation "runtime worker service process is unavailable: $verified_unit"
    fi
    set -- $(awk '$1 == "Uid:" {print $2, $3, $4, $5}' "$status_path")
    if [ "$#" -ne 4 ] \
        || [ "$1" != "$verified_uid" ] \
        || [ "$2" != "$verified_uid" ] \
        || [ "$3" != "$verified_uid" ] \
        || [ "$4" != "$verified_uid" ]
    then
        fail_activation "runtime worker service UID changed: $verified_unit"
    fi
    set -- $(awk '$1 == "Gid:" {print $2, $3, $4, $5}' "$status_path")
    if [ "$#" -ne 4 ] \
        || [ "$1" != "$verified_gid" ] \
        || [ "$2" != "$verified_gid" ] \
        || [ "$3" != "$verified_gid" ] \
        || [ "$4" != "$verified_gid" ]
    then
        fail_activation "runtime worker service GID changed: $verified_unit"
    fi
    actual_groups=$(awk '$1 == "Groups:" {$1=""; sub(/^ /, ""); print}' "$status_path")
    if [ "$actual_groups" != "$verified_groups" ]; then
        fail_activation "runtime worker service groups changed: $verified_unit"
    fi
    if [ "$(awk '$1 == "CapEff:" {print $2}' "$status_path")" \
        != 0000000000000000 ] \
        || [ "$(awk '$1 == "NoNewPrivs:" {print $2}' "$status_path")" != 1 ]
    then
        fail_activation "runtime worker process privileges changed: $verified_unit"
    fi
}

wait_socket()
{
    waited_path=$1
    waited_uid=$2
    waited_gid=$3
    attempt=0
    while [ "$attempt" -lt 100 ]
    do
        attempt=$((attempt + 1))
        if [ -L "$waited_path" ]; then
            fail_activation "runtime worker endpoint is a symlink: $waited_path"
        fi
        if [ -S "$waited_path" ]; then
            if [ "$(stat -c '%F:%u:%g:%a:%h' -- "$waited_path")" \
                != "socket:$waited_uid:$waited_gid:660:1" ]
            then
                fail_activation "runtime worker endpoint metadata is unsafe: $waited_path"
            fi
            return
        fi
        sleep 0.1
    done
    fail_activation "runtime worker endpoint did not become ready: $waited_path"
}

verify_gateway_listener()
{
    gateway_pid=$(unit_property "$gateway_unit" MainPID)
    case "$gateway_pid" in
        ""|0|*[!0-9]*)
            fail_activation "gateway service PID is invalid"
            ;;
    esac
    attempt=0
    while [ "$attempt" -lt 300 ]
    do
        attempt=$((attempt + 1))
        if [ "$(unit_property "$gateway_unit" MainPID)" != "$gateway_pid" ]; then
            fail_activation "gateway service PID changed during readiness"
        fi
        listener_inodes=$(
            awk '$2 == "0100007F:4965" && $4 == "0A" {print $10}' \
                "/proc/$gateway_pid/net/tcp" 2>/dev/null || :
        )
        set -- $listener_inodes
        if [ "$#" -eq 1 ]
        then
            listener_inode=$1
            listener_owners=0
            for descriptor in /proc/$gateway_pid/fd/*
            do
                if [ "$(readlink "$descriptor" 2>/dev/null || :)" \
                    = "socket:[$listener_inode]" ]
                then
                    listener_owners=$((listener_owners + 1))
                fi
            done
            if [ "$listener_owners" -eq 1 ]; then
                return
            fi
        fi
        sleep 0.1
    done
    fail_activation "gateway listener is not owned by its MainPID"
}

/usr/bin/systemctl daemon-reload
require_unit_file \
    "$worker_unit" \
    e231978207dd27b71ef43449cf603ac424f6129f64c8a03dd0851ddf32503723
require_unit_file \
    "$gateway_unit" \
    32dea7dfdf5ccb9914c46ea2aadfc88a491d6eadba5bdb8b4982d473af1a0ebe
require_unit_file \
    "$broker_unit" \
    c43a81b394e0b96b0950af94b937a79e777d7e0c815a0104f1ab45871f4afa64
require_unit_file \
    "$sensor_unit" \
    d0f433abba94a4560c26cb99017f56543b432e2fc3aa74e3374ee4e04addeeaf
require_unit_file \
    aragorn-runtime-revocation-publisher.service \
    edac3cde6f441496320689edb5dd8ba202879c802dc877800cbd308be718e453
ARAGORN_RUNTIME_ACTIVATION_LOCK_HELD=1 "$base_activator"
/usr/bin/systemctl disable "$worker_unit" "$sensor_unit" "$broker_unit"
wait_socket "$broker_socket" "$broker_uid" "$sensor_gid"
wait_socket "$sensor_socket" "$sensor_uid" "$worker_gid"

verify_unit \
    "$worker_unit" \
    "$worker_user" \
    "$worker_user" \
    "$gateway_user" \
    "/usr/bin/python3.12 -I -S -B /usr/libexec/aragorn/aragorn-runtime-action-worker-service.py %d/worker-binding" \
    "/usr/bin/python3.12 -I -S -B /usr/libexec/aragorn/aragorn-runtime-action-worker-service.py /run/credentials/$worker_unit/worker-binding" \
    worker-binding:"$worker_binding" \
    /org/freedesktop/systemd1/unit/aragorn_2druntime_2daction_2dworker_2eservice
require_unit_value "$worker_unit" PrivateNetwork yes
require_unit_value "$worker_unit" RestrictAddressFamilies AF_UNIX

gateway_command="/usr/local/bin/node /runtime/lib/node_modules/openclaw/openclaw.mjs gateway run --auth token --bind loopback --port 18789 --tailscale off"
verify_unit \
    "$gateway_unit" \
    "$gateway_user" \
    "$gateway_user" \
    "" \
    "$gateway_command" \
    "$gateway_command" \
    openclaw-config:"$gateway_config" \
    /org/freedesktop/systemd1/unit/aragorn_2dagent_2dgateway_2eservice
require_unit_value "$gateway_unit" PrivateNetwork no
require_unit_value "$gateway_unit" RestrictAddressFamilies "AF_INET AF_INET6 AF_UNIX"
require_unit_value \
    "$gateway_unit" \
    EnvironmentFiles \
    "$gateway_environment (ignore_errors=no)"

/usr/bin/systemctl start "$worker_unit"
wait_socket "$worker_socket" "$worker_uid" "$gateway_gid"
require_exact_directory "$worker_runtime" "$worker_uid" "$gateway_gid" 711

/usr/bin/systemctl start "$gateway_unit"
require_unit_value "$broker_unit" ActiveState active
require_unit_value "$sensor_unit" ActiveState active
require_unit_value "$worker_unit" ActiveState active
require_unit_value "$gateway_unit" ActiveState active

if [ "$gateway_gid" -lt "$worker_gid" ]; then
    worker_groups="$gateway_gid $worker_gid"
else
    worker_groups="$worker_gid $gateway_gid"
fi
verify_gateway_listener
verify_process "$worker_unit" "$worker_uid" "$worker_gid" "$worker_groups"
verify_process "$gateway_unit" "$gateway_uid" "$gateway_gid" "$gateway_gid"

for unit in "$worker_unit" "$sensor_unit" "$broker_unit"
do
    if [ "$(/usr/bin/systemctl is-enabled "$unit" 2>/dev/null || :)" != disabled ]; then
        fail_activation "runtime worker service retained boot authority: $unit"
    fi
done
if [ "$(/usr/bin/systemctl is-enabled "$gateway_unit" 2>/dev/null || :)" \
    != static ]
then
    fail_activation "gateway retained boot authority"
fi

armed=0
cleanup_preflight
trap - EXIT HUP INT TERM
