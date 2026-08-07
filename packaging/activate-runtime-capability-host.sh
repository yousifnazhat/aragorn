#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH

if [ "$(id -u)" -ne 0 ] || [ ! -x /usr/bin/systemctl ] \
    || [ ! -x /usr/bin/busctl ]
then
    echo "Aragorn runtime capability activation requires root and systemd" >&2
    exit 1
fi

fail_activation()
{
    echo "$1" >&2
    exit 1
}

require_safe_root_directory()
{
    authority_path=$1
    if [ -L "$authority_path" ] || [ ! -d "$authority_path" ]; then
        fail_activation "runtime capability authority ancestry is unsafe: $authority_path"
    fi
    if ! authority_metadata=$(stat -c '%u:%g:%a' -- "$authority_path"); then
        fail_activation "runtime capability authority ancestry cannot be inspected: $authority_path"
    fi
    authority_uid=${authority_metadata%%:*}
    authority_remainder=${authority_metadata#*:}
    authority_gid=${authority_remainder%%:*}
    authority_mode=${authority_remainder##*:}
    if [ "$authority_uid" != 0 ] || [ "$authority_gid" != 0 ]; then
        fail_activation "runtime capability authority ancestry is not root-owned: $authority_path"
    fi
    case "$authority_mode" in
        *[2367][0-7]|*[2367])
            fail_activation "runtime capability authority ancestry is writable: $authority_path"
            ;;
    esac
}

grant_path=/etc/aragorn/runtime-capability-grant.json
require_safe_root_directory /
require_safe_root_directory /etc
require_safe_root_directory /etc/aragorn
if [ -L "$grant_path" ] || [ ! -f "$grant_path" ]; then
    fail_activation "runtime capability grant is not a regular non-symlink file"
fi
if ! grant_metadata=$(stat -c '%u:%g:%a:%h' -- "$grant_path"); then
    fail_activation "runtime capability grant cannot be inspected"
fi
if [ "$grant_metadata" != "0:0:400:1" ]; then
    fail_activation "runtime capability grant must be root:root mode 0400 with one link"
fi

for path in \
    /etc/aragorn/runtime-action-runtime.json \
    /etc/aragorn/runtime-action-observation.json \
    "$grant_path" \
    /var/lib/aragorn-runtime-action/control/policy.json \
    /var/lib/aragorn-runtime-action/control/revocations.json \
    /var/lib/aragorn-runtime-action/control/health.json \
    /var/lib/aragorn-runtime-action/control/observation.json \
    /var/lib/aragorn-runtime-action/control/state.json
do
    if [ ! -f "$path" ]; then
        echo "missing runtime capability prerequisite: $path" >&2
        exit 1
    fi
done

old_units="
aragorn-runtime-action-broker.service
aragorn-runtime-profile-action-broker.service
aragorn-runtime-observation-publisher.service
aragorn-runtime-profile-observation-publisher.service
"
new_broker=aragorn-runtime-capability-action-broker.service
new_sensor=aragorn-runtime-capability-observation-publisher.service

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
    checked_value=$(unit_property "$checked_unit" "$checked_property")
    if [ "$checked_value" != "$checked_expected" ]; then
        fail_activation "effective $checked_property is unsafe for $checked_unit"
    fi
}

verify_effective_unit()
{
    verified_unit=$1
    verified_user=$2
    verified_group=$3
    verified_supplementary_group=$4
    verified_raw_command=$5
    verified_expanded_command=$6
    verified_first_credential=$7
    verified_second_credential=$8
    verified_object_path=$9

    verified_fragment=$(unit_property "$verified_unit" FragmentPath)
    case "$verified_fragment" in
        "/usr/lib/systemd/system/$verified_unit"|"/lib/systemd/system/$verified_unit")
            ;;
        *)
            fail_activation "effective FragmentPath is unsafe for $verified_unit"
            ;;
    esac
    require_unit_value "$verified_unit" DropInPaths ""
    require_unit_value "$verified_unit" User "$verified_user"
    require_unit_value "$verified_unit" Group "$verified_group"
    require_unit_value \
        "$verified_unit" SupplementaryGroups "$verified_supplementary_group"

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
            "$verified_object_path" \
            org.freedesktop.systemd1.Service \
            LoadCredential
    ); then
        fail_activation "cannot inspect effective LoadCredential for $verified_unit"
    fi
    verified_first_name=${verified_first_credential%%:*}
    verified_first_source=${verified_first_credential#*:}
    verified_second_name=${verified_second_credential%%:*}
    verified_second_source=${verified_second_credential#*:}
    verified_expected_credentials="a(ss) 2 \"$verified_first_name\" \"$verified_first_source\" \"$verified_second_name\" \"$verified_second_source\""
    verified_reverse_credentials="a(ss) 2 \"$verified_second_name\" \"$verified_second_source\" \"$verified_first_name\" \"$verified_first_source\""
    case "$verified_credentials" in
        "$verified_expected_credentials"|"$verified_reverse_credentials")
            ;;
        *)
            fail_activation "effective LoadCredential is unsafe for $verified_unit"
            ;;
    esac
}

/usr/bin/systemctl daemon-reload
/usr/bin/systemctl disable --now "$new_sensor" "$new_broker"
if /usr/bin/systemctl is-active --quiet "$new_sensor" \
    || /usr/bin/systemctl is-active --quiet "$new_broker"
then
    fail_activation "previous runtime capability route remained active"
fi
for unit in $old_units
do
    if /usr/bin/systemctl cat "$unit" >/dev/null 2>&1; then
        /usr/bin/systemctl disable --now "$unit"
        /usr/bin/systemctl mask "$unit"
        if [ "$(/usr/bin/systemctl is-enabled "$unit")" != masked ]; then
            echo "legacy runtime route was not masked: $unit" >&2
            exit 1
        fi
    fi
done

/usr/bin/systemctl unmask "$new_broker" "$new_sensor"
/usr/bin/systemctl daemon-reload
verify_effective_unit \
    "$new_broker" \
    aragorn-broker \
    aragorn-runtime \
    aragorn-sensor \
    "/usr/bin/python3.12 -I -S -B /usr/libexec/aragorn/aragorn-runtime-action-service-v4.py %d/runtime-binding %d/capability-grant" \
    "/usr/bin/python3.12 -I -S -B /usr/libexec/aragorn/aragorn-runtime-action-service-v4.py /run/credentials/$new_broker/runtime-binding /run/credentials/$new_broker/capability-grant" \
    runtime-binding:/etc/aragorn/runtime-action-runtime.json \
    capability-grant:/etc/aragorn/runtime-capability-grant.json \
    /org/freedesktop/systemd1/unit/aragorn_2druntime_2dcapability_2daction_2dbroker_2eservice
verify_effective_unit \
    "$new_sensor" \
    aragorn-sensor \
    aragorn-sensor \
    aragorn-runtime \
    "/usr/bin/python3.12 -I -S -B /usr/libexec/aragorn/aragorn-runtime-observation-service-v3.py %d/observation-binding %d/capability-grant" \
    "/usr/bin/python3.12 -I -S -B /usr/libexec/aragorn/aragorn-runtime-observation-service-v3.py /run/credentials/$new_sensor/observation-binding /run/credentials/$new_sensor/capability-grant" \
    observation-binding:/etc/aragorn/runtime-action-observation.json \
    capability-grant:/etc/aragorn/runtime-capability-grant.json \
    /org/freedesktop/systemd1/unit/aragorn_2druntime_2dcapability_2dobservation_2dpublisher_2eservice
/usr/bin/systemctl enable --now "$new_broker"
/usr/bin/systemctl enable --now "$new_sensor"
/usr/bin/systemctl is-active --quiet "$new_broker"
/usr/bin/systemctl is-active --quiet "$new_sensor"
for unit in $old_units
do
    if /usr/bin/systemctl is-active --quiet "$unit"; then
        echo "legacy runtime route remained active: $unit" >&2
        exit 1
    fi
done
