#!/bin/sh
set -eu

PATH=/usr/bin:/bin
export PATH

if [ "$(id -u)" -ne 0 ] || [ ! -x /usr/bin/systemctl ]; then
    echo "Aragorn runtime capability activation requires root and systemd" >&2
    exit 1
fi

for path in \
    /etc/aragorn/runtime-action-runtime.json \
    /etc/aragorn/runtime-action-observation.json \
    /etc/aragorn/runtime-capability-lease.json \
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

/usr/bin/systemctl daemon-reload
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
