#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
"$root/packaging/install-runtime-action-host.sh"

destdir=${DESTDIR:-}
install -m 0644 \
    "$root/src/aragorn/runtime_process_profile.py" \
    "$root/src/aragorn/runtime_action_broker_v2.py" \
    "$root/src/aragorn/runtime_action_observation_publisher_v2.py" \
    "$root/src/aragorn/runtime_action_service_v2.py" \
    "$root/src/aragorn/runtime_observation_service_v2.py" \
    "$destdir/usr/lib/aragorn/aragorn/"
install -m 0755 \
    "$root/packaging/libexec/aragorn-runtime-action-service-v2.py" \
    "$root/packaging/libexec/aragorn-runtime-observation-service-v2.py" \
    "$destdir/usr/libexec/aragorn/"
install -m 0644 \
    "$root/packaging/systemd/aragorn-runtime-profile-action-broker.service" \
    "$root/packaging/systemd/aragorn-runtime-profile-observation-publisher.service" \
    "$destdir/usr/lib/systemd/system/"
