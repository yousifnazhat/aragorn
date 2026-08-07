#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destdir=${DESTDIR:-}
if [ -z "$destdir" ] && [ ! -x /usr/bin/python3.12 ]; then
    echo "Aragorn runtime capability mediation requires /usr/bin/python3.12" >&2
    exit 1
fi

install -d -m 0755 \
    "$destdir/usr/lib/aragorn/aragorn" \
    "$destdir/usr/libexec/aragorn" \
    "$destdir/usr/lib/systemd/system" \
    "$destdir/usr/lib/sysusers.d" \
    "$destdir/usr/lib/tmpfiles.d"
for obsolete_shim in \
    aragorn-runtime-action-service.py \
    aragorn-runtime-action-service-v2.py \
    aragorn-runtime-action-service-v3.py \
    aragorn-runtime-observation-service.py \
    aragorn-runtime-observation-service-v2.py
do
    rm -f -- "$destdir/usr/libexec/aragorn/$obsolete_shim"
done
install -m 0644 \
    "$root/src/aragorn/__init__.py" \
    "$root/src/aragorn/oci_worker_protocol.py" \
    "$root/src/aragorn/runtime_action_decision.py" \
    "$root/src/aragorn/runtime_action_broker.py" \
    "$root/src/aragorn/runtime_action_observation_publisher.py" \
    "$root/src/aragorn/runtime_action_service.py" \
    "$root/src/aragorn/runtime_observation_service.py" \
    "$root/src/aragorn/runtime_process_profile.py" \
    "$root/src/aragorn/runtime_action_broker_v2.py" \
    "$root/src/aragorn/runtime_action_observation_publisher_v2.py" \
    "$root/src/aragorn/runtime_action_service_v2.py" \
    "$root/src/aragorn/runtime_observation_service_v2.py" \
    "$root/src/aragorn/runtime_action_broker_v3.py" \
    "$root/src/aragorn/runtime_capability_grant.py" \
    "$root/src/aragorn/runtime_action_observation_publisher_v3.py" \
    "$root/src/aragorn/runtime_action_broker_v4.py" \
    "$root/src/aragorn/runtime_action_service_v4.py" \
    "$root/src/aragorn/runtime_observation_service_v3.py" \
    "$destdir/usr/lib/aragorn/aragorn/"
install -m 0755 \
    "$root/packaging/activate-runtime-capability-host.sh" \
    "$root/packaging/libexec/aragorn-runtime-action-service-v4.py" \
    "$root/packaging/libexec/aragorn-runtime-observation-service-v3.py" \
    "$destdir/usr/libexec/aragorn/"
install -m 0644 \
    "$root/packaging/systemd/aragorn-gateway.sysusers" \
    "$destdir/usr/lib/sysusers.d/aragorn-gateway.conf"
install -m 0644 \
    "$root/packaging/systemd/aragorn-runtime-action.tmpfiles" \
    "$destdir/usr/lib/tmpfiles.d/aragorn-runtime-action.conf"
install -m 0644 \
    "$root/packaging/systemd/aragorn-runtime-capability-action-broker.service" \
    "$root/packaging/systemd/aragorn-runtime-capability-observation-publisher.service" \
    "$destdir/usr/lib/systemd/system/"
