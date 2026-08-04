#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destdir=${DESTDIR:-}
if [ -z "$destdir" ] && [ ! -x /usr/bin/python3.12 ]; then
    echo "Aragorn runtime action requires /usr/bin/python3.12" >&2
    exit 1
fi

install -d -m 0755 \
    "$destdir/usr/lib/aragorn/aragorn" \
    "$destdir/usr/libexec/aragorn" \
    "$destdir/usr/lib/systemd/system" \
    "$destdir/usr/lib/sysusers.d" \
    "$destdir/usr/lib/tmpfiles.d"
install -m 0644 \
    "$root/src/aragorn/__init__.py" \
    "$root/src/aragorn/oci_worker_protocol.py" \
    "$root/src/aragorn/runtime_action_broker.py" \
    "$root/src/aragorn/runtime_action_decision.py" \
    "$root/src/aragorn/runtime_action_observation_publisher.py" \
    "$root/src/aragorn/runtime_observation_service.py" \
    "$root/src/aragorn/runtime_action_service.py" \
    "$destdir/usr/lib/aragorn/aragorn/"
install -m 0755 \
    "$root/packaging/libexec/aragorn-runtime-action-service.py" \
    "$root/packaging/libexec/aragorn-runtime-observation-service.py" \
    "$destdir/usr/libexec/aragorn/"
install -m 0644 \
    "$root/packaging/systemd/aragorn-gateway.sysusers" \
    "$destdir/usr/lib/sysusers.d/aragorn-gateway.conf"
install -m 0644 \
    "$root/packaging/systemd/aragorn-runtime-action.tmpfiles" \
    "$destdir/usr/lib/tmpfiles.d/aragorn-runtime-action.conf"
install -m 0644 \
    "$root/packaging/systemd/aragorn-runtime-action-broker.service" \
    "$root/packaging/systemd/aragorn-runtime-observation-publisher.service" \
    "$destdir/usr/lib/systemd/system/"
