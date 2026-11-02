#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destdir=${DESTDIR:-}
DESTDIR=$destdir "$root/packaging/install-runtime-action-worker-host.sh"
install -d -m 0700 "$destdir/var/lib/aragorn-runtime-response"

install -m 0644 \
    "$root/src/aragorn/runtime_response_service.py" \
    "$root/src/aragorn/runtime_health_service.py" \
    "$destdir/usr/lib/aragorn/aragorn/"
install -m 0755 \
    "$root/packaging/libexec/aragorn-runtime-response-service.py" \
    "$root/packaging/libexec/aragorn-runtime-health-service.py" \
    "$destdir/usr/libexec/aragorn/"
install -d -m 0755 "$destdir/usr/lib/systemd/system" "$destdir/usr/share/aragorn/systemd"
install -m 0644 \
    "$root/packaging/systemd/aragorn-runtime-revocation-response.service" \
    "$root/packaging/systemd/aragorn-runtime-health-publisher.service" \
    "$root/packaging/systemd/aragorn-runtime-health-response.service" \
    "$destdir/usr/lib/systemd/system/"
install -m 0644 \
    "$root/packaging/systemd/50-runtime-response.conf" \
    "$root/packaging/systemd/50-runtime-health-response.conf" \
    "$destdir/usr/share/aragorn/systemd/"
