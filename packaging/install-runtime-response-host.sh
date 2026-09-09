#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destdir=${DESTDIR:-}
DESTDIR=$destdir "$root/packaging/install-runtime-action-worker-host.sh"

install -m 0644 \
    "$root/src/aragorn/runtime_response_service.py" \
    "$destdir/usr/lib/aragorn/aragorn/"
install -m 0755 \
    "$root/packaging/libexec/aragorn-runtime-response-service.py" \
    "$destdir/usr/libexec/aragorn/"
