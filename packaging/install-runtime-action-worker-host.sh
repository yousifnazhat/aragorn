#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destdir=${DESTDIR:-}
DESTDIR=$destdir "$root/packaging/install-runtime-capability-host.sh"

plugin_root="$destdir/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker"
install -d -m 0755 \
    "$destdir/usr/lib/aragorn/openclaw" \
    "$plugin_root"
install -m 0644 \
    "$root/src/aragorn/runtime_action_worker.py" \
    "$destdir/usr/lib/aragorn/aragorn/"
install -m 0755 \
    "$root/packaging/activate-runtime-action-worker-host.sh" \
    "$root/packaging/libexec/aragorn-runtime-action-worker-service.py" \
    "$destdir/usr/libexec/aragorn/"
install -m 0644 \
    "$root/packaging/systemd/aragorn-agent-gateway.service" \
    "$root/packaging/systemd/aragorn-runtime-action-worker.service" \
    "$destdir/usr/lib/systemd/system/"
install -m 0644 \
    "$root/packaging/systemd/aragorn-runtime-action-worker.sysusers" \
    "$destdir/usr/lib/sysusers.d/aragorn-runtime-action-worker.conf"
install -m 0644 \
    "$root/packaging/openclaw/aragorn-runtime-action-worker/index.js" \
    "$root/packaging/openclaw/aragorn-runtime-action-worker/openclaw.plugin.json" \
    "$root/packaging/openclaw/aragorn-runtime-action-worker/package.json" \
    "$plugin_root/"
