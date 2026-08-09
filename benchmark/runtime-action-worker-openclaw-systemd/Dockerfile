ARG WORKER_BASE

FROM ${WORKER_BASE}

ARG WORKER_BASE

COPY packaging/install-runtime-action-worker-host.sh \
    packaging/install-runtime-capability-host.sh \
    /src/packaging/
COPY packaging/activate-runtime-capability-host.sh \
    /src/packaging/
COPY packaging/libexec/ \
    /src/packaging/libexec/
COPY packaging/systemd/aragorn-agent-gateway.service \
    packaging/systemd/aragorn-runtime-action-worker.service \
    packaging/systemd/aragorn-runtime-action-worker.sysusers \
    /src/packaging/systemd/
COPY packaging/openclaw/aragorn-runtime-action-worker/ \
    /src/packaging/openclaw/aragorn-runtime-action-worker/
COPY src/aragorn/runtime_action_worker.py \
    /src/src/aragorn/
COPY benchmark/runtime-action-worker-openclaw-systemd/ \
    /src/benchmark/runtime-action-worker-openclaw-systemd/
COPY scripts/runtime_action_worker_openclaw_systemd_probe.py \
    scripts/capture_runtime_action_worker_openclaw_systemd.sh \
    /src/scripts/

# WORKER_BASE carries P3.6b's exact source/install closure. Check that closure
# before its inherited installer is reused; no earlier evidence document is an
# input to this child.
RUN set -eux; \
    test "$WORKER_BASE" = "sha256:e0992ea8995a7ce1f537d6372cb78febab8761edbcbfc06e07b6c096c65ca16f"; \
    test "$(sha256sum /usr/local/bin/node | cut -d ' ' -f 1)" = \
        "3a988781edde7f1c76751f771cf402e0866fb4a81fbcd0852a2ce2f5bd2ccd37"; \
    for installed in /usr/lib/aragorn/aragorn/*.py; do \
        source="/src/src/aragorn/${installed##*/}"; \
        test -f "$source"; \
        cmp "$source" "$installed"; \
    done; \
    for installed in /usr/libexec/aragorn/*; do \
        case "${installed##*/}" in \
            activate-runtime-capability-host.sh) \
                source=/src/packaging/activate-runtime-capability-host.sh ;; \
            *) source="/src/packaging/libexec/${installed##*/}" ;; \
        esac; \
        test -f "$source"; \
        cmp "$source" "$installed"; \
    done; \
    sh /src/packaging/install-runtime-action-worker-host.sh; \
    systemd-sysusers \
        /usr/lib/sysusers.d/aragorn-runtime-action-worker.conf; \
    systemd-analyze verify \
        /usr/lib/systemd/system/aragorn-runtime-action-worker.service \
        /usr/lib/systemd/system/aragorn-agent-gateway.service; \
    test "$(sha256sum /src/packaging/systemd/aragorn-agent-gateway.service | cut -d ' ' -f 1)" = \
        "32dea7dfdf5ccb9914c46ea2aadfc88a491d6eadba5bdb8b4982d473af1a0ebe"; \
    test "$(sha256sum /src/packaging/systemd/aragorn-runtime-action-worker.service | cut -d ' ' -f 1)" = \
        "e231978207dd27b71ef43449cf603ac424f6129f64c8a03dd0851ddf32503723"; \
    grep -Fx 'Requires=aragorn-runtime-action-worker.service' \
        /src/packaging/systemd/aragorn-agent-gateway.service; \
    grep -Fx 'SupplementaryGroups=' \
        /src/packaging/systemd/aragorn-agent-gateway.service; \
    grep -Fx 'LoadCredential=openclaw-config:/etc/aragorn/agent-gateway/openclaw.json' \
        /src/packaging/systemd/aragorn-agent-gateway.service; \
    grep -Fx 'ExecStart=/usr/local/bin/node /runtime/lib/node_modules/openclaw/openclaw.mjs gateway run --auth token --bind loopback --port 18789 --tailscale off' \
        /src/packaging/systemd/aragorn-agent-gateway.service; \
    grep -Fx 'ReadWritePaths=/var/lib/aragorn-agent-gateway' \
        /src/packaging/systemd/aragorn-agent-gateway.service; \
    grep -Fx 'IPAddressDeny=any' \
        /src/packaging/systemd/aragorn-agent-gateway.service; \
    grep -Fx 'IPAddressAllow=localhost' \
        /src/packaging/systemd/aragorn-agent-gateway.service; \
    ! grep -Eq '^\[Install\]$|^WantedBy=|^PrivateNetwork=|^MemoryDenyWriteExecute=' \
        /src/packaging/systemd/aragorn-agent-gateway.service; \
    grep -Fx 'SupplementaryGroups=aragorn-agent-gateway' \
        /src/packaging/systemd/aragorn-runtime-action-worker.service; \
    grep -Fx 'LoadCredential=worker-binding:/etc/aragorn/runtime-action-worker.json' \
        /src/packaging/systemd/aragorn-runtime-action-worker.service; \
    grep -Fx 'ExecStart=/usr/bin/python3.12 -I -S -B /usr/libexec/aragorn/aragorn-runtime-action-worker-service.py %d/worker-binding' \
        /src/packaging/systemd/aragorn-runtime-action-worker.service; \
    grep -Fx 'PrivateNetwork=yes' \
        /src/packaging/systemd/aragorn-runtime-action-worker.service; \
    grep -Fx 'MemoryDenyWriteExecute=yes' \
        /src/packaging/systemd/aragorn-runtime-action-worker.service; \
    grep -Fx '[Install]' \
        /src/packaging/systemd/aragorn-runtime-action-worker.service; \
    grep -Fx 'WantedBy=multi-user.target' \
        /src/packaging/systemd/aragorn-runtime-action-worker.service; \
    test "$(sha256sum /src/benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs | cut -d ' ' -f 1)" = \
        "e6e1803e9593d8c1bcb1ad4a3fdf2cb5c3657f1b4bd06e65470b8ad16e9e0140"; \
    test "$(sha256sum /src/packaging/openclaw/aragorn-runtime-action-worker/index.js | cut -d ' ' -f 1)" = \
        "71dfcdc6d2f1d51472230e9cda240c25d0b316fee39434e6761bb2e7b411467b"; \
    test "$(/usr/local/bin/node --version)" = "v24.16.0"; \
    /usr/local/bin/node --check \
        /src/benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs; \
    /usr/local/bin/node --check \
        /usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/index.js; \
    cmp \
        /src/src/aragorn/runtime_action_worker.py \
        /usr/lib/aragorn/aragorn/runtime_action_worker.py; \
    cmp \
        /src/packaging/libexec/aragorn-runtime-action-worker-service.py \
        /usr/libexec/aragorn/aragorn-runtime-action-worker-service.py; \
    cmp \
        /src/packaging/systemd/aragorn-agent-gateway.service \
        /usr/lib/systemd/system/aragorn-agent-gateway.service; \
    cmp \
        /src/packaging/systemd/aragorn-runtime-action-worker.service \
        /usr/lib/systemd/system/aragorn-runtime-action-worker.service; \
    cmp \
        /src/packaging/systemd/aragorn-runtime-action-worker.sysusers \
        /usr/lib/sysusers.d/aragorn-runtime-action-worker.conf; \
    for name in index.js openclaw.plugin.json package.json; do \
        cmp \
            "/src/packaging/openclaw/aragorn-runtime-action-worker/$name" \
            "/usr/lib/aragorn/openclaw/aragorn-runtime-action-worker/$name"; \
    done; \
    for installed in /usr/lib/aragorn/aragorn/*.py; do \
        source="/src/src/aragorn/${installed##*/}"; \
        test -f "$source"; \
        cmp "$source" "$installed"; \
    done; \
    for installed in /usr/libexec/aragorn/*; do \
        case "${installed##*/}" in \
            activate-runtime-capability-host.sh) \
                source=/src/packaging/activate-runtime-capability-host.sh ;; \
            *) source="/src/packaging/libexec/${installed##*/}" ;; \
        esac; \
        test -f "$source"; \
        cmp "$source" "$installed"; \
    done; \
    chmod 0555 \
        /src/packaging/activate-runtime-capability-host.sh \
        /src/packaging/install-runtime-action-worker-host.sh \
        /src/benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs \
        /src/scripts/runtime_action_worker_openclaw_systemd_probe.py \
        /src/scripts/capture_runtime_action_worker_openclaw_systemd.sh; \
    chmod 0444 \
        /src/benchmark/runtime-action-worker-openclaw-systemd/Dockerfile \
        /src/packaging/libexec/aragorn-runtime-action-worker-service.py \
        /src/packaging/openclaw/aragorn-runtime-action-worker/index.js \
        /src/packaging/openclaw/aragorn-runtime-action-worker/openclaw.plugin.json \
        /src/packaging/openclaw/aragorn-runtime-action-worker/package.json \
        /src/packaging/systemd/aragorn-agent-gateway.service \
        /src/packaging/systemd/aragorn-runtime-action-worker.service \
        /src/packaging/systemd/aragorn-runtime-action-worker.sysusers \
        /src/src/aragorn/runtime_action_worker.py
