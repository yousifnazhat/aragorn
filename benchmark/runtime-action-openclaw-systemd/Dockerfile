ARG SYSTEMD_BASE=aragorn-p33b-systemd

FROM node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf AS node-runtime

FROM ${SYSTEMD_BASE}

COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY packaging/openclaw/aragorn-runtime-action /src/packaging/openclaw/aragorn-runtime-action
COPY packaging/openclaw/aragorn-runtime-action /opt/aragorn/openclaw/aragorn-runtime-action
COPY scripts/runtime_action_openclaw_systemd_probe.py /src/scripts/runtime_action_openclaw_systemd_probe.py
COPY scripts/capture_runtime_action_openclaw_systemd.sh /src/scripts/capture_runtime_action_openclaw_systemd.sh
COPY benchmark/runtime-action-openclaw-systemd/openclaw-probe.mjs \
    /src/benchmark/runtime-action-openclaw-systemd/openclaw-probe.mjs
COPY benchmark/runtime-action-openclaw-systemd/Dockerfile \
    /src/benchmark/runtime-action-openclaw-systemd/Dockerfile
COPY root.dockerignore /src/.dockerignore

RUN test "$(/usr/local/bin/node --version)" = "v24.16.0" \
    && chmod -R a-w /opt/aragorn/openclaw/aragorn-runtime-action
