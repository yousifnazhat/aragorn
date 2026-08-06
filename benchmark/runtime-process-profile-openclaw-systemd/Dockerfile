ARG PROFILE_BASE

FROM node@sha256:242549cd46785b480c832479a730f4f2a20865d61ea2e404fdb2a5c3d3b73ecf AS node-runtime

FROM ${PROFILE_BASE}

COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY packaging/openclaw/aragorn-runtime-action \
    /src/packaging/openclaw/aragorn-runtime-action
COPY packaging/openclaw/aragorn-runtime-action \
    /opt/aragorn/openclaw/aragorn-runtime-action
COPY benchmark/runtime-process-profile-openclaw-systemd/ \
    /src/benchmark/runtime-process-profile-openclaw-systemd/
COPY scripts/runtime_action_openclaw_systemd_probe.py \
    scripts/runtime_process_profile_openclaw_systemd_probe.py \
    scripts/capture_runtime_process_profile_openclaw_systemd.sh \
    /src/scripts/

RUN test "$(/usr/local/bin/node --version)" = "v24.16.0" \
    && install -d -m 0555 \
        /etc/aragorn/openclaw-profile \
        /opt/aragorn/runtime-profile/aragorn-runtime-composition \
    && install -m 0444 \
        /src/benchmark/runtime-process-profile-openclaw-systemd/SKILL.md \
        /opt/aragorn/runtime-profile/aragorn-runtime-composition/SKILL.md \
    && install -m 0644 \
        /src/benchmark/runtime-process-profile-openclaw-systemd/aragorn-openclaw-profile.service \
        /usr/lib/systemd/system/aragorn-openclaw-profile.service \
    && install -d -m 0700 -o aragorn-runtime -g aragorn-runtime \
        /var/lib/aragorn-openclaw-profile \
        /var/lib/aragorn-openclaw-profile/home \
        /var/lib/aragorn-openclaw-profile/state \
        /var/lib/aragorn-openclaw-profile/workspace \
    && chmod -R a-w /opt/aragorn/openclaw/aragorn-runtime-action \
    && chmod 0555 \
        /src/benchmark/runtime-process-profile-openclaw-systemd/openclaw-profile-driver.mjs \
        /src/scripts/runtime_action_openclaw_systemd_probe.py \
        /src/scripts/runtime_process_profile_openclaw_systemd_probe.py \
        /src/scripts/capture_runtime_process_profile_openclaw_systemd.sh \
    && chmod 0444 \
        /src/benchmark/runtime-process-profile-openclaw-systemd/Dockerfile \
        /src/benchmark/runtime-process-profile-openclaw-systemd/SKILL.md \
        /src/benchmark/runtime-process-profile-openclaw-systemd/aragorn-openclaw-profile.service \
        /usr/lib/systemd/system/aragorn-openclaw-profile.service \
    && cmp \
        /src/packaging/openclaw/aragorn-runtime-action/index.js \
        /opt/aragorn/openclaw/aragorn-runtime-action/index.js \
    && cmp \
        /src/packaging/openclaw/aragorn-runtime-action/openclaw.plugin.json \
        /opt/aragorn/openclaw/aragorn-runtime-action/openclaw.plugin.json \
    && cmp \
        /src/packaging/openclaw/aragorn-runtime-action/package.json \
        /opt/aragorn/openclaw/aragorn-runtime-action/package.json
