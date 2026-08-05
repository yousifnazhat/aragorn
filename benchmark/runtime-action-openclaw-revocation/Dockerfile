ARG OPENCLAW_BASE

FROM ${OPENCLAW_BASE}

COPY scripts/runtime_action_openclaw_revocation_probe.py \
    /src/scripts/runtime_action_openclaw_revocation_probe.py
COPY scripts/capture_runtime_action_openclaw_revocation.sh \
    /src/scripts/capture_runtime_action_openclaw_revocation.sh
COPY benchmark/runtime-action-openclaw-revocation/Dockerfile \
    /src/benchmark/runtime-action-openclaw-revocation/Dockerfile

RUN chmod 0555 \
        /src/scripts/runtime_action_openclaw_revocation_probe.py \
        /src/scripts/capture_runtime_action_openclaw_revocation.sh \
    && chmod 0444 \
        /src/benchmark/runtime-action-openclaw-revocation/Dockerfile
