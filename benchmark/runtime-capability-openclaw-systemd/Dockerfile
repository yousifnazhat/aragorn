ARG CAPABILITY_BASE

FROM ${CAPABILITY_BASE}

COPY packaging/install-runtime-capability-host.sh \
    packaging/activate-runtime-capability-host.sh \
    /src/packaging/
COPY packaging/libexec/aragorn-runtime-action-service-v4.py \
    packaging/libexec/aragorn-runtime-observation-service-v3.py \
    /src/packaging/libexec/
COPY packaging/systemd/aragorn-runtime-capability-action-broker.service \
    packaging/systemd/aragorn-runtime-capability-observation-publisher.service \
    /src/packaging/systemd/
COPY src/aragorn/runtime_action_broker_v3.py \
    src/aragorn/runtime_capability_grant.py \
    src/aragorn/runtime_action_observation_publisher_v3.py \
    src/aragorn/runtime_action_broker_v4.py \
    src/aragorn/runtime_action_service_v4.py \
    src/aragorn/runtime_observation_service_v3.py \
    /src/src/aragorn/
COPY benchmark/runtime-capability-openclaw-systemd/Dockerfile \
    /src/benchmark/runtime-capability-openclaw-systemd/Dockerfile
COPY scripts/runtime_capability_openclaw_systemd_probe.py \
    scripts/capture_runtime_capability_openclaw_systemd.sh \
    /src/scripts/

RUN sh /src/packaging/install-runtime-capability-host.sh \
    && test "$(/usr/local/bin/node --version)" = "v24.16.0" \
    && test -x \
        /src/benchmark/runtime-process-profile-openclaw-systemd/openclaw-profile-driver.mjs \
    && test -f \
        /usr/lib/systemd/system/aragorn-openclaw-profile.service \
    && test -f \
        /opt/aragorn/runtime-profile/aragorn-runtime-composition/SKILL.md \
    && test -f \
        /opt/aragorn/openclaw/aragorn-runtime-action/index.js \
    && chmod 0555 \
        /src/packaging/install-runtime-capability-host.sh \
        /src/packaging/activate-runtime-capability-host.sh \
        /src/scripts/runtime_capability_openclaw_systemd_probe.py \
        /src/scripts/capture_runtime_capability_openclaw_systemd.sh \
    && chmod 0444 \
        /src/benchmark/runtime-capability-openclaw-systemd/Dockerfile \
        /src/packaging/libexec/aragorn-runtime-action-service-v4.py \
        /src/packaging/libexec/aragorn-runtime-observation-service-v3.py \
        /src/packaging/systemd/aragorn-runtime-capability-action-broker.service \
        /src/packaging/systemd/aragorn-runtime-capability-observation-publisher.service \
        /src/src/aragorn/runtime_action_broker_v3.py \
        /src/src/aragorn/runtime_capability_grant.py \
        /src/src/aragorn/runtime_action_observation_publisher_v3.py \
        /src/src/aragorn/runtime_action_broker_v4.py \
        /src/src/aragorn/runtime_action_service_v4.py \
        /src/src/aragorn/runtime_observation_service_v3.py
