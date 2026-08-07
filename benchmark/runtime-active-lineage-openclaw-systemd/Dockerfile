ARG LINEAGE_BASE

FROM ${LINEAGE_BASE}

COPY packaging/install-runtime-capability-host.sh \
    packaging/activate-runtime-capability-host.sh \
    /src/packaging/
COPY packaging/libexec/aragorn-runtime-action-service-v5.py \
    packaging/libexec/aragorn-runtime-observation-service-v4.py \
    /src/packaging/libexec/
COPY packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service \
    packaging/systemd/aragorn-runtime-lineage-capability-observation-publisher.service \
    /src/packaging/systemd/
COPY src/aragorn/runtime_active_skill_lineage.py \
    src/aragorn/runtime_lineage_capability_issuer.py \
    src/aragorn/runtime_action_observation_publisher_v4.py \
    src/aragorn/runtime_action_broker_v5.py \
    src/aragorn/runtime_action_service_v5.py \
    src/aragorn/runtime_observation_service_v4.py \
    /src/src/aragorn/
COPY benchmark/evidence/runtime-revocation-openclaw-systemd-composition-p3-5b-2026-08-06.json \
    /src/benchmark/evidence/
COPY benchmark/runtime-active-lineage-openclaw-systemd/Dockerfile \
    /src/benchmark/runtime-active-lineage-openclaw-systemd/
COPY scripts/runtime_active_lineage_openclaw_systemd_probe.py \
    scripts/capture_runtime_active_lineage_openclaw_systemd.sh \
    /src/scripts/

RUN sh /src/packaging/install-runtime-capability-host.sh \
    && test -x /usr/libexec/aragorn/aragorn-runtime-action-service-v5.py \
    && test -x /usr/libexec/aragorn/aragorn-runtime-observation-service-v4.py \
    && test -f /usr/lib/systemd/system/aragorn-runtime-lineage-capability-action-broker.service \
    && test -f /usr/lib/systemd/system/aragorn-runtime-lineage-capability-observation-publisher.service \
    && chmod 0555 \
        /src/packaging/install-runtime-capability-host.sh \
        /src/packaging/activate-runtime-capability-host.sh \
        /src/scripts/runtime_active_lineage_openclaw_systemd_probe.py \
        /src/scripts/capture_runtime_active_lineage_openclaw_systemd.sh \
    && chmod 0444 \
        /src/benchmark/evidence/runtime-revocation-openclaw-systemd-composition-p3-5b-2026-08-06.json \
        /src/benchmark/runtime-active-lineage-openclaw-systemd/Dockerfile \
        /src/packaging/libexec/aragorn-runtime-action-service-v5.py \
        /src/packaging/libexec/aragorn-runtime-observation-service-v4.py \
        /src/packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service \
        /src/packaging/systemd/aragorn-runtime-lineage-capability-observation-publisher.service \
        /src/src/aragorn/runtime_active_skill_lineage.py \
        /src/src/aragorn/runtime_lineage_capability_issuer.py \
        /src/src/aragorn/runtime_action_observation_publisher_v4.py \
        /src/src/aragorn/runtime_action_broker_v5.py \
        /src/src/aragorn/runtime_action_service_v5.py \
        /src/src/aragorn/runtime_observation_service_v4.py
