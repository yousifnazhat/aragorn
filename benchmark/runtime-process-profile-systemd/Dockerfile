ARG SYSTEMD_BASE

FROM ${SYSTEMD_BASE}

COPY packaging/install-runtime-profile-host.sh \
    /src/packaging/install-runtime-profile-host.sh
COPY packaging/libexec/aragorn-runtime-observation-service-v2.py \
    /src/packaging/libexec/aragorn-runtime-observation-service-v2.py
COPY packaging/libexec/aragorn-runtime-action-service-v2.py \
    /src/packaging/libexec/aragorn-runtime-action-service-v2.py
COPY packaging/systemd/aragorn-runtime-profile-action-broker.service \
    packaging/systemd/aragorn-runtime-profile-observation-publisher.service \
    /src/packaging/systemd/
COPY src/aragorn/runtime_process_profile.py \
    src/aragorn/runtime_action_broker_v2.py \
    src/aragorn/runtime_action_observation_publisher_v2.py \
    src/aragorn/runtime_action_service_v2.py \
    src/aragorn/runtime_observation_service_v2.py \
    /src/src/aragorn/
COPY benchmark/runtime-process-profile-systemd/ \
    /src/benchmark/runtime-process-profile-systemd/
COPY scripts/runtime_process_profile_systemd_probe.py \
    /src/scripts/runtime_process_profile_systemd_probe.py
COPY scripts/capture_runtime_process_profile_systemd.sh \
    /src/scripts/capture_runtime_process_profile_systemd.sh

RUN sh /src/packaging/install-runtime-profile-host.sh \
    && install -m 0644 \
        /src/benchmark/runtime-process-profile-systemd/aragorn-runtime-profile-client.service \
        /usr/lib/systemd/system/aragorn-runtime-profile-client.service \
    && install -d -m 0555 /opt/aragorn/runtime-profile \
    && install -m 0444 \
        /src/benchmark/runtime-process-profile-systemd/SKILL.md \
        /opt/aragorn/runtime-profile/SKILL.md \
    && chmod 0555 /src/scripts/runtime_process_profile_systemd_probe.py \
    && chmod 0555 /src/scripts/capture_runtime_process_profile_systemd.sh \
    && chmod 0444 \
        /src/benchmark/runtime-process-profile-systemd/Dockerfile \
        /usr/lib/systemd/system/aragorn-runtime-profile-client.service
