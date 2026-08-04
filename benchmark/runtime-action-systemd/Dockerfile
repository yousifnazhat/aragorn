FROM python@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ENV container=docker

RUN apt-get update >/dev/null \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        dbus \
        procps \
        strace \
        systemd=252.39-1~deb12u2 \
        util-linux \
    >/dev/null \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s /usr/local/bin/python3.12 /usr/bin/python3.12

COPY packaging/install-runtime-action-host.sh /src/packaging/install-runtime-action-host.sh
COPY packaging/libexec/aragorn-runtime-action-service.py \
    packaging/libexec/aragorn-runtime-observation-service.py \
    /src/packaging/libexec/
COPY packaging/systemd/aragorn-gateway.sysusers \
    packaging/systemd/aragorn-runtime-action.tmpfiles \
    packaging/systemd/aragorn-runtime-action-broker.service \
    packaging/systemd/aragorn-runtime-observation-publisher.service \
    /src/packaging/systemd/
COPY src/aragorn/__init__.py \
    src/aragorn/oci_worker_protocol.py \
    src/aragorn/runtime_action_broker.py \
    src/aragorn/runtime_action_decision.py \
    src/aragorn/runtime_action_observation_publisher.py \
    src/aragorn/runtime_action_service.py \
    src/aragorn/runtime_observation_service.py \
    /src/src/aragorn/
COPY scripts/capture_runtime_action_systemd.sh /src/scripts/capture_runtime_action_systemd.sh
COPY scripts/runtime_action_systemd_probe.py /src/scripts/runtime_action_systemd_probe.py
COPY benchmark/runtime-action-systemd/Dockerfile /src/benchmark/runtime-action-systemd/Dockerfile
COPY .dockerignore /src/.dockerignore

RUN sh /src/packaging/install-runtime-action-host.sh \
    && systemd-sysusers /usr/lib/sysusers.d/aragorn-gateway.conf \
    && systemd-tmpfiles --create /usr/lib/tmpfiles.d/aragorn-runtime-action.conf

STOPSIGNAL SIGRTMIN+3

CMD ["/bin/sh", "-c", "mount --make-rshared /run && exec /usr/lib/systemd/systemd"]
