ARG REVOCATION_BASE

FROM ${REVOCATION_BASE}

COPY packaging/install-runtime-capability-host.sh \
    packaging/activate-runtime-capability-host.sh \
    /src/packaging/
COPY packaging/libexec/aragorn-runtime-revocation-service.py \
    /src/packaging/libexec/
COPY packaging/systemd/aragorn-runtime-revocation-publisher.service \
    /src/packaging/systemd/
COPY src/aragorn/runtime_revocation_service.py \
    /src/src/aragorn/
COPY benchmark/runtime-revocation-openclaw-systemd/Dockerfile \
    /src/benchmark/runtime-revocation-openclaw-systemd/
COPY scripts/runtime_revocation_openclaw_systemd_probe.py \
    scripts/capture_runtime_revocation_openclaw_systemd.sh \
    /src/scripts/

RUN sh /src/packaging/install-runtime-capability-host.sh \
    && test -f \
        /usr/lib/aragorn/aragorn/runtime_revocation_service.py \
    && test -x \
        /usr/libexec/aragorn/aragorn-runtime-revocation-service.py \
    && test -f \
        /usr/lib/systemd/system/aragorn-runtime-revocation-publisher.service \
    && chmod 0555 \
        /src/packaging/install-runtime-capability-host.sh \
        /src/packaging/activate-runtime-capability-host.sh \
        /src/scripts/runtime_revocation_openclaw_systemd_probe.py \
        /src/scripts/capture_runtime_revocation_openclaw_systemd.sh \
    && chmod 0444 \
        /src/benchmark/runtime-revocation-openclaw-systemd/Dockerfile \
        /src/packaging/libexec/aragorn-runtime-revocation-service.py \
        /src/packaging/systemd/aragorn-runtime-revocation-publisher.service \
        /src/src/aragorn/runtime_revocation_service.py
