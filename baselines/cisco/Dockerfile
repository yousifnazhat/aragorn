# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM ghcr.io/astral-sh/uv@sha256:eb2843a1e56fd9e30c7276ce1a52cba86e64c7b385f5e3279a0e08e02dd058fc AS uv
FROM python@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b AS builder

COPY --from=uv /uv /usr/local/bin/uv
COPY scripts/verify_build_inputs.py /usr/local/lib/aragorn/verify_build_inputs.py
WORKDIR /src
COPY --from=vendor pyproject.toml uv.lock ./

RUN python /usr/local/lib/aragorn/verify_build_inputs.py /src \
    1e421a8597cd5eea40ad02da598ae9c4ee491ddb2a7bd7582c8226e21db5e73b

ADD --checksum=sha256:e49f979e97b7842549b1f531dc5f426c9780d798a0b21f0125044e3b5ae4a1f7 \
    https://files.pythonhosted.org/packages/2c/11/318cd4b984514df20ec3467b180bdc5158885cc06ae736e23aecf4bb5213/cisco_ai_skill_scanner-2.0.12-py3-none-any.whl \
    /tmp/cisco_ai_skill_scanner-2.0.12-py3-none-any.whl

ENV UV_PYTHON_DOWNLOADS=never
RUN --mount=type=cache,target=/root/.cache/uv \
    uv export --locked --no-dev --no-emit-project --format requirements.txt \
        --output-file /tmp/requirements.txt \
    && uv venv --python /usr/local/bin/python /opt/venv \
    && uv pip install --python /opt/venv/bin/python --require-hashes --no-build \
        --strict --requirements /tmp/requirements.txt \
    && uv pip install --python /opt/venv/bin/python --no-deps --no-build \
        /tmp/cisco_ai_skill_scanner-2.0.12-py3-none-any.whl \
    && uv pip check --python /opt/venv/bin/python

FROM python@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

RUN groupadd --gid 65532 aragorn \
    && useradd --uid 65532 --gid 65532 --no-create-home \
        --shell /usr/sbin/nologin aragorn
COPY --from=builder /opt/venv /opt/venv

ENV HOME=/tmp/aragorn \
    PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONHASHSEED=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1
WORKDIR /opt/aragorn-control
USER 65532:65532

LABEL org.opencontainers.image.source="https://github.com/cisco-ai-defense/skill-scanner" \
      org.opencontainers.image.revision="605afdc5c7ea887c07e2afeb0fadc1452c07bfa7" \
      org.opencontainers.image.version="2.0.12" \
      dev.aragorn.baseline.build-input-sha256="1e421a8597cd5eea40ad02da598ae9c4ee491ddb2a7bd7582c8226e21db5e73b" \
      dev.aragorn.baseline.distribution-sha256="e49f979e97b7842549b1f531dc5f426c9780d798a0b21f0125044e3b5ae4a1f7" \
      dev.aragorn.baseline.lock-sha256="59fac955bd7537b4e17692d34592ce28922347004d39d7ead2b550e1c3a62f00" \
      dev.aragorn.closure-status="candidate-not-runner-attested"

ENTRYPOINT ["/opt/venv/bin/skill-scanner"]
