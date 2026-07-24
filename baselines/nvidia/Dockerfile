# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM ghcr.io/astral-sh/uv@sha256:eb2843a1e56fd9e30c7276ce1a52cba86e64c7b385f5e3279a0e08e02dd058fc AS uv
FROM python@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b AS forbiddenfruit-builder

COPY --from=uv /uv /usr/local/bin/uv
COPY scripts/extract_pinned_sdist.py /usr/local/lib/aragorn/extract_pinned_sdist.py
ENV UV_PYTHON_DOWNLOADS=never

ADD --checksum=sha256:e3f7e66561a29ae129aac139a85d610dbf3dd896128187ed5454b6421f624253 \
    https://files.pythonhosted.org/packages/e6/79/d4f20e91327c98096d605646bdc6a5ffedae820f38d378d3515c42ec5e60/forbiddenfruit-0.1.4.tar.gz \
    /tmp/forbiddenfruit-0.1.4.tar.gz
ADD --checksum=sha256:29b23c360f22f414dc7336bb39178cc7bcbf6021ed2733cde173f09dba19abb3 \
    https://files.pythonhosted.org/packages/5d/40/e1e72872c6354b306daef1703549e8e83b4d43cfea356311bf722a043752/setuptools-83.0.0-py3-none-any.whl \
    /tmp/setuptools-83.0.0-py3-none-any.whl

RUN --network=none \
    python /usr/local/lib/aragorn/extract_pinned_sdist.py \
        /tmp/forbiddenfruit-0.1.4.tar.gz /tmp/forbiddenfruit-source \
        forbiddenfruit-0.1.4 \
    && uv venv --python /usr/local/bin/python /tmp/forbiddenfruit-build-venv \
    && uv pip install --offline --python /tmp/forbiddenfruit-build-venv/bin/python \
        --no-deps --no-build /tmp/setuptools-83.0.0-py3-none-any.whl \
    && cd /tmp/forbiddenfruit-source/forbiddenfruit-0.1.4 \
    && SOURCE_DATE_EPOCH=1610831015 PYTHONHASHSEED=0 TZ=UTC LC_ALL=C \
        /tmp/forbiddenfruit-build-venv/bin/python setup.py bdist_wheel \
        --dist-dir /tmp/forbiddenfruit-wheel \
    && actual="$(sha256sum /tmp/forbiddenfruit-wheel/forbiddenfruit-0.1.4-py3-none-any.whl | cut -d ' ' -f 1)" \
    && echo "forbiddenfruit wheel sha256: ${actual}" \
    && test "${actual}" = "9170567169d955c62922e64a366f072e1ff0dbafc5f401bb1f351280dbe297fe"

FROM python@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b AS builder

COPY --from=uv /uv /usr/local/bin/uv
COPY scripts/verify_build_inputs.py /usr/local/lib/aragorn/verify_build_inputs.py
COPY --from=forbiddenfruit-builder \
    /tmp/forbiddenfruit-wheel/forbiddenfruit-0.1.4-py3-none-any.whl \
    /tmp/forbiddenfruit-0.1.4-py3-none-any.whl
COPY baselines/nvidia/skillspector-2.4.3.dist-info /tmp/skillspector-2.4.3.dist-info
WORKDIR /src
COPY --from=vendor pyproject.toml uv.lock LICENSE THIRD_PARTY_NOTICES.md ./
COPY --from=vendor src ./src

RUN python /usr/local/lib/aragorn/verify_build_inputs.py /src \
    450b8a5cc1f3ff2a518b3f063601074ccc8673909cf7770af9c8842a2d5a7f8d \
    && python /usr/local/lib/aragorn/verify_build_inputs.py \
        /tmp/skillspector-2.4.3.dist-info \
        0968c78a54eb94f3dfb037eefc56fd12d893f457bcf1ebe4631a3057a0bf566a \
    && test "$(sha256sum /tmp/forbiddenfruit-0.1.4-py3-none-any.whl | cut -d ' ' -f 1)" \
        = "9170567169d955c62922e64a366f072e1ff0dbafc5f401bb1f351280dbe297fe"

ENV UV_PYTHON_DOWNLOADS=never
RUN --mount=type=cache,target=/root/.cache/uv \
    uv export --locked --no-dev --no-emit-project --format requirements.txt \
        --output-file /tmp/requirements.txt \
    && uv venv --python /usr/local/bin/python /opt/venv \
    && uv pip install --python /opt/venv/bin/python --no-deps --no-build \
        /tmp/forbiddenfruit-0.1.4-py3-none-any.whl \
    && uv pip install --python /opt/venv/bin/python --require-hashes --no-build \
        --strict --requirements /tmp/requirements.txt \
    && uv pip check --python /opt/venv/bin/python

FROM python@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

RUN groupadd --gid 65532 aragorn \
    && useradd --uid 65532 --gid 65532 --no-create-home \
        --shell /usr/sbin/nologin aragorn
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /src/src /opt/skillspector-src
COPY --from=builder /src/LICENSE /usr/share/licenses/skillspector/LICENSE
COPY --from=builder /src/THIRD_PARTY_NOTICES.md /usr/share/licenses/skillspector/THIRD_PARTY_NOTICES.md
COPY --from=builder /tmp/skillspector-2.4.3.dist-info \
    /opt/skillspector-src/skillspector-2.4.3.dist-info

ENV HOME=/tmp/aragorn \
    PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONHASHSEED=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1 \
    PYTHONSAFEPATH=1 \
    PYTHONPATH=/opt/skillspector-src \
    SKILLSPECTOR_OSV_TIMEOUT=0.2
WORKDIR /opt/aragorn-control
USER 65532:65532

LABEL org.opencontainers.image.source="https://github.com/NVIDIA/SkillSpector" \
      org.opencontainers.image.revision="a54947c307fe19a24a43db55f6148e181a987a67" \
      org.opencontainers.image.version="2.4.3" \
      dev.aragorn.baseline.build-input-sha256="450b8a5cc1f3ff2a518b3f063601074ccc8673909cf7770af9c8842a2d5a7f8d" \
      dev.aragorn.baseline.derived-wheel-sha256="9170567169d955c62922e64a366f072e1ff0dbafc5f401bb1f351280dbe297fe" \
      dev.aragorn.baseline.dist-info-sha256="0968c78a54eb94f3dfb037eefc56fd12d893f457bcf1ebe4631a3057a0bf566a" \
      dev.aragorn.baseline.lock-sha256="c45e6ff70bb1eddebb028b4e5ea25845ee2ea2ae6643881d0f1a1a9a251d5fea" \
      dev.aragorn.closure-status="candidate-not-runner-attested"

ENTRYPOINT ["/opt/venv/bin/python", "-P", "-m", "skillspector.cli"]
