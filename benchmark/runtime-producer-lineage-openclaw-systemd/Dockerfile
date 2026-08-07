ARG LINEAGE_BASE

FROM ${LINEAGE_BASE}

COPY benchmark/evidence/phase1-protected-recursive-v4-live-0307946e55d9-2026-07-29.tar.xz \
    benchmark/evidence/runtime-active-lineage-openclaw-systemd-composition-p3-6a-2026-08-07.json \
    /src/benchmark/evidence/
COPY benchmark/admission/openclaw-v2026.7.1/protected-install-broker-recursive-v3.py \
    /src/benchmark/admission/openclaw-v2026.7.1/
COPY src/aragorn/github_quarantine_receipt.py \
    src/aragorn/protected_install.py \
    /src/src/aragorn/
COPY packaging/libexec/aragorn-protected-install-launcher.py \
    /src/packaging/libexec/
COPY packaging/systemd/aragorn-protected-install.service \
    /src/packaging/systemd/
COPY scripts/capture_runtime_producer_lineage_openclaw_systemd.sh \
    scripts/runtime_producer_lineage_openclaw_systemd_probe.py \
    /src/scripts/
COPY benchmark/runtime-producer-lineage-openclaw-systemd/Dockerfile \
    benchmark/runtime-producer-lineage-openclaw-systemd/aragorn-protected-install-python312.conf \
    /src/benchmark/runtime-producer-lineage-openclaw-systemd/

RUN set -eux; \
    retained=/var/lib/aragorn-p36b-retained/phase1-protected-recursive-v4-live-0307946e55d9; \
    package=/opt/aragorn-broker-p36b; \
    namespace=/var/lib/aragorn-quarantine/918090c29df9d1dfc1f79e0534cb67d961403b4c89567c565ad4de52a042f0a1; \
    test "$(sha256sum /src/benchmark/evidence/phase1-protected-recursive-v4-live-0307946e55d9-2026-07-29.tar.xz | cut -d' ' -f1)" = 08bb32c12e159fede3618bcdeecff5e56c8630e9681d70fe7922f4654cb1b6d8; \
    test "$(sha256sum /src/benchmark/evidence/runtime-active-lineage-openclaw-systemd-composition-p3-6a-2026-08-07.json | cut -d' ' -f1)" = b70ca54d1efdb4b9e93ed2d3895819a2f248c132cf29d811b24635fe79517362; \
    install -d -o root -g root -m 0700 /var/lib/aragorn-p36b-retained; \
    /usr/local/bin/python3.12 -I -S -B -c 'import tarfile; archive=tarfile.open("/src/benchmark/evidence/phase1-protected-recursive-v4-live-0307946e55d9-2026-07-29.tar.xz"); archive.extractall("/var/lib/aragorn-p36b-retained", filter="data"); archive.close()'; \
    test -d "$retained/runtime/package"; \
    test -d "$retained/cas/install/blobs/sha256"; \
    test -f "$retained/requests/install.json"; \
    test -f "$retained/runtime/revocations.json"; \
    test ! -e "$package"; \
    test ! -e "$namespace"; \
    install -d -o root -g root -m 0700 \
        /var/lib/aragorn-p36b \
        /var/lib/aragorn-quarantine; \
    mv "$retained/runtime/package" "$package"; \
    mv "$retained/cas/install" "$namespace"; \
    install -o root -g root -m 0400 \
        "$retained/requests/install.json" \
        /var/lib/aragorn-p36b/request-template.json; \
    install -d -o root -g root -m 0755 /etc/aragorn; \
    install -o root -g root -m 0400 \
        "$retained/runtime/revocations.json" \
        /etc/aragorn/protected-install-revocations.json; \
    rm -rf /var/lib/aragorn-p36b-retained

RUN set -eux; \
    package=/opt/aragorn-broker-p36b; \
    install -o root -g root -m 0444 \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-install-broker-recursive-v3.py \
        "$package/benchmark/admission/openclaw-v2026.7.1/protected-install-broker-recursive-v3.py"; \
    install -o root -g root -m 0444 \
        /src/src/aragorn/github_quarantine_receipt.py \
        "$package/src/aragorn/github_quarantine_receipt.py"; \
    install -o root -g root -m 0444 \
        /src/src/aragorn/protected_install.py \
        "$package/src/aragorn/protected_install.py"; \
    chown -R root:root "$package"; \
    find "$package" -type d -exec chmod 0555 '{}' +; \
    find "$package" -type f -exec chmod 0444 '{}' +; \
    install -o root -g root -m 0555 \
        /src/packaging/libexec/aragorn-protected-install-launcher.py \
        /usr/libexec/aragorn/aragorn-protected-install-launcher.py; \
    install -o root -g root -m 0444 \
        /src/packaging/systemd/aragorn-protected-install.service \
        /usr/lib/systemd/system/aragorn-protected-install.service; \
    chown root:root /src/scripts/runtime_producer_lineage_openclaw_systemd_probe.py; \
    chmod 0555 \
        /src/scripts/capture_runtime_producer_lineage_openclaw_systemd.sh \
        /src/scripts/runtime_producer_lineage_openclaw_systemd_probe.py; \
    chmod 0444 \
        /src/benchmark/admission/openclaw-v2026.7.1/protected-install-broker-recursive-v3.py \
        /src/benchmark/runtime-producer-lineage-openclaw-systemd/Dockerfile \
        /src/benchmark/runtime-producer-lineage-openclaw-systemd/aragorn-protected-install-python312.conf \
        /src/packaging/libexec/aragorn-protected-install-launcher.py \
        /src/packaging/systemd/aragorn-protected-install.service \
        /src/src/aragorn/github_quarantine_receipt.py \
        /src/src/aragorn/protected_install.py; \
    install -d -o root -g root -m 0755 \
        /etc/systemd/system/aragorn-protected-install.service.d; \
    install -o root -g root -m 0444 \
        /src/benchmark/runtime-producer-lineage-openclaw-systemd/aragorn-protected-install-python312.conf \
        /etc/systemd/system/aragorn-protected-install.service.d/python312.conf; \
    install -d -o root -g aragorn-runtime -m 0750 \
        /var/lib/aragorn-protected \
        /var/lib/aragorn-protected/skills; \
    chown -R root:root /var/lib/aragorn-quarantine; \
    find /var/lib/aragorn-quarantine -type d -exec chmod 0700 '{}' +; \
    find /var/lib/aragorn-quarantine -type f -exec chmod 0400 '{}' +; \
    python_digest="sha256:$(sha256sum /usr/local/bin/python3.12 | cut -d' ' -f1)"; \
    launcher_digest="sha256:$(sha256sum /usr/libexec/aragorn/aragorn-protected-install-launcher.py | cut -d' ' -f1)"; \
    broker_digest="sha256:$(sha256sum "$package/benchmark/admission/openclaw-v2026.7.1/protected-install-broker-recursive-v3.py" | cut -d' ' -f1)"; \
    tree_digest="$(/usr/local/bin/python3.12 -I -S -B -c 'import runpy; from pathlib import Path; module=runpy.run_path("/usr/libexec/aragorn/aragorn-protected-install-launcher.py", run_name="_aragorn_release_measurement"); print(module["_measure_package"](Path("/opt/aragorn-broker-p36b"), 0))')"; \
    printf '{"broker":{"digest":"%s","path":"benchmark/admission/openclaw-v2026.7.1/protected-install-broker-recursive-v3.py"},"launcher":{"digest":"%s","path":"/usr/libexec/aragorn/aragorn-protected-install-launcher.py"},"package":{"root":"/opt/aragorn-broker-p36b","tree_digest":"%s"},"python":{"digest":"%s","path":"/usr/local/bin/python3.12"},"schema":"aragorn/protected-broker-launch-identity/v1"}' \
        "$broker_digest" "$launcher_digest" "$tree_digest" "$python_digest" \
        > /etc/aragorn/protected-broker-release.json; \
    chown root:root /etc/aragorn/protected-broker-release.json; \
    chmod 0400 /etc/aragorn/protected-broker-release.json; \
    /usr/local/bin/python3.12 -I -S -B -c 'import runpy; from pathlib import Path; module=runpy.run_path("/usr/libexec/aragorn/aragorn-protected-install-launcher.py", run_name="_aragorn_release_validation"); module["_validated_launch"](Path("/etc/aragorn/protected-broker-release.json"), (), expected_uid=0, launcher_path=Path("/usr/libexec/aragorn/aragorn-protected-install-launcher.py"))'; \
    systemd-analyze verify /usr/lib/systemd/system/aragorn-protected-install.service; \
    test "$(stat -c '%U:%G:%a' /etc/aragorn/protected-broker-release.json)" = root:root:400; \
    test "$(stat -c '%U:%G:%a' /var/lib/aragorn-p36b/request-template.json)" = root:root:400; \
    test "$(stat -c '%U:%G:%a' /etc/aragorn/protected-install-revocations.json)" = root:root:400; \
    test "$(stat -c '%U:%G:%a' /usr/libexec/aragorn/aragorn-protected-install-launcher.py)" = root:root:555; \
    test "$(stat -c '%U:%G:%a' /usr/lib/systemd/system/aragorn-protected-install.service)" = root:root:444; \
    test "$(stat -c '%U:%G:%a' /etc/systemd/system/aragorn-protected-install.service.d/python312.conf)" = root:root:444
