FROM sha256:21184b7a6a096a8625994b524203bf5b521d749b24e415378a69decd4e78009b

COPY packaging/activate-runtime-capability-host.sh \
    packaging/activate-runtime-action-worker-host.sh \
    /src/packaging/
COPY packaging/systemd/aragorn-agent-gateway.service \
    packaging/systemd/aragorn-runtime-action-worker.service \
    packaging/systemd/aragorn-runtime-lineage-capability-observation-publisher.service \
    packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service \
    /src/packaging/systemd/

RUN set -eu; \
    test "$(sha256sum /src/packaging/activate-runtime-capability-host.sh | cut -d ' ' -f 1)" = \
        b4ad162940d842e93ede73143f607cff4c612716334b66430d71b885f398984c; \
    test "$(sha256sum /src/packaging/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        dd615a00aacd5f76f52ac60400ea095f9014c2ef29d7793fd3ba35b26ffe3186; \
    test "$(sha256sum /src/packaging/systemd/aragorn-agent-gateway.service | cut -d ' ' -f 1)" = \
        70a0aa0a89aae8bce8b7785b26d73d844c784e85be449363cb739835500de067; \
    test "$(sha256sum /src/packaging/systemd/aragorn-runtime-action-worker.service | cut -d ' ' -f 1)" = \
        e4ef9e3f2229d92ed9dd9ee4896646e646d7171ee585ecba5aecdd87dba5e790; \
    test "$(sha256sum /src/packaging/systemd/aragorn-runtime-lineage-capability-observation-publisher.service | cut -d ' ' -f 1)" = \
        f48258b00213c2c1ff4c5c95d0f1c446f78593d1d04780719cba79bf8dd73d8a; \
    test "$(sha256sum /src/packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service | cut -d ' ' -f 1)" = \
        e0273dbeb4ed40a203193a52eb6146f81ecbc6abca605fa0bfff69774676b2db; \
    install -o 0 -g 0 -m 0755 \
        /src/packaging/activate-runtime-capability-host.sh \
        /usr/libexec/aragorn/activate-runtime-capability-host.sh; \
    install -o 0 -g 0 -m 0755 \
        /src/packaging/activate-runtime-action-worker-host.sh \
        /usr/libexec/aragorn/activate-runtime-action-worker-host.sh; \
    install -o 0 -g 0 -m 0644 \
        /src/packaging/systemd/aragorn-agent-gateway.service \
        /usr/lib/systemd/system/aragorn-agent-gateway.service; \
    install -o 0 -g 0 -m 0644 \
        /src/packaging/systemd/aragorn-runtime-action-worker.service \
        /usr/lib/systemd/system/aragorn-runtime-action-worker.service; \
    install -o 0 -g 0 -m 0644 \
        /src/packaging/systemd/aragorn-runtime-lineage-capability-observation-publisher.service \
        /usr/lib/systemd/system/aragorn-runtime-lineage-capability-observation-publisher.service; \
    install -o 0 -g 0 -m 0644 \
        /src/packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service \
        /usr/lib/systemd/system/aragorn-runtime-lineage-capability-action-broker.service; \
    cmp /src/packaging/activate-runtime-capability-host.sh \
        /usr/libexec/aragorn/activate-runtime-capability-host.sh; \
    cmp /src/packaging/activate-runtime-action-worker-host.sh \
        /usr/libexec/aragorn/activate-runtime-action-worker-host.sh; \
    cmp /src/packaging/systemd/aragorn-agent-gateway.service \
        /usr/lib/systemd/system/aragorn-agent-gateway.service; \
    cmp /src/packaging/systemd/aragorn-runtime-action-worker.service \
        /usr/lib/systemd/system/aragorn-runtime-action-worker.service; \
    cmp /src/packaging/systemd/aragorn-runtime-lineage-capability-observation-publisher.service \
        /usr/lib/systemd/system/aragorn-runtime-lineage-capability-observation-publisher.service; \
    cmp /src/packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service \
        /usr/lib/systemd/system/aragorn-runtime-lineage-capability-action-broker.service; \
    test "$(stat -c '%u:%g:%a:%h:%s' /usr/libexec/aragorn/activate-runtime-capability-host.sh)" = \
        0:0:755:1:12420; \
    test "$(stat -c '%u:%g:%a:%h:%s' /usr/libexec/aragorn/activate-runtime-action-worker-host.sh)" = \
        0:0:755:1:32271; \
    test "$(stat -c '%u:%g:%a:%h:%s' /usr/lib/systemd/system/aragorn-agent-gateway.service)" = \
        0:0:644:1:3437; \
    test "$(stat -c '%u:%g:%a:%h:%s' /usr/lib/systemd/system/aragorn-runtime-action-worker.service)" = \
        0:0:644:1:2573; \
    test "$(stat -c '%u:%g:%a:%h:%s' /usr/lib/systemd/system/aragorn-runtime-lineage-capability-observation-publisher.service)" = \
        0:0:644:1:2777; \
    test "$(stat -c '%u:%g:%a:%h:%s' /usr/lib/systemd/system/aragorn-runtime-lineage-capability-action-broker.service)" = \
        0:0:644:1:2725
