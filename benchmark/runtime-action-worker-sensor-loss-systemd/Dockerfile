FROM sha256:21184b7a6a096a8625994b524203bf5b521d749b24e415378a69decd4e78009b

COPY packaging/activate-runtime-action-worker-host.sh \
    /src/packaging/activate-runtime-action-worker-host.sh
COPY packaging/systemd/aragorn-agent-gateway.service \
    /src/packaging/systemd/aragorn-agent-gateway.service

RUN set -eu; \
    test "$(sha256sum /src/packaging/activate-runtime-action-worker-host.sh | cut -d ' ' -f 1)" = \
        47d03e4600813cb32b536a267608f8d7eb97219c2421ba944426444693fee009; \
    test "$(sha256sum /src/packaging/systemd/aragorn-agent-gateway.service | cut -d ' ' -f 1)" = \
        70a0aa0a89aae8bce8b7785b26d73d844c784e85be449363cb739835500de067; \
    install -o 0 -g 0 -m 0755 \
        /src/packaging/activate-runtime-action-worker-host.sh \
        /usr/libexec/aragorn/activate-runtime-action-worker-host.sh; \
    install -o 0 -g 0 -m 0644 \
        /src/packaging/systemd/aragorn-agent-gateway.service \
        /usr/lib/systemd/system/aragorn-agent-gateway.service; \
    cmp /src/packaging/activate-runtime-action-worker-host.sh \
        /usr/libexec/aragorn/activate-runtime-action-worker-host.sh; \
    cmp /src/packaging/systemd/aragorn-agent-gateway.service \
        /usr/lib/systemd/system/aragorn-agent-gateway.service; \
    test "$(stat -c '%u:%g:%a:%h:%s' /usr/libexec/aragorn/activate-runtime-action-worker-host.sh)" = \
        0:0:755:1:31295; \
    test "$(stat -c '%u:%g:%a:%h:%s' /usr/lib/systemd/system/aragorn-agent-gateway.service)" = \
        0:0:644:1:3437
