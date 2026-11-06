"""Fixed action wrapper; invoke only with pinned Python -I -S -B, not directly."""

import sys

if __name__ == "__main__":
    if not (sys.flags.isolated == 1 and sys.flags.no_site == 1 and sys.dont_write_bytecode is True):
        raise SystemExit(126)
    import os
    denied = {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "ssl_cert_file", "ssl_cert_dir",
        "requests_ca_bundle", "curl_ca_bundle", "node_extra_ca_certs", "pythonhttpsverify", "pythonpath", "pythonhome",
        "randfile", "glibc_tunables"}
    if any(key.lower() in denied or key.lower().startswith(("openssl_", "ld_", "dyld_", "openai_")) for key in os.environ):
        raise SystemExit(126)
    # The future unit must already have a clean loader environment. This guard
    # precedes importing ssl, but cannot undo loader behavior before Python ran.
    sys.path.insert(0, "/opt/aragorn/src")
    try:
        from aragorn.pi_core_service_entry import main
        result = main("action")
    except BaseException:
        print("PI_SERVICE_ENTRY_REFUSED_OR_CLEANUP_HOLD", file=sys.stderr)
        result = 126
    raise SystemExit(result)
