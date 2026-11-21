"""Independently derive B69's deployment metadata from signed B68 blobs and pinned B65 records.

Prints a public review record. No target imports, image tools, filesystem writes,
installed identities, or access to a live device.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess


REVISION = "0910f1d1c5710cb7730002ac5d974803e14e2431"
TREE = "e45cb0c200f3ba9c1201c2b301a371a892f3d15e"
SIGNER = "SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk"
B65_PAYLOAD = "156c94630eec1fe9285e8732fd7574c14f2fd9926aa3dd6d0e5f95cb408ceb51"
REPOSITORY = Path(__file__).resolve().parents[1]
RETAINED = Path.home() / "Library/Application Support/Aragorn-B65-Offline"
IMPORT = "opt/aragorn/src/"
ADDED = ("aragorn/pi_core_manager_state_view.py", "aragorn/pi_core_configuration_carrier.py")
HOST = "/etc/aragorn/coordinator-host.json"
WRAPPER = "/opt/aragorn/bin/coordinator.py"
RUNTIME = "/var/lib/aragorn/pi-service-runtime/"
D = "/etc/aragorn/service-runtime-inputs/"
MANIFEST, BINDING, RECEIPT = D + "manifest.json", D + "runtime-binding.json", RUNTIME + "service-runtime-receipt.json"
MARKER = b"_ARAGORN_SOURCE_DIGESTS = None  # assembled source pins\n"


def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def retained(path, expected):
    if path.resolve(strict=True) != path or not path.is_file() or path.stat().st_size > 2 << 20:
        raise ValueError("invalid retained metadata path")
    raw = path.read_bytes()
    if sha(raw) != expected:
        raise ValueError("retained metadata digest mismatch")
    return json.loads(raw)


def _git(*args, request=b""):
    # Keep the local repository's allowed-signers policy. Do not inherit user
    # Git configuration, helper paths, a remote protocol or an agent socket.
    env = dict(PATH="/usr/bin:/bin", HOME="/var/empty", LC_ALL="C", GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL="/dev/null", GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="",
               GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    cmd = ["/usr/bin/git", "--no-pager", "--no-replace-objects", "-c", "protocol.allow=never",
           "-c", "core.hooksPath=/dev/null", "-c", "gpg.format=ssh", "-c", "gpg.ssh.program=/usr/bin/ssh-keygen",
           "-c", "gpg.program=/usr/bin/false", "-c", "gpg.x509.program=/usr/bin/false", *args]
    return subprocess.run(cmd, input=request, cwd=REPOSITORY, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=30, check=True).stdout


def _blobs(names, *, revision=REVISION, tree=TREE):
    if not all(type(v) is str and re.fullmatch("[0-9a-f]{40}", v) for v in (revision, tree)):
        raise ValueError("invalid signed source identity")
    identity = _git("log", "-1", "--no-notes", "--no-show-signature", "--format=%H%n%T%n%G?%n%GF", revision)
    if identity.splitlines() != [revision.encode(), tree.encode(), b"G", SIGNER.encode()]:
        raise ValueError("wrong signed source commit, tree or signer")
    order = sorted(names)
    request = "".join(tree + ":" + n + "\n" for n in order).encode("ascii")
    out, at, result = _git("cat-file", "--batch", request=request), 0, {}
    for name in order:
        end = out.index(b"\n", at)
        _, kind, length = out[at:end].split()
        if kind != b"blob" or not length.isdigit() or not 0 < int(length) <= 4 << 20:
            raise ValueError("invalid signed source blob")
        at = end + 1 + int(length)
        if out[at:at + 1] != b"\n":
            raise ValueError("incomplete signed source blob")
        result[name] = out[end + 1:at]
        at += 1
    if at != len(out):
        raise ValueError("extra source blob")
    return result


def project(*, directory, predecessor, host_additions, service_additions, revision, tree):
    """Project changed metadata only; the caller provides independently frozen predecessor and source pins."""
    base = retained(directory / "payload.json", predecessor)
    entries = {r["path"]: r for r in base["entries"]}
    original = entries.copy()
    def doc(name):
        return retained(directory / "root" / name[1:], entries[name]["sha256"])
    host, manifest, binding, receipt = map(doc, (HOST, MANIFEST, BINDING, RECEIPT))
    roles = ("action", "provider", "sensor")
    hosts = {r["path"]: r for r in host["files"]}
    files = {r["path"]: r for r in manifest["files"]}
    services = {p.removeprefix(IMPORT) for p in binding["source_digests"]} | set(service_additions)
    coordinators = {p.removeprefix("/" + IMPORT) for p in hosts if p.startswith("/" + IMPORT)} | set(host_additions)
    templates = {r: "packaging/pi-core/services-v2/" + r + ".py" for r in roles}
    sources = _blobs({"src/" + n for n in coordinators | services} | set(templates.values()) |
                     {"packaging/pi-core/coordinator.py"}, revision=revision, tree=tree)
    def file_row(name, raw, mode):
        entries[name] = dict(path=name, type="file", uid=0, gid=0, mode=mode, size=len(raw), sha256=sha(raw))
    for name, raw in [(WRAPPER, sources["packaging/pi-core/coordinator.py"]),
                      *(("/" + IMPORT + n, sources["src/" + n]) for n in coordinators)]:
        hosts[name] = dict(path=name, digest="sha256:" + sha(raw), size=len(raw))
        file_row(name, raw, 0o444)
    host["files"] = [hosts[n] for n in sorted(hosts, key=PurePosixPath)]
    code = {IMPORT + n: sources["src/" + n] for n in sorted(services)}
    binding["source_digests"] = {p: "sha256:" + sha(raw) for p, raw in code.items()}
    for role in roles:
        path = binding["wrappers"][role]["path"]
        template = sources[templates[role]]
        if template.count(MARKER) != 1 or path != "opt/aragorn/bin/" + role + ".py":
            raise ValueError("unrecognized role wrapper")
        code[path] = template.replace(MARKER, ("_ARAGORN_SOURCE_DIGESTS = " + repr(binding["source_digests"]) +
                                               "\n").encode("ascii"))
        binding["wrappers"][role]["digest"] = "sha256:" + sha(code[path])
    for path, raw in code.items():
        executable = path not in binding["source_digests"]
        files[path] = dict(path=path, digest="sha256:" + sha(raw), size=len(raw), executable=executable)
        file_row(RUNTIME + "root/" + path, raw, 0o555 if executable else 0o444)
    manifest["files"] = [files[n] for n in sorted(files)]
    receipt.update(binding_digest="sha256:" + sha(encode(binding)), runtime_closure_digest="sha256:" + sha(encode(manifest)))
    for name, content in ((HOST, host), (MANIFEST, manifest), (BINDING, binding), (RECEIPT, receipt)):
        file_row(name, encode(content), entries[name]["mode"])
    base["entries"] = [entries[n] for n in sorted(entries)]
    pins = dict(schema="aragorn/pi-core-managed-payload/v1", payload_sha256=sha(encode(base)),
                host_profile_sha256=sha(encode(host)), manifest_sha256=sha(encode(manifest)),
                binding_sha256=sha(encode(binding)), layout_receipt_sha256=sha(encode(receipt)))
    return pins, original, entries


def derive():
    return project(directory=RETAINED, predecessor=B65_PAYLOAD, host_additions=ADDED, service_additions=ADDED,
                   revision=REVISION, tree=TREE)[0]


if __name__ == "__main__":
    print(json.dumps(derive(), indent=2))
