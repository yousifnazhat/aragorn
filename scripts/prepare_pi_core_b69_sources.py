"""Project B69 host and service code from authenticated Git objects, never from checkout source."""
import json
import re
import subprocess

from scripts import prepare_pi_core_b62_host_sources as host
from scripts import prepare_pi_core_service_image as image
from scripts import prepare_pi_core_service_successor_sources as previous
from scripts.build_pi_core_linux import ROOT, canonical


REVISION = "0910f1d1c5710cb7730002ac5d974803e14e2431"
TREE = "e45cb0c200f3ba9c1201c2b301a371a892f3d15e"
SIGNER = "SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk"
REVIEW = ROOT / "packaging/pi-core/managed-sources-b69.json"
REVIEW_PIN = "sha256:ce8f0f265d206a681c8413578d81d09be504276f61c1c9af3335d77fe3f38495"
WRAPPERS = "packaging/pi-core/services-v2"
_NAME = re.compile(r"(?:src/aragorn/(?:[A-Za-z_]\w*/)*[A-Za-z_]\w*|packaging/pi-core/(?:coordinator|services-v2/(?:action|provider|sensor)))\.py", re.ASCII)


def _git(args, request=b""):
    # No replace refs, lazy promisor downloads, pager, stdin credentials, hooks,
    # worktree filter, or smudge driver; cat-file is only given reviewed blob IDs.
    env = {"HOME": "/var/empty", "PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_NO_LAZY_FETCH": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_ALLOW_PROTOCOL": "", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
    return subprocess.run(["/usr/bin/git", "--no-replace-objects", "--no-pager",
                           "-c", "protocol.allow=never", "-c", "core.hooksPath=/dev/null",
                           "-c", "gpg.format=ssh", "-c", "gpg.ssh.program=/usr/bin/ssh-keygen",
                           "-c", "gpg.program=/usr/bin/false", "-c", "gpg.x509.program=/usr/bin/false",
                           *args], cwd=ROOT, env=env,
                          input=request, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          timeout=20, check=True).stdout


def _objects(expected, *, revision=REVISION, tree=TREE):
    image.require(all(type(v) is str and re.fullmatch("[0-9a-f]{40}", v) for v in (revision, tree)),
                  "invalid signed source identity")
    paths = sorted(expected)
    image.require(0 < len(paths) <= image.MAX_SOURCE_FILES and all(_NAME.fullmatch(p) for p in paths),
                  "invalid signed code path selection")
    signed = _git(["log", "-1", "--no-notes", "--no-show-signature", "--format=%H%n%T%n%G?%n%GF", revision])
    image.require(signed.splitlines() == [revision.encode(), tree.encode(), b"G", SIGNER.encode()],
                  "source commit, tree or approved signature differs")
    raw = _git(["ls-tree", "-z", "-l", tree, "--", *paths])
    image.require(raw.endswith(b"\0") and len(raw) <= len(paths) * 1024, "unexpected source tree response")
    listing = {}
    for line in raw[:-1].split(b"\0"):
        info, name = line.split(b"\t")
        mode, kind, oid, size = info.split()
        path = name.decode("ascii")
        image.require(path not in listing and path in expected and (mode, kind) == (b"100644", b"blob")
                      and re.fullmatch(rb"[0-9a-f]{40}", oid) and size.isdigit()
                      and 0 < int(size) <= image.MAX_SOURCE_FILE, "unsafe signed tree member")
        listing[path] = (oid, int(size))
    image.require(listing.keys() == expected.keys() and sum(s for _, s in listing.values()) <= image.MAX_SOURCE_BYTES,
                  "incomplete or oversized source projection")
    data = _git(["cat-file", "--batch"], b"".join(listing[p][0] + b"\n" for p in paths))
    cursor, result = 0, {}
    for path in paths:
        oid, size = listing[path]
        header = oid + b" blob " + str(size).encode("ascii") + b"\n"
        image.require(data.startswith(header, cursor), "unexpected signed blob header")
        cursor += len(header)
        blob = data[cursor:cursor + size]
        cursor += size
        image.require(len(blob) == size and data[cursor:cursor + 1] == b"\n" and image.pin(blob) == expected[path],
                      "source bytes differ from reviewed SHA-256")
        result[path] = blob
        cursor += 1
    image.require(cursor == len(data), "extra signed blob bytes")
    return result


def _prior(raw, digest):
    image.require(type(raw) is bytes and 0 < len(raw) <= 2 << 20 and image.pin(raw) == digest,
                  "foreign predecessor document")
    return json.loads(raw)


def prepare(b65_host_profile_raw, b65_manifest_raw, b65_binding_raw):
    """Return full host code, service code (including rendered wrappers), and public source identities."""
    return _prepare(b65_host_profile_raw, b65_manifest_raw, b65_binding_raw, review_path=REVIEW,
                    review_pin=REVIEW_PIN, revision=REVISION, tree=TREE)


def _prepare(host_raw, manifest_raw, binding_raw, *, review_path, review_pin, revision, tree):
    review = previous._document(review_path, review_pin)
    image.require((review["signed_revision"], review["signed_tree"]) == (revision, tree), "wrong catalog revision")
    profile = _prior(host_raw, review["prior_host_profile_digest"])
    prior = _prior(manifest_raw, review["prior_service_manifest_digest"])
    binding = _prior(binding_raw, review["prior_service_binding_digest"])
    old_host = {r["path"]: r for r in profile["files"]
                if r["path"] == host.WRAPPER or r["path"].startswith(host.PREFIX + "aragorn/")}
    image.require(all(old_host.get(p) != row and p == row["path"] for p, row in review["host_changes"].items()),
                  "redundant or malformed host delta")
    rows = old_host | review["host_changes"]
    image.require(image.pin(canonical([rows[p] for p in sorted(rows)])) == review["host_rows_digest"]
                  and len(rows) == review["host_count"], "host source inventory differs")
    old_service = {p.removeprefix(image.IMPORT_ROOT + "/"): v for p, v in binding["source_digests"].items()}
    image.require(all(old_service.get(p) != v for p, v in review["service_changes"].items()),
                  "redundant service delta")
    inventory = old_service | review["service_changes"]
    image.require(image.pin(canonical(inventory)) == review["service_inventory_digest"]
                  and len(inventory) == review["service_count"], "service source inventory differs")

    repo = {p: ("packaging/pi-core/coordinator.py" if p == host.WRAPPER else p.removeprefix("/opt/aragorn/"))
            for p in rows}
    expected = {repo[p]: r["digest"] for p, r in rows.items()}
    for name, digest in inventory.items():
        image.require(expected.setdefault("src/" + name, digest) == digest, "host and service source pins disagree")
    expected.update({WRAPPERS + "/" + name: v for name, v in review["template_digests"].items()})
    blobs = _objects(expected, revision=revision, tree=tree)
    host_code = {p: blobs[q] for p, q in repo.items()}
    image.require(all(len(host_code[p]) == r["size"] for p, r in rows.items()), "host source size differs")
    host._project_imports(host_code)
    helper = host.b60.helper_bytes(host_code[host.b60._PROBE])

    def read(root, name, _expected_pin):
        return blobs[root + "/" + name]  # Both original scanners independently check this digest.

    stdlib = image.stdlib_modules(r["path"] for r in prior["files"])
    sources, _, unsupported = image.source_closure("src", inventory, stdlib, reader=read)
    image.require(image.pin(canonical(unsupported)) == review["unsupported_import_sites_digest"] and
                  helper == host.b60.helper_bytes(sources["aragorn/pi_core_mask_probe.py"]),
                  "unsupported imports or fixed observer helper changed")
    wrappers = image._wrappers(WRAPPERS, review["template_digests"], inventory, reader=read)
    image.require({p: image.pin(v) for p, v in wrappers.items()} == review["rendered_wrapper_digests"],
                  "service wrapper rendering differs")
    service_code = {image.IMPORT_ROOT + "/" + p: v for p, v in sources.items()}
    service_code.update({"opt/aragorn/bin/" + p: v for p, v in wrappers.items()})
    meta = {k: review[k] for k in ("host_rows_digest", "host_count", "service_inventory_digest", "service_count",
                                    "rendered_wrapper_digests", "unsupported_import_sites_digest")}
    meta.update(source_revision=revision, source_tree=tree, source_signer=SIGNER,
                host_delta_count=len(review["host_changes"]), service_delta_count=len(review["service_changes"]))
    return host_code, service_code, meta
