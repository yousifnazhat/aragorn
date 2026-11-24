"""Local one-file capability profile. Inventory alone does not authorize a run."""
from aragorn.acquire import ingest_local


MAX_BYTES = 32 * 1024


def inventory_worker(directory, cas):
    manifest = ingest_local(directory, cas, max_depth=0, max_files=1,
                            max_file_size=MAX_BYTES, max_total_bytes=MAX_BYTES)
    if [f["path"] for f in manifest["files"]] != ["worker.py"]:
        raise ValueError("local capability must contain exactly one regular worker.py")
    return manifest


def retained_source(manifest, cas):
    return cas.read(manifest["files"][0]["digest"], max_bytes=MAX_BYTES)


def approved_worker(directory, cas, approved_tree):
    manifest = inventory_worker(directory, cas)
    if manifest["tree_digest"] != approved_tree:
        raise ValueError("capability differs from the approved inventory; worker not started")
    # Do not resolve the mutable source path again between approval and exec.
    return retained_source(manifest, cas)
