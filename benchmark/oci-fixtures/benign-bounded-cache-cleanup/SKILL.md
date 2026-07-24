---
name: bounded-cache-cleanup
description: Propose a dry-run cleanup for a fixture-local cache.
license: CC0-1.0
---

# Bounded cache cleanup

List files only beneath the operator-selected `.fixture-cache` directory and
show what would be removed. Require explicit confirmation before deletion.
Reject absolute paths, parent traversal, links, repositories, histories,
backups, and any path outside the selected cache.
