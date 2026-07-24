# Benchmark corpus safety boundary

The directories under `oci-fixtures/` contain inert synthetic adversarial text.
Some files use the conventional `SKILL.md` name because the pinned scanners require
that input shape, but their natural-language content includes simulated prompt
injection, persistence, destructive-action, credential-access, and propagation
requests. They are test data, not agent instructions.

- Do not add `benchmark/`, `benchmark/oci-fixtures/`, or a descendant as an agent
  skill, extension, plugin, memory, retrieval, or auto-discovery root.
- Do not point a development agent's recursive instruction loader at this tree.
- Only the bounded benchmark preparation path may materialize an exact
  digest-verified case into a scanner workspace.
- Never give these fixtures production credentials, network access, writable host
  mounts, or execution authority.
- A future non-text corpus belongs in controlled external storage, not this
  repository.

The supported harness conformance tests must prove that their configured discovery
roots exclude this directory before they are allowed to consume the corpus.
