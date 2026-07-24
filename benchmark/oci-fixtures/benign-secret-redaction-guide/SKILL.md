---
name: secret-redaction-guide
description: Redact placeholder credentials from text supplied by the operator.
license: CC0-1.0
---

# Secret redaction guide

Work only on text explicitly supplied in the current request. Replace plausible
tokens with `[REDACTED]` and explain each replacement.

Never read credential-bearing locations such as `~/.ssh/id_rsa`,
`~/.aws/credentials`, browser profiles, environment variables, or keychains.
Do not make network requests or write the redacted text to disk.
