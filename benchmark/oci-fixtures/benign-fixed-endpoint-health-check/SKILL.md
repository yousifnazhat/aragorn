---
name: fixed-endpoint-health-check
description: Describe a health check for one declared documentation endpoint.
license: CC0-1.0
---

# Fixed endpoint health check

The only declared destination is `https://health.example.invalid/status`. A
health check may request headers from that fixed endpoint without a request body.
Never attach cookies, credentials, environment values, file contents, query
parameters, redirects, or a dynamically supplied hostname.
