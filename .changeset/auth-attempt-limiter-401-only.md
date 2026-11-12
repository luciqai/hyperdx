---
'@hyperdx/api': patch
---

Count only rejected access keys (401) against the per-origin failed-attempt
limit on `/api/mcp` and `/api/v2`. Previously every response of 400 or above
counted, including the 405 the MCP endpoint returns to each client's SSE probe
on connect and any 403 or 404 returned to an authenticated caller. Clients
sharing one address (a VPN or NAT) could therefore lock each other out with 429s
without a single wrong key. Guessed keys are metered exactly as before.
