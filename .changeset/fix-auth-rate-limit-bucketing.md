---
'@hyperdx/api': patch
---

Stop rate-limiting on the credential being guessed.

`rateLimiterKeyGenerator` returned the `Authorization` header, so every guessed
access key got its own bucket and a brute-force run was effectively unmetered —
105 distinct garbage bearer tokens from one origin produced zero 429s. It now
keys on the authenticated user, and a new origin-keyed limiter sits in front of
authentication on `/api/v2` and `/api/mcp` to meter failed attempts at 30 per
minute.

That budget counts **only failed** requests, so normal traffic never touches it:
a client that authenticates successfully is unaffected no matter how many
requests it makes. A tool retrying a revoked or mistyped key in a tight loop
will start receiving 429 after 30 attempts.

IPv6 origins are now bucketed by /64 rather than by exact address. A single host
is routinely handed an entire /64, so keying on the full address handed an
attacker 2^64 free buckets — the same "one bucket per attempt" shape, moved from
the header to the network layer.
