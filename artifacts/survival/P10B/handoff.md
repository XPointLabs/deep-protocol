# P10B handoff

Current state: independent contract GO; runtime blocked.

- source: `c6fcf1a90a5bf85e613b0aa0f15cd61d5c246b2f`
- package version: `0.3.0-p10b.c6fcf1a`
- package hashes: `package-manifest.json`
- tests: `test-results.md`
- wire/security boundary: `security-boundary.md`

P10/P11B/P15 may consume the exact package/hash set. They receive no permission to activate a
server, change Docker, access live credentials, publish packages or infer mailbox authority from
outer transport.
