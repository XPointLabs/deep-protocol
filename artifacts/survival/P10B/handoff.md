# P10B handoff

Current state: contract candidate complete; independent rereview pending; runtime blocked.

- source: `7cf846a51411b82b1e4146940a72c80fa2ec16fb`
- package version: `0.3.0-p10b.7cf846a`
- package hashes: `package-manifest.json`
- tests: `test-results.md`
- wire/security boundary: `security-boundary.md`

P10/P11B/P15 may consume only after independent P10B GO. They receive no permission to activate a
server, change Docker, access live credentials, publish packages or infer mailbox authority from
outer transport.
