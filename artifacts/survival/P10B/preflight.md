# P10B preflight

Status: local contract green / independent review pending / runtime blocked.

- Human owner: Mr. X.
- Prompt SHA-256: `02bc3fa1b13adfc96a97d6553000a2d8f3fac4ad6b3e5b4ddb4c4ceab08ef2d4`.
- Accepted W1/W2 evidence: `1c01e24e24647a46b4f37622f3934dc2cc1284ef`.
- W1/W2 carrier: `524c5796aa868fa3d057fbf7eaa13cfea2e0d19c`.
- Detached manifest SHA-256: `920b24bb5bcfcc8b4f91aef56ed210127246ec9fd2d49178ed9856c8555d0b93`.
- Accepted P04 source/base: `b887fa088f486390be182cac4cbcb59b60ce8931`.
- P04 evidence carrier: `db58937d4070eb057642c00d10a64d2f738f6e41`.
- P03 source/evidence: `814f15d8965da8728132ba35a61cf47457b2b00b` /
  `90e306ebf9d4ce722b95f128f5ff4bebcaddcde3`.
- P03B source/evidence: `6e2c709a378ffac40c441e97e2e4da40aac9a104` /
  `b1d74e5229137928bf9c70daa0dc133350a98c34`.
- P05 is design-only and not approved.

The explicit dispatch selected the accepted P04 source commit as the worktree base, while the
accepted W1/W2 manifest pins the later P04 evidence carrier. This is recorded rather than silently
moving either pin.

P10B owns only a bounded outer H2 opaque-transit contract. It does not implement a server, inner
mailbox semantics, storage, deployment, TLS, DNS, Docker, network access or production keys.
HTTP success is never accepted, durable or delivered authority.
