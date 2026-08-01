# P10B independent review

Status: GO for contract package; runtime blocked.

The earlier review of rejected candidate `c6e3a5dca3b1159bfdd978cf128edd1b58eff967`
reported P0/P1/P2/P3 = 0/5/4/0. That candidate started from the wrong base and its packages carried
an invalid source commit. It is not an accepted artifact.

The first v2 rereview of `7cf846a...` reported P0/P1/P2/P3 = 0/3/3/1. Corrective red
`ab672f6...` and source commits through `c6fcf1a...` permanently poison failed streaming
admissions, bind success to actual complete body bytes, include mandatory response headers in
limits, enforce strict supplemental-header grammar, and add language-neutral fixtures plus a
deterministic worst-case producer bound.

The independent v3 rereview covered evidence HEAD `a21b2a2cbbec845b5497601d6bbf21c1283fd236`,
evidence content `b456d4826286f96bb42ac1e7eeddf5a66ca862f1` and source
`c6fcf1a90a5bf85e613b0aa0f15cd61d5c246b2f`.

Verdict: GO, P0/P1/P2/P3 = 0/0/0/2.

Repeated gates:

- Release build 0 warnings/errors, format PASS;
- focused 116/116, malformed 41/41, full 289/289;
- exact base ancestry and raw P03/P03B/P04 manifest hashes MATCH;
- prompt, package manifest, nupkg and TRX hashes MATCH;
- every nuspec names the exact existing source commit;
- no production inner-codec, protobuf, Abstractions or runtime dependency.

All previous P1/P2 findings are closed. P3 advisories:

1. the language-neutral maximum-producer vector uses the generic `timestampMs` field for a byte
   bound and substring assertions rather than a dedicated structured schema;
2. `work-package-report.json` names `449e3c1...` as the immutable evidence carrier while the later
   bookkeeping wrapper reviewed at HEAD is `a21b2a2...`.

These do not affect wire behavior, source/package identity or safety. P10B remains contract-only;
server/runtime activation is blocked.
