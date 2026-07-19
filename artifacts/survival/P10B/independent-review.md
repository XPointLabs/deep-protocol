# P10B independent review

Status: pending corrective exact-source rereview.

The earlier review of rejected candidate `c6e3a5dca3b1159bfdd978cf128edd1b58eff967`
reported P0/P1/P2/P3 = 0/5/4/0. That candidate started from the wrong base and its packages carried
an invalid source commit. It is not an accepted artifact.

The first v2 rereview of `7cf846a...` reported P0/P1/P2/P3 = 0/3/3/1. Corrective red
`ab672f6...` and source commits through `c6fcf1a...` permanently poison failed streaming
admissions, bind success to actual complete body bytes, include mandatory response headers in
limits, enforce strict supplemental-header grammar, and add language-neutral fixtures plus a
deterministic worst-case producer bound.

A new independent reviewer must repeat every exact-source, package and evidence gate and replace
this pending section with an exact-SHA verdict.
