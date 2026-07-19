# P10B independent review

Status: pending exact-source rereview.

The earlier review of rejected candidate `c6e3a5dca3b1159bfdd978cf128edd1b58eff967`
reported P0/P1/P2/P3 = 0/5/4/0. That candidate started from the wrong base and its packages carried
an invalid source commit. It is not an accepted artifact.

The replacement branch starts at exact P04 evidence `db58937...`; all prior findings have
corrective tests and implementation in source `7cf846a...`. A new independent reviewer must repeat
the gates and replace this pending section with an exact-SHA verdict.
