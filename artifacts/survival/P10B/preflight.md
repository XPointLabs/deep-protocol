# P10B preflight

Status: exact-base gate passed; runtime remains blocked.

- W1/W2 manifest carrier: `524c5796aa868fa3d057fbf7eaa13cfea2e0d19c`
- W1/W2 validation evidence: `1c01e24e24647a46b4f37622f3934dc2cc1284ef`
- detached manifest SHA-256:
  `920b24bb5bcfcc8b4f91aef56ed210127246ec9fd2d49178ed9856c8555d0b93`
- compatibility contract SHA-256:
  `c45f66f7a688cbd70b7ca57a777851962ce2ab59eb37a3304d9b4bf7e4c55719`
- exact P10B base: `db58937d4070eb057642c00d10a64d2f738f6e41`
- P10B source: `7cf846a51411b82b1e4146940a72c80fa2ec16fb`
- prompt SHA-256:
  `02bc3fa1b13adfc96a97d6553000a2d8f3fac4ad6b3e5b4ddb4c4ceab08ef2d4`

`db58937...` is an ancestor of the source commit. Raw Git bytes of the accepted historical package
manifests match:

| Contract | Evidence commit | SHA-256 |
| --- | --- | --- |
| P03 | `90e306ebf9d4ce722b95f128f5ff4bebcaddcde3` | `87b6bafd6f3f065a720f078cee3cbad41b76492fa2c2bceb607da1ddb32b7b77` |
| P03B | `b1d74e5229137928bf9c70daa0dc133350a98c34` | `1c820f59033bee6157ecc89c9d7123664f404a6b6a9f5a05703667be5f45f694` |
| P04 | `db58937d4070eb057642c00d10a64d2f738f6e41` | `fd3ef27bf0b9272570d6c6e680a3c99e581f6220799d13ee3afbd86ea0e99298` |

P05 carrier `b986fe3bbbe3b47b3a13aac1e9da64e9969cb02c` is a
design-review GO but remains proposed/not approved. P10B imports no P05/P05A/P06/P07 runtime type.
Those work packages remain activation and E2E dependencies.

No server, Docker topology, live endpoint, blockchain, credential, publish or push operation is
part of this evidence.
