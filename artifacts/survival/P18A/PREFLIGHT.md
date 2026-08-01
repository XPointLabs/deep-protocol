# P18A preflight evidence

Status: prerequisites accepted; red phase authorized.

Human owner: Mr. X.

## Immutable repository pins

- repository: `deep-protocol`;
- branch: `survival/w03-p18a-lora-fragment`;
- exact source base:
  `b887fa088f486390be182cac4cbcb59b60ce8931`;
- required P03C ancestor:
  `261c77658c8ff1f51ba45116ca8d938b1336eaa9`;
- ancestry proof: PASS;
- accepted P03C local package identity: `0.3.0-p03c.261c776`;
- initial worktree/index: clean.

The branch was created directly from the accepted P04 source commit. No
evidence-only carrier was used as the source base.

## W1/W2 closure

- independently reviewed DevOps evidence:
  `1c01e24e24647a46b4f37622f3934dc2cc1284ef`;
- detached compatibility carrier:
  `524c5796aa868fa3d057fbf7eaa13cfea2e0d19c`;
- `deep-protocol` evidence carrier:
  `db58937d4070eb057642c00d10a64d2f738f6e41`;
- detached manifest raw SHA-256:
  `920b24bb5bcfcc8b4f91aef56ed210127246ec9fd2d49178ed9856c8555d0b93`;
- compatibility contract raw SHA-256:
  `c45f66f7a688cbd70b7ca57a777851962ce2ab59eb37a3304d9b4bf7e4c55719`;
- strict producer artifacts: 17/17;
- independent closure verdict: GO, P0/P1/P2/P3 = 0/0/0/0.

The immutable detached manifest itself has no
`independentReviewRequired=true` field. The older closure-evidence JSON
retains that historical pre-review flag; the later independent handoff
records the GO above. This P18A evidence does not rewrite or reinterpret
either immutable artifact.

## Scope and execution boundary

P18A is an offline, local contract/vector/package slice. It may define a
Deep-extension frame, opaque authentication/replay adapter boundaries,
bounded planner/reassembly state, deterministic test-only vectors and local
packages.

It does not authorize:

- a production authenticator, link-key derivation or secret storage;
- runtime dependency injection or a durable production replay store;
- BLE, USB, LoRa, radio, simulator or hardware behavior;
- frequency, region, power, airtime or legal defaults;
- Docker, deployment, blockchain or billing work;
- credentials, seed phrases, private keys or environment-secret inspection;
- network restore, package publication, GitHub push or pull request;
- production, anonymity, battery, range or censorship-resistance claims.

No forbidden action was performed during preflight.
