# P03B verification results

Environment: Windows, .NET SDK 10.0.301, target `net10.0`, Release.

| Check | Result |
| --- | --- |
| Locked restore | pass |
| Release build | pass; 0 warnings, 0 errors |
| Full Release tests with XPlat coverage | pass; 133/133, 0 skipped |
| Focused P03B mailbox tests | pass; 34/34, 0 skipped |
| Capability truncations | every prefix shorter than the canonical vector rejected |
| Replica/quorum/error truncations | every prefix shorter than each canonical statement rejected |
| Fixed-seed malformed smoke | pass; 2,000 capability plus 2,000 quorum inputs |
| Structured mutations | version/domain/lifecycle/reserved/length/trailing/signature rejected |
| Review corrections | false equivocation, admission time, idempotent retry/conflict and expected-context substitution tests pass |
| Coverage | 2,710/6,305 lines (42.98%); 1,124/3,326 branches (33.79%) |

Evidence SHA-256:

- full TRX:
  `c212d25757738011ed37c0edcb0c6fc2ff0bf8a3a44866d8ae57ee46e6189b7a`;
- focused TRX:
  `a88250007cd5bf3c2bc0af5cc59f358154c1380dfd8488edf6999fea27e24f16`;
- full Cobertura:
  `8fa41893bde29ff4c5a2df65f08daaf8717af694e5283e7c592385e244ec4178`;
- capability vector:
  `6090cf6d4e97db1e08e1eb988a8276bfd38ab72c962702708d93a2d136e23b90`;
- receipt vectors:
  `ca3a385d7ae07fdccc37d2d5661387a1deed102a542752889db5307b7ff9b20e`;
- ADR:
  `68bbc876c50a8f7edd1d85db6f1b25719ff0de3d9e8679e5178fb2a16113bf36`.

The deterministic test signatures are framing/verifier fixtures, not production cryptographic
vectors. Fixed-seed random suites are deterministic regression smoke, not coverage-guided fuzzing.
