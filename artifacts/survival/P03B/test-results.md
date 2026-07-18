# P03B verification results

Environment: Windows, .NET SDK 10.0.301, target `net10.0`, Release.

| Check | Result |
| --- | --- |
| Locked restore | pass |
| Release build | pass; 0 warnings, 0 errors |
| Full Release tests with XPlat coverage | pass; 130/130, 0 skipped |
| Focused P03B mailbox tests | pass; 31/31, 0 skipped |
| Capability truncations | every prefix shorter than the canonical vector rejected |
| Replica/quorum/error truncations | every prefix shorter than each canonical statement rejected |
| Fixed-seed malformed smoke | pass; 2,000 capability plus 2,000 quorum inputs |
| Structured mutations | version/domain/lifecycle/reserved/length/trailing/signature rejected |
| Coverage | 2,638/6,228 lines (42.35%); 1,090/3,285 branches (33.18%) |

Evidence SHA-256:

- full TRX:
  `3fce642fd791b8e3bf01f492b5474da88cf9545ca8065ff47c208140f2fde27e`;
- focused TRX:
  `d70a55abdf03bc8523d535192372835997d0a745981311aa2e66193b8626206f`;
- full Cobertura:
  `4dddffc56bcaa362fe114116bb32f9dfa5b6b6ae3e52c595994c94fb9e6080a1`;
- capability vector:
  `6090cf6d4e97db1e08e1eb988a8276bfd38ab72c962702708d93a2d136e23b90`;
- receipt vectors:
  `ca3a385d7ae07fdccc37d2d5661387a1deed102a542752889db5307b7ff9b20e`;
- ADR:
  `909d3ea771e83cd7b8dbbe694f51cc2897487499ff44a3bf81d3fff73b693464`.

The deterministic test signatures are framing/verifier fixtures, not production cryptographic
vectors. Fixed-seed random suites are deterministic regression smoke, not coverage-guided fuzzing.
