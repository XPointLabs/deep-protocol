# P03 verification results

Environment: Windows, .NET SDK 10.0.301, target `net10.0`, Release.

| Check | Result |
| --- | --- |
| `dotnet restore Deep.Protocol.slnx` | pass |
| Release build, no restore | pass; 0 warnings, 0 errors |
| Full Release tests with XPlat coverage | pass; 79/79, 0 skipped |
| Focused opaque bundle tests | pass; 32/32, 0 skipped |
| Deterministic structural mutation cases | pass; length overflow, truncation, trailing bytes, padding, critical/required feature, payload kind, attempt/dedup and legacy branches |
| Deterministic random malformed inputs inside fuzz test | 4096 |
| Coverage | 1718/5216 lines (32.93%); 764/2879 branches (26.53%) |

Evidence hashes:

- full coverage Cobertura:
  `b38a30af668575aa294c03407ad99f827f7f0b6d126b191e39634450acec106f`;
- full corrective TRX:
  `83c5f401fb6850dd770c6b0d0e8d0718119602d8d7856dbde9314cd342e5954c`;
- focused corrective P03 TRX:
  `73c5fa82ea43ad756850bb12edde1851582a8ec9d04acf5ffdf8e35555307dd9`.

The repository-wide coverage percentage is reported as evidence, not treated as a newly introduced
threshold. New P03 failure branches are exercised by golden, malformed, truncation, bounds,
negotiation, legacy and deterministic structural mutation tests. The 4096 fixed-seed random
malformed inputs are a smoke test. Neither suite is coverage-guided fuzzing and no such claim is
made.
