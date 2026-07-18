# P03 verification results

Environment: Windows, .NET SDK 10.0.301, target `net10.0`, Release.

| Check | Result |
| --- | --- |
| `dotnet restore Deep.Protocol.slnx` | pass |
| Release build, no restore | pass; 0 warnings, 0 errors |
| Full Release tests with XPlat coverage | pass; 78/78, 0 skipped |
| Focused opaque bundle tests | pass; 31/31, 0 skipped |
| Deterministic structural mutation cases | pass; length overflow, truncation, trailing bytes, padding, critical/required feature, payload kind, attempt/dedup and legacy branches |
| Deterministic random malformed inputs inside fuzz test | 4096 |
| Coverage | 1711/5216 lines (32.80%); 768/2879 branches (26.67%) |

Evidence hashes:

- full coverage Cobertura:
  `ce06917e32ed196e1fba3e37195a4facbb02353bf6b73720c7a06e434ed3fef0`;
- full corrective TRX:
  `61879775d3e0dad6753cd120e27d99329ff97222232dfae97ddaf44e8373ef29`;
- focused corrective P03 TRX:
  `0d3c843480d2500baf50474c4feb1ab48b8fe119175a3935010b8ce8b9b217c3`.

The repository-wide coverage percentage is reported as evidence, not treated as a newly introduced
threshold. New P03 failure branches are exercised by golden, malformed, truncation, bounds,
negotiation, legacy and deterministic structural mutation tests. The 4096 fixed-seed random
malformed inputs are a smoke test. Neither suite is coverage-guided fuzzing and no such claim is
made.
