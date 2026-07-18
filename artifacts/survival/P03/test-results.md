# P03 verification results

Environment: Windows, .NET SDK 10.0.301, target `net10.0`, Release.

| Check | Result |
| --- | --- |
| `dotnet restore Deep.Protocol.slnx` | pass |
| Release build, no restore | pass; 0 warnings, 0 errors |
| Full Release tests with XPlat coverage | pass; 65/65, 0 skipped |
| Focused opaque bundle tests | pass; 18/18 |
| Focused malformed/fuzz class | pass; 4/4 |
| Deterministic random malformed inputs inside fuzz test | 4096 |
| Coverage | 1682/5193 lines (32.38%); 748/2867 branches (26.08%) |

Evidence hashes:

- full coverage Cobertura:
  `3cc42d2a1e65ec7f12ac00d215d260801cf2843ec03a3126ae9297592ecabf20`;
- focused malformed/fuzz TRX:
  `f0597e045ea95bdd020d2d57cf59cd3abcec53b696e40f51d53b58eca37ecc33`;
- focused complete P03 TRX:
  `4a1a4327b95962914208d8b5283f07dad42e81a4f1cf926356a62405ff170fc5`.

The repository-wide coverage percentage is reported as evidence, not treated as a newly introduced
threshold. New P03 failure branches are exercised by golden, malformed, truncation, bounds,
negotiation, legacy and deterministic fuzz tests.
