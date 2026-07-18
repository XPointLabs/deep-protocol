# P03A verification results

Environment: Windows, .NET SDK 10.0.301, target `net10.0`, Release.

| Check | Result |
| --- | --- |
| Restore | pass |
| Release build | pass; 0 warnings, 0 errors |
| Full Release tests with XPlat coverage | pass; 95/95, 0 skipped |
| Focused P03A tests | pass; 16/16, 0 skipped |
| P03 plus P03A focused compatibility lane | pass; 48/48 |
| Every single-bit mutation of canonical 512-byte vector | pass; 4096/4096 rejected |
| Every canonical-vector truncation | pass; 512/512 rejected |
| Fixed-seed random malformed smoke | pass; 2048 inputs |
| Coverage | 2027/5536 lines (36.61%); 841/2957 branches (28.44%) |

Evidence SHA-256:

- full TRX:
  `4d7daa759de82ac9ae2a085d8096d5f7e6bceea9df8fbadedb1dfcf864605b0c`;
- focused TRX:
  `9598c9ed8cd1aa4193961df2a72b03addff2ef9c69d369a62794b47f922b6b51`;
- full Cobertura:
  `49526733e280e7279ff7bd29f261289e7c7f3cee4b98f72c638a69de47177d8c`;
- canonical test-adapter vector:
  `fd05c9c63ceee13607f484af5759fbfaf7a438e3aacaa01ade369fa393a882de`;
- ADR:
  `6f15ad68b89dc17ddcafa9a039f0b74076ef6abb60d0b637052d24f87f249496`.

The deterministic adapter exists only in the test assembly. Its bytes are a framing/orchestration
contract vector, not a production cryptographic or cross-language primitive vector. The
single-bit, truncation and fixed-seed suites are deterministic regression/smoke tests, not
coverage-guided fuzzing.

