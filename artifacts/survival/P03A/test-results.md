# P03A verification results

Environment: Windows, .NET SDK 10.0.301, target `net10.0`, Release.

| Check | Result |
| --- | --- |
| Restore | pass |
| Release build | pass; 0 warnings, 0 errors |
| Full Release tests with XPlat coverage | pass; 99/99, 0 skipped |
| Focused P03A tests | pass; 20/20, 0 skipped |
| P03 plus P03A focused compatibility lane | pass; 52/52 |
| Post-open ciphertext overhead bounds | pass; header/payload at overhead 0 and 513 rejected before replay |
| Every single-bit mutation of canonical 512-byte vector | pass; 4096/4096 rejected |
| Every canonical-vector truncation | pass; 512/512 rejected |
| Fixed-seed random malformed smoke | pass; 2048 inputs |
| Coverage | 2045/5550 lines (36.84%); 840/2963 branches (28.34%) |

Evidence SHA-256:

- full TRX:
  `b73646179b68389689a7d4cc0b27c04c789b87cdf5a268a81d455a86d591279f`;
- focused TRX:
  `94a4eb43a2c9d26a453b23b6769a5c6f5aee56d5554a9fe86fc5c67080403d16`;
- P03/P03A compatibility TRX:
  `eb7ff1c43f33f6d8d49039b09ea6b63cc15d1934194ad55a1c5cd676413a436a`;
- full Cobertura:
  `e9de820ac6f7bea023e9ab455571c9d2558cd87fa5a180035ce0abce2b4b8df0`;
- canonical test-adapter vector:
  `fd05c9c63ceee13607f484af5759fbfaf7a438e3aacaa01ade369fa393a882de`;
- ADR:
  `6f15ad68b89dc17ddcafa9a039f0b74076ef6abb60d0b637052d24f87f249496`.

The deterministic adapter exists only in the test assembly. Its bytes are a framing/orchestration
contract vector, not a production cryptographic or cross-language primitive vector. The
single-bit, truncation and fixed-seed suites are deterministic regression/smoke tests, not
coverage-guided fuzzing.
