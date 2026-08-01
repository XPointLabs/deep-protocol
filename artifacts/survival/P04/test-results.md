# P04 verification results

Environment: Windows, .NET SDK 10.0.301, target `net10.0`, Release.
Accepted source: `b887fa088f486390be182cac4cbcb59b60ce8931`.

| Check | Result |
| --- | --- |
| Release build | pass; 0 warnings, 0 errors |
| Full Release tests with XPlat coverage | pass; 173/173, 0 skipped |
| Focused P04 membership tests | pass; 26/26, 0 skipped |
| Canonical decoder truncation/trailing/reserved/order cases | pass |
| Structured fixed-seed malformed decoder smoke | pass; 9 decoders × 300 inputs |
| Legacy fixed-seed genesis malformed smoke | pass; 2,000 inputs |
| Authority rollback/fork/overflow and active-delegation pinning | pass |
| Cross-domain update/reward/billing/bridge-to-membership negatives | pass |
| Coverage | 4,078/7,786 lines (52.37%); 1,516/3,939 branches (38.48%) |

SHA-256: full TRX `1c6b8315d6ad85aa63ebf289467e88f1f0377161fd33b45d2b63b852fb898cb9`;
focused TRX `606338960bd2a6385aabcdea8ead2cfdd707181a4c53125ffdac9b1461cf8808`;
Cobertura `2e867e45f2e8383e81e72ecc8993d2d0f6f020381f18d6d290025e1bc383e93e`;
vector `758707e4705c0499f546ce1e1e5201df253ef70822225c5fd3086c43d8d9bf45`;
ADR `a0a45103b28ad49358bc2c17ac2fbc888835e9f33d47e8abb9030c68ed8785b9`.

The deterministic signature verifier and key material are test-only. Random malformed testing is
bounded deterministic smoke, not coverage-guided fuzzing. No cross-language cryptographic
verification or production runtime is claimed.
