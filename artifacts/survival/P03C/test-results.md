# P03C verification results

Environment: Windows, .NET SDK 10.0.301, target `net10.0`, Release.

| Check | Result |
| --- | --- |
| Release build | pass; 0 warnings, 0 errors |
| Full Release tests with XPlat coverage | pass; 147/147, 0 skipped |
| Focused P03C tests | pass; 14/14, 0 skipped |
| Advertisement/frame truncations | every canonical prefix rejected |
| Fixed-seed malformed frame smoke | pass; 2,000 inputs |
| Wrong contact/tamper/replay | rejected by deterministic test-only adapter contract |
| Coverage | 3,015/6,661 lines (45.26%); 1,230/3,511 branches (35.03%) |

SHA-256: full TRX `930ab314fb9c1d9d30ac1413ab34c4ac20eee6f309d4ef4fc551bb7330fc7582`;
focused TRX `92c6d04e89052703577c02ee5b9d2c652280d57eaaac7f8287eb96d6b8b48df7`;
Cobertura `ba863e7a50a7fa14bf79654386c12e62cfa789df7c91863ee7f75633f1e986fa`;
vector `104b0de3b029b6e738be48ee81a1bd236a8a8307aa94083f959410e575c6fcad`;
ADR `a9010ff67aaa6b55cf1010356f0e5f771e9df1f1b7171f1e4feb200858b09cd8`.

The deterministic adapter is test code, not a production AKE or cross-language crypto vector.
Random malformed testing is deterministic smoke, not coverage-guided fuzzing.
