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

SHA-256: full TRX `2db47c56d5cb5f4b66a9ccf338e60e4565b3c1423e893ad0d9e4ec3284a2fee4`;
focused TRX `c990ef8f524fb474db8b750fb6ab27d5f5dd391e45025ed0e8b6e8a73053eb25`;
Cobertura `2cee2923f68776faae85c5011d5fdeaeb851632c476fa5b91da713a3cdf4f5b0`;
vector `104b0de3b029b6e738be48ee81a1bd236a8a8307aa94083f959410e575c6fcad`;
ADR `a9010ff67aaa6b55cf1010356f0e5f771e9df1f1b7171f1e4feb200858b09cd8`.

The deterministic adapter is test code, not a production AKE or cross-language crypto vector.
Random malformed testing is deterministic smoke, not coverage-guided fuzzing.
