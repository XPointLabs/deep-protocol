# P03C verification results

Environment: Windows, .NET SDK 10.0.301, target `net10.0`, Release.

| Check | Result |
| --- | --- |
| Release build | pass; 0 warnings, 0 errors |
| Full Release tests with XPlat coverage | pass; 146/146, 0 skipped |
| Focused P03C tests | pass; 13/13, 0 skipped |
| Advertisement/frame truncations | every canonical prefix rejected |
| Fixed-seed malformed frame smoke | pass; 2,000 inputs |
| Wrong contact/tamper/replay | rejected by deterministic test-only adapter contract |
| Coverage | 2,972/6,619 lines (44.90%); 1,215/3,493 branches (34.78%) |

SHA-256: full TRX `e5dac98e1db24e321261a29fb286d6065f9e11df4263badbbe10f5c698bf33e3`;
focused TRX `3476d6588107726d946903f85df19c3747b3be1ce827b63b2610ebf6d2d19f73`;
Cobertura `c3f86f64622a996e5aed6c2e7175ccd2faa50d333e9e247367a16bfbd2a5c0d4`;
vector `665e0d69c732205a0b9e7178fc7180550dbc933800816cfb8e8d68d8b90d413a`;
ADR `5ddc17a76003cb7db9b839893ab49a3ffd77c78924453882dc8974ca68121cc1`.

The deterministic adapter is test code, not a production AKE or cross-language crypto vector.
Random malformed testing is deterministic smoke, not coverage-guided fuzzing.
