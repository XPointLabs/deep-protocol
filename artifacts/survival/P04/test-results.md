# P04 verification results

Environment: Windows, .NET SDK 10.0.301, target `net10.0`, Release.
Accepted source: `388e482823c8e5d0844c0468ad48d76958d6065e`.

| Check | Result |
| --- | --- |
| Release build | pass; 0 warnings, 0 errors |
| Full Release tests with XPlat coverage | pass; 166/166, 0 skipped |
| Focused P04 membership tests | pass; 19/19, 0 skipped |
| Canonical decoder truncation/trailing/reserved/order cases | pass |
| Structured fixed-seed malformed decoder smoke | pass; 9 decoders × 300 inputs |
| Legacy fixed-seed genesis malformed smoke | pass; 2,000 inputs |
| Authority rollback/fork/overflow and active-delegation pinning | pass |
| Cross-domain update/reward/billing/bridge-to-membership negatives | pass |
| Coverage | 3,983/7,662 lines (51.98%); 1,422/3,803 branches (37.39%) |

SHA-256: full TRX `6bb444d6f8d91ba1762d91dd2f5b6a1588a955c86529380c784eba17fe5f159a`;
focused TRX `bc4847fb342128bf20922c35040a65109a7666723336fc646e11b0a809555701`;
Cobertura `93043724f6060aaca6a4f1741b8257c561d9ea551b4b2fbfcc0dc950830cd468`;
vector `4c1c4d45b9653f78eeade016d409e104013dcdd6dd55f7414b15ead77e26e5d5`;
ADR `ae0b42d522fbba0cc44e1a3c06d8b127a5a85aed137f55b589028ffb4306cc6e`.

The deterministic signature verifier and key material are test-only. Random malformed testing is
bounded deterministic smoke, not coverage-guided fuzzing. No cross-language cryptographic
verification or production runtime is claimed.
