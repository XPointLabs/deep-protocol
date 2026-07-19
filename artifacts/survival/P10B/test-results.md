# P10B test results

Exact source: `7cf846a51411b82b1e4146940a72c80fa2ec16fb`.

| Gate | Result | Evidence |
| --- | --- | --- |
| Release build | 0 warnings, 0 errors | local exact-source run |
| Focused `ManagedIngress` | 96 passed, 0 failed, 0 skipped | `results/p10b-focused.trx`, SHA-256 `5e42c03ef6fb406738c04018e3392eacb82d2377025893dd7118858101a3e61f` |
| Full solution | 269 passed, 0 failed, 0 skipped | `results/p10b-full.trx`, SHA-256 `d03066ed19e004ff489876a51a76d34577c232571c08b304f0686528594c9ef1` |
| format | PASS | `dotnet format Deep.Protocol.slnx --verify-no-changes --no-restore` |
| exact-base ancestry | PASS | `db58937...` is an ancestor of source |
| production inner-codec reference scan | PASS | no matches |
| production accepted/durable/delivered word scan | PASS | no matches |

The focused count includes fixed-seed malformed `DIE1` smoke, exact error/status/retry mappings,
canonical capabilities, header privacy/bounds, streaming truncation/overflow/cancellation and the
maximum selected three-hop producer profile.

No server, Docker, network path, live TLS, Android device, Windows application or end-to-end
messaging test is claimed by this contract-only gate.
