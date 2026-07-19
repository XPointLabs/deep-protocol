# P10B test results

Exact source: `c6fcf1a90a5bf85e613b0aa0f15cd61d5c246b2f`.

| Gate | Result | Evidence |
| --- | --- | --- |
| Release build | 0 warnings, 0 errors | local exact-source run |
| Focused `ManagedIngress` | 116 passed, 0 failed, 0 skipped | `results/p10b-focused.trx`, SHA-256 `23f71a337d12f18c53d6419b6fd0deb169c42d4584cac42e5d35015c6788aa85` |
| Focused malformed/fuzz | 41 passed, 0 failed, 0 skipped | independent exact-source rerun |
| Full solution | 289 passed, 0 failed, 0 skipped | `results/p10b-full.trx`, SHA-256 `2d1efe933f24f7692ced8546c1ec3903bf8ebefa85a82524346c7a6157e57a4e` |
| format | PASS | `dotnet format Deep.Protocol.slnx --verify-no-changes --no-restore` |
| exact-base ancestry | PASS | `db58937...` is an ancestor of source |
| production inner-codec reference scan | PASS | no matches |
| production accepted/durable/delivered word scan | PASS | no matches |

The focused count includes fixed-seed malformed `DIE1` smoke, exact error/status/retry mappings,
canonical capabilities, header privacy/bounds, streaming truncation/overflow/cancellation and the
language-neutral fixtures and the reproducible worst-case bound for the selected three-hop
producer profile.

No server, Docker, network path, live TLS, Android device, Windows application or end-to-end
messaging test is claimed by this contract-only gate.
