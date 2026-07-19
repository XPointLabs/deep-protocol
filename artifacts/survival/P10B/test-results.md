# P10B test results

Reviewed source candidate: `9815aa5b8c5f46f67977e955bf12df39e64b0ec4`.

| Gate | Exact command | Exit | Result |
| --- | --- | ---: | --- |
| Red | `dotnet test tests\Deep.Protocol.Tests\Deep.Protocol.Tests.csproj -c Release --filter "FullyQualifiedName~ManagedIngress" -p:NuGetAudit=false` | 1 | Missing P10B namespace/types, as intended |
| Focused | `dotnet test tests\Deep.Protocol.Tests\Deep.Protocol.Tests.csproj -c Release --no-build --filter "FullyQualifiedName~ManagedIngress" --logger "trx;LogFileName=p10b-focused.trx" --results-directory artifacts\survival\P10B\test-results -p:NuGetAudit=false` | 0 | 71/71, 0 failed/skipped |
| Build | `dotnet build Deep.Protocol.slnx -c Release --no-restore -p:NuGetAudit=false` | 0 | 0 warnings/errors |
| Full+coverage | `dotnet test Deep.Protocol.slnx -c Release --no-build --collect:"XPlat Code Coverage" --logger "trx;LogFileName=p10b-full.trx" --results-directory artifacts\survival\P10B\test-results -p:NuGetAudit=false` | 0 | 244/244, 0 failed/skipped |

Evidence hashes:

- focused TRX: `4dc271682e806f6352829f3132b922f374c2a32ec5174b027aac7b28b6b43280`;
- full TRX: `6e920ca5a3378a4e65ca46a970734199044a94c1cba210c35ac8cd88f52b91a4`;
- Cobertura: `126d6b3e34065995087bb3152df88542219ecb129a80dd20f29864a9d6c13e12`.

No server, Docker, network, TLS, deployment or live-key test was run.
