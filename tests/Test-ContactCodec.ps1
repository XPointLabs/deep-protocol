[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
$project = Join-Path $repository 'tests\Deep.Protocol.Tests\Deep.Protocol.Tests.csproj'
$vectorsPath = Join-Path (Split-Path -Parent $repository) 'docs\survival-program\releases\v3.0.0\specs\contact-codec-v1.vectors.json'
$vectors = Get-Content -LiteralPath $vectorsPath -Raw | ConvertFrom-Json

if ($vectors.ed25519Fixtures.Count -ne 3 -or
    @($vectors.ed25519Fixtures | Where-Object {
        -not $_.projectionPrimitiveId -or -not $_.signatureDomain -or
        $_.seedHex.Length -ne 64 -or $_.publicKeyHex.Length -ne 64 -or $_.signatureHex.Length -ne 128
    }).Count -ne 0) {
    throw 'CONTACT-CODEC frozen vectors must contain three complete deterministic Ed25519 fixtures.'
}

dotnet test $project -c Release --filter 'FullyQualifiedName~Deep.Protocol.Tests.ContactV1'
if ($LASTEXITCODE -ne 0) {
    throw "CONTACT-CODEC focused Release checker failed with exit code $LASTEXITCODE."
}
