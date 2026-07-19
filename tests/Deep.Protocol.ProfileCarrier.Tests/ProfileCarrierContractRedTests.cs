using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;

namespace Deep.Protocol.ProfileCarrier.Tests;

public sealed class ProfileCarrierContractRedTests
{
    [Fact]
    public void ComposerMatchesAcceptedXNodeGoldenBytesAndInspectorRoundTripsExactly()
    {
        var parts = SyntheticProfileFixture.Parts();
        var oracle = AcceptedXNodeDpf1Oracle.Encode(parts);
        var golden = GoldenCorpus.Load();

        Assert.Equal(golden.Hex, Convert.ToHexStringLower(oracle));
        Assert.Equal(golden.Sha256, Convert.ToHexStringLower(SHA256.HashData(oracle)));

        var composed = ProfileCarrierComposer.ComposeExact(
            Input(parts),
            Options(),
            SyntheticProfileFixture.Verifier());
        Assert.Equal(oracle, composed.FilePayload.ToArray());
        Assert.Equal("sha256:989287543166ae448ee19453e6e748115e2df3c2756b63acf0d108a247a281d4", composed.Fingerprint);
        Assert.Equal(1, composed.MinimumProtocol);
        Assert.Equal(3, composed.MaximumProtocol);
        Assert.Equal(4, composed.ComponentCount);
        Assert.Equal(1, composed.BridgeCount);

        var verified = ProfileCarrierVerifier.VerifyExact(
            composed.FilePayload.Span,
            Options(),
            SyntheticProfileFixture.Verifier());
        Assert.Equal(composed.FilePayload.ToArray(), verified.FilePayload.ToArray());
        Assert.Equal(composed.Fingerprint, verified.Fingerprint);
        Assert.Equal(composed.FilePayloadSha256.ToArray(), verified.FilePayloadSha256.ToArray());
        Assert.Equal(composed.ComponentCount, verified.ComponentCount);
        Assert.Equal(composed.BridgeCount, verified.BridgeCount);
    }

    [Fact]
    public void InputPermutationsHaveOneCanonicalOutput()
    {
        var canonical = SyntheticProfileFixture.Parts(bridgeCount: 2);
        var permuted = SyntheticProfileFixture.Parts(
            reverseGenesisSignatures: true,
            reverseBridges: true,
            bridgeCount: 2);

        var first = ProfileCarrierComposer.ComposeExact(
            Input(canonical),
            Options(),
            SyntheticProfileFixture.Verifier());
        var second = ProfileCarrierComposer.ComposeExact(
            Input(permuted),
            Options(),
            SyntheticProfileFixture.Verifier());

        Assert.Equal(first.FilePayload.ToArray(), second.FilePayload.ToArray());
    }

    internal static ProfileCarrierAssemblyInput Input(SyntheticProfileParts parts) =>
        new(
            parts.CanonicalGenesis,
            parts.GenesisApprovals,
            parts.CanonicalSignedDelegation,
            parts.CanonicalSignedBridges.Select(static value =>
                (ReadOnlyMemory<byte>)value));

    internal static ProfileCarrierVerificationOptions Options() =>
        new(
            SyntheticProfileFixture.VerificationTime,
            allowedClockSkewSeconds: 30,
            SyntheticProfileFixture.Protocol);

    private sealed record GoldenCorpus(
        string SourceCommit,
        string Sha256,
        string Hex)
    {
        public static GoldenCorpus Load()
        {
            var path = Path.Combine(AppContext.BaseDirectory, "Vectors", "dpf1-v1.golden.json");
            return JsonSerializer.Deserialize<GoldenCorpus>(
                File.ReadAllText(path),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
        }
    }
}
