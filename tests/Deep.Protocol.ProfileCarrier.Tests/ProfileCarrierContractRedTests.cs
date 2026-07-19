using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.Membership;
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

        Assert.Equal(
            "eff452368fa4cb1324c5b3c8ee06e2f10e96b835",
            golden.SourceCommit);
        Assert.Equal(golden.Hex, Convert.ToHexStringLower(oracle));
        Assert.Equal(golden.Sha256, Convert.ToHexStringLower(SHA256.HashData(oracle)));

        var composed = ProfileCarrierComposer.ComposeExact(
            Input(parts),
            Options(),
            SyntheticProfileFixture.Verifier());
        Assert.Equal(oracle, composed.FilePayload.ToArray());
        Assert.Equal(
            "sha256:f297fde558e06fb88b83ab638e7bd85113a5d0cf617e3d4fe20d8e77a9b18fe2",
            composed.Fingerprint);
        Assert.Equal(1, composed.MinimumProtocol);
        Assert.Equal(3, composed.MaximumProtocol);
        Assert.Equal(4, composed.ComponentCount);
        Assert.Equal(1, composed.BridgeCount);

        var verified = ProfileCarrierVerifier.VerifyExact(
            composed.FilePayload.Span,
            Options(),
            SyntheticProfileFixture.Verifier());
        Assert.Equal(composed.Fingerprint, verified.Fingerprint);
        Assert.Equal(composed.FilePayloadSha256.ToArray(), verified.FilePayloadSha256.ToArray());
        Assert.Equal(composed.MinimumProtocol, verified.MinimumProtocol);
        Assert.Equal(composed.MaximumProtocol, verified.MaximumProtocol);
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

    [Fact]
    public void InputsAndCompositionOutputsAreDefensiveCopies()
    {
        var parts = SyntheticProfileFixture.Parts();
        var input = Input(parts);
        var first = ProfileCarrierComposer.ComposeExact(
            input,
            Options(),
            SyntheticProfileFixture.Verifier());
        var expected = first.FilePayload.ToArray();
        var expectedHash = first.FilePayloadSha256.ToArray();

        parts.CanonicalGenesis.AsSpan().Fill(0xff);
        parts.CanonicalSignedDelegation.AsSpan().Fill(0xff);
        parts.CanonicalSignedBridges[0].AsSpan().Fill(0xff);
        var approvals = Assert.IsType<MembershipSignature[]>(parts.GenesisApprovals);
        approvals[0] = approvals[0] with
        {
            SignerId = new byte[approvals[0].SignerId.Length],
            Signature = new byte[approvals[0].Signature.Length]
        };

        var exportedPayload = first.FilePayload.ToArray();
        var exportedHash = first.FilePayloadSha256.ToArray();
        exportedPayload.AsSpan().Fill(0xff);
        exportedHash.AsSpan().Fill(0xff);

        var second = ProfileCarrierComposer.ComposeExact(
            input,
            Options(),
            SyntheticProfileFixture.Verifier());
        Assert.Equal(expected, second.FilePayload.ToArray());
        Assert.Equal(expectedHash, second.FilePayloadSha256.ToArray());
        Assert.Equal(expected, first.FilePayload.ToArray());
        Assert.Equal(expectedHash, first.FilePayloadSha256.ToArray());
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
