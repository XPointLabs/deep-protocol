using System.Reflection;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed partial class XPointOnionCapabilityProducerTests
{
    [Theory]
    [InlineData("advance")]
    [InlineData("equal")]
    [InlineData("older")]
    [InlineData("same-generation-hash")]
    [InlineData("foreign")]
    [InlineData("view-authority")]
    [InlineData("view-policy")]
    [InlineData("view-network")]
    [InlineData("short")]
    [InlineData("trailing")]
    [InlineData("wrong-magic")]
    [InlineData("bad-dtt-signature")]
    [InlineData("same-hash-higher-generation")]
    public void CoherentAcquisitionHint_IsOnlyBoundedAuthenticatedForwardMetadata(string fault) =>
        Fixture.Create().CheckAcquisitionHint(fault);

    [Fact]
    public void CoherentAcquisitionHint_PublicApiReturnsNoCapabilityAndAcceptsNoClockOrCallback()
    {
        var method = Assert.Single(typeof(OnionNetworkContextVerifier).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Where(method => method.Name == nameof(OnionNetworkContextVerifier.ProofNamesStrictlyNewerView)));
        Assert.Equal(typeof(bool), method.ReturnType);
        Assert.Equal(new[] { typeof(VerifiedXPointNetworkAuthority), typeof(VerifiedDeepIdV2DirectoryFreshness), typeof(ReadOnlyMemory<byte>) },
            method.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.All(method.GetParameters(), parameter => Assert.False(parameter.IsOptional));
    }

    internal sealed partial class Fixture
    {
        internal void CheckAcquisitionHint(string fault)
        {
            var chain = BuildSuccessorChain();
            var proof = chain.Freshness;
            var view = _xnv.ToArray();
            switch (fault)
            {
                case "equal": proof = Did2TimeEvidence(); break;
                case "older": proof = Did2TimeEvidence(); view = chain.Views[^1]; break;
                case "same-generation-hash": proof = WithArtifacts(0x73).Did2TimeEvidence(); break;
                case "foreign": proof = Create(networkMarker: 0x12).Did2TimeEvidence(); break;
                case "view-authority": view = XPointNetworkTestRecords.MutateField(view, 7, bytes => bytes[^1] ^= 1); break;
                case "view-policy": view = XPointNetworkTestRecords.MutateField(view, 8, bytes => bytes[^1] ^= 1); break;
                case "view-network": view = XPointNetworkTestRecords.MutateField(view, 1, bytes => bytes[^1] ^= 1); break;
                case "short": view = view[..11]; break;
                case "trailing": view = [.. view, 0]; break;
                case "wrong-magic": view[0] ^= 1; break;
                case "bad-dtt-signature":
                    var damaged = proof.ExactDtt1.ToArray(); damaged[^1] ^= 1;
                    proof = CopyAcquisitionProofHolder(proof, damaged); break;
                case "same-hash-higher-generation":
                    var dtt = AccountDirectoryDtt1Codec.Decode(proof.ExactDtt1.Span);
                    var same = new AccountDirectoryDtt1(dtt.NetworkId.Span, dtt.ClientNonce.Span,
                        dtt.ObservedUnixTime, dtt.UncertaintySeconds, dtt.CurrentAdh1CoreHash.Span,
                        dtt.CurrentAdh1Generation, ViewCoreHash, dtt.CurrentXnv1Generation,
                        dtt.AuthorizingXna1CoreReference.Span, dtt.WitnessPolicyHash.Span,
                        dtt.IssuedAt, dtt.ExpiresAt, dtt.IssuanceEpochId.Span, dtt.Witnesses);
                    proof = CopyAcquisitionProofHolder(proof, AccountDirectoryDtt1Codec.Encode(same)); break;
                case "advance": break;
                default: throw new ArgumentException("Unknown observation case.", nameof(fault));
            }
            if (fault is "short" or "trailing" or "wrong-magic")
                Assert.Throws<XPointValidationException>(() => OnionNetworkContextVerifier.ProofNamesStrictlyNewerView(_authority, proof, view));
            else if (fault == "bad-dtt-signature")
                Assert.Throws<OnionBoundaryException>(() => OnionNetworkContextVerifier.ProofNamesStrictlyNewerView(_authority, proof, view));
            else
                Assert.Equal(fault == "advance", OnionNetworkContextVerifier.ProofNamesStrictlyNewerView(_authority, proof, view));
        }

        // Test-internal holder for hostile DTT bytes only. It grants no account
        // admission/current network; real PQ proof + owned acquisition is tested
        // independently in Shared's signed connected source fixture.
        private static VerifiedDeepIdV2DirectoryFreshness CopyAcquisitionProofHolder(
            VerifiedDeepIdV2DirectoryFreshness source, byte[] dtt)
        {
            var time = (IVerifiedDirectoryNetworkTime)source;
            return new(source.ExactAdh1.Span, dtt, source.ExactAdp1V2.Span,
                source.NetworkId.Span, source.QueriedDirectoryLeafKey.Span,
                new AccountDirectoryMonotonicRequestWindow(time.BootId.Span,
                    source.MonotonicSample, source.MonotonicSample, source.MonotonicSample),
                source.FreshnessDeadlineMonotonicSeconds, source.TrustedLowerUnixSeconds,
                source.TrustedUpperUnixSeconds, source.ResultKind, source.CurrentCheckpoint,
                source.HasRootAuthorizedForwardLineage, null);
        }
    }
}
