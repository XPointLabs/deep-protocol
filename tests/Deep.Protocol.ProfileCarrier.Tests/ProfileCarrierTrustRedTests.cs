using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;

namespace Deep.Protocol.ProfileCarrier.Tests;

public sealed class ProfileCarrierTrustRedTests
{
    [Fact]
    public void EverySignedArtifactIsVerifiedByP04()
    {
        var tracking = new TrackingVerifier(SyntheticProfileFixture.Verifier());
        _ = ProfileCarrierComposer.ComposeExact(
            ProfileCarrierContractRedTests.Input(
                SyntheticProfileFixture.Parts(bridgeCount: 2)),
            ProfileCarrierContractRedTests.Options(),
            tracking);

        Assert.Equal(3, tracking.Count(MembershipSignatureDomain.Genesis));
        Assert.Equal(9, tracking.Count(MembershipSignatureDomain.OfflineDelegation));
        Assert.Equal(4, tracking.Count(MembershipSignatureDomain.Bridge));
        Assert.Equal(16, tracking.Total);
    }

    [Fact]
    public void WrongQuorumsDomainsDuplicatesAndRejectedSignaturesFailClosed()
    {
        var parts = SyntheticProfileFixture.Parts();
        var twoApprovals = parts with
        {
            GenesisApprovals = parts.GenesisApprovals.Take(2).ToArray()
        };
        AssertVerification(twoApprovals, SyntheticProfileFixture.Verifier());

        var wrongDomain = parts.GenesisApprovals
            .Select(static value => value with
            {
                Domain = MembershipSignatureDomain.OfflineDelegation
            })
            .ToArray();
        AssertVerification(parts with { GenesisApprovals = wrongDomain },
            SyntheticProfileFixture.Verifier());

        var duplicate = parts.GenesisApprovals
            .Select(value => value with
            {
                SignerId = parts.GenesisApprovals[0].SignerId.ToArray()
            })
            .ToArray();
        AssertVerification(parts with { GenesisApprovals = duplicate },
            SyntheticProfileFixture.Verifier());
        AssertVerification(parts, new RejectingVerifier());
    }

    [Fact]
    public void NullVerifierAndInvalidOptionsUseSanitizedContractErrors()
    {
        var parts = SyntheticProfileFixture.Parts();
        var nullVerifier = Assert.Throws<ProfileCarrierException>(() =>
            ProfileCarrierComposer.ComposeExact(
                ProfileCarrierContractRedTests.Input(parts),
                ProfileCarrierContractRedTests.Options(),
                null!));
        Assert.Equal(ProfileCarrierError.InvalidInput, nullVerifier.Error);
        Assert.Null(nullVerifier.InnerException);

        var invalidOptions = Assert.Throws<ProfileCarrierException>(() =>
            new ProfileCarrierVerificationOptions(
                SyntheticProfileFixture.VerificationTime,
                MembershipLimits.MaximumClockSkewSeconds + 1,
                SyntheticProfileFixture.Protocol));
        Assert.Equal(ProfileCarrierError.InvalidInput, invalidOptions.Error);
        Assert.Null(invalidOptions.InnerException);
    }

    [Theory]
    [InlineData("network")]
    [InlineData("policy")]
    [InlineData("previous-hash")]
    [InlineData("sequence")]
    public void ResignedDelegationContextMismatchMatrixFailsClosed(string mismatch)
    {
        var parts = SyntheticProfileFixture.PartsWithDelegationMutation(
            delegation => mismatch switch
            {
                "network" => delegation with
                {
                    NetworkId = Mutate(delegation.NetworkId.Span)
                },
                "policy" => delegation with
                {
                    PolicyVersion = delegation.PolicyVersion + 1
                },
                "previous-hash" => delegation with
                {
                    PreviousHash = Mutate(delegation.PreviousHash.Span)
                },
                "sequence" => delegation with
                {
                    Sequence = delegation.Sequence + 1
                },
                _ => throw new ArgumentOutOfRangeException(nameof(mismatch))
            });
        AssertVerification(parts, SyntheticProfileFixture.Verifier());
    }

    [Theory]
    [InlineData(900UL, 2)]
    [InlineData(2_100UL, 2)]
    [InlineData(1_100UL, 4)]
    public void TimeAndProtocolContextMismatchMatrixFailsClosed(
        ulong verificationTime,
        ushort protocol)
    {
        var parts = SyntheticProfileFixture.Parts();
        var exception = Assert.Throws<ProfileCarrierException>(() =>
            ProfileCarrierComposer.ComposeExact(
                ProfileCarrierContractRedTests.Input(parts),
                new ProfileCarrierVerificationOptions(
                    verificationTime,
                    30,
                    protocol),
                SyntheticProfileFixture.Verifier()));
        Assert.Equal(ProfileCarrierError.VerificationRejected, exception.Error);
        Assert.Null(exception.InnerException);
    }

    private static void AssertVerification(
        SyntheticProfileParts parts,
        IMembershipSignatureVerifier verifier)
    {
        var exception = Assert.Throws<ProfileCarrierException>(() =>
            ProfileCarrierComposer.ComposeExact(
                ProfileCarrierContractRedTests.Input(parts),
                ProfileCarrierContractRedTests.Options(),
                verifier));
        Assert.Equal(ProfileCarrierError.VerificationRejected, exception.Error);
        Assert.Null(exception.InnerException);
    }

    private sealed class TrackingVerifier(IMembershipSignatureVerifier inner)
        : IMembershipSignatureVerifier
    {
        private readonly List<MembershipSignatureDomain> domains = [];

        public int Total => domains.Count;

        public int Count(MembershipSignatureDomain domain) =>
            domains.Count(value => value == domain);

        public bool Verify(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            domains.Add(domain);
            return inner.Verify(signerId, publicKey, domain, signingBytes, signature);
        }
    }

    private sealed class RejectingVerifier : IMembershipSignatureVerifier
    {
        public bool Verify(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) =>
            false;
    }

    private static byte[] Mutate(ReadOnlySpan<byte> source)
    {
        var result = source.ToArray();
        result[0] ^= 0x80;
        return result;
    }
}
