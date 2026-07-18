using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class MembershipContractTests
{
    [Fact]
    public void ApprovedPolicy_IsCanonicalData_NotPrivateKeyMaterial()
    {
        var policy = MembershipPolicy.Beta(
            offlineRootSignerIds: Signers(0x10, 5),
            onlineSignerIds: Signers(0x40, 3));

        Assert.Equal(3, policy.OfflineThreshold);
        Assert.Equal(5, policy.OfflineRootSignerIds.Count);
        Assert.Equal(2, policy.OnlineThreshold);
        Assert.Equal(3, policy.OnlineSignerIds.Count);
        Assert.DoesNotContain(policy.GetType().GetProperties(), property =>
            property.Name.Contains("private", StringComparison.OrdinalIgnoreCase) ||
            property.Name.Contains("secret", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void OneOnlineSignerAndCrossDomainBridgeSignature_CannotAuthorizeMembership()
    {
        var verifier = new DeterministicMembershipVerifier();
        var commitment = MembershipFixtures.Commitment(sequence: 7);
        var oneSigner = MembershipFixtures.Sign(commitment, MembershipSignatureDomain.Membership,
            signerIndexes: [0], verifier);
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembership(oneSigner, MembershipFixtures.Context(), verifier));

        var bridgeDomain = MembershipFixtures.Sign(commitment, MembershipSignatureDomain.Bridge,
            signerIndexes: [0, 1], verifier);
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembership(bridgeDomain, MembershipFixtures.Context(), verifier));
    }

    [Fact]
    public void SequencePreviousHashExpiryRevocationAndFork_FailClosed()
    {
        var verifier = new DeterministicMembershipVerifier();
        var context = MembershipFixtures.Context(lastSequence: 6);
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembership(
                MembershipFixtures.SignedCommitment(sequence: 6, verifier), context, verifier));
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembership(
                MembershipFixtures.SignedCommitment(sequence: 7, verifier, wrongPreviousHash: true),
                context, verifier));
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembership(
                MembershipFixtures.SignedCommitment(sequence: 7, verifier, expiredDelegation: true),
                context, verifier));

        var evidence = MembershipContractVerifier.CreateForkEvidence(
            MembershipFixtures.SignedCommitment(sequence: 7, verifier),
            MembershipFixtures.SignedCommitment(sequence: 7, verifier, alternateBody: true),
            context,
            verifier);
        Assert.Equal(7UL, evidence.Sequence);
    }

    [Fact]
    public void BridgeSnapshot_DoesNotExposeFullMembershipTopology()
    {
        var properties = typeof(BridgeSnapshot).GetProperties().Select(p => p.Name).ToArray();
        Assert.DoesNotContain(properties, name =>
            name.Contains("storage", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("core", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("membership", StringComparison.OrdinalIgnoreCase));
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> Signers(int start, int count) =>
        Enumerable.Range(0, count)
            .Select(index => (ReadOnlyMemory<byte>)Enumerable.Range(start + index * 16, 16)
                .Select(value => (byte)value).ToArray())
            .ToArray();
}
