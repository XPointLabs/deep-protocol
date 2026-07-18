using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class MembershipCorrectiveContractTests
{
    [Fact]
    public void DelegationAuthorityChain_IsMonotonicHashPinnedAndForkEvident()
    {
        var verifier = new DeterministicMembershipVerifier();
        var genesis = MembershipFixtures.Genesis();
        var authority = MembershipFixtures.GenesisAuthorityLastKnownGood();
        var first = MembershipFixtures.SignedDelegation(verifier);

        var accepted = MembershipContractVerifier.VerifyDelegation(
            first, genesis, authority, 1010, 30, 2, verifier);
        Assert.Equal(2UL, accepted.NextAuthorityLastKnownGood.Sequence);
        Assert.Equal(
            SHA256.HashData(MembershipContractCodec.GetDelegationSigningBytes(first)),
            accepted.NextAuthorityLastKnownGood.CanonicalHash.ToArray());

        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyDelegation(
                first with { Sequence = 1 }, genesis, authority, 1010, 30, 2, verifier));
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyDelegation(
                first with { PreviousHash = MembershipFixtures.Range(0, 32) },
                genesis, authority, 1010, 30, 2, verifier));

        var evidence = MembershipContractVerifier.CreateDelegationForkEvidence(
            first,
            MembershipFixtures.SignedDelegation(verifier, alternateKey: true),
            genesis,
            authority,
            1010,
            30,
            2,
            verifier);
        Assert.Equal(2UL, evidence.Sequence);
    }

    [Fact]
    public void ActiveDelegation_IsPinnedToAuthorityLkg_AndPublicKeyTamperFails()
    {
        var verifier = new DeterministicMembershipVerifier();
        var signed = MembershipFixtures.SignedCommitment(7, verifier);
        var context = MembershipFixtures.Context();

        Assert.NotNull(context.AuthorityLastKnownGood);
        _ = MembershipContractVerifier.VerifyMembership(signed, context, verifier);

        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembership(
                signed,
                context with
                {
                    AuthorityLastKnownGood = context.AuthorityLastKnownGood with
                    {
                        CanonicalHash = MembershipFixtures.Range(0, MembershipLimits.HashLength)
                    }
                },
                verifier));

        var tampered = context.ActiveDelegation with
        {
            OnlineSigners = context.ActiveDelegation.OnlineSigners
                .Select((signer, index) => index == 0
                    ? signer with { PublicKey = MembershipFixtures.Range(0, MembershipLimits.PublicKeyLength) }
                    : signer)
                .ToArray()
        };
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembership(
                signed, context with { ActiveDelegation = tampered }, verifier));
    }

    [Fact]
    public void BetaV1Policy_IsExactAndBridgeIdsAreUnique()
    {
        var invalid = MembershipPolicy.Beta(
            offlineRootSignerIds: Enumerable.Range(0, 4)
                .Select(index => (ReadOnlyMemory<byte>)MembershipFixtures.Range(index, 16)).ToArray(),
            onlineSignerIds: Enumerable.Range(0, 3)
                .Select(index => (ReadOnlyMemory<byte>)MembershipFixtures.Range(0x40 + index, 16)).ToArray());
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractCodec.EncodeGenesis(
                MembershipFixtures.Genesis() with { Policy = invalid }));

        var bridge = MembershipFixtures.BridgeSnapshot();
        var duplicate = bridge with
        {
            EntryContacts =
            [
                bridge.EntryContacts[0],
                bridge.EntryContacts[0] with { Contact = "https://other.example.invalid/v1" }
            ]
        };
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractCodec.GetBridgeSigningBytes(duplicate));
    }

    [Fact]
    public void AllStatementDecodersAndGoldenVectors_AreCanonical()
    {
        var verifier = new DeterministicMembershipVerifier();
        var delegation = MembershipFixtures.SignedDelegation(verifier);
        var revocation = MembershipFixtures.SignedRevocation(verifier);
        var commitment = MembershipFixtures.Commitment(7);
        var witness = MembershipFixtures.BridgeSnapshot().ForkWitness;
        var proof = MembershipFixtures.InclusionProof();
        var vectors = GoldenVectorLoader.Load("membership-contract-v1.json");

        AssertVector("deep-extension/membership/v1/signer-delegation",
            MembershipContractCodec.GetDelegationSigningBytes(delegation), vectors);
        AssertVector("deep-extension/membership/v1/signer-revocation",
            MembershipContractCodec.GetRevocationSigningBytes(revocation), vectors);
        AssertVector("deep-extension/membership/v1/node-membership",
            MembershipContractCodec.GetMembershipSigningBytes(commitment), vectors);
        AssertVector("deep-extension/membership/v1/fork-witness",
            MembershipContractCodec.EncodeForkWitness(witness), vectors);
        AssertVector("deep-extension/membership/v1/inclusion-proof",
            MembershipContractCodec.EncodeInclusionProof(proof), vectors);

        Assert.Equal(delegation.Sequence,
            MembershipContractCodec.DecodeDelegationSigningBytes(
                MembershipContractCodec.GetDelegationSigningBytes(delegation)).Sequence);
        Assert.Equal(revocation.Sequence,
            MembershipContractCodec.DecodeRevocationSigningBytes(
                MembershipContractCodec.GetRevocationSigningBytes(revocation)).Sequence);
        Assert.Equal(proof.LeafIndex,
            MembershipContractCodec.DecodeInclusionProof(
                MembershipContractCodec.EncodeInclusionProof(proof)).LeafIndex);
    }

    [Fact]
    public void SigningDomainTags_AreFixedDistinctAndProviderIndependent()
    {
        var domains = new[]
        {
            MembershipSignatureDomain.Update,
            MembershipSignatureDomain.Membership,
            MembershipSignatureDomain.Bridge,
            MembershipSignatureDomain.Reward,
            MembershipSignatureDomain.Billing
        };
        var tags = domains
            .Select(domain => Convert.ToHexString(MembershipSigningDomains.GetFixedTag(domain).Span))
            .ToArray();
        Assert.Equal(tags.Length, tags.Distinct(StringComparer.Ordinal).Count());
        Assert.All(tags, tag => Assert.Equal(MembershipSigningDomains.FixedTagLength * 2, tag.Length));
    }

    private static void AssertVector(
        string id,
        byte[] encoded,
        GoldenVectorSet vectors) =>
        Assert.Equal(vectors.GetRequired(id).Hex, Convert.ToHexString(encoded).ToLowerInvariant());
}
