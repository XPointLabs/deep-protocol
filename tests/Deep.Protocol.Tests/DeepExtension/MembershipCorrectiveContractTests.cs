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

        var verifier = new DeterministicMembershipVerifier();
        foreach (var cryptographicDomain in new[]
                 {
                     MembershipSignatureDomain.Update,
                     MembershipSignatureDomain.Reward,
                     MembershipSignatureDomain.Billing,
                     MembershipSignatureDomain.Bridge
                 })
        {
            var forged = MembershipFixtures.SignWithCryptographicDomain(
                MembershipFixtures.Commitment(7),
                MembershipSignatureDomain.Membership,
                cryptographicDomain,
                verifier);
            Assert.Throws<MembershipContractException>(() =>
                MembershipContractVerifier.VerifyMembership(
                    forged, MembershipFixtures.Context(), verifier));
        }
    }

    [Fact]
    public void SignedContainers_AreCanonicalStrictAndFullyBounded()
    {
        var verifier = new DeterministicMembershipVerifier();
        var membership = MembershipContractCodec.EncodeSignedMembership(
            MembershipFixtures.SignedCommitment(7, verifier));
        var bridge = MembershipContractCodec.EncodeSignedBridge(
            MembershipFixtures.SignedBridge(verifier, [0, 1]));

        Assert.Equal(2, MembershipContractCodec.DecodeSignedMembership(membership).Signatures.Count);
        Assert.Equal(2, MembershipContractCodec.DecodeSignedBridge(bridge).Signatures.Count);
        AssertEveryTruncation(
            membership,
            value => MembershipContractCodec.DecodeSignedMembership(value.Span));
        AssertEveryTruncation(
            bridge,
            value => MembershipContractCodec.DecodeSignedBridge(value.Span));
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractCodec.DecodeSignedMembership([.. membership, (byte)0]));
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractCodec.DecodeSignedBridge([.. bridge, (byte)0]));

        var reserved = membership.ToArray();
        reserved[5] = 1;
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractCodec.DecodeSignedMembership(reserved));

        var nonCanonical = membership.ToArray();
        var statementLength = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(
            nonCanonical.AsSpan(6, 2));
        var firstSignatureOffset = 12 + statementLength;
        const int deterministicSignatureRecordLength = 52;
        var first = nonCanonical.AsSpan(firstSignatureOffset, deterministicSignatureRecordLength).ToArray();
        var second = nonCanonical.AsSpan(
            firstSignatureOffset + deterministicSignatureRecordLength,
            deterministicSignatureRecordLength).ToArray();
        second.CopyTo(nonCanonical, firstSignatureOffset);
        first.CopyTo(nonCanonical, firstSignatureOffset + deterministicSignatureRecordLength);
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractCodec.DecodeSignedMembership(nonCanonical));
    }

    [Fact]
    public void AuthorityAndBridgeForkEvidence_IsDomainSafe()
    {
        var verifier = new DeterministicMembershipVerifier();
        var genesis = MembershipFixtures.Genesis();
        var delegation = MembershipFixtures.SignedDelegation(verifier);
        var delegationLkg = MembershipContractVerifier.VerifyDelegation(
            delegation,
            genesis,
            MembershipFixtures.GenesisAuthorityLastKnownGood(),
            1010,
            30,
            2,
            verifier).NextAuthorityLastKnownGood;

        var revocationEvidence = MembershipContractVerifier.CreateRevocationForkEvidence(
            MembershipFixtures.SignedRevocation(verifier),
            MembershipFixtures.SignedRevocation(verifier, alternate: true),
            genesis,
            delegationLkg,
            1010,
            30,
            2,
            verifier);
        Assert.Equal(MembershipSignatureDomain.OfflineRevocation, revocationEvidence.Domain);

        var bridgeEvidence = MembershipContractVerifier.CreateBridgeForkEvidence(
            MembershipFixtures.SignedBridge(verifier, [0, 1]),
            MembershipFixtures.SignedBridge(verifier, [0, 1], alternateContact: true),
            MembershipFixtures.Context(),
            verifier);
        Assert.Equal(MembershipSignatureDomain.Bridge, bridgeEvidence.Domain);
    }

    [Fact]
    public void DescriptorKeysAreDistinct_StrictPolicyAndSequenceOverflowFailClosed()
    {
        var genesis = MembershipFixtures.Genesis();
        var duplicateRootKey = genesis with
        {
            OfflineRoots = genesis.OfflineRoots.Select((root, index) =>
                index == 1 ? root with { PublicKey = genesis.OfflineRoots[0].PublicKey } : root).ToArray()
        };
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractCodec.EncodeGenesis(duplicateRootKey));

        var invalidPolicy = genesis.Policy with
        {
            OnlineThreshold = 1
        };
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractCodec.EncodeGenesis(genesis with { Policy = invalidPolicy }));

        var verifier = new DeterministicMembershipVerifier();
        var delegation = MembershipFixtures.SignedDelegation(verifier);
        var duplicateOnlineKey = delegation with
        {
            OnlineSigners = delegation.OnlineSigners.Select((signer, index) =>
                index == 1
                    ? signer with { PublicKey = delegation.OnlineSigners[0].PublicKey }
                    : signer).ToArray()
        };
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractCodec.GetDelegationSigningBytes(duplicateOnlineKey));

        var overflowLkg = MembershipFixtures.GenesisAuthorityLastKnownGood() with
        {
            Sequence = ulong.MaxValue
        };
        var overflow = Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyDelegation(
                delegation, genesis, overflowLkg, 1010, 30, 2, verifier));
        Assert.Equal(MembershipContractError.SequenceOverflow, overflow.Error);
    }

    [Fact]
    public void NewCanonicalDecoders_RejectTruncationTrailingAndStructuredMalformedInput()
    {
        var verifier = new DeterministicMembershipVerifier();
        var samples = new (byte[] Bytes, Action<ReadOnlyMemory<byte>> Decode)[]
        {
            (MembershipContractCodec.GetDelegationSigningBytes(MembershipFixtures.SignedDelegation(verifier)),
                value => MembershipContractCodec.DecodeDelegationSigningBytes(value.Span)),
            (MembershipContractCodec.GetRevocationSigningBytes(MembershipFixtures.SignedRevocation(verifier)),
                value => MembershipContractCodec.DecodeRevocationSigningBytes(value.Span)),
            (MembershipContractCodec.GetMembershipSigningBytes(MembershipFixtures.Commitment(7)),
                value => MembershipContractCodec.DecodeMembershipSigningBytes(value.Span)),
            (MembershipContractCodec.EncodeForkWitness(MembershipFixtures.BridgeSnapshot().ForkWitness),
                value => MembershipContractCodec.DecodeForkWitness(value.Span)),
            (MembershipContractCodec.EncodeInclusionProof(MembershipFixtures.InclusionProof()),
                value => MembershipContractCodec.DecodeInclusionProof(value.Span))
        };
        foreach (var sample in samples)
        {
            AssertEveryTruncation(sample.Bytes, sample.Decode);
            Assert.Throws<MembershipContractException>(() =>
                sample.Decode(sample.Bytes.Concat([(byte)0]).ToArray()));
            var reserved = sample.Bytes.ToArray();
            reserved[5] = 1;
            Assert.Throws<MembershipContractException>(() => sample.Decode(reserved));
        }

        var decoders = samples.Select(static sample => sample.Decode)
            .Append(value => MembershipContractCodec.DecodeGenesis(value.Span))
            .Append(value => MembershipContractCodec.DecodeBridgeSigningBytes(value.Span))
            .Append(value => MembershipContractCodec.DecodeSignedMembership(value.Span))
            .Append(value => MembershipContractCodec.DecodeSignedBridge(value.Span))
            .ToArray();
        var random = new Random(0x504c);
        foreach (var decoder in decoders)
        {
            for (var iteration = 0; iteration < 300; iteration++)
            {
                var malformed = new byte[random.Next(0, 768)];
                random.NextBytes(malformed);
                Assert.Throws<MembershipContractException>(() => decoder(malformed));
            }
        }
    }

    private static void AssertEveryTruncation(
        byte[] canonical,
        Action<ReadOnlyMemory<byte>> decode)
    {
        for (var length = 0; length < canonical.Length; length++)
        {
            var truncated = canonical.AsMemory(0, length);
            Assert.Throws<MembershipContractException>(() => decode(truncated));
        }
    }

    private static void AssertVector(
        string id,
        byte[] encoded,
        GoldenVectorSet vectors) =>
        Assert.Equal(vectors.GetRequired(id).Hex, Convert.ToHexString(encoded).ToLowerInvariant());
}
