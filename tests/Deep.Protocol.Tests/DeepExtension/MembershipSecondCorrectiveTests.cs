using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class MembershipSecondCorrectiveTests
{
    [Fact]
    public void EveryVerifierEntry_RejectsCallerConstructedInvalidGenesisWithContractException()
    {
        var verifier = new DeterministicMembershipVerifier();
        var genesis = MembershipFixtures.Genesis();
        var weakPolicy = new MembershipPolicy
        {
            Version = 1,
            OfflineThreshold = 1,
            OfflineRootSignerIds = [genesis.OfflineRoots[0].SignerId],
            OnlineThreshold = 1,
            OnlineSignerCount = 1
        };
        var weakGenesis = genesis with
        {
            Policy = weakPolicy,
            OfflineRoots = [genesis.OfflineRoots[0]]
        };

        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyRevocation(
                MembershipFixtures.SignedRevocation(verifier),
                weakGenesis,
                MembershipFixtures.Context().AuthorityLastKnownGood,
                1010, 30, 2, verifier));
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyDelegation(
                MembershipFixtures.SignedDelegation(verifier),
                weakGenesis,
                MembershipFixtures.GenesisAuthorityLastKnownGood(),
                1010, 30, 2, verifier));
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembership(
                MembershipFixtures.SignedCommitment(7, verifier),
                MembershipFixtures.Context() with { Genesis = weakGenesis },
                verifier));

        var mismatchedRoots = genesis with
        {
            OfflineRoots = genesis.OfflineRoots.Select((root, index) =>
                index == 0
                    ? root with { SignerId = MembershipFixtures.Range(0, MembershipLimits.SignerIdLength) }
                    : root).ToArray()
        };
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyDelegation(
                MembershipFixtures.SignedDelegation(verifier),
                mismatchedRoots,
                MembershipFixtures.GenesisAuthorityLastKnownGood(),
                1010, 30, 2, verifier));

        var duplicateKey = genesis with
        {
            OfflineRoots = genesis.OfflineRoots.Select((root, index) =>
                index == 1 ? root with { PublicKey = genesis.OfflineRoots[0].PublicKey } : root).ToArray()
        };
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyRevocation(
                MembershipFixtures.SignedRevocation(verifier),
                duplicateKey,
                MembershipFixtures.Context().AuthorityLastKnownGood,
                1010, 30, 2, verifier));
    }

    [Fact]
    public void SignedAuthorityEnvelopes_AreCanonicalGoldenAndStrict()
    {
        var verifier = new DeterministicMembershipVerifier();
        var delegation = MembershipFixtures.SignedDelegation(verifier);
        var revocation = MembershipFixtures.SignedRevocation(verifier);
        var encodedDelegation = MembershipContractCodec.EncodeSignedDelegation(delegation);
        var encodedRevocation = MembershipContractCodec.EncodeSignedRevocation(revocation);
        var vectors = GoldenVectorLoader.Load("membership-contract-v1.json");

        Assert.Equal(
            vectors.GetRequired("deep-extension/membership/v1/signed-delegation").Hex,
            Convert.ToHexString(encodedDelegation).ToLowerInvariant());
        Assert.Equal(
            vectors.GetRequired("deep-extension/membership/v1/signed-revocation").Hex,
            Convert.ToHexString(encodedRevocation).ToLowerInvariant());
        Assert.Equal(
            vectors.GetRequired("deep-extension/membership/v1/signed-membership").Hex,
            Convert.ToHexString(MembershipContractCodec.EncodeSignedMembership(
                MembershipFixtures.SignedCommitment(7, verifier))).ToLowerInvariant());
        Assert.Equal(
            vectors.GetRequired("deep-extension/membership/v1/signed-bridge").Hex,
            Convert.ToHexString(MembershipContractCodec.EncodeSignedBridge(
                MembershipFixtures.SignedBridge(verifier, [0, 1]))).ToLowerInvariant());
        Assert.Equal(3, MembershipContractCodec.DecodeSignedDelegation(encodedDelegation).Signatures.Count);
        Assert.Equal(3, MembershipContractCodec.DecodeSignedRevocation(encodedRevocation).Signatures.Count);

        AssertStrictEnvelope(encodedDelegation, value =>
            MembershipContractCodec.DecodeSignedDelegation(value.Span));
        AssertStrictEnvelope(encodedRevocation, value =>
            MembershipContractCodec.DecodeSignedRevocation(value.Span));
    }

    [Fact]
    public void SelfHostedImport_RequiresExpectedNetworkAndCanonicalGenesisHashPins()
    {
        var verifier = new DeterministicMembershipVerifier();
        var genesis = MembershipFixtures.Genesis();
        var canonical = MembershipContractCodec.EncodeGenesis(genesis);
        var signatures = MembershipFixtures.GenesisSignatures(genesis, verifier);
        var hash = MembershipContractHash.Sha256(canonical);

        _ = MembershipContractVerifier.ImportSelfHostedGenesis(
            canonical, genesis.NetworkId.Span, hash, signatures, verifier);
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.ImportSelfHostedGenesis(
                canonical,
                MembershipFixtures.Range(0, MembershipLimits.NetworkIdLength),
                hash,
                signatures,
                verifier));
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.ImportSelfHostedGenesis(
                canonical,
                genesis.NetworkId.Span,
                MembershipFixtures.Range(0, MembershipLimits.HashLength),
                signatures,
                verifier));
    }

    [Fact]
    public void RootSignedDelegation_CanRotateAllOnlineIdsAndKeys()
    {
        var verifier = new DeterministicMembershipVerifier();
        var rotated = MembershipFixtures.SignedDelegation(verifier, rotatedIdentity: true);
        var accepted = MembershipContractVerifier.VerifyDelegation(
            rotated,
            MembershipFixtures.Genesis(),
            MembershipFixtures.GenesisAuthorityLastKnownGood(),
            1010, 30, 2, verifier);

        Assert.Equal(3, rotated.OnlineSigners.Count);
        Assert.Equal(2, MembershipFixtures.Genesis().Policy.OnlineThreshold);
        Assert.Equal(3, MembershipFixtures.Genesis().Policy.OnlineSignerCount);
        Assert.Equal(2UL, accepted.NextAuthorityLastKnownGood.Sequence);
    }

    [Fact]
    public void SignatureAndRevocationCollections_AreStrictlyBoundedAndUniform()
    {
        var verifier = new DeterministicMembershipVerifier();
        var signed = MembershipFixtures.SignedCommitment(7, verifier);
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembership(
                signed, MembershipFixtures.Context(), null!));
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembership(
                signed with { Signatures = null! }, MembershipFixtures.Context(), verifier));
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembership(
                signed with
                {
                    Signatures = Enumerable.Repeat(
                        signed.Signatures[0],
                        MembershipLimits.MaximumSigners + 1).ToArray()
                },
                MembershipFixtures.Context(),
                verifier));
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembership(
                signed,
                MembershipFixtures.Context() with
                {
                    RevokedDelegationHashes = Enumerable.Range(
                            0,
                            MembershipLimits.MaximumRevokedDelegationHashes + 1)
                        .Select(index => (ReadOnlyMemory<byte>)MembershipFixtures.Range(index, 32))
                        .ToArray()
                },
                verifier));
    }

    [Fact]
    public void SignedAuthorityEnvelope_RejectsZeroSignatureCanonicalPrefix()
    {
        var verifier = new DeterministicMembershipVerifier();
        var encoded = MembershipContractCodec.EncodeSignedDelegation(
            MembershipFixtures.SignedDelegation(verifier));
        var statementLength = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(
            encoded.AsSpan(6, 2));
        var unsignedEnvelope = encoded.AsSpan(0, 12 + statementLength).ToArray();
        unsignedEnvelope[8] = 0;
        unsignedEnvelope[9] = 0;

        Assert.Throws<MembershipContractException>(() =>
            MembershipContractCodec.DecodeSignedDelegation(unsignedEnvelope));
    }

    [Fact]
    public void ContractVersionDomainTagsFramesAndHashes_AreExactGoldenData()
    {
        Assert.Equal("Deep.Protocol/P04-canonical-v1", MembershipContractVersion.Identifier);
        var vectors = GoldenVectorLoader.Load("membership-contract-v1.json");
        foreach (var domain in new[]
                 {
                     MembershipSignatureDomain.Update,
                     MembershipSignatureDomain.Membership,
                     MembershipSignatureDomain.Bridge,
                     MembershipSignatureDomain.Reward,
                     MembershipSignatureDomain.Billing
                 })
        {
            var name = domain.ToString().ToLowerInvariant();
            var tag = MembershipSigningDomains.GetFixedTag(domain).ToArray();
            Assert.Equal(
                vectors.GetRequired($"deep-extension/membership/v1/domain-tag/{name}").Hex,
                Convert.ToHexString(tag).ToLowerInvariant());
        }

        var membership = MembershipContractCodec.GetMembershipSigningBytes(
            MembershipFixtures.Commitment(7));
        var framed = MembershipSigningDomains.Frame(
            MembershipSignatureDomain.Membership, membership);
        Assert.Equal(
            vectors.GetRequired("deep-extension/membership/v1/framed-membership").Hex,
            Convert.ToHexString(framed).ToLowerInvariant());
        Assert.Equal(
            vectors.GetRequired("deep-extension/membership/v1/node-membership").Message,
            $"sha256:{Convert.ToHexString(MembershipContractHash.Sha256(membership)).ToLowerInvariant()}");
    }

    private static void AssertStrictEnvelope(
        byte[] canonical,
        Action<ReadOnlyMemory<byte>> decode)
    {
        for (var length = 0; length < canonical.Length; length++)
            Assert.Throws<MembershipContractException>(() => decode(canonical.AsMemory(0, length)));
        Assert.Throws<MembershipContractException>(() =>
            decode(canonical.Concat([(byte)0]).ToArray()));
        var reserved = canonical.ToArray();
        reserved[5] = 1;
        Assert.Throws<MembershipContractException>(() => decode(reserved));

        var statementLength = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(
            canonical.AsSpan(6, 2));
        var signatureOffset = 12 + statementLength;
        const int signatureRecordLength = 52;
        var nonCanonical = canonical.ToArray();
        var first = nonCanonical.AsSpan(signatureOffset, signatureRecordLength).ToArray();
        var second = nonCanonical.AsSpan(signatureOffset + signatureRecordLength, signatureRecordLength).ToArray();
        second.CopyTo(nonCanonical, signatureOffset);
        first.CopyTo(nonCanonical, signatureOffset + signatureRecordLength);
        Assert.Throws<MembershipContractException>(() => decode(nonCanonical));
    }
}
