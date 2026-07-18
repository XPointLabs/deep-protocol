using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class MembershipContractTests
{
    [Fact]
    public void GenesisAndBridge_MatchCanonicalGoldenVectors()
    {
        var genesisBytes = MembershipContractCodec.EncodeGenesis(MembershipFixtures.Genesis());
        var bridgeBytes = MembershipContractCodec.GetBridgeSigningBytes(
            MembershipFixtures.BridgeSnapshot());
        var vectors = GoldenVectorLoader.Load("membership-contract-v1.json");

        Assert.Equal(
            vectors.GetRequired("deep-extension/membership/v1/network-genesis").Hex,
            Convert.ToHexString(genesisBytes).ToLowerInvariant());
        Assert.Equal(
            vectors.GetRequired("deep-extension/membership/v1/bridge-snapshot").Hex,
            Convert.ToHexString(bridgeBytes).ToLowerInvariant());

        var decodedGenesis = MembershipContractCodec.DecodeGenesis(genesisBytes);
        var decodedBridge = MembershipContractCodec.DecodeBridgeSigningBytes(bridgeBytes);
        Assert.Equal(5, decodedGenesis.OfflineRoots.Count);
        Assert.Single(decodedBridge.EntryContacts);
        Assert.Equal("https://bridge.example.invalid/v1", decodedBridge.EntryContacts[0].Contact);
    }

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
    public void BridgeSnapshot_RequiresTwoOnlineSignersAndBoundForkWitness()
    {
        var verifier = new DeterministicMembershipVerifier();
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyBridge(
                MembershipFixtures.SignedBridge(verifier, [0]),
                MembershipFixtures.Context(),
                verifier));

        var verified = MembershipContractVerifier.VerifyBridge(
            MembershipFixtures.SignedBridge(verifier, [0, 1]),
            MembershipFixtures.Context(),
            verifier);
        Assert.Equal(7UL, verified.NextLastKnownGood.Sequence);

        var signed = MembershipFixtures.SignedBridge(verifier, [0, 1]);
        var invalidWitness = signed with
        {
            Statement = signed.Statement with
            {
                ForkWitness = signed.Statement.ForkWitness with
                {
                    CandidateHash = MembershipFixtures.Range(0, MembershipLimits.HashLength)
                }
            }
        };
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyBridge(
                invalidWitness,
                MembershipFixtures.Context(),
                verifier));
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
                MembershipFixtures.SignedCommitment(sequence: 7, verifier),
                MembershipFixtures.Context(lastSequence: 6, expiredDelegation: true), verifier));

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

    [Fact]
    public void CanonicalParsers_RejectEveryTruncationTrailingReservedAndInvalidUtf8()
    {
        var genesis = MembershipContractCodec.EncodeGenesis(MembershipFixtures.Genesis());
        for (var length = 0; length < genesis.Length; length++)
        {
            Assert.Throws<MembershipContractException>(() =>
                MembershipContractCodec.DecodeGenesis(genesis.AsSpan(0, length)));
        }
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractCodec.DecodeGenesis([.. genesis, (byte)0]));
        var reserved = genesis.ToArray();
        reserved[5] = 1;
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractCodec.DecodeGenesis(reserved));

        var bridge = MembershipContractCodec.GetBridgeSigningBytes(
            MembershipFixtures.BridgeSnapshot());
        for (var length = 0; length < bridge.Length; length++)
        {
            Assert.Throws<MembershipContractException>(() =>
                MembershipContractCodec.DecodeBridgeSigningBytes(bridge.AsSpan(0, length)));
        }
        var invalidUtf8 = bridge.ToArray();
        // The single contact starts after the 98-byte common/count prefix and 16-byte entry ID.
        invalidUtf8[116] = 0xff;
        Assert.Throws<MembershipContractException>(() =>
            MembershipContractCodec.DecodeBridgeSigningBytes(invalidUtf8));
    }

    [Fact]
    public void VerificationClockSkew_IsCallerSuppliedBoundedAndFailClosed()
    {
        var verifier = new DeterministicMembershipVerifier();
        var signed = MembershipFixtures.SignedCommitment(7, verifier);

        _ = MembershipContractVerifier.VerifyMembership(
            signed,
            MembershipFixtures.Context(verificationTime: 970, allowedClockSkew: 30),
            verifier);

        var tooEarly = Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembership(
                signed,
                MembershipFixtures.Context(verificationTime: 969, allowedClockSkew: 30),
                verifier));
        Assert.Equal(MembershipContractError.NotYetValid, tooEarly.Error);

        var excessiveSkew = Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembership(
                signed,
                MembershipFixtures.Context(
                    verificationTime: 970,
                    allowedClockSkew: MembershipLimits.MaximumClockSkewSeconds + 1),
                verifier));
        Assert.Equal(MembershipContractError.ClockSkewOutOfRange, excessiveSkew.Error);
    }

    [Fact]
    public void SelfHostedGenesis_RequiresItsOwnOfflineRootQuorum()
    {
        var verifier = new DeterministicMembershipVerifier();
        var genesis = MembershipFixtures.Genesis() with
        {
            NetworkId = MembershipFixtures.Range(0x20, MembershipLimits.NetworkIdLength)
        };
        var canonical = MembershipContractCodec.EncodeGenesis(genesis);
        var signatures = genesis.OfflineRoots.Take(3).Select(root => new MembershipSignature
        {
            SignerId = root.SignerId,
            Domain = MembershipSignatureDomain.Genesis,
            Signature = verifier.Sign(
                root.SignerId.Span,
                root.PublicKey.Span,
                MembershipSignatureDomain.Genesis,
                canonical)
        }).ToArray();

        var imported = MembershipContractVerifier.ImportSelfHostedGenesis(
            canonical, signatures, verifier);
        Assert.Equal(genesis.NetworkId.ToArray(), imported.NetworkId.ToArray());

        Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.ImportSelfHostedGenesis(
                canonical, signatures.Take(2).ToArray(), verifier));
    }

    [Fact]
    public void FixedSeedMalformedInputs_StayInsideExpectedExceptionSurface()
    {
        var random = new Random(0x504);
        for (var iteration = 0; iteration < 2_000; iteration++)
        {
            var bytes = new byte[random.Next(0, 8_192)];
            random.NextBytes(bytes);
            try
            {
                _ = MembershipContractCodec.DecodeGenesis(bytes);
            }
            catch (MembershipContractException)
            {
                continue;
            }

            Assert.Fail("Random malformed membership input unexpectedly decoded.");
        }
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> Signers(int start, int count) =>
        Enumerable.Range(0, count)
            .Select(index => (ReadOnlyMemory<byte>)Enumerable.Range(start + index * 16, 16)
                .Select(value => (byte)value).ToArray())
            .ToArray();
}
