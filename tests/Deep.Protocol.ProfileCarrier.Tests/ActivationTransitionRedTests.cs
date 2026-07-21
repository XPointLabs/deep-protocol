using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepExtension.SelfHostedProfiles;
using System.Security.Cryptography;

namespace Deep.Protocol.ProfileCarrier.Tests;

public sealed class ActivationTransitionRedTests
{
    [Fact]
    public void ExactReplayIsIdempotentAndBothInputsAreReverified()
    {
        var payload = Compose(SyntheticProfileFixture.Parts());
        var singleInputTracking = new TransitionTrackingVerifier(
            SyntheticProfileFixture.Verifier());
        _ = ProfileCarrierVerifier.VerifyExact(
            payload,
            ProfileCarrierContractRedTests.Options(),
            singleInputTracking);
        var tracking = new TransitionTrackingVerifier(
            SyntheticProfileFixture.Verifier());

        var decision = ProfileCarrierTransitionVerifier.VerifyExact(
            payload,
            ProfileCarrierContractRedTests.Options(),
            payload,
            ProfileCarrierContractRedTests.Options(),
            tracking);

        Assert.Equal(ProfileCarrierTransitionDecision.Idempotent, decision);
        Assert.True(singleInputTracking.Calls > 0);
        Assert.Equal(checked(singleInputTracking.Calls * 2), tracking.Calls);
    }

    [Fact]
    public void AlternateValidQuorumsOverSameStatementsAreEquivalent()
    {
        var previous = Compose(SyntheticProfileFixture.Parts());
        var candidate = Compose(TransitionFixture.PartsWithAlternateQuorums());

        Assert.NotEqual(previous, candidate);
        Assert.Equal(
            ProfileCarrierTransitionDecision.EquivalentSameState,
            Verify(previous, candidate));
    }

    [Fact]
    public void AppendedSameGenesisBridgeChainIsForward()
    {
        var previous = Compose(SyntheticProfileFixture.Parts(bridgeCount: 1));
        var candidate = Compose(SyntheticProfileFixture.Parts(bridgeCount: 2));

        Assert.Equal(
            ProfileCarrierTransitionDecision.ForwardSameGenesis,
            Verify(previous, candidate));
    }

    [Fact]
    public void RemovingAcceptedBridgeStateIsRollback()
    {
        var previous = Compose(SyntheticProfileFixture.Parts(bridgeCount: 2));
        var candidate = Compose(SyntheticProfileFixture.Parts(bridgeCount: 1));

        Assert.Equal(
            ProfileCarrierTransitionDecision.RollbackRejected,
            Verify(previous, candidate));
    }

    [Fact]
    public void EqualBridgeSequenceWithDifferentValidCommitmentIsFork()
    {
        var previous = Compose(SyntheticProfileFixture.Parts(contactLength: 48));
        var candidate = Compose(SyntheticProfileFixture.Parts(contactLength: 49));

        Assert.Equal(
            ProfileCarrierTransitionDecision.ForkRejected,
            Verify(previous, candidate));
    }

    [Fact]
    public void SameSequenceDifferentDelegationStatementIsFork()
    {
        var previous = Compose(SyntheticProfileFixture.Parts());
        var candidate = Compose(SyntheticProfileFixture.PartsWithDelegationMutation(
            delegation => delegation with
            {
                OnlineSigners = delegation.OnlineSigners
                    .Select((signer, index) => index == 0
                        ? signer with
                        {
                            PublicKey = signer.PublicKey.ToArray()
                                .Select(static (value, keyIndex) => keyIndex == 0
                                    ? (byte)(value ^ 0x20)
                                    : value)
                                .ToArray()
                        }
                        : signer)
                    .ToArray()
            }));

        Assert.Equal(
            ProfileCarrierTransitionDecision.ForkRejected,
            Verify(previous, candidate));
    }

    [Fact]
    public void EarlierBridgeForkWithHigherCandidateHeadIsStillFork()
    {
        var previous = Compose(SyntheticProfileFixture.Parts(
            bridgeCount: 2,
            contactLength: 48));
        var candidate = Compose(SyntheticProfileFixture.Parts(
            bridgeCount: 3,
            contactLength: 49));

        Assert.Equal(
            ProfileCarrierTransitionDecision.ForkRejected,
            Verify(previous, candidate));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1)]
    public void UnrepresentableDelegationRotationIsTrustRejected(int delta)
    {
        var previous = Compose(SyntheticProfileFixture.Parts());
        var invalidCandidate = SyntheticProfileFixture.PartsWithDelegationMutation(
            delegation => delegation with
            {
                Sequence = checked((ulong)((long)delegation.Sequence + delta))
            });
        var validParts = SyntheticProfileFixture.Parts();
        var candidate = Compose(validParts);
        var offset = candidate.AsSpan().IndexOf(validParts.CanonicalSignedDelegation);
        Assert.True(offset >= 0);
        Assert.Equal(
            validParts.CanonicalSignedDelegation.Length,
            invalidCandidate.CanonicalSignedDelegation.Length);
        invalidCandidate.CanonicalSignedDelegation.CopyTo(candidate, offset);

        Assert.Equal(
            ProfileCarrierTransitionDecision.TrustRejected,
            Verify(previous, candidate));
    }

    [Fact]
    public void DifferentGenesisIsOnlyExplicitSwitchCandidate()
    {
        var previousParts = SyntheticProfileFixture.Parts();
        var otherGenesis = SyntheticProfileFixture.Genesis() with
        {
            NetworkId = SyntheticProfileFixture.Genesis().NetworkId.ToArray()
                .Select(static (value, index) => index == 0 ? (byte)(value ^ 0x40) : value)
                .ToArray()
        };
        var candidateParts = TransitionFixture.Parts(otherGenesis, bridgeCount: 1);

        Assert.Equal(
            ProfileCarrierTransitionDecision.ExplicitNetworkSwitchCandidate,
            Verify(Compose(previousParts), Compose(candidateParts)));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void MutationOfEitherCarrierIsTrustRejected(bool mutatePrevious)
    {
        var previous = Compose(SyntheticProfileFixture.Parts());
        var candidate = previous.ToArray();
        var target = mutatePrevious ? previous : candidate;
        target[^1] ^= 0x80;

        Assert.Equal(
            ProfileCarrierTransitionDecision.TrustRejected,
            Verify(previous, candidate));
    }

    [Fact]
    public void PreviousAndCandidateUseSeparateTrustedTimeSnapshots()
    {
        var payload = Compose(SyntheticProfileFixture.Parts());
        var earlierAccepted = new ProfileCarrierVerificationOptions(1_100, 30, 2);
        var current = new ProfileCarrierVerificationOptions(2_100, 30, 2);
        var currentCandidate = Compose(TransitionFixture.PartsWithValidity(3_000));

        var expired = Assert.Throws<ProfileCarrierException>(() =>
            ProfileCarrierVerifier.VerifyExact(
                payload,
                current,
                SyntheticProfileFixture.Verifier()));
        Assert.Equal(ProfileCarrierError.VerificationRejected, expired.Error);

        Assert.Equal(
            ProfileCarrierTransitionDecision.ForkRejected,
            ProfileCarrierTransitionVerifier.VerifyExact(
                payload,
                earlierAccepted,
                currentCandidate,
                current,
                SyntheticProfileFixture.Verifier()));
    }

    [Fact]
    public void TransitionSurfaceDisclosesOnlyBoundedDecision()
    {
        var publicTypes = typeof(ProfileCarrierTransitionVerifier).Assembly
            .GetExportedTypes()
            .Where(type => type.Namespace == typeof(ProfileCarrierTransitionVerifier).Namespace)
            .ToArray();
        var continuityTokens = new[]
        {
            "GenesisCommitment", "DelegationCommitment", "BridgeCommitment",
            "NetworkId", "Endpoint", "Signer", "Signature", "CarrierBytes"
        };

        foreach (var type in publicTypes)
        {
            foreach (var member in type.GetMembers())
            {
                Assert.DoesNotContain(
                    continuityTokens,
                    token => member.Name.Contains(token, StringComparison.OrdinalIgnoreCase));
            }
        }

        foreach (var decision in Enum.GetValues<ProfileCarrierTransitionDecision>())
        {
            Assert.DoesNotContain("sha", decision.ToString(), StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void TransitionClearsEveryEphemeralContinuityProjection()
    {
        var payload = Compose(SyntheticProfileFixture.Parts(bridgeCount: 2));
        var disposalEvidence = new List<bool>();

        var decision = ProfileCarrierTransitionVerifier.VerifyExact(
            payload,
            ProfileCarrierContractRedTests.Options(),
            payload,
            ProfileCarrierContractRedTests.Options(),
            SyntheticProfileFixture.Verifier(),
            disposalEvidence.Add);

        Assert.Equal(ProfileCarrierTransitionDecision.Idempotent, decision);
        Assert.Equal(new[] { true, true }, disposalEvidence);
    }

    [Fact]
    public void OrdinaryExactVerificationDoesNotCaptureContinuity()
    {
        var payload = Compose(SyntheticProfileFixture.Parts());
        var disposalEvidence = new List<bool>();

        var result = ProfileCarrierVerifier.VerifyExactWithoutContinuity(
            payload,
            ProfileCarrierContractRedTests.Options(),
            SyntheticProfileFixture.Verifier(),
            disposalEvidence.Add);

        Assert.Equal(SHA256.HashData(payload), result.FilePayloadSha256.ToArray());
        Assert.Empty(disposalEvidence);
    }

    [Fact]
    public void TransitionPropagatesExactVerifierOomAndClearsPriorProjection()
    {
        var payload = Compose(SyntheticProfileFixture.Parts());
        var firstInputCallCount = new TransitionTrackingVerifier(
            SyntheticProfileFixture.Verifier());
        _ = ProfileCarrierVerifier.VerifyExact(
            payload,
            ProfileCarrierContractRedTests.Options(),
            firstInputCallCount);
        var oom = new OutOfMemoryException("exact-transition-oom");
        var verifier = new OomAfterCallsVerifier(
            SyntheticProfileFixture.Verifier(),
            firstInputCallCount.Calls,
            oom);
        var disposalEvidence = new List<bool>();

        var thrown = Assert.Throws<OutOfMemoryException>(() =>
            ProfileCarrierTransitionVerifier.VerifyExact(
                payload,
                ProfileCarrierContractRedTests.Options(),
                payload,
                ProfileCarrierContractRedTests.Options(),
                verifier,
                disposalEvidence.Add));

        Assert.Same(oom, thrown);
        Assert.Equal(new[] { true }, disposalEvidence);
    }

    private static ProfileCarrierTransitionDecision Verify(
        byte[] previous,
        byte[] candidate) =>
        ProfileCarrierTransitionVerifier.VerifyExact(
            previous,
            ProfileCarrierContractRedTests.Options(),
            candidate,
            ProfileCarrierContractRedTests.Options(),
            SyntheticProfileFixture.Verifier());

    private static byte[] Compose(SyntheticProfileParts parts) =>
        ProfileCarrierComposer.ComposeExact(
            ProfileCarrierContractRedTests.Input(parts),
            ProfileCarrierContractRedTests.Options(),
            SyntheticProfileFixture.Verifier()).FilePayload.ToArray();

    private sealed class TransitionTrackingVerifier(IMembershipSignatureVerifier inner)
        : IMembershipSignatureVerifier
    {
        public int Calls { get; private set; }

        public bool Verify(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            Calls++;
            return inner.Verify(signerId, publicKey, domain, signingBytes, signature);
        }
    }

    private sealed class OomAfterCallsVerifier(
        IMembershipSignatureVerifier inner,
        int allowedCalls,
        OutOfMemoryException oom) : IMembershipSignatureVerifier
    {
        private int calls;

        public bool Verify(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            if (calls++ == allowedCalls)
            {
                throw oom;
            }
            return inner.Verify(signerId, publicKey, domain, signingBytes, signature);
        }
    }
}

internal static class TransitionFixture
{
    public static SyntheticProfileParts Parts(NetworkGenesis genesis, int bridgeCount)
    {
        var verifier = SyntheticProfileFixture.Verifier();
        var canonicalGenesis = MembershipContractCodec.EncodeGenesis(genesis);
        var approvals = SyntheticProfileFixture.Signatures(
            genesis.OfflineRoots,
            MembershipSignatureDomain.Genesis,
            canonicalGenesis,
            3,
            verifier);
        var delegation = SyntheticProfileFixture.SignedDelegation(
            genesis,
            canonicalGenesis,
            verifier);
        var bridges = SyntheticProfileFixture.SignedBridges(
                genesis,
                canonicalGenesis,
                delegation,
                bridgeCount,
                48,
                1,
                null,
                verifier)
            .Select(MembershipContractCodec.EncodeSignedBridge)
            .ToArray();
        return new(
            canonicalGenesis,
            approvals,
            MembershipContractCodec.EncodeSignedDelegation(delegation),
            bridges);
    }

    public static SyntheticProfileParts PartsWithAlternateQuorums()
    {
        var parts = SyntheticProfileFixture.Parts();
        var verifier = SyntheticProfileFixture.Verifier();
        var genesis = MembershipContractCodec.DecodeGenesis(parts.CanonicalGenesis);
        var approvals = genesis.OfflineRoots.Skip(1).Take(3)
            .Select(signer => new MembershipSignature
            {
                SignerId = signer.SignerId.ToArray(),
                Domain = MembershipSignatureDomain.Genesis,
                Signature = verifier.Sign(
                    signer,
                    MembershipSignatureDomain.Genesis,
                    parts.CanonicalGenesis)
            })
            .ToArray();
        var delegation = MembershipContractCodec.DecodeSignedDelegation(
            parts.CanonicalSignedDelegation);
        var delegationStatement = MembershipContractCodec.GetDelegationSigningBytes(
            delegation with { Signatures = [] });
        delegation = delegation with
        {
            Signatures = genesis.OfflineRoots.Skip(1).Take(3)
                .Select(signer => new MembershipSignature
                {
                    SignerId = signer.SignerId.ToArray(),
                    Domain = MembershipSignatureDomain.OfflineDelegation,
                    Signature = verifier.Sign(
                        signer,
                        MembershipSignatureDomain.OfflineDelegation,
                        delegationStatement)
                })
                .ToArray()
        };
        var bridge = MembershipContractCodec.DecodeSignedBridge(
            parts.CanonicalSignedBridges[0]);
        var bridgeStatement = MembershipContractCodec.GetBridgeSigningBytes(bridge.Statement);
        bridge = bridge with
        {
            Signatures = delegation.OnlineSigners.Skip(1).Take(2)
                .Select(signer => new MembershipSignature
                {
                    SignerId = signer.SignerId.ToArray(),
                    Domain = MembershipSignatureDomain.Bridge,
                    Signature = verifier.Sign(
                        signer,
                        MembershipSignatureDomain.Bridge,
                        bridgeStatement)
                })
                .ToArray()
        };
        return new(
            parts.CanonicalGenesis,
            approvals,
            MembershipContractCodec.EncodeSignedDelegation(delegation),
            [MembershipContractCodec.EncodeSignedBridge(bridge)]);
    }

    public static SyntheticProfileParts PartsWithValidity(ulong validUntil)
    {
        var verifier = SyntheticProfileFixture.Verifier();
        var genesis = SyntheticProfileFixture.Genesis();
        var canonicalGenesis = MembershipContractCodec.EncodeGenesis(genesis);
        var approvals = SyntheticProfileFixture.Signatures(
            genesis.OfflineRoots,
            MembershipSignatureDomain.Genesis,
            canonicalGenesis,
            3,
            verifier);
        var delegation = SyntheticProfileFixture.SignedDelegation(
            genesis,
            canonicalGenesis,
            verifier) with
        {
            ValidUntilUnixSeconds = validUntil,
            Signatures = []
        };
        delegation = delegation with
        {
            Signatures = SyntheticProfileFixture.Signatures(
                genesis.OfflineRoots,
                MembershipSignatureDomain.OfflineDelegation,
                MembershipContractCodec.GetDelegationSigningBytes(delegation),
                3,
                verifier)
        };
        var bridge = SyntheticProfileFixture.SignedBridges(
            genesis,
            canonicalGenesis,
            delegation,
            1,
            48,
            1,
            null,
            verifier)[0];
        var unsignedBridge = bridge.Statement with { ValidUntilUnixSeconds = validUntil };
        unsignedBridge = unsignedBridge with
        {
            ForkWitness = unsignedBridge.ForkWitness with
            {
                CandidateHash = MembershipContractHash.Sha256(
                    MembershipContractCodec.GetBridgeCandidateBytes(unsignedBridge))
            }
        };
        var signedBridge = bridge with
        {
            Statement = unsignedBridge,
            Signatures = SyntheticProfileFixture.Signatures(
                delegation.OnlineSigners,
                MembershipSignatureDomain.Bridge,
                MembershipContractCodec.GetBridgeSigningBytes(unsignedBridge),
                2,
                verifier)
        };
        return new(
            canonicalGenesis,
            approvals,
            MembershipContractCodec.EncodeSignedDelegation(delegation),
            [MembershipContractCodec.EncodeSignedBridge(signedBridge)]);
    }
}
