using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class AuthenticatedMailboxCapabilityContractTests
{
    [Fact]
    public void OfflineIssuerAndHolder_BindExactStoreRequest()
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        var issuerSeed = Range(0x10, 32);
        var holderSeed = Range(0x40, 32);
        var grant = Grant(
            crypto.GetPublicKey(issuerSeed),
            crypto.GetPublicKey(holderSeed),
            MailboxCapabilityDomain.Deposit);
        var signedGrant = crypto.SignGrant(grant, issuerSeed);
        var binding = Binding(MailboxAuthenticatedOperation.Store);
        var presentation = crypto.SignPresentation(
            signedGrant,
            binding,
            replayCounter: 9,
            holderSeed);

        var replay = new MemoryReplayJournal();
        var verified = MailboxAuthenticatedCapabilityCodec.Verify(
            MailboxAuthenticatedCapabilityCodec.EncodePresentation(presentation),
            binding,
            Policy(grant),
            crypto,
            new NoRevocations(),
            replay);

        Assert.Equal(MailboxAuthenticatedReplayDisposition.NewReserved, verified.ReplayDisposition);
        Assert.Equal(grant.Serial.ToArray(), verified.Grant.Serial.ToArray());
        Assert.DoesNotContain(
            typeof(MailboxAuthenticatedGrant).GetProperties(),
            property => property.Name.Contains("Session", StringComparison.OrdinalIgnoreCase) ||
                        property.Name.Contains("Payment", StringComparison.OrdinalIgnoreCase) ||
                        property.Name.Contains("Wallet", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RequestOperationDomainAndSignatures_FailClosed()
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        var issuerSeed = Range(0x10, 32);
        var holderSeed = Range(0x40, 32);
        var grant = crypto.SignGrant(
            Grant(
                crypto.GetPublicKey(issuerSeed),
                crypto.GetPublicKey(holderSeed),
                MailboxCapabilityDomain.Deposit),
            issuerSeed);
        var binding = Binding(MailboxAuthenticatedOperation.Store);
        var encoded = MailboxAuthenticatedCapabilityCodec.EncodePresentation(
            crypto.SignPresentation(grant, binding, 9, holderSeed));

        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedCapabilityCodec.Verify(
                encoded,
                binding with { RequestDigest = Range(0x01, 32) },
                Policy(grant),
                crypto,
                new NoRevocations(),
                new MemoryReplayJournal()));
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedCapabilityCodec.Verify(
                encoded,
                binding with { Operation = MailboxAuthenticatedOperation.Retrieve },
                Policy(grant),
                crypto,
                new NoRevocations(),
                new MemoryReplayJournal()));

        encoded[^1] ^= 1;
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedCapabilityCodec.Verify(
                encoded,
                binding,
                Policy(grant),
                crypto,
                new NoRevocations(),
                new MemoryReplayJournal()));
    }

    [Fact]
    public void RotationRevocationReplayAndMixedVersion_AreExplicit()
    {
        var crypto = new SodiumMailboxCapabilityCrypto();
        var issuerSeed = Range(0x10, 32);
        var holderSeed = Range(0x40, 32);
        var grant = crypto.SignGrant(
            Grant(
                crypto.GetPublicKey(issuerSeed),
                crypto.GetPublicKey(holderSeed),
                MailboxCapabilityDomain.Retrieve),
            issuerSeed);
        var binding = Binding(MailboxAuthenticatedOperation.Ack);
        var encoded = MailboxAuthenticatedCapabilityCodec.EncodePresentation(
            crypto.SignPresentation(grant, binding, 9, holderSeed));
        var replay = new MemoryReplayJournal();

        _ = MailboxAuthenticatedCapabilityCodec.Verify(
            encoded, binding, Policy(grant), crypto, new NoRevocations(), replay);
        var second = MailboxAuthenticatedCapabilityCodec.Verify(
            encoded, binding, Policy(grant), crypto, new NoRevocations(), replay);
        Assert.Equal(MailboxAuthenticatedReplayDisposition.InFlight, second.ReplayDisposition);

        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedCapabilityCodec.Verify(
                encoded,
                binding,
                Policy(grant) with { MinimumGeneration = grant.Generation + 1 },
                crypto,
                new NoRevocations(),
                new MemoryReplayJournal()));
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedCapabilityCodec.Verify(
                encoded,
                binding,
                Policy(grant),
                crypto,
                new AllRevoked(),
                new MemoryReplayJournal()));

        var v1 = MailboxCapabilityCodec.Encode(new MailboxCapabilityPresentation
        {
            DomainValue = new RotatingRetrieveCapability(Range(1, 32)),
            Lifecycle = MailboxCapabilityLifecycle.Active,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            Generation = 1,
            NotBeforeBucket = 1,
            ExpiresAtBucket = 2,
            OverlapUntilBucket = 0,
            ReplayCounter = 1,
            IdempotencyKey = Range(2, 16)
        });
        Assert.Throws<MailboxAuthenticatedCapabilityException>(() =>
            MailboxAuthenticatedCapabilityCodec.DecodePresentation(v1));
    }

    private static MailboxAuthenticatedGrant Grant(
        byte[] issuer,
        byte[] holder,
        MailboxCapabilityDomain domain) =>
        new()
        {
            Domain = domain,
            Lifecycle = MailboxCapabilityLifecycle.Active,
            Generation = 7,
            NetworkId = Range(0x70, 16),
            Epoch = 11,
            Serial = Range(0x80, 16),
            NotBeforeUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1100,
            OverlapUntilUnixSeconds = 0,
            PlacementCommitment = Range(0x90, 32),
            MembershipCommitment = Range(0xb0, 32),
            IssuerPublicKey = issuer,
            HolderPublicKey = holder,
            IssuerSignature = ReadOnlyMemory<byte>.Empty
        };

    private static MailboxAuthenticatedRequestBinding Binding(
        MailboxAuthenticatedOperation operation) =>
        new()
        {
            Operation = operation,
            OperationId = Range(0xd0, 16),
            RequestDigest = Range(0xe0, 32)
        };

    private static MailboxAuthenticatedVerificationPolicy Policy(MailboxAuthenticatedGrant grant) =>
        new()
        {
            NetworkId = grant.NetworkId,
            Epoch = grant.Epoch,
            PlacementCommitment = grant.PlacementCommitment,
            MembershipCommitment = grant.MembershipCommitment,
            NowUnixSeconds = 1050,
            MinimumGeneration = grant.Generation,
            TrustedIssuerPublicKeys = [grant.IssuerPublicKey]
        };

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => unchecked((byte)value)).ToArray();

    private sealed class NoRevocations : IMailboxCapabilityRevocationSource
    {
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => false;
    }

    private sealed class AllRevoked : IMailboxCapabilityRevocationSource
    {
        public bool IsRevoked(MailboxCapabilityRevocationQuery query) => true;
    }

    private sealed class MemoryReplayJournal : IMailboxCapabilityReplayJournal
    {
        private readonly HashSet<string> _claims = new(StringComparer.Ordinal);

        public MailboxCapabilityAtomicReplayEvaluation EvaluateAndReserve(
            MailboxCapabilityAtomicReplayClaim claim)
        {
            var key = Convert.ToHexString(claim.ClaimDigest.Span);
            return new()
            {
                State = _claims.Add(key)
                    ? MailboxCapabilityAtomicReplayState.NewReserved
                    : MailboxCapabilityAtomicReplayState.PendingSame,
                CachedOutcome = ReadOnlyMemory<byte>.Empty
            };
        }

        public void CompleteAtomically(
            MailboxCapabilityAtomicReplayClaim claim,
            ReadOnlyMemory<byte> canonicalOutcome) =>
            throw new NotSupportedException();
    }
}
