using System.Text;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class MailboxCapabilityContractTests
{
    private static readonly byte[] DomainValue = Range(0x40, 32);
    private static readonly byte[] IdempotencyKey = Range(0x10, 16);

    [Fact]
    public void CanonicalDepositPresentation_MatchesGoldenVector()
    {
        var encoded = MailboxCapabilityCodec.Encode(CreatePresentation(
            new RotatingDepositCapability(DomainValue)));
        var vector = GoldenVectorLoader.Load("mailbox-capability-v1.json")
            .GetRequired("deep-extension/mailbox-capability/v1/deposit-active");

        Assert.Equal(vector.Hex, Convert.ToHexString(encoded).ToLowerInvariant());
        var decoded = MailboxCapabilityCodec.Decode(
            encoded,
            MailboxCapabilityDomain.Deposit,
            StrictPolicy(),
            new AcceptOnceCapabilityReplayGuard());

        Assert.IsType<RotatingDepositCapability>(decoded.DomainValue);
        Assert.Equal(7UL, decoded.Generation);
        Assert.Equal(DomainValue, decoded.DomainValue.Bytes.ToArray());
    }

    [Fact]
    public void DepositRetrieveAndPlacement_AreWireAndRuntimeDistinct()
    {
        var deposit = MailboxCapabilityCodec.Encode(CreatePresentation(
            new RotatingDepositCapability(DomainValue)));
        var retrieve = MailboxCapabilityCodec.Encode(CreatePresentation(
            new RotatingRetrieveCapability(DomainValue)));
        var placement = MailboxCapabilityCodec.Encode(CreatePresentation(
            new OpaquePlacementKey(DomainValue)));

        Assert.NotEqual(deposit, retrieve);
        Assert.NotEqual(deposit, placement);
        Assert.NotEqual(retrieve, placement);
        Assert.Throws<MailboxCapabilityException>(() =>
            MailboxCapabilityCodec.Decode(
                deposit,
                MailboxCapabilityDomain.Retrieve,
                StrictPolicy(),
                new AcceptOnceCapabilityReplayGuard()));
        Assert.Throws<MailboxCapabilityException>(() =>
            MailboxCapabilityCodec.Decode(
                retrieve,
                MailboxCapabilityDomain.Placement,
                StrictPolicy(),
                new AcceptOnceCapabilityReplayGuard()));

        var productionMethods = typeof(MailboxCapabilityCodec).Assembly
            .GetTypes()
            .SelectMany(static type => type.GetMethods())
            .Where(method =>
                method.ReturnType == typeof(RotatingRetrieveCapability) &&
                method.GetParameters().Any(parameter =>
                    parameter.ParameterType == typeof(RotatingDepositCapability)))
            .ToArray();
        Assert.Empty(productionMethods);
    }

    [Theory]
    [InlineData(MailboxCapabilityLifecycle.Overlap, 1050u, true)]
    [InlineData(MailboxCapabilityLifecycle.Overlap, 0u, false)]
    [InlineData(MailboxCapabilityLifecycle.Revoked, 0u, false)]
    [InlineData(MailboxCapabilityLifecycle.Recovery, 0u, false)]
    public void LifecycleMarkers_RequireExplicitPolicy(
        MailboxCapabilityLifecycle lifecycle,
        uint overlapUntil,
        bool strictAccepted)
    {
        var presentation = CreatePresentation(new RotatingDepositCapability(DomainValue)) with
        {
            Lifecycle = lifecycle,
            OverlapUntilBucket = overlapUntil
        };
        if (lifecycle == MailboxCapabilityLifecycle.Overlap && overlapUntil == 0)
        {
            Assert.Throws<MailboxCapabilityException>(() =>
                MailboxCapabilityCodec.Encode(presentation));
            return;
        }

        var encoded = MailboxCapabilityCodec.Encode(presentation);

        if (strictAccepted)
        {
            _ = MailboxCapabilityCodec.Decode(
                encoded,
                MailboxCapabilityDomain.Deposit,
                StrictPolicy(),
                new AcceptOnceCapabilityReplayGuard());
        }
        else
        {
            Assert.Throws<MailboxCapabilityException>(() =>
                MailboxCapabilityCodec.Decode(
                    encoded,
                    MailboxCapabilityDomain.Deposit,
                    StrictPolicy(),
                    new AcceptOnceCapabilityReplayGuard()));
        }
    }

    [Fact]
    public void MixedVersionOverlap_IsBoundedAndNeverImplicit()
    {
        var presentation = CreatePresentation(new RotatingDepositCapability(DomainValue)) with
        {
            Lifecycle = MailboxCapabilityLifecycle.Overlap,
            MixedVersion = MailboxMixedVersionMarker.LegacyMirrorOverlap,
            OverlapUntilBucket = 1050
        };
        var encoded = MailboxCapabilityCodec.Encode(presentation);

        var strict = Assert.Throws<MailboxCapabilityException>(() =>
            MailboxCapabilityCodec.Decode(
                encoded,
                MailboxCapabilityDomain.Deposit,
                StrictPolicy(),
                new AcceptOnceCapabilityReplayGuard()));
        Assert.Equal(MailboxCapabilityError.LegacyOverlapNotAllowed, strict.Error);

        var accepted = MailboxCapabilityCodec.Decode(
            encoded,
            MailboxCapabilityDomain.Deposit,
            StrictPolicy() with { AllowLegacyMirrorOverlap = true },
            new AcceptOnceCapabilityReplayGuard());
        Assert.Equal(MailboxMixedVersionMarker.LegacyMirrorOverlap, accepted.MixedVersion);
    }

    [Fact]
    public void ReplayAndIdempotency_AreScopedAndFailClosed()
    {
        var encoded = MailboxCapabilityCodec.Encode(CreatePresentation(
            new RotatingDepositCapability(DomainValue)));
        var replay = new AcceptOnceCapabilityReplayGuard();

        _ = MailboxCapabilityCodec.Decode(
            encoded,
            MailboxCapabilityDomain.Deposit,
            StrictPolicy(),
            replay);
        var repeated = Assert.Throws<MailboxCapabilityException>(() =>
            MailboxCapabilityCodec.Decode(
                encoded,
                MailboxCapabilityDomain.Deposit,
                StrictPolicy(),
                replay));

        Assert.Equal(MailboxCapabilityError.ReplayRejected, repeated.Error);
        Assert.Equal(2, replay.Calls);
    }

    [Fact]
    public void FreeAdmission_IsBoundedAndContainsNoPaymentIdentity()
    {
        var admission = new MailboxFreeAdmissionSlot
        {
            SlotId = Range(0x90, 16),
            ValidFromBucket = 1000,
            ValidUntilBucket = 1020,
            UseLimit = 4,
            Authorization = Range(0xa0, 32)
        };
        var encoded = MailboxCapabilityCodec.Encode(
            CreatePresentation(new RotatingDepositCapability(DomainValue)) with
            {
                FreeAdmission = admission
            });
        var decoded = MailboxCapabilityCodec.Decode(
            encoded,
            MailboxCapabilityDomain.Deposit,
            StrictPolicy(),
            new AcceptOnceCapabilityReplayGuard());

        Assert.Equal((ushort)4, decoded.FreeAdmission?.UseLimit);
        var propertyNames = typeof(MailboxFreeAdmissionSlot)
            .GetProperties()
            .Select(static property => property.Name)
            .ToArray();
        Assert.DoesNotContain(propertyNames, name =>
            name.Contains("payer", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("wallet", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("payment", StringComparison.OrdinalIgnoreCase) ||
            name.Contains("plan", StringComparison.OrdinalIgnoreCase));
        var ascii = Encoding.ASCII.GetString(encoded);
        Assert.DoesNotContain("payer", ascii, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("wallet", ascii, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void MalformedTrailingAndUnknownDomain_FailClosed()
    {
        var encoded = MailboxCapabilityCodec.Encode(CreatePresentation(
            new RotatingDepositCapability(DomainValue)));
        encoded[5] = 0xff;
        Assert.Throws<MailboxCapabilityException>(() =>
            MailboxCapabilityCodec.Decode(
                encoded,
                MailboxCapabilityDomain.Deposit,
                StrictPolicy(),
                new AcceptOnceCapabilityReplayGuard()));

        encoded = MailboxCapabilityCodec.Encode(CreatePresentation(
            new RotatingDepositCapability(DomainValue)));
        Assert.Throws<MailboxCapabilityException>(() =>
            MailboxCapabilityCodec.Decode(
                [.. encoded, (byte)0],
                MailboxCapabilityDomain.Deposit,
                StrictPolicy(),
                new AcceptOnceCapabilityReplayGuard()));
    }

    private static MailboxCapabilityPresentation CreatePresentation(MailboxDomainValue value) =>
        new()
        {
            DomainValue = value,
            Lifecycle = MailboxCapabilityLifecycle.Active,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            Generation = 7,
            NotBeforeBucket = 1000,
            ExpiresAtBucket = 1100,
            OverlapUntilBucket = 0,
            ReplayCounter = 9,
            IdempotencyKey = IdempotencyKey
        };

    private static MailboxCapabilityDecodePolicy StrictPolicy() =>
        new()
        {
            CurrentBucket = 1010,
            MinimumGeneration = 7,
            AllowLegacyMirrorOverlap = false,
            AllowRevoked = false,
            AllowRecovery = false
        };

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => (byte)value).ToArray();

    private sealed class AcceptOnceCapabilityReplayGuard : IMailboxCapabilityReplayGuard
    {
        private readonly HashSet<string> _seen = new(StringComparer.Ordinal);

        public int Calls { get; private set; }

        public bool TryAccept(MailboxCapabilityReplayScope scope)
        {
            Calls++;
            return _seen.Add(
                $"{scope.Domain}:{scope.Generation}:{scope.ReplayCounter}:" +
                Convert.ToHexString(scope.IdempotencyKey.Span));
        }
    }
}
