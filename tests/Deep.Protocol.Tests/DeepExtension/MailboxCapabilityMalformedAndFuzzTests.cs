using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class MailboxCapabilityMalformedAndFuzzTests
{
    [Fact]
    public void EveryTruncation_IsRejected()
    {
        var encoded = Canonical();
        for (var length = 0; length < encoded.Length; length++)
        {
            Assert.Throws<MailboxCapabilityException>(() =>
                MailboxCapabilityCodec.Decode(
                    encoded.AsSpan(0, length),
                    MailboxCapabilityDomain.Deposit,
                    Policy(),
                    new AcceptAllReplayGuard()));
        }
    }

    [Theory]
    [InlineData(4, 2)]
    [InlineData(5, 2)]
    [InlineData(6, 0)]
    [InlineData(7, 0)]
    [InlineData(28, 1)]
    [InlineData(60, 1)]
    public void StructuredHeaderMutations_AreRejected(int offset, byte value)
    {
        var encoded = Canonical();
        encoded[offset] = value;
        Assert.Throws<MailboxCapabilityException>(() =>
            MailboxCapabilityCodec.Decode(
                encoded,
                MailboxCapabilityDomain.Deposit,
                Policy(),
                new AcceptAllReplayGuard()));
    }

    [Fact]
    public void LengthMutationAndTrailingByte_AreRejected()
    {
        var encoded = Canonical();
        encoded[57]++;
        Assert.Throws<MailboxCapabilityException>(() =>
            MailboxCapabilityCodec.Decode(
                encoded,
                MailboxCapabilityDomain.Deposit,
                Policy(),
                new AcceptAllReplayGuard()));

        var trailing = Canonical().Concat(new byte[] { 0 }).ToArray();
        Assert.Throws<MailboxCapabilityException>(() =>
            MailboxCapabilityCodec.Decode(
                trailing,
                MailboxCapabilityDomain.Deposit,
                Policy(),
                new AcceptAllReplayGuard()));
    }

    [Fact]
    public void FixedSeedMalformedInputs_StayInsideExpectedExceptionSurface()
    {
        var random = new Random(0x503B);
        for (var iteration = 0; iteration < 2_000; iteration++)
        {
            var encoded = new byte[random.Next(0, MailboxCapabilityLimits.MaximumPresentationLength + 32)];
            random.NextBytes(encoded);
            try
            {
                _ = MailboxCapabilityCodec.Decode(
                    encoded,
                    MailboxCapabilityDomain.Deposit,
                    Policy(),
                    new AcceptAllReplayGuard());
            }
            catch (MailboxCapabilityException)
            {
                continue;
            }

            Assert.Fail("Random malformed input unexpectedly decoded.");
        }
    }

    private static byte[] Canonical() =>
        MailboxCapabilityCodec.Encode(new MailboxCapabilityPresentation
        {
            DomainValue = new RotatingDepositCapability(
                Enumerable.Range(0x40, 32).Select(static value => (byte)value).ToArray()),
            Lifecycle = MailboxCapabilityLifecycle.Active,
            MixedVersion = MailboxMixedVersionMarker.StrictV1,
            Generation = 7,
            NotBeforeBucket = 1000,
            ExpiresAtBucket = 1100,
            OverlapUntilBucket = 0,
            ReplayCounter = 9,
            IdempotencyKey = Enumerable.Range(0x10, 16)
                .Select(static value => (byte)value)
                .ToArray()
        });

    private static MailboxCapabilityDecodePolicy Policy() =>
        new()
        {
            CurrentBucket = 1010,
            MinimumGeneration = 7
        };

    private sealed class AcceptAllReplayGuard : IMailboxCapabilityReplayGuard
    {
        public bool TryAccept(MailboxCapabilityReplayScope scope) => true;
    }
}
