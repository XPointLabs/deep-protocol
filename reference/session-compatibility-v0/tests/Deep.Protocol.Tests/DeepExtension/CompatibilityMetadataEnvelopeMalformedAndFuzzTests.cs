using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.CompatibilityEnvelopes;
using Deep.Protocol.DeepExtension.OpaqueBundles;
using Deep.Protocol.Tests.Fakes;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class CompatibilityMetadataEnvelopeMalformedAndFuzzTests
{
    [Fact]
    public void EverySingleBitMutation_FailsClosed()
    {
        var encoded = CompatibilityMetadataEnvelopeCodec.Encode(
            CreateRequest(),
            Profile(),
            new DeterministicTestCompatibilityEnvelopeCrypto());

        for (var byteIndex = 0; byteIndex < encoded.Length; byteIndex++)
        {
            for (var bit = 0; bit < 8; bit++)
            {
                var mutated = encoded.ToArray();
                mutated[byteIndex] ^= (byte)(1 << bit);

                try
                {
                    _ = CompatibilityMetadataEnvelopeCodec.Decode(
                        mutated,
                        RecipientMaterial(),
                        Policy(),
                        new DeterministicTestCompatibilityEnvelopeCrypto(),
                        new AcceptOnceReplayGuard());
                    Assert.Fail($"Single-bit mutation at byte {byteIndex}, bit {bit} was accepted.");
                }
                catch (Exception exception)
                {
                    Assert.True(
                        exception is OpaqueBundleException or CompatibilityEnvelopeException,
                        $"Unexpected exception surface: {exception.GetType().FullName}");
                }
            }
        }
    }

    [Fact]
    public void EveryTruncation_FailsWithoutPartialResult()
    {
        var encoded = CompatibilityMetadataEnvelopeCodec.Encode(
            CreateRequest(),
            Profile(),
            new DeterministicTestCompatibilityEnvelopeCrypto());

        for (var length = 0; length < encoded.Length; length++)
        {
            Assert.ThrowsAny<OpaqueBundleException>(() =>
                CompatibilityMetadataEnvelopeCodec.Decode(
                    encoded.AsSpan(0, length),
                    RecipientMaterial(),
                    Policy(),
                    new DeterministicTestCompatibilityEnvelopeCrypto(),
                    new AcceptOnceReplayGuard()));
        }
    }

    [Fact]
    public void FixedSeedRandomMalformedSmoke_StaysInsideExpectedExceptionSurface()
    {
        var random = new Random(0x503A);
        for (var iteration = 0; iteration < 2048; iteration++)
        {
            var bytes = new byte[random.Next(0, 2049)];
            random.NextBytes(bytes);

            try
            {
                _ = CompatibilityMetadataEnvelopeCodec.Decode(
                    bytes,
                    RecipientMaterial(),
                    Policy(),
                    new DeterministicTestCompatibilityEnvelopeCrypto(),
                    new AcceptOnceReplayGuard());
                Assert.Fail($"Random malformed input {iteration} was accepted.");
            }
            catch (Exception exception)
            {
                Assert.True(
                    exception is OpaqueBundleException or CompatibilityEnvelopeException,
                    $"Unexpected exception surface: {exception.GetType().FullName}");
            }
        }
    }

    [Fact]
    public void OptionalOuterMetadata_IsRejectedBeforeCryptoOpen()
    {
        var crypto = new DeterministicTestCompatibilityEnvelopeCrypto();
        var encoded = CompatibilityMetadataEnvelopeCodec.Encode(CreateRequest(), Profile(), crypto);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(14, 4), 1);

        var exception = Assert.Throws<CompatibilityEnvelopeException>(() =>
            CompatibilityMetadataEnvelopeCodec.Decode(
                encoded,
                RecipientMaterial(),
                Policy(),
                crypto,
                new AcceptOnceReplayGuard()));

        Assert.Equal(CompatibilityEnvelopeError.InvalidOuterMetadata, exception.Error);
        Assert.Empty(crypto.OpenDomains);
    }

    [Fact]
    public void SwappingHeaderAndPayloadDomains_FailsAuthentication()
    {
        var encoded = CompatibilityMetadataEnvelopeCodec.Encode(
            CreateRequest(),
            Profile(),
            new DeterministicTestCompatibilityEnvelopeCrypto());
        var capabilityLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(54, 2));
        var headerLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(56, 2));
        var payloadLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(58, 4)));
        var headerOffset = OpaqueBundleLimits.FixedHeaderLength + capabilityLength;
        var payloadOffset = headerOffset + headerLength;
        var header = encoded.AsSpan(headerOffset, headerLength).ToArray();
        var payload = encoded.AsSpan(payloadOffset, payloadLength).ToArray();
        payload.CopyTo(encoded, headerOffset);
        header.CopyTo(encoded, headerOffset + payloadLength);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(56, 2), checked((ushort)payloadLength));
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(58, 4), checked((uint)headerLength));

        var exception = Assert.Throws<CompatibilityEnvelopeException>(() =>
            CompatibilityMetadataEnvelopeCodec.Decode(
                encoded,
                RecipientMaterial(),
                Policy(),
                new DeterministicTestCompatibilityEnvelopeCrypto(),
                new AcceptOnceReplayGuard()));

        Assert.Equal(CompatibilityEnvelopeError.AuthenticationFailed, exception.Error);
    }

    [Theory]
    [InlineData(OpenMutation.HeaderMagic, CompatibilityEnvelopeError.MalformedHeader)]
    [InlineData(OpenMutation.PayloadDpe1Magic, CompatibilityEnvelopeError.InvalidLegacyDpe1)]
    [InlineData(OpenMutation.PayloadSender, CompatibilityEnvelopeError.SenderAuthenticationMismatch)]
    public void PostDecryptValidation_FailsClosed(
        OpenMutation mutation,
        CompatibilityEnvelopeError expectedError)
    {
        var inner = new DeterministicTestCompatibilityEnvelopeCrypto();
        var encoded = CompatibilityMetadataEnvelopeCodec.Encode(CreateRequest(), Profile(), inner);
        var mutating = new MutatingOpenCrypto(
            inner,
            (request, result) => MutateOpenedResult(request, result, mutation));

        var exception = Assert.Throws<CompatibilityEnvelopeException>(() =>
            CompatibilityMetadataEnvelopeCodec.Decode(
                encoded,
                RecipientMaterial(),
                Policy(),
                mutating,
                new AcceptOnceReplayGuard()));

        Assert.Equal(expectedError, exception.Error);
    }

    [Theory]
    [InlineData(OverheadDomain.Header, false)]
    [InlineData(OverheadDomain.Header, true)]
    [InlineData(OverheadDomain.Payload, false)]
    [InlineData(OverheadDomain.Payload, true)]
    public void DecodeRejectsInvalidCiphertextOverhead_BeforeReplayCommit(
        OverheadDomain domain,
        bool aboveMaximum)
    {
        var headerPlaintext = CreateHeaderPlaintext();
        var payloadPlaintext = CreateRequest().LegacyDpe1.ToArray();
        var headerCiphertextLength = headerPlaintext.Length + 1;
        var payloadCiphertextLength = payloadPlaintext.Length + 1;
        var targetPlaintextLength = domain == OverheadDomain.Header
            ? headerPlaintext.Length
            : payloadPlaintext.Length;
        var invalidCiphertextLength = aboveMaximum
            ? targetPlaintextLength + CompatibilityEnvelopeLimits.MaximumCryptoOverhead + 1
            : targetPlaintextLength;
        if (domain == OverheadDomain.Header)
        {
            headerCiphertextLength = invalidCiphertextLength;
        }
        else
        {
            payloadCiphertextLength = invalidCiphertextLength;
        }

        var encoded = CreateDirectEnvelope(headerCiphertextLength, payloadCiphertextLength);
        var replay = new CountingReplayGuard();
        var exception = Assert.Throws<CompatibilityEnvelopeException>(() =>
            CompatibilityMetadataEnvelopeCodec.Decode(
                encoded,
                RecipientMaterial(),
                Policy(),
                new ValidOpenedResultCrypto(headerPlaintext, payloadPlaintext),
                replay));

        Assert.Equal(CompatibilityEnvelopeError.InvalidCryptoResult, exception.Error);
        Assert.Equal(0, replay.Calls);
    }

    [Fact]
    public void EncodeRejectsMalformedDpe1AndOversizedCryptoResult()
    {
        var invalidDpe1 = CreateRequest() with { LegacyDpe1 = Encoding.ASCII.GetBytes("NOPE") };
        var invalid = Assert.Throws<CompatibilityEnvelopeException>(() =>
            CompatibilityMetadataEnvelopeCodec.Encode(
                invalidDpe1,
                Profile(),
                new DeterministicTestCompatibilityEnvelopeCrypto()));
        Assert.Equal(CompatibilityEnvelopeError.InvalidLegacyDpe1, invalid.Error);

        var oversized = Assert.Throws<CompatibilityEnvelopeException>(() =>
            CompatibilityMetadataEnvelopeCodec.Encode(
                CreateRequest(),
                Profile(),
                new OversizedSealCrypto()));
        Assert.Equal(CompatibilityEnvelopeError.InvalidCryptoResult, oversized.Error);
    }

    private static CompatibilityEnvelopeOpenedResult MutateOpenedResult(
        CompatibilityEnvelopeOpenRequest request,
        CompatibilityEnvelopeOpenedResult result,
        OpenMutation mutation)
    {
        if (mutation == OpenMutation.HeaderMagic &&
            request.Purpose == CompatibilityEnvelopePurpose.Header)
        {
            var plaintext = result.Plaintext.ToArray();
            plaintext[0] ^= 1;
            return result with { Plaintext = plaintext };
        }

        if (mutation == OpenMutation.PayloadDpe1Magic &&
            request.Purpose == CompatibilityEnvelopePurpose.Payload)
        {
            var plaintext = result.Plaintext.ToArray();
            plaintext[0] ^= 1;
            return result with { Plaintext = plaintext };
        }

        if (mutation == OpenMutation.PayloadSender &&
            request.Purpose == CompatibilityEnvelopePurpose.Payload)
        {
            var sender = result.SenderAuthenticationData.ToArray();
            sender[0] ^= 1;
            return result with { SenderAuthenticationData = sender };
        }

        return result;
    }

    private static byte[] CreateDirectEnvelope(
        int headerCiphertextLength,
        int payloadCiphertextLength)
    {
        var request = CreateRequest();
        return OpaqueBundleCodec.Encode(
            new OpaqueBundleWriteRequest
            {
                Capability = request.Capability,
                TransportAttemptId = request.TransportAttemptId,
                EndToEndDedupId = request.EndToEndDedupId,
                ExpiryBucket = request.ExpiryBucket,
                PaddingClass = OpaqueBundlePaddingClass.Bytes1024,
                ReplayMaterial = request.ReplayMaterial,
                EncryptedHeader = FrameZeros(
                    request.HeaderNonceContext,
                    headerCiphertextLength),
                EncryptedPayload = FrameZeros(
                    request.PayloadNonceContext,
                    payloadCiphertextLength),
                PayloadKind = OpaqueBundlePayloadKind.AuthenticatedLegacyDpe1,
                CriticalFeatures =
                    OpaqueBundleFeatures.V1Required |
                    OpaqueBundleFeatures.LegacyDpe1Compatibility |
                    OpaqueBundleFeatures.AuthenticatedCompatibilityEnvelope
            },
            Profile());
    }

    private static byte[] FrameZeros(
        ReadOnlyMemory<byte> nonceContext,
        int ciphertextLength)
    {
        var framed = new byte[nonceContext.Length + ciphertextLength];
        nonceContext.Span.CopyTo(framed);
        return framed;
    }

    private static byte[] CreateHeaderPlaintext()
    {
        var header = new byte[CompatibilityEnvelopeLimits.HeaderPlaintextLength];
        Encoding.ASCII.GetBytes("P3A1").CopyTo(header, 0);
        BinaryPrimitives.WriteUInt32BigEndian(
            header.AsSpan(4),
            checked((uint)CreateRequest().LegacyDpe1.Length));
        return header;
    }

    private static CompatibilityEnvelopeWriteRequest CreateRequest() =>
        new()
        {
            Capability = new OpaqueDepositCapability(Range(0x40, 32)),
            TransportAttemptId = new TransportAttemptId(Range(0x10, 16)),
            EndToEndDedupId = new EndToEndDedupId(Range(0x20, 16)),
            ExpiryBucket = 123456,
            PaddingClass = OpaqueBundlePaddingClass.Bytes256,
            ReplayMaterial = Range(0x30, 16),
            HeaderNonceContext = Range(0x60, 32),
            PayloadNonceContext = Range(0x80, 32),
            RecipientKeyMaterial = RecipientMaterial(),
            SenderAuthenticationSecret = Range(0xc0, 32),
            LegacyDpe1 = Encoding.ASCII.GetBytes("DPE1\0\0exact-legacy-payload")
        };

    private static OpaqueBundleNegotiatedProfile Profile() =>
        new(
            OpaqueBundleWireVersion.V1,
            OpaqueBundleFeatures.V1Required |
            OpaqueBundleFeatures.LegacyDpe1Compatibility |
            OpaqueBundleFeatures.AuthenticatedCompatibilityEnvelope,
            AllowLegacyDpe1: true);

    private static OpaqueBundleDecodePolicy Policy() =>
        new()
        {
            MinimumVersion = OpaqueBundleWireVersion.V1,
            MaximumVersion = OpaqueBundleWireVersion.V1,
            SupportedCriticalFeatures =
                OpaqueBundleFeatures.V1Required |
                OpaqueBundleFeatures.LegacyDpe1Compatibility |
                OpaqueBundleFeatures.AuthenticatedCompatibilityEnvelope,
            MinimumExpiryBucket = 123456,
            MaximumExpiryBucket = 123460,
            AllowLegacyDpe1 = true
        };

    private static byte[] RecipientMaterial() => Range(0xa0, 32);

    private static byte[] Range(int start, int length) =>
        Enumerable.Range(start, length).Select(static value => (byte)value).ToArray();

    public enum OpenMutation
    {
        HeaderMagic,
        PayloadDpe1Magic,
        PayloadSender
    }

    public enum OverheadDomain
    {
        Header,
        Payload
    }

    private sealed class AcceptOnceReplayGuard : ICompatibilityEnvelopeReplayGuard
    {
        private bool _accepted;

        public bool TryAccept(CompatibilityEnvelopeReplayScope scope)
        {
            _ = scope;
            if (_accepted)
            {
                return false;
            }

            _accepted = true;
            return true;
        }
    }

    private sealed class MutatingOpenCrypto(
        ICompatibilityEnvelopeCrypto inner,
        Func<
            CompatibilityEnvelopeOpenRequest,
            CompatibilityEnvelopeOpenedResult,
            CompatibilityEnvelopeOpenedResult> mutate)
        : ICompatibilityEnvelopeCrypto
    {
        public CompatibilityEnvelopeSealedResult Seal(CompatibilityEnvelopeSealRequest request) =>
            inner.Seal(request);

        public CompatibilityEnvelopeOpenedResult Open(CompatibilityEnvelopeOpenRequest request) =>
            mutate(request, inner.Open(request));
    }

    private sealed class ValidOpenedResultCrypto(
        ReadOnlyMemory<byte> headerPlaintext,
        ReadOnlyMemory<byte> payloadPlaintext)
        : ICompatibilityEnvelopeCrypto
    {
        private static readonly byte[] SenderAuthentication = Range(0xc0, 32);

        public CompatibilityEnvelopeSealedResult Seal(CompatibilityEnvelopeSealRequest request) =>
            throw new NotSupportedException();

        public CompatibilityEnvelopeOpenedResult Open(CompatibilityEnvelopeOpenRequest request) =>
            new(
                request.Purpose == CompatibilityEnvelopePurpose.Header
                    ? headerPlaintext
                    : payloadPlaintext,
                SenderAuthentication);
    }

    private sealed class CountingReplayGuard : ICompatibilityEnvelopeReplayGuard
    {
        public int Calls { get; private set; }

        public bool TryAccept(CompatibilityEnvelopeReplayScope scope)
        {
            _ = scope;
            Calls++;
            return true;
        }
    }

    private sealed class OversizedSealCrypto : ICompatibilityEnvelopeCrypto
    {
        public CompatibilityEnvelopeSealedResult Seal(CompatibilityEnvelopeSealRequest request)
        {
            _ = request;
            return new CompatibilityEnvelopeSealedResult(
                new byte[OpaqueBundleLimits.MaximumEncryptedHeaderLength]);
        }

        public CompatibilityEnvelopeOpenedResult Open(CompatibilityEnvelopeOpenRequest request) =>
            throw new NotSupportedException();
    }
}
