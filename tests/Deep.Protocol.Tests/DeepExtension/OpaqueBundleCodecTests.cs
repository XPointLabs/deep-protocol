using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.DeepExtension.OpaqueBundles;
using Deep.Protocol.GoldenVectors;

namespace Deep.Protocol.Tests.DeepExtension;

public sealed class OpaqueBundleCodecTests
{
    private static readonly byte[] DepositCapability = Enumerable.Range(0x40, 32).Select(static value => (byte)value).ToArray();
    private static readonly byte[] AttemptId = Enumerable.Range(0x10, 16).Select(static value => (byte)value).ToArray();
    private static readonly byte[] DedupId = Enumerable.Range(0x20, 16).Select(static value => (byte)value).ToArray();
    private static readonly byte[] ReplayMaterial = Enumerable.Range(0x30, 16).Select(static value => (byte)value).ToArray();

    [Fact]
    public void V1DepositBundle_MatchesCanonicalGoldenVector()
    {
        var request = CreateDepositRequest(
            Encoding.ASCII.GetBytes("sealed-header-v1"),
            Encoding.ASCII.GetBytes("opaque-payload-v1"));

        var encoded = OpaqueBundleCodec.Encode(request, StrictV1Profile());

        Assert.Equal(256, encoded.Length);
        var vector = GoldenVectorLoader.Load("opaque-bundle-v1.json")
            .GetRequired("deep-extension/opaque-bundle/v1/deposit-256");
        VectorDiffs.AssertHex(
            vector.Id,
            vector.Hex + new string('0', 254),
            Convert.ToHexString(encoded).ToLowerInvariant());

        var decoded = OpaqueBundleCodec.Decode(encoded, StrictV1Policy());

        Assert.Equal(OpaqueBundleWireVersion.V1, decoded.WireVersion);
        Assert.IsType<OpaqueDepositCapability>(decoded.Capability);
        Assert.Equal(DepositCapability, decoded.Capability.Bytes.ToArray());
        Assert.Equal(AttemptId, decoded.TransportAttemptId.Bytes.ToArray());
        Assert.Equal(ReplayMaterial, decoded.ReplayMaterial.ToArray());
        Assert.Equal("sealed-header-v1", Encoding.ASCII.GetString(decoded.EncryptedHeader.Span));
        Assert.Equal("opaque-payload-v1", Encoding.ASCII.GetString(decoded.EncryptedPayload.Span));
    }

    [Fact]
    public void LegacyDpe1Payload_IsPreservedByteForByte_OnlyWithExplicitProfile()
    {
        var dpe1 = Encoding.ASCII.GetBytes("DPE1\0\0exact-legacy-payload");
        var request = CreateDepositRequest([0xaa], dpe1, OpaqueBundlePayloadKind.LegacyDpe1);

        Assert.Throws<OpaqueBundlePolicyException>(() =>
            OpaqueBundleCodec.Encode(request, StrictV1Profile()));

        var encoded = OpaqueBundleCodec.Encode(request, StrictV1Profile(allowLegacyDpe1: true));
        Assert.Throws<OpaqueBundlePolicyException>(() =>
            OpaqueBundleCodec.Decode(encoded, StrictV1Policy()));

        var decoded = OpaqueBundleCodec.Decode(encoded, StrictV1Policy(allowLegacyDpe1: true));
        Assert.Equal(dpe1, decoded.EncryptedPayload.ToArray());
    }

    [Fact]
    public void TransportAttemptId_CannotEqualEndToEndDedupId()
    {
        var request = CreateDepositRequest([0xaa], [0xbb]) with
        {
            EndToEndDedupId = new EndToEndDedupId(AttemptId)
        };

        Assert.Throws<OpaqueBundlePolicyException>(() =>
            OpaqueBundleCodec.Encode(request, StrictV1Profile()));
    }

    [Fact]
    public void OuterContract_DoesNotSerializeInnerDedupOrManagedIdentityMetadata()
    {
        var request = CreateDepositRequest([0xaa], [0xbb]);
        var encoded = OpaqueBundleCodec.Encode(request, StrictV1Profile());

        Assert.DoesNotContain(Convert.ToHexString(DedupId), Convert.ToHexString(encoded));
        var ascii = Encoding.ASCII.GetString(encoded);
        Assert.DoesNotContain("payer", ascii, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("plan", ascii, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("session", ascii, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(54, 0x7f, 0xff)]
    [InlineData(56, 0x7f, 0xff)]
    [InlineData(58, 0x7f, 0xff)]
    public void MalformedLengths_FailClosed(int offset, byte high, byte low)
    {
        var encoded = OpaqueBundleCodec.Encode(CreateDepositRequest([0xaa], [0xbb]), StrictV1Profile());
        encoded[offset] = high;
        encoded[offset + 1] = low;

        var exception = Assert.Throws<OpaqueBundleFormatException>(() =>
            OpaqueBundleCodec.Decode(encoded, StrictV1Policy()));

        Assert.Equal(OpaqueBundleDecodeError.MalformedLength, exception.Error);
    }

    [Fact]
    public void NonCanonicalPadding_FailsClosed()
    {
        var encoded = OpaqueBundleCodec.Encode(CreateDepositRequest([0xaa], [0xbb]), StrictV1Profile());
        encoded[^1] = 1;

        var exception = Assert.Throws<OpaqueBundleFormatException>(() =>
            OpaqueBundleCodec.Decode(encoded, StrictV1Policy()));

        Assert.Equal(OpaqueBundleDecodeError.NonCanonicalPadding, exception.Error);
    }

    [Fact]
    public void NonCanonicalMinimumReaderVersion_FailsClosed()
    {
        var encoded = OpaqueBundleCodec.Encode(CreateDepositRequest([0xaa], [0xbb]), StrictV1Profile());
        encoded[5] = 0;

        var exception = Assert.Throws<OpaqueBundleFormatException>(() =>
            OpaqueBundleCodec.Decode(encoded, StrictV1Policy()));

        Assert.Equal(OpaqueBundleDecodeError.DowngradeRejected, exception.Error);
    }

    [Fact]
    public void UnknownCriticalFeature_FailsClosed_ButUnknownOptionalFeatureIsCarried()
    {
        var encoded = OpaqueBundleCodec.Encode(CreateDepositRequest([0xaa], [0xbb]), StrictV1Profile());
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(10, 4), 0x8000_0007);

        var critical = Assert.Throws<OpaqueBundlePolicyException>(() =>
            OpaqueBundleCodec.Decode(encoded, StrictV1Policy()));
        Assert.Equal(OpaqueBundleDecodeError.UnknownCriticalFeature, critical.Error);

        encoded = OpaqueBundleCodec.Encode(CreateDepositRequest([0xaa], [0xbb]), StrictV1Profile());
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(14, 4), 0x8000_0000);
        var decoded = OpaqueBundleCodec.Decode(encoded, StrictV1Policy());
        Assert.Equal((OpaqueBundleFeatures)0x8000_0000, decoded.OptionalFeatures);
    }

    [Fact]
    public void CallerSuppliedProfileAndPolicy_CannotExtendImplementationCriticalFeatures()
    {
        const OpaqueBundleFeatures maliciousUnknownFeature = (OpaqueBundleFeatures)0x8000_0000;
        var request = CreateDepositRequest([0xaa], [0xbb]) with
        {
            CriticalFeatures = OpaqueBundleFeatures.V1Required | maliciousUnknownFeature
        };
        var maliciousProfile = StrictV1Profile() with
        {
            SupportedCriticalFeatures = OpaqueBundleFeatures.V1Required |
                OpaqueBundleFeatures.LegacyDpe1Compatibility |
                maliciousUnknownFeature
        };

        var encode = Assert.Throws<OpaqueBundlePolicyException>(() =>
            OpaqueBundleCodec.Encode(request, maliciousProfile));
        Assert.Equal(OpaqueBundleDecodeError.UnknownCriticalFeature, encode.Error);

        var encoded = OpaqueBundleCodec.Encode(
            CreateDepositRequest([0xaa], [0xbb]),
            StrictV1Profile());
        BinaryPrimitives.WriteUInt32BigEndian(
            encoded.AsSpan(10, 4),
            (uint)(OpaqueBundleFeatures.V1Required | maliciousUnknownFeature));
        var maliciousPolicy = StrictV1Policy() with
        {
            SupportedCriticalFeatures = OpaqueBundleFeatures.V1Required |
                OpaqueBundleFeatures.LegacyDpe1Compatibility |
                maliciousUnknownFeature
        };

        var decode = Assert.Throws<OpaqueBundlePolicyException>(() =>
            OpaqueBundleCodec.Decode(encoded, maliciousPolicy));
        Assert.Equal(OpaqueBundleDecodeError.UnknownCriticalFeature, decode.Error);
    }

    [Fact]
    public void NegotiationOffers_CannotExtendImplementationCriticalFeatures()
    {
        const OpaqueBundleFeatures maliciousUnknownFeature = (OpaqueBundleFeatures)0x8000_0000;
        var malicious = new OpaqueBundleNegotiationOffer(
            OpaqueBundleWireVersion.V1,
            OpaqueBundleWireVersion.V1,
            OpaqueBundleFeatures.V1Required | maliciousUnknownFeature);
        var normal = new OpaqueBundleNegotiationOffer(
            OpaqueBundleWireVersion.V1,
            OpaqueBundleWireVersion.V1,
            OpaqueBundleFeatures.V1Required);

        Assert.Throws<OpaqueBundleNegotiationException>(() =>
            OpaqueBundleNegotiator.Negotiate(
                malicious,
                normal,
                minimumSafeVersion: OpaqueBundleWireVersion.V1));
        Assert.Throws<OpaqueBundleNegotiationException>(() =>
            OpaqueBundleNegotiator.Negotiate(
                normal,
                malicious,
                minimumSafeVersion: OpaqueBundleWireVersion.V1));
    }

    [Fact]
    public void CallerPolicies_MayNarrowButNeverExtendKnownCriticalFeatures()
    {
        Assert.Equal(
            OpaqueBundleFeatures.V1Required | OpaqueBundleFeatures.LegacyDpe1Compatibility,
            OpaqueBundleFeatureSet.KnownCriticalFeatures);

        var nativeOnlyProfile = new OpaqueBundleNegotiatedProfile(
            OpaqueBundleWireVersion.V1,
            OpaqueBundleFeatures.V1Required,
            AllowLegacyDpe1: false);
        var nativeOnlyPolicy = StrictV1Policy() with
        {
            SupportedCriticalFeatures = OpaqueBundleFeatures.V1Required
        };
        var encoded = OpaqueBundleCodec.Encode(
            CreateDepositRequest([0xaa], [0xbb]),
            nativeOnlyProfile);

        var decoded = OpaqueBundleCodec.Decode(encoded, nativeOnlyPolicy);

        Assert.Equal(OpaqueBundlePayloadKind.NativeOpaque, decoded.PayloadKind);
    }

    [Fact]
    public void Encode_RejectsUndefinedPayloadKindBeforeWriting()
    {
        var request = CreateDepositRequest([0xaa], [0xbb]) with
        {
            PayloadKind = (OpaqueBundlePayloadKind)0xff
        };

        var exception = Assert.Throws<OpaqueBundleFormatException>(() =>
            OpaqueBundleCodec.Encode(request, StrictV1Profile()));

        Assert.Equal(OpaqueBundleDecodeError.InvalidEnumValue, exception.Error);
    }

    [Theory]
    [InlineData(123455u)]
    [InlineData(123461u)]
    public void ExpiryOutsideNegotiatedBucketWindow_FailsClosed(uint expiryBucket)
    {
        var request = CreateDepositRequest([0xaa], [0xbb]) with { ExpiryBucket = expiryBucket };
        var encoded = OpaqueBundleCodec.Encode(request, StrictV1Profile());

        var exception = Assert.Throws<OpaqueBundlePolicyException>(() =>
            OpaqueBundleCodec.Decode(encoded, StrictV1Policy()));

        Assert.Equal(OpaqueBundleDecodeError.ExpiryOutsideWindow, exception.Error);
    }

    [Fact]
    public void Negotiation_UsesHighestIntersection_AndNeverSilentlyDowngrades()
    {
        var local = new OpaqueBundleNegotiationOffer(
            MinimumVersion: OpaqueBundleWireVersion.V1,
            MaximumVersion: OpaqueBundleWireVersion.V1,
            SupportedCriticalFeatures: OpaqueBundleFeatures.V1Required);
        var peer = local;

        var profile = OpaqueBundleNegotiator.Negotiate(local, peer, minimumSafeVersion: OpaqueBundleWireVersion.V1);

        Assert.Equal(OpaqueBundleWireVersion.V1, profile.WireVersion);
        Assert.Throws<OpaqueBundleNegotiationException>(() =>
            OpaqueBundleNegotiator.Negotiate(
                local,
                new OpaqueBundleNegotiationOffer(
                    (OpaqueBundleWireVersion)0,
                    (OpaqueBundleWireVersion)0,
                    OpaqueBundleFeatures.V1Required),
                minimumSafeVersion: OpaqueBundleWireVersion.V1));
        Assert.Throws<OpaqueBundleNegotiationException>(() =>
            OpaqueBundleNegotiator.Negotiate(
                local,
                peer,
                minimumSafeVersion: (OpaqueBundleWireVersion)2));
    }

    [Fact]
    public void RetrieveCapability_RoundTripsAsDistinctRuntimeType()
    {
        var request = new OpaqueBundleWriteRequest
        {
            Capability = new OpaqueRetrieveCapability(DepositCapability),
            TransportAttemptId = new TransportAttemptId(AttemptId),
            EndToEndDedupId = new EndToEndDedupId(DedupId),
            ExpiryBucket = 123456,
            PaddingClass = OpaqueBundlePaddingClass.Bytes256,
            ReplayMaterial = ReplayMaterial,
            EncryptedHeader = new byte[] { 0xaa },
            EncryptedPayload = new byte[] { 0xbb },
            PayloadKind = OpaqueBundlePayloadKind.NativeOpaque,
            CriticalFeatures = OpaqueBundleFeatures.V1Required
        };

        var decoded = OpaqueBundleCodec.Decode(
            OpaqueBundleCodec.Encode(request, StrictV1Profile()),
            StrictV1Policy());

        Assert.IsType<OpaqueRetrieveCapability>(decoded.Capability);
    }

    private static OpaqueBundleWriteRequest CreateDepositRequest(
        byte[] header,
        byte[] payload,
        OpaqueBundlePayloadKind payloadKind = OpaqueBundlePayloadKind.NativeOpaque) =>
        new()
        {
            Capability = new OpaqueDepositCapability(DepositCapability),
            TransportAttemptId = new TransportAttemptId(AttemptId),
            EndToEndDedupId = new EndToEndDedupId(DedupId),
            ExpiryBucket = 123456,
            PaddingClass = OpaqueBundlePaddingClass.Bytes256,
            ReplayMaterial = ReplayMaterial,
            EncryptedHeader = header,
            EncryptedPayload = payload,
            PayloadKind = payloadKind,
            CriticalFeatures = OpaqueBundleFeatures.V1Required |
                (payloadKind == OpaqueBundlePayloadKind.LegacyDpe1
                    ? OpaqueBundleFeatures.LegacyDpe1Compatibility
                    : OpaqueBundleFeatures.None)
        };

    private static OpaqueBundleNegotiatedProfile StrictV1Profile(bool allowLegacyDpe1 = false) =>
        new(
            OpaqueBundleWireVersion.V1,
            OpaqueBundleFeatures.V1Required | OpaqueBundleFeatures.LegacyDpe1Compatibility,
            allowLegacyDpe1);

    private static OpaqueBundleDecodePolicy StrictV1Policy(bool allowLegacyDpe1 = false) =>
        new()
        {
            MinimumVersion = OpaqueBundleWireVersion.V1,
            MaximumVersion = OpaqueBundleWireVersion.V1,
            SupportedCriticalFeatures =
                OpaqueBundleFeatures.V1Required | OpaqueBundleFeatures.LegacyDpe1Compatibility,
            MinimumExpiryBucket = 123456,
            MaximumExpiryBucket = 123460,
            AllowLegacyDpe1 = allowLegacyDpe1
        };
}
