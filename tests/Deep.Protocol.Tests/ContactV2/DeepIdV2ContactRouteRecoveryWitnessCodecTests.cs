using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.Tests.ContactV1;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2ContactRouteRecoveryWitnessCodecTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(3)]
    public void CompactPublicCandidatesKeepExactSixRecordRouteSeparate(int count)
    {
        var tail = Tail(count); var snapshot = tail.ToArray();
        var parsed = DeepIdV2ContactRouteRecoveryWitnessCodec.Decode(tail);
        Assert.Equal(count, parsed.PairCount); tail.AsSpan().Clear();
        Assert.Equal(snapshot, parsed.CanonicalBytes.ToArray());
        var original = OrdinaryRecord(false); var ordinary = Assert.IsType<ContactRouteUpdateDmc2Payload>(original.ParsedPayload);
        Assert.Null(ordinary.RecoveryWitness); Assert.Equal(6, ordinary.CanonicalBytes.Span[72]);
        var recovered = ApplicationCoreCodec.DecodeDmc2(ReplacePayload(original, Augment(ordinary.CanonicalBytes.Span, snapshot)));
        var update = Assert.IsType<ContactRouteUpdateDmc2Payload>(recovered.ParsedPayload);
        Assert.Equal(7, update.CanonicalBytes.Span[72]); Assert.Equal(count, update.RecoveryWitness!.PairCount);
        Assert.Equal(ordinary.ExactRouteClosure.ToArray(), update.ExactRouteClosure.ToArray());
        Assert.Equal(6, update.ExactRouteClosure.Span[0]);
        Assert.Equal(ordinary.ExactRouteClosure.ToArray(), ContactRouteClosureCodec.Decode(update.ExactRouteClosure.Span).ExactBytes.ToArray());
        Assert.ThrowsAny<FormatException>(() => ContactRouteClosureCodec.Decode(update.CanonicalBytes.Span[72..]));
        Assert.Empty(typeof(ParsedDeepIdV2ContactRouteRecoveryWitness).GetConstructors());
    }

    [Theory]
    [InlineData("version")]
    [InlineData("zero-pairs")]
    [InlineData("four-pairs")]
    [InlineData("reserved")]
    [InlineData("anchor-version")]
    [InlineData("nonce")]
    [InlineData("zero-floor")]
    [InlineData("response-length")]
    [InlineData("foreign-network")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    public void MalformedCompactTailNeverBecomesAnAuthority(string fault)
    {
        var tail = Tail(1);
        switch (fault)
        {
            case "version": tail[0] = 2; break;
            case "zero-pairs": tail[1] = 0; break;
            case "four-pairs": tail[1] = 4; break;
            case "reserved": tail[2] = 1; break;
            case "anchor-version": tail[9] = 1; break;
            case "nonce": tail[615] ^= 1; break;
            case "zero-floor": tail.AsSpan(655, 32).Clear(); break;
            case "response-length": BinaryPrimitives.WriteUInt32BigEndian(tail.AsSpan(1237), uint.MaxValue); break;
            case "foreign-network": tail[4 + 20] ^= 1; break;
            case "truncated": tail = tail[..^1]; break;
            case "trailing": tail = [.. tail, 0]; break;
        }
        if (fault == "nonce")
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => DeepIdV2ContactRouteRecoveryWitnessCodec.Decode(tail));
        else
            Assert.ThrowsAny<FormatException>(() => DeepIdV2ContactRouteRecoveryWitnessCodec.Decode(tail));
    }

    [Theory]
    [InlineData("count5")]
    [InlineData("count8")]
    [InlineData("missing-tail")]
    [InlineData("ordinary-with-tail")]
    [InlineData("tail-length")]
    public void PayloadCountAndTailFramingAreClosed(string fault)
    {
        var original = OrdinaryRecord(false); var plain = original.ParsedPayload.CanonicalBytes.ToArray();
        var tail = Tail(1); var payload = Augment(plain, tail);
        if (fault == "count5") payload[72] = 5;
        if (fault == "count8") payload[72] = 8;
        if (fault == "missing-tail") payload = [.. plain];
        if (fault == "missing-tail") payload[72] = 7;
        if (fault == "ordinary-with-tail") payload[72] = 6;
        if (fault == "tail-length") BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(plain.Length), uint.MaxValue);
        Assert.ThrowsAny<FormatException>(() => ApplicationCoreCodec.DecodeDmc2(ReplacePayload(original, payload)));
    }

    [Fact]
    public void AggregateCapacityRejectsWithoutTruncatingAndOrdinaryMaximumStaysExact()
    {
        var original = OrdinaryRecord(true);
        Assert.Equal(23_367, original.ParsedPayload.CanonicalBytes.Length);
        Assert.Equal(23_649, original.CanonicalBytes.Length);
        var augmented = Augment(original.ParsedPayload.CanonicalBytes.Span, Tail(3));
        Assert.True(augmented.Length > 32_768, "The hostile aggregate did not cross the unchanged payload cap.");
        Assert.ThrowsAny<FormatException>(() => ApplicationCoreCodec.DecodeDmc2(ReplacePayload(original, augmented)));
        Assert.ThrowsAny<FormatException>(() => DeepIdV2ContactRouteRecoveryWitnessCodec.Decode(new byte[28_550]));
        Assert.Equal(33_050, ApplicationCoreCodec.MaximumContactRouteUpdateRecordBytes);
        Assert.Equal(3_825, DeepIdV2ContactRouteRecoveryWitnessCodec.MinimumBytes);
        Assert.Equal(28_549, DeepIdV2ContactRouteRecoveryWitnessCodec.MaximumBytes);
    }

    private static ParsedDmc2 OrdinaryRecord(bool maximum)
    {
        var records = maximum ? ContactCodecTests.Records.MaximumRouteClosure : ContactCodecTests.Records.RouteClosure;
        var payload = ContactCodecValidation.CreateContactRouteUpdatePayload(B(32, 0x51), 0, new byte[32],
            records.Xrr, records.Xra, records.Xrc, records.Xss, records.Pmt, records.Pms);
        return ContactCodecValidation.AuthorDmc2(records.Xrr.Field(1).Span, B(32, 0x52), B(32, 0x53), B(32, 0x54),
            B(32, 0x55), 1, 1_000, 2_000, Dmc2Flags.None, [], payload);
    }

    // Public structural fixtures only. Parsing deliberately grants no history,
    // ratchet authentication, native predecessor, publication or route authority.
    private static byte[] Tail(int count)
    {
        var (request, response) = DeepIdV2ContactRouteRecoveryWireCodecTests.Ordinary();
        var encodedResponse = ContactRouteAuthorityWireCodec.EncodeResponse(request, response);
        var bytes = new byte[615 + count * (626 + encodedResponse.Length)]; bytes[0] = 1; bytes[1] = checked((byte)count);
        request.ExactPredecessorXir1V2.Span.CopyTo(bytes.AsSpan(4)); var offset = 615;
        for (var index = 0; index < count; index++)
        {
            request.RequestNonce.Span.CopyTo(bytes.AsSpan(offset));
            BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset + 32), request.MinimumAdh1Generation);
            request.MinimumAdh1CoreHash.Span.CopyTo(bytes.AsSpan(offset + 40)); request.ExactXra1.Span.CopyTo(bytes.AsSpan(offset + 72));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 622), checked((uint)encodedResponse.Length));
            encodedResponse.CopyTo(bytes, offset + 626); offset += 626 + encodedResponse.Length;
        }
        return bytes;
    }
    private static byte[] Augment(ReadOnlySpan<byte> ordinary, byte[] tail)
    {
        var bytes = new byte[ordinary.Length + 4 + tail.Length]; ordinary.CopyTo(bytes); bytes[72] = 7;
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(ordinary.Length), checked((uint)tail.Length)); tail.CopyTo(bytes, ordinary.Length + 4);
        return bytes;
    }
    internal static byte[] ReplacePayload(ParsedDmc2 original, byte[] payload)
    {
        var prior = original.CanonicalBytes.ToArray(); var offset = 12;
        while (BinaryPrimitives.ReadUInt16BigEndian(prior.AsSpan(offset)) != 12)
            offset += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(prior.AsSpan(offset + 4)));
        var encoded = new byte[offset + 8 + payload.Length]; prior.AsSpan(0, offset + 8).CopyTo(encoded);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(offset + 4), checked((uint)payload.Length)); payload.CopyTo(encoded, offset + 8);
        return encoded;
    }
    private static byte[] B(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
}
