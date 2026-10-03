using System.Buffers.Binary;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.Tests.ContactV1;

namespace Deep.Protocol.Tests.ContactV2;

/// <summary>
/// Executable mapping for the retained identity-neutral contact negatives.
/// Parsed codec/graph inputs only: no signed authority, callback, publication,
/// transport, service mutation or physical E2E claim.
/// </summary>
public sealed class CurrentContactSecurityTests
{
    [Theory]
    [InlineData("xrc-xra-sealing-binding", "Xrc1AuthorityBindingMismatch")]
    [InlineData("xrc-pmt-xnv-binding", "Xrc1AuthorityBindingMismatch")]
    [InlineData("xrr-device-binding", "RouteValidityIntersectionMismatch")]
    [InlineData("route-validity-intersection", "RouteValidityIntersectionMismatch")]
    public void InBandRouteRejectsExactCrossFieldMutation(string id, string rejection)
    {
        var closure = ContactCodecTests.Records.RouteClosure;
        ContactCodec.ValidateRouteUpdateGraph(closure.Xrr, closure.Xra, closure.Xrc,
            closure.Xss, closure.Pmt, closure.Pms);
        var xrc = closure.Xrc;
        var xrr = closure.Xrr;
        switch (id)
        {
            case "xrc-xra-sealing-binding": xrc = Flip(closure.Xrc, 11, 0); break;
            case "xrc-pmt-xnv-binding": xrc = Flip(closure.Xrc, 8, 6); break;
            case "xrr-device-binding": xrr = Flip(closure.Xrr, 18, 6); break;
            case "route-validity-intersection":
                var exact = closure.Xrr.CanonicalBytes.ToArray();
                BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(FieldOffset(exact, 17)), 3);
                xrr = ContactCodec.Decode("XRR1", exact);
                break;
            default: throw new InvalidDataException("Unmapped current contact negative.");
        }
        // Mutation remains individually canonical, so this must reach the
        // actual complete graph check rather than stop at an invalid header.
        var error = Assert.Throws<ContactFormatException>(() => ContactCodec.ValidateRouteUpdateGraph(
            xrr, closure.Xra, xrc, closure.Xss, closure.Pmt, closure.Pms));
        Assert.Equal(ContactValidationStage.Closure, error.Stage);
        Assert.Equal(rejection, error.Code);
    }

    [Fact]
    [Trait("ContactVector", "xir-xra-binding")]
    public void CurrentPrivateRouteRejectsChangedXraReferenceInInvite()
    {
        var exact = DeepIdV2ContactMailboxRouteTests.Package(false);
        _ = DeepIdV2ContactMailboxRouteCodec.Decode(exact);
        // DR-0062 package: four-byte local header, DCA1[473], XIR1[611].
        const int inviteOffset = 4 + 473;
        exact[inviteOffset + FieldOffset(exact.AsSpan(inviteOffset, 611), 18) + 6] ^= 1;
        Assert.Throws<System.Security.Cryptography.CryptographicException>(() =>
            DeepIdV2ContactMailboxRouteCodec.Decode(exact));
    }

    [Fact]
    [Trait("ContactVector", "xrr-minimum-reader-zero")]
    public void ZeroMinimumReaderRejectsAtScalarStage()
    {
        var exact = ContactCodecTests.Records.RouteClosure.Xrr.CanonicalBytes.ToArray();
        Array.Clear(exact, FieldOffset(exact, 14), 2);
        var error = Assert.Throws<ContactFormatException>(() => ContactCodec.Decode("XRR1", exact));
        Assert.Equal(ContactValidationStage.Scalar, error.Stage);
        Assert.Equal("InvalidReachabilityPolicy", error.Code);
    }

    [Fact]
    [Trait("ContactVector", "pms-tie-break")]
    public void EqualScoreUsesNodeIdInTheActualIssuerVerifierOrdering()
    {
        var smaller = Enumerable.Repeat((byte)0x10, 32).ToArray();
        var larger = Enumerable.Repeat((byte)0x11, 32).ToArray();
        var score = Enumerable.Repeat((byte)0x20, 32).ToArray();
        Assert.True(ContactCodec.CompareRendezvousCandidates((larger, score), (smaller, score)) > 0);
        Assert.True(ContactCodec.CompareRendezvousCandidates((smaller, score), (larger, score)) < 0);
        Assert.Equal(0, ContactCodec.CompareRendezvousCandidates((smaller, score), (smaller.ToArray(), score.ToArray())));
        // Score has priority even when node ordering goes the other way.
        var lowerScore = score.ToArray(); lowerScore[^1]--;
        Assert.True(ContactCodec.CompareRendezvousCandidates((larger, lowerScore), (smaller, score)) < 0);
        var ranked = new List<(byte[] NodeId, byte[] Score)> { (larger, score), (smaller, score) };
        ranked.Sort(ContactCodec.CompareRendezvousCandidates);
        Assert.Equal(smaller, ranked[0].NodeId);
        Assert.Equal(larger, ranked[1].NodeId);
    }

    private static ContactRecord Flip(ContactRecord original, int tag, int byteIndex)
    {
        var exact = original.CanonicalBytes.ToArray();
        exact[FieldOffset(exact, tag) + byteIndex] ^= 1;
        return ContactCodec.Decode(original.Magic, exact);
    }

    private static int FieldOffset(ReadOnlySpan<byte> record, int sought)
    {
        var offset = 12;
        for (var index = 0; index < BinaryPrimitives.ReadUInt16BigEndian(record[8..]); index++)
        {
            var tag = BinaryPrimitives.ReadUInt16BigEndian(record[offset..]);
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(record[(offset + 4)..]));
            offset += 8;
            if (tag == sought) return offset;
            offset = checked(offset + length);
        }
        throw new InvalidDataException("Missing canonical field in test input.");
    }
}
