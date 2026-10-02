using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.Tests.ContactV1;
using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;

namespace Deep.Protocol.Tests.ContactV2;

public sealed class DeepIdV2ContactMailboxRouteTests
{
    [Theory]
    [InlineData(false, 5235)]
    [InlineData(true, 24387)]
    public void PrivateRoute_ExactBoundsAndDefensiveUntrustedData(bool maximum, int expected)
    {
        var exact = Package(maximum);
        var original = exact.ToArray();
        var parsed = DeepIdV2ContactMailboxRouteCodec.Decode(exact);
        Assert.Equal(expected, exact.Length);
        Assert.Equal(original, parsed.ExactBytes.ToArray());
        Assert.Empty(typeof(ParsedDeepIdV2ContactMailboxRoute).GetConstructors());
        Assert.Empty(typeof(VerifiedDeepIdV2ContactMailboxRoute).GetConstructors());
        Assert.All(typeof(ParsedDeepIdV2ContactMailboxRoute).GetProperties(), property => Assert.False(property.CanWrite));
        Assert.All(typeof(VerifiedDeepIdV2ContactMailboxRoute).GetProperties(), property => Assert.False(property.CanWrite));
        exact[^1] ^= 1;
        var returned = parsed.ExactBytes.ToArray(); returned[0] ^= 1;
        Assert.Equal(original, parsed.ExactBytes.ToArray());
        Assert.Equal(parsed.Authorization.NetworkId.ToArray(), parsed.Invite.Field(1).ToArray());
        Assert.Equal(parsed.Authorization.NetworkId.ToArray(), parsed.Route.Reachability.Field(1).ToArray());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    public void PrivateRoute_HostileFramingRejectsBeforeInnerRecords(int fault)
    {
        var exact = Package(false);
        if (fault == 0) exact[1] = 1;
        if (fault == 1) exact[2] = 1;
        if (fault == 2) exact[3] = 1;
        if (fault == 3) BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(1088), uint.MaxValue);
        if (fault == 4) exact = exact[..^1];
        if (fault == 5) exact = exact.Append((byte)0).ToArray();
        if (fault == 6) exact = new byte[DeepIdV2ContactMailboxRouteCodec.MaximumBytes + 1];
        Assert.Throws<CryptographicException>(() => DeepIdV2ContactMailboxRouteCodec.Decode(exact));
    }

    [Theory]
    [InlineData(4)]
    [InlineData(477)]
    public void PrivateRoute_RetiredInnerVersionHasNoReader(int offset)
    {
        var exact = Package(false); exact[offset + 5] = 1;
        Assert.Throws<ApplicationCoreFormatException>(() => DeepIdV2ContactMailboxRouteCodec.Decode(exact));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void PrivateRoute_MixedDelegationInviteAndNetworkReject(int fault)
    {
        var exact = Package(false);
        // Canonical inner records stay structurally parseable; their shared
        // references/network must still reject before verification or use.
        if (fault == 0) exact[4 + 20] ^= 1; // DCA network value.
        if (fault == 1) exact[4 + 473 - 1] ^= 1; // DCA hash changes.
        if (fault == 2) exact[477 + 611 - 1] ^= 1; // XIR XRA hash changes.
        Assert.Throws<CryptographicException>(() => DeepIdV2ContactMailboxRouteCodec.Decode(exact));
    }

    [Fact]
    public void PrivateRoute_LocatorUsesExistingPublicCredentialDomainWithoutReadSecret()
    {
        var capability = B(16, 0x31);
        var did = DeepIdV2Codec.AuthorDid2(B(32, 0x21), B(1952, 0x22), capability);
        using var original = DeepIdV2PermanentContactResolutionDerivation.Derive(B(16, 0x11), did, capability);
        Assert.Equal(original.LocatorHash.ToArray(), DeepIdV2PermanentContactResolutionDerivation.ComputeLocator(B(16, 0x11), did.RecordHash.Span));
        Assert.NotEqual(original.LocatorHash.ToArray(), DeepIdV2PermanentContactResolutionDerivation.ComputeLocator(B(16, 0x12), did.RecordHash.Span));
        Assert.Throws<ArgumentException>(() => DeepIdV2PermanentContactResolutionDerivation.ComputeLocator(new byte[16], did.RecordHash.Span));
        Assert.Throws<ArgumentException>(() => DeepIdV2PermanentContactResolutionDerivation.ComputeLocator(B(16, 0x11), new byte[32]));
    }

    // Deliberately synthetic *parsed* records only; no verified route/grant,
    // authenticated-origin or publication claim is made by these codec vectors.
    internal static byte[] Package(bool maximum, VerifiedDeepIdV2DirectoryFreshness? endpoint = null)
    {
        var current = endpoint?.CurrentCheckpoint;
        var device = current?.Directory.Identity.ActiveDevices.Single().Certificate;
        var records = endpoint is null
            ? maximum ? ContactCodecTests.Records.MaximumRouteClosure : ContactCodecTests.Records.RouteClosure
            : ContactCodecTests.Records.CreateRouteClosure(maximum, endpoint.NetworkId, device!.DeviceId,
                new ContactArtifactReference(ProtocolMagic.DPD1, 1, device.CanonicalHash.Span).CanonicalBytes);
        var closure = ContactRouteClosureCodec.EncodeRecords([records.Xrr, records.Xra, records.Xrc, records.Xss, records.Pmt, records.Pms]);
        var dca = DeepIdV2ContactAuthorizationCodec.Author(records.Xra.Field(1).Span,
            current is null ? B(32, 0x61) : current.Binding.Record.DeepAccountId.Span,
            new(1, 644, B(32, 0x62)), current?.Directory.Record.DirectoryGeneration ?? 1,
            current is null ? B(32, 0x63) : current.Directory.Record.RecordHash.Span,
            B(32, 0x64), records.Xra.Field(14).Span, 1, 0, 1, 2, B(64, 0x65),
            current is null ? B(32, 0x66) : current.Binding.DeepId.RecordHash.Span,
            new(DeepIdV2Codec.Dab2ArtifactType, DeepIdV2Codec.Dab2Length,
                current is null ? B(32, 0x67) : current.Binding.Record.RecordHash.Span));
        byte[][] xirFields = [records.Xra.Field(1).ToArray(), B(32, 0x68), new byte[8], new byte[32],
            records.Xra.Field(5).ToArray(), records.Xra.Field(6).ToArray(), records.Xra.Field(10).ToArray(),
            records.Xra.Field(11).ToArray(), [1], new byte[4], [0, 1], records.Xra.Field(9).ToArray(),
            records.Xra.Field(12).ToArray(), records.Xra.Field(13).ToArray(), records.Xra.Field(15).ToArray(),
            new ContactArtifactReference(ProtocolMagic.DCA1, 2, dca.RecordHash.Span).CanonicalBytes.ToArray(), B(64, 0x69),
            ContactCodec.ArtifactReference(ProtocolMagic.XRA1, records.Xra).CanonicalBytes.ToArray()];
        var xir = DeepIdV2ContactPublicationCodecTests.Build(ProtocolMagic.XIR1,
            Enumerable.Range(1, 18).Select(value => (ushort)value).ToArray(), xirFields);
        var exact = new byte[1092 + closure.Length]; BinaryPrimitives.WriteUInt16BigEndian(exact, 2);
        dca.CanonicalBytes.Span.CopyTo(exact.AsSpan(4)); xir.CopyTo(exact, 477);
        BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(1088), (uint)closure.Length); closure.CopyTo(exact, 1092);
        return exact;
    }
    private static byte[] B(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
}
