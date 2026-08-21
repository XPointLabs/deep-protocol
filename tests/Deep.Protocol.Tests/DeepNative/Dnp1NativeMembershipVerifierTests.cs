using System.Buffers.Binary;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class NativeMembershipVerifierTests
{
    [Fact]
    public void Mrl2Projection_ZerosOnlyDnrAndAnchorReferences()
    {
        var full = Mrl2(Bytes16(1), Bytes(3), Ref(ArtifactType.Dnr1, 756, 5));
        var projected = new byte[Mrl2Projection.Length];

        Mrl2Projection.WriteFromFull(full, projected);

        var dnr = FieldValueRange(full, 5);
        var dpc = FieldValueRange(full, 9);
        for (var index = 0; index < full.Length; index++)
        {
            var projectedReferenceByte =
                index >= dnr.Offset && index < dnr.Offset + dnr.Length ||
                index >= dpc.Offset && index < dpc.Offset + dpc.Length;
            Assert.Equal(projectedReferenceByte ? (byte)0 : full[index], projected[index]);
        }
    }

    [Fact]
    public void Mrl2Leaf_UsesProjectionButRetainsEveryOtherFullRowByte()
    {
        var reset = Bytes(2);
        var first = Mrl2(Bytes16(1), Bytes(3), Ref(ArtifactType.Dnr1, 756, 5));
        var changedReferences = first.ToArray();
        changedReferences[FieldValueRange(changedReferences, 5).Offset + 6] ^= 0x5a;
        changedReferences[FieldValueRange(changedReferences, 9).Offset + 6] ^= 0xa5;
        var changedRouter = first.ToArray();
        changedRouter[FieldValueRange(changedRouter, 4).Offset] ^= 1;

        var firstLeaf = NativeMembershipVerifier.RealLeaf(reset, 7, 9, 0, first);

        Assert.Equal(firstLeaf,
            NativeMembershipVerifier.RealLeaf(reset, 7, 9, 0, changedReferences));
        Assert.NotEqual(firstLeaf,
            NativeMembershipVerifier.RealLeaf(reset, 7, 9, 0, changedRouter));
        Assert.NotEqual(firstLeaf,
            NativeMembershipVerifier.RealLeaf(Bytes(7), 7, 9, 0, first));
        Assert.NotEqual(firstLeaf,
            NativeMembershipVerifier.RealLeaf(reset, 8, 9, 0, first));
        Assert.NotEqual(firstLeaf,
            NativeMembershipVerifier.RealLeaf(reset, 7, 10, 0, first));
        Assert.NotEqual(firstLeaf,
            NativeMembershipVerifier.RealLeaf(reset, 7, 9, 1, first));
    }

    [Fact]
    public void FullMrl2LeafFormula_DiffersFromRequiredProjection()
    {
        var reset = Bytes(2);
        var full = Mrl2(Bytes16(1), Bytes(3), Ref(ArtifactType.Dnr1, 756, 5));
        var required = NativeMembershipVerifier.RealLeaf(reset, 7, 9, 0, full);
        var payload = new byte[57 + full.Length];
        payload[0] = 0;
        reset.CopyTo(payload, 1);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(33, 8), 7);
        BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(41, 8), 9);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(49, 4), 0);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(53, 4), checked((uint)full.Length));
        full.CopyTo(payload, 57);

        var downgraded = CanonicalGrammar.Sha256Domain(
            "Deep/NativeRouting/V2/mrl-leaf", payload);

        Assert.NotEqual(required, downgraded);
    }

    [Fact]
    public void Mrl2Projection_RejectsPartialOrMalformedFullRows()
    {
        var full = Mrl2(Bytes16(1), Bytes(3), Ref(ArtifactType.Dnr1, 756, 5));
        var oneZeroReference = full.ToArray();
        oneZeroReference.AsSpan(
            FieldValueRange(oneZeroReference, 5).Offset,
            ArtifactReference.Length).Clear();

        Assert.Throws<RecordException>(() =>
            Mrl2Projection.WriteFromFull(oneZeroReference, new byte[Mrl2Projection.Length]));
        Assert.Throws<RecordException>(() =>
            Mrl2Projection.WriteFromFull(full[..^1], new byte[Mrl2Projection.Length]));
        Assert.Throws<RecordException>(() =>
            Mrl2Projection.WriteFromFull(full, new byte[Mrl2Projection.Length - 1]));
    }

    [Fact]
    public void SingleMemberRip2_VerifiesAndReturnsDefensiveSealedCapability()
    {
        var network = Bytes16(1);
        var reset = Bytes(2);
        var router = Bytes(3);
        var key = Bytes(4);
        var dnr = Ref(ArtifactType.Dnr1, 756, 5);
        var mrl = Mrl2(network, router, dnr);
        var root = NativeMembershipVerifier.Root(
            reset, 7, 1, 1,
            NativeMembershipVerifier.RealLeaf(reset, 7, 9, 0, mrl));
        var lkg = new VerifiedMembershipRoutingLkg(
            network, reset, 11, 7, 100, root, Bytes(9),
            [new VerifiedRouterEntry(router, key, dnr, mrl, 9,
                RouterRoles.MailboxReplica,
                RouterCapabilities.NativePeerMailboxV2)]);
        var rip = Rip2(network, reset, root, mrl);
        var outer = MailboxPeerReplicationCodec.EncodeMembershipProof(new MailboxReplicaMembershipProof
        {
            ReplicaId = router,
            SigningPublicKey = key,
            Epoch = 7,
            MembershipCommitment = root,
            CanonicalInclusionProof = rip
        });

        var verified = NativeMembershipVerifier.VerifyMailboxMembership(outer, lkg);
        outer.AsSpan().Fill(0xff);
        mrl.AsSpan().Fill(0xee);

        Assert.Equal(router, verified.RouterId.ToArray());
        Assert.Equal(key, verified.RouterEd25519PublicKey.ToArray());
        Assert.Equal(9UL, verified.DescriptorGeneration);
        Assert.Equal(RouterRoles.MailboxReplica, verified.Roles);
        Assert.Equal(RouterCapabilities.NativePeerMailboxV2, verified.Capabilities);
        Assert.Equal("MIP1", System.Text.Encoding.ASCII.GetString(
            verified.CanonicalMailboxProof.Span[..4]));
    }

    [Fact]
    public void RootOrOuterKeyMix_Rejects()
    {
        var network = Bytes16(1);
        var reset = Bytes(2);
        var router = Bytes(3);
        var key = Bytes(4);
        var dnr = Ref(ArtifactType.Dnr1, 756, 5);
        var mrl = Mrl2(network, router, dnr);
        var root = NativeMembershipVerifier.Root(
            reset, 7, 1, 1,
            NativeMembershipVerifier.RealLeaf(reset, 7, 9, 0, mrl));
        var lkg = new VerifiedMembershipRoutingLkg(
            network, reset, 11, 7, 100, root, Bytes(9),
            [new VerifiedRouterEntry(router, key, dnr, mrl, 9,
                RouterRoles.MailboxReplica,
                RouterCapabilities.NativePeerMailboxV2)]);
        var outer = MailboxPeerReplicationCodec.EncodeMembershipProof(new MailboxReplicaMembershipProof
        {
            ReplicaId = router,
            SigningPublicKey = Bytes(99),
            Epoch = 7,
            MembershipCommitment = root,
            CanonicalInclusionProof = Rip2(network, reset, root, mrl)
        });

        Assert.Throws<RecordException>(() =>
            NativeMembershipVerifier.VerifyMailboxMembership(outer, lkg));
    }

    private static byte[] Mrl2(byte[] network, byte[] router, byte[] dnr)
    {
        var f = RecordDefinitions.Mrl2.Fields
            .Select(static x => (ReadOnlyMemory<byte>)new byte[x.MinimumLength]).ToArray();
        f[0] = network;
        f[1] = U64(7);
        f[2] = U64(9);
        f[3] = router;
        f[4] = dnr;
        f[5] = U64((ulong)RouterRoles.MailboxReplica);
        f[6] = U64((ulong)RouterCapabilities.NativePeerMailboxV2);
        f[7] = U64(1);
        f[8] = Ref(ArtifactType.Dpc1, 431, 6);
        f[9] = U64(1);
        f[10] = U64(100);
        f[11] = new byte[38];
        return CanonicalGrammar.Encode(RecordDefinitions.Mrl2, f);
    }

    private static byte[] Rip2(byte[] network, byte[] reset, byte[] root, byte[] mrl)
    {
        var f = RecordDefinitions.Rip2.Fields
            .Select(static x => (ReadOnlyMemory<byte>)new byte[x.MinimumLength]).ToArray();
        f[0] = network;
        f[1] = reset;
        f[2] = U64(11);
        f[3] = U64(7);
        f[4] = U16(2);
        f[5] = U64(9);
        f[6] = U32(1);
        f[7] = U32(1);
        f[8] = U32(0);
        f[9] = root;
        f[10] = U32(326);
        f[11] = mrl;
        f[12] = new byte[] { 0 };
        f[13] = Array.Empty<byte>();
        return CanonicalGrammar.Encode(RecordDefinitions.Rip2, f);
    }

    private static byte[] Ref(ArtifactType type, uint length, byte marker)
    {
        var value = new byte[38];
        BinaryPrimitives.WriteUInt16BigEndian(value, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(2), length);
        value[6] = marker;
        return value;
    }

    private static (int Offset, int Length) FieldValueRange(ReadOnlySpan<byte> canonical, int tag)
    {
        var offset = CanonicalGrammar.HeaderLength;
        for (var current = 1; current <= tag; current++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(offset + 4, 4)));
            offset += CanonicalGrammar.FieldHeaderLength;
            if (current == tag) return (offset, length);
            offset = checked(offset + length);
        }
        throw new InvalidOperationException();
    }

    private static byte[] Bytes(byte value) => Enumerable.Repeat(value, 32).ToArray();
    private static byte[] Bytes16(byte value) => Enumerable.Repeat(value, 16).ToArray();
    private static byte[] U16(ushort value) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); return b; }
    private static byte[] U32(uint value) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, value); return b; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
}
