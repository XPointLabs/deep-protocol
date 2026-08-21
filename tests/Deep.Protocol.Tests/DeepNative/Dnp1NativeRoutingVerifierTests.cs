using System.Buffers.Binary;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class NativeRoutingVerifierTests
{
    [Fact]
    public void AnchorAndSuccessor_VerifyExactMrlBindingAndDefensiveOwnership()
    {
        var keys = PublicKeyAuth.GenerateKeyPair();
        var network = Bytes(1, 16);
        var router = Bytes(2, 32);
        var dnr = Ref(ArtifactType.Dnr1, 756, 3);
        var anchor = Contact(network, router, dnr, 4, new byte[38], keys, 10, 50);
        var anchorRef = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Dpc1, anchor));
        var mrl = Mrl2(network, router, dnr, anchorRef);
        var membership = new VerifiedMrl2Membership(
            new byte[693], mrl, router, keys.PublicKey,
            NativeMembershipVerifier.RealLeaf(new byte[32], 7, 9, 0, mrl),
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Mrl2, mrl)), 7, 9,
            RouterRoles.MailboxReplica,
            RouterCapabilities.NativePeerMailboxV2);
        var verifier = new NativeRoutingVerifier();

        var verifiedAnchor = verifier.VerifyAnchorContact(membership, anchor, 20);
        var successor = Contact(network, router, dnr, 5,
            verifiedAnchor.ArtifactReference.ToArray(), keys, 20, 60);
        var verifiedSuccessor = verifier.VerifyContactSuccessor(
            membership, verifiedAnchor, successor, 30);
        successor.AsSpan().Fill(0xff);

        Assert.Equal(5UL, verifiedSuccessor.Generation);
        Assert.Equal(router, verifiedSuccessor.RouterId.ToArray());
        Assert.Equal(EndpointKind.Ipv4, verifiedSuccessor.EndpointKind);
    }

    [Fact]
    public void SuccessorPredecessorOrWindowMix_RejectsBeforeSignatureUse()
    {
        var keys = PublicKeyAuth.GenerateKeyPair();
        var network = Bytes(1, 16);
        var router = Bytes(2, 32);
        var dnr = Ref(ArtifactType.Dnr1, 756, 3);
        var anchor = Contact(network, router, dnr, 4, new byte[38], keys, 10, 50);
        var anchorRef = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Dpc1, anchor));
        var mrl = Mrl2(network, router, dnr, anchorRef);
        var membership = new VerifiedMrl2Membership(
            new byte[693], mrl, router, keys.PublicKey,
            NativeMembershipVerifier.RealLeaf(new byte[32], 7, 9, 0, mrl),
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Mrl2, mrl)), 7, 9,
            RouterRoles.MailboxReplica,
            RouterCapabilities.NativePeerMailboxV2);
        var verifier = new NativeRoutingVerifier();
        var current = verifier.VerifyAnchorContact(membership, anchor, 20);
        var wrong = Contact(network, router, dnr, 5,
            Ref(ArtifactType.Dpc1, 431, 99), keys, 20, 60);

        Assert.Throws<RecordException>(() =>
            verifier.VerifyContactSuccessor(membership, current, wrong, 30));
        Assert.Throws<RecordException>(() =>
            verifier.VerifyAnchorContact(membership, anchor, 50));
    }

    private static byte[] Mrl2(byte[] network, byte[] router, byte[] dnr, byte[] anchor)
    {
        var f = RecordDefinitions.Mrl2.Fields
            .Select(static x => (ReadOnlyMemory<byte>)new byte[x.MinimumLength]).ToArray();
        f[0] = network; f[1] = U64(7); f[2] = U64(9); f[3] = router; f[4] = dnr;
        f[5] = U64((ulong)RouterRoles.MailboxReplica);
        f[6] = U64((ulong)RouterCapabilities.NativePeerMailboxV2);
        f[7] = U64(4); f[8] = anchor; f[9] = U64(10); f[10] = U64(100); f[11] = new byte[38];
        return CanonicalGrammar.Encode(RecordDefinitions.Mrl2, f);
    }

    private static byte[] Contact(
        byte[] network,
        byte[] router,
        byte[] dnr,
        ulong generation,
        byte[] predecessor,
        KeyPair keys,
        ulong issuedAt,
        ulong expiresAt)
    {
        var f = RecordDefinitions.Dpc1.Fields
            .Select(static x => (ReadOnlyMemory<byte>)new byte[x.MinimumLength]).ToArray();
        f[0] = network; f[1] = router; f[2] = dnr; f[3] = U64(generation); f[4] = predecessor;
        f[5] = U64(issuedAt); f[6] = U64(expiresAt);
        f[7] = U64((ulong)RouterCapabilities.NativePeerMailboxV2);
        f[8] = new byte[] { (byte)EndpointKind.Ipv4 }; f[9] = new byte[4]; f[10] = U16(443);
        f[11] = Bytes(8, 32); f[12] = new byte[32]; f[13] = U64(1); f[14] = new byte[64];
        var unsigned = CanonicalGrammar.Encode(RecordDefinitions.Dpc1, f);
        var record = CanonicalGrammar.DecodeOwned(unsigned, RecordDefinitions.Dpc1);
        f[14] = PublicKeyAuth.SignDetached(
            CanonicalGrammar.GetSigningBytes(record, "Deep/NativeRouting/V1/contact"),
            keys.PrivateKey);
        return CanonicalGrammar.Encode(RecordDefinitions.Dpc1, f);
    }

    private static byte[] Ref(ArtifactType type, uint length, byte marker)
    {
        var value = new byte[38];
        BinaryPrimitives.WriteUInt16BigEndian(value, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(2), length);
        value[6] = marker;
        return value;
    }

    private static byte[] Bytes(byte value, int length) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] U16(ushort value) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); return b; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
}
