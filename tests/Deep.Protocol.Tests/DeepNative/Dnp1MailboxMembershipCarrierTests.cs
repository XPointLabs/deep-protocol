using System.Buffers.Binary;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class MailboxMembershipCarrierTests
{
    [Fact]
    public void ExactMailboxMip1WithRip2_PreflightsAndOwns()
    {
        var inner = Rip2();
        var outer = MailboxPeerReplicationCodec.EncodeMembershipProof(new MailboxReplicaMembershipProof
        {
            ReplicaId = Bytes(1),
            SigningPublicKey = Bytes(2),
            Epoch = 1,
            MembershipCommitment = Bytes(3),
            CanonicalInclusionProof = inner
        });

        var decoded = MailboxMembershipCarrier.DecodeOwned(outer);
        outer[120] ^= 0xff;
        Assert.Equal("RIP2", System.Text.Encoding.ASCII.GetString(
            decoded.CanonicalInclusionProof.Span[..4]));
    }

    [Theory]
    [InlineData("RIP1")]
    [InlineData("MRL1")]
    public void LegacyInnerMagic_RejectsBeforeOwnership(string magic)
    {
        var inner = new byte[573];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(inner, 0);
        var outer = MailboxPeerReplicationCodec.EncodeMembershipProof(new MailboxReplicaMembershipProof
        {
            ReplicaId = Bytes(1), SigningPublicKey = Bytes(2), Epoch = 1,
            MembershipCommitment = Bytes(3), CanonicalInclusionProof = inner
        });
        Assert.Throws<RecordException>(() => MailboxMembershipCarrier.DecodeOwned(outer));
    }

    [Fact]
    public void P04MembershipContractMip1_IsNotTheMailboxCarrier()
    {
        var p04 = new byte[FixedP04Length + 20 * 32];
        "MIP1"u8.CopyTo(p04); p04[4] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(p04.AsSpan(68, 2), 20);
        Assert.Throws<RecordException>(() => MailboxMembershipCarrier.Preflight(p04));
    }

    private const int FixedP04Length = 72;

    private static byte[] Rip2()
    {
        var f = RecordDefinitions.Rip2.Fields
            .Select(static x => (ReadOnlyMemory<byte>)new byte[x.MinimumLength]).ToArray();
        var mrl = RecordDefinitions.Mrl2.Fields
            .Select(static x => (ReadOnlyMemory<byte>)new byte[x.MinimumLength]).ToArray();
        mrl[2]=U64(1);mrl[4]=Ref(ArtifactType.Dnr1,756,1);
        mrl[5]=U64(1);mrl[6]=U64(1);mrl[8]=Ref(ArtifactType.Dpc1,430,2);
        f[4] = U16(2); f[5]=U64(1);f[6] = U32(1); f[7] = U32(1); f[10] = U32(326);
        f[11]=CanonicalGrammar.Encode(RecordDefinitions.Mrl2,mrl);
        return CanonicalGrammar.Encode(RecordDefinitions.Rip2, f);
    }

    private static byte[] Bytes(byte value) => Enumerable.Repeat(value, 32).ToArray();
    private static byte[] U16(ushort value) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); return b; }
    private static byte[] U32(uint value) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, value); return b; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
    private static byte[] Ref(ArtifactType type,uint length,byte marker) =>
        CanonicalGrammar.EncodeReference(new ArtifactReference(
            type,length,Enumerable.Repeat(marker,32).Select(static value=>(byte)value).ToArray()));
}
