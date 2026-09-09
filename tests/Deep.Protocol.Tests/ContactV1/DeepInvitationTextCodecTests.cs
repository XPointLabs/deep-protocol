using System.Buffers.Binary;
using System.Text;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class DeepInvitationTextCodecTests
{
    [Fact]
    public void ExactDia1RoundTripsThroughCanonicalUnpaddedBase64Url()
    {
        var invitation = ContactCodec.Decode("DIA1", Dia1());

        var text = DeepInvitationTextCodec.EncodeCanonical(invitation);
        var decoded = DeepInvitationTextCodec.DecodeCanonical(text);

        Assert.Equal(DeepInvitationTextCodec.ExactTextLength, text.Length);
        Assert.StartsWith("deepinvite:", text, StringComparison.Ordinal);
        Assert.DoesNotContain('=', text);
        Assert.Equal(invitation.CanonicalBytes.ToArray(), decoded.CanonicalBytes.ToArray());
    }

    [Theory]
    [InlineData("")]
    [InlineData("deepinvite:")]
    [InlineData("DEEPINVITE:")]
    [InlineData(" deepinvite:")]
    [InlineData("deepinvite: ")]
    public void NonCanonicalEnvelopeIsRejected(string text)
    {
        var error = Assert.Throws<ContactFormatException>(() =>
            DeepInvitationTextCodec.DecodeCanonical(text));
        Assert.Equal("InvitationTextNonCanonical", error.Code);
    }

    [Fact]
    public void PaddingAndStandardBase64AlphabetAreRejected()
    {
        var canonical = DeepInvitationTextCodec.EncodeCanonical(
            ContactCodec.Decode("DIA1", Dia1()));

        Assert.Throws<ContactFormatException>(() =>
            DeepInvitationTextCodec.DecodeCanonical(canonical[..^1] + "="));
        Assert.Throws<ContactFormatException>(() =>
            DeepInvitationTextCodec.DecodeCanonical(canonical[..^1] + "+"));
        Assert.Throws<ContactFormatException>(() =>
            DeepInvitationTextCodec.DecodeCanonical(canonical + "\r\n"));
    }

    [Fact]
    public void ExactLengthNonDiaRecordIsRejected()
    {
        var bytes = Dia1();
        Encoding.ASCII.GetBytes("DCR1").CopyTo(bytes, 0);
        var payload = Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_');

        Assert.Throws<ContactFormatException>(() =>
            DeepInvitationTextCodec.DecodeCanonical("deepinvite:" + payload));
    }

    private static byte[] Dia1()
    {
        ReadOnlyMemory<byte>[] fields =
        [
            Bytes(16, 0x11),
            Bytes(32, 0x22),
            new byte[] { 2 },
            U16(1),
            Bytes(16, 0x33),
            Bytes(32, 0x44),
            Bytes(32, 0x55),
            U64(2_000_000_000),
            U16(1),
        ];
        var output = new byte[12 + fields.Sum(static field => 8 + field.Length)];
        Encoding.ASCII.GetBytes("DIA1").CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Length));
        var offset = 12;
        for (var index = 0; index < fields.Length; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4), checked((uint)fields[index].Length));
            fields[index].Span.CopyTo(output.AsSpan(offset + 8));
            offset += 8 + fields[index].Length;
        }
        Assert.Equal(DeepInvitationTextCodec.ExactRecordSize, output.Length);
        return output;
    }

    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] U16(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
}
