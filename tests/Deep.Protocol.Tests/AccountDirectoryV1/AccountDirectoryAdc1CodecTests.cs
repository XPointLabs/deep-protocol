using System.Buffers.Binary;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryAdc1CodecTests
{
    [Fact]
    public void EncodeDecode_RoundTripsAndKeepsDefensiveCopies()
    {
        var input = Fixture();
        var encoded = AccountDirectoryAdc1Codec.Encode(input);
        var decoded = AccountDirectoryAdc1Codec.Decode(encoded);

        Assert.Equal(input.AccountGeneration, decoded.AccountGeneration);
        Assert.Equal(input.CheckpointGeneration, decoded.CheckpointGeneration);
        Assert.Equal(input.IssuedAt, decoded.IssuedAt);
        Assert.Equal(input.MinimumReader, decoded.MinimumReader);
        Assert.Equal(input.NetworkId.ToArray(), decoded.NetworkId.ToArray());
        Assert.Equal(input.ExactDpa1Reference.ToArray(), decoded.ExactDpa1Reference.ToArray());
        Assert.Equal(input.DeviceIssuerSignature.ToArray(), decoded.DeviceIssuerSignature.ToArray());

        var propertyCopy = decoded.NetworkId.ToArray();
        propertyCopy[0] ^= 0xff;
        encoded[12 + 8] ^= 0xff;
        Assert.NotEqual(propertyCopy, decoded.NetworkId.ToArray());
        Assert.NotEqual(encoded[20], decoded.NetworkId.Span[0]);
    }

    [Fact]
    public void EncodeUnsigned_UsesCanonicalProjectionWithoutSignatureField()
    {
        var unsigned = AccountDirectoryAdc1Codec.EncodeUnsigned(Fixture());

        Assert.Equal(12, BinaryPrimitives.ReadUInt16BigEndian(unsigned.AsSpan(8)));
        Assert.Equal(386, unsigned.Length);
        Assert.Equal((ushort)0, BinaryPrimitives.ReadUInt16BigEndian(unsigned.AsSpan(10)));
        Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(unsigned.AsSpan(12)));

        var offset = 12;
        for (var tag = 1; tag <= 12; tag++)
        {
            Assert.Equal((ushort)tag, BinaryPrimitives.ReadUInt16BigEndian(unsigned.AsSpan(offset)));
            offset += 8 + BinaryPrimitives.ReadInt32BigEndian(unsigned.AsSpan(offset + 4));
        }
        Assert.Equal(unsigned.Length, offset);
    }

    [Fact]
    public void PublicAuthoringApi_CreatesExactSigningInputWithoutPlaceholderSignature()
    {
        var fixture = Fixture();
        var signingInput = AccountDirectoryAdc1Codec.CreateDeviceIssuerSigningInput(
            fixture.NetworkId.Span, fixture.DirectoryLeafKey.Span,
            fixture.AccountGeneration, fixture.CheckpointGeneration,
            fixture.PredecessorCheckpointHash.Span, fixture.ExactDpa1Reference.Span,
            fixture.ExactDrs1Reference.Span, fixture.ExactDmd1Hash.Span,
            fixture.ExactDab1Hash.Span, fixture.RevokedDcaAuthorizationIdsHash.Span,
            fixture.IssuedAt, fixture.MinimumReader);

        Assert.Equal(AccountDirectoryCrypto.ComputeAdc1SigningInput(fixture), signingInput);
        Assert.True(signingInput.AsSpan().EndsWith(AccountDirectoryAdc1Codec.EncodeUnsigned(fixture)));
    }

    [Fact]
    public void Decode_RejectsEnvelopeAndFieldViolations()
    {
        var encoded = AccountDirectoryAdc1Codec.Encode(Fixture());
        var mutations = new Action<byte[]>[]
        {
            bytes => bytes[0] = (byte)'X',
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 2),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0202),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), 12),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(10), 1),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(12), 2),
            bytes => BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(14), 1),
            bytes => BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(16), 15),
            bytes => { }
        };

        foreach (var mutate in mutations)
        {
            var candidate = encoded.ToArray();
            mutate(candidate);
            if (mutations[^1] == mutate)
                candidate = candidate[..^1];
            Assert.Throws<AccountDirectoryAdc1FormatException>(() => AccountDirectoryAdc1Codec.Decode(candidate));
        }

        var extra = encoded.Concat(new byte[] { 0 }).ToArray();
        Assert.Throws<AccountDirectoryAdc1FormatException>(() => AccountDirectoryAdc1Codec.Decode(extra));
    }

    [Fact]
    public void Decode_RejectsEveryWrongFieldLength()
    {
        var encoded = AccountDirectoryAdc1Codec.Encode(Fixture());
        var lengths = new[] { 16, 32, 8, 8, 32, 38, 38, 32, 32, 32, 8, 2, 64 };
        var offset = 12;
        for (var index = 0; index < lengths.Length; index++)
        {
            var candidate = encoded.ToArray();
            BinaryPrimitives.WriteUInt32BigEndian(candidate.AsSpan(offset + 4), checked((uint)(lengths[index] + 1)));
            Assert.Throws<AccountDirectoryAdc1FormatException>(() => AccountDirectoryAdc1Codec.Decode(candidate));
            offset += 8 + lengths[index];
        }
    }

    [Fact]
    public void Constructor_RejectsWrongComponentLengths()
    {
        var values = Enumerable.Repeat<byte[]>(new byte[16], 1).ToArray();
        Assert.Throws<ArgumentException>(() => new AccountDirectoryAdc1(
            values[0], new byte[32], 1, 1, new byte[32], new byte[37], new byte[38],
            new byte[32], new byte[32], new byte[32], 1, 1, new byte[64]));
    }

    [Fact]
    public void ConstructorAndDecode_RejectWrongTypedReferences()
    {
        Assert.Throws<ArgumentException>(() => new AccountDirectoryAdc1(
            Bytes(16, 1), Bytes(32, 2), 1, 1, Bytes(32, 3), Bytes(38, 4), Reference("DRS1", 5),
            Bytes(32, 6), Bytes(32, 7), Bytes(32, 8), 1, 1, Bytes(64, 9)));

        var encoded = AccountDirectoryAdc1Codec.Encode(Fixture());
        encoded[156] = (byte)'X';
        Assert.Throws<AccountDirectoryAdc1FormatException>(() => AccountDirectoryAdc1Codec.Decode(encoded));
    }

    [Fact]
    public void Decode_RejectsZeroRequiredValuesAndInvalidPredecessorRule()
    {
        var encoded = AccountDirectoryAdc1Codec.Encode(Fixture());
        var mutations = new Action<byte[]>[]
        {
            bytes => Array.Clear(bytes, 20, 16),
            bytes => BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(84), 0),
            bytes => { BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(100), 0); bytes[116] = 1; },
            bytes => { BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(100), 1); Array.Clear(bytes, 116, 32); },
            bytes => Array.Clear(bytes, 394, 64)
        };

        foreach (var mutate in mutations)
        {
            var candidate = encoded.ToArray();
            mutate(candidate);
            Assert.Throws<AccountDirectoryAdc1FormatException>(() => AccountDirectoryAdc1Codec.Decode(candidate));
        }
    }

    private static AccountDirectoryAdc1 Fixture() => new(
        Bytes(16, 0x10), Bytes(32, 0x20), 7, 9, Bytes(32, 0x30), Reference("DPA1", 0x40),
        Reference("DRS1", 0x50), Bytes(32, 0x60), Bytes(32, 0x70), Bytes(32, 0x80),
        1_700_000_123, 0x0201, Bytes(64, 0x90));

    private static byte[] Reference(string magic, byte first)
    {
        var value = Bytes(38, first);
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        return value;
    }

    private static byte[] Bytes(int length, byte first)
    {
        var value = new byte[length];
        for (var index = 0; index < value.Length; index++)
            value[index] = unchecked((byte)(first + index));
        return value;
    }
}
