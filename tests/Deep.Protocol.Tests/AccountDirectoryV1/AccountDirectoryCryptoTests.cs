using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryCryptoTests
{
    [Fact]
    public void Framing_IsExactAndDomainSeparated()
    {
        var payload = new byte[] { 1, 2, 3 };
        var label = Encoding.ASCII.GetBytes("domain");
        var hashPreimage = new byte[label.Length + 1 + 4 + payload.Length];
        label.CopyTo(hashPreimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(hashPreimage.AsSpan(label.Length + 1), 3);
        payload.CopyTo(hashPreimage, label.Length + 5);
        Assert.Equal(SHA256.HashData(hashPreimage), AccountDirectoryCrypto.Sha256Domain("domain", payload));

        var signatureInput = AccountDirectoryCrypto.SignatureInput("domain", 0x0201, payload);
        Assert.Equal("646f6d61696e00020100000003010203", Convert.ToHexStringLower(signatureInput));
        Assert.NotEqual(
            AccountDirectoryCrypto.Sha256Domain("domain", payload),
            AccountDirectoryCrypto.Sha256Domain("domain-2", payload));
    }

    [Fact]
    public void AdcArtifactAndAdhCore_UseTheirNormativeProjections()
    {
        var adc = new AccountDirectoryAdc1(
            Bytes(16, 1), Bytes(32, 2), 1, 0, new byte[32], Reference("DPA1", 3),
            Reference("DRS1", 4), Bytes(32, 5), Bytes(32, 6), Bytes(32, 7), 10, 1, Bytes(64, 8));
        Assert.Equal(
            SHA256.HashData(AccountDirectoryAdc1Codec.Encode(adc)),
            AccountDirectoryCrypto.ComputeAdc1ArtifactHash(adc));
        var adcProjection = AccountDirectoryAdc1Codec.EncodeUnsigned(adc);
        Assert.True(AccountDirectoryCrypto.ComputeAdc1SigningInput(adc).AsSpan().EndsWith(adcProjection));

        var adh = new AccountDirectoryAdh1(
            Bytes(16, 1), 0, new byte[32], 0, Bytes(32, 2), Bytes(32, 3), Reference("XNA1", 4),
            Bytes(32, 5), 10, 20, 1,
            [new AccountDirectoryAdh1WitnessEntry(Bytes(32, 6), Bytes(64, 7))]);
        Assert.Equal(
            AccountDirectoryCrypto.Sha256Domain(
                AccountDirectoryCrypto.Adh1CoreDomain,
                AccountDirectoryAdh1Codec.EncodeUnsigned(adh)),
            AccountDirectoryCrypto.ComputeAdh1CoreHash(adh));
        var adhProjection = AccountDirectoryAdh1Codec.EncodeUnsigned(adh);
        Assert.True(AccountDirectoryCrypto.ComputeAdh1SigningInput(adh).AsSpan().EndsWith(adhProjection));
    }

    [Fact]
    public void Reference_RejectsWrongShapeAndZeroHash()
    {
        var reference = AccountDirectoryCrypto.CreateReference("ADH1"u8, 1, Bytes(32, 1));
        Assert.Equal(38, reference.Length);
        Assert.Equal("ADH1"u8.ToArray(), reference[..4]);
        Assert.Equal((ushort)1, BinaryPrimitives.ReadUInt16BigEndian(reference.AsSpan(4)));
        Assert.Throws<ArgumentException>(() => AccountDirectoryCrypto.CreateReference("ADH"u8, 1, Bytes(32, 1)));
        Assert.Throws<ArgumentException>(() => AccountDirectoryCrypto.CreateReference("ADH1"u8, 1, new byte[32]));
    }

    [Fact]
    public void TrustedTimeHashesAndSignatureInputs_UseUnsignedCanonicalBytes()
    {
        var receipts = new[]
        {
            new AccountDirectoryDts1RootReceipt(Bytes(32, 0x10), Bytes(64, 0x20))
        };
        var dts = new AccountDirectoryDts1(Bytes(16, 1), 0, new byte[32],
            [
                new AccountDirectoryDts1Source(Bytes(32, 1), Bytes(32, 3), 1, "a.example", 123, Bytes(32, 5), 5),
                new AccountDirectoryDts1Source(Bytes(32, 2), Bytes(32, 4), 1, "b.example", 123, Bytes(32, 6), 5)
            ], 2, 2, 30, 10, 1, 2, 1, 1, receipts);
        var dtsUnsigned = AccountDirectoryDts1Codec.EncodeUnsigned(dts);
        Assert.Equal(AccountDirectoryCrypto.Sha256Domain(AccountDirectoryCrypto.Dts1PolicyDomain, dtsUnsigned),
            AccountDirectoryCrypto.ComputeDts1PolicyHash(dts));
        Assert.True(AccountDirectoryCrypto.ComputeDts1SigningInput(dts).AsSpan().EndsWith(dtsUnsigned));

        var dtt = new AccountDirectoryDtt1(Bytes(16, 1), Bytes(32, 2), 100, 5, Bytes(32, 3), 0,
            Bytes(32, 4), 0, Reference("XNA1", 5), Bytes(32, 6), 103, 104,
            Bytes(32, 9),
            [new AccountDirectoryDtt1WitnessReceipt(Bytes(32, 7), Bytes(64, 8))]);
        var dttUnsigned = AccountDirectoryDtt1Codec.EncodeUnsigned(dtt);
        Assert.Equal(AccountDirectoryCrypto.Sha256Domain(AccountDirectoryCrypto.Dtt1CoreDomain, dttUnsigned),
            AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt));
        Assert.True(AccountDirectoryCrypto.ComputeDtt1SigningInput(dtt).AsSpan().EndsWith(dttUnsigned));
    }

    private static byte[] Reference(string magic, byte first)
    {
        var value = Bytes(38, first);
        Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
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
