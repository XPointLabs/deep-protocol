using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Protocol.AccountDirectoryV1;

internal static class AccountDirectoryCrypto
{
    internal const string Adc1SignatureDomain = "Deep/AccountDirectory/V1/ADC1/account";
    internal const string Adh1SignatureDomain = "Deep/AccountDirectory/V1/ADH1/witness";
    internal const string Adh1CoreDomain = "Deep/AccountDirectory/V1/ADH1/core";
    internal const string Dtt1SignatureDomain = "Deep/AccountDirectory/V1/DTT1/live-time";
    internal const string Dtt1CoreDomain = "Deep/AccountDirectory/V1/DTT1/core";
    internal const string Dts1SignatureDomain = "Deep/AccountDirectory/V1/DTS1/root";
    internal const string Dts1PolicyDomain = "Deep/AccountDirectory/V1/time-source-policy";
    internal const string Adf1SignatureDomain = "Deep/AccountDirectory/V1/ADF1/root";
    internal const string Adf1CoreDomain = "Deep/AccountDirectory/V1/ADF1/core";

    internal static byte[] ComputeAdc1SigningInput(AccountDirectoryAdc1 value) =>
        SignatureInput(
            Adc1SignatureDomain,
            AccountDirectoryAdc1Codec.Suite,
            AccountDirectoryAdc1Codec.EncodeUnsigned(value));

    internal static byte[] ComputeAdc1ArtifactHash(AccountDirectoryAdc1 value) =>
        SHA256.HashData(AccountDirectoryAdc1Codec.Encode(value));

    internal static byte[] ComputeAdh1SigningInput(AccountDirectoryAdh1 value) =>
        SignatureInput(
            Adh1SignatureDomain,
            AccountDirectoryAdh1Codec.Suite,
            AccountDirectoryAdh1Codec.EncodeUnsigned(value));

    internal static byte[] ComputeAdh1CoreHash(AccountDirectoryAdh1 value) =>
        Sha256Domain(Adh1CoreDomain, AccountDirectoryAdh1Codec.EncodeUnsigned(value));

    internal static byte[] ComputeDtt1SigningInput(AccountDirectoryDtt1 value)
    {
        var unsigned = AccountDirectoryDtt1Codec.EncodeUnsigned(value);
        try
        {
            return SignatureInput(Dtt1SignatureDomain, AccountDirectoryDtt1Codec.Suite, unsigned);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(unsigned);
        }
    }

    internal static byte[] ComputeDtt1CoreHash(AccountDirectoryDtt1 value) =>
        Sha256Domain(Dtt1CoreDomain, AccountDirectoryDtt1Codec.EncodeUnsigned(value));

    internal static byte[] ComputeDts1SigningInput(AccountDirectoryDts1 value) =>
        SignatureInput(Dts1SignatureDomain, AccountDirectoryDts1Codec.Suite,
            AccountDirectoryDts1Codec.EncodeUnsigned(value));

    internal static byte[] ComputeDts1PolicyHash(AccountDirectoryDts1 value) =>
        Sha256Domain(Dts1PolicyDomain, AccountDirectoryDts1Codec.EncodeUnsigned(value));

    internal static byte[] ComputeAdf1SigningInput(AccountDirectoryAdf1 value) =>
        SignatureInput(Adf1SignatureDomain, AccountDirectoryAdf1Codec.Suite,
            AccountDirectoryAdf1Codec.EncodeUnsigned(value));

    internal static byte[] ComputeAdf1CoreHash(AccountDirectoryAdf1 value) =>
        Sha256Domain(Adf1CoreDomain, AccountDirectoryAdf1Codec.EncodeUnsigned(value));

    internal static byte[] CreateReference(ReadOnlySpan<byte> magic, ushort version, ReadOnlySpan<byte> hash)
    {
        if (magic.Length != 4 || !IsPrintableAscii(magic))
            throw new ArgumentException("Reference magic must be four printable ASCII bytes.", nameof(magic));
        if (version == 0)
            throw new ArgumentOutOfRangeException(nameof(version));
        if (hash.Length != 32 || hash.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Reference hash must be exactly 32 non-zero bytes.", nameof(hash));
        var result = new byte[38];
        magic.CopyTo(result);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), version);
        hash.CopyTo(result.AsSpan(6));
        return result;
    }

    internal static byte[] Sha256Domain(string domain, ReadOnlySpan<byte> payload)
    {
        var domainBytes = StrictAscii(domain);
        var preimage = new byte[checked(domainBytes.Length + 1 + 4 + payload.Length)];
        domainBytes.CopyTo(preimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(
            preimage.AsSpan(domainBytes.Length + 1),
            checked((uint)payload.Length));
        payload.CopyTo(preimage.AsSpan(domainBytes.Length + 5));
        return SHA256.HashData(preimage);
    }

    internal static byte[] SignatureInput(
        string domain,
        ushort suite,
        ReadOnlySpan<byte> canonicalProjection)
    {
        var domainBytes = StrictAscii(domain);
        var result = new byte[checked(domainBytes.Length + 1 + 2 + 4 + canonicalProjection.Length)];
        domainBytes.CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(domainBytes.Length + 1), suite);
        BinaryPrimitives.WriteUInt32BigEndian(
            result.AsSpan(domainBytes.Length + 3),
            checked((uint)canonicalProjection.Length));
        canonicalProjection.CopyTo(result.AsSpan(domainBytes.Length + 7));
        return result;
    }

    private static byte[] StrictAscii(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Any(static character => character is < (char)0x21 or > (char)0x7e))
            throw new ArgumentException("A protocol domain must be non-empty printable ASCII.", nameof(value));
        return Encoding.ASCII.GetBytes(value);
    }

    private static bool IsPrintableAscii(ReadOnlySpan<byte> value)
    {
        foreach (var item in value)
            if (item is < 0x21 or > 0x7e)
                return false;
        return true;
    }
}
