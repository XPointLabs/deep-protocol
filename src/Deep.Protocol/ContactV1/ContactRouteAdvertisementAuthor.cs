using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.ContactV1;

public sealed class AuthoredContactRouteAdvertisement
{
    private readonly byte[] exactXra1;
    private readonly byte[] placementInput;

    internal AuthoredContactRouteAdvertisement(
        ContactRecord record,
        ReadOnlySpan<byte> placementInput)
    {
        Record = record;
        exactXra1 = record.CanonicalBytes.ToArray();
        this.placementInput = placementInput.ToArray();
    }

    public ContactRecord Record { get; }
    public ReadOnlyMemory<byte> ExactXra1 => exactXra1.ToArray();
    public ReadOnlyMemory<byte> PlacementInput => placementInput.ToArray();
}

/// <summary>
/// Rehydrates the device-authored XRA1 capability at a remote threshold-authority
/// boundary. Raw XRA1 bytes become usable only after they match the exact current
/// proposal capability and their device signature verifies.
/// </summary>
public static class ContactRouteAdvertisementVerifier
{

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>
/// Authors only the device-owned XRA1 proposal. Selection, replica and live
/// route authority remain absent until the directory threshold returns PMS2,
/// XRC1 and XSS1 for these exact bytes.
/// </summary>
public static class ContactRouteAdvertisementAuthor
{

    private static byte[] RandomNonZero32()
    {
        var value = new byte[32];
        do RandomNumberGenerator.Fill(value);
        while (value.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return value;
    }

    private static byte[] PlaceholderSignature()
    {
        var value = new byte[64];
        value[^1] = 1;
        return value;
    }

    private static byte[] U16(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }

    private static byte[] U32(uint value)
    {
        var result = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
