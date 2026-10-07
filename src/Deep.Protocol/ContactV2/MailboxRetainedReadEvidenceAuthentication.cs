using System.Buffers.Binary;
using System.Text;

namespace Deep.Protocol.ContactV2;

/// <summary>Canonical untrusted transcript only. Construction does not prove
/// protected route custody, capability ownership or current issuance authority.</summary>
public static class MailboxRetainedReadEvidenceAuthentication
{
    public const int TupleLength = 136;
    public const string SigningDomain = "Deep/ContactResolver/V2/mailbox-retained-read";

    public static byte[] CreateTuple(ReadOnlySpan<byte> requestHash, ReadOnlySpan<byte> locatorHash,
        ReadOnlySpan<byte> retrieveCapabilityDigest, ReadOnlySpan<byte> originalRouteHash,
        ulong readUntilUnixSeconds)
    {
        Require32(requestHash); Require32(locatorHash); Require32(retrieveCapabilityDigest); Require32(originalRouteHash);
        if (readUntilUnixSeconds == 0) throw new ArgumentOutOfRangeException(nameof(readUntilUnixSeconds));
        var result = new byte[TupleLength];
        requestHash.CopyTo(result); locatorHash.CopyTo(result.AsSpan(32));
        retrieveCapabilityDigest.CopyTo(result.AsSpan(64)); originalRouteHash.CopyTo(result.AsSpan(96));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(128), readUntilUnixSeconds);
        return result;
    }

    public static byte[] GetSigningBytes(ReadOnlySpan<byte> canonicalTuple)
    {
        if (canonicalTuple.Length != TupleLength) throw new ArgumentException("Retained read tuple has an invalid exact length.");
        for (var offset = 0; offset < 128; offset += 32) Require32(canonicalTuple.Slice(offset, 32));
        if (BinaryPrimitives.ReadUInt64BigEndian(canonicalTuple[128..]) == 0)
            throw new ArgumentException("Retained read tuple has no horizon.");
        var domain = Encoding.ASCII.GetBytes(SigningDomain);
        var result = new byte[domain.Length + 7 + TupleLength]; domain.CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(domain.Length + 1), 0x0201);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(domain.Length + 3), TupleLength);
        canonicalTuple.CopyTo(result.AsSpan(domain.Length + 7));
        return result;
    }

    private static void Require32(ReadOnlySpan<byte> value)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Retained read tuple requires exact nonzero 32-byte fields.");
    }
}
