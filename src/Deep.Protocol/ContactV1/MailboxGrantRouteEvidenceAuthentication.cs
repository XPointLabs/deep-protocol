using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.ContactV1;

/// <summary>
/// Canonical portable evidence signed independently by both resolver replicas
/// after a role-scoped capability lookup. It lets the isolated mailbox issuer
/// authorize Retrieve without trusting one forwarding XNode.
/// </summary>
public static class MailboxGrantRouteEvidenceAuthentication
{
    public const int TupleLength = 139;
    private static readonly byte[] Domain =
        Encoding.ASCII.GetBytes("Deep/ContactResolver/V1/mailbox-grant-route");

    public static byte[] CreateTuple(
        ReadOnlySpan<byte> exactXmg1Hash,
        ReadOnlySpan<byte> locatorHash,
        ReadOnlySpan<byte> capabilityDigest,
        byte role,
        ushort disposition,
        ReadOnlySpan<byte> exactRouteClosureHash,
        ulong effectiveExpiresAtUnixSeconds)
    {
        RequireNonZero32(exactXmg1Hash, nameof(exactXmg1Hash));
        RequireNonZero32(locatorHash, nameof(locatorHash));
        RequireNonZero32(capabilityDigest, nameof(capabilityDigest));
        if (role is not (1 or 2)) throw new ArgumentOutOfRangeException(nameof(role));
        if (disposition is < 1 or > 6) throw new ArgumentOutOfRangeException(nameof(disposition));
        if (exactRouteClosureHash.Length != 32)
            throw new ArgumentException("The route hash must contain exactly 32 bytes.", nameof(exactRouteClosureHash));
        if (disposition == 1)
        {
            if (exactRouteClosureHash.IndexOfAnyExcept((byte)0) < 0
                || effectiveExpiresAtUnixSeconds == 0)
                throw new ArgumentException("Current route evidence requires a route hash and expiry.");
        }
        else if (exactRouteClosureHash.IndexOfAnyExcept((byte)0) >= 0
            || effectiveExpiresAtUnixSeconds != 0)
            throw new ArgumentException("Non-current route evidence must carry zero route authority.");

        var tuple = new byte[TupleLength];
        exactXmg1Hash.CopyTo(tuple);
        locatorHash.CopyTo(tuple.AsSpan(32));
        capabilityDigest.CopyTo(tuple.AsSpan(64));
        tuple[96] = role;
        BinaryPrimitives.WriteUInt16BigEndian(tuple.AsSpan(97), disposition);
        exactRouteClosureHash.CopyTo(tuple.AsSpan(99));
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(131), effectiveExpiresAtUnixSeconds);
        return tuple;
    }

    public static byte[] GetSigningBytes(ReadOnlySpan<byte> canonicalTuple)
    {
        if (canonicalTuple.Length != TupleLength)
            throw new ArgumentException("Mailbox route evidence tuple has an invalid length.", nameof(canonicalTuple));
        var output = new byte[Domain.Length + 7 + TupleLength];
        Domain.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(Domain.Length + 1), 0x0201);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(Domain.Length + 3), TupleLength);
        canonicalTuple.CopyTo(output.AsSpan(Domain.Length + 7));
        return output;
    }

    private static void RequireNonZero32(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The value must contain exactly 32 non-zero bytes.", name);
    }
}

public static class MailboxGrantCapabilityDigest
{
    public static byte[] Compute(
        ReadOnlySpan<byte> capability,
        MailboxCapabilityDomain domain)
    {
        if (capability.Length != 32 || capability.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException(
                "Mailbox grant capability must contain exactly 32 non-zero bytes.",
                nameof(capability));
        ReadOnlySpan<byte> label = domain switch
        {
            MailboxCapabilityDomain.Deposit =>
                "Deep/ContactResolver/V1/grant-capability/deposit"u8,
            MailboxCapabilityDomain.Retrieve =>
                "Deep/ContactResolver/V1/grant-capability/retrieve"u8,
            _ => throw new ArgumentOutOfRangeException(nameof(domain)),
        };
        return SHA256.HashData([.. label, 0, .. capability]);
    }
}
