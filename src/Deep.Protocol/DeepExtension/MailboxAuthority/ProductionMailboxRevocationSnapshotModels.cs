using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.DeepExtension.MailboxAuthority;

public static class ProductionMailboxRevocationSnapshotConstants
{
    public const string Schema = "production-mailbox-revocation-snapshot.v1";
    public const byte Version = 1;
    public const int MaximumRevokedGrantSerials = 4_096;
    public const int FixedArtifactBytesWithoutSerials = 220;
    public const int RevokedGrantSerialBytes = 16;
    public const int MaximumArtifactBytes = FixedArtifactBytesWithoutSerials +
        (MaximumRevokedGrantSerials * RevokedGrantSerialBytes);
}

public enum ProductionMailboxRevocationSnapshotError
{
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    ReservedFieldNotZero,
    InvalidField,
    InvalidSerialOrder,
    NonCanonical,
    AuthorityBindingMismatch,
    SnapshotHashMismatch,
    AuthorityFieldMismatch,
    InvalidSignature,
    NotYetValid,
    Expired
}

public sealed class ProductionMailboxRevocationSnapshotException(
    ProductionMailboxRevocationSnapshotError error,
    string message) : Exception(message)
{
    public ProductionMailboxRevocationSnapshotError Error { get; } = error;
}

/// <summary>Public PMR1 data only: exact MCG2 serials and public authority bindings.</summary>
public sealed record ProductionMailboxRevocationSnapshot
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ulong AuthorityGeneration { get; init; }
    public required ReadOnlyMemory<byte> AuthorityBindingHash { get; init; }
    public required ulong RevocationGeneration { get; init; }
    public required ReadOnlyMemory<byte> RevocationHeadHash { get; init; }
    public required ReadOnlyMemory<byte> PreviousRevocationHeadHash { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required IReadOnlyList<ReadOnlyMemory<byte>> RevokedGrantSerials { get; init; }
    public required ReadOnlyMemory<byte> IssuerSignature { get; init; }
}

public interface IProductionMailboxRevocationSnapshotSignatureVerifier
{
    bool Verify(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature);
}

/// <summary>
/// Verified, immutable PMR1 handle and direct fail-closed MCG2 revocation source. A query for a
/// different issuer is a policy error, not an unrevoked result.
/// </summary>
public sealed class VerifiedProductionMailboxRevocationSnapshot : IMailboxCapabilityRevocationSource
{
    private readonly ProductionMailboxRevocationSnapshot _snapshot;
    private readonly byte[] _canonicalHash;
    private readonly byte[] _issuerPublicKey;
    private readonly byte[][] _serials;

    internal VerifiedProductionMailboxRevocationSnapshot(
        ProductionMailboxRevocationSnapshot snapshot,
        ReadOnlySpan<byte> canonicalHash,
        ReadOnlySpan<byte> issuerPublicKey)
    {
        _snapshot = ProductionMailboxRevocationSnapshotCopy.Clone(snapshot);
        _canonicalHash = canonicalHash.ToArray();
        _issuerPublicKey = issuerPublicKey.ToArray();
        _serials = snapshot.RevokedGrantSerials.Select(static serial => serial.ToArray()).ToArray();
    }

    public ProductionMailboxRevocationSnapshot Snapshot => ProductionMailboxRevocationSnapshotCopy.Clone(_snapshot);
    public ReadOnlyMemory<byte> CanonicalSnapshotHash => _canonicalHash.ToArray();
    public int RevokedGrantSerialCount => _serials.Length;

    public bool IsRevokedSerial(ReadOnlySpan<byte> serial)
    {
        if (serial.Length != MailboxAuthenticatedCapabilityLimits.SerialLength || serial.IndexOfAnyExcept((byte)0) < 0)
            throw Error(ProductionMailboxRevocationSnapshotError.InvalidField, "MCG2 serial is invalid.");
        var low = 0;
        var high = _serials.Length - 1;
        while (low <= high)
        {
            var middle = low + ((high - low) / 2);
            var comparison = _serials[middle].AsSpan().SequenceCompareTo(serial);
            if (comparison == 0)
                return true;
            if (comparison < 0)
                low = middle + 1;
            else
                high = middle - 1;
        }
        return false;
    }

    public bool IsRevoked(MailboxCapabilityRevocationQuery query)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (query.IssuerPublicKey.Length != _issuerPublicKey.Length ||
            !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(query.IssuerPublicKey.Span, _issuerPublicKey))
            throw Error(ProductionMailboxRevocationSnapshotError.AuthorityFieldMismatch, "Revocation query issuer is not the verified PMA1 issuer.");
        return IsRevokedSerial(query.Serial.Span);
    }

    private static ProductionMailboxRevocationSnapshotException Error(
        ProductionMailboxRevocationSnapshotError error,
        string message) => new(error, message);
}

internal static class ProductionMailboxRevocationSnapshotCopy
{
    public static ProductionMailboxRevocationSnapshot Clone(ProductionMailboxRevocationSnapshot value) => new()
    {
        NetworkId = value.NetworkId.ToArray(),
        AuthorityGeneration = value.AuthorityGeneration,
        AuthorityBindingHash = value.AuthorityBindingHash.ToArray(),
        RevocationGeneration = value.RevocationGeneration,
        RevocationHeadHash = value.RevocationHeadHash.ToArray(),
        PreviousRevocationHeadHash = value.PreviousRevocationHeadHash.ToArray(),
        IssuedAtUnixSeconds = value.IssuedAtUnixSeconds,
        ExpiresAtUnixSeconds = value.ExpiresAtUnixSeconds,
        RevokedGrantSerials = value.RevokedGrantSerials.Select(static serial => (ReadOnlyMemory<byte>)serial.ToArray()).ToArray(),
        IssuerSignature = value.IssuerSignature.ToArray()
    };
}
