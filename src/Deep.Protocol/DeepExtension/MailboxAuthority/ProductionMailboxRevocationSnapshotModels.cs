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
/// Verified, immutable retained PMR1 provenance for native DNP1 consumers.
/// This observation cannot answer current mailbox-grant revocation queries.
/// </summary>
public sealed class VerifiedProductionMailboxRevocationSnapshot
{
    private readonly ProductionMailboxRevocationSnapshot _snapshot;
    private readonly byte[] _canonicalHash;

    internal VerifiedProductionMailboxRevocationSnapshot(
        ProductionMailboxRevocationSnapshot snapshot,
        ReadOnlySpan<byte> canonicalHash)
    {
        _snapshot = ProductionMailboxRevocationSnapshotCopy.Clone(snapshot);
        _canonicalHash = canonicalHash.ToArray();
    }

    public ProductionMailboxRevocationSnapshot Snapshot => ProductionMailboxRevocationSnapshotCopy.Clone(_snapshot);
    public ReadOnlyMemory<byte> CanonicalSnapshotHash => _canonicalHash.ToArray();
    public int RevokedGrantSerialCount => _snapshot.RevokedGrantSerials.Count;
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
