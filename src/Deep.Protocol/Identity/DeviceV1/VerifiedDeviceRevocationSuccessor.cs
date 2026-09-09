using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Identity.DeviceV1;

/// <summary>
/// Non-forgeable proof that one already verified DRS1 is the exact append-one
/// successor of another and that the appended catalog row revokes one exact DPD1.
/// Construction is private; public callers can only obtain it from the verifier.
/// </summary>
public sealed class VerifiedDeviceRevocationSuccessor
{
    private readonly byte[] accountId;
    private readonly byte[] deviceId;
    private readonly byte[] priorDrsHash;
    private readonly byte[] successorDrsHash;

    private VerifiedDeviceRevocationSuccessor(
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> deviceId,
        ArtifactReference revokedDpdReference,
        ulong priorDrsRevision,
        ReadOnlySpan<byte> priorDrsHash,
        ulong successorDrsRevision,
        ReadOnlySpan<byte> successorDrsHash)
    {
        this.accountId = accountId.ToArray();
        AccountGeneration = accountGeneration;
        this.deviceId = deviceId.ToArray();
        RevokedDpdReference = revokedDpdReference;
        PriorDrsRevision = priorDrsRevision;
        this.priorDrsHash = priorDrsHash.ToArray();
        SuccessorDrsRevision = successorDrsRevision;
        this.successorDrsHash = successorDrsHash.ToArray();
    }

    public ReadOnlyMemory<byte> AccountId => accountId.ToArray();
    public ulong AccountGeneration { get; }
    public ReadOnlyMemory<byte> RevokedDeviceId => deviceId.ToArray();
    public ArtifactReference RevokedDpdReference { get; }
    public ulong PriorDrsRevision { get; }
    public ReadOnlyMemory<byte> PriorDrsHash => priorDrsHash.ToArray();
    public ulong SuccessorDrsRevision { get; }
    public ReadOnlyMemory<byte> SuccessorDrsHash => successorDrsHash.ToArray();

    internal static VerifiedDeviceRevocationSuccessor Create(
        VerifiedRevocationState prior,
        VerifiedRevocationState successor,
        VerifiedDevice revokedDevice)
    {
        var reference = CanonicalGrammar.ComputeReference(
            ArtifactType.Dpd1, revokedDevice.Certificate.CanonicalBytes.Span);
        return new(
            prior.Account.DeepAccountIdHash.Span,
            prior.Account.Certificate.AccountGeneration,
            revokedDevice.Certificate.DeviceId.Span,
            reference,
            prior.Snapshot.Revision,
            prior.Snapshot.CanonicalHash.Span,
            successor.Snapshot.Revision,
            successor.Snapshot.CanonicalHash.Span);
    }
}

public static class DeviceRevocationSuccessorVerifier
{
    public static VerifiedDeviceRevocationSuccessor Verify(
        VerifiedRevocationState prior,
        VerifiedRevocationState successor,
        VerifiedDevice revokedDevice)
    {
        ArgumentNullException.ThrowIfNull(prior);
        ArgumentNullException.ThrowIfNull(successor);
        ArgumentNullException.ThrowIfNull(revokedDevice);
        var account = prior.Account;
        if (!SameAccount(account, successor.Account)
            || !SameAccount(account, revokedDevice.Revocations.Account)
            || !SameArtifact(prior.Snapshot, revokedDevice.Revocations.Snapshot))
            Invalid("The prior DRS1, successor DRS1, and revoked DPD1 do not share one verified account closure.");
        if (prior.Snapshot.Revision == ulong.MaxValue
            || successor.Snapshot.Revision != prior.Snapshot.Revision + 1)
            Invalid("A device-revocation DRS1 successor must advance the exact prior revision by one.");
        if (prior.Catalog.IsAccountTerminal
            || prior.Catalog.Contains(ArtifactType.Dpd1, revokedDevice.Certificate.CanonicalHash.Span))
            Invalid("The prior DRS1 is terminal or already revokes the target DPD1.");

        var oldRecord = prior.Snapshot.Record;
        var newRecord = successor.Snapshot.Record;
        if (!newRecord.FieldSpan(6).SequenceEqual(oldRecord.FieldSpan(6))
            || !newRecord.FieldSpan(7).SequenceEqual(oldRecord.FieldSpan(7))
            || successor.Snapshot.EntryCount != prior.Snapshot.EntryCount + 1)
            Invalid("A device revocation must be an append-one DRS1 successor under the same revocation key head.");
        var oldEntries = oldRecord.FieldSpan(10);
        var newEntries = newRecord.FieldSpan(10);
        if (newEntries.Length != oldEntries.Length + 62
            || !newEntries[..oldEntries.Length].SequenceEqual(oldEntries))
            Invalid("The successor DRS1 does not preserve the exact prior catalog prefix.");
        if (!successor.Catalog.Contains(ArtifactType.Dpd1, revokedDevice.Certificate.CanonicalHash.Span))
            Invalid("The successor DRS1 catalog does not revoke the exact DPD1.");

        var appended = successor.Catalog.Entries[^1];
        var certificateReference = appended.Target.CertificateReference;
        if (appended.Target.TargetKind != RevocationTargetKind.DeviceCertificate
            || certificateReference.Type != ArtifactType.Dpd1
            || certificateReference.CanonicalLength != revokedDevice.Certificate.CanonicalBytes.Length
            || !certificateReference.CanonicalHash.Span.SequenceEqual(revokedDevice.Certificate.CanonicalHash.Span)
            || !appended.CertificateCanonical.SequenceEqual(revokedDevice.Certificate.CanonicalBytes.Span))
            Invalid("The appended revocation row is not bound to the exact revoked DPD1 reference and bytes.");

        return VerifiedDeviceRevocationSuccessor.Create(prior, successor, revokedDevice);
    }

    private static bool SameAccount(VerifiedAccount left, VerifiedAccount right) =>
        SameArtifact(left.Certificate, right.Certificate)
        && left.DeepAccountIdHash.Span.SequenceEqual(right.DeepAccountIdHash.Span);

    private static bool SameArtifact(CanonicalIdentityArtifact left, CanonicalIdentityArtifact right) =>
        left.ArtifactType == right.ArtifactType
        && left.CanonicalBytes.Length == right.CanonicalBytes.Length
        && left.CanonicalHash.Span.SequenceEqual(right.CanonicalHash.Span);

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidTransition, message);
}

/// <summary>
/// Sealed output reserved for the ADC1/ADP1 verifier. Its constructor is internal
/// so no consumer can elevate a bare hash. ACCOUNT-DIRECTORY-AUTH-01 supplies the
/// wire adapter when ADC1 bytes are frozen.
/// </summary>
public sealed class VerifiedAccountDirectoryDeviceSuccessor
{
    private readonly byte[] accountId;
    private readonly byte[] priorAdcHash;
    private readonly byte[] successorAdcHash;
    private readonly byte[] successorDrsHash;
    private readonly byte[] successorDmdHash;

    internal VerifiedAccountDirectoryDeviceSuccessor(
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> priorAdcHash,
        ReadOnlySpan<byte> successorAdcHash,
        ReadOnlySpan<byte> successorDrsHash,
        ReadOnlySpan<byte> successorDmdHash)
    {
        Require32(accountId, nameof(accountId));
        Require32(priorAdcHash, nameof(priorAdcHash));
        Require32(successorAdcHash, nameof(successorAdcHash));
        Require32(successorDrsHash, nameof(successorDrsHash));
        Require32(successorDmdHash, nameof(successorDmdHash));
        this.accountId = accountId.ToArray();
        AccountGeneration = accountGeneration;
        this.priorAdcHash = priorAdcHash.ToArray();
        this.successorAdcHash = successorAdcHash.ToArray();
        this.successorDrsHash = successorDrsHash.ToArray();
        this.successorDmdHash = successorDmdHash.ToArray();
    }

    public ReadOnlyMemory<byte> AccountId => accountId.ToArray();
    public ulong AccountGeneration { get; }
    public ReadOnlyMemory<byte> PriorAdcHash => priorAdcHash.ToArray();
    public ReadOnlyMemory<byte> SuccessorAdcHash => successorAdcHash.ToArray();
    public ReadOnlyMemory<byte> SuccessorDrsHash => successorDrsHash.ToArray();
    public ReadOnlyMemory<byte> SuccessorDmdHash => successorDmdHash.ToArray();

    private static void Require32(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("A verified account-directory commitment must be a nonzero 32-byte value.", name);
    }
}

public sealed class VerifiedDeviceControlSuccessor
{
    private VerifiedDeviceControlSuccessor(
        VerifiedDeviceRevocationSuccessor revocation,
        VerifiedDmd1 directory,
        VerifiedAccountDirectoryDeviceSuccessor accountDirectory)
    {
        Revocation = revocation;
        Directory = directory;
        AccountDirectory = accountDirectory;
    }

    public VerifiedDeviceRevocationSuccessor Revocation { get; }
    public VerifiedDmd1 Directory { get; }
    public VerifiedAccountDirectoryDeviceSuccessor AccountDirectory { get; }

    public static VerifiedDeviceControlSuccessor Verify(
        VerifiedDeviceRevocationSuccessor revocation,
        VerifiedDmd1 directory,
        VerifiedAccountDirectoryDeviceSuccessor accountDirectory)
    {
        ArgumentNullException.ThrowIfNull(revocation);
        ArgumentNullException.ThrowIfNull(directory);
        ArgumentNullException.ThrowIfNull(accountDirectory);
        var record = directory.Record;
        if (!record.DeepAccountId.Span.SequenceEqual(revocation.AccountId.Span)
            || record.AccountGeneration != revocation.AccountGeneration
            || !record.Drs1Reference.CanonicalHash.Span.SequenceEqual(revocation.SuccessorDrsHash.Span)
            || record.ActiveDevices.Any(value => value.DeviceId.Span.SequenceEqual(revocation.RevokedDeviceId.Span)))
            throw new RecordException(RecordError.InvalidTransition,
                "The verified DMD1 successor does not exclude the revoked device under the exact successor DRS1.");
        if (!accountDirectory.AccountId.Span.SequenceEqual(revocation.AccountId.Span)
            || accountDirectory.AccountGeneration != revocation.AccountGeneration
            || !accountDirectory.SuccessorDrsHash.Span.SequenceEqual(revocation.SuccessorDrsHash.Span)
            || !accountDirectory.SuccessorDmdHash.Span.SequenceEqual(record.RecordHash.Span))
            throw new RecordException(RecordError.InvalidTransition,
                "The verified ADC successor is not bound to the exact DRS1/DMD1 control successor.");
        return new VerifiedDeviceControlSuccessor(revocation, directory, accountDirectory);
    }
}
