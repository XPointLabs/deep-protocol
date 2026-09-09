using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Identity.DeviceV1;

public sealed class VerifiedDeviceHistoryTransferAuthorization
{
    private readonly byte[] accountId;
    private readonly byte[] sourceDeviceId;
    private readonly byte[] targetDeviceId;
    private readonly byte[] directoryHash;

    private VerifiedDeviceHistoryTransferAuthorization(
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> sourceDeviceId,
        ReadOnlySpan<byte> targetDeviceId,
        ulong directoryGeneration,
        ReadOnlySpan<byte> directoryHash)
    {
        this.accountId = accountId.ToArray();
        AccountGeneration = accountGeneration;
        this.sourceDeviceId = sourceDeviceId.ToArray();
        this.targetDeviceId = targetDeviceId.ToArray();
        DirectoryGeneration = directoryGeneration;
        this.directoryHash = directoryHash.ToArray();
    }

    public ReadOnlyMemory<byte> AccountId => accountId.ToArray();
    public ulong AccountGeneration { get; }
    public ReadOnlyMemory<byte> SourceDeviceId => sourceDeviceId.ToArray();
    public ReadOnlyMemory<byte> TargetDeviceId => targetDeviceId.ToArray();
    public ulong DirectoryGeneration { get; }
    public ReadOnlyMemory<byte> DirectoryHash => directoryHash.ToArray();

    internal static VerifiedDeviceHistoryTransferAuthorization Create(
        VerifiedDmd1 directory,
        VerifiedDevice source,
        VerifiedDevice target) =>
        new(directory.Record.DeepAccountId.Span, directory.Record.AccountGeneration,
            source.Certificate.DeviceId.Span, target.Certificate.DeviceId.Span,
            directory.Record.DirectoryGeneration, directory.Record.RecordHash.Span);
}

public sealed class VerifiedDeviceBackupManifest
{
    private readonly byte[] accountId;
    private readonly byte[] targetDeviceId;
    private readonly byte[] manifestHash;

    internal VerifiedDeviceBackupManifest(
        ReadOnlySpan<byte> accountId,
        ulong accountGeneration,
        ReadOnlySpan<byte> targetDeviceId,
        ReadOnlySpan<byte> manifestHash)
    {
        if (accountId.Length != 32 || targetDeviceId.Length != 32 || manifestHash.Length != 32
            || accountId.IndexOfAnyExcept((byte)0) < 0
            || targetDeviceId.IndexOfAnyExcept((byte)0) < 0
            || manifestHash.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Verified backup manifest facts are malformed.");
        this.accountId = accountId.ToArray();
        AccountGeneration = accountGeneration;
        this.targetDeviceId = targetDeviceId.ToArray();
        this.manifestHash = manifestHash.ToArray();
    }

    public ReadOnlyMemory<byte> AccountId => accountId.ToArray();
    public ulong AccountGeneration { get; }
    public ReadOnlyMemory<byte> TargetDeviceId => targetDeviceId.ToArray();
    public ReadOnlyMemory<byte> ManifestHash => manifestHash.ToArray();
}

public sealed class VerifiedDeviceBackupAuthorization
{
    private readonly byte[] accountId;
    private readonly byte[] targetDeviceId;
    private readonly byte[] manifestHash;

    private VerifiedDeviceBackupAuthorization(VerifiedDeviceBackupManifest manifest)
    {
        accountId = manifest.AccountId.ToArray();
        AccountGeneration = manifest.AccountGeneration;
        targetDeviceId = manifest.TargetDeviceId.ToArray();
        manifestHash = manifest.ManifestHash.ToArray();
    }

    public ReadOnlyMemory<byte> AccountId => accountId.ToArray();
    public ulong AccountGeneration { get; }
    public ReadOnlyMemory<byte> TargetDeviceId => targetDeviceId.ToArray();
    public ReadOnlyMemory<byte> ManifestHash => manifestHash.ToArray();

    internal static VerifiedDeviceBackupAuthorization Create(VerifiedDeviceBackupManifest manifest) => new(manifest);
}

public static class DeviceHistoryAuthorizationVerifier
{
    public static VerifiedDeviceHistoryTransferAuthorization VerifyTransfer(
        VerifiedDmd1 directory,
        VerifiedDevice source,
        VerifiedDevice target)
    {
        ArgumentNullException.ThrowIfNull(directory);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(target);
        if (source.Certificate.DeviceId.Span.SequenceEqual(target.Certificate.DeviceId.Span))
            throw new RecordException(RecordError.InvalidTransition, "History transfer requires distinct devices.");
        if (!SameClosure(directory, source) || !SameClosure(directory, target)
            || !directory.Record.ActiveDevices.Any(value => value.DeviceId.Span.SequenceEqual(source.Certificate.DeviceId.Span))
            || !directory.Record.ActiveDevices.Any(value => value.DeviceId.Span.SequenceEqual(target.Certificate.DeviceId.Span)))
            throw new RecordException(RecordError.InvalidTransition,
                "History transfer requires both exact verified devices active in one verified DMD1.");
        return VerifiedDeviceHistoryTransferAuthorization.Create(directory, source, target);
    }

    public static VerifiedDeviceBackupAuthorization VerifyBackup(
        VerifiedDevice target,
        VerifiedDeviceBackupManifest manifest)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(manifest);
        if (!target.Certificate.AccountHash.Span.SequenceEqual(manifest.AccountId.Span)
            || target.Certificate.AccountGeneration != manifest.AccountGeneration
            || !target.Certificate.DeviceId.Span.SequenceEqual(manifest.TargetDeviceId.Span))
            throw new RecordException(RecordError.InvalidTransition,
                "The verified encrypted backup manifest is not bound to the exact target DPD1.");
        return VerifiedDeviceBackupAuthorization.Create(manifest);
    }

    private static bool SameClosure(VerifiedDmd1 directory, VerifiedDevice device) =>
        directory.Record.DeepAccountId.Span.SequenceEqual(device.Certificate.AccountHash.Span)
        && directory.Record.AccountGeneration == device.Certificate.AccountGeneration
        && directory.Record.Drs1Reference.CanonicalHash.Span.SequenceEqual(device.Revocations.Snapshot.CanonicalHash.Span);
}
