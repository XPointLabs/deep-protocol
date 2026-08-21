namespace Deep.Protocol.DeepNative;

public abstract class CanonicalIdentityArtifact
{
    private readonly byte[] _hash;

    internal CanonicalIdentityArtifact(
        OwnedRecord record,
        ArtifactType type)
    {
        Record = record;
        var reference = CanonicalGrammar.ComputeReference(type, record.CanonicalSpan);
        ArtifactType = type;
        _hash = reference.CanonicalHash.ToArray();
    }

    internal OwnedRecord Record { get; }
    public ArtifactType ArtifactType { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => Record.CanonicalCopy();
    public ReadOnlyMemory<byte> CanonicalHash => _hash.ToArray();
}

public sealed class AccountCertificate : CanonicalIdentityArtifact
{
    internal AccountCertificate(OwnedRecord record) : base(record, ArtifactType.Dpa1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ulong AccountGeneration => Scalars.UInt64(Record.FieldSpan(2));
    public ulong CertificateGeneration => Scalars.UInt64(Record.FieldSpan(3));
    public ReadOnlyMemory<byte> AccountEd25519PublicKey => Record.FieldCopy(5);
    public ReadOnlyMemory<byte> DeviceIssuerEd25519PublicKey => Record.FieldCopy(6);
    public ReadOnlyMemory<byte> RevocationEd25519PublicKey => Record.FieldCopy(7);
    public ReadOnlyMemory<byte> ResetControlEd25519PublicKey => Record.FieldCopy(8);
    public ReadOnlyMemory<byte> AccountRevocationHandle => Record.FieldCopy(9);
    public ulong CreatedAtUnixSeconds => Scalars.UInt64(Record.FieldSpan(10));
    public ulong PolicyGeneration => Scalars.UInt64(Record.FieldSpan(11));
}

public sealed class DeviceCertificate : CanonicalIdentityArtifact
{
    internal DeviceCertificate(OwnedRecord record) : base(record, ArtifactType.Dpd1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ReadOnlyMemory<byte> AccountHash => Record.FieldCopy(2);
    public ulong AccountGeneration => Scalars.UInt64(Record.FieldSpan(3));
    public ReadOnlyMemory<byte> DeviceId => Record.FieldCopy(4);
    public ulong DeviceGeneration => Scalars.UInt64(Record.FieldSpan(5));
    public ReadOnlyMemory<byte> DeviceEd25519PublicKey => Record.FieldCopy(6);
    public ReadOnlyMemory<byte> DeviceX25519PublicKey => Record.FieldCopy(7);
    public ReadOnlyMemory<byte> RevocationHandle => Record.FieldCopy(8);
    public ulong IssuerTransitionGeneration => Scalars.UInt64(Record.FieldSpan(9));
    public ArtifactReference IssuerTransitionReference =>
        CanonicalGrammar.DecodeReference(Record.FieldSpan(10), allowZero: true);
    public ReadOnlyMemory<byte> IssuerKeyHash => Record.FieldCopy(11);
    public ulong IssuedAtUnixSeconds => Scalars.UInt64(Record.FieldSpan(16));
    public ulong ExpiresAtUnixSeconds => Scalars.UInt64(Record.FieldSpan(17));
    public DeviceCapabilities Capabilities =>
        (DeviceCapabilities)Scalars.UInt64(Record.FieldSpan(18));
}

public sealed class MailboxRoleCertificate : CanonicalIdentityArtifact
{
    internal MailboxRoleCertificate(OwnedRecord record) : base(record, ArtifactType.Dpm1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ReadOnlyMemory<byte> AccountHash => Record.FieldCopy(2);
    public ulong AccountGeneration => Scalars.UInt64(Record.FieldSpan(3));
    public ReadOnlyMemory<byte> DeviceId => Record.FieldCopy(4);
    public ReadOnlyMemory<byte> MailboxOwnerId => Record.FieldCopy(6);
    public ulong RoleGeneration => Scalars.UInt64(Record.FieldSpan(7));
    public ReadOnlyMemory<byte> MailboxEd25519PublicKey => Record.FieldCopy(8);
    public ReadOnlyMemory<byte> RevocationHandle => Record.FieldCopy(9);
    public ulong IssuedAtUnixSeconds => Scalars.UInt64(Record.FieldSpan(14));
    public ulong ExpiresAtUnixSeconds => Scalars.UInt64(Record.FieldSpan(15));
    public MailboxCapabilities Capabilities =>
        (MailboxCapabilities)Scalars.UInt64(Record.FieldSpan(16));
}

public sealed class RevocationSnapshot : CanonicalIdentityArtifact
{
    internal RevocationSnapshot(OwnedRecord record) : base(record, ArtifactType.Drs1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ReadOnlyMemory<byte> AccountHash => Record.FieldCopy(2);
    public ulong AccountGeneration => Scalars.UInt64(Record.FieldSpan(3));
    public ulong Revision => Scalars.UInt64(Record.FieldSpan(4));
    public ushort EntryCount => Scalars.UInt16(Record.FieldSpan(9));
    public ReadOnlyMemory<byte> CurrentHead => Record.FieldCopy(11);
}

public sealed class VerifiedAccount
{
    private readonly byte[] _accountHash;
    internal VerifiedAccount(AccountCertificate certificate, ReadOnlySpan<byte> accountHash)
    {
        Certificate = certificate;
        _accountHash = accountHash.ToArray();
    }
    public AccountCertificate Certificate { get; }
    public ReadOnlyMemory<byte> DeepAccountIdHash => _accountHash.ToArray();
}

public sealed class VerifiedRevocationState
{
    internal VerifiedRevocationState(
        VerifiedAccount account,
        RevocationSnapshot snapshot,
        RevocationCatalog catalog)
    {
        Account = account;
        Snapshot = snapshot;
        Catalog = catalog;
    }
    public VerifiedAccount Account { get; }
    public RevocationSnapshot Snapshot { get; }
    internal RevocationCatalog Catalog { get; }
}

public sealed class VerifiedDevice
{
    internal VerifiedDevice(
        DeviceCertificate certificate,
        VerifiedRevocationState revocations,
        X25519Possession possession)
    {
        Certificate = certificate;
        Revocations = revocations;
        Possession = possession;
    }
    public DeviceCertificate Certificate { get; }
    public VerifiedRevocationState Revocations { get; }
    internal X25519Possession Possession { get; }
}

public sealed class VerifiedMailboxRole
{
    internal VerifiedMailboxRole(MailboxRoleCertificate certificate, VerifiedDevice device)
    {
        Certificate = certificate;
        Device = device;
    }
    public MailboxRoleCertificate Certificate { get; }
    public VerifiedDevice Device { get; }
}

internal static class Scalars
{
    internal static ulong UInt64(ReadOnlySpan<byte> value) =>
        System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(value);
    internal static ushort UInt16(ReadOnlySpan<byte> value) =>
        System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(value);
}
