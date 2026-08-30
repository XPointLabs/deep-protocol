using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

public enum RevocationTargetKind : byte { DeviceCertificate = 1, MailboxRoleCertificate = 2, AccountTerminal = 3 }
public enum RevocationReason : ushort { KeyCompromise = 1, DeviceLost = 2, RoleRetired = 3, AccountShutdown = 4 }
public enum ResetReason : ushort { UserInitiatedRecovery = 1, KeyCompromise = 2, AdministrativeReset = 3 }
public enum KeyScope : byte { ReleaseRoot = 1, DeviceCertificateIssuer = 2, AccountRevocation = 3, ResetControl = 4 }
public enum KeyAction : byte { Rotate = 1, Revoke = 2 }
public enum X25519PossessionRole : byte { Device = 1, Router = 2 }
public enum ComponentKind : ushort { Registry = 1, XNode = 2, Shared = 3, Maui = 4 }
public enum EndpointKind : byte { Ipv4 = 1, Ipv6 = 2, Dns = 3 }
public enum WitnessEndpointKind : byte { Ipv4 = 1, Ipv6 = 2 }
public enum DurabilityClass : byte { FsyncReplicated = 1 }
public enum OuterPeerOperation : ushort { MailboxPeerV2 = 1 }
public enum JournalPhase : byte { Prepared = 0, InnerPending = 1, Completed = 2 }

[Flags]
public enum DeviceCapabilities : ulong { MailboxRoleIssuer = 1 }
[Flags]
public enum MailboxCapabilities : ulong { RouteOwnerControl = 1, RouterCertificateIssuer = 2 }
[Flags]
public enum RouterRoles : ulong { PeerIngress = 1, PeerCore = 2, MailboxReplica = 4 }
[Flags]
public enum RouterCapabilities : ulong
{
    NativePeerMailboxV2 = 1,
    ClientMailboxIngressV2 = 2,
    ProductionMailboxCacheV2 = 4,
    ProductionMailboxCapacityV1 = 8,
    MembershipCatalogV2 = 16
}

public enum RecordError
{
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedSuite,
    InvalidHeader,
    InvalidTag,
    InvalidField,
    InvalidArtifactReference,
    InvalidSignature,
    InvalidTransition,
    ForkDetected,
    Expired,
    Revoked
}

public sealed class RecordException(RecordError error, string message)
    : Exception(message)
{
    public RecordError Error { get; } = error;
}

public readonly struct ArtifactReference
{
    public const int Length = 38;
    private readonly byte[] _hash;

    public ArtifactReference(
        ArtifactType type,
        uint canonicalLength,
        ReadOnlySpan<byte> canonicalHash)
    {
        if (!ArtifactRegistry.IsKnown(type) || canonicalHash.Length != 32)
            throw new RecordException(
                RecordError.InvalidArtifactReference,
                "The artifact reference is malformed.");
        Type = type;
        CanonicalLength = canonicalLength;
        _hash = canonicalHash.ToArray();
    }

    public ArtifactType Type { get; }
    public uint CanonicalLength { get; }
    public ReadOnlyMemory<byte> CanonicalHash => _hash?.ToArray() ?? Array.Empty<byte>();
    public bool IsZero => (ushort)Type == 0 && CanonicalLength == 0 &&
                          (_hash is null || _hash.All(static value => value == 0));
}

internal enum RecordClass
{
    PublicAuthenticated,
    PublicCommittedUnsigned,
    ProtectedHmac,
    ProtectedAead
}

internal sealed record FieldDefinition(
    string Name,
    int MinimumLength,
    int MaximumLength)
{
    internal static FieldDefinition Fixed(string name, int length) =>
        new(name, length, length);
}

internal sealed record RecordDefinition(
    string Magic,
    ushort Version,
    ushort Suite,
    RecordClass RecordClass,
    int MinimumLength,
    int MaximumLength,
    IReadOnlyList<FieldDefinition> Fields,
    IReadOnlySet<int> OmittedSigningFieldIndexes);

internal sealed class OwnedRecord
{
    private readonly byte[] _canonical;

    internal OwnedRecord(
        RecordDefinition definition,
        byte[] canonical)
    {
        Definition = definition;
        _canonical = canonical;
    }

    internal RecordDefinition Definition { get; }
    internal ReadOnlySpan<byte> CanonicalSpan => _canonical;
    internal ReadOnlyMemory<byte> CanonicalMemory => _canonical;
    internal ReadOnlySpan<byte> FieldSpan(int oneBasedTag) =>
        RecordDefinitions.Field(_canonical, oneBasedTag);
    internal ReadOnlyMemory<byte> FieldMemory(int oneBasedTag)
    {
        if (oneBasedTag < 1 || oneBasedTag > Definition.Fields.Count)
            throw new ArgumentOutOfRangeException(nameof(oneBasedTag));
        var offset = CanonicalGrammar.HeaderLength;
        for (var tag = 1; tag <= oneBasedTag; tag++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                _canonical.AsSpan(offset + 4, 4)));
            offset += CanonicalGrammar.FieldHeaderLength;
            if (tag == oneBasedTag) return _canonical.AsMemory(offset, length);
            offset = checked(offset + length);
        }
        throw new ArgumentOutOfRangeException(nameof(oneBasedTag));
    }
    internal byte[] CanonicalCopy() => _canonical.ToArray();
    internal byte[] FieldCopy(int oneBasedTag) => FieldSpan(oneBasedTag).ToArray();
}
