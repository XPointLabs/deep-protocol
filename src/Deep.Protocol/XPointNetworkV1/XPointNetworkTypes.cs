using System.Buffers.Binary;
using System.Collections.ObjectModel;

namespace Deep.Protocol.XPointNetworkV1;

internal enum XPointRecordKind
{
    Xna1,
    Xvp1,
    Xnd1,
    Xnv1,
    Xnh1,
    Xnp1,
    Xnf1,
    Nfp1,
    Xcd1,
}

internal enum XPointFieldKind
{
    Bytes,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    FixedList,
    CoreReference,
    ArtifactReference,
}

internal enum XPointValidationStage
{
    Length,
    Header,
    Scalar,
    ListArithmetic,
    CanonicalList,
    Reference,
    Transition,
    DerivedValue,
    CrossField,
    Closure,
    Proof,
    Signature,
}

internal sealed class XPointValidationException : FormatException
{
    internal XPointValidationException(
        XPointValidationStage stage,
        string error,
        string message) : base(message)
    {
        Stage = stage;
        Error = error;
    }

    internal XPointValidationStage Stage { get; }
    internal string Error { get; }
}

internal sealed record XPointFieldDefinition(
    ushort Tag,
    string Name,
    XPointFieldKind Kind,
    int MinimumLength,
    int MaximumLength,
    ulong MinimumValue = 0,
    ulong MaximumValue = ulong.MaxValue,
    ushort CountTag = 0,
    int EntryBytes = 0,
    string? ReferenceMagic = null,
    bool NonZero = false,
    ushort ZeroIffGenerationTag = 0,
    ulong[]? AllowedValues = null);

internal sealed record XPointRecordDefinition(
    XPointRecordKind Kind,
    string Magic,
    ushort Version,
    ushort Suite,
    int MinimumBytes,
    int MaximumBytes,
    IReadOnlyList<XPointFieldDefinition> Fields,
    int UnsignedLastTag,
    string? SignatureDomain,
    string HashDomain,
    int GenerationTag,
    int PredecessorHashTag);

internal readonly struct XPointBytes : IEquatable<XPointBytes>
{
    private readonly byte[]? _value;

    internal XPointBytes(ReadOnlySpan<byte> value) => _value = value.ToArray();

    internal ReadOnlySpan<byte> Span => _value ?? [];
    internal int Length => _value?.Length ?? 0;
    internal byte[] ToArray() => Span.ToArray();

    public bool Equals(XPointBytes other) => Span.SequenceEqual(other.Span);
    public override bool Equals(object? obj) => obj is XPointBytes other && Equals(other);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(Span);
        return hash.ToHashCode();
    }
}

internal readonly record struct XPointCoreReference(string Magic, ushort Version, XPointBytes Hash)
{
    internal const int Length = 38;

    internal byte[] Encode()
    {
        var output = new byte[Length];
        System.Text.Encoding.ASCII.GetBytes(Magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), Version);
        Hash.Span.CopyTo(output.AsSpan(6));
        return output;
    }
}

internal readonly record struct XPointArtifactReference(string Magic, ushort Version, XPointBytes Hash)
{
    internal const int Length = 38;
}

internal abstract class XPointParsedRecord
{
    private readonly byte[] _canonical;
    private readonly byte[][] _fields;

    protected XPointParsedRecord(
        XPointRecordDefinition definition,
        byte[] canonical,
        byte[][] fields)
    {
        Definition = definition;
        _canonical = canonical;
        _fields = fields;
    }

    internal XPointRecordDefinition Definition { get; }
    internal XPointRecordKind Kind => Definition.Kind;
    internal string Magic => Definition.Magic;
    internal int CanonicalLength => _canonical.Length;
    internal ReadOnlySpan<byte> CanonicalSpan => _canonical;
    internal byte[] CanonicalCopy() => _canonical.ToArray();
    internal ReadOnlySpan<byte> FieldSpan(int tag) => _fields[tag - 1];
    internal XPointBytes FieldBytes(int tag) => new(_fields[tag - 1]);
    internal byte UInt8(int tag) => FieldSpan(tag)[0];
    internal ushort UInt16(int tag) => BinaryPrimitives.ReadUInt16BigEndian(FieldSpan(tag));
    internal uint UInt32(int tag) => BinaryPrimitives.ReadUInt32BigEndian(FieldSpan(tag));
    internal ulong UInt64(int tag) => BinaryPrimitives.ReadUInt64BigEndian(FieldSpan(tag));
    internal XPointCoreReference CoreReference(int tag) => XPointNetworkCodec.DecodeCoreReference(FieldSpan(tag));
    internal XPointArtifactReference ArtifactReference(int tag) => XPointNetworkCodec.DecodeArtifactReference(FieldSpan(tag));
    internal XPointBytes NetworkId => FieldBytes(1);
    internal ulong Generation => Definition.GenerationTag == 0 ? 0 : UInt64(Definition.GenerationTag);
    internal XPointBytes CoreHash => new(XPointNetworkCrypto.ComputeCoreHash(this));
    internal XPointCoreReference CoreReferenceValue => new(Magic, Definition.Version, CoreHash);
}

internal sealed record XPointRootKeyEntry(XPointBytes Id, ulong Generation, XPointBytes PublicKey);
internal sealed record XPointWitnessEntry(XPointBytes Id, ulong Generation, XPointBytes PublicKey, XPointBytes FailureDomainHash);
internal sealed record XPointSignatureEntry(XPointBytes Id, XPointBytes Signature);
internal sealed record XPointPeerOriginEntry(
    XPointBytes Id,
    byte Transport,
    byte AddressFamily,
    XPointBytes Address,
    ushort Port,
    XPointBytes CurrentSpki,
    ulong CurrentNotBefore,
    ulong CurrentExpiresAt,
    XPointBytes NextSpki,
    ulong NextNotBefore,
    ulong NextExpiresAt);
internal sealed record XPointRoleKeyEntry(byte RoleId, ulong Generation, XPointBytes PublicKey);
internal sealed record XPointCallReplicaEntry(
    XPointBytes ReplicaId,
    ulong RoleKeyGeneration,
    XPointBytes RolePublicKey,
    XPointBytes NodeId,
    XPointBytes FailureDomainHash,
    XPointBytes ProofOfPossession);

internal sealed class Xna1Record : XPointParsedRecord
{
    internal Xna1Record(XPointRecordDefinition d, byte[] c, byte[][] f) : base(d, c, f)
    {
        RootKeys = XPointRecordMaterializer.RootKeys(FieldSpan(5));
        Witnesses = XPointRecordMaterializer.Witnesses(FieldSpan(10));
        Signatures = XPointRecordMaterializer.Signatures(FieldSpan(20));
    }

    internal ulong AuthorityGeneration => UInt64(2);
    internal XPointBytes PredecessorAuthorityCoreHash => FieldBytes(3);
    internal ReadOnlyCollection<XPointRootKeyEntry> RootKeys { get; }
    internal byte RootThreshold => UInt8(6);
    internal ReadOnlyCollection<XPointWitnessEntry> Witnesses { get; }
    internal byte WitnessThreshold => UInt8(11);
    internal XPointBytes DirectoryWitnessPolicyHash => new(XPointNetworkCrypto.Sha256Domain(
        XPointNetworkRegistry.DirectoryWitnessPolicyDomain,
        XPointNetworkCrypto.Project(this, 7, 14)));
    internal ulong IssuedAt => UInt64(16);
    internal ulong NotBefore => UInt64(17);
    internal ulong ExpiresAt => UInt64(18);
    internal ReadOnlyCollection<XPointSignatureEntry> Signatures { get; }
}

internal sealed class Xvp1Record : XPointParsedRecord
{
    internal Xvp1Record(XPointRecordDefinition d, byte[] c, byte[][] f) : base(d, c, f) =>
        Signatures = XPointRecordMaterializer.Signatures(FieldSpan(20));
    internal ulong PolicyGeneration => UInt64(2);
    internal ushort EnabledRoleMask => UInt16(4);
    internal byte MailboxReplicaCount => UInt8(6);
    internal XPointCoreReference AuthorizingXna => CoreReference(18);
    internal ulong IssuedAt => UInt64(15);
    internal ulong NotBefore => UInt64(16);
    internal ulong ExpiresAt => UInt64(17);
    internal ReadOnlyCollection<XPointSignatureEntry> Signatures { get; }
}

internal sealed class Xnd1Record : XPointParsedRecord
{
    internal Xnd1Record(XPointRecordDefinition d, byte[] c, byte[][] f) : base(d, c, f)
    {
        Origins = XPointRecordMaterializer.Origins(FieldSpan(20));
        RoleKeys = XPointRecordMaterializer.RoleKeys(FieldSpan(32));
    }

    internal XPointBytes NodeId => FieldBytes(2);
    internal ulong DescriptorGeneration => UInt64(3);
    internal XPointBytes IdentityPublicKey => FieldBytes(5);
    internal XPointBytes StakingIdentityHash => FieldBytes(6);
    internal XPointBytes FailureDomainHash => FieldBytes(12);
    internal ushort RoleMask => UInt16(13);
    internal ReadOnlyCollection<XPointPeerOriginEntry> Origins { get; }
    internal ReadOnlyCollection<XPointRoleKeyEntry> RoleKeys { get; }
    internal ulong NotBefore => UInt64(34);
    internal ulong ExpiresAt => UInt64(35);
    internal XPointBytes Signature => FieldBytes(37);
    internal XPointRoleKeyEntry? FindRole(byte roleId) => RoleKeys.SingleOrDefault(value => value.RoleId == roleId);
}

internal sealed class Xnv1Record : XPointParsedRecord
{
    internal Xnv1Record(XPointRecordDefinition d, byte[] c, byte[][] f) : base(d, c, f) =>
        WitnessSignatures = XPointRecordMaterializer.Signatures(FieldSpan(24));
    internal ulong ViewGeneration => UInt64(2);
    internal ulong FinalizedBlockHeight => UInt64(5);
    internal XPointCoreReference AuthorizingXna => CoreReference(7);
    internal XPointBytes DirectoryWitnessPolicyHash => FieldBytes(8);
    internal XPointCoreReference ActivePolicy => CoreReference(9);
    internal ulong NotBefore => UInt64(20);
    internal ulong ExpiresAt => UInt64(21);
    internal ReadOnlyCollection<XPointSignatureEntry> WitnessSignatures { get; }
}

internal sealed class Xnh1Record : XPointParsedRecord
{
    internal Xnh1Record(XPointRecordDefinition d, byte[] c, byte[][] f) : base(d, c, f) =>
        WitnessSignatures = XPointRecordMaterializer.Signatures(FieldSpan(16));
    internal ulong LogGeneration => UInt64(2);
    internal ulong TreeSize => UInt64(4);
    internal XPointBytes Root => FieldBytes(5);
    internal XPointCoreReference LatestView => CoreReference(6);
    internal ulong LatestViewGeneration => UInt64(7);
    internal XPointCoreReference AuthorizingXna => CoreReference(8);
    internal XPointBytes DirectoryWitnessPolicyHash => FieldBytes(9);
    internal ulong ValidFrom => UInt64(10);
    internal ulong ValidUntil => UInt64(11);
    internal ReadOnlyCollection<XPointSignatureEntry> WitnessSignatures { get; }
}

internal sealed class Xnp1Record : XPointParsedRecord
{
    internal Xnp1Record(XPointRecordDefinition d, byte[] c, byte[][] f) : base(d, c, f) { }
    internal ulong SourceTreeSize => UInt64(3);
    internal ulong TargetTreeSize => UInt64(8);
    internal ulong SourceViewGeneration => UInt64(6);
    internal ulong TargetViewGeneration => UInt64(11);
}

internal sealed class Xnf1Record : XPointParsedRecord
{
    internal Xnf1Record(XPointRecordDefinition d, byte[] c, byte[][] f) : base(d, c, f) =>
        Signatures = XPointRecordMaterializer.Signatures(FieldSpan(15));
    internal ulong CheckpointGeneration => UInt64(2);
    internal ulong FirstCoveredGeneration => BinaryPrimitives.ReadUInt64BigEndian(FieldSpan(4));
    internal ulong LastCoveredGeneration => BinaryPrimitives.ReadUInt64BigEndian(FieldSpan(4)[8..]);
    internal ulong CoveredHeadCount => UInt64(5);
    internal XPointCoreReference TargetView => CoreReference(7);
    internal XPointCoreReference TargetHead => CoreReference(9);
    internal XPointCoreReference AuthorizingXna => CoreReference(11);
    internal ReadOnlyCollection<XPointSignatureEntry> Signatures { get; }
}

internal sealed class Nfp1Record : XPointParsedRecord
{
    internal Nfp1Record(XPointRecordDefinition d, byte[] c, byte[][] f) : base(d, c, f) { }
    internal ulong SourceViewGeneration => UInt64(2);
    internal ulong SourceTreeSize => UInt64(4);
    internal ulong SourceLeafIndex => UInt64(6);
}

internal sealed class Xcd1Record : XPointParsedRecord
{
    internal Xcd1Record(XPointRecordDefinition d, byte[] c, byte[][] f) : base(d, c, f) =>
        Replicas = XPointRecordMaterializer.CallReplicas(FieldSpan(8));
    internal XPointBytes CallRelayNodeId => FieldBytes(2);
    internal ulong DescriptorGeneration => UInt64(3);
    internal XPointBytes TargetRolePublicKey => FieldBytes(5);
    internal ulong TargetRoleKeyGeneration => UInt64(6);
    internal ReadOnlyCollection<XPointCallReplicaEntry> Replicas { get; }
    internal ulong NotBefore => UInt64(19);
    internal ulong ExpiresAt => UInt64(20);
    internal XPointBytes Signature => FieldBytes(21);
}

internal static class XPointRecordMaterializer
{
    internal static ReadOnlyCollection<XPointRootKeyEntry> RootKeys(ReadOnlySpan<byte> list) =>
        Materialize(list, 72, static value => new XPointRootKeyEntry(
            new(value[..32]), BinaryPrimitives.ReadUInt64BigEndian(value[32..40]), new(value[40..72])));

    internal static ReadOnlyCollection<XPointWitnessEntry> Witnesses(ReadOnlySpan<byte> list) =>
        Materialize(list, 104, static value => new XPointWitnessEntry(
            new(value[..32]), BinaryPrimitives.ReadUInt64BigEndian(value[32..40]),
            new(value[40..72]), new(value[72..104])));

    internal static ReadOnlyCollection<XPointSignatureEntry> Signatures(ReadOnlySpan<byte> list) =>
        Materialize(list, 96, static value => new XPointSignatureEntry(new(value[..32]), new(value[32..96])));

    internal static ReadOnlyCollection<XPointPeerOriginEntry> Origins(ReadOnlySpan<byte> list) =>
        Materialize(list, 148, static value => new XPointPeerOriginEntry(
            new(value[..32]), value[32], value[33], new(value[34..50]),
            BinaryPrimitives.ReadUInt16BigEndian(value[50..52]), new(value[52..84]),
            BinaryPrimitives.ReadUInt64BigEndian(value[84..92]), BinaryPrimitives.ReadUInt64BigEndian(value[92..100]),
            new(value[100..132]), BinaryPrimitives.ReadUInt64BigEndian(value[132..140]),
            BinaryPrimitives.ReadUInt64BigEndian(value[140..148])));

    internal static ReadOnlyCollection<XPointRoleKeyEntry> RoleKeys(ReadOnlySpan<byte> list) =>
        Materialize(list, 41, static value => new XPointRoleKeyEntry(
            value[0], BinaryPrimitives.ReadUInt64BigEndian(value[1..9]), new(value[9..41])));

    internal static ReadOnlyCollection<XPointCallReplicaEntry> CallReplicas(ReadOnlySpan<byte> list) =>
        Materialize(list, 200, static value => new XPointCallReplicaEntry(
            new(value[..32]), BinaryPrimitives.ReadUInt64BigEndian(value[32..40]), new(value[40..72]),
            new(value[72..104]), new(value[104..136]), new(value[136..200])));

    private delegate T SpanFactory<T>(ReadOnlySpan<byte> value);

    private static ReadOnlyCollection<T> Materialize<T>(ReadOnlySpan<byte> list, int width, SpanFactory<T> factory)
    {
        var output = new List<T>(list.Length / width);
        for (var offset = 0; offset < list.Length; offset += width)
            output.Add(factory(list.Slice(offset, width)));
        return output.AsReadOnly();
    }
}
