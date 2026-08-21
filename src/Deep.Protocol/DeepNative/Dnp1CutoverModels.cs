namespace Deep.Protocol.DeepNative;

public abstract class CanonicalCutoverArtifact
{
    private readonly byte[] _hash;

    internal CanonicalCutoverArtifact(
        OwnedRecord record,
        ArtifactType artifactType)
    {
        Record = record;
        ArtifactType = artifactType;
        _hash = CanonicalGrammar.ComputeReference(artifactType, record.CanonicalSpan)
            .CanonicalHash.ToArray();
    }

    internal OwnedRecord Record { get; }
    public ArtifactType ArtifactType { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => Record.CanonicalCopy();
    public ReadOnlyMemory<byte> CanonicalHash => _hash.ToArray();
}

public sealed class CutoverManifest : CanonicalCutoverArtifact
{
    internal CutoverManifest(OwnedRecord record) : base(record, ArtifactType.Dcm1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ReadOnlyMemory<byte> ResetId => Record.FieldCopy(2);
    public ulong ResetGeneration => Scalars.UInt64(Record.FieldSpan(3));
    public ulong AccountGeneration => Scalars.UInt64(Record.FieldSpan(4));
    public ulong ActivationAtUnixSeconds => Scalars.UInt64(Record.FieldSpan(14));
}

public sealed class AccountResetAuthorization : CanonicalCutoverArtifact
{
    internal AccountResetAuthorization(OwnedRecord record) : base(record, ArtifactType.Dra1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ulong OldAccountGeneration => Scalars.UInt64(Record.FieldSpan(2));
    public ulong NewAccountGeneration => Scalars.UInt64(Record.FieldSpan(9));
    public ulong CutoffAtUnixSeconds => Scalars.UInt64(Record.FieldSpan(13));
}

public sealed class WitnessDelegation : CanonicalCutoverArtifact
{
    internal WitnessDelegation(OwnedRecord record) : base(record, ArtifactType.Dwd1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ulong DelegationGeneration => Scalars.UInt64(Record.FieldSpan(2));
    public ulong WitnessEpoch => Scalars.UInt64(Record.FieldSpan(4));
    public ulong ValidFromUnixSeconds => Scalars.UInt64(Record.FieldSpan(5));
    public ulong ValidUntilUnixSeconds => Scalars.UInt64(Record.FieldSpan(6));
    public ulong MaximumTreeSize => Scalars.UInt64(Record.FieldSpan(9));
}

public sealed class ComponentCheckpoint : CanonicalCutoverArtifact
{
    internal ComponentCheckpoint(OwnedRecord record) : base(record, ArtifactType.Dcp1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ReadOnlyMemory<byte> ComponentSubject => Record.FieldCopy(2);
    public ushort ComponentKind => Scalars.UInt16(Record.FieldSpan(3));
    public ulong Sequence => Scalars.UInt64(Record.FieldSpan(4));
    public ulong AccountGeneration => Scalars.UInt64(Record.FieldSpan(6));
}

public sealed class DeploymentSet : CanonicalCutoverArtifact
{
    internal DeploymentSet(OwnedRecord record) : base(record, ArtifactType.Dcs1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ulong AccountGeneration => Scalars.UInt64(Record.FieldSpan(2));
    public ReadOnlyMemory<byte> ResetId => Record.FieldCopy(3);
    public ulong Sequence => Scalars.UInt64(Record.FieldSpan(4));
}

public sealed class CasTranscript : CanonicalCutoverArtifact
{
    internal CasTranscript(OwnedRecord record) : base(record, ArtifactType.Dct1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ReadOnlyMemory<byte> DeploymentSubject => Record.FieldCopy(2);
    public ulong ExpectedSequence => Scalars.UInt64(Record.FieldSpan(3));
}

public sealed class WitnessReceipt : CanonicalCutoverArtifact
{
    internal WitnessReceipt(OwnedRecord record) : base(record, ArtifactType.Dcn1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ReadOnlyMemory<byte> DeploymentSubject => Record.FieldCopy(2);
    public ulong Sequence => Scalars.UInt64(Record.FieldSpan(3));
    public ReadOnlyMemory<byte> WitnessId => Record.FieldCopy(14);
    public ulong TreeSize => Scalars.UInt64(Record.FieldSpan(17));
}

public sealed class QuorumReceipt : CanonicalCutoverArtifact
{
    internal QuorumReceipt(OwnedRecord record) : base(record, ArtifactType.Dcq1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ReadOnlyMemory<byte> DeploymentSubject => Record.FieldCopy(2);
    public ulong Sequence => Scalars.UInt64(Record.FieldSpan(3));
}

public sealed class HeadLease : CanonicalCutoverArtifact
{
    internal HeadLease(OwnedRecord record) : base(record, ArtifactType.Dhl1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ReadOnlyMemory<byte> DeploymentSubject => Record.FieldCopy(2);
    public ulong Sequence => Scalars.UInt64(Record.FieldSpan(3));
    public ReadOnlyMemory<byte> WitnessId => Record.FieldCopy(13);
}

public sealed class QuorumLease : CanonicalCutoverArtifact
{
    internal QuorumLease(OwnedRecord record) : base(record, ArtifactType.Dcl1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ReadOnlyMemory<byte> DeploymentSubject => Record.FieldCopy(2);
    public ulong Sequence => Scalars.UInt64(Record.FieldSpan(3));
    public ulong ExpiresAtUnixSeconds => Scalars.UInt64(Record.FieldSpan(13));
}

/// <summary>Signed manifest bytes only; this type carries no deployment-root authority.</summary>
public sealed class ReleaseRootManifest : CanonicalCutoverArtifact
{
    internal ReleaseRootManifest(OwnedRecord record) : base(record, ArtifactType.Rrm1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ulong ActivationAtUnixSeconds => Scalars.UInt64(Record.FieldSpan(6));
    public ReadOnlyMemory<byte> ManifestSignerKeyId => Record.FieldCopy(9);
}

/// <summary>Witness termination evidence bytes only; this type carries no activation authority.</summary>
public sealed class WitnessTermination : CanonicalCutoverArtifact
{
    internal WitnessTermination(OwnedRecord record) : base(record, ArtifactType.Dwt1) { }
    public ReadOnlyMemory<byte> NetworkId => Record.FieldCopy(1);
    public ulong WitnessEpoch => Scalars.UInt64(Record.FieldSpan(3));
    public ulong EffectiveAtUnixSeconds => Scalars.UInt64(Record.FieldSpan(7));
}
