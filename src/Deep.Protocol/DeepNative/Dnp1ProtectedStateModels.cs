namespace Deep.Protocol.DeepNative;

/// <summary>Canonical protected-state bytes only. This carry model is not an authority or durability claim.</summary>
public abstract class CanonicalProtectedState
{
    private readonly byte[] _hash;

    internal CanonicalProtectedState(OwnedRecord record, ArtifactType artifactType)
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

public sealed class ProtectedLocalPin : CanonicalProtectedState
{
    internal ProtectedLocalPin(OwnedRecord value) : base(value, ArtifactType.Dpl1) { }
    public ComponentKind ComponentKind => (ComponentKind)Scalars.UInt16(Record.FieldSpan(2));
    public ulong AccountGeneration => Scalars.UInt64(Record.FieldSpan(3));
}

public sealed class ProtectedBootstrapGuard : CanonicalProtectedState
{
    internal ProtectedBootstrapGuard(OwnedRecord value) : base(value, ArtifactType.Dbg1) { }
    public ComponentKind ComponentKind => (ComponentKind)Scalars.UInt16(Record.FieldSpan(2));
}

public sealed class RegistryIdentityBinding : CanonicalProtectedState
{
    internal RegistryIdentityBinding(OwnedRecord value) : base(value, ArtifactType.Rib1) { }
}

public sealed class XNodeIdentityBinding : CanonicalProtectedState
{
    internal XNodeIdentityBinding(OwnedRecord value) : base(value, ArtifactType.Xib1) { }
}

public sealed class WitnessLastKnownGood : CanonicalProtectedState
{
    internal WitnessLastKnownGood(OwnedRecord value) : base(value, ArtifactType.Dwl1) { }
    public ulong Sequence => Scalars.UInt64(Record.FieldSpan(7));
    public ulong LeaseExpiresAtUnixSeconds => Scalars.UInt64(Record.FieldSpan(11));
}

public sealed class MembershipRoutingLastKnownGood : CanonicalProtectedState
{
    internal MembershipRoutingLastKnownGood(OwnedRecord value) : base(value, ArtifactType.Mrlc) { }
    public uint MemberCount => System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(Record.FieldSpan(13));
}

public sealed class OuterPeerJournalRecord : CanonicalProtectedState
{
    internal OuterPeerJournalRecord(OwnedRecord value) : base(value, ArtifactType.Dpj1) { }
    public JournalPhase Phase => (JournalPhase)Record.FieldSpan(11)[0];
    public bool DeliveryAuthorized => Record.FieldSpan(12)[0] == 1;
    public bool TerminalStale => Record.FieldSpan(13)[0] == 1;
}

public sealed class ReleaseRootLastKnownGood : CanonicalProtectedState
{
    internal ReleaseRootLastKnownGood(OwnedRecord value) : base(value, ArtifactType.Rrl1) { }
    public ulong CurrentGeneration => Scalars.UInt64(Record.FieldSpan(3));
    public bool Terminal => Record.FieldSpan(7)[0] == 1;
    public bool ForkLatched => Record.FieldSpan(8)[0] == 1;
}
