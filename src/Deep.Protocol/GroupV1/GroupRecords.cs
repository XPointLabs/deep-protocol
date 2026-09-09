using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.GroupV1;

/// <summary>Closed roles for the owner-sequenced DeepSmallGroupV1 profile.</summary>
public enum GroupRole : byte { Owner = 1, Admin = 2, Member = 3 }
public enum GroupProposalAction : ushort { ActivateAcceptedInvite = 1, RemoveAccount = 2, ChangeRole = 3, AddDevice = 4, RemoveDevice = 5, ChangeProfile = 6, TransferOwnerDevice = 7, LeaveAccount = 8 }
public enum GroupApplicationEventKind : ushort { Text = 1, Edit = 2, Delete = 3, Reaction = 4, Receipt = 5, Attachment = 6, ProfileNotice = 7 }

public sealed class GroupArtifactReference
{
    private readonly byte[] hash;
    internal GroupArtifactReference(string magic, ReadOnlySpan<byte> hash) { Magic = magic; this.hash = hash.ToArray(); }
    public string Magic { get; }
    public ReadOnlyMemory<byte> Hash => hash.ToArray();
    public ReadOnlyMemory<byte> CanonicalBytes
    {
        get
        {
            var value = new byte[38];
            System.Text.Encoding.ASCII.GetBytes(Magic).CopyTo(value, 0);
            value[5] = 1;
            hash.CopyTo(value, 6);
            return value;
        }
    }
}

public class GroupRecord
{
    private readonly byte[] canonical;
    private readonly byte[][] fields;
    private readonly int signatureTag;
    private readonly string? signatureDomain;
    private readonly int[] tags;
    internal GroupRecord(string magic, byte[] canonical, byte[][] fields, int signatureTag, string? signatureDomain, int[]? tags = null)
    {
        Magic = magic; this.canonical = canonical; this.fields = fields;
        this.signatureTag = signatureTag; this.signatureDomain = signatureDomain;
        this.tags = tags?.ToArray() ?? Enumerable.Range(1, fields.Length).ToArray();
    }
    public string Magic { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    /// <summary>The normative domain-separated application record hash.</summary>
    public ReadOnlyMemory<byte> ArtifactHash => GroupCodec.RecordHash(Magic, canonical);
    public ReadOnlyMemory<byte> Field(int tag) => FieldSpan(tag).ToArray();
    internal ReadOnlySpan<byte> FieldSpan(int tag)
    {
        var index = Array.IndexOf(tags, tag);
        if (index < 0) throw new ArgumentOutOfRangeException(nameof(tag));
        return fields[index];
    }
    internal IReadOnlyList<int> Tags => tags;
    public bool HasDeviceSignature => signatureTag != 0;
    public ReadOnlyMemory<byte> SigningProjection => signatureTag == 0 ? throw new InvalidOperationException("This record has no device signature.") : GroupCodec.Project(this, tags.Where(tag => tag != signatureTag).ToArray());
    public ReadOnlyMemory<byte> SignatureInput => signatureDomain is null ? throw new InvalidOperationException("This record has no device signature.") : GroupCodec.SignatureInput(signatureDomain, SigningProjection.Span);
}

public sealed class GroupInvitationRecord : GroupRecord { internal GroupInvitationRecord(byte[] c, byte[][] f) : base(ProtocolMagic.GIV1, c, f, 18, "Deep/Group/V1/invitation") { } }
public sealed class GroupInvitationAcceptanceRecord : GroupRecord { internal GroupInvitationAcceptanceRecord(byte[] c, byte[][] f) : base(ProtocolMagic.GIA1, c, f, 15, "Deep/Group/V1/invitation-acceptance") { } }
public sealed class GroupProposalRecord : GroupRecord { internal GroupProposalRecord(byte[] c, byte[][] f) : base(ProtocolMagic.DGP1, c, f, 13, "Deep/Group/V1/proposal") { } }
public sealed class GroupCommitRecord : GroupRecord { internal GroupCommitRecord(byte[] c, byte[][] f) : base(ProtocolMagic.DGC1, c, f, 17, "Deep/Group/V1/commit") { } }
public sealed class GroupEmergencyTransferRecord : GroupRecord { internal GroupEmergencyTransferRecord(byte[] c, byte[][] f) : base(ProtocolMagic.DGT1, c, f, 14, "Deep/Group/V1/emergency-sequencer-transfer") { } }
public sealed class GroupApplicationMessageRecord : GroupRecord { internal GroupApplicationMessageRecord(byte[] c, byte[][] f) : base(ProtocolMagic.DGM1, c, f, 0, null) { } }
public sealed class GroupCommitPackageRecord : GroupRecord { internal GroupCommitPackageRecord(byte[] c, byte[][] f) : base(ProtocolMagic.GCP1, c, f, 0, null) { } }
public sealed class GroupCommitChunkRecord : GroupRecord { internal GroupCommitChunkRecord(byte[] c, byte[][] f) : base(ProtocolMagic.GCF1, c, f, 0, null) { } }
public sealed class GroupControlRendezvousRecord : GroupRecord { internal GroupControlRendezvousRecord(byte[] c, byte[][] f) : base(ProtocolMagic.GSR1, c, f, 14, "Deep/Group/V1/control-rendezvous") { } }
public sealed class GroupControlWriteRecord : GroupRecord { internal GroupControlWriteRecord(byte[] c, byte[][] f) : base(ProtocolMagic.GSW1, c, f, 0, null, [1,2,3,4,5,6,16,17,18,19,20,21,22]) { } }
public sealed class GroupControlQueryRecord : GroupRecord { internal GroupControlQueryRecord(byte[] c, byte[][] f) : base(ProtocolMagic.GSQ1, c, f, 0, null, [1,2,3,4,5,6,16,17,18,19,20]) { } }
public sealed class GroupControlResultRecord : GroupRecord { internal GroupControlResultRecord(byte[] c, byte[][] f) : base(ProtocolMagic.GSS1, c, f, 0, null, [1,2,3,4,5,6,7,8,16,17,18,19,20]) { } }

/// <summary>Non-forgeable, current-identity-verified GSR1 rendezvous.</summary>
public sealed class VerifiedGroupControlRendezvous
{
    internal VerifiedGroupControlRendezvous(GroupControlRendezvousRecord record, VerifiedContactBundleClosure owner)
    { Record = record; Owner = owner; }
    public GroupControlRendezvousRecord Record { get; }
    public VerifiedContactBundleClosure Owner { get; }
}

public interface IGroupClosureResolver { ReadOnlyMemory<byte>? Resolve(GroupArtifactReference reference); }
public sealed class GroupFormatException(GroupValidationStage stage, string code) : FormatException(code) { public GroupValidationStage Stage { get; } = stage; public string Code { get; } = code; }
public enum GroupValidationStage { Length, Header, FieldScan, Bounds, Scalar, Reference, Signature, Closure, Transition }

public enum GroupLineageDisposition
{
    AcceptedGenesis = 1,
    AcceptedSuccessor = 2,
    ExactReplay = 3,
    ForkLatched = 4,
}

/// <summary>A fully verified owner-sequenced state transition.</summary>
public abstract class VerifiedGroupTransition
{
    private readonly byte[] exactVerifiedGcp1Sha256;

    private protected VerifiedGroupTransition(
        GroupCommitRecord commit,
        GroupCommitRecord? predecessor,
        ReadOnlySpan<byte> exactCanonicalGcp1Bytes)
    {
        Commit = commit;
        Predecessor = predecessor;
        exactVerifiedGcp1Sha256 = System.Security.Cryptography.SHA256.HashData(exactCanonicalGcp1Bytes);
    }

    public GroupCommitRecord Commit { get; }
    public GroupCommitRecord? Predecessor { get; }

    /// <summary>
    /// Exact SHA-256 of the canonical GCP1 bytes that produced this verified
    /// transition. The verifier capability, rather than caller-supplied package
    /// bytes, is the authority for this binding.
    /// </summary>
    public ReadOnlyMemory<byte> ExactVerifiedGcp1Sha256 => exactVerifiedGcp1Sha256.ToArray();

    /// <summary>Checks whether bytes are the exact GCP1 package promoted by this verifier result.</summary>
    public bool BindsExactGcp1(ReadOnlySpan<byte> candidateCanonicalGcp1Bytes)
    {
        Span<byte> candidateSha256 = stackalloc byte[32];
        System.Security.Cryptography.SHA256.HashData(candidateCanonicalGcp1Bytes, candidateSha256);
        return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
            exactVerifiedGcp1Sha256, candidateSha256);
    }
}

/// <summary>
/// Non-authoring input to group verification.  Values can only be promoted
/// from the public Contact verifier's non-forgeable current-directory result.
/// Base and current sets are distinct so removal and replacement verify both
/// sides of every DMD1 lineage instead of trusting only the resulting state.
/// </summary>
public sealed class GroupIdentityClosure
{
    private readonly VerifiedContactBundleClosure[] baseDirectories;
    private readonly VerifiedContactBundleClosure[] currentDirectories;
    private readonly byte[] currentBootId;

    private GroupIdentityClosure(
        IReadOnlyList<VerifiedContactBundleClosure> baseDirectories,
        IReadOnlyList<VerifiedContactBundleClosure> currentDirectories,
        ReadOnlySpan<byte> currentBootId,
        ulong currentMonotonicSample)
    {
        this.baseDirectories = Copy(baseDirectories, nameof(baseDirectories));
        this.currentDirectories = Copy(currentDirectories, nameof(currentDirectories));
        if (this.currentDirectories.Length == 0)
            throw new ArgumentException("At least one current verified directory is required.", nameof(currentDirectories));
        if (currentBootId.Length != 16 || currentBootId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException(
                "The current monotonic boot ID must be exactly 16 non-zero bytes.", nameof(currentBootId));
        this.currentBootId = currentBootId.ToArray();
        CurrentMonotonicSample = currentMonotonicSample;
    }

    public static GroupIdentityClosure FromVerifiedContactDirectories(
        IReadOnlyList<VerifiedContactBundleClosure> baseDirectories,
        IReadOnlyList<VerifiedContactBundleClosure> currentDirectories,
        ReadOnlySpan<byte> currentBootId,
        ulong currentMonotonicSample) =>
        new(baseDirectories, currentDirectories, currentBootId, currentMonotonicSample);

    internal IReadOnlyList<VerifiedContactBundleClosure> BaseDirectories => baseDirectories;
    internal IReadOnlyList<VerifiedContactBundleClosure> CurrentDirectories => currentDirectories;
    internal ReadOnlySpan<byte> CurrentBootId => currentBootId;
    internal ulong CurrentMonotonicSample { get; }

    private static VerifiedContactBundleClosure[] Copy(
        IReadOnlyList<VerifiedContactBundleClosure> values, string parameter)
    {
        ArgumentNullException.ThrowIfNull(values, parameter);
        return values.Select(value => value ??
            throw new ArgumentException("A null verified contact directory is not allowed.", parameter)).ToArray();
    }
}
