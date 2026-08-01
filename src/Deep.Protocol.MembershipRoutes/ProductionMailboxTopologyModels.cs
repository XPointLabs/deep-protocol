using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

public static class ProductionMailboxTopologyConstants
{
    public const string TopologySchema = "production-mailbox-topology.v1";
    public const string SelectionSchema = "production-mailbox-selection.v1";
    public const byte Version = 1;
    public const int HashLength = 32;
    public const int NodeIdLength = 32;
    public const int MaximumNodesPerEpoch = 4_096;
    public const int MaximumEndpointBytes = 512;
    public const int ReplicaCount = 2;
    public const int NetworkIdLength = 16;
    public const int SignatureLength = 64;
    public const int MaximumClockSkewSeconds = 300;
    public const ulong MaximumArtifactLifetimeSeconds = 86_400;
    public const int MaximumTopologyArtifactBytes = 4_997_504;
    public const int MaximumSelectionArtifactBytes = 8_808;
}

public enum ProductionMailboxSelectionAlgorithm : byte
{
    RendezvousSha256V1 = 1
}

public enum ProductionMailboxTopologyError
{
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    ReservedFieldNotZero,
    InvalidField,
    InvalidOrder,
    InvalidEndpoint,
    InvalidPinSet,
    InvalidValidityWindow,
    NonCanonical,
    AuthorityMismatch,
    AuthorityExpired,
    TopologyRollback,
    PreviousHashMismatch,
    TopologyMismatch,
    SelectionMismatch,
    InvalidMembershipProof,
    InvalidSignature,
    NotYetValid,
    Expired
}

public sealed class ProductionMailboxTopologyException(
    ProductionMailboxTopologyError error,
    string message) : Exception(message)
{
    public ProductionMailboxTopologyError Error { get; } = error;
}

public sealed record ProductionMailboxTopologyNode
{
    public required ReadOnlyMemory<byte> NodeId { get; init; }
    public required string HttpsEndpoint { get; init; }
    public required ReadOnlyMemory<byte> CurrentSpkiSha256 { get; init; }
    public required ReadOnlyMemory<byte> NextSpkiSha256 { get; init; }
}

public sealed record ProductionMailboxTopologyEpoch
{
    public required ulong Epoch { get; init; }
    public required ulong Generation { get; init; }
    public required ReadOnlyMemory<byte> MembershipCommitment { get; init; }
    public required ReadOnlyMemory<byte> PlacementCommitment { get; init; }
    public required ulong NotBeforeUnixSeconds { get; init; }
    public required ulong NotAfterUnixSeconds { get; init; }
    public required IReadOnlyList<ProductionMailboxTopologyNode> Nodes { get; init; }
}

public sealed record ProductionMailboxTopologySnapshot
{
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ulong AuthorityGeneration { get; init; }
    public required ReadOnlyMemory<byte> CanonicalAuthorityHash { get; init; }
    public required ulong TopologyGeneration { get; init; }
    public required ReadOnlyMemory<byte> PreviousTopologyHash { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required ProductionMailboxTopologyEpoch CurrentEpoch { get; init; }
    public required ProductionMailboxTopologyEpoch NextEpoch { get; init; }
    public required ReadOnlyMemory<byte> IssuerSignature { get; init; }
}

public sealed record ProductionMailboxTopologyVerificationContext
{
    public required ulong LastCommittedTopologyGeneration { get; init; }
    public required ReadOnlyMemory<byte> LastCommittedTopologyHash { get; init; }
    public required ulong NowUnixSeconds { get; init; }
    public uint ClockSkewSeconds { get; init; }
}

public sealed record ProductionMailboxSelectionReplica
{
    public required ReadOnlyMemory<byte> ReplicaId { get; init; }
    /// <summary>Exact canonical MIP1 containing a canonical RIP1 route inclusion proof.</summary>
    public required ReadOnlyMemory<byte> CanonicalMIP1Proof { get; init; }
}

public sealed record ProductionMailboxSelectionProof
{
    public required ProductionMailboxSelectionAlgorithm Algorithm { get; init; }
    public required ReadOnlyMemory<byte> NetworkId { get; init; }
    public required ulong AuthorityGeneration { get; init; }
    public required ReadOnlyMemory<byte> CanonicalAuthorityHash { get; init; }
    public required ulong TopologyGeneration { get; init; }
    public required ReadOnlyMemory<byte> CanonicalTopologyHash { get; init; }
    public required ulong Epoch { get; init; }
    public required ulong Generation { get; init; }
    public required ReadOnlyMemory<byte> MembershipCommitment { get; init; }
    public required ReadOnlyMemory<byte> PlacementCommitment { get; init; }
    public required ReadOnlyMemory<byte> SelectionInputCommitment { get; init; }
    public required ulong IssuedAtUnixSeconds { get; init; }
    public required ulong ExpiresAtUnixSeconds { get; init; }
    public required IReadOnlyList<ProductionMailboxSelectionReplica> Replicas { get; init; }
    public required ReadOnlyMemory<byte> IssuerSignature { get; init; }
}

public interface IProductionMailboxTopologySignatureVerifier
{
    bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature);
}

public sealed class SodiumProductionMailboxTopologySignatureVerifier : IProductionMailboxTopologySignatureVerifier
{
    private readonly SodiumProductionMailboxRevocationSnapshotSignatureVerifier _inner = new();

    public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> signature) =>
        _inner.Verify(publicKey, signingBytes, signature);
}

public sealed class VerifiedProductionMailboxTopology
{
    private readonly ProductionMailboxTopologySnapshot _snapshot;
    private readonly byte[] _canonicalHash;

    internal VerifiedProductionMailboxTopology(ProductionMailboxTopologySnapshot snapshot, ReadOnlySpan<byte> canonicalHash)
    {
        _snapshot = ProductionMailboxTopologyCopy.Clone(snapshot);
        _canonicalHash = canonicalHash.ToArray();
    }

    public ProductionMailboxTopologySnapshot Snapshot => ProductionMailboxTopologyCopy.Clone(_snapshot);
    public ReadOnlyMemory<byte> CanonicalTopologyHash => _canonicalHash.ToArray();
    public ulong CommittedTopologyGeneration => _snapshot.TopologyGeneration;
    internal ProductionMailboxTopologySnapshot TrustedSnapshot => _snapshot;
    internal ReadOnlySpan<byte> TrustedCanonicalHash => _canonicalHash;
}

public sealed record VerifiedProductionMailboxSelectedReplica
{
    public required ReadOnlyMemory<byte> ReplicaId { get; init; }
    public required ReadOnlyMemory<byte> CanonicalMIP1Proof { get; init; }
    public required Uri HttpsEndpoint { get; init; }
    public required ReadOnlyMemory<byte> CurrentSpkiSha256 { get; init; }
    public required ReadOnlyMemory<byte> NextSpkiSha256 { get; init; }
}

public sealed class VerifiedProductionMailboxSelection
{
    private readonly ProductionMailboxSelectionProof _proof;
    private readonly VerifiedProductionMailboxSelectedReplica[] _replicas;
    private readonly byte[] _canonicalHash;

    internal VerifiedProductionMailboxSelection(
        ProductionMailboxSelectionProof proof,
        IReadOnlyList<VerifiedProductionMailboxSelectedReplica> replicas,
        ReadOnlySpan<byte> canonicalHash)
    {
        _proof = ProductionMailboxTopologyCopy.Clone(proof);
        _replicas = replicas.Select(ProductionMailboxTopologyCopy.Clone).ToArray();
        _canonicalHash = canonicalHash.ToArray();
    }

    public ProductionMailboxSelectionProof Proof => ProductionMailboxTopologyCopy.Clone(_proof);
    public IReadOnlyList<VerifiedProductionMailboxSelectedReplica> Replicas =>
        _replicas.Select(ProductionMailboxTopologyCopy.Clone).ToArray();
    public ReadOnlyMemory<byte> CanonicalSelectionHash => _canonicalHash.ToArray();
}

internal static class ProductionMailboxTopologyCopy
{
    public static ProductionMailboxTopologySnapshot Clone(ProductionMailboxTopologySnapshot value) => new()
    {
        NetworkId = value.NetworkId.ToArray(),
        AuthorityGeneration = value.AuthorityGeneration,
        CanonicalAuthorityHash = value.CanonicalAuthorityHash.ToArray(),
        TopologyGeneration = value.TopologyGeneration,
        PreviousTopologyHash = value.PreviousTopologyHash.ToArray(),
        IssuedAtUnixSeconds = value.IssuedAtUnixSeconds,
        ExpiresAtUnixSeconds = value.ExpiresAtUnixSeconds,
        CurrentEpoch = Clone(value.CurrentEpoch),
        NextEpoch = Clone(value.NextEpoch),
        IssuerSignature = value.IssuerSignature.ToArray()
    };

    public static ProductionMailboxTopologyEpoch Clone(ProductionMailboxTopologyEpoch value) => new()
    {
        Epoch = value.Epoch,
        Generation = value.Generation,
        MembershipCommitment = value.MembershipCommitment.ToArray(),
        PlacementCommitment = value.PlacementCommitment.ToArray(),
        NotBeforeUnixSeconds = value.NotBeforeUnixSeconds,
        NotAfterUnixSeconds = value.NotAfterUnixSeconds,
        Nodes = value.Nodes.Select(Clone).ToArray()
    };

    public static ProductionMailboxTopologyNode Clone(ProductionMailboxTopologyNode value) => new()
    {
        NodeId = value.NodeId.ToArray(),
        HttpsEndpoint = value.HttpsEndpoint,
        CurrentSpkiSha256 = value.CurrentSpkiSha256.ToArray(),
        NextSpkiSha256 = value.NextSpkiSha256.ToArray()
    };

    public static ProductionMailboxSelectionProof Clone(ProductionMailboxSelectionProof value) => new()
    {
        Algorithm = value.Algorithm,
        NetworkId = value.NetworkId.ToArray(),
        AuthorityGeneration = value.AuthorityGeneration,
        CanonicalAuthorityHash = value.CanonicalAuthorityHash.ToArray(),
        TopologyGeneration = value.TopologyGeneration,
        CanonicalTopologyHash = value.CanonicalTopologyHash.ToArray(),
        Epoch = value.Epoch,
        Generation = value.Generation,
        MembershipCommitment = value.MembershipCommitment.ToArray(),
        PlacementCommitment = value.PlacementCommitment.ToArray(),
        SelectionInputCommitment = value.SelectionInputCommitment.ToArray(),
        IssuedAtUnixSeconds = value.IssuedAtUnixSeconds,
        ExpiresAtUnixSeconds = value.ExpiresAtUnixSeconds,
        Replicas = value.Replicas.Select(Clone).ToArray(),
        IssuerSignature = value.IssuerSignature.ToArray()
    };

    public static ProductionMailboxSelectionReplica Clone(ProductionMailboxSelectionReplica value) => new()
    {
        ReplicaId = value.ReplicaId.ToArray(),
        CanonicalMIP1Proof = value.CanonicalMIP1Proof.ToArray()
    };

    public static VerifiedProductionMailboxSelectedReplica Clone(VerifiedProductionMailboxSelectedReplica value) => new()
    {
        ReplicaId = value.ReplicaId.ToArray(),
        CanonicalMIP1Proof = value.CanonicalMIP1Proof.ToArray(),
        HttpsEndpoint = new Uri(value.HttpsEndpoint.AbsoluteUri, UriKind.Absolute),
        CurrentSpkiSha256 = value.CurrentSpkiSha256.ToArray(),
        NextSpkiSha256 = value.NextSpkiSha256.ToArray()
    };
}
