using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.GroupV1;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.DeepExtension.PrivacyRouting;

public static class OnionLimits
{
    public const int RouteHopCount = 3;
    public const int DefaultPaddingBlockBytes = 4_096;
    public const int MinimumPaddingBlockBytes = 256;
    public const int MaximumPaddingBlockBytes = 65_536;
    public const int MinimumFrameBytes = 176;
    public const int MaximumFrameBytes = 1_572_864;
    public const int MaximumCanonicalRequestBytes = 1_048_576;
    public const int MaximumContactResolverRequestBytes = 69_649;
    public const int MaximumContactResolverResponseBytes = 131_072;
    public const int MaximumGroupControlRequestBytes = 33_160;
    public const int MaximumGroupControlResponseBytes = 65_535;
}

public enum OnionOperation : byte
{
    Store = 1,
    Retrieve = 2,
    Acknowledge = 3,
    ContactResolve = 4,
    GroupControl = 5
}

public enum OnionReceivePosition : byte
{
    Ingress = 1,
    Core = 2,
    Exit = 3
}

public enum OnionNextHopTransport : byte
{
    TcpTls = 1,
    QuicTls = 2
}

public enum OnionNextHopAddressFamily : byte
{
    IPv4 = 4,
    IPv6 = 6
}

public enum OnionTerminalResultKind : byte { Success = 1, Failure = 2 }

public enum OnionFailureCode : ushort
{
    MalformedRequest = 1,
    AuthenticationRejected = 2,
    AuthorizationRejected = 3,
    ReplayRejected = 4,
    MailboxNotFound = 5,
    Conflict = 6,
    CapacityExceeded = 7,
    Unavailable = 8,
    OutcomeUnknown = 9,
    InternalFailure = 10
}

public enum OnionEntropyCommitOutcome { Committed = 1, Duplicate = 2, Rejected = 3, Ambiguous = 4 }
public enum OnionReplayCommitOutcome { Committed = 1, Replayed = 2, Saturated = 3, Rejected = 4, Ambiguous = 5 }

public sealed class OnionBoundaryException : Exception
{
    internal OnionBoundaryException(string code, string message, Exception? inner = null) : base(message, inner) => Code = code;
    public string Code { get; }
}

/// <summary>An immutable batch of hashes. CommitAsync must atomically and durably reserve all hashes or none.</summary>
public sealed class OnionEntropyCommitmentBatch
{
    private readonly byte[][] _commitments;

    internal OnionEntropyCommitmentBatch(bool response, IEnumerable<byte[]> commitments)
    {
        IsResponse = response;
        _commitments = commitments.Select(static value => value.ToArray()).ToArray();
    }

    public bool IsResponse { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> Commitments =>
        Array.AsReadOnly(_commitments.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
}

public interface IOnionEntropyUniquenessLedger
{
    ValueTask<OnionEntropyCommitOutcome> CommitAsync(
        OnionEntropyCommitmentBatch batch,
        CancellationToken cancellationToken);
}

/// <summary>
/// Opaque-key host adapter. The returned fresh 32-byte shared-secret array transfers ownership
/// to Protocol and is zeroized before the call completes. Raw private key bytes never cross this API.
/// </summary>
public interface IOnionKeyAgreementVault
{
    ValueTask<byte[]> DeriveX25519SharedSecretAsync(
        OnionKeyHandle keyHandle,
        ReadOnlyMemory<byte> peerPublicKey,
        CancellationToken cancellationToken);
}

public interface IOnionDurableReplayTransaction : IAsyncDisposable
{
    ValueTask<OnionReplayCommitOutcome> CommitAsync(
        ReadOnlyMemory<byte> replayId,
        CancellationToken cancellationToken);
}

public interface IOnionDurableReplayStore
{
    ValueTask<IOnionDurableReplayTransaction> BeginAsync(
        OnionReplayScope scope,
        CancellationToken cancellationToken);
}

public sealed class OnionReplayScope
{
    private readonly byte[] _networkId, _ownerId, _keyId, _keyHandleId, _frameHash, _bootId;
    internal OnionReplayScope(VerifiedOnionReceiveContext receive, ReadOnlySpan<byte> frameHash)
    {
        _networkId = receive.Network.NetworkIdSpan.ToArray();
        _ownerId = receive.LocalHop.RouterOwnerIdSpan.ToArray();
        _keyId = receive.LocalHop.KeyIdSpan.ToArray();
        _keyHandleId = receive.KeyHandle.IdSpan.ToArray();
        _frameHash = frameHash.ToArray();
        _bootId = receive.TrustedTime.BootIdSpan.ToArray();
        Epoch = receive.LocalHop.Epoch;
        Position = receive.Position;
    }
    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> RouterOwnerId => _ownerId.ToArray();
    public ReadOnlyMemory<byte> KeyId => _keyId.ToArray();
    public ReadOnlyMemory<byte> KeyHandleId => _keyHandleId.ToArray();
    public ReadOnlyMemory<byte> ExactFrameHash => _frameHash.ToArray();
    public ReadOnlyMemory<byte> BootId => _bootId.ToArray();
    public ulong Epoch { get; }
    public OnionReceivePosition Position { get; }
}

public sealed class OnionReplayAuthority
{
    private readonly IOnionDurableReplayStore _store;
    public OnionReplayAuthority(IOnionDurableReplayStore store) =>
        _store = store ?? throw new ArgumentNullException(nameof(store));

    public async ValueTask<OnionReplayOpenLease> BeginOpenAsync(
        VerifiedOnionReceiveContext receive,
        ReadOnlyMemory<byte> exactFrame,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receive);
        cancellationToken.ThrowIfCancellationRequested();
        receive.TrustedTime.EnsureLive();
        var frameHash = SHA256.HashData(exactFrame.Span);
        try
        {
            var ephemeral = PrivacyRoutingWire.ReadBoundRequestEphemeral(exactFrame.Span, receive);
            CryptographicOperations.ZeroMemory(ephemeral);
            IOnionDurableReplayTransaction transaction;
            try
            {
                transaction = await _store.BeginAsync(new OnionReplayScope(receive, frameHash), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception exception)
            {
                throw new OnionBoundaryException("replay-begin-failed", "The durable replay transaction could not be started.", exception);
            }
            if (transaction is null)
                throw new OnionBoundaryException("replay-begin-failed", "The durable replay store returned no transaction.");
            return new OnionReplayOpenLease(receive, frameHash, transaction);
        }
        finally { CryptographicOperations.ZeroMemory(frameHash); }
    }
}

public sealed class OnionKeyAgreementAuthority
{
    private readonly IOnionKeyAgreementVault _vault;
    public OnionKeyAgreementAuthority(IOnionKeyAgreementVault vault) =>
        _vault = vault ?? throw new ArgumentNullException(nameof(vault));

    public OnionKeyHandle BindKeyHandle(ReadOnlyMemory<byte> opaqueKeyHandleId) =>
        new(opaqueKeyHandleId.Span);

    internal ValueTask<byte[]> DeriveAsync(
        OnionKeyHandle handle,
        ReadOnlyMemory<byte> peerPublicKey,
        CancellationToken cancellationToken) =>
        _vault.DeriveX25519SharedSecretAsync(handle, peerPublicKey, cancellationToken);
}

public sealed class OnionKeyHandle
{
    private readonly byte[] _id;
    internal OnionKeyHandle(ReadOnlySpan<byte> id)
    {
        PrivacyRoutingWire.ValidateId(id, PrivacyRoutingProtocolError.InvalidIdentifier, "key handle id");
        _id = id.ToArray();
    }
    public ReadOnlyMemory<byte> Id => _id.ToArray();
    internal ReadOnlySpan<byte> IdSpan => _id;
}

public sealed class OnionTrustedTimeLease
{
    private readonly TimeProvider _timeProvider;
    private readonly long _createdTimestamp;
    private readonly TimeSpan _lifetime;
    private readonly byte[] _bootId;

    internal OnionTrustedTimeLease(TimeProvider timeProvider, TimeSpan lifetime, ReadOnlySpan<byte> bootId)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        if (lifetime <= TimeSpan.Zero || lifetime > PrivacyRoutingLimits.ReplyContextLifetime)
            throw new ArgumentOutOfRangeException(nameof(lifetime));
        PrivacyRoutingWire.ValidateId(bootId, PrivacyRoutingProtocolError.InvalidIdentifier, "trusted boot id");
        _timeProvider = timeProvider;
        _createdTimestamp = timeProvider.GetTimestamp();
        _lifetime = lifetime;
        _bootId = bootId.ToArray();
    }

    internal TimeProvider TimeProvider => _timeProvider;
    internal ReadOnlySpan<byte> BootIdSpan => _bootId;
    internal TimeSpan Remaining
    {
        get
        {
            var elapsed = _timeProvider.GetElapsedTime(_createdTimestamp);
            return elapsed < TimeSpan.Zero ? TimeSpan.Zero : _lifetime - elapsed;
        }
    }

    internal void EnsureLive()
    {
        if (Remaining <= TimeSpan.Zero)
            throw new OnionBoundaryException("trusted-time-expired", "The verified ONION trusted-time lease has expired.");
    }
}

public sealed class OnionMonotonicReading
{
    private readonly byte[] _bootId;
    public OnionMonotonicReading(ReadOnlySpan<byte> bootId, ulong sampleSeconds)
    {
        if (bootId.Length != 16 || PrivacyRoutingWire.IsZero(bootId))
            throw new ArgumentException("The monotonic boot id must be nonzero 16 bytes.", nameof(bootId));
        _bootId = bootId.ToArray();
        SampleSeconds = sampleSeconds;
    }
    public ReadOnlyMemory<byte> BootId => _bootId.ToArray();
    public ulong SampleSeconds { get; }
}

public interface IOnionMonotonicClock
{
    ValueTask<OnionMonotonicReading> ReadAsync(CancellationToken cancellationToken);
}

public sealed class OnionTrustedTimeAuthority
{
    private readonly IOnionMonotonicClock _clock;
    public OnionTrustedTimeAuthority(IOnionMonotonicClock clock) =>
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));

    internal async ValueTask<OnionMonotonicReading> ReadCurrentAsync(CancellationToken cancellationToken)
    {
        var reading = await _clock.ReadAsync(cancellationToken).ConfigureAwait(false);
        return reading ?? throw new OnionBoundaryException(
            "trusted-time-invalid", "The protected monotonic clock returned no current reading.");
    }

    internal async ValueTask<OnionTrustedTimeLease> MintAsync(
        VerifiedAccountDirectoryFreshness freshness,
        ulong hardUpperUnixSeconds,
        CancellationToken cancellationToken)
    {
        var reading = await ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(reading.BootId.Span, freshness.BootId.Span) ||
            reading.SampleSeconds < freshness.MonotonicSample ||
            reading.SampleSeconds >= freshness.FreshnessDeadlineMonotonicSeconds)
            throw new OnionBoundaryException("trusted-time-invalid", "The protected monotonic clock does not keep the verified DTT1 closure current.");
        if (hardUpperUnixSeconds <= freshness.TrustedUpperUnixSeconds)
            throw new OnionBoundaryException("trusted-time-invalid", "The verified network closure has no remaining admissible interval.");
        var remainingSeconds = Math.Min(
            freshness.FreshnessDeadlineMonotonicSeconds - reading.SampleSeconds,
            hardUpperUnixSeconds - freshness.TrustedUpperUnixSeconds);
        var lifetime = TimeSpan.FromSeconds(Math.Min(remainingSeconds, (ulong)PrivacyRoutingLimits.ReplyContextLifetime.TotalSeconds));
        return new OnionTrustedTimeLease(TimeProvider.System, lifetime, ExpandBootId(reading.BootId.Span));
    }

    private static byte[] ExpandBootId(ReadOnlySpan<byte> bootId) =>
        PrivacyRoutingWire.Sha256Domain("Deep/XPoint/V1/monotonic-boot-id", bootId.ToArray());
}

public sealed class VerifiedOnionNetworkContext
{
    private readonly byte[] _networkId;
    private readonly IReadOnlyDictionary<string, VerifiedNetworkNode> _nodes;
    internal VerifiedOnionNetworkContext(ReadOnlySpan<byte> networkId)
    {
        PrivacyRoutingWire.ValidateNetwork(networkId);
        _networkId = networkId.ToArray();
        _nodes = new Dictionary<string, VerifiedNetworkNode>(StringComparer.Ordinal);
    }
    internal VerifiedOnionNetworkContext(
        ReadOnlySpan<byte> networkId,
        OnionTrustedTimeLease trustedTime,
        IEnumerable<VerifiedNetworkNode> nodes) : this(networkId)
    {
        TrustedTime = trustedTime;
        _nodes = nodes.ToDictionary(static node => Convert.ToHexString(node.NodeId), StringComparer.Ordinal);
    }
    internal VerifiedOnionNetworkContext(
        ReadOnlySpan<byte> networkId,
        OnionTrustedTimeLease trustedTime,
        IEnumerable<VerifiedNetworkNode> nodes,
        VerifiedOnionNetworkClosure closure,
        XPointNetworkProtectedLkg protectedLkg,
        XPointNetworkProtectedLkg? priorProtectedLkg) : this(networkId)
    {
        TrustedTime = trustedTime;
        _nodes = nodes.ToDictionary(static node => Convert.ToHexString(node.NodeId), StringComparer.Ordinal);
        Closure = closure;
        ProtectedLkg = CopyLkg(protectedLkg);
        PriorProtectedLkg = priorProtectedLkg is null ? null : CopyLkg(priorProtectedLkg);
    }
    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public XPointNetworkProtectedLkg? ProtectedLkg { get; }
    public XPointNetworkProtectedLkg? PriorProtectedLkg { get; }

    public void EnsureCurrent()
    {
        if (TrustedTime is null || ProtectedLkg is null || Closure is null)
            throw new OnionBoundaryException(
                "network-context-incomplete",
                "Only a complete NETCODEC-minted network context can be used as current authority.");
        TrustedTime.EnsureLive();
    }

    internal ReadOnlySpan<byte> NetworkIdSpan => _networkId;
    internal OnionTrustedTimeLease? TrustedTime { get; }
    internal VerifiedOnionNetworkClosure? Closure { get; }
    internal IEnumerable<VerifiedNetworkNode> CandidateNodes => _nodes.Values;
    internal VerifiedNetworkNode ResolveNode(ReadOnlySpan<byte> nodeId)
    {
        PrivacyRoutingWire.ValidateId(nodeId, PrivacyRoutingProtocolError.InvalidIdentifier, "node id");
        return _nodes.TryGetValue(Convert.ToHexString(nodeId), out var node)
            ? node
            : throw new OnionBoundaryException("node-not-in-view", "The selected node is absent from the exact verified XNV1 view.");
    }

    private static XPointNetworkProtectedLkg CopyLkg(XPointNetworkProtectedLkg value) => new(
        value.NetworkId,
        value.HeadCoreReference,
        value.HeadTreeSize,
        value.HeadRoot,
        value.ViewCoreReference,
        value.ViewGeneration,
        value.AuthorityCoreReference,
        value.LastForwardCheckpointCoreReference,
        value.LastForwardCheckpointGeneration);
}

public enum OnionCandidateCapacityClass : byte
{
    None = 0,
    Small = 1,
    Medium = 2,
    Large = 3,
}

/// <summary>
/// A defensive, key-free projection of one node from an exact verified XPoint
/// view. Presence in this projection means the node and its active onion key
/// passed the production network-closure verifier; it is not a caller-authored
/// trust assertion.
/// </summary>
public sealed class VerifiedOnionPathCandidate
{
    private readonly byte[] _nodeId, _ownerId, _hostId, _failureDomainId, _originId;

    internal VerifiedOnionPathCandidate(VerifiedNetworkNode node)
    {
        _nodeId = node.NodeId.ToArray();
        _ownerId = node.RouterOwnerId.ToArray();
        _hostId = node.PhysicalHostId.ToArray();
        _failureDomainId = node.FailureDomainHash.ToArray();
        _originId = node.OriginId.ToArray();
        VerifiedRoleMask = node.RoleMask;
        EntryCapacityClass = Classify(node.EntryCapacity);
        RelayCapacityClass = Classify(node.RelayCapacity);
        MailboxCapacityClass = Classify(node.MailboxCapacity);
    }

    public ReadOnlyMemory<byte> NodeId => _nodeId.ToArray();
    public ushort VerifiedRoleMask { get; }
    public ReadOnlyMemory<byte> RouterOwnerId => _ownerId.ToArray();
    public ReadOnlyMemory<byte> PhysicalHostId => _hostId.ToArray();
    public ReadOnlyMemory<byte> FailureDomainId => _failureDomainId.ToArray();
    public ReadOnlyMemory<byte> OriginId => _originId.ToArray();
    public OnionCandidateCapacityClass EntryCapacityClass { get; }
    public OnionCandidateCapacityClass RelayCapacityClass { get; }
    public OnionCandidateCapacityClass MailboxCapacityClass { get; }

    private static OnionCandidateCapacityClass Classify(ulong capacity) => capacity switch
    {
        0 => OnionCandidateCapacityClass.None,
        < 1_024 => OnionCandidateCapacityClass.Small,
        < 65_536 => OnionCandidateCapacityClass.Medium,
        _ => OnionCandidateCapacityClass.Large,
    };
}

/// <summary>
/// Non-forgeable selection facts bound to one current verified network view.
/// Raw onion keys and transport endpoints intentionally remain inside Protocol.
/// </summary>
public sealed class VerifiedOnionPathCandidateSnapshot
{
    private readonly byte[] _networkId, _viewHash;
    private readonly VerifiedOnionPathCandidate[] _candidates;

    internal VerifiedOnionPathCandidateSnapshot(
        VerifiedOnionNetworkContext network,
        XPointNetworkProtectedLkg protectedLkg)
    {
        Network = network;
        _networkId = network.NetworkIdSpan.ToArray();
        _viewHash = protectedLkg.ViewCoreReference.Slice(6, 32).ToArray();
        ViewGeneration = protectedLkg.ViewGeneration;
        _candidates = network.CandidateNodes
            .OrderBy(static node => node.NodeId, ByteArrayLexicographicComparer.Instance)
            .Select(static node => new VerifiedOnionPathCandidate(node))
            .ToArray();
    }

    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ulong ViewGeneration { get; }
    public ReadOnlyMemory<byte> ViewHash => _viewHash.ToArray();
    public IReadOnlyList<VerifiedOnionPathCandidate> Candidates =>
        Array.AsReadOnly(_candidates.ToArray());
    internal VerifiedOnionNetworkContext Network { get; }
}

public static class OnionPathCandidateSnapshotFactory
{
    public static VerifiedOnionPathCandidateSnapshot Create(
        VerifiedOnionNetworkContext network)
    {
        ArgumentNullException.ThrowIfNull(network);
        network.EnsureCurrent();
        return new VerifiedOnionPathCandidateSnapshot(network,
            network.ProtectedLkg ?? throw new OnionBoundaryException(
                "network-context-incomplete",
                "Path selection requires a complete verified network closure."));
    }
}

internal sealed class ByteArrayLexicographicComparer : IComparer<byte[]>
{
    internal static readonly ByteArrayLexicographicComparer Instance = new();
    public int Compare(byte[]? left, byte[]? right) =>
        left.AsSpan().SequenceCompareTo(right);
}

internal sealed record VerifiedNetworkNode(
    byte[] NodeId,
    byte[] RouterOwnerId,
    byte[] PhysicalHostId,
    byte[] FailureDomainHash,
    byte[] OriginId,
    byte OriginTransport,
    byte OriginAddressFamily,
    byte[] OriginAddress,
    ushort OriginPort,
    byte[] OriginSpki,
    ushort RoleMask,
    uint EntryCapacity,
    ulong RelayCapacity,
    ulong MailboxCapacity,
    ulong KeyEpoch,
    byte[] KeyId,
    byte[] OnionPublicKey,
    byte[]? IdentityPublicKey = null);

public static class OnionNetworkContextVerifier
{
    public static ValueTask<VerifiedOnionNetworkContext> VerifyAsync(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness trustedFreshness,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXvp1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnv1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnh1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactActiveXnd1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedPmt2Chain,
        VerifiedOnionNetworkContext? protectedPrevious,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken)
        => XPointOnionCapabilityProducer.VerifyAsync(
            authority, trustedFreshness, exactOrderedXvp1Chain, exactOrderedXnv1Chain,
            exactOrderedXnh1Chain, exactActiveXnd1, exactOrderedPmt2Chain,
            protectedPrevious, trustedTimeAuthority,
            cancellationToken);

    public static ValueTask<VerifiedOnionNetworkContext> VerifyFromForwardCheckpointAsync(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness trustedFreshness,
        VerifiedXPointNetworkForwardCheckpoint forwardCheckpoint,
        ReadOnlyMemory<byte> exactCurrentXvp1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactActiveXnd1,
        ReadOnlyMemory<byte> exactCurrentPmt2,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(forwardCheckpoint);
        return XPointOnionCapabilityProducer.VerifyAsync(
            authority, trustedFreshness,
            [exactCurrentXvp1],
            [forwardCheckpoint.ExactTargetXnv1],
            [forwardCheckpoint.ExactTargetXnh1],
            exactActiveXnd1,
            [exactCurrentPmt2],
            null,
            trustedTimeAuthority,
            cancellationToken,
            forwardCheckpoint);
    }
}

/// <summary>
/// Exact two-replica group-control placement derived only from a current
/// NETCODEC closure and a current identity-verified GSR1 capability.
/// </summary>
public sealed class VerifiedGroupControlPlacement
{
    private readonly byte[] _viewHash, _placementHash;
    private readonly byte[][] _replicaNodeIds;

    internal VerifiedGroupControlPlacement(
        VerifiedOnionNetworkContext network,
        VerifiedGroupControlRendezvous rendezvous,
        ReadOnlySpan<byte> viewHash,
        ReadOnlySpan<byte> placementHash,
        IReadOnlyList<byte[]> replicaNodeIds)
    {
        Network = network;
        Rendezvous = rendezvous;
        _viewHash = viewHash.ToArray();
        _placementHash = placementHash.ToArray();
        _replicaNodeIds = replicaNodeIds.Select(static value => value.ToArray()).ToArray();
    }

    public VerifiedGroupControlRendezvous Rendezvous { get; }
    public ReadOnlyMemory<byte> ViewHash => _viewHash.ToArray();
    public ReadOnlyMemory<byte> PlacementHash => _placementHash.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> ReplicaNodeIds =>
        Array.AsReadOnly(_replicaNodeIds
            .Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
    internal VerifiedOnionNetworkContext Network { get; }
        internal bool ContainsReplica(ReadOnlySpan<byte> nodeId)
    {
        foreach (var value in _replicaNodeIds)
            if (Fixed(value, nodeId))
                return true;
        return false;
    }
    internal VerifiedNetworkNode[] ResolveSelectedReplicas() =>
        _replicaNodeIds.Select(nodeId => Network.ResolveNode(nodeId)).ToArray();

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

public static class GroupControlPlacementVerifier
{
    private static readonly byte[] RankDomain =
        "Deep/XPoint/V1/PMS2/rendezvous-sha256/v2"u8.ToArray();

    public static VerifiedGroupControlPlacement Verify(
        VerifiedOnionNetworkContext network,
        VerifiedGroupControlRendezvous rendezvous)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(rendezvous);
        network.EnsureCurrent();
        var closure = network.Closure ?? throw new OnionBoundaryException(
            "network-context-incomplete", "Group-control placement requires a complete verified network closure.");
        var gsr1 = rendezvous.Record;
        if (!Fixed(network.NetworkIdSpan, gsr1.Field(1).Span) ||
            !Fixed(network.NetworkIdSpan, rendezvous.Owner.Freshness.NetworkId.Span))
            throw new OnionBoundaryException(
                "group-placement-network-mismatch", "GSR1 and its owner do not belong to the exact verified network context.");
        if (!Fixed(gsr1.Field(6).Span, closure.PmtArtifactReference))
            throw new OnionBoundaryException(
                "group-placement-pmt-mismatch", "GSR1 does not name the exact current NETCODEC-verified PMT2.");
        if (closure.PmtNodeIds.Length < 2)
            throw new OnionBoundaryException(
                "group-placement-insufficient-replicas", "The exact verified PMT2 has fewer than two group-control replicas.");

        var ranked = new List<(byte[] NodeId, byte[] Score)>(closure.PmtNodeIds.Length);
        foreach (var candidate in closure.PmtNodeIds)
        {
            _ = network.ResolveNode(candidate);
            var input = new byte[checked(RankDomain.Length + 1 + 16 + 38 + 8 + 32 + 32)];
            try
            {
                var offset = 0;
                RankDomain.CopyTo(input, offset); offset += RankDomain.Length;
                input[offset++] = 0;
                network.NetworkIdSpan.CopyTo(input.AsSpan(offset)); offset += 16;
                closure.PmtArtifactReference.CopyTo(input, offset); offset += 38;
                System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(
                    input.AsSpan(offset, 8), closure.SelectionEpoch); offset += 8;
                gsr1.Field(7).Span.CopyTo(input.AsSpan(offset)); offset += 32;
                candidate.CopyTo(input, offset);
                ranked.Add((candidate.ToArray(), SHA256.HashData(input)));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(input);
            }
        }

        try
        {
            ranked.Sort(static (left, right) =>
            {
                var score = left.Score.AsSpan().SequenceCompareTo(right.Score);
                return score != 0 ? score : left.NodeId.AsSpan().SequenceCompareTo(right.NodeId);
            });
            var replicas = new[] { ranked[0].NodeId, ranked[1].NodeId };
            var placementPayload = Join(
                closure.NetworkId,
                closure.ViewCoreReference,
                closure.PmtArtifactReference,
                U64(closure.SelectionEpoch),
                gsr1.Field(2).ToArray(),
                gsr1.Field(7).ToArray(),
                [(byte)replicas.Length],
                Join(replicas));
            var placementHash = XPointNetworkCrypto.Sha256Domain(
                "Deep/Group/V1/control-placement", placementPayload);
            return new VerifiedGroupControlPlacement(network, rendezvous, closure.ViewCoreHash,
                placementHash, replicas);
        }
        finally
        {
            foreach (var item in ranked)
                CryptographicOperations.ZeroMemory(item.Score);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }
    private static byte[] Join(params byte[][] values)
    {
        var output = new byte[checked(values.Sum(static value => value.Length))];
        var offset = 0;
        foreach (var value in values) { value.CopyTo(output, offset); offset += value.Length; }
        return output;
    }
}

public static class OnionPathContextFactory
{
    public static VerifiedOnionPathContext CreateContactResolver(
        VerifiedOnionNetworkContext network,
        VerifiedContactServicePlacement placement,
        ReadOnlyMemory<byte> ingressNodeId,
        ReadOnlyMemory<byte> coreNodeId,
        ReadOnlyMemory<byte> exitNodeId)
    {
        ArgumentNullException.ThrowIfNull(network);
        var trustedTime = network.TrustedTime ?? throw new OnionBoundaryException(
            "network-context-incomplete", "The network context was not minted from a complete production closure.");
        trustedTime.EnsureLive();
        ArgumentNullException.ThrowIfNull(placement);
        if (!ReferenceEquals(network, placement.Network))
            throw new OnionBoundaryException("placement-context-mismatch", "The service placement belongs to another verified network context.");
        var nodes = new[]
        {
            network.ResolveNode(ingressNodeId.Span),
            network.ResolveNode(coreNodeId.Span),
            network.ResolveNode(exitNodeId.Span)
        };
        RequireRole(nodes[0], 0, "Ingress");
        RequireRole(nodes[1], 1, "Core");
        RequireRole(nodes[2], 2, "Exit");
        if (!placement.ContainsReplica(nodes[2].NodeId))
            throw new OnionBoundaryException("path-exit-placement-mismatch", "The Contact Resolver exit is not in the verified ranked replica set.");
        RequireDistinct(nodes, static node => node.NodeId, "path-node-duplicate");
        RequireDistinct(nodes, static node => node.RouterOwnerId, "path-owner-duplicate");
        RequireDistinct(nodes, static node => node.KeyId, "path-key-duplicate");
        RequireDistinct(nodes, static node => node.OnionPublicKey, "path-public-key-duplicate");
        RequireDistinct(nodes, static node => node.PhysicalHostId, "path-host-duplicate");
        RequireDistinct(nodes, static node => node.FailureDomainHash, "path-failure-domain-duplicate");
        RequireDistinct(nodes, static node => node.OriginId, "path-origin-duplicate");
        var route = new[]
        {
            Hop(nodes[0], PrivacyRoutingKeyRole.Relay),
            Hop(nodes[1], PrivacyRoutingKeyRole.Relay),
            Hop(nodes[2], PrivacyRoutingKeyRole.Exit)
        };
        return new VerifiedOnionPathContext(network, trustedTime, OnionOperation.ContactResolve, route);
    }

    public static VerifiedOnionPathContext CreateGroupControl(
        VerifiedOnionNetworkContext network,
        VerifiedGroupControlPlacement placement,
        ReadOnlyMemory<byte> ingressNodeId,
        ReadOnlyMemory<byte> coreNodeId,
        ReadOnlyMemory<byte> exitNodeId)
    {
        ArgumentNullException.ThrowIfNull(network);
        var trustedTime = network.TrustedTime ?? throw new OnionBoundaryException(
            "network-context-incomplete", "The network context was not minted from a complete production closure.");
        trustedTime.EnsureLive();
        ArgumentNullException.ThrowIfNull(placement);
        if (!ReferenceEquals(network, placement.Network))
            throw new OnionBoundaryException(
                "placement-context-mismatch", "The group-control placement belongs to another verified network context.");
        var nodes = new[]
        {
            network.ResolveNode(ingressNodeId.Span),
            network.ResolveNode(coreNodeId.Span),
            network.ResolveNode(exitNodeId.Span)
        };
        RequireRole(nodes[0], 0, "Ingress");
        RequireRole(nodes[1], 1, "Core");
        RequireRole(nodes[2], 2, "Exit");
        if (!placement.ContainsReplica(nodes[2].NodeId))
            throw new OnionBoundaryException(
                "path-exit-placement-mismatch", "The GroupControl exit is not in the exact verified two-replica placement.");
        RequireExactPathDiversity(nodes);
        var route = new[]
        {
            Hop(nodes[0], PrivacyRoutingKeyRole.Relay),
            Hop(nodes[1], PrivacyRoutingKeyRole.Relay),
            Hop(nodes[2], PrivacyRoutingKeyRole.Exit)
        };
        return new VerifiedOnionPathContext(network, trustedTime, OnionOperation.GroupControl, route);
    }

    internal static PrivacyRoutingHop Hop(VerifiedNetworkNode node, PrivacyRoutingKeyRole role) =>
        new(node.NodeId, node.KeyId, node.KeyEpoch, role, node.OnionPublicKey);

    internal static void RequireRole(VerifiedNetworkNode node, int bit, string position)
    {
        if ((node.RoleMask & (1 << bit)) == 0)
            throw new OnionBoundaryException("path-role-invalid", $"The selected {position} node lacks its verified XND1 service role.");
    }

    private static void RequireExactPathDiversity(IReadOnlyList<VerifiedNetworkNode> nodes)
    {
        RequireDistinct(nodes, static node => node.NodeId, "path-node-duplicate");
        RequireDistinct(nodes, static node => node.RouterOwnerId, "path-owner-duplicate");
        RequireDistinct(nodes, static node => node.KeyId, "path-key-duplicate");
        RequireDistinct(nodes, static node => node.OnionPublicKey, "path-public-key-duplicate");
        RequireDistinct(nodes, static node => node.PhysicalHostId, "path-host-duplicate");
        RequireDistinct(nodes, static node => node.FailureDomainHash, "path-failure-domain-duplicate");
        RequireDistinct(nodes, static node => node.OriginId, "path-origin-duplicate");
    }

    private static void RequireDistinct(
        IReadOnlyList<VerifiedNetworkNode> nodes,
        Func<VerifiedNetworkNode, byte[]> selector,
        string code)
    {
        if (nodes.Select(node => Convert.ToHexString(selector(node))).Distinct(StringComparer.Ordinal).Count() != OnionLimits.RouteHopCount)
            throw new OnionBoundaryException(code, "The exact-three path contains a duplicated verified identity, key, host, or origin.");
    }
}

public sealed class VerifiedOnionLocalNodeKey
{
    private readonly PrivacyRoutingHop _localHop;
    private readonly VerifiedNetworkNode _localNode;

    internal VerifiedOnionLocalNodeKey(
        VerifiedOnionNetworkContext network,
        OnionReceivePosition position,
        VerifiedNetworkNode localNode,
        OnionKeyHandle keyHandle)
    {
        ArgumentNullException.ThrowIfNull(network);
        var trustedTime = network.TrustedTime ?? throw new OnionBoundaryException(
            "network-context-incomplete", "The network context was not minted from a complete production closure.");
        trustedTime.EnsureLive();
        ArgumentNullException.ThrowIfNull(localNode);
        ArgumentNullException.ThrowIfNull(keyHandle);
        if (!ReferenceEquals(localNode, network.ResolveNode(localNode.NodeId)))
            throw new OnionBoundaryException("local-node-context-mismatch", "The local node does not belong to this exact verified network closure.");
        var expectedRole = position == OnionReceivePosition.Exit
            ? PrivacyRoutingKeyRole.Exit
            : PrivacyRoutingKeyRole.Relay;
        OnionPathContextFactory.RequireRole(localNode, position switch
        {
            OnionReceivePosition.Ingress => 0,
            OnionReceivePosition.Core => 1,
            OnionReceivePosition.Exit => 2,
            _ => throw new OnionBoundaryException("invalid-receive-position", "Unknown ONION receive position.")
        }, position.ToString());
        Network = network;
        TrustedTime = trustedTime;
        Position = position;
        KeyHandle = keyHandle;
        _localNode = localNode;
        _localHop = OnionPathContextFactory.Hop(localNode, expectedRole);
    }

    public OnionReceivePosition Position { get; }
    internal VerifiedOnionNetworkContext Network { get; }
    internal OnionTrustedTimeLease TrustedTime { get; }
    internal OnionKeyHandle KeyHandle { get; }
    internal PrivacyRoutingHop LocalHop => _localHop;
    internal VerifiedNetworkNode LocalNode => _localNode;
}

public static class OnionLocalNodeKeyFactory
{
    public static VerifiedOnionLocalNodeKey Bind(
        VerifiedOnionNetworkContext network,
        OnionReceivePosition position,
        ReadOnlyMemory<byte> localNodeId,
        OnionKeyHandle keyHandle)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(keyHandle);
        var local = network.ResolveNode(localNodeId.Span);
        OnionPathContextFactory.RequireRole(local, position switch
        {
            OnionReceivePosition.Ingress => 0,
            OnionReceivePosition.Core => 1,
            OnionReceivePosition.Exit => 2,
            _ => throw new OnionBoundaryException("invalid-receive-position", "Unknown ONION receive position.")
        }, position.ToString());
        return new VerifiedOnionLocalNodeKey(
            network, position, local, keyHandle);
    }
}

public static class OnionReceiveContextSelector
{
    public static VerifiedOnionReceiveContext Select(
        ReadOnlyMemory<byte> exactFrame,
        VerifiedOnionLocalNodeKey localNodeKey)
    {
        ArgumentNullException.ThrowIfNull(localNodeKey);
        localNodeKey.TrustedTime.EnsureLive();
        var receive = new VerifiedOnionReceiveContext(localNodeKey);
        try
        {
            var ephemeral = PrivacyRoutingWire.ReadBoundRequestEphemeral(exactFrame.Span, receive);
            CryptographicOperations.ZeroMemory(ephemeral);
            return receive;
        }
        catch (PrivacyRoutingProtocolException exception)
        {
            throw new OnionBoundaryException(
                "receive-frame-invalid",
                "The exact ONION frame does not bind the verified local node/key capability.",
                exception);
        }
    }
}

public sealed class VerifiedOnionPathContext
{
    private readonly PrivacyRoutingHop[] _route;
    private readonly byte[] _entryRouterId;

    internal VerifiedOnionPathContext(
        VerifiedOnionNetworkContext network,
        OnionTrustedTimeLease trustedTime,
        OnionOperation operation,
        IReadOnlyList<PrivacyRoutingHop> route)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(trustedTime);
        PrivacyRoutingValidationBuilder.ValidateVerifiedRoute(route);
        Network = network;
        TrustedTime = trustedTime;
        Operation = operation;
        _ = ProductionConversions.Operation(operation);
        _route = route.ToArray();
        _entryRouterId = route[0].RouterOwnerIdSpan.ToArray();
    }

    public ReadOnlyMemory<byte> EntryRouterId => _entryRouterId.ToArray();
    internal VerifiedOnionNetworkContext Network { get; }
    internal OnionOperation Operation { get; }
    internal OnionTrustedTimeLease TrustedTime { get; }
    internal IReadOnlyList<PrivacyRoutingHop> Route => _route;

    internal void EnsureUsable(VerifiedCanonicalOnionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        TrustedTime.EnsureLive();
        if (!ReferenceEquals(Network, request.Network) || Operation != request.Operation)
            throw new OnionBoundaryException("request-path-mismatch", "The verified request is not bound to this path capability.");
        PrivacyRoutingValidationBuilder.ValidateVerifiedRoute(_route);
    }
}

public sealed class VerifiedCanonicalOnionRequest
{
    private readonly byte[] _bytes;

    internal VerifiedCanonicalOnionRequest(
        VerifiedOnionNetworkContext network,
        OnionOperation operation,
        ReadOnlySpan<byte> exactCanonicalBytes)
    {
        ArgumentNullException.ThrowIfNull(network);
        var internalOperation = ProductionConversions.Operation(operation);
        PrivacyRoutingPayloadVerifier.ValidateRequest(network.NetworkIdSpan, internalOperation, exactCanonicalBytes);
        Network = network;
        Operation = operation;
        _bytes = exactCanonicalBytes.ToArray();
    }

    public VerifiedOnionNetworkContext Network { get; }
    public OnionOperation Operation { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => _bytes.ToArray();
    internal ReadOnlySpan<byte> BytesSpan => _bytes;
}

public sealed class VerifiedOnionTerminalResult
{
    private readonly PrivacyRoutingTerminalResult _result;
    private readonly byte[] _body;

    internal VerifiedOnionTerminalResult(
        VerifiedCanonicalOnionRequest request,
        PrivacyRoutingTerminalResult result)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(result);
        PrivacyRoutingPayloadVerifier.ValidateResult(
            ProductionConversions.Operation(request.Operation), request.BytesSpan, result);
        Request = request;
        _result = result;
        _body = result.Body.ToArray();
    }

    public VerifiedCanonicalOnionRequest Request { get; }
    public OnionOperation Operation => Request.Operation;
    public OnionTerminalResultKind Kind => (OnionTerminalResultKind)_result.Kind;
    public OnionFailureCode? FailureCode => _result.FailureCode is { } code ? (OnionFailureCode)code : null;
    public bool Retryable => _result.Retryable;
    public ReadOnlyMemory<byte> Body => _body.ToArray();
    internal PrivacyRoutingTerminalResult Result => _result;

    internal static VerifiedOnionTerminalResult Success(VerifiedCanonicalOnionRequest request, ReadOnlySpan<byte> body) =>
        new(request, PrivacyRoutingTerminalResult.Success(ProductionConversions.Operation(request.Operation), body));

    internal static VerifiedOnionTerminalResult Failure(VerifiedCanonicalOnionRequest request, OnionFailureCode code) =>
        new(request, PrivacyRoutingTerminalResult.Failure(
            ProductionConversions.Operation(request.Operation), (PrivacyRoutingFailureCode)code));
}

public static class OnionTerminalPayloadVerifierV1
{
    public static VerifiedCanonicalOnionRequest VerifyRequest(
        VerifiedOnionNetworkContext network,
        OnionOperation operation,
        ReadOnlyMemory<byte> exactCanonicalRequest)
    {
        ArgumentNullException.ThrowIfNull(network);
        return new VerifiedCanonicalOnionRequest(network, operation, exactCanonicalRequest.Span);
    }

    public static VerifiedOnionTerminalResult VerifySuccess(
        VerifiedCanonicalOnionRequest request,
        ReadOnlyMemory<byte> exactCanonicalResult)
    {
        ArgumentNullException.ThrowIfNull(request);
        return VerifiedOnionTerminalResult.Success(request, exactCanonicalResult.Span);
    }

    public static VerifiedOnionTerminalResult VerifyFailure(
        VerifiedCanonicalOnionRequest request,
        OnionFailureCode failureCode)
    {
        ArgumentNullException.ThrowIfNull(request);
        return VerifiedOnionTerminalResult.Failure(request, failureCode);
    }
}

public sealed class VerifiedOnionReceiveContext
{
    private readonly PrivacyRoutingHop _localHop;
    private readonly VerifiedNetworkNode _localNode;

    internal VerifiedOnionReceiveContext(VerifiedOnionLocalNodeKey localNodeKey)
    {
        ArgumentNullException.ThrowIfNull(localNodeKey);
        var internalPosition = ProductionConversions.Position(localNodeKey.Position);
        var expectedRole = internalPosition == PrivacyRoutingReceivePosition.Exit
            ? PrivacyRoutingKeyRole.Exit
            : PrivacyRoutingKeyRole.Relay;
        if (localNodeKey.LocalHop.Role != expectedRole)
            throw new OnionBoundaryException("receive-role-mismatch", "The local traffic-key role contradicts the receive position.");
        Network = localNodeKey.Network;
        TrustedTime = localNodeKey.TrustedTime;
        Position = localNodeKey.Position;
        KeyHandle = localNodeKey.KeyHandle;
        _localHop = localNodeKey.LocalHop;
        _localNode = localNodeKey.LocalNode;
    }

    public VerifiedOnionNetworkContext Network { get; }
    public OnionReceivePosition Position { get; }
    public OnionKeyHandle KeyHandle { get; }
    internal OnionTrustedTimeLease TrustedTime { get; }
    internal PrivacyRoutingHop LocalHop => _localHop;

    internal PrivacyRoutingHop ResolveNextHop(ReadOnlySpan<byte> nextNodeId)
    {
        if (Position == OnionReceivePosition.Exit)
            throw new OnionBoundaryException("receive-next-hop-mismatch", "An exit receive context cannot resolve a next hop.");
        var next = Network.ResolveNode(nextNodeId);
        var nextRole = Position == OnionReceivePosition.Ingress
            ? PrivacyRoutingKeyRole.Relay
            : PrivacyRoutingKeyRole.Exit;
        OnionPathContextFactory.RequireRole(next, Position == OnionReceivePosition.Ingress ? 1 : 2, "next hop");
        if (CryptographicOperations.FixedTimeEquals(_localHop.RouterOwnerIdSpan, next.RouterOwnerId) ||
            CryptographicOperations.FixedTimeEquals(_localHop.KeyIdSpan, next.KeyId) ||
            CryptographicOperations.FixedTimeEquals(_localHop.X25519PublicKeySpan, next.OnionPublicKey) ||
            CryptographicOperations.FixedTimeEquals(_localNode.PhysicalHostId, next.PhysicalHostId) ||
            CryptographicOperations.FixedTimeEquals(_localNode.OriginId, next.OriginId))
            throw new OnionBoundaryException("receive-next-hop-duplicate", "The local and next-hop identities, keys, hosts and origins must be distinct.");
        return OnionPathContextFactory.Hop(next, nextRole);
    }

    internal VerifiedOnionNextHopTransport ResolveNextHopTransport(ReadOnlySpan<byte> nextNodeId)
    {
        _ = ResolveNextHop(nextNodeId);
        return new VerifiedOnionNextHopTransport(Network, Network.ResolveNode(nextNodeId));
    }
}

public sealed class VerifiedOnionNextHopTransport
{
    private readonly VerifiedOnionNetworkContext _network;
    private readonly byte[] _networkId, _nodeId, _originId, _address, _spkiSha256;

    internal VerifiedOnionNextHopTransport(VerifiedOnionNetworkContext network, VerifiedNetworkNode node)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(node);
        if (!ReferenceEquals(node, network.ResolveNode(node.NodeId)))
            throw new OnionBoundaryException("next-hop-context-mismatch", "The next hop does not belong to this exact verified network closure.");
        Transport = node.OriginTransport switch
        {
            1 => OnionNextHopTransport.TcpTls,
            2 => OnionNextHopTransport.QuicTls,
            _ => throw new OnionBoundaryException("next-hop-origin-invalid", "The verified next-hop transport is unsupported.")
        };
        AddressFamily = node.OriginAddressFamily switch
        {
            4 => OnionNextHopAddressFamily.IPv4,
            6 => OnionNextHopAddressFamily.IPv6,
            _ => throw new OnionBoundaryException("next-hop-origin-invalid", "The verified next-hop address family is unsupported.")
        };
        PrivacyRoutingWire.ValidateId(node.NodeId, PrivacyRoutingProtocolError.InvalidIdentifier, "next-hop node id");
        PrivacyRoutingWire.ValidateId(node.OriginId, PrivacyRoutingProtocolError.InvalidIdentifier, "next-hop origin id");
        if (node.OriginAddress.Length != 16 || node.OriginPort == 0 || node.OriginSpki.Length != 32 ||
            PrivacyRoutingWire.IsZero(node.OriginAddress) || PrivacyRoutingWire.IsZero(node.OriginSpki) ||
            AddressFamily == OnionNextHopAddressFamily.IPv4 && !PrivacyRoutingWire.IsZero(node.OriginAddress.AsSpan(4)))
            throw new OnionBoundaryException("next-hop-origin-invalid", "The verified next-hop origin is not canonical.");
        _network = network;
        _networkId = network.NetworkIdSpan.ToArray();
        _nodeId = node.NodeId.ToArray();
        _originId = node.OriginId.ToArray();
        _address = node.OriginAddress.ToArray();
        _spkiSha256 = node.OriginSpki.ToArray();
        Port = node.OriginPort;
    }

    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> NodeId => _nodeId.ToArray();
    public ReadOnlyMemory<byte> OriginId => _originId.ToArray();
    public OnionNextHopTransport Transport { get; }
    public OnionNextHopAddressFamily AddressFamily { get; }
    public ReadOnlyMemory<byte> Address => _address.ToArray();
    public ushort Port { get; }
    public ReadOnlyMemory<byte> SpkiSha256 => _spkiSha256.ToArray();
    internal VerifiedOnionNetworkContext Network => _network;
}

public sealed class OnionReplayOpenLease : IAsyncDisposable
{
    private readonly byte[] _frameHash;
    private readonly byte[] _networkId;
    private readonly byte[] _ownerId;
    private readonly byte[] _keyId;
    private readonly byte[] _keyHandleId;
    private readonly byte[] _bootId;
    private IOnionDurableReplayTransaction? _transaction;
    private int _used;

    internal OnionReplayOpenLease(
        VerifiedOnionReceiveContext receive,
        ReadOnlySpan<byte> exactFrameHash,
        IOnionDurableReplayTransaction transaction)
    {
        ArgumentNullException.ThrowIfNull(receive);
        ArgumentNullException.ThrowIfNull(transaction);
        PrivacyRoutingWire.ValidateId(exactFrameHash, PrivacyRoutingProtocolError.InvalidIdentifier, "frame hash");
        _frameHash = exactFrameHash.ToArray();
        _networkId = receive.Network.NetworkIdSpan.ToArray();
        _ownerId = receive.LocalHop.RouterOwnerIdSpan.ToArray();
        _keyId = receive.LocalHop.KeyIdSpan.ToArray();
        _keyHandleId = receive.KeyHandle.IdSpan.ToArray();
        _bootId = receive.TrustedTime.BootIdSpan.ToArray();
        Epoch = receive.LocalHop.Epoch;
        Position = receive.Position;
        _transaction = transaction;
    }

    internal ulong Epoch { get; }
    internal OnionReceivePosition Position { get; }

    internal void BeginUse(VerifiedOnionReceiveContext receive, ReadOnlySpan<byte> frameHash)
    {
        receive.TrustedTime.EnsureLive();
        if (!CryptographicOperations.FixedTimeEquals(_frameHash, frameHash) ||
            !CryptographicOperations.FixedTimeEquals(_networkId, receive.Network.NetworkIdSpan) ||
            !CryptographicOperations.FixedTimeEquals(_ownerId, receive.LocalHop.RouterOwnerIdSpan) ||
            !CryptographicOperations.FixedTimeEquals(_keyId, receive.LocalHop.KeyIdSpan) ||
            !CryptographicOperations.FixedTimeEquals(_keyHandleId, receive.KeyHandle.IdSpan) ||
            !CryptographicOperations.FixedTimeEquals(_bootId, receive.TrustedTime.BootIdSpan) ||
            Epoch != receive.LocalHop.Epoch || Position != receive.Position)
            throw new OnionBoundaryException("replay-lease-mismatch", "The replay lease is not bound to this exact frame and receive context.");
        if (Interlocked.Exchange(ref _used, 1) != 0 || Volatile.Read(ref _transaction) is null)
            throw new OnionBoundaryException("replay-lease-consumed", "The replay lease is single-use.");
    }

    internal async ValueTask CommitAsync(ReadOnlyMemory<byte> replayId, CancellationToken cancellationToken)
    {
        var transaction = Volatile.Read(ref _transaction) ??
            throw new OnionBoundaryException("replay-lease-consumed", "The replay lease is unavailable.");
        OnionReplayCommitOutcome outcome;
        try
        {
            outcome = await transaction.CommitAsync(replayId, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception)
        {
            throw new OnionBoundaryException("replay-commit-failed", "The durable replay commit failed closed.", exception);
        }
        if (outcome != OnionReplayCommitOutcome.Committed)
            throw new OnionBoundaryException(
                outcome == OnionReplayCommitOutcome.Ambiguous ? "replay-commit-ambiguous" : "replay-rejected",
                "The durable replay transaction did not commit uniquely.");
        cancellationToken.ThrowIfCancellationRequested();
    }

    public async ValueTask DisposeAsync()
    {
        var transaction = Interlocked.Exchange(ref _transaction, null);
        if (transaction is not null) await transaction.DisposeAsync().ConfigureAwait(false);
        CryptographicOperations.ZeroMemory(_frameHash);
        CryptographicOperations.ZeroMemory(_networkId);
        CryptographicOperations.ZeroMemory(_ownerId);
        CryptographicOperations.ZeroMemory(_keyId);
        CryptographicOperations.ZeroMemory(_keyHandleId);
        CryptographicOperations.ZeroMemory(_bootId);
    }
}

public sealed class OnionReplyContext : IDisposable
{
    private PrivacyRoutingReplyContext? _inner;
    internal OnionReplyContext(
        PrivacyRoutingReplyContext inner,
        VerifiedCanonicalOnionRequest request,
        OnionTrustedTimeLease trustedTime)
    {
        _inner = inner;
        Request = request;
        TrustedTime = trustedTime;
    }
    internal VerifiedCanonicalOnionRequest Request { get; }
    internal OnionTrustedTimeLease TrustedTime { get; }
    internal PrivacyRoutingReplyContext Inner => Volatile.Read(ref _inner) ?? throw new ObjectDisposedException(nameof(OnionReplyContext));
    public ReadOnlyMemory<byte> AttemptId => Inner.AttemptId;
    public void Dispose() => Interlocked.Exchange(ref _inner, null)?.Dispose();
}

public sealed class PrivacyRoutingBuiltRequest : IDisposable
{
    private byte[]? _frame;
    internal PrivacyRoutingBuiltRequest(byte[] frame, OnionReplyContext replyContext)
    {
        _frame = frame;
        ReplyContext = replyContext;
    }
    public ReadOnlyMemory<byte> Frame => (_frame ?? throw new ObjectDisposedException(nameof(PrivacyRoutingBuiltRequest))).ToArray();
    public ReadOnlyMemory<byte> AttemptId => ReplyContext.AttemptId;
    public OnionReplyContext ReplyContext { get; }
    public void Dispose()
    {
        var frame = Interlocked.Exchange(ref _frame, null);
        if (frame is not null) CryptographicOperations.ZeroMemory(frame);
        ReplyContext.Dispose();
    }
}

public abstract class OpenedOnionLayer : IDisposable
{
    private PrivacyRoutingOpenedLayer? _inner;
    private protected OpenedOnionLayer(PrivacyRoutingOpenedLayer inner) => _inner = inner;
    internal PrivacyRoutingOpenedLayer Inner => Volatile.Read(ref _inner) ?? throw new ObjectDisposedException(GetType().Name);
    public void Dispose() => Interlocked.Exchange(ref _inner, null)?.Dispose();
}

public sealed class OpenedOnionRelay : OpenedOnionLayer
{
    internal OpenedOnionRelay(
        PrivacyRoutingRelayLayer inner,
        VerifiedOnionNextHopTransport nextHop) : base(inner) => NextHop = nextHop;
    private PrivacyRoutingRelayLayer Relay => (PrivacyRoutingRelayLayer)Inner;
    public VerifiedOnionNextHopTransport NextHop { get; }
    public ReadOnlyMemory<byte> InnerFrame => Relay.InnerFrame;
}

public sealed class OpenedOnionExit : OpenedOnionLayer
{
    internal OpenedOnionExit(
        PrivacyRoutingExitLayer inner,
        VerifiedCanonicalOnionRequest request,
        OnionExitReplyContext replyContext) : base(inner)
    {
        Request = request;
        ReplyContext = replyContext;
    }
    public VerifiedCanonicalOnionRequest Request { get; }
    public OnionExitReplyContext ReplyContext { get; }
    public ReadOnlyMemory<byte> AttemptId => ((PrivacyRoutingExitLayer)Inner).AttemptId;
}

public sealed class OnionExitReplyContext
{
    internal OnionExitReplyContext(
        PrivacyRoutingExitLayer inner,
        VerifiedCanonicalOnionRequest request,
        OnionTrustedTimeLease trustedTime)
    {
        Inner = inner;
        Request = request;
        TrustedTime = trustedTime;
    }
    internal PrivacyRoutingExitLayer Inner { get; }
    internal VerifiedCanonicalOnionRequest Request { get; }
    internal OnionTrustedTimeLease TrustedTime { get; }
}

public sealed class PrivacyRoutingOpenedResponse
{
    internal PrivacyRoutingOpenedResponse(VerifiedOnionTerminalResult result) => Result = result;
    public VerifiedOnionTerminalResult Result { get; }
}

public sealed class OnionEntropyAuthority
{
    private readonly IOnionEntropyUniquenessLedger _ledger;
    public OnionEntropyAuthority(IOnionEntropyUniquenessLedger ledger) =>
        _ledger = ledger ?? throw new ArgumentNullException(nameof(ledger));

    internal async ValueTask<PrivacyRoutingTestEntropy> ReserveRequestAsync(
        VerifiedOnionPathContext path,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var lifetime = path.TrustedTime.Remaining;
        if (lifetime > PrivacyRoutingLimits.ReplyContextLifetime) lifetime = PrivacyRoutingLimits.ReplyContextLifetime;
        if (lifetime <= TimeSpan.Zero)
            throw new OnionBoundaryException("trusted-time-expired", "No live interval remains for reply state.");
        var entropy = PrivacyRoutingTestEntropy.CreateProductionRequest(path.TrustedTime.TimeProvider, lifetime);
        try
        {
            var commitments = RequestCommitments(path, entropy);
            try { await CommitAsync(new OnionEntropyCommitmentBatch(false, commitments), cancellationToken).ConfigureAwait(false); }
            finally { foreach (var commitment in commitments) CryptographicOperations.ZeroMemory(commitment); }
            return entropy;
        }
        catch
        {
            entropy.Dispose();
            throw;
        }
    }

    internal async ValueTask<PrivacyRoutingTestEntropy> ReserveResponseAsync(
        OnionExitReplyContext reply,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        reply.TrustedTime.EnsureLive();
        var entropy = PrivacyRoutingTestEntropy.CreateProductionResponse();
        try
        {
            var commitments = ResponseCommitments(reply, entropy);
            try { await CommitAsync(new OnionEntropyCommitmentBatch(true, commitments), cancellationToken).ConfigureAwait(false); }
            finally { foreach (var commitment in commitments) CryptographicOperations.ZeroMemory(commitment); }
            return entropy;
        }
        catch
        {
            entropy.Dispose();
            throw;
        }
    }

    private async ValueTask CommitAsync(OnionEntropyCommitmentBatch batch, CancellationToken cancellationToken)
    {
        OnionEntropyCommitOutcome outcome;
        try { outcome = await _ledger.CommitAsync(batch, cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception)
        {
            throw new OnionBoundaryException("entropy-ledger-failed", "The durable entropy reservation failed closed.", exception);
        }
        if (outcome != OnionEntropyCommitOutcome.Committed)
            throw new OnionBoundaryException(
                outcome == OnionEntropyCommitOutcome.Duplicate ? "entropy-duplicate" :
                outcome == OnionEntropyCommitOutcome.Ambiguous ? "entropy-commit-ambiguous" : "entropy-commit-rejected",
                "The entropy uniqueness ledger did not atomically commit the reservation.");
        cancellationToken.ThrowIfCancellationRequested();
    }

    private static byte[][] RequestCommitments(VerifiedOnionPathContext path, PrivacyRoutingTestEntropy entropy)
    {
        var replyPublic = ScalarMult.Base(entropy.ReplyPrivateScalar);
        var values = new List<byte[]>(8);
        try
        {
            values.Add(PrivacyRoutingWire.Sha256Domain("Deep/XPoint/V1/attempt-commitment", entropy.AttemptId));
            values.Add(PrivacyRoutingWire.Sha256Domain("Deep/XPoint/V1/reply-key-commitment", replyPublic));
        }
        finally { CryptographicOperations.ZeroMemory(replyPublic); }
        for (var routeIndex = 0; routeIndex < 3; routeIndex++)
        {
            values.Add(PrivacyRoutingWire.Sha256Domain("Deep/XPoint/V1/replay-commitment", entropy.ReplayIds[routeIndex]));
            var entropyIndex = 2 - routeIndex;
            var hop = path.Route[routeIndex];
            var ephemeralPublic = ScalarMult.Base(entropy.RequestEphemeralPrivateScalars[entropyIndex]);
            try
            {
                values.Add(FrameCommitment(path.Network.NetworkIdSpan, 1, (byte)hop.Role, hop, ephemeralPublic, entropy.RequestNonces[entropyIndex]));
            }
            finally { CryptographicOperations.ZeroMemory(ephemeralPublic); }
        }
        return values.ToArray();
    }

    private static byte[][] ResponseCommitments(OnionExitReplyContext reply, PrivacyRoutingTestEntropy entropy)
    {
        var ephemeralPublic = ScalarMult.Base(entropy.ResponseEphemeralPrivateScalar);
        try
        {
            var inner = reply.Inner;
            var owner = PrivacyRoutingWire.Sha256Domain("Deep/XPoint/V1/reply-owner", inner.ReplyPublicKeySpan.ToArray());
            var keyId = PrivacyRoutingWire.Sha256Domain("Deep/XPoint/V1/reply-key", inner.ReplyPublicKeySpan.ToArray());
            try
            {
                var epoch = PrivacyRoutingWire.U64(0);
                try
                {
                    return
                    [
                        PrivacyRoutingWire.Sha256Domain(
                            "Deep/XPoint/V1/frame-commitment",
                            inner.NetworkIdSpan.ToArray(), [2], [3], owner, keyId, epoch,
                            ephemeralPublic, entropy.ResponseNonce)
                    ];
                }
                finally { CryptographicOperations.ZeroMemory(epoch); }
            }
            finally { CryptographicOperations.ZeroMemory(owner); CryptographicOperations.ZeroMemory(keyId); }
        }
        finally { CryptographicOperations.ZeroMemory(ephemeralPublic); }
    }

    private static byte[] FrameCommitment(
        ReadOnlySpan<byte> network,
        byte purpose,
        byte layer,
        PrivacyRoutingHop hop,
        ReadOnlySpan<byte> ephemeralPublic,
        ReadOnlySpan<byte> nonce)
    {
        var epoch = PrivacyRoutingWire.U64(hop.Epoch);
        try
        {
            return PrivacyRoutingWire.Sha256Domain(
                "Deep/XPoint/V1/frame-commitment", network.ToArray(), [purpose], [layer],
                hop.RouterOwnerIdSpan.ToArray(), hop.KeyIdSpan.ToArray(), epoch,
                ephemeralPublic.ToArray(), nonce.ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(epoch); }
    }
}

public sealed partial class PrivacyRoutingCodec
{
    private readonly OnionEntropyAuthority _entropyAuthority;
    private readonly OnionKeyAgreementAuthority _keyAgreementAuthority;

    public PrivacyRoutingCodec(OnionEntropyAuthority entropyAuthority, OnionKeyAgreementAuthority keyAgreementAuthority)
    {
        _entropyAuthority = entropyAuthority ?? throw new ArgumentNullException(nameof(entropyAuthority));
        _keyAgreementAuthority = keyAgreementAuthority ?? throw new ArgumentNullException(nameof(keyAgreementAuthority));
    }

    public async ValueTask<PrivacyRoutingBuiltRequest> BuildAsync(
        VerifiedOnionPathContext path,
        VerifiedCanonicalOnionRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(request);
        path.EnsureUsable(request);
        using var entropy = await _entropyAuthority.ReserveRequestAsync(path, cancellationToken).ConfigureAwait(false);
        var built = PrivacyRoutingValidationBuilder.BuildForCanonicalRequest(
            path.Network.NetworkIdSpan,
            path.Route,
            ProductionConversions.Operation(path.Operation),
            request.BytesSpan,
            entropy);
        var reply = new OnionReplyContext(built.ReplyContext, request, path.TrustedTime);
        var frame = built.Frame.ToArray();
        built.DetachReplyContextForProduction();
        built.Dispose();
        return new PrivacyRoutingBuiltRequest(frame, reply);
    }

    public async ValueTask<OpenedOnionLayer> OpenAsync(
        ReadOnlyMemory<byte> frame,
        VerifiedOnionReceiveContext receive,
        OnionReplayOpenLease replayLease,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(receive);
        ArgumentNullException.ThrowIfNull(replayLease);
        cancellationToken.ThrowIfCancellationRequested();
        var frameHash = SHA256.HashData(frame.Span);
        PrivacyRoutingOpenedLayer? opened = null;
        VerifiedOnionNextHopTransport? nextHop = null;
        byte[]? sharedSecret = null;
        try
        {
            replayLease.BeginUse(receive, frameHash);
            var ephemeral = PrivacyRoutingWire.ReadBoundRequestEphemeral(frame.Span, receive);
            try
            {
                sharedSecret = await _keyAgreementAuthority.DeriveAsync(
                    receive.KeyHandle, ephemeral, cancellationToken).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(ephemeral); }
            if (sharedSecret is null || sharedSecret.Length != PrivacyRoutingLimits.X25519KeyBytes || PrivacyRoutingWire.IsZero(sharedSecret))
                throw new OnionBoundaryException("key-agreement-invalid", "The opaque key vault returned an invalid X25519 shared secret.");
            opened = PrivacyRoutingValidationBuilder.OpenRequestWithSharedSecret(frame.Span, receive, sharedSecret);
            if (opened is PrivacyRoutingRelayLayer openedRelay)
                nextHop = receive.ResolveNextHopTransport(openedRelay.NextRouterId.Span);
            await replayLease.CommitAsync(opened.ReplayId, cancellationToken).ConfigureAwait(false);
            await replayLease.DisposeAsync().ConfigureAwait(false);
            if (opened is PrivacyRoutingRelayLayer relay)
            {
                opened = null;
                return new OpenedOnionRelay(relay, nextHop!);
            }
            var exit = (PrivacyRoutingExitLayer)opened;
            var request = new VerifiedCanonicalOnionRequest(
                receive.Network, ProductionConversions.Operation(exit.Operation), exit.PayloadSpan);
            var reply = new OnionExitReplyContext(exit, request, receive.TrustedTime);
            opened = null;
            return new OpenedOnionExit(exit, request, reply);
        }
        catch
        {
            opened?.Dispose();
            await replayLease.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(frameHash);
            if (sharedSecret is not null) CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    public async ValueTask<ReadOnlyMemory<byte>> SealAsync(
        OnionExitReplyContext reply,
        VerifiedOnionTerminalResult result,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reply);
        ArgumentNullException.ThrowIfNull(result);
        reply.TrustedTime.EnsureLive();
        if (!ReferenceEquals(reply.Request, result.Request))
            throw new OnionBoundaryException("terminal-result-mismatch", "The terminal result was not verified for this exact opened request capability.");
        using var entropy = await _entropyAuthority.ReserveResponseAsync(reply, cancellationToken).ConfigureAwait(false);
        return PrivacyRoutingValidationBuilder.SealResponse(reply.Inner, result.Result, entropy);
    }

    public ValueTask<PrivacyRoutingOpenedResponse> OpenResponseAsync(
        ReadOnlyMemory<byte> frame,
        OnionReplyContext reply,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reply);
        cancellationToken.ThrowIfCancellationRequested();
        reply.TrustedTime.EnsureLive();
        var opened = PrivacyRoutingValidationBuilder.OpenResponse(frame.Span, reply.Inner);
        return ValueTask.FromResult(new PrivacyRoutingOpenedResponse(
            new VerifiedOnionTerminalResult(reply.Request, opened.Result)));
    }
}

internal static class ProductionConversions
{
    internal static PrivacyRoutingOperation Operation(OnionOperation value) => value switch
    {
        OnionOperation.Store => PrivacyRoutingOperation.Store,
        OnionOperation.Retrieve => PrivacyRoutingOperation.Retrieve,
        OnionOperation.Acknowledge => PrivacyRoutingOperation.Acknowledge,
        OnionOperation.ContactResolve => PrivacyRoutingOperation.ContactResolve,
        OnionOperation.GroupControl => PrivacyRoutingOperation.GroupControl,
        _ => throw new OnionBoundaryException("invalid-operation", "Unknown ONION terminal operation.")
    };

    internal static OnionOperation Operation(PrivacyRoutingOperation value) => value switch
    {
        PrivacyRoutingOperation.Store => OnionOperation.Store,
        PrivacyRoutingOperation.Retrieve => OnionOperation.Retrieve,
        PrivacyRoutingOperation.Acknowledge => OnionOperation.Acknowledge,
        PrivacyRoutingOperation.ContactResolve => OnionOperation.ContactResolve,
        PrivacyRoutingOperation.GroupControl => OnionOperation.GroupControl,
        _ => throw new OnionBoundaryException("invalid-operation", "Unknown ONION terminal operation.")
    };

    internal static PrivacyRoutingReceivePosition Position(OnionReceivePosition value) => value switch
    {
        OnionReceivePosition.Ingress => PrivacyRoutingReceivePosition.Ingress,
        OnionReceivePosition.Core => PrivacyRoutingReceivePosition.Core,
        OnionReceivePosition.Exit => PrivacyRoutingReceivePosition.Exit,
        _ => throw new OnionBoundaryException("invalid-receive-position", "Unknown ONION receive position.")
    };
}
