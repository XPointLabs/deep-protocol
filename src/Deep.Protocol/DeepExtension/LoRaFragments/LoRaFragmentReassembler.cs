using System.Buffers.Binary;
using Deep.Protocol.DeepExtension.OpaqueBundles;

namespace Deep.Protocol.DeepExtension.LoRaFragments;

/// <summary>Absolute, lower-only limits for durable P18A reassembly admission.</summary>
public static class LoRaFragmentReassemblyLimits
{
    public const int MaximumIncompleteMessagesPerReplayScope = 4;
    public const int MaximumIncompleteMessagesGlobal = 16;
    public const int MaximumReservedBytesGlobal = 64 * 1024;
    public const int ReservationMetadataBytes = 256;
    public const int MaximumTombstonesPerReplayScope = 256;
    public const int MaximumTombstonesGlobal = 1024;
    public const int MaximumTombstoneBytesGlobal = 128 * 1024;
}

/// <summary>
/// Explicit caller-supplied time and quota limits. All limits only narrow the
/// V1 contract; none can increase an absolute limit.
/// </summary>
public sealed class LoRaFragmentReassemblyPolicy
{
    public LoRaFragmentReassemblyPolicy(
        LoRaFragmentPolicy fragmentPolicy,
        uint currentExpiryBucket,
        uint provisionalExpiryBucket,
        uint acceptedExpirySkewBuckets,
        int maximumIncompleteMessagesPerReplayScope = LoRaFragmentReassemblyLimits.MaximumIncompleteMessagesPerReplayScope,
        int maximumIncompleteMessagesGlobal = LoRaFragmentReassemblyLimits.MaximumIncompleteMessagesGlobal,
        int maximumReservedBytesGlobal = LoRaFragmentReassemblyLimits.MaximumReservedBytesGlobal,
        int maximumTombstonesPerReplayScope = LoRaFragmentReassemblyLimits.MaximumTombstonesPerReplayScope,
        int maximumTombstonesGlobal = LoRaFragmentReassemblyLimits.MaximumTombstonesGlobal,
        int maximumTombstoneBytesGlobal = LoRaFragmentReassemblyLimits.MaximumTombstoneBytesGlobal)
    {
        ArgumentNullException.ThrowIfNull(fragmentPolicy);
        ValidateLowerLimit(maximumIncompleteMessagesPerReplayScope, 1, LoRaFragmentReassemblyLimits.MaximumIncompleteMessagesPerReplayScope, nameof(maximumIncompleteMessagesPerReplayScope));
        ValidateLowerLimit(maximumIncompleteMessagesGlobal, 1, LoRaFragmentReassemblyLimits.MaximumIncompleteMessagesGlobal, nameof(maximumIncompleteMessagesGlobal));
        ValidateLowerLimit(maximumReservedBytesGlobal, 1, LoRaFragmentReassemblyLimits.MaximumReservedBytesGlobal, nameof(maximumReservedBytesGlobal));
        ValidateLowerLimit(maximumTombstonesPerReplayScope, 1, LoRaFragmentReassemblyLimits.MaximumTombstonesPerReplayScope, nameof(maximumTombstonesPerReplayScope));
        ValidateLowerLimit(maximumTombstonesGlobal, 1, LoRaFragmentReassemblyLimits.MaximumTombstonesGlobal, nameof(maximumTombstonesGlobal));
        ValidateLowerLimit(maximumTombstoneBytesGlobal, 1, LoRaFragmentReassemblyLimits.MaximumTombstoneBytesGlobal, nameof(maximumTombstoneBytesGlobal));

        var opaquePolicy = fragmentPolicy.OpaqueBundleDecodePolicy;
        if (currentExpiryBucket < opaquePolicy.MinimumExpiryBucket ||
            currentExpiryBucket > opaquePolicy.MaximumExpiryBucket ||
            provisionalExpiryBucket < currentExpiryBucket ||
            provisionalExpiryBucket < opaquePolicy.MinimumExpiryBucket ||
            provisionalExpiryBucket > opaquePolicy.MaximumExpiryBucket)
        {
            throw new ArgumentOutOfRangeException(nameof(provisionalExpiryBucket), "Current and provisional expiry buckets must be explicit and inside the accepted opaque-bundle window.");
        }

        try
        {
            _ = checked(currentExpiryBucket + acceptedExpirySkewBuckets);
            _ = checked(provisionalExpiryBucket + acceptedExpirySkewBuckets);
        }
        catch (OverflowException)
        {
            throw new ArgumentOutOfRangeException(nameof(acceptedExpirySkewBuckets), "Expiry retention arithmetic must not overflow.");
        }

        FragmentPolicy = fragmentPolicy;
        CurrentExpiryBucket = currentExpiryBucket;
        ProvisionalExpiryBucket = provisionalExpiryBucket;
        AcceptedExpirySkewBuckets = acceptedExpirySkewBuckets;
        MaximumIncompleteMessagesPerReplayScope = maximumIncompleteMessagesPerReplayScope;
        MaximumIncompleteMessagesGlobal = maximumIncompleteMessagesGlobal;
        MaximumReservedBytesGlobal = maximumReservedBytesGlobal;
        MaximumTombstonesPerReplayScope = maximumTombstonesPerReplayScope;
        MaximumTombstonesGlobal = maximumTombstonesGlobal;
        MaximumTombstoneBytesGlobal = maximumTombstoneBytesGlobal;
    }

    public LoRaFragmentPolicy FragmentPolicy { get; }
    public uint CurrentExpiryBucket { get; }
    public uint ProvisionalExpiryBucket { get; }
    public uint AcceptedExpirySkewBuckets { get; }
    public int MaximumIncompleteMessagesPerReplayScope { get; }
    public int MaximumIncompleteMessagesGlobal { get; }
    public int MaximumReservedBytesGlobal { get; }
    public int MaximumTombstonesPerReplayScope { get; }
    public int MaximumTombstonesGlobal { get; }
    public int MaximumTombstoneBytesGlobal { get; }

    public uint GetRetentionExpiryBucket(uint expiryBucket)
    {
        if (expiryBucket < CurrentExpiryBucket || expiryBucket > ProvisionalExpiryBucket)
        {
            throw new ArgumentOutOfRangeException(nameof(expiryBucket));
        }

        return checked(expiryBucket + AcceptedExpirySkewBuckets);
    }

    private static void ValidateLowerLimit(int value, int minimum, int maximum, string name)
    {
        if (value < minimum || value > maximum)
        {
            throw new ArgumentOutOfRangeException(name, $"The value must be {minimum}..{maximum} and may only lower the V1 ceiling.");
        }
    }
}

public enum LoRaFragmentTerminalStatus : byte
{
    Completed = 1,
    Poisoned = 2
}

public enum LoRaFragmentStoreApplyStatus : byte
{
    Incomplete = 1,
    Ready = 2,
    Rejected = 3,
    OutcomeUnknown = 4
}

public enum LoRaFragmentStoreCommitStatus : byte
{
    Committed = 1,
    GenerationMismatch = 2,
    Rejected = 3,
    OutcomeUnknown = 4
}

public enum LoRaFragmentReassemblyOutcome : byte
{
    Incomplete = 1,
    Completed = 2,
    Rejected = 3,
    OutcomeUnknown = 4
}

public enum LoRaFragmentReassemblyError : byte
{
    None = 0,
    FrameRejected = 1,
    StoreRejected = 2,
    InvalidSnapshot = 3,
    DescriptorRejected = 4,
    BundleRejected = 5,
    ReplayRejected = 6,
    OutcomeUnknown = 7
}

/// <summary>Immutable provider-scoped replay key. The opaque handle is never serialized by protocol code.</summary>
public sealed class LoRaFragmentReplayKey
{
    private readonly byte[] _messageId;

    public LoRaFragmentReplayKey(
        LoRaFragmentReplayScopeHandle replayScope,
        LoRaFragmentDirection direction,
        ReadOnlySpan<byte> messageId)
    {
        ArgumentNullException.ThrowIfNull(replayScope);
        if (direction is not LoRaFragmentDirection.Forward and not LoRaFragmentDirection.Reverse)
        {
            throw new ArgumentOutOfRangeException(nameof(direction));
        }

        if (messageId.Length != LoRaFragmentLimits.MessageIdLength || messageId.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("A replay key requires eight nonzero opaque message-ID bytes.", nameof(messageId));
        }

        ReplayScope = replayScope;
        Direction = direction;
        _messageId = messageId.ToArray();
    }

    public LoRaFragmentReplayScopeHandle ReplayScope { get; }
    public LoRaFragmentDirection Direction { get; }
    public ReadOnlyMemory<byte> MessageId => _messageId.ToArray();
}

/// <summary>Authenticated input handed to the store after codec validation and before persistent copying.</summary>
public sealed class LoRaFragmentAuthenticatedFragment
{
    public LoRaFragmentAuthenticatedFragment(LoRaFragmentReplayKey key, LoRaFragmentFrame frame)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(frame);
        if (!key.MessageId.Span.SequenceEqual(frame.Header.MessageIdSpan))
        {
            throw new ArgumentException("The replay key must use the exact authenticated frame message ID.", nameof(key));
        }

        Key = key;
        Frame = frame;
    }

    public LoRaFragmentReplayKey Key { get; }
    public LoRaFragmentFrame Frame { get; }
    /// <summary>Exact authenticated header and shard; the tag is intentionally excluded for duplicate equality.</summary>
    public ReadOnlyMemory<byte> CanonicalHeaderAndShard
    {
        get
        {
            var bytes = new byte[checked(LoRaFragmentLimits.HeaderLength + Frame.Header.ShardSize)];
            LoRaFragmentCodec.EncodeHeader(Frame.Header).CopyTo(bytes, 0);
            Frame.ShardSpan.CopyTo(bytes.AsSpan(LoRaFragmentLimits.HeaderLength));
            return bytes;
        }
    }

    /// <summary>The exact logical reservation charge that the store must admit atomically.</summary>
    public int ReservationCharge => checked(
        checked(Frame.Header.TotalFragmentCount * Frame.Header.ShardSize) +
        LoRaFragmentReassemblyLimits.ReservationMetadataBytes);
}

/// <summary>Defensive, generation-pinned durable state returned only after sufficient authenticated shards exist.</summary>
public sealed class LoRaFragmentReassemblySnapshot
{
    private readonly byte[]?[] _dataShards;
    private readonly byte[]?[] _parityShards;

    public LoRaFragmentReassemblySnapshot(
        LoRaFragmentReplayKey key,
        LoRaFragmentHeader shape,
        long generation,
        uint expiryBucket,
        IEnumerable<ReadOnlyMemory<byte>?> dataShards,
        IEnumerable<ReadOnlyMemory<byte>?> parityShards)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(shape);
        ArgumentNullException.ThrowIfNull(dataShards);
        ArgumentNullException.ThrowIfNull(parityShards);
        if (!key.MessageId.Span.SequenceEqual(shape.MessageIdSpan))
        {
            throw new ArgumentException("Snapshot key and shape must have the same message ID.", nameof(key));
        }

        _dataShards = CopyShards(dataShards, shape.DataShardCount, shape.ShardSize, nameof(dataShards));
        _parityShards = CopyShards(parityShards, shape.ParityShardCount, shape.ShardSize, nameof(parityShards));
        if (generation < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(generation));
        }

        Key = key;
        Shape = shape;
        Generation = generation;
        ExpiryBucket = expiryBucket;
    }

    public LoRaFragmentReplayKey Key { get; }
    public LoRaFragmentHeader Shape { get; }
    public long Generation { get; }
    public uint ExpiryBucket { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>?> DataShards => CopyForRead(_dataShards);
    public IReadOnlyList<ReadOnlyMemory<byte>?> ParityShards => CopyForRead(_parityShards);

    private static byte[]?[] CopyShards(IEnumerable<ReadOnlyMemory<byte>?> source, int expectedCount, int shardSize, string name)
    {
        var values = source.ToArray();
        if (values.Length != expectedCount)
        {
            throw new ArgumentException("The shard collection does not match the authenticated shape.", name);
        }

        return values.Select(value =>
        {
            if (value is null)
            {
                return null;
            }

            if (value.Value.Length != shardSize)
            {
                throw new ArgumentException("Every present shard must have the exact authenticated size.", name);
            }

            return value.Value.ToArray();
        }).ToArray();
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>?> CopyForRead(IEnumerable<byte[]?> source) =>
        source.Select(static value => value is null ? null : (ReadOnlyMemory<byte>?)value.ToArray()).ToArray();
}

public sealed class LoRaFragmentStoreApplyResult
{
    public LoRaFragmentStoreApplyResult(LoRaFragmentStoreApplyStatus status, LoRaFragmentReassemblySnapshot? snapshot = null)
    {
        if (status == LoRaFragmentStoreApplyStatus.Ready && snapshot is null)
        {
            throw new ArgumentException("A ready store result requires an immutable snapshot.", nameof(snapshot));
        }

        if (status != LoRaFragmentStoreApplyStatus.Ready && snapshot is not null)
        {
            throw new ArgumentException("Only a ready store result may carry a snapshot.", nameof(snapshot));
        }

        Status = status;
        Snapshot = snapshot;
    }

    public LoRaFragmentStoreApplyStatus Status { get; }
    public LoRaFragmentReassemblySnapshot? Snapshot { get; }
}

public sealed class LoRaFragmentTerminalCommit
{
    private readonly byte[]? _bundleDigest;

    public LoRaFragmentTerminalCommit(
        LoRaFragmentReplayKey key,
        long generation,
        LoRaFragmentTerminalStatus status,
        uint expiryBucket,
        uint retentionExpiryBucket,
        ReadOnlySpan<byte> bundleDigest = default)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (generation < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(generation));
        }

        if (status is not LoRaFragmentTerminalStatus.Completed and not LoRaFragmentTerminalStatus.Poisoned)
        {
            throw new ArgumentOutOfRangeException(nameof(status));
        }

        if (status == LoRaFragmentTerminalStatus.Completed && bundleDigest.Length == 0)
        {
            throw new ArgumentException("A completed record requires a canonical bundle digest.", nameof(bundleDigest));
        }

        Key = key;
        Generation = generation;
        Status = status;
        ExpiryBucket = expiryBucket;
        RetentionExpiryBucket = retentionExpiryBucket;
        _bundleDigest = bundleDigest.Length == 0 ? null : bundleDigest.ToArray();
    }

    public LoRaFragmentReplayKey Key { get; }
    public long Generation { get; }
    public LoRaFragmentTerminalStatus Status { get; }
    public uint ExpiryBucket { get; }
    /// <summary>Checked expiry-plus-skew retention deadline for the durable tombstone.</summary>
    public uint RetentionExpiryBucket { get; }
    public ReadOnlyMemory<byte>? BundleDigest =>
        _bundleDigest is null
            ? (ReadOnlyMemory<byte>?)null
            : _bundleDigest.ToArray();
}

public sealed class LoRaFragmentStoreCommitResult
{
    public LoRaFragmentStoreCommitResult(LoRaFragmentStoreCommitStatus status) => Status = status;
    public LoRaFragmentStoreCommitStatus Status { get; }
}

/// <summary>
/// Durable replay/quota boundary. Implementations provide serializable transactions;
/// this contract intentionally exposes only the two P18A mutation boundaries.
/// Apply performs expiry eviction, tombstone/shape checks, full-message reservation
/// (including <see cref="LoRaFragmentAuthenticatedFragment.ReservationCharge"/>), and
/// shard copying in one transaction. Commit must retain terminal records through the
/// supplied checked retention deadline and enforce the policy's tombstone ceilings.
/// </summary>
public interface ILoRaFragmentReplayStore
{
    ValueTask<LoRaFragmentStoreApplyResult> ApplyAuthenticatedFragmentAsync(
        LoRaFragmentAuthenticatedFragment fragment,
        LoRaFragmentReassemblyPolicy policy,
        CancellationToken cancellationToken);

    ValueTask<LoRaFragmentStoreCommitResult> TryCommitTerminalAsync(
        LoRaFragmentTerminalCommit terminal,
        LoRaFragmentReassemblyPolicy policy,
        CancellationToken cancellationToken);

    ValueTask<LoRaFragmentReassemblySnapshot?> ReadAsync(
        LoRaFragmentReplayKey key,
        CancellationToken cancellationToken);
}

public sealed class LoRaFragmentReassemblyRequest
{
    private readonly ReadOnlyMemory<byte> _encodedFrame;

    public LoRaFragmentReassemblyRequest(
        ReadOnlyMemory<byte> encodedFrame,
        LoRaFragmentAuthenticationHandle authenticationHandle,
        LoRaFragmentReplayScopeHandle replayScope,
        LoRaFragmentDirection direction)
    {
        ArgumentNullException.ThrowIfNull(authenticationHandle);
        ArgumentNullException.ThrowIfNull(replayScope);
        if (direction is not LoRaFragmentDirection.Forward and not LoRaFragmentDirection.Reverse)
        {
            throw new ArgumentOutOfRangeException(nameof(direction));
        }

        // This is an ephemeral input view, not retained reassembly state. The
        // caller keeps it stable until Process/ProcessAsync begins; the codec
        // authenticates it synchronously before the first retained shard copy.
        _encodedFrame = encodedFrame;
        AuthenticationHandle = authenticationHandle;
        ReplayScope = replayScope;
        Direction = direction;
    }

    public ReadOnlyMemory<byte> EncodedFrame => _encodedFrame;
    public LoRaFragmentAuthenticationHandle AuthenticationHandle { get; }
    public LoRaFragmentReplayScopeHandle ReplayScope { get; }
    public LoRaFragmentDirection Direction { get; }
}

public sealed class LoRaFragmentReassemblyResult
{
    private readonly byte[]? _encodedOpaqueBundle;

    public LoRaFragmentReassemblyResult(LoRaFragmentReassemblyOutcome outcome, LoRaFragmentReassemblyError error = LoRaFragmentReassemblyError.None, ReadOnlySpan<byte> encodedOpaqueBundle = default)
    {
        if (outcome == LoRaFragmentReassemblyOutcome.Completed && encodedOpaqueBundle.Length == 0)
        {
            throw new ArgumentException("Completed reassembly requires an exact opaque bundle.", nameof(encodedOpaqueBundle));
        }

        if (outcome != LoRaFragmentReassemblyOutcome.Completed && encodedOpaqueBundle.Length != 0)
        {
            throw new ArgumentException("Only completed reassembly may return bundle bytes.", nameof(encodedOpaqueBundle));
        }

        Outcome = outcome;
        Error = error;
        _encodedOpaqueBundle = encodedOpaqueBundle.Length == 0 ? null : encodedOpaqueBundle.ToArray();
    }

    public LoRaFragmentReassemblyOutcome Outcome { get; }
    public LoRaFragmentReassemblyError Error { get; }
    public ReadOnlyMemory<byte>? EncodedOpaqueBundle =>
        _encodedOpaqueBundle is null
            ? (ReadOnlyMemory<byte>?)null
            : _encodedOpaqueBundle.ToArray();
}

/// <summary>Bounded coordinator over an externally supplied durable replay store.</summary>
public sealed class LoRaFragmentReassembler
{
    private readonly ILoRaFragmentReplayStore _store;
    private readonly LoRaFragmentReassemblyPolicy _policy;
    private readonly ILoRaFragmentAuthenticator _authenticator;

    public LoRaFragmentReassembler(
        ILoRaFragmentReplayStore store,
        LoRaFragmentReassemblyPolicy policy,
        ILoRaFragmentAuthenticator authenticator)
    {
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(authenticator);
        _store = store;
        _policy = policy;
        _authenticator = authenticator;
    }

    /// <summary>Non-blocking canonical entry point; no synchronous wait or wake-lock policy is implied.</summary>
    public ValueTask<LoRaFragmentReassemblyResult> Process(
        LoRaFragmentReassemblyRequest request,
        CancellationToken cancellationToken = default) =>
        ProcessAsync(request, cancellationToken);

    public ValueTask<LoRaFragmentReassemblyResult> ProcessAsync(LoRaFragmentReassemblyRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return ProcessCoreAsync(request, cancellationToken);
    }

    private async ValueTask<LoRaFragmentReassemblyResult> ProcessCoreAsync(LoRaFragmentReassemblyRequest request, CancellationToken cancellationToken)
    {
        LoRaFragmentFrame frame;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            frame = LoRaFragmentCodec.Decode(request.EncodedFrame.Span, _policy.FragmentPolicy, request.AuthenticationHandle, request.Direction, _authenticator);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            return Rejected(LoRaFragmentReassemblyError.FrameRejected);
        }
        catch (Exception exception) when (IsRecoverable(exception))
        {
            return Rejected(LoRaFragmentReassemblyError.FrameRejected);
        }

        var key = new LoRaFragmentReplayKey(request.ReplayScope, request.Direction, frame.Header.MessageIdSpan);
        LoRaFragmentStoreApplyResult applied;
        try
        {
            applied = await _store.ApplyAuthenticatedFragmentAsync(new LoRaFragmentAuthenticatedFragment(key, frame), _policy, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            await ReconcileAsync(key, CancellationToken.None).ConfigureAwait(false);
            return Unknown();
        }
        catch (Exception exception) when (IsRecoverable(exception))
        {
            await ReconcileAsync(key, CancellationToken.None).ConfigureAwait(false);
            return Unknown();
        }

        if (applied.Status == LoRaFragmentStoreApplyStatus.OutcomeUnknown)
        {
            await ReconcileAsync(key, cancellationToken).ConfigureAwait(false);
            return Unknown();
        }

        if (applied.Status == LoRaFragmentStoreApplyStatus.Rejected)
        {
            return Rejected(LoRaFragmentReassemblyError.StoreRejected);
        }

        if (applied.Status == LoRaFragmentStoreApplyStatus.Incomplete)
        {
            return new LoRaFragmentReassemblyResult(LoRaFragmentReassemblyOutcome.Incomplete);
        }

        if (applied.Status != LoRaFragmentStoreApplyStatus.Ready || applied.Snapshot is null)
        {
            return Unknown();
        }

        var snapshot = applied.Snapshot;
        if (!SnapshotMatches(snapshot, key, frame.Header))
        {
            return await PoisonAsync(snapshot, LoRaFragmentReassemblyError.InvalidSnapshot, cancellationToken).ConfigureAwait(false);
        }

        var reconstruction = TryReconstructData(snapshot, out var reconstructedData);
        if (reconstruction == LoRaFragmentReconstructionStatus.Incomplete)
        {
            // A store may pessimistically return a snapshot; it is not terminal until all data is present or recoverable.
            return new LoRaFragmentReassemblyResult(LoRaFragmentReassemblyOutcome.Incomplete);
        }
        if (reconstruction == LoRaFragmentReconstructionStatus.Invalid)
        {
            return await PoisonAsync(
                snapshot,
                LoRaFragmentReassemblyError.InvalidSnapshot,
                cancellationToken).ConfigureAwait(false);
        }

        if (!TryValidateAndDecode(snapshot, reconstructedData, out var bundle, out var error))
        {
            return await PoisonAsync(snapshot, error, cancellationToken).ConfigureAwait(false);
        }

        var digest = System.Security.Cryptography.SHA256.HashData(bundle);
        var terminal = new LoRaFragmentTerminalCommit(
            key,
            snapshot.Generation,
            LoRaFragmentTerminalStatus.Completed,
            snapshot.ExpiryBucket,
            _policy.GetRetentionExpiryBucket(snapshot.ExpiryBucket),
            digest);
        LoRaFragmentStoreCommitResult committed;
        try
        {
            committed = await _store.TryCommitTerminalAsync(terminal, _policy, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return Unknown();
        }
        catch (Exception exception) when (IsRecoverable(exception))
        {
            return Unknown();
        }

        if (committed.Status == LoRaFragmentStoreCommitStatus.Committed)
        {
            return new LoRaFragmentReassemblyResult(LoRaFragmentReassemblyOutcome.Completed, LoRaFragmentReassemblyError.None, bundle);
        }

        if (!await ReconcileAsync(key, cancellationToken).ConfigureAwait(false))
        {
            return Unknown();
        }

        return committed.Status == LoRaFragmentStoreCommitStatus.OutcomeUnknown ? Unknown() : Rejected(LoRaFragmentReassemblyError.ReplayRejected);
    }

    private async ValueTask<LoRaFragmentReassemblyResult> PoisonAsync(LoRaFragmentReassemblySnapshot snapshot, LoRaFragmentReassemblyError error, CancellationToken cancellationToken)
    {
        try
        {
            var terminal = new LoRaFragmentTerminalCommit(
                snapshot.Key,
                snapshot.Generation,
                LoRaFragmentTerminalStatus.Poisoned,
                snapshot.ExpiryBucket,
                _policy.GetRetentionExpiryBucket(snapshot.ExpiryBucket));
            var result = await _store.TryCommitTerminalAsync(terminal, _policy, cancellationToken).ConfigureAwait(false);
            if (result.Status == LoRaFragmentStoreCommitStatus.Committed)
            {
                return Rejected(error);
            }

            await ReconcileAsync(snapshot.Key, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (IsRecoverable(exception))
        {
            // A cancellation or store failure has an unknown durable outcome.
        }

        return Unknown();
    }

    private async ValueTask<bool> ReconcileAsync(LoRaFragmentReplayKey key, CancellationToken cancellationToken)
    {
        try
        {
            _ = await _store.ReadAsync(key, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (Exception exception) when (IsRecoverable(exception))
        {
            // Read failure is deliberately indistinguishable from an unknown mutation outcome.
            return false;
        }
    }

    private bool TryValidateAndDecode(LoRaFragmentReassemblySnapshot snapshot, byte[] data, out byte[] bundle, out LoRaFragmentReassemblyError error)
    {
        bundle = Array.Empty<byte>();
        error = LoRaFragmentReassemblyError.DescriptorRejected;
        if (data.Length < LoRaFragmentLimits.DescriptorLength ||
            data[0] != LoRaFragmentLimits.DescriptorVersion ||
            data[1] != LoRaFragmentLimits.OpaqueBundlePayloadKind ||
            data[2] != LoRaFragmentLimits.OpaqueBundleWireVersion)
        {
            return false;
        }

        var currentHop = (byte)(data[3] >> 4);
        var hopLimit = (byte)(data[3] & 0x0f);
        if (currentHop >= hopLimit || hopLimit > 15)
        {
            return false;
        }

        var bundleLength = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(4, 2));
        var descriptorExpiry = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(6, 4));
        if (bundleLength < LoRaFragmentLimits.MinimumBundleLength ||
            bundleLength > LoRaFragmentLimits.MaximumBundleLength ||
            bundleLength > _policy.FragmentPolicy.MaxBundleLength ||
            descriptorExpiry < _policy.CurrentExpiryBucket ||
            descriptorExpiry > _policy.ProvisionalExpiryBucket ||
            descriptorExpiry < _policy.FragmentPolicy.OpaqueBundleDecodePolicy.MinimumExpiryBucket ||
            descriptorExpiry > _policy.FragmentPolicy.OpaqueBundleDecodePolicy.MaximumExpiryBucket ||
            snapshot.ExpiryBucket != descriptorExpiry)
        {
            return false;
        }

        var describedLength = checked(LoRaFragmentLimits.DescriptorLength + (int)bundleLength);
        var expectedDataCount = checked((describedLength + snapshot.Shape.ShardSize - 1) / snapshot.Shape.ShardSize);
        if (snapshot.Shape.DataShardCount != expectedDataCount || describedLength > data.Length || data.AsSpan(describedLength).IndexOfAnyExcept((byte)0) >= 0)
        {
            return false;
        }

        bundle = data.AsSpan(LoRaFragmentLimits.DescriptorLength, bundleLength).ToArray();
        try
        {
            var decoded = OpaqueBundleCodec.Decode(bundle, _policy.FragmentPolicy.OpaqueBundleDecodePolicy);
            if (decoded.WireVersion != OpaqueBundleWireVersion.V1 || decoded.ExpiryBucket != descriptorExpiry)
            {
                error = LoRaFragmentReassemblyError.BundleRejected;
                return false;
            }
        }
        catch (OpaqueBundleException)
        {
            error = LoRaFragmentReassemblyError.BundleRejected;
            return false;
        }

        error = LoRaFragmentReassemblyError.None;
        return true;
    }

    private static LoRaFragmentReconstructionStatus TryReconstructData(
        LoRaFragmentReassemblySnapshot snapshot,
        out byte[] data)
    {
        var shape = snapshot.Shape;
        var presentData = snapshot.DataShards.Select(static shard => shard?.ToArray()).ToArray();
        var presentParity = snapshot.ParityShards.Select(static shard => shard?.ToArray()).ToArray();
        if (shape.FecMode == LoRaFragmentFecMode.Xor1)
        {
            for (var group = 0; group < shape.ParityShardCount; group++)
            {
                var first = checked(group * LoRaFragmentLimits.XorDataShardsPerGroup);
                var end = Math.Min(shape.DataShardCount, checked(first + LoRaFragmentLimits.XorDataShardsPerGroup));
                var missing = -1;
                for (var index = first; index < end; index++)
                {
                    if (presentData[index] is null)
                    {
                        if (missing >= 0)
                        {
                            missing = -2;
                            break;
                        }

                        missing = index;
                    }
                }

                if (missing >= 0 && presentParity[group] is not null)
                {
                    var recovered = presentParity[group]!.ToArray();
                    for (var index = first; index < end; index++)
                    {
                        if (index == missing)
                        {
                            continue;
                        }

                        var member = presentData[index];
                        if (member is null)
                        {
                            data = Array.Empty<byte>();
                            return LoRaFragmentReconstructionStatus.Incomplete;
                        }

                        for (var offset = 0; offset < recovered.Length; offset++)
                        {
                            recovered[offset] ^= member[offset];
                        }
                    }

                    presentData[missing] = recovered;
                }

                if (presentParity[group] is { } parity &&
                    presentData
                        .Skip(first)
                        .Take(end - first)
                        .All(static shard => shard is not null))
                {
                    var expectedParity = new byte[shape.ShardSize];
                    for (var index = first; index < end; index++)
                    {
                        var member = presentData[index]!;
                        for (var offset = 0; offset < expectedParity.Length; offset++)
                        {
                            expectedParity[offset] ^= member[offset];
                        }
                    }

                    if (!expectedParity.AsSpan().SequenceEqual(parity))
                    {
                        data = Array.Empty<byte>();
                        return LoRaFragmentReconstructionStatus.Invalid;
                    }
                }
            }
        }

        if (presentData.Any(static shard => shard is null))
        {
            data = Array.Empty<byte>();
            return LoRaFragmentReconstructionStatus.Incomplete;
        }

        try
        {
            data = new byte[checked(shape.DataShardCount * shape.ShardSize)];
            for (var index = 0; index < presentData.Length; index++)
            {
                presentData[index]!.CopyTo(data, checked(index * shape.ShardSize));
            }

            return LoRaFragmentReconstructionStatus.Complete;
        }
        catch (OverflowException)
        {
            data = Array.Empty<byte>();
            return LoRaFragmentReconstructionStatus.Invalid;
        }
    }

    private static bool SnapshotMatches(LoRaFragmentReassemblySnapshot snapshot, LoRaFragmentReplayKey key, LoRaFragmentHeader header) =>
        // Provider-issued scope handles are opaque, but their object identity is
        // still part of the replay key and must survive an untrusted store round trip.
        ReferenceEquals(snapshot.Key.ReplayScope, key.ReplayScope) &&
        snapshot.Key.Direction == key.Direction &&
        snapshot.Key.MessageId.Span.SequenceEqual(key.MessageId.Span) &&
        snapshot.Shape.MessageIdSpan.SequenceEqual(header.MessageIdSpan) &&
        snapshot.Shape.DataShardCount == header.DataShardCount &&
        snapshot.Shape.ParityShardCount == header.ParityShardCount &&
        snapshot.Shape.ShardSize == header.ShardSize &&
        snapshot.Shape.FecMode == header.FecMode;

    private enum LoRaFragmentReconstructionStatus : byte
    {
        Incomplete = 1,
        Complete = 2,
        Invalid = 3
    }

    private static LoRaFragmentReassemblyResult Rejected(LoRaFragmentReassemblyError error) =>
        new(LoRaFragmentReassemblyOutcome.Rejected, error);

    private static LoRaFragmentReassemblyResult Unknown() =>
        new(LoRaFragmentReassemblyOutcome.OutcomeUnknown, LoRaFragmentReassemblyError.OutcomeUnknown);

    private static bool IsRecoverable(Exception exception)
    {
        if (exception is
            OutOfMemoryException or
            StackOverflowException or
            AccessViolationException or
            AppDomainUnloadedException)
        {
            return false;
        }

        if (exception is AggregateException aggregate)
        {
            return aggregate.InnerExceptions.All(IsRecoverable);
        }

        return exception.InnerException is null || IsRecoverable(exception.InnerException);
    }
}
