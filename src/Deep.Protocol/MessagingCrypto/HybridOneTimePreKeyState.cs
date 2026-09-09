using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;

namespace Deep.Protocol.MessagingCrypto;

internal enum PreKeyConsumeOutcome { Fresh, ExactReplay }
internal enum PreKeySecretKind { X25519OneTime, MlKem768OneTime }

internal sealed class PreKeyDeletionObligation
{
    private readonly byte[] _preKeyId;

    internal PreKeyDeletionObligation(PreKeySecretKind kind, ReadOnlySpan<byte> preKeyId)
    {
        Kind = kind;
        _preKeyId = preKeyId.ToArray();
    }

    internal PreKeySecretKind Kind { get; }
    internal ReadOnlyMemory<byte> PreKeyId => _preKeyId.ToArray();
}

internal sealed class ClaimedHybridPreKeyData : IDisposable
{
    internal ClaimedHybridPreKeyData(
        byte[]? x25519PrivateKey,
        byte[] mlKemDecapsulationKey,
        byte[] sessionId,
        byte[] initiationHash,
        byte[]? x25519PreKeyId,
        byte[] mlKemPreKeyId)
    {
        X25519PrivateKey = x25519PrivateKey;
        MlKemDecapsulationKey = mlKemDecapsulationKey;
        SessionId = sessionId;
        InitiationHash = initiationHash;
        X25519PreKeyId = x25519PreKeyId;
        MlKemPreKeyId = mlKemPreKeyId;
    }

    internal byte[]? X25519PrivateKey { get; }
    internal byte[] MlKemDecapsulationKey { get; }
    internal byte[] SessionId { get; }
    internal byte[] InitiationHash { get; }
    internal byte[]? X25519PreKeyId { get; }
    internal byte[] MlKemPreKeyId { get; }

    public void Dispose()
    {
        if (X25519PrivateKey is not null) CryptographicOperations.ZeroMemory(X25519PrivateKey);
        CryptographicOperations.ZeroMemory(MlKemDecapsulationKey);
    }
}

internal sealed class ClaimedHybridPreKeyLease : IDisposable
{
    private SecretBuffer? _x25519PrivateKey;
    private SecretBuffer? _mlKemDecapsulationKey;
    private readonly byte[] _sessionId;
    private readonly byte[] _initiationHash;
    private readonly byte[]? _x25519PreKeyId;
    private readonly byte[] _mlKemPreKeyId;
    private int _state;

    internal ClaimedHybridPreKeyLease(
        SecretBuffer? x25519PrivateKey,
        SecretBuffer mlKemDecapsulationKey,
        VerifiedPreKeyClaimData claim)
    {
        SecretBuffer? x25519 = null;
        SecretBuffer? mlKem = null;
        try
        {
            x25519 = x25519PrivateKey?.Clone();
            if (x25519 is not null)
                MessagingCryptoFaultInjection.OwnedSecret("prekey.claimed.x25519", x25519);
            mlKem = mlKemDecapsulationKey.Clone();
            MessagingCryptoFaultInjection.OwnedSecret("prekey.claimed.ml-kem", mlKem);
            _sessionId = claim.SessionId.ToArray();
            _initiationHash = claim.InitiationHash.ToArray();
            _x25519PreKeyId = claim.X25519PreKeyId?.ToArray();
            _mlKemPreKeyId = claim.MlKemPreKeyId.ToArray();
            _x25519PrivateKey = x25519; x25519 = null;
            _mlKemDecapsulationKey = mlKem; mlKem = null;
        }
        finally
        {
            x25519?.Dispose();
            mlKem?.Dispose();
        }
    }

    internal ClaimedHybridPreKeyData ConsumeForHandshake()
    {
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0) throw Consumed();
        byte[]? x25519 = null;
        byte[]? mlKem = null;
        try
        {
            x25519 = _x25519PrivateKey?.Copy();
            mlKem = _mlKemDecapsulationKey!.Copy();
            var data = new ClaimedHybridPreKeyData(
                x25519,
                mlKem,
                _sessionId.ToArray(),
                _initiationHash.ToArray(),
                _x25519PreKeyId?.ToArray(),
                _mlKemPreKeyId.ToArray());
            x25519 = null;
            mlKem = null;
            DisposeOwned();
            return data;
        }
        finally
        {
            if (x25519 is not null) CryptographicOperations.ZeroMemory(x25519);
            if (mlKem is not null) CryptographicOperations.ZeroMemory(mlKem);
            DisposeOwned();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _state, 2) == 0) DisposeOwned();
    }

    private void DisposeOwned()
    {
        _x25519PrivateKey?.Dispose(); _x25519PrivateKey = null;
        _mlKemDecapsulationKey?.Dispose(); _mlKemDecapsulationKey = null;
    }

    private static MessagingCryptoException Consumed() => new(
        MessagingCryptoError.CapabilityConsumed,
        "The claimed hybrid prekey lease is single-use.");
}

internal sealed class HybridOneTimePreKeyState : IDisposable
{
    private readonly object _lifecycleSync = new();
    private readonly byte[]? _x25519PreKeyId;
    private readonly byte[] _mlKemPreKeyId;
    private readonly SecretBuffer? _x25519PrivateKey;
    private readonly SecretBuffer? _mlKemDecapsulationKey;
    private readonly byte[]? _committedClaimId;
    private readonly byte[]? _committedSessionId;
    private readonly byte[]? _committedInitiationHash;
    private readonly byte[] _stateCommitment;
    private bool _disposed;

    private HybridOneTimePreKeyState(
        byte[]? x25519PreKeyId,
        byte[] mlKemPreKeyId,
        SecretBuffer? x25519PrivateKey,
        SecretBuffer? mlKemDecapsulationKey,
        ulong storageGeneration,
        byte[]? claimId,
        byte[]? sessionId,
        byte[]? initiationHash)
    {
        _x25519PreKeyId = x25519PreKeyId;
        _mlKemPreKeyId = mlKemPreKeyId;
        _x25519PrivateKey = x25519PrivateKey;
        _mlKemDecapsulationKey = mlKemDecapsulationKey;
        StorageGeneration = storageGeneration;
        _committedClaimId = claimId;
        _committedSessionId = sessionId;
        _committedInitiationHash = initiationHash;
        _stateCommitment = ComputeCommitment();
    }

    internal bool IsConsumed => _committedClaimId is not null;
    internal ulong StorageGeneration { get; }
    internal ReadOnlyMemory<byte> StateCommitment => _stateCommitment.ToArray();

    internal static HybridOneTimePreKeyState Create(
        ReadOnlySpan<byte> x25519PreKeyId,
        ReadOnlySpan<byte> x25519PrivateKey,
        ReadOnlySpan<byte> mlKemPreKeyId,
        ReadOnlySpan<byte> mlKemDecapsulationKey,
        ulong storageGeneration = 0)
    {
        if (x25519PreKeyId.IsEmpty != x25519PrivateKey.IsEmpty)
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The X25519 one-time key ID and secret must both be present or absent.");
        if (!x25519PreKeyId.IsEmpty)
        {
            MessagingCryptoValidation.NonZeroExact(x25519PreKeyId, 32, nameof(x25519PreKeyId));
            MessagingCryptoValidation.NonZeroExact(x25519PrivateKey, 32, nameof(x25519PrivateKey));
        }
        MessagingCryptoValidation.NonZeroExact(mlKemPreKeyId, 32, nameof(mlKemPreKeyId));
        if (mlKemDecapsulationKey.Length is < 1 or > 4096 ||
            MessagingCryptoValidation.IsZero(mlKemDecapsulationKey))
            throw new MessagingCryptoException(
                MessagingCryptoError.InvalidInput,
                "The provider-owned ML-KEM decapsulation key is invalid.");

        SecretBuffer? x25519 = null;
        SecretBuffer? mlKem = null;
        try
        {
            x25519 = x25519PrivateKey.IsEmpty
                ? null
                : SecretBuffer.ImportExact(x25519PrivateKey, 32, nameof(x25519PrivateKey));
            mlKem = SecretBuffer.ImportBounded(mlKemDecapsulationKey, 1, 4096, nameof(mlKemDecapsulationKey));
            var state = new HybridOneTimePreKeyState(
                x25519PreKeyId.IsEmpty ? null : x25519PreKeyId.ToArray(),
                mlKemPreKeyId.ToArray(),
                x25519,
                mlKem,
                storageGeneration,
                null, null, null);
            x25519 = null;
            mlKem = null;
            return state;
        }
        finally
        {
            x25519?.Dispose();
            mlKem?.Dispose();
        }
    }

    internal OneTimePreKeyConsumePlan PrepareConsume(VerifiedPreKeyClaimCapability capability)
    {
        lock (_lifecycleSync)
        {
        ThrowIfDisposed();
        MessagingCryptoFaultInjection.Point("prekey.prepare-entered");
        ArgumentNullException.ThrowIfNull(capability);
        var claim = capability.Consume();
        if (!MessagingCryptoValidation.FixedEquals(_mlKemPreKeyId, claim.MlKemPreKeyId) ||
            !OptionalEquals(_x25519PreKeyId, claim.X25519PreKeyId))
            throw new MessagingCryptoException(
                MessagingCryptoError.PreKeyConflict,
                "The verified claim names a different hybrid prekey set.");

        var cas = new PersistenceCasExpectation(StorageGeneration, _stateCommitment);
        if (IsConsumed)
        {
            if (MessagingCryptoValidation.FixedEquals(_committedClaimId!, claim.ClaimId) &&
                MessagingCryptoValidation.FixedEquals(_committedSessionId!, claim.SessionId) &&
                MessagingCryptoValidation.FixedEquals(_committedInitiationHash!, claim.InitiationHash))
                return OneTimePreKeyConsumePlan.ExactReplay(cas);
            if (MessagingCryptoValidation.FixedEquals(_committedClaimId!, claim.ClaimId) ||
                MessagingCryptoValidation.FixedEquals(_committedSessionId!, claim.SessionId))
                throw new MessagingCryptoException(
                    MessagingCryptoError.PreKeyConflict,
                    "A consumed prekey claim or session was replayed with changed bytes.");
            throw new MessagingCryptoException(
                MessagingCryptoError.PreKeyAlreadyConsumed,
                "The hybrid one-time prekey was already consumed by another claim.");
        }

        if (_mlKemDecapsulationKey is null)
            throw new MessagingCryptoException(MessagingCryptoError.ObjectDisposed, "Prekey material is unavailable.");
        HybridOneTimePreKeyState? next = null;
        ClaimedHybridPreKeyLease? claimedLease = null;
        var ownershipTransferred = false;
        try
        {
            next = new HybridOneTimePreKeyState(
                _x25519PreKeyId?.ToArray(),
                _mlKemPreKeyId.ToArray(),
                null,
                null,
                checked(StorageGeneration + 1),
                claim.ClaimId.ToArray(),
                claim.SessionId.ToArray(),
                claim.InitiationHash.ToArray());
            MessagingCryptoFaultInjection.OwnedDisposable("prekey.next-state", next);
            claimedLease = new ClaimedHybridPreKeyLease(
                _x25519PrivateKey, _mlKemDecapsulationKey, claim);
            MessagingCryptoFaultInjection.OwnedDisposable("prekey.claimed-lease", claimedLease);
            MessagingCryptoFaultInjection.Point("prekey.before-obligations-plan");
            var deletions = new List<PreKeyDeletionObligation>
            {
                new(PreKeySecretKind.MlKem768OneTime, _mlKemPreKeyId),
            };
            if (_x25519PreKeyId is not null)
                deletions.Insert(0, new PreKeyDeletionObligation(PreKeySecretKind.X25519OneTime, _x25519PreKeyId));
            MessagingCryptoFaultInjection.Point("prekey.after-obligations-before-plan");
            var plan = OneTimePreKeyConsumePlan.Fresh(cas, next, claimedLease, deletions);
            ownershipTransferred = true;
            next = null;
            claimedLease = null;
            return plan;
        }
        finally
        {
            if (!ownershipTransferred)
            {
                next?.Dispose();
                claimedLease?.Dispose();
            }
        }
        }
    }

    public void Dispose()
    {
        lock (_lifecycleSync)
        {
            if (_disposed) return;
            _disposed = true;
            _x25519PrivateKey?.Dispose();
            _mlKemDecapsulationKey?.Dispose();
        }
    }

    private byte[] ComputeCommitment()
    {
        byte[]? xSecret = null;
        byte[]? mlSecret = null;
        byte[]? xHash = null;
        byte[]? mlHash = null;
        try
        {
            xSecret = _x25519PrivateKey?.Copy();
            mlSecret = _mlKemDecapsulationKey?.Copy();
            xHash = xSecret is null ? new byte[32] : SHA256.HashData(xSecret);
            mlHash = mlSecret is null ? new byte[32] : SHA256.HashData(mlSecret);
            Span<byte> fixedPart = stackalloc byte[8 + 1 + 32 + 32 + 32 + 32 + 32 + 32 + 32];
            BinaryPrimitives.WriteUInt64BigEndian(fixedPart, StorageGeneration);
            fixedPart[8] = IsConsumed ? (byte)1 : (byte)0;
            (_x25519PreKeyId ?? new byte[32]).CopyTo(fixedPart[9..]);
            _mlKemPreKeyId.CopyTo(fixedPart[41..]);
            xHash.CopyTo(fixedPart[73..]);
            mlHash.CopyTo(fixedPart[105..]);
            (_committedClaimId ?? new byte[32]).CopyTo(fixedPart[137..]);
            (_committedSessionId ?? new byte[32]).CopyTo(fixedPart[169..]);
            (_committedInitiationHash ?? new byte[32]).CopyTo(fixedPart[201..]);
            return MessagingKdf.Sha256Domain("Deep/Messaging/V2/prekey-state", fixedPart);
        }
        finally
        {
            if (xSecret is not null) CryptographicOperations.ZeroMemory(xSecret);
            if (mlSecret is not null) CryptographicOperations.ZeroMemory(mlSecret);
            if (xHash is not null) CryptographicOperations.ZeroMemory(xHash);
            if (mlHash is not null) CryptographicOperations.ZeroMemory(mlHash);
        }
    }

    private static bool OptionalEquals(byte[]? left, byte[]? right) =>
        left is null && right is null ||
        left is not null && right is not null && MessagingCryptoValidation.FixedEquals(left, right);

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new MessagingCryptoException(
                MessagingCryptoError.ObjectDisposed,
                "The hybrid prekey state has been disposed.");
    }
}

internal sealed class OneTimePreKeyCommit : IDisposable
{
    private HybridOneTimePreKeyState? _nextState;
    private ClaimedHybridPreKeyLease? _claimedLease;

    internal OneTimePreKeyCommit(
        PreKeyConsumeOutcome outcome,
        HybridOneTimePreKeyState? nextState,
        ClaimedHybridPreKeyLease? claimedLease,
        PersistenceCasExpectation stateCas,
        IReadOnlyList<PreKeyDeletionObligation> deletions)
    {
        Outcome = outcome;
        _nextState = nextState;
        _claimedLease = claimedLease;
        StateCas = stateCas;
        DeletionObligations = deletions;
    }

    internal PreKeyConsumeOutcome Outcome { get; }
    internal bool HasNextState => _nextState is not null;
    internal bool HasClaimedLease => _claimedLease is not null;
    internal PersistenceCasExpectation StateCas { get; }
    internal IReadOnlyList<PreKeyDeletionObligation> DeletionObligations { get; }

    internal HybridOneTimePreKeyState TakeNextState() =>
        Interlocked.Exchange(ref _nextState, null) ?? throw new MessagingCryptoException(
            MessagingCryptoError.CapabilityConsumed, "The next prekey state is unavailable.");

    internal ClaimedHybridPreKeyLease TakeClaimedLease() =>
        Interlocked.Exchange(ref _claimedLease, null) ?? throw new MessagingCryptoException(
            MessagingCryptoError.CapabilityConsumed, "The claimed prekey lease is unavailable.");

    public void Dispose()
    {
        Interlocked.Exchange(ref _nextState, null)?.Dispose();
        Interlocked.Exchange(ref _claimedLease, null)?.Dispose();
    }
}

internal sealed class OneTimePreKeyConsumePlan : IDisposable
{
    private HybridOneTimePreKeyState? _nextState;
    private ClaimedHybridPreKeyLease? _claimedLease;
    private int _state;

    private OneTimePreKeyConsumePlan(
        PreKeyConsumeOutcome outcome,
        PersistenceCasExpectation stateCas,
        HybridOneTimePreKeyState? nextState,
        ClaimedHybridPreKeyLease? claimedLease,
        IReadOnlyList<PreKeyDeletionObligation> deletions)
    {
        Outcome = outcome;
        StateCas = stateCas;
        _nextState = nextState;
        _claimedLease = claimedLease;
        DeletionObligations = deletions;
    }

    internal PreKeyConsumeOutcome Outcome { get; }
    internal PersistenceCasExpectation StateCas { get; }
    internal IReadOnlyList<PreKeyDeletionObligation> DeletionObligations { get; }
    internal ulong? ProposedGeneration => _nextState?.StorageGeneration;
    internal ReadOnlyMemory<byte> ProposedStateCommitment =>
        _nextState?.StateCommitment ?? ReadOnlyMemory<byte>.Empty;

    internal static OneTimePreKeyConsumePlan Fresh(
        PersistenceCasExpectation cas,
        HybridOneTimePreKeyState next,
        ClaimedHybridPreKeyLease lease,
        IReadOnlyList<PreKeyDeletionObligation> deletions) =>
        new(PreKeyConsumeOutcome.Fresh, cas, next, lease, deletions);

    internal static OneTimePreKeyConsumePlan ExactReplay(PersistenceCasExpectation cas) =>
        new(PreKeyConsumeOutcome.ExactReplay, cas, null, null, []);

    internal OneTimePreKeyCommit Commit(DurableDatabaseCasSuccessCapability durableCasSuccess)
    {
        ArgumentNullException.ThrowIfNull(durableCasSuccess);
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0) throw Consumed();
        var next = Interlocked.Exchange(ref _nextState, null);
        var lease = Interlocked.Exchange(ref _claimedLease, null);
        try
        {
            if (Outcome != PreKeyConsumeOutcome.Fresh || next is null || lease is null)
                throw new MessagingCryptoException(
                    MessagingCryptoError.TransitionRejected,
                    "Only a fresh prekey plan can be durably committed.");
            durableCasSuccess.ConsumeAndVerify(
                StateCas,
                next.StorageGeneration,
                next.StateCommitment.Span);
            var commit = new OneTimePreKeyCommit(Outcome, next, lease, StateCas, DeletionObligations);
            next = null;
            lease = null;
            return commit;
        }
        finally
        {
            next?.Dispose();
            lease?.Dispose();
        }
    }

    internal OneTimePreKeyCommit ConsumeExactReplay()
    {
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0) throw Consumed();
        if (Outcome != PreKeyConsumeOutcome.ExactReplay || _nextState is not null || _claimedLease is not null)
            throw new MessagingCryptoException(
                MessagingCryptoError.TransitionRejected,
                "Only an exact replay plan can bypass a state CAS mutation.");
        return new OneTimePreKeyCommit(Outcome, null, null, StateCas, DeletionObligations);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _state, 2) != 0) return;
        Interlocked.Exchange(ref _nextState, null)?.Dispose();
        Interlocked.Exchange(ref _claimedLease, null)?.Dispose();
    }

    private static MessagingCryptoException Consumed() => new(
        MessagingCryptoError.CapabilityConsumed,
        "The prekey transition plan is single-consumer.");
}
