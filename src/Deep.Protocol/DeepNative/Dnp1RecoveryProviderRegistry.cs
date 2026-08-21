using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// Defensively owned lookup selector for the reset-surviving recovery provider registry.
/// Protocol constructs it only from one canonical DRC1; callers cannot select a reset or key ID.
/// </summary>
public sealed class RecoveryProviderRegistryRequest
{
    public const int OperationSelectorLength = 120;
    private readonly byte[] _operationSelector;

    internal RecoveryProviderRegistryRequest(OwnedRecord drc)
    {
        _operationSelector = new byte[OperationSelectorLength];
        var offset = 0;
        Append(drc.FieldSpan(1));
        Append(drc.FieldSpan(2));
        Append(drc.FieldSpan(4));
        Append(drc.FieldSpan(3));
        Append(drc.FieldSpan(13));
        if (offset != OperationSelectorLength)
            Invalid("The recovery provider operation selector has an invalid length.");
        RetainUntilUnixSeconds = Scalars.UInt64(drc.FieldSpan(15));

        void Append(ReadOnlySpan<byte> value)
        {
            value.CopyTo(_operationSelector.AsSpan(offset));
            offset += value.Length;
        }
    }

    public ReadOnlyMemory<byte> OperationSelector => _operationSelector.ToArray();
    public ReadOnlyMemory<byte> NetworkId => _operationSelector.AsSpan(0, 16).ToArray();
    public ReadOnlyMemory<byte> ComponentSubject => _operationSelector.AsSpan(16, 32).ToArray();
    public ulong AccountGeneration => BinaryPrimitives.ReadUInt64BigEndian(_operationSelector.AsSpan(48, 8));
    public ReadOnlyMemory<byte> TransactionId => _operationSelector.AsSpan(56, 32).ToArray();
    public ReadOnlyMemory<byte> ProtectorKeyId => _operationSelector.AsSpan(88, 32).ToArray();
    public ulong RetainUntilUnixSeconds { get; }

    internal ReadOnlySpan<byte> TrustedOperationSelector => _operationSelector;

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

/// <summary>
/// One typed read from the external reset-surviving provider registry. It is untrusted input to
/// Protocol and cannot itself authorize recovery or construct a sealed registry context.
/// </summary>
public sealed class RecoveryProviderRegistryReadResult
{
    private readonly byte[] _scope;

    public RecoveryProviderRegistryReadResult(
        ReadOnlySpan<byte> exactScope158,
        ulong sourceRevision,
        bool protectedStateHmacHealthy,
        bool recoveryNonceLatchHealthy)
    {
        _scope = exactScope158.ToArray();
        SourceRevision = sourceRevision;
        ProtectedStateHmacHealthy = protectedStateHmacHealthy;
        RecoveryNonceLatchHealthy = recoveryNonceLatchHealthy;
    }

    public ReadOnlyMemory<byte> ExactScope => _scope.ToArray();
    public ulong SourceRevision { get; }
    public bool ProtectedStateHmacHealthy { get; }
    public bool RecoveryNonceLatchHealthy { get; }
}

/// <summary>
/// Typed external verifier for the reset-surviving recovery provider registry. Implementations
/// own source durability, monotonic revision and retention enforcement; Protocol revalidates the
/// complete returned snapshot before it can produce a relative recovery result.
/// </summary>
public abstract class RecoveryProviderRegistry
{
    public abstract ValueTask<RecoveryProviderRegistryReadResult> ReadAsync(
        RecoveryProviderRegistryRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Exact sealed provider selection for one DRC operation. It is nonserializable, defensively
/// owned and carries no storage, activation or publication authority.
/// </summary>
public sealed class RecoveryProviderRegistryContext
{
    public const int ExactScopeLength = 158;
    private const int ResetOffset = 16;
    private const int ComponentOffset = 48;
    private const int AccountGenerationOffset = 80;
    private const int RowCountOffset = 88;
    private const int FirstKindOffset = 90;
    private const int FirstKeyIdOffset = 92;
    private const int SecondKindOffset = 124;
    private const int SecondKeyIdOffset = 126;

    private readonly byte[] _scope;
    private readonly byte[] _operationSelector;

    private RecoveryProviderRegistryContext(
        ReadOnlySpan<byte> exactScope,
        ReadOnlySpan<byte> operationSelector,
        ulong sourceRevision)
    {
        _scope = exactScope.ToArray();
        _operationSelector = operationSelector.ToArray();
        SourceRevision = sourceRevision;
    }

    public ReadOnlyMemory<byte> ExactScope => _scope.ToArray();
    public ReadOnlyMemory<byte> OperationSelector => _operationSelector.ToArray();
    public ulong SourceRevision { get; }
    public bool NoAuthorityClaim => true;

    internal ReadOnlySpan<byte> TrustedResetId => _scope.AsSpan(ResetOffset, 32);
    internal ReadOnlySpan<byte> ProtectedStateHmacKeyId => _scope.AsSpan(FirstKeyIdOffset, 32);
    internal ReadOnlySpan<byte> RecoveryNonceLatchKeyId => _scope.AsSpan(SecondKeyIdOffset, 32);
    internal bool Matches(RecoveryProviderRegistryRequest request) =>
        CanonicalGrammar.FixedEquals(_operationSelector, request.TrustedOperationSelector);

    internal static async ValueTask<RecoveryProviderRegistryContext> ReadAsync(
        RecoveryProviderRegistry registry,
        RecoveryProviderRegistryRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var returned = await registry.ReadAsync(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (returned is null)
            Invalid("The recovery provider registry returned no context.");
        var scope = returned!.ExactScope.ToArray();
        try
        {
            Validate(scope, request, returned.SourceRevision,
                returned.ProtectedStateHmacHealthy, returned.RecoveryNonceLatchHealthy);
            return new RecoveryProviderRegistryContext(
                scope, request.TrustedOperationSelector, returned.SourceRevision);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scope);
        }
    }

    internal async ValueTask RevalidateAsync(
        RecoveryProviderRegistry registry,
        RecoveryProviderRegistryRequest request,
        CancellationToken cancellationToken)
    {
        var current = await ReadAsync(registry, request, cancellationToken).ConfigureAwait(false);
        if (current.SourceRevision != SourceRevision ||
            !CanonicalGrammar.FixedEquals(current._scope, _scope) ||
            !CanonicalGrammar.FixedEquals(current._operationSelector, _operationSelector))
            Invalid("The recovery provider registry moved during recovery.");
    }

    internal async ValueTask RevalidateLatchAsync(
        RecoveryNonceLatch nonceLatch,
        ReadOnlyMemory<byte> latchKey56,
        ReadOnlyMemory<byte> latchValue32,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(nonceLatch);
        if (latchKey56.Length != 56 || latchValue32.Length != 32 ||
            !CanonicalGrammar.FixedEquals(latchKey56.Span[..32], _operationSelector.AsSpan(88, 32)))
            Invalid("The recovery nonce-latch replay tuple differs from the frozen DRC selector.");
        var request = new RecoveryNonceLatchRequest(
            RecoveryNonceLatchKeyId, latchKey56.Span[..32], latchKey56.Span[32..], latchValue32.Span);
        var decision = await nonceLatch.CompareOrLatchAsync(request, cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (decision != RecoveryNonceLatchDecision.ExactReplay)
            Invalid("The recovery nonce-latch state moved or is permanently forked.");
    }

    private static void Validate(
        ReadOnlySpan<byte> scope,
        RecoveryProviderRegistryRequest request,
        ulong sourceRevision,
        bool protectedStateHmacHealthy,
        bool recoveryNonceLatchHealthy)
    {
        if (scope.Length != ExactScopeLength)
            Invalid("The recovery provider registry scope is not exactly 158 bytes.");
        if (sourceRevision == 0 || !protectedStateHmacHealthy || !recoveryNonceLatchHealthy)
            Invalid("The recovery provider registry source is absent or unhealthy.");
        if (!CanonicalGrammar.FixedEquals(scope[..16], request.TrustedOperationSelector[..16]) ||
            !CanonicalGrammar.FixedEquals(scope.Slice(ComponentOffset, 32),
                request.TrustedOperationSelector.Slice(16, 32)) ||
            !CanonicalGrammar.FixedEquals(scope.Slice(AccountGenerationOffset, 8),
                request.TrustedOperationSelector.Slice(48, 8)) ||
            CanonicalGrammar.IsZero(scope.Slice(ResetOffset, 32)) ||
            BinaryPrimitives.ReadUInt16BigEndian(scope.Slice(RowCountOffset, 2)) != 2 ||
            BinaryPrimitives.ReadUInt16BigEndian(scope.Slice(FirstKindOffset, 2)) !=
                (ushort)RecoveryProtectedKeyKind.ProtectedStateHmac ||
            BinaryPrimitives.ReadUInt16BigEndian(scope.Slice(SecondKindOffset, 2)) !=
                (ushort)RecoveryProtectedKeyKind.RecoveryNonceLatch ||
            CanonicalGrammar.IsZero(scope.Slice(FirstKeyIdOffset, 32)) ||
            CanonicalGrammar.IsZero(scope.Slice(SecondKeyIdOffset, 32)) ||
            CanonicalGrammar.FixedEquals(scope.Slice(FirstKeyIdOffset, 32),
                scope.Slice(SecondKeyIdOffset, 32)))
            Invalid("The recovery provider registry scope or ordered key rows are invalid.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

/// <summary>
/// Defensively owned typed nonce-latch request. Protocol constructs the exact 120-byte request;
/// callers cannot substitute a latch selector, protector, nonce or transcript value.
/// </summary>
public sealed class RecoveryNonceLatchRequest
{
    public const int ExactLength = 120;
    private readonly byte[] _exact;

    internal RecoveryNonceLatchRequest(
        ReadOnlySpan<byte> recoveryLatchKeyId,
        ReadOnlySpan<byte> protectorKeyId,
        ReadOnlySpan<byte> derivedNonce,
        ReadOnlySpan<byte> latchValue)
    {
        if (recoveryLatchKeyId.Length != 32 || protectorKeyId.Length != 32 ||
            derivedNonce.Length != 24 || latchValue.Length != 32 ||
            CanonicalGrammar.IsZero(recoveryLatchKeyId) || CanonicalGrammar.IsZero(protectorKeyId))
            throw new RecordException(RecordError.InvalidField,
                "The typed recovery nonce-latch request is invalid.");
        _exact = new byte[ExactLength];
        recoveryLatchKeyId.CopyTo(_exact);
        protectorKeyId.CopyTo(_exact.AsSpan(32));
        derivedNonce.CopyTo(_exact.AsSpan(64));
        latchValue.CopyTo(_exact.AsSpan(88));
    }

    public ReadOnlyMemory<byte> ExactRequest => _exact.ToArray();
    public ReadOnlyMemory<byte> RecoveryNonceLatchKeyId => _exact.AsSpan(0, 32).ToArray();
    public ReadOnlyMemory<byte> ProtectorKeyId => _exact.AsSpan(32, 32).ToArray();
    public ReadOnlyMemory<byte> DerivedNonce => _exact.AsSpan(64, 24).ToArray();
    public ReadOnlyMemory<byte> LatchValue => _exact.AsSpan(88, 32).ToArray();
}
