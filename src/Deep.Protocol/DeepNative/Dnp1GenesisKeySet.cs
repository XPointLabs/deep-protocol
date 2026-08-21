using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisProtectedKeySetRequest
{
    public const int ExactScopeAxesLength = 90;
    private readonly byte[] _scopeAxes;

    internal GenesisProtectedKeySetRequest(
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> resetId,
        ComponentKind componentKind,
        ReadOnlySpan<byte> componentSubject,
        ulong accountGeneration)
    {
        if (network.Length != 16 || resetId.Length != 32 || componentSubject.Length != 32 ||
            CanonicalGrammar.IsZero(network) || CanonicalGrammar.IsZero(resetId) ||
            CanonicalGrammar.IsZero(componentSubject) || !Enum.IsDefined(componentKind) ||
            componentKind == 0 || accountGeneration == 0)
            Invalid("The genesis protected-key scope axes are invalid.");
        _scopeAxes = new byte[ExactScopeAxesLength];
        network.CopyTo(_scopeAxes);
        resetId.CopyTo(_scopeAxes.AsSpan(16));
        BinaryPrimitives.WriteUInt16BigEndian(_scopeAxes.AsSpan(48, 2), (ushort)componentKind);
        componentSubject.CopyTo(_scopeAxes.AsSpan(50));
        BinaryPrimitives.WriteUInt64BigEndian(_scopeAxes.AsSpan(82, 8), accountGeneration);
    }

    public ReadOnlyMemory<byte> ExactScopeAxes => _scopeAxes.ToArray();
    internal ReadOnlySpan<byte> TrustedScopeAxes => _scopeAxes;

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisProtectedKeySetReadResult
{
    private readonly byte[] _exactScope;
    private readonly bool[] _healthy;

    public GenesisProtectedKeySetReadResult(
        ReadOnlySpan<byte> exactScope296,
        ulong sourceRevision,
        IReadOnlyList<bool> roleHealth)
    {
        ArgumentNullException.ThrowIfNull(roleHealth);
        _exactScope = exactScope296.ToArray();
        SourceRevision = sourceRevision;
        _healthy = roleHealth.ToArray();
    }

    public ReadOnlyMemory<byte> ExactScope => _exactScope.ToArray();
    public ulong SourceRevision { get; }
    public IReadOnlyList<bool> RoleHealth => _healthy.ToArray();
}

public abstract class GenesisProtectedKeySetRegistry
{
    public abstract ValueTask<GenesisProtectedKeySetReadResult> ReadAsync(
        GenesisProtectedKeySetRequest request,
        CancellationToken cancellationToken);
}

public sealed class GenesisProtectedKeySetContext
{
    public const int ExactScopeLength = 296;
    private readonly byte[] _scope;
    private readonly byte[] _scopeAxes;

    private GenesisProtectedKeySetContext(
        ReadOnlySpan<byte> scope,
        ReadOnlySpan<byte> scopeAxes,
        ulong sourceRevision)
    {
        _scope = scope.ToArray();
        _scopeAxes = scopeAxes.ToArray();
        SourceRevision = sourceRevision;
    }

    public ulong SourceRevision { get; }
    public bool NoAuthorityClaim => true;
    internal ReadOnlySpan<byte> Network => _scope.AsSpan(0, 16);
    internal ReadOnlySpan<byte> ResetId => _scope.AsSpan(16, 32);
    internal ComponentKind ComponentKind =>
        (ComponentKind)BinaryPrimitives.ReadUInt16BigEndian(_scope.AsSpan(48, 2));
    internal ReadOnlySpan<byte> ComponentSubject => _scope.AsSpan(50, 32);
    internal ulong AccountGeneration => BinaryPrimitives.ReadUInt64BigEndian(_scope.AsSpan(82, 8));
    internal ReadOnlySpan<byte> DplKeyId => KeyId(0);
    internal ReadOnlySpan<byte> DwlKeyId => KeyId(1);
    internal ReadOnlySpan<byte> RrlKeyId => KeyId(2);
    internal ReadOnlySpan<byte> RibKeyId => KeyId(3);
    internal ReadOnlySpan<byte> MrlcKeyId => KeyId(4);
    internal ReadOnlySpan<byte> DxrKeyId => KeyId(5);

    internal static async ValueTask<GenesisProtectedKeySetContext> ReadAsync(
        GenesisProtectedKeySetRegistry registry,
        GenesisProtectedKeySetRequest request,
        ReadOnlyMemory<byte> sharedProtectedStateHmacKeyId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registry);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        var returned = await registry.ReadAsync(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (returned is null) Invalid("The genesis protected-key registry returned no state.");
        var scope = returned!.ExactScope.ToArray();
        try
        {
            Validate(scope, request, returned.SourceRevision, returned.RoleHealth,
                sharedProtectedStateHmacKeyId.Span);
            return new GenesisProtectedKeySetContext(
                scope, request.TrustedScopeAxes, returned.SourceRevision);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(scope);
        }
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal static async ValueTask<GenesisProtectedKeySetContext> ReadAsync(
        GenesisProtectedKeySetRegistry registry,
        GenesisProtectedKeySetRequest request,
        ReadOnlyMemory<byte> sharedProtectedStateHmacKeyId,
        ReadOnlyMemory<byte> recoveryNonceLatchKeyId,
        ReadOnlyMemory<byte> protectorKeyId,
        CancellationToken cancellationToken)
    {
        var current = await ReadAsync(registry, request, sharedProtectedStateHmacKeyId,
            cancellationToken).ConfigureAwait(false);
        EnsureExternalRolesDistinct(current, recoveryNonceLatchKeyId.Span, protectorKeyId.Span);
        return current;
    }
#endif

    internal async ValueTask RevalidateAsync(
        GenesisProtectedKeySetRegistry registry,
        GenesisProtectedKeySetRequest request,
        ReadOnlyMemory<byte> sharedProtectedStateHmacKeyId,
        CancellationToken cancellationToken)
    {
        var current = await ReadAsync(registry, request, sharedProtectedStateHmacKeyId,
            cancellationToken).ConfigureAwait(false);
        if (current.SourceRevision != SourceRevision ||
            !CanonicalGrammar.FixedEquals(current._scope, _scope) ||
            !CanonicalGrammar.FixedEquals(current._scopeAxes, _scopeAxes))
            Invalid("The genesis protected-key registry moved during authoring.");
    }

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    internal async ValueTask RevalidateAsync(
        GenesisProtectedKeySetRegistry registry,
        GenesisProtectedKeySetRequest request,
        ReadOnlyMemory<byte> sharedProtectedStateHmacKeyId,
        ReadOnlyMemory<byte> recoveryNonceLatchKeyId,
        ReadOnlyMemory<byte> protectorKeyId,
        CancellationToken cancellationToken)
    {
        var current = await ReadAsync(registry, request, sharedProtectedStateHmacKeyId,
            recoveryNonceLatchKeyId, protectorKeyId, cancellationToken).ConfigureAwait(false);
        if (current.SourceRevision != SourceRevision ||
            !CanonicalGrammar.FixedEquals(current._scope, _scope) ||
            !CanonicalGrammar.FixedEquals(current._scopeAxes, _scopeAxes))
            Invalid("The genesis protected-key registry moved during authoring.");
    }
#endif

    private ReadOnlySpan<byte> KeyId(int index) =>
        _scope.AsSpan(94 + index * 34, 32);

#if DEEP_PROTOCOL_RECOVERY_TEST_SEAM
    private static void EnsureExternalRolesDistinct(
        GenesisProtectedKeySetContext current,
        ReadOnlySpan<byte> recoveryNonceLatchKeyId,
        ReadOnlySpan<byte> protectorKeyId)
    {
        if (recoveryNonceLatchKeyId.Length != 32 || protectorKeyId.Length != 32 ||
            CanonicalGrammar.IsZero(recoveryNonceLatchKeyId) ||
            CanonicalGrammar.IsZero(protectorKeyId) ||
            CanonicalGrammar.FixedEquals(recoveryNonceLatchKeyId, protectorKeyId))
            Invalid("The genesis external protector roles are invalid.");
        for (var index = 0; index < 6; index++)
            if (CanonicalGrammar.FixedEquals(current.KeyId(index), recoveryNonceLatchKeyId) ||
                CanonicalGrammar.FixedEquals(current.KeyId(index), protectorKeyId))
                Invalid("The genesis protected-key role set is cross-fed.");
    }
#endif

    private static void Validate(
        ReadOnlySpan<byte> scope,
        GenesisProtectedKeySetRequest request,
        ulong sourceRevision,
        IReadOnlyList<bool> health,
        ReadOnlySpan<byte> sharedProtectedStateHmacKeyId)
    {
        if (scope.Length != ExactScopeLength || sourceRevision == 0 || health.Count != 6 ||
            health.Any(static healthy => !healthy) ||
            !CanonicalGrammar.FixedEquals(scope[..90], request.TrustedScopeAxes) ||
            BinaryPrimitives.ReadUInt16BigEndian(scope.Slice(90, 2)) != 6)
            Invalid("The genesis protected-key registry scope is absent or unhealthy.");
        Span<byte> previous = stackalloc byte[32];
        for (var index = 0; index < 6; index++)
        {
            var row = scope.Slice(92 + index * 34, 34);
            if (BinaryPrimitives.ReadUInt16BigEndian(row[..2]) != index + 1 ||
                CanonicalGrammar.IsZero(row[2..]) ||
                CanonicalGrammar.FixedEquals(row[2..], sharedProtectedStateHmacKeyId))
                Invalid("The genesis protected-key role set is invalid.");
            for (var prior = 0; prior < index; prior++)
                if (CanonicalGrammar.FixedEquals(
                        row[2..], scope.Slice(94 + prior * 34, 32)))
                    Invalid("Genesis protected-key IDs are not pairwise distinct.");
            row[2..].CopyTo(previous);
        }
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<GenesisProtectedKeySetContext> ReadGenesisProtectedKeySetAsync(
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisProtectedKeySetRegistry registry,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(registry);
        if (!ReferenceEquals(intent.Identity, identity))
            throw new RecordException(RecordError.InvalidField,
                "The genesis key-set intent differs from the sealed identity.");
        var request = new GenesisProtectedKeySetRequest(
            identity.BaseIdentity.Network, identity.BaseIdentity.ResetId,
            intent.ComponentKind, intent.ComponentSubject.Span,
            identity.BaseIdentity.AccountGeneration);
        return await GenesisProtectedKeySetContext.ReadAsync(
            registry, request, identity.ProtectedStateHmacKeyId.ToArray(),
            cancellationToken).ConfigureAwait(false);
    }
}
