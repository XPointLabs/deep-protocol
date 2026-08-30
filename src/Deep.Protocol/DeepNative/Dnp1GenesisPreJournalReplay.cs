using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepNative;

/// <summary>Protocol-minted scope for checking the crash window before GAJ1 exists.</summary>
public sealed class GenesisPreJournalScopeV1
{
    private readonly byte[] _scope;

    internal GenesisPreJournalScopeV1(ReadOnlySpan<byte> exactAuthorScope122)
    {
        if (exactAuthorScope122.Length != 122)
            Invalid("The genesis pre-journal scope is not exact122.");
        _scope = exactAuthorScope122.ToArray();
    }

    public bool NoAuthorityClaim => true;
    internal ReadOnlySpan<byte> TrustedScope => _scope;

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

/// <summary>
/// Untrusted consumer snapshot of GAJ absence and the external/local zero heads.
/// Protocol validates the closed zero shape and monotonic revisions before use.
/// </summary>
public sealed class GenesisPreJournalHeadReadResult
{
    private readonly byte[] _externalDplReference;
    private readonly byte[] _externalSource;
    private readonly byte[] _localDpl;
    private readonly byte[] _localDplReference;
    private readonly byte[] _localSource;

    public GenesisPreJournalHeadReadResult(
        bool journalExists,
        ulong externalSequence,
        ReadOnlySpan<byte> externalDplReference38,
        ReadOnlySpan<byte> externalSourceFingerprint32,
        ReadOnlySpan<byte> canonicalLocalDpl,
        ReadOnlySpan<byte> localDplReference38,
        ReadOnlySpan<byte> localSourceFingerprint32,
        ulong externalSourceRevision,
        ulong localSourceRevision,
        ulong journalSourceRevision)
    {
        if (externalDplReference38.Length != 38 ||
            externalSourceFingerprint32.Length != 32 ||
            canonicalLocalDpl.Length is not (0 or 576) ||
            localDplReference38.Length != 38 || localSourceFingerprint32.Length != 32)
            Invalid("The genesis pre-journal head exceeds its closed bounds.");
        JournalExists = journalExists;
        ExternalSequence = externalSequence;
        _externalDplReference = externalDplReference38.ToArray();
        _externalSource = externalSourceFingerprint32.ToArray();
        _localDpl = canonicalLocalDpl.ToArray();
        _localDplReference = localDplReference38.ToArray();
        _localSource = localSourceFingerprint32.ToArray();
        ExternalSourceRevision = externalSourceRevision;
        LocalSourceRevision = localSourceRevision;
        JournalSourceRevision = journalSourceRevision;
    }

    public bool JournalExists { get; }
    public ulong ExternalSequence { get; }
    public ReadOnlyMemory<byte> ExternalDplReference => _externalDplReference.ToArray();
    public ReadOnlyMemory<byte> ExternalSourceFingerprint => _externalSource.ToArray();
    public ReadOnlyMemory<byte> CanonicalLocalDpl => _localDpl.ToArray();
    public ReadOnlyMemory<byte> LocalDplReference => _localDplReference.ToArray();
    public ReadOnlyMemory<byte> LocalSourceFingerprint => _localSource.ToArray();
    public ulong ExternalSourceRevision { get; }
    public ulong LocalSourceRevision { get; }
    public ulong JournalSourceRevision { get; }
    internal ReadOnlySpan<byte> TrustedExternalDplReference => _externalDplReference;
    internal ReadOnlySpan<byte> TrustedExternalSource => _externalSource;
    internal ReadOnlySpan<byte> TrustedLocalDpl => _localDpl;
    internal ReadOnlySpan<byte> TrustedLocalDplReference => _localDplReference;
    internal ReadOnlySpan<byte> TrustedLocalSource => _localSource;

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

/// <summary>
/// Consumer-owned transactional reader for GAJ absence plus external/local heads.
/// It receives no raw lookup key and returns no authority.
/// </summary>
public abstract class GenesisPreJournalHeadProvider
{
    public abstract ValueTask<GenesisPreJournalHeadReadResult> ReadAsync(
        GenesisPreJournalScopeV1 scope,
        CancellationToken cancellationToken);
}

public abstract class GenesisPreJournalRestorePlan : IDisposable
{
    private readonly SealedGenesisRecoveryCandidate _ownedCandidate;
    private int _disposed;

    private protected GenesisPreJournalRestorePlan(GenesisPreExternalCandidatePlan candidate)
    {
        _ownedCandidate = candidate.Candidate;
    }

    public bool NoAuthorityClaim => true;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _ownedCandidate.Dispose();
    }
}

public sealed class GenesisAfterGas : GenesisPreJournalRestorePlan
{
    internal GenesisAfterGas(
        GenesisPreExternalCandidatePlan candidate,
        VerifiedGenesisArtifactSet artifactSet)
        : base(candidate)
    {
        Candidate = candidate;
        ArtifactSet = artifactSet;
    }

    public GenesisPreExternalCandidatePlan Candidate { get; }
    public VerifiedGenesisArtifactSet ArtifactSet { get; }
}

public sealed class GenesisAfterGqp : GenesisPreJournalRestorePlan
{
    internal GenesisAfterGqp(
        GenesisPreExternalCandidatePlan candidate,
        VerifiedGenesisArtifactSet artifactSet,
        GenesisQuorumPending pending,
        GenesisResetReservationResult reservation)
        : base(candidate)
    {
        Candidate = candidate;
        ArtifactSet = artifactSet;
        Pending = pending;
        Reservation = reservation;
    }

    public GenesisPreExternalCandidatePlan Candidate { get; }
    public VerifiedGenesisArtifactSet ArtifactSet { get; }
    public GenesisQuorumPending Pending { get; }
    public GenesisResetReservationResult Reservation { get; }
}

internal static class GenesisPreJournalReplayVerifier
{
    internal static async ValueTask<GenesisPreJournalRestorePlan> RestoreAsync(
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisResetReservationResult reservation,
        GenesisProtectedKeySetContext keySet,
        GenesisProtectedKeySetRegistry keyRegistry,
        GenesisRecoveryProtectorContext protector,
        RecoverySealingProvider sealingProvider,
        GenesisCutoverSourceContext source,
        GenesisArtifactStore artifactStore,
        GenesisQuorumStateProvider quorumProvider,
        GenesisPreJournalHeadProvider headProvider,
        RecoveryProtectorProvider recoveryProvider,
        RecoveryNonceLatch nonceLatch,
        IProtectedHmacProvider protectedHmacProvider,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(release);
        ArgumentNullException.ThrowIfNull(reservation);
        ArgumentNullException.ThrowIfNull(keySet);
        ArgumentNullException.ThrowIfNull(keyRegistry);
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(sealingProvider);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(artifactStore);
        ArgumentNullException.ThrowIfNull(quorumProvider);
        ArgumentNullException.ThrowIfNull(headProvider);
        ArgumentNullException.ThrowIfNull(recoveryProvider);
        ArgumentNullException.ThrowIfNull(nonceLatch);
        ArgumentNullException.ThrowIfNull(protectedHmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        if (nowUnixSeconds == 0 || !ReferenceEquals(intent.Identity, identity) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.ResetId, reservation.ResetId) ||
            !CanonicalGrammar.FixedEquals(identity.Scope.ExactScope.Slice(90, 32),
                reservation.ReservationHash.Span))
            Invalid("The genesis pre-journal sealed contexts differ.");

        var scopeBytes = GenesisArtifactSetVerifier.AuthorScope(identity);
        var scope = new GenesisPreJournalScopeV1(scopeBytes);
        var firstHead = await ReadZeroHeadAsync(headProvider, scope, cancellationToken)
            .ConfigureAwait(false);
        var artifacts = await GenesisArtifactSetVerifier.RestoreByScopeAsync(
            identity, artifactStore, protectedHmacProvider, cancellationToken)
            .ConfigureAwait(false);
        RequireRetained(artifacts.Receipt.CanonicalReceipt.Span, 212, nowUnixSeconds, ProtocolMagic.GAS1);
        var secondHead = await ReadZeroHeadAsync(headProvider, scope, cancellationToken)
            .ConfigureAwait(false);
        RequireMonotonic(firstHead, secondHead);

        var keyRequest = new GenesisProtectedKeySetRequest(
            identity.BaseIdentity.Network, identity.BaseIdentity.ResetId,
            intent.ComponentKind, intent.ComponentSubject.Span,
            identity.BaseIdentity.AccountGeneration);
        var protectorRequest = new GenesisRecoveryProtectorRequest(identity, intent);
        await keySet.RevalidateAsync(keyRegistry, keyRequest,
            identity.ProtectedStateHmacKeyId.ToArray(), cancellationToken)
            .ConfigureAwait(false);
        await protector.RevalidateAsync(sealingProvider, protectorRequest,
            identity.ProtectedStateHmacKeyId.ToArray(), keySet, cancellationToken)
            .ConfigureAwait(false);

        RecoveryCandidatePlan? opened = null;
        GenesisPreExternalCandidatePlan? reconstructed = null;
        try
        {
            opened = await RecoveryEngine.OpenGenesisPreJournalAsync(
                artifacts, identity, intent, release, keySet, protector, source,
                recoveryProvider, nonceLatch, protectedHmacProvider, cancellationToken)
                .ConfigureAwait(false);
            reconstructed = GenesisReplayVerifier.Reconstruct(
                opened, artifacts, identity, intent, release, source);
            opened.Dispose();
            opened = null;

            var pending = await GenesisQuorumStateVerifier.TryRestorePendingByScopeAsync(
                artifacts, identity, release, quorumProvider, protectedHmacProvider,
                cancellationToken).ConfigureAwait(false);
            if (pending is not null)
                RequireRetained(pending.CanonicalPending.Span, 387, nowUnixSeconds, ProtocolMagic.GQP1);

            var finalArtifacts = await GenesisArtifactSetVerifier.RestoreByScopeAsync(
                identity, artifactStore, protectedHmacProvider, cancellationToken)
                .ConfigureAwait(false);
            RequireSameArtifacts(artifacts, finalArtifacts);
            var finalPending = await GenesisQuorumStateVerifier.TryRestorePendingByScopeAsync(
                artifacts, identity, release, quorumProvider, protectedHmacProvider,
                cancellationToken).ConfigureAwait(false);
            RequireSamePending(pending, finalPending);

            await keySet.RevalidateAsync(keyRegistry, keyRequest,
                identity.ProtectedStateHmacKeyId.ToArray(), cancellationToken)
                .ConfigureAwait(false);
            await protector.RevalidateAsync(sealingProvider, protectorRequest,
                identity.ProtectedStateHmacKeyId.ToArray(), keySet, cancellationToken)
                .ConfigureAwait(false);
            var finalHead = await ReadZeroHeadAsync(headProvider, scope, cancellationToken)
                .ConfigureAwait(false);
            RequireMonotonic(secondHead, finalHead);

            GenesisPreJournalRestorePlan result = pending is null
                ? new GenesisAfterGas(reconstructed, artifacts)
                : new GenesisAfterGqp(reconstructed, artifacts, pending, reservation);
            reconstructed = null;
            return result;
        }
        catch
        {
            reconstructed?.Candidate.Dispose();
            throw;
        }
        finally
        {
            opened?.Dispose();
            CryptographicOperations.ZeroMemory(scopeBytes);
        }
    }

    private static async ValueTask<GenesisPreJournalHeadReadResult> ReadZeroHeadAsync(
        GenesisPreJournalHeadProvider provider,
        GenesisPreJournalScopeV1 scope,
        CancellationToken cancellationToken)
    {
        var value = await provider.ReadAsync(scope, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (value is null || value.JournalExists || value.ExternalSequence != 0 ||
            !CanonicalGrammar.IsZero(value.TrustedExternalDplReference) ||
            !CanonicalGrammar.IsZero(value.TrustedExternalSource) ||
            value.TrustedLocalDpl.Length != 0 ||
            !CanonicalGrammar.IsZero(value.TrustedLocalDplReference) ||
            !CanonicalGrammar.IsZero(value.TrustedLocalSource) ||
            value.ExternalSourceRevision == 0 || value.LocalSourceRevision == 0 ||
            value.JournalSourceRevision == 0)
            Invalid("The genesis pre-journal head is not exact zero with GAJ1 absent.");
        return value!;
    }

    private static void RequireMonotonic(
        GenesisPreJournalHeadReadResult earlier,
        GenesisPreJournalHeadReadResult later)
    {
        if (later.ExternalSourceRevision < earlier.ExternalSourceRevision ||
            later.LocalSourceRevision < earlier.LocalSourceRevision ||
            later.JournalSourceRevision < earlier.JournalSourceRevision)
            Invalid("A genesis pre-journal source revision moved backwards.");
    }

    private static void RequireSameArtifacts(
        VerifiedGenesisArtifactSet expected,
        VerifiedGenesisArtifactSet actual)
    {
        if (expected.SourceRevision != actual.SourceRevision ||
            !CanonicalGrammar.FixedEquals(expected.Receipt.CanonicalReceipt.Span,
                actual.Receipt.CanonicalReceipt.Span) ||
            expected.Artifacts.Count != actual.Artifacts.Count)
            Invalid("The retained GAS1 changed during pre-journal restore.");
        for (var index = 0; index < expected.Artifacts.Count; index++)
            if (!CanonicalGrammar.FixedEquals(expected.Artifacts[index].Span,
                    actual.Artifacts[index].Span))
                Invalid("A retained genesis artifact changed during pre-journal restore.");
    }

    private static void RequireSamePending(
        GenesisQuorumPending? expected,
        GenesisQuorumPending? actual)
    {
        if (expected is null != (actual is null) ||
            expected is not null && !CanonicalGrammar.FixedEquals(
                expected.CanonicalPending.Span, actual!.CanonicalPending.Span))
            Invalid("The retained GQP1 changed during pre-journal restore.");
    }

    private static void RequireRetained(
        ReadOnlySpan<byte> canonical,
        int retainOffset,
        ulong nowUnixSeconds,
        string label)
    {
        var retainUntil = BinaryPrimitives.ReadUInt64BigEndian(
            canonical.Slice(retainOffset, 8));
        if (retainUntil == 0 || nowUnixSeconds >= retainUntil)
            throw new RecordException(RecordError.Expired,
                $"The retained {label} expired before pre-journal restore.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<GenesisPreJournalRestorePlan> RestoreGenesisPreJournalAsync(
        GenesisIdentityContext identity,
        GenesisComponentIntent intent,
        GenesisReleaseContext release,
        GenesisResetReservationResult reservation,
        GenesisProtectedKeySetContext keySet,
        GenesisProtectedKeySetRegistry keyRegistry,
        GenesisRecoveryProtectorContext protector,
        RecoverySealingProvider sealingProvider,
        GenesisCutoverSourceContext source,
        GenesisArtifactStore artifactStore,
        GenesisQuorumStateProvider quorumProvider,
        GenesisPreJournalHeadProvider headProvider,
        RecoveryProtectorProvider recoveryProvider,
        RecoveryNonceLatch nonceLatch,
        IProtectedHmacProvider protectedHmacProvider,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken = default) =>
        await GenesisPreJournalReplayVerifier.RestoreAsync(
            identity, intent, release, reservation, keySet, keyRegistry, protector,
            sealingProvider, source, artifactStore, quorumProvider, headProvider,
            recoveryProvider, nonceLatch, protectedHmacProvider, nowUnixSeconds,
            cancellationToken).ConfigureAwait(false);
}
