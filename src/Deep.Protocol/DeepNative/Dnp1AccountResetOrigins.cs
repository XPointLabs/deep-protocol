using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// A verified old terminal account and its last signed DCM. It is a relative fact only;
/// it cannot sign, reserve, mutate, or publish anything.
/// </summary>
public sealed class VerifiedAccountResetOldCutover
{
    internal VerifiedAccountResetOldCutover(
        VerifiedIdentityRelative identity,
        CutoverManifest manifest,
        ReadOnlySpan<byte> manifestResetPublicKey,
        ReadOnlySpan<byte> currentResetPublicKey)
    {
        Identity = identity;
        Manifest = manifest;
        ManifestResetPublicKey = manifestResetPublicKey.ToArray();
        CurrentResetPublicKey = currentResetPublicKey.ToArray();
    }

    internal VerifiedIdentityRelative Identity { get; }
    internal CutoverManifest Manifest { get; }
    internal ReadOnlyMemory<byte> ManifestResetPublicKey { get; }
    internal ReadOnlyMemory<byte> CurrentResetPublicKey { get; }
    public bool NoAuthorityClaim => true;
}

/// <summary>
/// Sealed account-reset origin request. The consumer provider must retain the exact
/// evidence and its signer-remint lookup atomically with GAR1.
/// </summary>
public sealed class AccountResetOriginRequest
{
    private readonly byte[] _transcript;
    private readonly byte[][] _evidence;

    internal AccountResetOriginRequest(ReadOnlySpan<byte> transcript,
        IEnumerable<ReadOnlyMemory<byte>> evidence)
    {
        _transcript = transcript.ToArray();
        _evidence = evidence.Select(static item => item.ToArray()).ToArray();
    }

    public ReadOnlyMemory<byte> VerifiedOriginTranscript => _transcript.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> RetainedEvidence =>
        _evidence.Select(static item => (ReadOnlyMemory<byte>)item.ToArray()).ToArray();
    public bool NoAuthorityClaim => true;
}

/// <summary>Untrusted, defensively owned GAR1 provider result.</summary>
public sealed class AccountResetOriginReadResult
{
    private readonly byte[] _gar;
    public AccountResetOriginReadResult(ReadOnlySpan<byte> exactGar742, bool healthy)
    { _gar = exactGar742.ToArray(); Healthy = healthy; }
    public ReadOnlyMemory<byte> ExactGar => _gar.ToArray();
    public bool Healthy { get; }
    public bool NoAuthorityClaim => true;
}

/// <summary>Consumer-owned atomic evidence-retention and GAR1 boundary.</summary>
public abstract class AccountResetOriginProvider
{
    /// <summary>
    /// The sole consumer-authorized durable mutation. The provider atomically retains the
    /// exact verified evidence and creates or restores the unique GAR1 for this origin.
    /// </summary>
    public abstract ValueTask<AccountResetOriginReadResult> RestoreOrCreateAsync(
        AccountResetOriginRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// Performs a fresh, nonmutating reread of the already retained exact evidence and GAR1.
    /// Absence, duplication, rollback, or changed evidence must fail closed.
    /// </summary>
    public abstract ValueTask<AccountResetOriginReadResult> ReadAsync(
        AccountResetOriginRequest request, CancellationToken cancellationToken);
}

/// <summary>HMAC-verified reset origin from which the reset branch is derived.</summary>
public sealed class AccountResetOriginContext
{
    private readonly byte[] _transcript;
    private readonly byte[] _originHash;
    private readonly byte[] _gar;
    private readonly byte[] _receiptHash;

    internal AccountResetOriginContext(VerifiedAccountResetOldCutover oldCutover,
        VerifiedIdentityRelative newIdentity, VerifiedDeploymentGovernanceContext governance,
        AccountResetOriginRequest request, ReadOnlySpan<byte> transcript,
        ReadOnlySpan<byte> originHash, ReadOnlySpan<byte> gar)
    {
        OldCutover = oldCutover;
        NewIdentity = newIdentity;
        Governance = governance;
        Request = request;
        _transcript = transcript.ToArray();
        _originHash = originHash.ToArray();
        _gar = gar.ToArray();
        _receiptHash = DeploymentGovernanceRecords.GarReceiptHash(gar);
    }

    internal VerifiedAccountResetOldCutover OldCutover { get; }
    internal VerifiedIdentityRelative NewIdentity { get; }
    internal VerifiedDeploymentGovernanceContext Governance { get; }
    internal AccountResetOriginRequest Request { get; }
    internal ReadOnlyMemory<byte> ExactTranscript => _transcript;
    internal ReadOnlyMemory<byte> OriginHash => _originHash;
    internal ReadOnlyMemory<byte> ExactGar => _gar;
    internal ReadOnlyMemory<byte> GarReceiptHash => _receiptHash;
    internal ReadOnlyMemory<byte> OperationId => _gar.AsMemory(628, 32);
    public bool NoAuthorityClaim => true;
}

internal static class AccountResetOriginVerifier
{
    internal static VerifiedAccountResetOldCutover VerifyOld(
        VerifiedIdentityRelative oldTerminalIdentity,
        ReadOnlySpan<byte> exactSignedDcm812)
    {
        ArgumentNullException.ThrowIfNull(oldTerminalIdentity);
        if (!oldTerminalIdentity.IsTerminal || oldTerminalIdentity.ForkLatched)
            Invalid("The old account-reset identity is not a usable terminal account.");
        var dcm = CanonicalGrammar.DecodeOwned(exactSignedDcm812, RecordDefinitions.Dcm1);
        var account = oldTerminalIdentity.Account;
        var dpa = account.Certificate;
        Equal(dcm.FieldSpan(1), dpa.NetworkId.Span, "old DCM network");
        if (Scalars.UInt64(dcm.FieldSpan(4)) != dpa.AccountGeneration)
            Invalid("The old DCM account generation differs.");
        Equal(dcm.FieldSpan(5), Reference(ArtifactType.Dpa1, dpa.Record), "old DCM DPA");

        var manifestResetKey = ResolveResetKey(oldTerminalIdentity, dcm);
        var signing = CanonicalGrammar.GetSigningBytes(dcm, "Deep/Cutover/V1/manifest");
        VerifySignature(dcm.FieldSpan(18), signing, manifestResetKey);
        VerifySignature(dcm.FieldSpan(19), signing, dpa.AccountEd25519PublicKey.Span);
        var currentReset = oldTerminalIdentity.Authority.GetKeyAuthority(KeyScope.ResetControl);
        if (currentReset.IsTerminal)
            Invalid("The old account reset-control authority is terminal.");
        return new VerifiedAccountResetOldCutover(oldTerminalIdentity,
            CutoverCodec.DecodeManifest(exactSignedDcm812), manifestResetKey,
            currentReset.CurrentEd25519PublicKey.Span);
    }

    internal static async ValueTask<AccountResetOriginContext> RestoreOrCreateAsync(
        VerifiedAccountResetOldCutover oldCutover,
        VerifiedIdentityRelative newIdentity,
        VerifiedDeploymentGovernanceContext governance,
        ulong cutoffAtUnixSeconds,
        ResetReason reason,
        AccountResetOriginProvider provider,
        IProtectedHmacProvider hmacProvider,
        ulong transactionTimeUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(oldCutover);
        ArgumentNullException.ThrowIfNull(newIdentity);
        ArgumentNullException.ThrowIfNull(governance);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        if (newIdentity.IsTerminal || newIdentity.ForkLatched ||
            !Enum.IsDefined(reason) || reason == 0 || cutoffAtUnixSeconds == 0 ||
            cutoffAtUnixSeconds > transactionTimeUnixSeconds)
            Invalid("The account-reset successor or cutoff is invalid.");

        var oldIdentity = oldCutover.Identity;
        var oldAccount = oldIdentity.Account;
        var newAccount = newIdentity.Account;
        var oldDpa = oldAccount.Certificate;
        var newDpa = newAccount.Certificate;
        var oldDrs = oldIdentity.Revocations.Snapshot;
        var newDrs = newIdentity.Revocations.Snapshot;
        var oldReset = oldIdentity.Authority.GetKeyAuthority(KeyScope.ResetControl);
        var newReset = newIdentity.Authority.GetKeyAuthority(KeyScope.ResetControl);
        if (oldReset.IsTerminal || newReset.IsTerminal ||
            oldDpa.AccountGeneration == ulong.MaxValue ||
            newDpa.AccountGeneration != oldDpa.AccountGeneration + 1)
            Invalid("The account-reset generation or reset-control authority is invalid.");
        Equal(governance.Network, oldDpa.NetworkId.Span, "governance/old network");
        Equal(governance.Network, newDpa.NetworkId.Span, "governance/new network");
        if (CanonicalGrammar.FixedEquals(oldAccount.DeepAccountIdHash.Span,
                newAccount.DeepAccountIdHash.Span))
            Invalid("Account reset requires a distinct successor account hash.");
        var terminal = oldIdentity.Revocations.Catalog.Entries[^1];
        if (terminal.Target.TargetKind != RevocationTargetKind.AccountTerminal ||
            terminal.Reason != RevocationReason.AccountShutdown ||
            cutoffAtUnixSeconds < terminal.RevokedAtUnixSeconds)
            Invalid("The account-reset cutoff precedes the authenticated terminal revocation.");

        var transcript = BuildTranscript(oldCutover, newIdentity, governance,
            cutoffAtUnixSeconds, reason);
        var originHash = DeploymentGovernanceRecords.HashU16(
            "Deep/Cutover/V10/account-reset-origin", transcript);
        var evidence = RetainedEvidence(oldCutover, newIdentity);
        var request = new AccountResetOriginRequest(transcript, evidence);
        var first = await provider.RestoreOrCreateAsync(request, cancellationToken).ConfigureAwait(false);
        var gar = await VerifyGarAsync(first, transcript, originHash, governance,
            hmacProvider, transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false);
        var second = await provider.ReadAsync(request, cancellationToken).ConfigureAwait(false);
        var reread = await VerifyGarAsync(second, transcript, originHash, governance,
            hmacProvider, transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false);
        if (!CanonicalGrammar.FixedEquals(gar, reread))
            Invalid("GAR1 or its retained evidence moved during restore.");
        return new AccountResetOriginContext(oldCutover, newIdentity, governance,
            request, transcript, originHash, gar);
    }

    private static byte[] BuildTranscript(VerifiedAccountResetOldCutover oldCutover,
        VerifiedIdentityRelative newIdentity, VerifiedDeploymentGovernanceContext governance,
        ulong cutoffAt, ResetReason reason)
    {
        var oldIdentity = oldCutover.Identity;
        var oldAccount = oldIdentity.Account; var newAccount = newIdentity.Account;
        var oldDpa = oldAccount.Certificate; var newDpa = newAccount.Certificate;
        var oldDrs = oldIdentity.Revocations.Snapshot; var newDrs = newIdentity.Revocations.Snapshot;
        var oldReset = oldIdentity.Authority.GetKeyAuthority(KeyScope.ResetControl);
        var newReset = newIdentity.Authority.GetKeyAuthority(KeyScope.ResetControl);
        var oldDcm = oldCutover.Manifest.Record;
        var result = new byte[588]; var offset = 0;
        Put(oldDpa.NetworkId.Span); U64(oldDpa.AccountGeneration); Put(oldAccount.DeepAccountIdHash.Span);
        Put(Reference(ArtifactType.Dpa1, oldDpa.Record)); U64(Scalars.UInt64(oldDcm.FieldSpan(3)));
        Put(Reference(ArtifactType.Dcm1, oldDcm)); U64(oldDrs.Revision); U64(oldDrs.EntryCount);
        Put(oldDrs.CurrentHead.Span); Put(Reference(ArtifactType.Drs1, oldDrs.Record));
        U64(oldReset.Generation); Put(Transition(oldReset)); Put(SHA256.HashData(oldReset.CurrentEd25519PublicKey.Span));
        U64(newDpa.AccountGeneration); Put(newAccount.DeepAccountIdHash.Span);
        Put(Reference(ArtifactType.Dpa1, newDpa.Record)); U64(newDrs.Revision); U64(newDrs.EntryCount);
        Put(newDrs.CurrentHead.Span); Put(Reference(ArtifactType.Drs1, newDrs.Record));
        U64(newReset.Generation); Put(Transition(newReset)); Put(SHA256.HashData(newReset.CurrentEd25519PublicKey.Span));
        Put(governance.DeploymentGovernanceBootstrapHash.Span); U64(cutoffAt);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(offset, 2), (ushort)reason); offset += 2;
        if (offset != result.Length) Invalid("The account-reset origin transcript length is invalid.");
        return result;

        void Put(ReadOnlySpan<byte> value) { value.CopyTo(result.AsSpan(offset)); offset += value.Length; }
        void U64(ulong value) { BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(offset, 8), value); offset += 8; }
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> RetainedEvidence(
        VerifiedAccountResetOldCutover oldCutover, VerifiedIdentityRelative newIdentity)
    {
        var values = new List<ReadOnlyMemory<byte>>
        {
            oldCutover.Identity.Account.Certificate.CanonicalBytes,
            oldCutover.Manifest.CanonicalBytes,
            oldCutover.Identity.Revocations.Snapshot.CanonicalBytes,
            newIdentity.Account.Certificate.CanonicalBytes,
            newIdentity.Revocations.Snapshot.CanonicalBytes,
            oldCutover.CurrentResetPublicKey,
            newIdentity.Authority.GetKeyAuthority(KeyScope.ResetControl).CurrentEd25519PublicKey
        };
        values.AddRange(oldCutover.Identity.Authority.OrderedTransitionCanonicals);
        values.AddRange(newIdentity.Authority.OrderedTransitionCanonicals);
        return values;
    }

    private static async ValueTask<byte[]> VerifyGarAsync(AccountResetOriginReadResult result,
        ReadOnlyMemory<byte> transcript, ReadOnlyMemory<byte> originHash,
        VerifiedDeploymentGovernanceContext governance, IProtectedHmacProvider hmacProvider,
        ulong now, CancellationToken cancellationToken)
    {
        if (result is null || !result.Healthy) Invalid("The GAR1 provider is absent or unhealthy.");
        var gar = result!.ExactGar.ToArray();
        DeploymentGovernanceRecords.PreflightGar(gar, now);
        await GenesisProtectedRecords.VerifyAsync("Deep/ProtectedState/V1/GAR1", gar,
            DeploymentGovernanceRecords.GarKeyOffset, hmacProvider, cancellationToken).ConfigureAwait(false);
        if (!CanonicalGrammar.FixedEquals(gar.AsSpan(8, 588), transcript.Span) ||
            !CanonicalGrammar.FixedEquals(gar.AsSpan(596, 32), originHash.Span) ||
            !CanonicalGrammar.FixedEquals(gar.AsSpan(678, 32), governance.ExactDgi.Slice(96, 32)))
            Invalid("GAR1 differs from its verified reset origin or governance key.");
        return gar;
    }

    private static byte[] ResolveResetKey(VerifiedIdentityRelative identity, OwnedRecord dcm)
    {
        var generation = Scalars.UInt64(dcm.FieldSpan(10));
        if (generation == 0)
        {
            if (!CanonicalGrammar.IsZero(dcm.FieldSpan(12)))
                Invalid("A generation-zero old DCM has a reset transition.");
            var key = identity.Account.Certificate.ResetControlEd25519PublicKey.ToArray();
            Equal(dcm.FieldSpan(11), SHA256.HashData(key), "old DCM reset key hash");
            return key;
        }
        foreach (var canonical in identity.Authority.OrderedTransitionCanonicals)
        {
            if (canonical.Length != 368 || !canonical.Span[..4].SequenceEqual("KRT1"u8)) continue;
            var transition = CanonicalGrammar.DecodeOwned(canonical.Span, RecordDefinitions.Krt1);
            if (transition.FieldSpan(2)[0] != (byte)KeyScope.ResetControl ||
                Scalars.UInt64(transition.FieldSpan(5)) != generation) continue;
            var reference = Reference(ArtifactType.Krt1, transition);
            if (!CanonicalGrammar.FixedEquals(reference, dcm.FieldSpan(12))) continue;
            var key = transition.FieldSpan(8).ToArray();
            Equal(dcm.FieldSpan(11), SHA256.HashData(key), "old DCM reset key hash");
            return key;
        }
        Invalid("The old DCM reset signing transition is not retained by the sealed identity.");
        return [];
    }

    private static byte[] Transition(VerifiedKeyAuthority authority) => authority.Generation == 0
        ? new byte[38]
        : CanonicalGrammar.EncodeReference(authority.TransitionReference);
    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));
    private static void VerifySignature(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> signing,
        ReadOnlySpan<byte> publicKey)
    {
        if (!PublicKeyAuth.VerifyDetached(signature.ToArray(), signing.ToArray(), publicKey.ToArray()))
            throw new RecordException(RecordError.InvalidSignature,
                "An account-reset origin DCM signature is invalid.");
    }
    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string name)
    { if (!CanonicalGrammar.FixedEquals(actual, expected)) Invalid($"The {name} differs."); }
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static VerifiedAccountResetOldCutover VerifyAccountResetOldCutover(
        VerifiedIdentityRelative oldTerminalIdentity, ReadOnlySpan<byte> exactSignedDcm812) =>
        AccountResetOriginVerifier.VerifyOld(oldTerminalIdentity, exactSignedDcm812);

    public static async ValueTask<AccountResetOriginContext> RestoreOrCreateAccountResetOriginAsync(
        VerifiedAccountResetOldCutover oldCutover, VerifiedIdentityRelative newIdentity,
        VerifiedDeploymentGovernanceContext governance, ulong cutoffAtUnixSeconds,
        ResetReason reason, AccountResetOriginProvider provider,
        IProtectedHmacProvider hmacProvider, ulong transactionTimeUnixSeconds,
        CancellationToken cancellationToken = default) =>
        await AccountResetOriginVerifier.RestoreOrCreateAsync(oldCutover, newIdentity, governance,
            cutoffAtUnixSeconds, reason, provider, hmacProvider, transactionTimeUnixSeconds,
            cancellationToken).ConfigureAwait(false);

    public static GenesisCutoverBranchContext CreateAccountResetCutoverBranch(
        AccountResetOriginContext origin) => new(origin);
}
