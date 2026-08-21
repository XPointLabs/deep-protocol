using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// One Protocol-derived cutover branch. It is relative to verified identity and governance
/// evidence and carries no signing, reservation, mutation, or publication authority.
/// </summary>
public sealed class GenesisCutoverBranchContext
{
    private readonly byte[] _transcript;
    private readonly byte[] _hash;
    private readonly GenesisResetReservationRequest? _reservationRequest;

    internal GenesisCutoverBranchContext(
        VerifiedDeploymentGovernanceContext governance,
        VerifiedIdentityRelative newIdentity)
    {
        ArgumentNullException.ThrowIfNull(governance);
        ArgumentNullException.ThrowIfNull(newIdentity);
        if (newIdentity.IsTerminal || newIdentity.ForkLatched)
            Invalid("First deployment requires one usable nonterminal identity.");

        var account = newIdentity.Account;
        var dpa = account.Certificate;
        var drs = newIdentity.Revocations.Snapshot;
        Equal(governance.Network, dpa.NetworkId.Span, "first-deployment network");
        Equal(dpa.NetworkId.Span, drs.NetworkId.Span, "first-deployment DRS network");
        Equal(account.DeepAccountIdHash.Span, drs.Record.FieldSpan(2),
            "first-deployment DRS account hash");
        if (dpa.AccountGeneration == 0 ||
            dpa.AccountGeneration != drs.Record.FieldSpan(3).AsU64())
            Invalid("First-deployment account generation differs from its DRS1.");

        var dpaRef = Reference(ArtifactType.Dpa1, dpa.Record);
        var drsRef = Reference(ArtifactType.Drs1, drs.Record);
        _transcript = new byte[197];
        _transcript[0] = 1;
        governance.Network.CopyTo(_transcript.AsSpan(1));
        BinaryPrimitives.WriteUInt64BigEndian(_transcript.AsSpan(17, 8), dpa.AccountGeneration);
        account.DeepAccountIdHash.Span.CopyTo(_transcript.AsSpan(25));
        dpaRef.CopyTo(_transcript, 57);
        drsRef.CopyTo(_transcript, 95);
        governance.DeploymentGovernanceBootstrapHash.Span.CopyTo(_transcript.AsSpan(133));
        governance.DeploymentGovernanceBootstrapHash.Span.CopyTo(_transcript.AsSpan(165));
        _hash = DeploymentGovernanceRecords.BranchHash(1, _transcript);

        var intent = new byte[235];
        intent[0] = 1;
        governance.Network.CopyTo(intent.AsSpan(1));
        account.DeepAccountIdHash.Span.CopyTo(intent.AsSpan(49));
        BinaryPrimitives.WriteUInt64BigEndian(intent.AsSpan(81, 8), dpa.AccountGeneration);
        dpaRef.CopyTo(intent, 127);
        var logicalKey = new byte[49];
        logicalKey[0] = 1;
        governance.Network.CopyTo(logicalKey.AsSpan(1));
        governance.DeploymentGovernanceBootstrapHash.Span.CopyTo(logicalKey.AsSpan(17));
        _reservationRequest = new GenesisResetReservationRequest(intent, logicalKey);
        Governance = governance;
        NewIdentity = newIdentity;
    }

    internal GenesisCutoverBranchContext(AccountResetOriginContext origin)
    {
        ArgumentNullException.ThrowIfNull(origin);
        Governance = origin.Governance;
        NewIdentity = origin.NewIdentity;
        AccountResetOrigin = origin;
        _transcript = new byte[65];
        _transcript[0] = 3;
        origin.OriginHash.Span.CopyTo(_transcript.AsSpan(1));
        Governance.DeploymentGovernanceBootstrapHash.Span.CopyTo(_transcript.AsSpan(33));
        _hash = DeploymentGovernanceRecords.BranchHash(3, _transcript);

        var oldAccount = origin.OldCutover.Identity.Account;
        var oldDcm = origin.OldCutover.Manifest.Record;
        var newAccount = NewIdentity.Account;
        var intent = new byte[235];
        intent[0] = 2;
        Governance.Network.CopyTo(intent.AsSpan(1));
        oldAccount.DeepAccountIdHash.Span.CopyTo(intent.AsSpan(17));
        newAccount.DeepAccountIdHash.Span.CopyTo(intent.AsSpan(49));
        BinaryPrimitives.WriteUInt64BigEndian(intent.AsSpan(81, 8),
            newAccount.Certificate.AccountGeneration);
        Reference(ArtifactType.Dpa1, oldAccount.Certificate.Record).CopyTo(intent, 89);
        Reference(ArtifactType.Dpa1, newAccount.Certificate.Record).CopyTo(intent, 127);
        oldDcm.FieldSpan(2).CopyTo(intent.AsSpan(203));

        var logicalKey = new byte[57];
        logicalKey[0] = 2;
        Governance.Network.CopyTo(logicalKey.AsSpan(1));
        BinaryPrimitives.WriteUInt64BigEndian(logicalKey.AsSpan(17, 8),
            oldAccount.Certificate.AccountGeneration);
        oldAccount.DeepAccountIdHash.Span.CopyTo(logicalKey.AsSpan(25));
        _reservationRequest = new GenesisResetReservationRequest(intent, logicalKey);
    }

    internal GenesisCutoverBranchContext(VerifiedDeploymentGovernanceContext governance,
        VerifiedIdentityRelative identity, CurrentCutoverRelative current)
    {
        ArgumentNullException.ThrowIfNull(governance); ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(current);
        if (identity.IsTerminal || identity.ForkLatched || !current.HasRecoveryClosure)
            Invalid("Same-account successor requires a usable current recovery closure.");
        var dpa = identity.Account.Certificate; var drs = identity.Revocations.Snapshot;
        Equal(governance.Network, dpa.NetworkId.Span, "same-account governance network");
        Equal(current.TrustedNetwork, dpa.NetworkId.Span, "same-account current network");
        Equal(current.TrustedAccountHash, identity.Account.DeepAccountIdHash.Span,
            "same-account hash");
        if (current.AccountGeneration != dpa.AccountGeneration ||
            !CanonicalGrammar.FixedEquals(current.TrustedDrsRef,
                Reference(ArtifactType.Drs1, drs.Record)) ||
            !CanonicalGrammar.FixedEquals(current.TrustedDcmRef,
                Reference(ArtifactType.Dcm1, CanonicalGrammar.DecodeOwned(
                    current.TrustedDcm, RecordDefinitions.Dcm1))))
            Invalid("The current cutover does not match the same-account identity.");
        _transcript = new byte[203]; _transcript[0] = 2;
        governance.Network.CopyTo(_transcript.AsSpan(1));
        BinaryPrimitives.WriteUInt64BigEndian(_transcript.AsSpan(17, 8), dpa.AccountGeneration);
        identity.Account.DeepAccountIdHash.Span.CopyTo(_transcript.AsSpan(25));
        Reference(ArtifactType.Dpa1, dpa.Record).CopyTo(_transcript, 57);
        Reference(ArtifactType.Drs1, drs.Record).CopyTo(_transcript, 95);
        current.TrustedDcmRef.CopyTo(_transcript.AsSpan(133));
        governance.DeploymentGovernanceBootstrapHash.Span.CopyTo(_transcript.AsSpan(171));
        _hash = DeploymentGovernanceRecords.BranchHash(2, _transcript);
        Governance = governance; NewIdentity = identity; CurrentCutover = current;
    }

    internal VerifiedDeploymentGovernanceContext Governance { get; }
    internal VerifiedIdentityRelative NewIdentity { get; }
    internal AccountResetOriginContext? AccountResetOrigin { get; }
    internal CurrentCutoverRelative? CurrentCutover { get; }
    internal ReadOnlySpan<byte> ExactTranscript => _transcript;
    internal ReadOnlySpan<byte> BranchHash => _hash;
    internal GenesisResetReservationRequest ReservationRequest => _reservationRequest ??
        throw new RecordException(RecordError.InvalidField,
            "SameAccount has no reset-reservation request.");
    internal byte BranchKind => _transcript[0];
    internal ReadOnlySpan<byte> OperationId => AccountResetOrigin is null
        ? ReadOnlySpan<byte>.Empty
        : AccountResetOrigin.OperationId.Span;
    public bool NoAuthorityClaim => true;

    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string name)
    {
        if (!CanonicalGrammar.FixedEquals(actual, expected)) Invalid($"The {name} differs.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static GenesisCutoverBranchContext CreateFirstDeploymentCutoverBranch(
        VerifiedDeploymentGovernanceContext governance,
        VerifiedIdentityRelative newIdentity) => new(governance, newIdentity);

    public static GenesisCutoverBranchContext CreateSameAccountCutoverBranch(
        VerifiedDeploymentGovernanceContext governance, VerifiedIdentityRelative identity,
        CurrentCutoverRelative current) => new(governance, identity, current);

    public static async ValueTask<GenesisResetReservationResult>
        RestoreOrReserveGenesisResetIdByScopeAsync(
            GenesisCutoverBranchContext branch,
            GenesisResetReservationProvider provider,
            IProtectedHmacProvider hmacProvider,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(branch);
        if (branch.BranchKind == 2)
            throw new RecordException(RecordError.InvalidField,
                "SameAccount derives its reset ID and does not reserve one.");
        return await GenesisReservationVerifier.RestoreResetAsync(provider,
            branch.ReservationRequest, hmacProvider, cancellationToken).ConfigureAwait(false);
    }
}

internal static class DeploymentGovernanceScalarExtensions
{
    internal static ulong AsU64(this ReadOnlySpan<byte> value) =>
        BinaryPrimitives.ReadUInt64BigEndian(value);
}
