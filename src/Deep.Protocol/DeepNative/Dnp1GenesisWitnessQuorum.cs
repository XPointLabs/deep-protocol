using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisWitnessReceiptRequest
{
    private readonly ReadOnlyMemory<byte>[] _commonFields;
    private readonly ReadOnlyMemory<byte>[] _artifacts;

    internal GenesisWitnessReceiptRequest(
        IReadOnlyList<ReadOnlyMemory<byte>> commonFields1Through14,
        IReadOnlyList<ReadOnlyMemory<byte>> canonicalArtifacts,
        ulong maximumTreeSize)
    {
        ArgumentNullException.ThrowIfNull(commonFields1Through14);
        ArgumentNullException.ThrowIfNull(canonicalArtifacts);
        if (commonFields1Through14.Count != 14 || canonicalArtifacts.Count != 7 ||
            maximumTreeSize == 0)
            Invalid("The genesis witness receipt request is not exact.");
        _commonFields = commonFields1Through14.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
        _artifacts = canonicalArtifacts.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
        MaximumTreeSize = maximumTreeSize;
    }

    public IReadOnlyList<ReadOnlyMemory<byte>> ExpectedFields1Through14 =>
        Array.AsReadOnly(_commonFields.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
    public ReadOnlyMemory<byte> SelectedWitnessId => _commonFields[13].ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> CanonicalPreExternalArtifacts =>
        Array.AsReadOnly(_artifacts.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
    public ulong MaximumTreeSize { get; }

    internal IReadOnlyList<ReadOnlyMemory<byte>> TrustedCommonFields => _commonFields;

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisWitnessReceiptReadResult
{
    private readonly byte[] _canonical;

    public GenesisWitnessReceiptReadResult(
        ReadOnlySpan<byte> canonicalDcn1,
        ulong sourceRevision,
        bool healthy)
    {
        _canonical = canonicalDcn1.ToArray();
        SourceRevision = sourceRevision;
        Healthy = healthy;
    }

    public ReadOnlyMemory<byte> CanonicalReceipt => _canonical.ToArray();
    public ulong SourceRevision { get; }
    public bool Healthy { get; }
}

public abstract class GenesisWitnessReceiptProvider
{
    public abstract ValueTask<GenesisWitnessReceiptReadResult> AppendOrRestoreAsync(
        GenesisWitnessReceiptRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Sealed lookup scope for the fresh ReleaseRoot/DWD/WHL read immediately before witness calls.
/// The values identify already-verified state and grant no publication or mutation authority.
/// </summary>
public sealed class GenesisWitnessHeadRequest
{
    private readonly byte[] _network;
    private readonly byte[] _resetId;
    private readonly byte[] _dwdReference;
    private readonly byte[] _authorityHead;

    internal GenesisWitnessHeadRequest(GenesisReleaseContext release)
    {
        _network = release.Network.ToArray();
        _resetId = release.ResetId.ToArray();
        _dwdReference = release.LatestDwdReference.ToArray();
        _authorityHead = release.CurrentReleaseRootAuthorityHead.ToArray();
    }

    public ReadOnlyMemory<byte> Network => _network.ToArray();
    public ReadOnlyMemory<byte> ResetId => _resetId.ToArray();
    public ReadOnlyMemory<byte> ExpectedDwdReference => _dwdReference.ToArray();
    public ReadOnlyMemory<byte> ExpectedReleaseRootAuthorityHead => _authorityHead.ToArray();
    public bool NoAuthorityClaim => true;
}

/// <summary>Untrusted, bounded, defensively-owned current witness-head bytes.</summary>
public sealed class GenesisWitnessHeadReadResult
{
    private readonly byte[] _dwd;
    private readonly byte[] _rrl;
    private readonly byte[] _whl;

    public GenesisWitnessHeadReadResult(
        ReadOnlySpan<byte> exactDwd1217,
        ReadOnlySpan<byte> exactRrl502,
        ReadOnlySpan<byte> exactWhl,
        ulong sourceRevision,
        bool healthy)
    {
        if (exactDwd1217.Length != 1217 || exactRrl502.Length != 502)
            Invalid("The current genesis witness head has a wrong fixed width.");
        WitnessHeadHistoryLkgInput.Preflight(exactWhl);
        _dwd = exactDwd1217.ToArray();
        _rrl = exactRrl502.ToArray();
        _whl = exactWhl.ToArray();
        SourceRevision = sourceRevision;
        Healthy = healthy;
    }

    public ReadOnlyMemory<byte> CanonicalDwd => _dwd.ToArray();
    public ReadOnlyMemory<byte> CanonicalReleaseRootLkg => _rrl.ToArray();
    public ReadOnlyMemory<byte> CanonicalWitnessHeadHistoryLkg => _whl.ToArray();
    public ulong SourceRevision { get; }
    public bool Healthy { get; }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidLength, message);
}

/// <summary>Consumer-owned current witness-head read. Returned bytes are always untrusted.</summary>
public abstract class GenesisWitnessHeadProvider
{
    public abstract ValueTask<GenesisWitnessHeadReadResult> ReadCurrentAsync(
        GenesisWitnessHeadRequest request,
        CancellationToken cancellationToken);
}

public sealed class GenesisWitnessReceiptSet
{
    private readonly WitnessReceipt[] _receipts;
    private readonly ulong[] _sourceRevisions;

    internal GenesisWitnessReceiptSet(
        IReadOnlyList<WitnessReceipt> receipts,
        IReadOnlyList<ulong> sourceRevisions)
    {
        if (receipts.Count != 3 || sourceRevisions.Count != 3)
            throw new RecordException(RecordError.InvalidField,
                "The genesis witness receipt set is not exact.");
        _receipts = receipts.ToArray();
        _sourceRevisions = sourceRevisions.ToArray();
    }

    public IReadOnlyList<WitnessReceipt> Receipts => Array.AsReadOnly(_receipts.ToArray());
    public IReadOnlyList<ulong> SourceRevisions => Array.AsReadOnly(_sourceRevisions.ToArray());
    public bool NoAuthorityClaim => true;
    internal IReadOnlyList<WitnessReceipt> TrustedReceipts => _receipts;
}

/// <summary>
/// One canonical DCQ1 assembled only from the sealed receipt set verified in this authoring
/// operation. It is relative data and cannot be constructed from caller-supplied DCQ bytes.
/// </summary>
public sealed class GenesisVerifiedQuorumReceipt
{
    private readonly byte[] _dcnReferences;

    internal GenesisVerifiedQuorumReceipt(
        GenesisPreExternalCandidatePlan plan,
        GenesisReleaseContext release,
        GenesisQuorumPending pending,
        QuorumReceipt receipt,
        ReadOnlySpan<byte> dcnReferences)
    {
        if (dcnReferences.Length != 114)
            throw new RecordException(RecordError.InvalidLength,
                "The verified genesis DCN reference set is not exact.");
        Plan = plan;
        Release = release;
        Pending = pending;
        Receipt = receipt;
        _dcnReferences = dcnReferences.ToArray();
    }

    public ReadOnlyMemory<byte> CanonicalBytes => Receipt.CanonicalBytes.ToArray();
    public bool NoAuthorityClaim => true;
    internal GenesisPreExternalCandidatePlan Plan { get; }
    internal GenesisReleaseContext Release { get; }
    internal GenesisQuorumPending Pending { get; }
    internal QuorumReceipt Receipt { get; }
    internal ReadOnlySpan<byte> DcnReferences => _dcnReferences;
}

internal static class GenesisWitnessQuorumAuthor
{
    internal static async ValueTask<GenesisWitnessReceiptSet> AuthorReceiptsAsync(
        GenesisAuthorCreatedPlan created,
        GenesisReleaseContext release,
        GenesisWitnessHeadProvider headProvider,
        GenesisWitnessReceiptProvider provider,
        IProtectedHmacProvider hmacProvider,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(created);
        ArgumentNullException.ThrowIfNull(release);
        ArgumentNullException.ThrowIfNull(headProvider);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        if (nowUnixSeconds == 0 || created.Journal.Phase != 0 ||
            !CanonicalGrammar.FixedEquals(created.Candidate.Identity.BaseIdentity.Network,
                release.Network) ||
            !CanonicalGrammar.FixedEquals(created.Candidate.Identity.BaseIdentity.ResetId,
                release.ResetId))
            Invalid("The genesis witness authoring context is not Created and current.");

        var plan = created.Candidate;
        var pending = created.QuorumPending.CanonicalPending.ToArray();
        var receipts = new WitnessReceipt[3];
        var revisions = new ulong[3];
        try
        {
            GenesisProtectedRecords.PreflightGqp(pending);
            await VerifyCurrentHeadAsync(release, headProvider, hmacProvider,
                cancellationToken).ConfigureAwait(false);
            var dcsRef = Reference(ArtifactType.Dcs1, plan.DeploymentSet.Record);
            var dctRef = Reference(ArtifactType.Dct1, plan.Transaction.Record);
            var common = new ReadOnlyMemory<byte>[14];
            common[0] = plan.Identity.BaseIdentity.Network.ToArray();
            common[1] = plan.DeploymentSubject.ToArray();
            common[2] = U64(1);
            common[3] = dcsRef;
            common[4] = dctRef;
            common[5] = release.LatestDelegation.Delegation.Record.FieldCopy(15);
            common[6] = U64(release.LatestWitnessEpoch);
            common[7] = release.LatestDwdReference.ToArray();
            common[8] = U64(release.CurrentRoot.CurrentGeneration);
            common[9] = CanonicalGrammar.EncodeReference(
                release.CurrentRoot.CurrentTransitionReference);
            common[10] = new byte[38];
            common[11] = new byte[] { 0 };
            common[12] = release.CurrentReleaseRootAuthorityHead.ToArray();

            for (var index = 0; index < 3; index++)
            {
                common[13] = pending.AsMemory(251 + index * 32, 32).ToArray();
                var request = new GenesisWitnessReceiptRequest(
                    common, created.ArtifactSet.Artifacts,
                    release.LatestDelegation.Delegation.MaximumTreeSize);
                var returned = await provider.AppendOrRestoreAsync(request, cancellationToken)
                    .ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (returned is null || !returned.Healthy || returned.SourceRevision == 0)
                    Invalid("A selected genesis witness is absent or unhealthy.");
                var canonical = returned!.CanonicalReceipt.ToArray();
                try
                {
                    var receipt = CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dcn1);
                    for (var tag = 1; tag <= 14; tag++)
                        Equal(receipt.FieldSpan(tag), common[tag - 1].Span,
                            $"DCN1 authoring field {tag}");
                    GenesisQuorumStateVerifier.VerifyDcn(
                        plan, release, created.QuorumPending, index, receipt, nowUnixSeconds);
                    receipts[index] = new WitnessReceipt(receipt);
                    revisions[index] = returned.SourceRevision;
                }
                finally { Array.Clear(canonical); }
            }

            return new GenesisWitnessReceiptSet(receipts, revisions);
        }
        finally { Array.Clear(pending); }
    }

    internal static async ValueTask VerifyCurrentHeadAsync(
        GenesisReleaseContext release,
        GenesisWitnessHeadProvider provider,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        var returned = await provider.ReadCurrentAsync(
            new GenesisWitnessHeadRequest(release), cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (returned is null)
            throw new RecordException(RecordError.InvalidField,
                "The current genesis witness head is absent.");
        if (!returned.Healthy || returned.SourceRevision == 0)
            Invalid("The current genesis witness head is absent or unhealthy.");
        var dwd = returned.CanonicalDwd.ToArray();
        var rrl = returned.CanonicalReleaseRootLkg.ToArray();
        var whl = returned.CanonicalWitnessHeadHistoryLkg.ToArray();
        try
        {
            if (!CanonicalGrammar.FixedEquals(
                    dwd, release.LatestDelegation.Delegation.CanonicalBytes.Span) ||
                !CanonicalGrammar.FixedEquals(rrl, release.ReleaseRootLkg) ||
                !CanonicalGrammar.FixedEquals(whl, release.WitnessHeadHistoryLkg))
                Invalid("The current genesis witness head moved before receipt authoring.");
            var verified = await new WitnessHeadHistoryLkgVerifier().VerifyGenesisAsync(
                new WitnessHeadHistoryLkgInput(whl), rrl, release.CurrentRoot,
                release.OrderedDwdAncestry, release.BaseIdentity, hmacProvider,
                cancellationToken).ConfigureAwait(false);
            var current = new GenesisReleaseContext(release.BaseIdentity, verified);
            if (!CanonicalGrammar.FixedEquals(current.Fingerprint.Span, release.Fingerprint.Span))
                Invalid("The current genesis witness head no longer matches the sealed release context.");
        }
        finally
        {
            Array.Clear(dwd);
            Array.Clear(rrl);
            Array.Clear(whl);
        }
    }

    internal static GenesisVerifiedQuorumReceipt AssembleAndVerify(
        GenesisAuthorCreatedPlan created,
        GenesisReleaseContext release,
        GenesisWitnessReceiptSet receiptSet,
        ulong nowUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(created);
        ArgumentNullException.ThrowIfNull(release);
        ArgumentNullException.ThrowIfNull(receiptSet);
        if (nowUnixSeconds == 0 || created.Journal.Phase != 0)
            Invalid("The genesis quorum assembly context is not Created and current.");
        var receipts = receiptSet.TrustedReceipts;
        if (receipts.Count != 3) Invalid("Genesis DCQ1 requires exactly three DCN1 receipts.");

        var fields = RecordDefinitions.Dcq1.Fields.Select(static field =>
            new byte[field.MinimumLength]).ToArray();
        var first = receipts[0].Record;
        for (var tag = 1; tag <= 5; tag++) fields[tag - 1] = first.FieldCopy(tag);
        fields[5] = first.FieldCopy(8);
        fields[6] = first.FieldCopy(6);
        fields[7] = first.FieldCopy(7);
        fields[8] = new byte[] { 3 };
        var blobLength = receipts.Sum(static value => checked(4 + value.CanonicalBytes.Length));
        var blob = new byte[blobLength];
        var cursor = 0;
        ulong issuedAt = 0;
        ulong expiresAt = ulong.MaxValue;
        var references = new byte[114];
        for (var index = 0; index < receipts.Count; index++)
        {
            var receipt = receipts[index];
            var canonical = receipt.CanonicalBytes.Span;
            BinaryPrimitives.WriteUInt32BigEndian(blob.AsSpan(cursor, 4),
                checked((uint)canonical.Length));
            cursor += 4;
            canonical.CopyTo(blob.AsSpan(cursor));
            cursor += canonical.Length;
            issuedAt = Math.Max(issuedAt, Scalars.UInt64(receipt.Record.FieldSpan(24)));
            expiresAt = Math.Min(expiresAt, Scalars.UInt64(receipt.Record.FieldSpan(25)));
            Reference(ArtifactType.Dcn1, receipt.Record).CopyTo(references, index * 38);
        }
        for (var left = 0; left < 3; left++)
            for (var right = left + 1; right < 3; right++)
                if (CanonicalGrammar.FixedEquals(references.AsSpan(left * 38, 38),
                    references.AsSpan(right * 38, 38)))
                    Invalid("Genesis DCN1 references are not distinct.");
        if (issuedAt == 0 || expiresAt <= issuedAt)
            Invalid("The genesis DCQ1 aggregate window is empty.");
        fields[9] = blob;
        fields[10] = U64(issuedAt);
        fields[11] = U64(expiresAt);
        fields[12] = GenesisQuorumStateVerifier.ComputeQuorumDigest(
            fields[1], fields[2], fields[3], fields[4], references);
        var dcq = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dcq1,
                fields.Select(static value => (ReadOnlyMemory<byte>)value).ToArray()),
            RecordDefinitions.Dcq1);
        return new GenesisVerifiedQuorumReceipt(
            created.Candidate, release, created.QuorumPending,
            new QuorumReceipt(dcq), references);
    }

    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));
    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }
    private static void Equal(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, string name)
    {
        if (!CanonicalGrammar.FixedEquals(left, right)) Invalid($"{name} differs.");
    }
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<GenesisWitnessReceiptSet> AuthorDcnReceiptAsync(
        GenesisAuthorCreatedPlan created,
        GenesisReleaseContext release,
        GenesisWitnessHeadProvider headProvider,
        GenesisWitnessReceiptProvider provider,
        IProtectedHmacProvider hmacProvider,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken = default) =>
        await GenesisWitnessQuorumAuthor.AuthorReceiptsAsync(
            created, release, headProvider, provider, hmacProvider,
            nowUnixSeconds, cancellationToken).ConfigureAwait(false);

    public static ValueTask<GenesisVerifiedQuorumReceipt> VerifyAndAssembleDcqAsync(
        GenesisAuthorCreatedPlan created,
        GenesisReleaseContext release,
        GenesisWitnessReceiptSet receiptSet,
        ulong nowUnixSeconds,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(GenesisWitnessQuorumAuthor.AssembleAndVerify(
            created, release, receiptSet, nowUnixSeconds));
    }
}
