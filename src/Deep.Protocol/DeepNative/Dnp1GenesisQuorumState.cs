using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisQuorumPendingRequest
{
    private readonly byte[] _stableScope;
    private readonly byte[] _operation;

    internal GenesisQuorumPendingRequest(
        ReadOnlySpan<byte> stableScope,
        ReadOnlySpan<byte> operation)
    {
        if (stableScope.Length != 150 || operation.Length != 339)
            Invalid("The genesis quorum-pending request is not exact.");
        _stableScope = stableScope.ToArray();
        _operation = operation.ToArray();
    }

    public ReadOnlyMemory<byte> ExactStableScope => _stableScope.ToArray();
    public ReadOnlyMemory<byte> ExactOperation => _operation.ToArray();
    public ReadOnlyMemory<byte> OperationHash => CanonicalGrammar.Sha256Domain(
        "Deep/Cutover/V6/genesis-quorum-pending-operation", _operation);
    internal ReadOnlySpan<byte> TrustedOperation => _operation;

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisQuorumPendingReadResult
{
    private readonly byte[] _canonical;
    public GenesisQuorumPendingReadResult(
        ReadOnlySpan<byte> canonicalGqp461,
        ulong sourceRevision,
        bool healthy)
    {
        _canonical = canonicalGqp461.ToArray();
        SourceRevision = sourceRevision;
        Healthy = healthy;
    }
    public ReadOnlyMemory<byte> CanonicalPending => _canonical.ToArray();
    public ulong SourceRevision { get; }
    public bool Healthy { get; }
}

public abstract class GenesisQuorumStateProvider
{
    public abstract ValueTask<GenesisQuorumPendingReadResult> RestoreOrCreatePendingAsync(
        GenesisQuorumPendingRequest request,
        CancellationToken cancellationToken);

    public virtual ValueTask<GenesisQuorumSelectionReadResult> CompleteAsync(
        GenesisQuorumSelectionRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("This provider does not support quorum completion.");

    public virtual ValueTask<GenesisQuorumPendingReadResult> RestorePendingByScopeAsync(
        GenesisQuorumPendingLookupRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("This provider does not support scope-only Pending restore.");

    public virtual ValueTask<GenesisQuorumPendingReadResult?> TryRestorePendingByScopeAsync(
        GenesisQuorumPendingLookupRequest request,
        CancellationToken cancellationToken) =>
        throw new NotSupportedException("This provider does not support optional Pending restore.");
}

public sealed class GenesisQuorumPendingLookupRequest
{
    private readonly byte[] _scope;
    internal GenesisQuorumPendingLookupRequest(ReadOnlySpan<byte> exactStableScope150)
    {
        if (exactStableScope150.Length != 150)
            throw new RecordException(RecordError.InvalidField,
                "The genesis quorum Pending lookup scope is invalid.");
        _scope = exactStableScope150.ToArray();
    }
    public ReadOnlyMemory<byte> ExactStableScope => _scope.ToArray();
}

public sealed class GenesisQuorumSelectionRequest
{
    private readonly byte[] _pendingHash;
    private readonly byte[] _unsigned548;
    internal GenesisQuorumSelectionRequest(
        ReadOnlySpan<byte> pendingHash,
        ReadOnlySpan<byte> unsigned548)
    {
        if (pendingHash.Length != 32 || CanonicalGrammar.IsZero(pendingHash) ||
            unsigned548.Length != GenesisProtectedRecords.GqsLength - 32)
            Invalid("The genesis quorum-selection request is invalid.");
        _pendingHash = pendingHash.ToArray();
        _unsigned548 = unsigned548.ToArray();
    }
    public ReadOnlyMemory<byte> PendingHash => _pendingHash.ToArray();
    public ReadOnlyMemory<byte> UnsignedSelection => _unsigned548.ToArray();
    internal ReadOnlySpan<byte> TrustedUnsigned => _unsigned548;
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisQuorumSelectionReadResult
{
    private readonly byte[] _canonical;
    public GenesisQuorumSelectionReadResult(
        ReadOnlySpan<byte> canonicalGqs580,
        ulong sourceRevision,
        bool healthy)
    {
        _canonical = canonicalGqs580.ToArray();
        SourceRevision = sourceRevision;
        Healthy = healthy;
    }
    public ReadOnlyMemory<byte> CanonicalSelection => _canonical.ToArray();
    public ulong SourceRevision { get; }
    public bool Healthy { get; }
}

public sealed class GenesisVerifiedQuorumPlan
{
    internal GenesisVerifiedQuorumPlan(
        QuorumReceipt quorumReceipt,
        GenesisQuorumSelection selection)
    {
        QuorumReceipt = quorumReceipt;
        Selection = selection;
    }
    public QuorumReceipt QuorumReceipt { get; }
    public GenesisQuorumSelection Selection { get; }
    public bool NoAuthorityClaim => true;
}

internal static class GenesisQuorumStateVerifier
{
    internal static byte[] ComputeQuorumDigest(
        ReadOnlySpan<byte> deploymentSubject32,
        ReadOnlySpan<byte> sequence8,
        ReadOnlySpan<byte> dcsReference38,
        ReadOnlySpan<byte> dctReference38,
        ReadOnlySpan<byte> orderedDcnReferences114)
    {
        if (deploymentSubject32.Length != 32 || sequence8.Length != 8 ||
            dcsReference38.Length != 38 || dctReference38.Length != 38 ||
            orderedDcnReferences114.Length != 114)
            Invalid("The quorum-digest transcript width is invalid.");
        Span<byte> digest = stackalloc byte[230];
        deploymentSubject32.CopyTo(digest);
        sequence8.CopyTo(digest[32..]);
        dcsReference38.CopyTo(digest[40..]);
        dctReference38.CopyTo(digest[78..]);
        orderedDcnReferences114.CopyTo(digest[116..]);
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/quorum-digest", digest);
    }

    internal static async ValueTask<GenesisQuorumPending?> TryRestorePendingByScopeAsync(
        VerifiedGenesisArtifactSet artifactSet,
        GenesisIdentityContext identity,
        GenesisReleaseContext release,
        GenesisQuorumStateProvider provider,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        var dct = CanonicalGrammar.DecodeOwned(
            artifactSet.Artifacts[6].Span, RecordDefinitions.Dct1);
        var stable = new byte[150];
        identity.BaseIdentity.Network.CopyTo(stable);
        identity.BaseIdentity.ResetId.CopyTo(stable.AsSpan(16));
        dct.FieldSpan(2).CopyTo(stable.AsSpan(48));
        Reference(ArtifactType.Dct1, dct).CopyTo(stable.AsSpan(80));
        identity.Transaction.TransactionId.CopyTo(stable.AsSpan(118));
        try
        {
            var returned = await provider.TryRestorePendingByScopeAsync(
                new GenesisQuorumPendingLookupRequest(stable), cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (returned is null) return null;
            return await RestorePendingByScopeAsync(
                artifactSet, identity, release, new FrozenPendingProvider(returned),
                hmacProvider, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(stable);
        }
    }

    internal static async ValueTask<GenesisVerifiedQuorumPlan> VerifyAndCompleteRestoredAsync(
        GenesisPreExternalCandidatePlan plan,
        GenesisReleaseContext release,
        GenesisQuorumPending pending,
        ReadOnlyMemory<byte> exactDcq1,
        ulong nowUnixSeconds,
        GenesisQuorumStateProvider provider,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        var dcq = CanonicalGrammar.DecodeOwned(exactDcq1.Span, RecordDefinitions.Dcq1);
        var references = VerifyDcq(plan, release, pending, dcq, nowUnixSeconds);
        var verified = new GenesisVerifiedQuorumReceipt(
            plan, release, pending, new QuorumReceipt(dcq), references);
        return await VerifyAndCompleteAsync(
            plan, release, pending, verified, nowUnixSeconds,
            provider, hmacProvider, cancellationToken).ConfigureAwait(false);
    }

    internal static async ValueTask<GenesisQuorumPending> RestoreOrCreatePendingAsync(
        GenesisPreExternalCandidatePlan plan,
        GenesisReleaseContext release,
        IReadOnlyList<ReadOnlyMemory<byte>> selectedWitnessIds,
        GenesisQuorumStateProvider provider,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(release);
        ArgumentNullException.ThrowIfNull(selectedWitnessIds);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        if (selectedWitnessIds.Count != 3)
            Invalid("Genesis quorum Pending must select exactly three witnesses.");
        var selected = selectedWitnessIds.Select(static value => value.ToArray()).ToArray();
        try
        {
            for (var index = 0; index < selected.Length; index++)
            {
                if (selected[index].Length != 32 || CanonicalGrammar.IsZero(selected[index]) ||
                    index != 0 && selected[index - 1].AsSpan().SequenceCompareTo(selected[index]) >= 0 ||
                    !release.LatestWitnessIds.Any(value =>
                        CanonicalGrammar.FixedEquals(value.Span, selected[index])))
                    Invalid("The genesis quorum witness set is not a strict current subset.");
            }
            var identity = plan.Identity;
            if (!CanonicalGrammar.FixedEquals(identity.BaseIdentity.Network, release.Network) ||
                !CanonicalGrammar.FixedEquals(identity.BaseIdentity.ResetId, release.ResetId))
                Invalid("The genesis quorum combines different sealed axes.");
            var dctRef = Reference(ArtifactType.Dct1, plan.Transaction.Record);
            var dcsRef = Reference(ArtifactType.Dcs1, plan.DeploymentSet.Record);
            var operation = new byte[339]; var offset = 0;
            Append(identity.BaseIdentity.Network); Append(identity.BaseIdentity.ResetId);
            Append(plan.DeploymentSubject.Span); U64(identity.BaseIdentity.AccountGeneration);
            Append(identity.Transaction.TransactionId); Append(dctRef); Append(dcsRef);
            Append(release.LatestDwdReference); U64(release.LatestWitnessEpoch);
            operation[offset++] = 3;
            foreach (var id in selected) Append(id);
            if (offset != operation.Length) Invalid("The genesis quorum operation width drifted.");
            var stable = new byte[150]; offset = 0;
            AppendStable(identity.BaseIdentity.Network); AppendStable(identity.BaseIdentity.ResetId);
            AppendStable(plan.DeploymentSubject.Span); AppendStable(dctRef);
            AppendStable(identity.Transaction.TransactionId);
            var request = new GenesisQuorumPendingRequest(stable, operation);
            var returned = await provider.RestoreOrCreatePendingAsync(request, cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (returned is null || !returned.Healthy || returned.SourceRevision == 0)
                Invalid("The genesis quorum Pending provider is absent or unhealthy.");
            var canonical = returned!.CanonicalPending.ToArray();
            try
            {
                GenesisProtectedRecords.PreflightGqp(canonical);
                if (!CanonicalGrammar.FixedEquals(canonical.AsSpan(8, 339), operation) ||
                    !CanonicalGrammar.FixedEquals(canonical.AsSpan(347, 32), request.OperationHash.Span) ||
                    returned.SourceRevision != BinaryPrimitives.ReadUInt64BigEndian(
                        canonical.AsSpan(379, 8)) ||
                    !CanonicalGrammar.FixedEquals(canonical.AsSpan(397, 32),
                        identity.ProtectedStateHmacKeyId))
                    Invalid("GQP1 differs from the sealed quorum operation.");
                await GenesisProtectedRecords.VerifyAsync(
                    "Deep/ProtectedState/V1/GQP1", canonical,
                    GenesisProtectedRecords.GqpKeyOffset, hmacProvider, cancellationToken)
                    .ConfigureAwait(false);
                return new GenesisQuorumPending(canonical);
            }
            finally { Array.Clear(canonical); }

            void Append(ReadOnlySpan<byte> value)
            { value.CopyTo(operation.AsSpan(offset)); offset += value.Length; }
            void U64(ulong value)
            { BinaryPrimitives.WriteUInt64BigEndian(operation.AsSpan(offset, 8), value); offset += 8; }
            void AppendStable(ReadOnlySpan<byte> value)
            { value.CopyTo(stable.AsSpan(offset)); offset += value.Length; }
        }
        finally
        {
            foreach (var value in selected) Array.Clear(value);
        }
    }

    internal static async ValueTask<GenesisQuorumPending> RestorePendingByScopeAsync(
        VerifiedGenesisArtifactSet artifactSet,
        GenesisIdentityContext identity,
        GenesisReleaseContext release,
        GenesisQuorumStateProvider provider,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(artifactSet);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(release);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        if (!CanonicalGrammar.FixedEquals(
                artifactSet.Receipt.CanonicalReceipt.Span.Slice(8, 122),
                GenesisArtifactSetVerifier.AuthorScope(identity)) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.Network, release.Network) ||
            !CanonicalGrammar.FixedEquals(identity.BaseIdentity.ResetId, release.ResetId))
            Invalid("The quorum Pending restore axes differ.");
        var dcs = CanonicalGrammar.DecodeOwned(
            artifactSet.Artifacts[5].Span, RecordDefinitions.Dcs1);
        var dct = CanonicalGrammar.DecodeOwned(
            artifactSet.Artifacts[6].Span, RecordDefinitions.Dct1);
        var dcsRef = Reference(ArtifactType.Dcs1, dcs);
        var dctRef = Reference(ArtifactType.Dct1, dct);
        var stable = new byte[150]; var offset = 0;
        Append(identity.BaseIdentity.Network); Append(identity.BaseIdentity.ResetId);
        Append(dct.FieldSpan(2)); Append(dctRef); Append(identity.Transaction.TransactionId);
        var returned = await provider.RestorePendingByScopeAsync(
            new GenesisQuorumPendingLookupRequest(stable), cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (returned is null || !returned.Healthy || returned.SourceRevision == 0)
            Invalid("The retained genesis quorum Pending is absent or unhealthy.");
        var canonical = returned!.CanonicalPending.ToArray();
        try
        {
            GenesisProtectedRecords.PreflightGqp(canonical);
            var operation = canonical.AsSpan(8, 339);
            if (!CanonicalGrammar.FixedEquals(operation[..16], identity.BaseIdentity.Network) ||
                !CanonicalGrammar.FixedEquals(operation.Slice(16, 32), identity.BaseIdentity.ResetId) ||
                !CanonicalGrammar.FixedEquals(operation.Slice(48, 32), dct.FieldSpan(2)) ||
                BinaryPrimitives.ReadUInt64BigEndian(operation.Slice(80, 8)) !=
                    identity.BaseIdentity.AccountGeneration ||
                !CanonicalGrammar.FixedEquals(operation.Slice(88, 32), identity.Transaction.TransactionId) ||
                !CanonicalGrammar.FixedEquals(operation.Slice(120, 38), dctRef) ||
                !CanonicalGrammar.FixedEquals(operation.Slice(158, 38), dcsRef) ||
                !CanonicalGrammar.FixedEquals(operation.Slice(196, 38), release.LatestDwdReference) ||
                BinaryPrimitives.ReadUInt64BigEndian(operation.Slice(234, 8)) != release.LatestWitnessEpoch ||
                operation[242] != 3 ||
                !CanonicalGrammar.FixedEquals(canonical.AsSpan(347, 32),
                    CanonicalGrammar.Sha256Domain(
                        "Deep/Cutover/V6/genesis-quorum-pending-operation", operation)) ||
                returned.SourceRevision != BinaryPrimitives.ReadUInt64BigEndian(
                    canonical.AsSpan(379, 8)) ||
                !CanonicalGrammar.FixedEquals(canonical.AsSpan(397, 32),
                    identity.ProtectedStateHmacKeyId))
                Invalid("The retained GQP1 differs from the exact genesis candidate.");
            for (var index = 0; index < 3; index++)
            {
                var id = operation.Slice(243 + index * 32, 32);
                var found = false;
                foreach (var current in release.LatestWitnessIds)
                    if (CanonicalGrammar.FixedEquals(current.Span, id))
                    {
                        found = true;
                        break;
                    }
                if (!found)
                    Invalid("The retained GQP1 selected a non-current witness.");
            }
            await GenesisProtectedRecords.VerifyAsync(
                "Deep/ProtectedState/V1/GQP1", canonical,
                GenesisProtectedRecords.GqpKeyOffset, hmacProvider, cancellationToken)
                .ConfigureAwait(false);
            return new GenesisQuorumPending(canonical);
        }
        finally { Array.Clear(canonical); }

        void Append(ReadOnlySpan<byte> value)
        { value.CopyTo(stable.AsSpan(offset)); offset += value.Length; }
    }

    internal static async ValueTask<GenesisVerifiedQuorumPlan> VerifyAndCompleteAsync(
        GenesisPreExternalCandidatePlan plan,
        GenesisReleaseContext release,
        GenesisQuorumPending pending,
        GenesisVerifiedQuorumReceipt verifiedDcq,
        ulong nowUnixSeconds,
        GenesisQuorumStateProvider provider,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(release);
        ArgumentNullException.ThrowIfNull(pending);
        ArgumentNullException.ThrowIfNull(verifiedDcq);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        if (nowUnixSeconds == 0) Invalid("The genesis quorum verification time is zero.");
        if (!ReferenceEquals(verifiedDcq.Plan, plan) ||
            !ReferenceEquals(verifiedDcq.Release, release) ||
            !ReferenceEquals(verifiedDcq.Pending, pending))
            Invalid("The verified DCQ1 belongs to another genesis authoring operation.");
        var dcq = verifiedDcq.Receipt.Record;
        var pendingBytes = pending.CanonicalPending.ToArray();
        try
        {
            var dcsRef = Reference(ArtifactType.Dcs1, plan.DeploymentSet.Record);
            var dctRef = Reference(ArtifactType.Dct1, plan.Transaction.Record);
            var dcnReferences = VerifyDcqCore(
                plan, release, pending, dcq, nowUnixSeconds, verifySignatures: false);
            if (!CanonicalGrammar.FixedEquals(
                    dcnReferences, verifiedDcq.DcnReferences))
                Invalid("The verified DCQ1 receipt set changed before completion.");
            var dcqRef = Reference(ArtifactType.Dcq1, dcq);

            var unsigned = new byte[GenesisProtectedRecords.GqsLength - 32];
            ProtocolMagicBytes.GQS1.CopyTo(unsigned);
            unsigned[4] = 1;
            pendingBytes.AsSpan(8, 243).CopyTo(unsigned.AsSpan(8));
            for (var index = 0; index < 3; index++)
            {
                pendingBytes.AsSpan(251 + index * 32, 32)
                    .CopyTo(unsigned.AsSpan(251 + index * 70, 32));
                dcnReferences.AsSpan(index * 38, 38)
                    .CopyTo(unsigned.AsSpan(283 + index * 70, 38));
            }
            dcqRef.CopyTo(unsigned, 461);
            BinaryPrimitives.WriteUInt64BigEndian(unsigned.AsSpan(499, 8),
                BinaryPrimitives.ReadUInt64BigEndian(pendingBytes.AsSpan(379, 8)));
            BinaryPrimitives.WriteUInt64BigEndian(unsigned.AsSpan(507, 8),
                BinaryPrimitives.ReadUInt64BigEndian(pendingBytes.AsSpan(387, 8)));
            unsigned[515] = 0;
            pendingBytes.AsSpan(397, 32).CopyTo(unsigned.AsSpan(516));
            var request = new GenesisQuorumSelectionRequest(pending.PendingHash.Span, unsigned);
            var returned = await provider.CompleteAsync(request, cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (returned is null || !returned.Healthy || returned.SourceRevision == 0)
                Invalid("The genesis quorum selection provider is absent or unhealthy.");
            var canonical = returned!.CanonicalSelection.ToArray();
            try
            {
                GenesisProtectedRecords.PreflightGqs(canonical);
                if (!CanonicalGrammar.FixedEquals(canonical.AsSpan(0, 548), unsigned) ||
                    returned.SourceRevision != BinaryPrimitives.ReadUInt64BigEndian(
                        canonical.AsSpan(499, 8)))
                    Invalid("GQS1 differs from the verified Pending and DCQ1.");
                await GenesisProtectedRecords.VerifyAsync(
                    "Deep/ProtectedState/V1/GQS1", canonical,
                    GenesisProtectedRecords.GqsKeyOffset, hmacProvider, cancellationToken)
                    .ConfigureAwait(false);
                return new GenesisVerifiedQuorumPlan(
                    verifiedDcq.Receipt, new GenesisQuorumSelection(canonical));
            }
            finally { Array.Clear(canonical); }
        }
        finally { Array.Clear(pendingBytes); }
    }

    internal static byte[] VerifyDcq(
        GenesisPreExternalCandidatePlan plan,
        GenesisReleaseContext release,
        GenesisQuorumPending pending,
        OwnedRecord dcq,
        ulong nowUnixSeconds) =>
        VerifyDcqCore(plan, release, pending, dcq, nowUnixSeconds, verifySignatures: true);

    private static byte[] VerifyDcqCore(
        GenesisPreExternalCandidatePlan plan,
        GenesisReleaseContext release,
        GenesisQuorumPending pending,
        OwnedRecord dcq,
        ulong nowUnixSeconds,
        bool verifySignatures)
    {
        var pendingBytes = pending.CanonicalPending.ToArray();
        try
        {
            var dcsRef = Reference(ArtifactType.Dcs1, plan.DeploymentSet.Record);
            var dctRef = Reference(ArtifactType.Dct1, plan.Transaction.Record);
            Equal(dcq.FieldSpan(1), plan.Identity.BaseIdentity.Network, "DCQ1 network");
            Equal(dcq.FieldSpan(2), plan.DeploymentSubject.Span, "DCQ1 deployment subject");
            if (Scalars.UInt64(dcq.FieldSpan(3)) != 1)
                Invalid("Genesis DCQ1 sequence is not one.");
            Equal(dcq.FieldSpan(4), dcsRef, "DCQ1 DCS");
            Equal(dcq.FieldSpan(5), dctRef, "DCQ1 DCT");
            Equal(dcq.FieldSpan(6), release.LatestDwdReference, "DCQ1 DWD");
            Equal(dcq.FieldSpan(7), release.LatestDelegation.Delegation.Record.FieldSpan(15),
                "DCQ1 witness-set root");
            if (Scalars.UInt64(dcq.FieldSpan(8)) != release.LatestWitnessEpoch)
                Invalid("Genesis DCQ1 witness epoch is stale.");
            Window(dcq.FieldSpan(11), dcq.FieldSpan(12), nowUnixSeconds, ProtocolMagic.DCQ1);
            return VerifyReceipts(
                dcq, release, pendingBytes.AsSpan(251, 96), nowUnixSeconds,
                verifySignatures);
        }
        finally { Array.Clear(pendingBytes); }
    }

    internal static byte[] VerifyDcn(
        GenesisPreExternalCandidatePlan plan,
        GenesisReleaseContext release,
        GenesisQuorumPending pending,
        int selectedIndex,
        OwnedRecord receipt,
        ulong nowUnixSeconds)
    {
        if (selectedIndex is < 0 or > 2)
            Invalid("The selected genesis witness index is invalid.");
        var pendingBytes = pending.CanonicalPending.ToArray();
        try
        {
            var dcsRef = Reference(ArtifactType.Dcs1, plan.DeploymentSet.Record);
            var dctRef = Reference(ArtifactType.Dct1, plan.Transaction.Record);
            return VerifyReceipt(
                receipt, release,
                plan.Identity.BaseIdentity.Network,
                plan.DeploymentSubject.Span,
                dcsRef,
                dctRef,
                pendingBytes.AsSpan(251 + selectedIndex * 32, 32),
                nowUnixSeconds,
                verifySignature: true);
        }
        finally { Array.Clear(pendingBytes); }
    }

    private static byte[] VerifyReceipts(
        OwnedRecord dcq,
        GenesisReleaseContext release,
        ReadOnlySpan<byte> selectedIds,
        ulong now,
        bool verifySignatures)
    {
        if (dcq.FieldSpan(9)[0] != 3)
            Invalid("Genesis DCQ1 must contain exactly three receipts.");
        var blob = dcq.FieldSpan(10); var cursor = 0;
        var references = new byte[114];
        ReadOnlySpan<byte> previousId = default;
        for (var index = 0; index < 3; index++)
        {
            if (cursor > blob.Length - 4) Invalid("Genesis DCQ1 receipt framing is truncated.");
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(blob.Slice(cursor, 4)));
            cursor += 4;
            if (length is < 758 or > 2806 || cursor > blob.Length - length)
                Invalid("Genesis DCQ1 receipt length is invalid.");
            var receipt = CanonicalGrammar.DecodeOwned(
                blob.Slice(cursor, length), RecordDefinitions.Dcn1);
            cursor += length;
            var witnessId = receipt.FieldSpan(14);
            if (index != 0 && previousId.SequenceCompareTo(witnessId) >= 0)
                Invalid("Genesis DCN1 witness IDs are not sorted.");
            previousId = witnessId;
            VerifyReceipt(receipt, release, dcq.FieldSpan(1), dcq.FieldSpan(2),
                dcq.FieldSpan(4), dcq.FieldSpan(5), selectedIds.Slice(index * 32, 32), now,
                verifySignatures)
                .CopyTo(references, index * 38);
        }
        if (cursor != blob.Length) Invalid("Genesis DCQ1 has trailing receipt bytes.");
        Equal(dcq.FieldSpan(13), ComputeQuorumDigest(
            dcq.FieldSpan(2), dcq.FieldSpan(3), dcq.FieldSpan(4),
            dcq.FieldSpan(5), references), "DCQ1 digest");
        return references;
    }

    private static byte[] VerifyReceipt(
        OwnedRecord receipt,
        GenesisReleaseContext release,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> deploymentSubject,
        ReadOnlySpan<byte> dcsRef,
        ReadOnlySpan<byte> dctRef,
        ReadOnlySpan<byte> selectedWitnessId,
        ulong now,
        bool verifySignature)
    {
        Equal(receipt.FieldSpan(1), network, "DCN1 network");
        Equal(receipt.FieldSpan(2), deploymentSubject, "DCN1 deployment subject");
        if (Scalars.UInt64(receipt.FieldSpan(3)) != 1)
            Invalid("Genesis DCN1 sequence is not one.");
        Equal(receipt.FieldSpan(4), dcsRef, "DCN1 DCS");
        Equal(receipt.FieldSpan(5), dctRef, "DCN1 DCT");
        Equal(receipt.FieldSpan(6), release.LatestDelegation.Delegation.Record.FieldSpan(15),
            "DCN1 witness-set root");
        if (Scalars.UInt64(receipt.FieldSpan(7)) != release.LatestWitnessEpoch)
            Invalid("Genesis DCN1 witness epoch is stale.");
        var root = release.CurrentRoot;
        WitnessAuthorityBinding.Verify(
            receipt.FieldSpan(8), Scalars.UInt64(receipt.FieldSpan(9)),
            receipt.FieldSpan(10), receipt.FieldSpan(11), receipt.FieldSpan(12)[0],
            receipt.FieldSpan(13), release.LatestDwdReference, root.CurrentGeneration,
            CanonicalGrammar.EncodeReference(root.CurrentTransitionReference), new byte[38],
            expectedTerminalState: false, release.CurrentReleaseRootAuthorityHead.Span);
        var witnessId = receipt.FieldSpan(14);
        Equal(witnessId, selectedWitnessId, "DCN1 selected witness ID");
        WitnessDescriptorRelative? descriptor = null;
        foreach (var candidate in release.LatestDelegation.Descriptors)
            if (CanonicalGrammar.FixedEquals(candidate.WitnessId.Span, witnessId))
            {
                descriptor = candidate;
                break;
            }
        if (descriptor is null) Invalid("A genesis DCN1 signer is not current.");
        var previousSize = Scalars.UInt64(receipt.FieldSpan(15));
        var treeSize = Scalars.UInt64(receipt.FieldSpan(17));
        if (treeSize > release.LatestDelegation.Delegation.MaximumTreeSize ||
            previousSize > treeSize ||
            receipt.FieldSpan(26)[0] != (byte)DurabilityClass.FsyncReplicated)
            Invalid("A genesis DCN1 tree or durability scalar is invalid.");
        Span<byte> leafPayload = stackalloc byte[116];
        deploymentSubject.CopyTo(leafPayload);
        receipt.FieldSpan(3).CopyTo(leafPayload.Slice(32));
        dcsRef.CopyTo(leafPayload.Slice(40));
        dctRef.CopyTo(leafPayload.Slice(78));
        WitnessTreeVerifier.VerifyInclusion(
            WitnessTreeVerifier.Leaf(leafPayload),
            Scalars.UInt64(receipt.FieldSpan(19)), treeSize,
            receipt.FieldSpan(21), receipt.FieldSpan(18));
        WitnessTreeVerifier.VerifyConsistency(
            previousSize, receipt.FieldSpan(16), treeSize, receipt.FieldSpan(18),
            receipt.FieldSpan(23), WitnessTreeVerifier.EmptyRoot(
                release.LatestWitnessEpoch, witnessId,
                release.LatestDelegation.Delegation.MaximumTreeSize));
        Window(receipt.FieldSpan(24), receipt.FieldSpan(25), now, ProtocolMagic.DCN1);
        if (verifySignature)
            VerifySignature(receipt.FieldSpan(27), CanonicalGrammar.GetSigningBytes(
                receipt, "Deep/Cutover/V1/witness-receipt"), descriptor!.Ed25519PublicKey.Span);
        return Reference(ArtifactType.Dcn1, receipt);
    }

    private static void Window(
        ReadOnlySpan<byte> issued,
        ReadOnlySpan<byte> expires,
        ulong now,
        string name)
    {
        var issuedAt = Scalars.UInt64(issued); var expiresAt = Scalars.UInt64(expires);
        if (issuedAt == 0 || expiresAt <= issuedAt || now < issuedAt || now >= expiresAt)
            throw new RecordException(RecordError.Expired, $"{name} is outside its live window.");
    }

    private static void VerifySignature(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> publicKey)
    {
        try
        {
            if (!PublicKeyAuth.VerifyDetached(
                    signature.ToArray(), message.ToArray(), publicKey.ToArray()))
                throw new RecordException(
                    RecordError.InvalidSignature, "A genesis witness signature is invalid.");
        }
        catch (CryptographicException exception)
        {
            throw new RecordException(RecordError.InvalidSignature, exception.Message);
        }
    }

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string name)
    {
        if (!CanonicalGrammar.FixedEquals(actual, expected)) Invalid($"The {name} differs.");
    }

    private static byte[] Reference(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);

    private sealed class FrozenPendingProvider(GenesisQuorumPendingReadResult value)
        : GenesisQuorumStateProvider
    {
        public override ValueTask<GenesisQuorumPendingReadResult> RestoreOrCreatePendingAsync(
            GenesisQuorumPendingRequest request,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public override ValueTask<GenesisQuorumPendingReadResult> RestorePendingByScopeAsync(
            GenesisQuorumPendingLookupRequest request,
            CancellationToken cancellationToken) => ValueTask.FromResult(value);
    }
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<GenesisQuorumPending> RestoreOrCreateGenesisQuorumPendingAsync(
        GenesisPreExternalCandidatePlan plan,
        GenesisReleaseContext release,
        IReadOnlyList<ReadOnlyMemory<byte>> selectedWitnessIds,
        GenesisQuorumStateProvider provider,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default) =>
        await GenesisQuorumStateVerifier.RestoreOrCreatePendingAsync(
            plan, release, selectedWitnessIds, provider, hmacProvider, cancellationToken)
            .ConfigureAwait(false);

    public static async ValueTask<GenesisVerifiedQuorumPlan> VerifyAndCompleteGenesisQuorumAsync(
        GenesisPreExternalCandidatePlan plan,
        GenesisReleaseContext release,
        GenesisQuorumPending pending,
        GenesisVerifiedQuorumReceipt verifiedDcq,
        ulong nowUnixSeconds,
        GenesisQuorumStateProvider provider,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default) =>
        await GenesisQuorumStateVerifier.VerifyAndCompleteAsync(
            plan, release, pending, verifiedDcq, nowUnixSeconds,
            provider, hmacProvider, cancellationToken).ConfigureAwait(false);

    public static async ValueTask<GenesisQuorumPending> RestoreGenesisQuorumPendingByScopeAsync(
        VerifiedGenesisArtifactSet artifactSet,
        GenesisIdentityContext identity,
        GenesisReleaseContext release,
        GenesisQuorumStateProvider provider,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default) =>
        await GenesisQuorumStateVerifier.RestorePendingByScopeAsync(
            artifactSet, identity, release, provider, hmacProvider, cancellationToken)
            .ConfigureAwait(false);
}
