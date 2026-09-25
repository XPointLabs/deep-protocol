using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// A DID2 lookup leaf bound to an independently verified DAB2 identity and
/// one exact protected directory floor. ADL1 parsing alone cannot mint it.
/// </summary>
public sealed class VerifiedDeepIdV2DirectoryQuery
{
    private readonly byte[] networkId;
    private readonly byte[] leaf;
    private readonly byte[] minimumAdhHash;
    private readonly byte[] exactDid2;

    private VerifiedDeepIdV2DirectoryQuery(ParsedAdl1V2 adl1,
        ReadOnlySpan<byte> directoryLeafKey, ParsedDid2 did2)
    {
        networkId = adl1.NetworkId.ToArray();
        leaf = directoryLeafKey.ToArray();
        exactDid2 = did2.CanonicalBytes.ToArray();
        MinimumAdhGeneration = adl1.MinimumAdhGeneration;
        minimumAdhHash = adl1.MinimumAdhHash.ToArray();
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> DirectoryLeafKey => leaf.ToArray();
    public ReadOnlyMemory<byte> ExactDid2 => exactDid2.ToArray();
    public ulong MinimumAdhGeneration { get; }
    public ReadOnlyMemory<byte> MinimumAdhHash => minimumAdhHash.ToArray();

    public static VerifiedDeepIdV2DirectoryQuery VerifyBinding(
        ParsedAdl1V2 adl1, VerifiedDab2 trustedBinding)
    {
        ArgumentNullException.ThrowIfNull(adl1);
        ArgumentNullException.ThrowIfNull(trustedBinding);
        var accountNetwork = trustedBinding.Identity.Account.Certificate.NetworkId.Span;
        if (adl1.NetworkId.Length != accountNetwork.Length ||
            !CryptographicOperations.FixedTimeEquals(adl1.NetworkId.Span,
                accountNetwork))
            throw new AccountDirectoryFreshnessVerificationException(
                "QueryNetworkMismatch",
                "DID2 ADL1 network differs from the verified account network.");
        var leaf = DeepIdV2AccountDirectoryLookupCodec
            .VerifyAndGetDirectoryLeafKey(adl1, trustedBinding);
        return new VerifiedDeepIdV2DirectoryQuery(adl1, leaf,
            trustedBinding.DeepId);
    }

    public static VerifiedDeepIdV2DirectoryQuery VerifyDid2(
        ParsedAdl1V2 adl1, ParsedDid2 requestedDid2)
    {
        ArgumentNullException.ThrowIfNull(adl1);
        ArgumentNullException.ThrowIfNull(requestedDid2);
        var leaf = DeepIdV2AccountDirectoryLookupCodec.MatchExactDid2(
            adl1, requestedDid2);
        return new VerifiedDeepIdV2DirectoryQuery(adl1, leaf,
            requestedDid2);
    }
}

/// <summary>
/// Non-forgeable, nonce-bound DID2 directory result. The positive closure is
/// limited to exact generation-zero account/binding/checkpoint admissions.
/// Direct signed successors and root-authorized forward checkpoint chains are
/// accepted only with the protected-floor and append consistency proofs.
/// </summary>
public sealed class VerifiedDeepIdV2DirectoryFreshness
{
    private readonly byte[] exactAdh1;
    private readonly byte[] exactDtt1;
    private readonly byte[] exactAdp1;
    private readonly byte[] networkId;
    private readonly byte[] queriedLeaf;
    private readonly byte[] bootId;
    private readonly byte[] verifiedProtectedLkgExactAdh1;

    internal VerifiedDeepIdV2DirectoryFreshness(
        ReadOnlySpan<byte> exactAdh1, ReadOnlySpan<byte> exactDtt1,
        ReadOnlySpan<byte> exactAdp1, ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> queriedLeaf,
        AccountDirectoryMonotonicRequestWindow monotonic,
        ulong freshnessDeadlineMonotonicSeconds,
        ulong trustedLowerUnixSeconds,
        ulong trustedUpperUnixSeconds,
        AccountDirectoryAdp1ResultKind resultKind,
        VerifiedAdc1V2? currentCheckpoint,
        bool hasRootAuthorizedForwardLineage,
        AccountDirectoryProtectedLkg? verifiedProtectedLkg)
    {
        this.exactAdh1 = exactAdh1.ToArray();
        this.exactDtt1 = exactDtt1.ToArray();
        this.exactAdp1 = exactAdp1.ToArray();
        this.networkId = networkId.ToArray();
        this.queriedLeaf = queriedLeaf.ToArray();
        verifiedProtectedLkgExactAdh1 = verifiedProtectedLkg?.ExactAdh1.ToArray()
            ?? [];
        bootId = monotonic.BootId.ToArray();
        MonotonicSample = monotonic.CurrentSample;
        FreshnessDeadlineMonotonicSeconds = freshnessDeadlineMonotonicSeconds;
        TrustedLowerUnixSeconds = trustedLowerUnixSeconds;
        TrustedUpperUnixSeconds = trustedUpperUnixSeconds;
        ResultKind = resultKind;
        CurrentCheckpoint = currentCheckpoint;
        HasRootAuthorizedForwardLineage = hasRootAuthorizedForwardLineage;
        NextProtectedLkg = new AccountDirectoryProtectedLkg(exactAdh1);
    }

    public ReadOnlyMemory<byte> ExactAdh1 => exactAdh1.ToArray();
    public ReadOnlyMemory<byte> ExactDtt1 => exactDtt1.ToArray();
    public ReadOnlyMemory<byte> ExactAdp1V2 => exactAdp1.ToArray();
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> QueriedDirectoryLeafKey => queriedLeaf.ToArray();
    public AccountDirectoryAdp1ResultKind ResultKind { get; }
    public VerifiedAdc1V2? CurrentCheckpoint { get; }
    public AccountDirectoryProtectedLkg NextProtectedLkg { get; }
    public bool HasRootAuthorizedForwardLineage { get; }
    public ReadOnlyMemory<byte> VerifiedProtectedLkgExactAdh1 =>
        verifiedProtectedLkgExactAdh1.ToArray();
    public ulong MonotonicSample { get; }
    public ulong FreshnessDeadlineMonotonicSeconds { get; }
    public ulong TrustedLowerUnixSeconds { get; }
    public ulong TrustedUpperUnixSeconds { get; }

    public bool IsCurrentAtMonotonic(ReadOnlySpan<byte> currentBootId,
        ulong currentSample) =>
        currentBootId.Length == bootId.Length &&
        CryptographicOperations.FixedTimeEquals(currentBootId, bootId) &&
        currentSample >= MonotonicSample &&
        currentSample < FreshnessDeadlineMonotonicSeconds;
}

/// <summary>
/// Public DID2-only ADH1/DTT1/ADP1 V2 verification. It shares only the
/// identity-neutral witness/time primitives with the pre-cutover reader;
/// ADP1 V1 and DID1/DAB1 are never decoded or accepted here.
/// </summary>
public static class DeepIdV2DirectoryCurrentProofVerifier
{
    public static VerifiedDeepIdV2DirectoryFreshness VerifyGenesis(
        VerifiedXPointNetworkAuthority authority,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlyMemory<byte> exactDtt1,
        ReadOnlyMemory<byte> exactAdp1V2,
        ReadOnlySpan<byte> callerNonce,
        VerifiedDeepIdV2DirectoryQuery query,
        AccountDirectoryMonotonicRequestWindow monotonic,
        AccountDirectoryProtectedLkg? protectedLkg,
        ushort deploymentProfileId, ushort supportedReader,
        IDeepMlDsa65Verifier mlDsa65)
    {
        ArgumentNullException.ThrowIfNull(query);
        return VerifyCore(authority, exactAdh1, exactDtt1, exactAdp1V2,
            callerNonce, query.DirectoryLeafKey.Span, monotonic, protectedLkg,
            deploymentProfileId, supportedReader, mlDsa65, query);
    }

    public static VerifiedDeepIdV2DirectoryFreshness VerifyRequestedDid2(
        VerifiedXPointNetworkAuthority authority,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlyMemory<byte> exactDtt1,
        ReadOnlyMemory<byte> exactAdp1V2,
        ReadOnlySpan<byte> callerNonce,
        VerifiedDeepIdV2DirectoryQuery query,
        AccountDirectoryMonotonicRequestWindow monotonic,
        AccountDirectoryProtectedLkg? protectedLkg,
        ushort deploymentProfileId, ushort supportedReader,
        IDeepMlDsa65Verifier mlDsa65)
    {
        ArgumentNullException.ThrowIfNull(query);
        return VerifyCore(authority, exactAdh1, exactDtt1, exactAdp1V2,
            callerNonce, query.DirectoryLeafKey.Span, monotonic,
            protectedLkg, deploymentProfileId, supportedReader, mlDsa65,
            query);
    }

    internal static VerifiedDeepIdV2DirectoryFreshness VerifyExactLeafForAuthor(
        VerifiedXPointNetworkAuthority authority,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlyMemory<byte> exactDtt1,
        ReadOnlyMemory<byte> exactAdp1V2,
        ReadOnlySpan<byte> callerNonce,
        ReadOnlySpan<byte> queriedDirectoryLeafKey,
        AccountDirectoryMonotonicRequestWindow monotonic,
        AccountDirectoryProtectedLkg? protectedLkg,
        ushort deploymentProfileId, ushort supportedReader,
        IDeepMlDsa65Verifier mlDsa65) =>
        VerifyCore(authority, exactAdh1, exactDtt1, exactAdp1V2,
            callerNonce, queriedDirectoryLeafKey, monotonic, protectedLkg,
            deploymentProfileId, supportedReader, mlDsa65, null);

    private static VerifiedDeepIdV2DirectoryFreshness VerifyCore(
        VerifiedXPointNetworkAuthority authority,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlyMemory<byte> exactDtt1,
        ReadOnlyMemory<byte> exactAdp1V2,
        ReadOnlySpan<byte> callerNonce,
        ReadOnlySpan<byte> queriedDirectoryLeafKey,
        AccountDirectoryMonotonicRequestWindow monotonic,
        AccountDirectoryProtectedLkg? protectedLkg,
        ushort deploymentProfileId, ushort supportedReader,
        IDeepMlDsa65Verifier mlDsa65,
        VerifiedDeepIdV2DirectoryQuery? boundQuery)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(monotonic);
        ArgumentNullException.ThrowIfNull(mlDsa65);
        if (supportedReader < 2 || deploymentProfileId == 0)
            throw new ArgumentOutOfRangeException(nameof(supportedReader));
        if (exactAdh1.Length is < 1 or > 4096 ||
            exactDtt1.Length is < 1 or > 65_535 ||
            exactAdp1V2.Length is < 1 or > DeepIdV2Adp1Codec.MaximumLength)
            throw new ArgumentOutOfRangeException(nameof(exactAdp1V2));
        if (callerNonce.Length != 32 ||
            callerNonce.IndexOfAnyExcept((byte)0) < 0 ||
            queriedDirectoryLeafKey.Length != 32 ||
            queriedDirectoryLeafKey.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("DID2 directory nonce and query must be nonzero 32-byte values.");

        try
        {
            var head = AccountDirectoryAdh1Codec.Decode(exactAdh1.Span);
            var dtt = AccountDirectoryDtt1Codec.Decode(exactDtt1.Span);
            var proof = DeepIdV2Adp1Codec.Decode(exactAdp1V2.Span);
            var headHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
            var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);
            if (head.MinimumReader < 2 || head.MinimumReader > supportedReader)
                Fail("UnsupportedReader", "The DID2 head requires reader version two or newer.");
            AccountDirectoryCurrentProofVerifier.VerifyAdhAuthorityAndWitnessClosure(
                authority, head, requireCurrentAuthority: true);
            AccountDirectoryCurrentProofVerifier.VerifyAuthorityClosure(
                authority, head, dtt, headHash, dttHash);
            var signingInput = AccountDirectoryCrypto.ComputeDtt1SigningInput(dtt);
            try
            {
                AccountDirectoryCurrentProofVerifier.VerifyWitnessThreshold(
                    authority, dtt.Witnesses, signingInput, ProtocolMagic.DTT1);
            }
            finally { CryptographicOperations.ZeroMemory(signingInput); }
            var (lower, upper) = AccountDirectoryCurrentProofVerifier.VerifyLiveTime(
                dtt, callerNonce, monotonic);
            AccountDirectoryCurrentProofVerifier.VerifyCurrentHeadTime(
                head, lower, upper);
            if (!Fixed(proof.ExactField(1).Span, authority.NetworkId.Span) ||
                !Fixed(proof.QueriedDirectoryLeafKey.Span,
                    queriedDirectoryLeafKey) ||
                !Fixed(proof.ExactField(4).Span, exactAdh1.Span) ||
                !Fixed(proof.LiveDtt1CoreHash.Span, dttHash))
                Fail("AdpCrossLinkMismatch", "ADP1 V2 does not bind the exact head, query and DTT1.");
            VerifyHistory(authority, proof, head, headHash, dttHash,
                protectedLkg, upper, supportedReader);
            if (boundQuery is not null)
                VerifyQueryFloor(boundQuery, authority, head, headHash,
                    protectedLkg, queriedDirectoryLeafKey);

            VerifiedAdc1V2? current = null;
            if (proof.ResultKind == AccountDirectoryAdp1ResultKind.CurrentValue)
            {
                var admission = new DeepIdV2GenesisAdmissionRequest(
                    proof.ExactField(19).Span, proof.ExactField(20).Span,
                    ExactDevices(proof), proof.ExactDid2.Span,
                    proof.ExactDab2.Span, proof.ExactField(21).Span,
                    proof.ExactCurrentAdc1V2.Span,
                    proof.RevokedDcaAuthorizationIds);
                current = DeepIdV2GenesisAdmissionVerifier.Verify(admission,
                    upper, deploymentProfileId, supportedReader, mlDsa65);
                if (!Fixed(current.Checkpoint.DirectoryLeafKey.Span,
                        queriedDirectoryLeafKey) ||
                    boundQuery is not null && !Fixed(
                        current.Binding.DeepId.CanonicalBytes.Span,
                        boundQuery.ExactDid2.Span))
                    Fail("CurrentValueMismatch", "Verified ADC1 V2 identity differs from the requested DID2.");
            }

            var remaining = head.ValidUntil > upper ? head.ValidUntil - upper : 0;
            var ttl = Math.Min(
                AccountDirectoryCurrentProofVerifier.RevocationFreshnessTtlSeconds,
                remaining);
            ulong deadline;
            try { deadline = checked(monotonic.CurrentSample + ttl); }
            catch (OverflowException) { deadline = ulong.MaxValue; }
            if (deadline <= monotonic.CurrentSample)
                Fail("AdhNotCurrent", "The DID2 directory head has no remaining freshness.");
            return new VerifiedDeepIdV2DirectoryFreshness(exactAdh1.Span,
                exactDtt1.Span, exactAdp1V2.Span, authority.NetworkId.Span,
                queriedDirectoryLeafKey, monotonic, deadline,
                lower, upper, proof.ResultKind, current,
                proof.HistoryMode == AccountDirectoryAdp1HistoryMode.ForwardCheckpoint ||
                (byte)proof.HistoryMode == DeepIdV2ForwardTailCodec.HistoryMode,
                protectedLkg);
        }
        catch (AccountDirectoryFreshnessVerificationException) { throw; }
        catch (Exception exception) when (exception is FormatException or
            ArgumentException or CryptographicException or RecordException or
            OverflowException)
        {
            throw new AccountDirectoryFreshnessVerificationException(
                "InvalidDid2DirectoryProof",
                "The exact DID2 directory proof failed closed.", exception);
        }
    }

    private static void VerifyQueryFloor(
        VerifiedDeepIdV2DirectoryQuery query,
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryAdh1 head, ReadOnlySpan<byte> headHash,
        AccountDirectoryProtectedLkg? lkg,
        ReadOnlySpan<byte> queriedDirectoryLeafKey)
    {
        if (!Fixed(query.NetworkId.Span, authority.NetworkId.Span) ||
            !Fixed(query.DirectoryLeafKey.Span, queriedDirectoryLeafKey))
            Fail("QueryNetworkMismatch", "The DID2 ADL1 query belongs to another network or leaf.");
        if (head.LogGeneration == query.MinimumAdhGeneration &&
            Fixed(headHash, query.MinimumAdhHash.Span))
            return;
        if (lkg is not null &&
            lkg.LogGeneration == query.MinimumAdhGeneration &&
            Fixed(lkg.CoreHash.Span, query.MinimumAdhHash.Span))
            return;
        Fail("QueryFloorMismatch", "The DID2 ADL1 floor is not this head or the exact protected LKG.");
    }

    private static void VerifyHistory(VerifiedXPointNetworkAuthority authority,
        ParsedAdp1V2 proof, AccountDirectoryAdh1 head,
        ReadOnlySpan<byte> headHash, ReadOnlySpan<byte> dttHash,
        AccountDirectoryProtectedLkg? lkg, ulong trustedUpper,
        ushort supportedReader)
    {
        var claimedSize = BinaryPrimitives.ReadUInt64BigEndian(
            proof.ExactField(5).Span);
        var claimedHash = proof.ExactField(6).Span;
        var hasLkg = proof.ExactField(12).Span[0] == 1;
        var consistency = proof.ExactField(8).Span;
        if (lkg is null)
        {
            if (hasLkg || claimedSize != 0 ||
                claimedHash.IndexOfAnyExcept((byte)0) >= 0 ||
                !consistency.IsEmpty)
                Fail("UnexpectedLkg", "ADP1 V2 claims a caller LKG that was not supplied.");
            return;
        }
        if (!hasLkg || lkg.Head.MinimumReader < 2 ||
            claimedSize != lkg.TreeSize ||
            !Fixed(claimedHash, lkg.CoreHash.Span) ||
            !Fixed(lkg.Head.NetworkId.Span, authority.NetworkId.Span))
            Fail("LkgMismatch", "ADP1 V2 does not bind the protected DID2 directory floor.");
        AccountDirectoryCurrentProofVerifier.VerifyAdhAuthorityAndWitnessClosure(
            authority, lkg.Head, requireCurrentAuthority: false);
        if (head.LogGeneration < lkg.LogGeneration ||
            head.TreeSize < lkg.TreeSize)
            Fail("LkgRollback", "ADH1 rolls back the protected DID2 directory floor.");
        if (proof.HistoryMode == AccountDirectoryAdp1HistoryMode.ForwardCheckpoint)
        {
            AccountDirectoryCurrentProofVerifier.VerifyForwardCheckpoint(
                authority, proof.ExactAfp1.Span, head, headHash, dttHash,
                lkg, trustedUpper, supportedReader, minimumReaderFloor: 2);
            return;
        }
        if ((byte)proof.HistoryMode == DeepIdV2ForwardTailCodec.HistoryMode)
        {
            VerifyForwardTail(authority, proof, head, headHash, dttHash,
                lkg, trustedUpper, supportedReader);
            return;
        }
        if (head.LogGeneration == lkg.LogGeneration)
        {
            if (!Fixed(headHash, lkg.CoreHash.Span))
                Fail("DirectoryFork", "A changed DID2 head exists at the protected generation.");
        }
        else if (lkg.LogGeneration == ulong.MaxValue ||
            head.LogGeneration != lkg.LogGeneration + 1 ||
            !Fixed(head.PredecessorAdh1CoreHash.Span, lkg.CoreHash.Span))
            Fail("ForwardCheckpointRequired", "Non-successor DID2 head requires a root-authorized forward checkpoint.");
        if (head.TreeSize == lkg.TreeSize &&
            (!Fixed(head.AppendLogMerkleRoot.Span,
                lkg.AppendLogMerkleRoot.Span) ||
             !Fixed(head.CurrentValueMapRoot.Span,
                lkg.CurrentValueMapRoot.Span)))
            Fail("DirectoryFork", "An empty DID2 head transition changed committed roots.");
        if (!AccountDirectoryRfc6962.VerifyConsistency(lkg.TreeSize,
                head.TreeSize, lkg.AppendLogMerkleRoot.Span,
                head.AppendLogMerkleRoot.Span, consistency))
            Fail("InvalidConsistencyProof", "ADP1 V2 does not prove append-log consistency.");
    }

    private static void VerifyForwardTail(
        VerifiedXPointNetworkAuthority authority,
        ParsedAdp1V2 proof, AccountDirectoryAdh1 currentHead,
        ReadOnlySpan<byte> currentHash, ReadOnlySpan<byte> dttHash,
        AccountDirectoryProtectedLkg lkg, ulong trustedUpper,
        ushort supportedReader)
    {
        var tail = DeepIdV2ForwardTailCodec.Decode(proof.ExactAfp1.Span);
        var anchor = tail.AnchorHead;
        var anchorHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(anchor);
        var chainSource = new AccountDirectoryProtectedLkg(
            tail.ExactChainSourceHead.Span);
        AccountDirectoryCurrentProofVerifier
            .VerifyAdhAuthorityAndWitnessClosure(authority,
                chainSource.Head, requireCurrentAuthority: false);
        AccountDirectoryCurrentProofVerifier.VerifyForwardCheckpoint(
            authority, tail.ExactAnchorAfp1.Span, anchor, anchorHash,
            dttHash, chainSource, trustedUpper, supportedReader,
            minimumReaderFloor: 2);
        var sourceCheckpoint = AccountDirectoryAdf1Codec.Decode(
            tail.AnchorProof.CheckpointChain[tail.SourceCheckpointIndex].Span);
        if (lkg.LogGeneration < sourceCheckpoint.CoveredFirstAdhGeneration ||
            lkg.LogGeneration > sourceCheckpoint.CoveredLastAdhGeneration ||
            lkg.LogGeneration >= anchor.LogGeneration ||
            tail.SourceLeafIndex >= sourceCheckpoint.CoveredHeadCount)
            Fail("InvalidForwardTail", "Protected DID2 floor is outside its root-signed covered set.");
        var sourceLeaf = AccountDirectoryCurrentProofVerifier
            .ComputeCoveredHeadLeaf(lkg.LogGeneration, lkg.TreeSize,
                lkg.CoreHash.Span);
        if (!AccountDirectoryRfc6962.VerifyInclusion(sourceLeaf,
                tail.SourceLeafIndex, sourceCheckpoint.CoveredHeadCount,
                AccountDirectoryCurrentProofVerifier.Join(
                    tail.SourceMembershipNodes),
                sourceCheckpoint.CoveredHeadMerkleRoot.Span))
            Fail("InvalidForwardTail", "Protected DID2 floor is not a member of its root-signed checkpoint.");
        var previous = anchor;
        var previousHash = anchorHash;
        foreach (var exact in tail.ExactTailHeads)
        {
            var next = AccountDirectoryAdh1Codec.Decode(exact.Span);
            if (next.MinimumReader < 2 ||
                next.MinimumReader > supportedReader ||
                next.ValidFrom > trustedUpper ||
                previous.LogGeneration == ulong.MaxValue ||
                next.LogGeneration != previous.LogGeneration + 1 ||
                next.TreeSize < previous.TreeSize ||
                !Fixed(next.PredecessorAdh1CoreHash.Span, previousHash) ||
                next.TreeSize == previous.TreeSize &&
                    (!Fixed(next.AppendLogMerkleRoot.Span,
                        previous.AppendLogMerkleRoot.Span) ||
                     !Fixed(next.CurrentValueMapRoot.Span,
                        previous.CurrentValueMapRoot.Span)))
                Fail("InvalidForwardTail", "DID2 successor tail is not an exact monotonic ADH1 lineage.");
            AccountDirectoryCurrentProofVerifier
                .VerifyAdhAuthorityAndWitnessClosure(authority, next,
                    requireCurrentAuthority: false);
            previous = next;
            previousHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(next);
        }
        if (!Fixed(previousHash, currentHash) ||
            !Fixed(AccountDirectoryAdh1Codec.Encode(previous),
                AccountDirectoryAdh1Codec.Encode(currentHead)))
            Fail("InvalidForwardTail", "DID2 successor tail does not end at the current DTT1 head.");
        if (!AccountDirectoryRfc6962.VerifyConsistency(anchor.TreeSize,
                currentHead.TreeSize, anchor.AppendLogMerkleRoot.Span,
                currentHead.AppendLogMerkleRoot.Span,
                proof.ExactField(8).Span))
            Fail("InvalidForwardTail", "DID2 successor tail does not preserve the anchored append log.");
    }

    private static ReadOnlyMemory<byte>[] ExactDevices(ParsedAdp1V2 proof)
    {
        var count = proof.ExactField(22).Span[0];
        var packed = proof.ExactField(23).Span;
        var records = new ReadOnlyMemory<byte>[count];
        var offset = 0;
        for (var index = 0; index < count; index++)
        {
            if (packed.Length - offset < 4 ||
                BinaryPrimitives.ReadUInt32BigEndian(packed[offset..]) != 776 ||
                packed.Length - offset - 4 < 776)
                Fail("InvalidDpdList", "ADP1 V2 DPD1 list is malformed.");
            offset += 4;
            records[index] = packed.Slice(offset, 776).ToArray();
            offset += 776;
        }
        if (offset != packed.Length)
            Fail("InvalidDpdList", "ADP1 V2 DPD1 list has trailing bytes.");
        return records;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new AccountDirectoryFreshnessVerificationException(code, message);
}
