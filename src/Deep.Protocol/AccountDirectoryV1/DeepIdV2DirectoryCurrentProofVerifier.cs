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

    private VerifiedDeepIdV2DirectoryQuery(ParsedAdl1V2 adl1,
        ReadOnlySpan<byte> directoryLeafKey)
    {
        networkId = adl1.NetworkId.ToArray();
        leaf = directoryLeafKey.ToArray();
        MinimumAdhGeneration = adl1.MinimumAdhGeneration;
        minimumAdhHash = adl1.MinimumAdhHash.ToArray();
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> DirectoryLeafKey => leaf.ToArray();
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
        return new VerifiedDeepIdV2DirectoryQuery(adl1, leaf);
    }
}

/// <summary>
/// Non-forgeable, nonce-bound DID2 directory result. The positive closure is
/// currently limited to exact generation-zero account/binding/checkpoint
/// admissions. Direct signed successor heads (including new genesis leaves)
/// are accepted with append consistency; beyond-horizon forward checkpoints
/// still fail closed.
/// </summary>
public sealed class VerifiedDeepIdV2DirectoryFreshness
{
    private readonly byte[] exactAdh1;
    private readonly byte[] exactDtt1;
    private readonly byte[] exactAdp1;
    private readonly byte[] networkId;
    private readonly byte[] queriedLeaf;
    private readonly byte[] bootId;

    internal VerifiedDeepIdV2DirectoryFreshness(
        ReadOnlySpan<byte> exactAdh1, ReadOnlySpan<byte> exactDtt1,
        ReadOnlySpan<byte> exactAdp1, ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> queriedLeaf,
        AccountDirectoryMonotonicRequestWindow monotonic,
        ulong freshnessDeadlineMonotonicSeconds,
        AccountDirectoryAdp1ResultKind resultKind,
        VerifiedAdc1V2? currentCheckpoint)
    {
        this.exactAdh1 = exactAdh1.ToArray();
        this.exactDtt1 = exactDtt1.ToArray();
        this.exactAdp1 = exactAdp1.ToArray();
        this.networkId = networkId.ToArray();
        this.queriedLeaf = queriedLeaf.ToArray();
        bootId = monotonic.BootId.ToArray();
        MonotonicSample = monotonic.CurrentSample;
        FreshnessDeadlineMonotonicSeconds = freshnessDeadlineMonotonicSeconds;
        ResultKind = resultKind;
        CurrentCheckpoint = currentCheckpoint;
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
    public ulong MonotonicSample { get; }
    public ulong FreshnessDeadlineMonotonicSeconds { get; }

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
            VerifyHistory(authority, proof, head, headHash, protectedLkg);
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
                        queriedDirectoryLeafKey))
                    Fail("CurrentValueMismatch", "Verified ADC1 V2 leaf differs from the requested DID2 leaf.");
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
                proof.ResultKind, current);
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
        ReadOnlySpan<byte> headHash,
        AccountDirectoryProtectedLkg? lkg)
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
