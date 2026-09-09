using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryFreshnessVerificationException : CryptographicException
{
    internal AccountDirectoryFreshnessVerificationException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Caller-measured monotonic timestamps for one nonce-bound DTT1 request.
/// Values are elapsed seconds from one boot-specific monotonic clock.
/// </summary>
public sealed class AccountDirectoryMonotonicRequestWindow
{
    private readonly byte[] bootId;

    public AccountDirectoryMonotonicRequestWindow(
        ReadOnlySpan<byte> bootId,
        ulong nonceCreatedAt,
        ulong responseReceivedAt,
        ulong currentSample)
    {
        if (bootId.Length != 16 || bootId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The monotonic boot ID must be exactly 16 non-zero bytes.", nameof(bootId));
        if (responseReceivedAt < nonceCreatedAt || currentSample < responseReceivedAt)
            throw new ArgumentException("Monotonic request samples are not ordered.");
        this.bootId = bootId.ToArray();
        NonceCreatedAt = nonceCreatedAt;
        ResponseReceivedAt = responseReceivedAt;
        CurrentSample = currentSample;
    }

    public ReadOnlyMemory<byte> BootId => bootId.ToArray();
    public ulong NonceCreatedAt { get; }
    public ulong ResponseReceivedAt { get; }
    public ulong CurrentSample { get; }
}

/// <summary>
/// Exact, locally protected account-directory head used as a rollback floor.
/// Instances are emitted only by successful protocol verification. Persisted
/// reconstruction requires the protected-state integration boundary; arbitrary
/// caller-supplied ADH1 bytes cannot create this capability.
/// </summary>
public sealed class AccountDirectoryProtectedLkg
{
    private readonly byte[] exactAdh1;
    private readonly byte[] coreHash;

    internal AccountDirectoryProtectedLkg(ReadOnlySpan<byte> exactAdh1)
    {
        this.exactAdh1 = exactAdh1.ToArray();
        Head = AccountDirectoryAdh1Codec.Decode(this.exactAdh1);
        coreHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(Head);
    }

    public ReadOnlyMemory<byte> ExactAdh1 => exactAdh1.ToArray();
    public AccountDirectoryAdh1 Head { get; }
    public ReadOnlyMemory<byte> CoreHash => coreHash.ToArray();
    public ulong LogGeneration => Head.LogGeneration;
    public ulong TreeSize => Head.TreeSize;
    public ReadOnlyMemory<byte> AppendLogMerkleRoot => Head.AppendLogMerkleRoot;
    public ReadOnlyMemory<byte> CurrentValueMapRoot => Head.CurrentValueMapRoot;
    public ReadOnlyMemory<byte> AuthorityCoreReference => Head.ExactXnaAuthorityCoreReference;
}

/// <summary>
/// Non-forgeable result of the production ADH1/DTT1/ADP1 verifier. It proves
/// that one exact lookup result is current at a nonce-bound monotonic sample.
/// </summary>
public sealed class VerifiedAccountDirectoryFreshness
{
    private readonly byte[] networkId;
    private readonly byte[] exactAdh1;
    private readonly byte[] exactAdh1CoreHash;
    private readonly byte[] exactAdh1CoreReference;
    private readonly byte[] exactDtt1;
    private readonly byte[] exactDtt1CoreHash;
    private readonly byte[] exactAdp1;
    private readonly byte[] exactAdp1Hash;
    private readonly byte[] directoryLeafKey;
    private readonly byte[] exactAdc1Reference;
    private readonly byte[] bootId;

    internal VerifiedAccountDirectoryFreshness(
        ReadOnlySpan<byte> exactAdh1,
        AccountDirectoryAdh1 head,
        ReadOnlySpan<byte> adhCoreHash,
        ReadOnlySpan<byte> exactDtt1,
        ReadOnlySpan<byte> dttCoreHash,
        ReadOnlySpan<byte> exactAdp1,
        ReadOnlySpan<byte> adpHash,
        AccountDirectoryAdp1 proof,
        ReadOnlySpan<byte> exactAdc1Reference,
        ulong trustedLowerUnixSeconds,
        ulong trustedUpperUnixSeconds,
        AccountDirectoryMonotonicRequestWindow monotonic,
        ulong freshnessDeadlineMonotonicSeconds,
        VerifiedAccountDirectoryCheckpoint? currentCheckpoint)
    {
        networkId = head.NetworkId.ToArray();
        this.exactAdh1 = exactAdh1.ToArray();
        exactAdh1CoreHash = adhCoreHash.ToArray();
        exactAdh1CoreReference = AccountDirectoryCrypto.CreateReference(ProtocolMagicBytes.ADH1, 1, adhCoreHash);
        this.exactDtt1 = exactDtt1.ToArray();
        exactDtt1CoreHash = dttCoreHash.ToArray();
        this.exactAdp1 = exactAdp1.ToArray();
        exactAdp1Hash = adpHash.ToArray();
        directoryLeafKey = proof.QueriedDirectoryLeafKey.ToArray();
        this.exactAdc1Reference = exactAdc1Reference.ToArray();
        bootId = monotonic.BootId.ToArray();
        ResultKind = proof.ResultKind;
        AdhGeneration = head.LogGeneration;
        TreeSize = head.TreeSize;
        ValidFromUnixSeconds = head.ValidFrom;
        ExpiresAtUnixSeconds = head.ValidUntil;
        TrustedLowerUnixSeconds = trustedLowerUnixSeconds;
        TrustedUpperUnixSeconds = trustedUpperUnixSeconds;
        MonotonicSample = monotonic.CurrentSample;
        FreshnessDeadlineMonotonicSeconds = freshnessDeadlineMonotonicSeconds;
        CurrentCheckpoint = currentCheckpoint;
        NextProtectedLkg = new AccountDirectoryProtectedLkg(exactAdh1);
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> ExactAdh1 => exactAdh1.ToArray();
    public ReadOnlyMemory<byte> ExactAdh1CoreHash => exactAdh1CoreHash.ToArray();
    public ReadOnlyMemory<byte> ExactAdh1CoreReference => exactAdh1CoreReference.ToArray();
    public ulong AdhGeneration { get; }
    public ulong TreeSize { get; }
    public ulong ValidFromUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> ExactDtt1 => exactDtt1.ToArray();
    public ReadOnlyMemory<byte> ExactDtt1CoreHash => exactDtt1CoreHash.ToArray();
    public ReadOnlyMemory<byte> ExactAdp1 => exactAdp1.ToArray();
    public ReadOnlyMemory<byte> ExactAdp1Hash => exactAdp1Hash.ToArray();
    public ReadOnlyMemory<byte> DirectoryLeafKey => directoryLeafKey.ToArray();
    public AccountDirectoryAdp1ResultKind ResultKind { get; }
    public ReadOnlyMemory<byte> ExactAdc1Reference => exactAdc1Reference.ToArray();
    public VerifiedAccountDirectoryCheckpoint? CurrentCheckpoint { get; }
    public ulong TrustedLowerUnixSeconds { get; }
    public ulong TrustedUpperUnixSeconds { get; }
    public ReadOnlyMemory<byte> BootId => bootId.ToArray();
    public ulong MonotonicSample { get; }
    public ulong FreshnessDeadlineMonotonicSeconds { get; }
    public AccountDirectoryProtectedLkg NextProtectedLkg { get; }

    public bool IsCurrentAtMonotonic(ReadOnlySpan<byte> currentBootId, ulong currentSample) =>
        currentBootId.Length == bootId.Length &&
        CryptographicOperations.FixedTimeEquals(currentBootId, bootId) &&
        currentSample >= MonotonicSample &&
        currentSample < FreshnessDeadlineMonotonicSeconds;
}

public static class AccountDirectoryCurrentProofVerifier
{
    public const ulong MaximumNonceRoundTripSeconds = 30;
    public const ulong RevocationFreshnessTtlSeconds = 86_400;
    private const ulong ArtifactBoundaryToleranceSeconds = 600;

    public static VerifiedAccountDirectoryFreshness Verify(
        VerifiedXPointNetworkAuthority authority,
        ReadOnlyMemory<byte> exactAdh1,
        ReadOnlyMemory<byte> exactDtt1,
        ReadOnlyMemory<byte> exactAdp1,
        ReadOnlySpan<byte> callerNonce,
        ReadOnlySpan<byte> queriedDirectoryLeafKey,
        AccountDirectoryMonotonicRequestWindow monotonic,
        AccountDirectoryProtectedLkg? protectedLkg,
        VerifiedAccountDirectoryCheckpoint? currentCheckpoint,
        ushort supportedReader)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(monotonic);
        if (supportedReader == 0)
            Fail("UnsupportedReader", "The supported account-directory reader must be non-zero.");
        if (callerNonce.Length != 32 || callerNonce.IndexOfAnyExcept((byte)0) < 0)
            Fail("InvalidNonce", "The caller nonce must be exactly 32 non-zero bytes.");
        if (queriedDirectoryLeafKey.Length != 32 || queriedDirectoryLeafKey.IndexOfAnyExcept((byte)0) < 0)
            Fail("InvalidQuery", "The queried directory leaf key must be exactly 32 non-zero bytes.");

        var adhBytes = Own(exactAdh1, ProtocolMagic.ADH1);
        var dttBytes = Own(exactDtt1, ProtocolMagic.DTT1);
        var adpBytes = Own(exactAdp1, ProtocolMagic.ADP1);
        var nonce = callerNonce.ToArray();
        var query = queriedDirectoryLeafKey.ToArray();

        try
        {
            var head = AccountDirectoryAdh1Codec.Decode(adhBytes);
            var dtt = AccountDirectoryDtt1Codec.Decode(dttBytes);
            var proof = AccountDirectoryAdp1Codec.Decode(adpBytes);
            var adhHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
            var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);

            VerifyAdhAuthorityAndWitnessClosure(authority, head, requireCurrentAuthority: true);
            VerifyAuthorityClosure(authority, head, dtt, adhHash, dttHash);
            VerifyWitnessThreshold(authority, dtt.Witnesses, AccountDirectoryCrypto.ComputeDtt1SigningInput(dtt), ProtocolMagic.DTT1);

            var (lower, upper) = VerifyLiveTime(dtt, nonce, monotonic);
            VerifyCurrentHeadTime(head, lower, upper);
            if (head.MinimumReader > supportedReader)
                Fail("UnsupportedReader", "ADH1 requires a newer reader.");

            if (!FixedEquals(proof.NetworkId.Span, authority.NetworkId.Span) ||
                !FixedEquals(proof.QueriedDirectoryLeafKey.Span, query) ||
                !FixedEquals(AccountDirectoryAdh1Codec.Encode(proof.Head), adhBytes) ||
                !FixedEquals(proof.LiveDtt1CoreHash.Span, dttHash))
                Fail("AdpCrossLinkMismatch", "ADP1 does not bind the exact network, query, ADH1 and DTT1 inputs.");

            VerifyHistory(authority, proof, head, adhHash, dttHash, protectedLkg, upper, supportedReader);
            var adcReference = VerifyResultClosure(proof, query, currentCheckpoint, upper, supportedReader);

            var remaining = head.ValidUntil > upper ? head.ValidUntil - upper : 0;
            var ttl = Math.Min(RevocationFreshnessTtlSeconds, remaining);
            ulong deadline;
            try { deadline = checked(monotonic.CurrentSample + ttl); }
            catch (OverflowException) { deadline = ulong.MaxValue; }
            if (deadline <= monotonic.CurrentSample)
                Fail("AdhNotCurrent", "ADH1 has no remaining currentness at the trusted interval.");

            var adpHash = AccountDirectoryCrypto.Sha256Domain(
                "Deep/Application/V1/record-hash/ADP1", adpBytes);
            return new VerifiedAccountDirectoryFreshness(
                adhBytes, head, adhHash, dttBytes, dttHash, adpBytes, adpHash, proof,
                adcReference, lower, upper, monotonic, deadline, currentCheckpoint);
        }
        catch (AccountDirectoryFreshnessVerificationException)
        {
            throw;
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or CryptographicException)
        {
            throw new AccountDirectoryFreshnessVerificationException(
                "InvalidAccountDirectoryProof", exception.Message, exception);
        }
    }

    internal static AccountDirectoryProtectedLkg RestoreProtectedLkg(
        VerifiedXPointNetworkAuthority authority,
        ReadOnlyMemory<byte> exactPersistedAdh1,
        ReadOnlySpan<byte> expectedAdh1CoreHash)
    {
        ArgumentNullException.ThrowIfNull(authority);
        if (expectedAdh1CoreHash.Length != 32 || expectedAdh1CoreHash.IndexOfAnyExcept((byte)0) < 0)
            Fail("InvalidPersistedLkgHash", "The protected LKG expected core hash must be exactly 32 non-zero bytes.");
        var exact = Own(exactPersistedAdh1, "persisted ADH1");
        try
        {
            var head = AccountDirectoryAdh1Codec.Decode(exact);
            if (!FixedEquals(AccountDirectoryAdh1Codec.Encode(head), exact))
                Fail("NonCanonicalPersistedLkg", "The protected LKG ADH1 bytes are not canonical.");
            var actualHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
            if (!FixedEquals(actualHash, expectedAdh1CoreHash))
                Fail("PersistedLkgHashMismatch", "The protected LKG ADH1 differs from its expected protected core hash.");
            VerifyAdhAuthorityAndWitnessClosure(authority, head, requireCurrentAuthority: false);
            return new AccountDirectoryProtectedLkg(exact);
        }
        catch (AccountDirectoryFreshnessVerificationException)
        {
            throw;
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or CryptographicException)
        {
            throw new AccountDirectoryFreshnessVerificationException(
                "InvalidPersistedLkg", exception.Message, exception);
        }
    }

    private static void VerifyAdhAuthorityAndWitnessClosure(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryAdh1 head,
        bool requireCurrentAuthority)
    {
        if (!FixedEquals(head.NetworkId.Span, authority.NetworkId.Span))
            Fail("NetworkMismatch", "ADH1 and the verified XPoint authority networks differ.");
        var authorizing = FindAuthority(authority, head.ExactXnaAuthorityCoreReference.Span);
        if (authorizing is null || requireCurrentAuthority
            && !FixedEquals(authorizing.CoreHash.Span, authority.AuthorityCoreHash.Span))
            Fail("AuthorityMismatch", "ADH1 names an authority outside the required verified XNA1 lineage position.");
        if (!FixedEquals(head.WitnessPolicyHash.Span, authorizing.DirectoryWitnessPolicyHash.Span))
            Fail("WitnessPolicyMismatch", "ADH1 names a different directory witness policy.");
        if (head.ValidFrom < authorizing.NotBefore || head.ValidUntil > authorizing.ExpiresAt)
            Fail("AuthorityTimeMismatch", "ADH1 validity lies outside its authorizing XNA1 interval.");
        VerifyAdhWitnessThreshold(authorizing, head,
            unknownWitnessCode: "UnknownWitness", invalidSignatureCode: "InvalidWitnessSignature",
            thresholdCode: "WrongWitnessThreshold");
    }

    private static void VerifyAuthorityClosure(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryAdh1 head,
        AccountDirectoryDtt1 dtt,
        ReadOnlySpan<byte> adhHash,
        ReadOnlySpan<byte> dttHash)
    {
        if (!FixedEquals(dtt.NetworkId.Span, authority.NetworkId.Span))
            Fail("NetworkMismatch", "DTT1 and the verified XPoint authority networks differ.");
        if (!FixedEquals(dtt.AuthorizingXna1CoreReference.Span, authority.AuthorityCoreReference.Span))
            Fail("AuthorityMismatch", "DTT1 names a different XNA1 authority core.");
        if (!FixedEquals(dtt.WitnessPolicyHash.Span, authority.DirectoryWitnessPolicyHash.Span))
            Fail("WitnessPolicyMismatch", "DTT1 names a different witness policy.");
        if (!FixedEquals(dtt.CurrentAdh1CoreHash.Span, adhHash) ||
            dtt.CurrentAdh1Generation != head.LogGeneration)
            Fail("DttHeadMismatch", "DTT1 does not attest the exact supplied ADH1 head.");
        if (dtt.UncertaintySeconds > authority.MaximumWitnessUncertaintySeconds)
            Fail("DttUncertaintyExceeded", "DTT1 uncertainty exceeds the exact XNA1 policy.");
        if (dtt.IssuedAt < authority.NotBefore || dtt.ExpiresAt > authority.ExpiresAt ||
            dtt.IssuedAt < authority.Dts1NotBefore || dtt.ExpiresAt > authority.Dts1ExpiresAt)
            Fail("AuthorityTimeMismatch", "ADH1 or DTT1 lies outside its exact XNA1/DTS1 authority interval.");
        var issuanceEpoch = AccountDirectoryDtt1IssuanceEpoch.Derive(
            authority, dtt.ObservedUnixTime, dtt.UncertaintySeconds);
        if (!FixedEquals(dtt.IssuanceEpochId.Span, issuanceEpoch.Id.Span))
            Fail("IssuanceEpochMismatch", "DTT1 names a different authority-bound issuance epoch.");
        if (dttHash.Length != 32)
            Fail("DttHashMismatch", "DTT1 core hash is invalid.");
    }

    private static void VerifyWitnessThreshold(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<AccountDirectoryDtt1WitnessReceipt> receipts,
        ReadOnlySpan<byte> signingInput,
        string magic)
    {
        VerifyWitnessThresholdCore(authority.WitnessThreshold,
            authority.WitnessKeys.Select(static key =>
                (key.Id, key.Ed25519PublicKey, key.FailureDomainHash)),
            receipts.Select(static receipt => (receipt.WitnessId, receipt.Signature)),
            signingInput, magic, "UnknownWitness", "InvalidWitnessSignature", "WrongWitnessThreshold");
    }

    private static void VerifyWitnessThresholdCore(
        byte threshold,
        IEnumerable<(ReadOnlyMemory<byte> Id, ReadOnlyMemory<byte> PublicKey, ReadOnlyMemory<byte> FailureDomain)> keys,
        IEnumerable<(ReadOnlyMemory<byte> Id, ReadOnlyMemory<byte> Signature)> receipts,
        ReadOnlySpan<byte> signingInput,
        string magic,
        string unknownWitnessCode,
        string invalidSignatureCode,
        string thresholdCode)
    {
        var available = keys.ToArray();
        var valid = 0;
        var domains = new HashSet<string>(StringComparer.Ordinal);
        foreach (var receipt in receipts)
        {
            var keyIndex = Array.FindIndex(available, candidate =>
                candidate.Id.Span.SequenceEqual(receipt.Id.Span));
            if (keyIndex < 0)
                Fail(unknownWitnessCode, $"{magic} contains a signer outside the exact XNA1 witness set.");
            var key = available[keyIndex];
            bool verified;
            try
            {
                verified = PublicKeyAuth.VerifyDetached(
                    receipt.Signature.ToArray(), signingInput.ToArray(), key.PublicKey.ToArray());
            }
            catch (Exception)
            {
                verified = false;
            }
            if (!verified)
                Fail(invalidSignatureCode, $"{magic} contains an invalid Ed25519 witness signature.");
            domains.Add(Convert.ToHexString(key.FailureDomain.Span));
            valid++;
        }
        if (valid < threshold || domains.Count < threshold)
            Fail(thresholdCode, $"{magic} does not meet the exact XNA1 witness threshold.");
    }

    private static (ulong Lower, ulong Upper) VerifyLiveTime(
        AccountDirectoryDtt1 dtt,
        ReadOnlySpan<byte> nonce,
        AccountDirectoryMonotonicRequestWindow monotonic)
    {
        if (!FixedEquals(dtt.ClientNonce.Span, nonce))
            Fail("NonceMismatch", "DTT1 does not bind the caller's exact live nonce.");
        if (monotonic.ResponseReceivedAt - monotonic.NonceCreatedAt > MaximumNonceRoundTripSeconds)
            Fail("NonceWindowExpired", "The DTT1 response arrived after the 30-second monotonic deadline.");

        var lower = dtt.ObservedUnixTime >= dtt.UncertaintySeconds
            ? dtt.ObservedUnixTime - dtt.UncertaintySeconds
            : 0;
        ulong upper;
        try { upper = checked(dtt.ObservedUnixTime + dtt.UncertaintySeconds); }
        catch (OverflowException) { Fail("InvalidDttInterval", "DTT1 time interval overflows."); throw; }
        if (dtt.IssuedAt < lower || dtt.IssuedAt > upper || upper > dtt.ExpiresAt)
            Fail("InvalidDttInterval", "DTT1 is future-dated or already expired at its signed observation.");

        var elapsed = monotonic.CurrentSample - monotonic.ResponseReceivedAt;
        try
        {
            lower = checked(lower + elapsed);
            upper = checked(upper + elapsed);
        }
        catch (OverflowException)
        {
            Fail("InvalidDttInterval", "Advancing DTT1 by the trusted monotonic elapsed time overflows.");
        }
        if (upper > dtt.ExpiresAt)
            Fail("DttExpired", "DTT1 expired before the caller's current monotonic sample.");
        return (lower, upper);
    }

    private static void VerifyCurrentHeadTime(AccountDirectoryAdh1 head, ulong lower, ulong upper)
    {
        var toleratedFrom = head.ValidFrom > ArtifactBoundaryToleranceSeconds
            ? head.ValidFrom - ArtifactBoundaryToleranceSeconds
            : 0;
        var toleratedUntil = head.ValidUntil > ulong.MaxValue - ArtifactBoundaryToleranceSeconds
            ? ulong.MaxValue
            : head.ValidUntil + ArtifactBoundaryToleranceSeconds;
        if (lower < toleratedFrom || upper > toleratedUntil)
            Fail("AdhTimeMismatch", "The authenticated time interval lies outside ADH1 validity bounds.");
        if (lower < head.ValidFrom || upper >= head.ValidUntil)
            Fail("AdhNotCurrent", "ADH1 is not current for the complete authenticated time interval.");
    }

    private static void VerifyHistory(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryAdp1 proof,
        AccountDirectoryAdh1 head,
        ReadOnlySpan<byte> headHash,
        ReadOnlySpan<byte> dttHash,
        AccountDirectoryProtectedLkg? lkg,
        ulong trustedUpper,
        ushort supportedReader)
    {
        if (lkg is null)
        {
            if (proof.HasLkg || proof.HistoryMode != AccountDirectoryAdp1HistoryMode.ConsistencyOrGenesis ||
                proof.ConsistencyProofNodes.Count != 0)
                Fail("UnexpectedLkg", "A proof without protected LKG must use the exact no-LKG genesis mode.");
            return;
        }

        if (!proof.HasLkg || proof.CallerLkgTreeSize != lkg.TreeSize ||
            !FixedEquals(proof.CallerLkgAdh1CoreHash.Span, lkg.CoreHash.Span) ||
            !FixedEquals(lkg.Head.NetworkId.Span, authority.NetworkId.Span))
            Fail("LkgMismatch", "ADP1 does not bind the caller's exact protected LKG tuple.");
        if (FindAuthority(authority, lkg.AuthorityCoreReference.Span) is null)
            Fail("LkgAuthorityMismatch", "The protected LKG authority is outside the verified XNA1 lineage.");

        if (proof.HistoryMode == AccountDirectoryAdp1HistoryMode.ForwardCheckpoint)
        {
            VerifyForwardCheckpoint(authority, proof, head, headHash, dttHash, lkg, trustedUpper, supportedReader);
            return;
        }

        if (head.LogGeneration < lkg.LogGeneration || head.TreeSize < lkg.TreeSize)
            Fail("LkgRollback", "ADH1 rolls back the protected generation or tree size.");
        if (head.LogGeneration == lkg.LogGeneration)
        {
            if (!FixedEquals(headHash, lkg.CoreHash.Span))
                Fail("DirectoryFork", "A changed ADH1 exists at the protected generation.");
        }
        else
        {
            if (lkg.LogGeneration == ulong.MaxValue || head.LogGeneration != lkg.LogGeneration + 1 ||
                !FixedEquals(head.PredecessorAdh1CoreHash.Span, lkg.CoreHash.Span))
                Fail("ForwardCheckpointRequired", "A non-successor ADH1 requires a root-authorized forward checkpoint.");
            if (head.TreeSize == lkg.TreeSize &&
                (!FixedEquals(head.AppendLogMerkleRoot.Span, lkg.AppendLogMerkleRoot.Span) ||
                 !FixedEquals(head.CurrentValueMapRoot.Span, lkg.CurrentValueMapRoot.Span)))
                Fail("DirectoryFork", "An empty ADH1 transition changed a committed root.");
        }

        var consistency = Join(proof.ConsistencyProofNodes);
        if (!AccountDirectoryRfc6962.VerifyConsistency(
                lkg.TreeSize, head.TreeSize, lkg.AppendLogMerkleRoot.Span,
                head.AppendLogMerkleRoot.Span, consistency))
            Fail("InvalidConsistencyProof", "ADP1 does not prove append-log consistency from the protected LKG.");
    }

    private static void VerifyForwardCheckpoint(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryAdp1 proof,
        AccountDirectoryAdh1 head,
        ReadOnlySpan<byte> headHash,
        ReadOnlySpan<byte> dttHash,
        AccountDirectoryProtectedLkg lkg,
        ulong trustedUpper,
        ushort supportedReader)
    {
        AccountDirectoryAfp1 afp;
        try { afp = AccountDirectoryAfp1Codec.Decode(proof.ExactAfp1.Span); }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        { throw new AccountDirectoryFreshnessVerificationException("InvalidForwardCheckpoint", exception.Message, exception); }

        if (afp.SourceAdhGeneration != lkg.LogGeneration || afp.SourceTreeSize != lkg.TreeSize ||
            !FixedEquals(afp.SourceAdh1CoreHash.Span, lkg.CoreHash.Span) ||
            !FixedEquals(afp.TargetAdh1CoreHash.Span, headHash) ||
            !FixedEquals(afp.LiveDtt1CoreHash.Span, dttHash) ||
            head.LogGeneration <= lkg.LogGeneration)
            Fail("InvalidForwardCheckpoint", "AFP1 does not bind the exact protected source and current target.");

        var authorityBytes = afp.AuthorityChain;
        var trusted = authority.AuthorityChain;
        var suppliedAuthorities = authorityBytes
            .Select(static bytes => XPointNetworkCodec.Parse<Xna1Record>(bytes.Span))
            .ToArray();
        if (!FixedEquals(suppliedAuthorities[0].CoreHash.Span, lkg.AuthorityCoreReference.Span[6..]))
            Fail("InvalidForwardCheckpoint", "AFP1 does not begin at the protected LKG authority.");
        var start = -1;
        for (var index = 0; index < trusted.Count; index++)
            if (trusted[index].CanonicalSpan.SequenceEqual(authorityBytes[0].Span)) { start = index; break; }
        if (start < 0 || start + authorityBytes.Count > trusted.Count)
            Fail("InvalidForwardCheckpoint", "AFP1 authority chain is outside the verified XNA1 lineage.");
        for (var index = 0; index < authorityBytes.Count; index++)
            if (!trusted[start + index].CanonicalSpan.SequenceEqual(authorityBytes[index].Span))
                Fail("InvalidForwardCheckpoint", "AFP1 skips or substitutes a verified XNA1 authority.");
        if (!FixedEquals(trusted[start + authorityBytes.Count - 1].CoreReferenceValue.Hash.Span,
                authority.AuthorityCoreHash.Span))
            Fail("InvalidForwardCheckpoint", "AFP1 contains an unused or missing authority tail.");

        var exactCheckpoints = afp.CheckpointChain;
        var checkpoints = exactCheckpoints
            .Select(static bytes => AccountDirectoryAdf1Codec.Decode(bytes.Span))
            .ToArray();
        var exactTargetHeads = afp.TargetHeadChain;
        if (exactTargetHeads.Count != checkpoints.Length)
            Fail("InvalidForwardCheckpoint", "AFP1 does not contain one exact target ADH1 per ADF1.");
        var targetHeads = exactTargetHeads
            .Select(static bytes => AccountDirectoryAdh1Codec.Decode(bytes.Span))
            .ToArray();
        if (checkpoints[0].CheckpointGeneration != 0 ||
            checkpoints[0].PredecessorCoreHash.Span.IndexOfAnyExcept((byte)0) >= 0)
            Fail("InvalidForwardCheckpoint", "AFP1 omits the generation-zero start of the complete ADF1 chain.");

        var firstCheckpoint = checkpoints[0];
        if (lkg.LogGeneration < firstCheckpoint.CoveredFirstAdhGeneration ||
            lkg.LogGeneration > firstCheckpoint.CoveredLastAdhGeneration ||
            afp.SourceLeafIndex >= firstCheckpoint.CoveredHeadCount)
            Fail("InvalidForwardCheckpoint", "The protected LKG tuple is outside the first ADF1 covered set.");
        var sourceLeaf = ComputeCoveredHeadLeaf(
            lkg.LogGeneration, lkg.TreeSize, lkg.CoreHash.Span);
        if (!AccountDirectoryRfc6962.VerifyInclusion(
                sourceLeaf, afp.SourceLeafIndex, firstCheckpoint.CoveredHeadCount,
                Join(afp.MembershipNodes), firstCheckpoint.CoveredHeadMerkleRoot.Span))
            Fail("InvalidForwardCheckpoint", "AFP1 does not prove membership of the exact protected LKG tuple.");

        AccountDirectoryAdf1? previous = null;
        var previousAuthorityIndex = -1;
        var targetReferences = new HashSet<string>(StringComparer.Ordinal);
        for (var checkpointIndex = 0; checkpointIndex < checkpoints.Length; checkpointIndex++)
        {
            var adf = checkpoints[checkpointIndex];
            var targetHead = targetHeads[checkpointIndex];
            if (previous is not null &&
                (previous.CheckpointGeneration == ulong.MaxValue ||
                 adf.CheckpointGeneration != previous.CheckpointGeneration + 1 ||
                 !FixedEquals(adf.PredecessorCoreHash.Span,
                     AccountDirectoryCrypto.ComputeAdf1CoreHash(previous))))
                Fail("InvalidForwardCheckpoint", "AFP1 omits, reorders or substitutes an ADF1 predecessor.");

            var authorityIndex = FindAuthorityIndex(suppliedAuthorities, adf.AuthorityXnaCoreReference.Span);
            if (authorityIndex < 0 || authorityIndex < previousAuthorityIndex)
                Fail("InvalidForwardCheckpoint", "ADF1 authorities are absent from or move backwards in the exact XNA1 lineage.");
            var authorizing = suppliedAuthorities[authorityIndex];
            if (adf.MinimumReader > supportedReader || adf.IssuedAt < authorizing.NotBefore ||
                adf.IssuedAt > authorizing.ExpiresAt || adf.IssuedAt > trustedUpper)
                Fail("InvalidForwardCheckpoint", "ADF1 reader or authority-time closure is invalid.");
            VerifyRootThreshold(authorizing, adf);

            var targetHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(targetHead);
            if (!FixedEquals(targetHead.NetworkId.Span, authority.NetworkId.Span) ||
                !FixedEquals(adf.TargetAdh1CoreReference.Span,
                    AccountDirectoryCrypto.CreateReference(ProtocolMagicBytes.ADH1, 1, targetHash)) ||
                adf.TargetTreeSize != targetHead.TreeSize ||
                !FixedEquals(adf.TargetAppendLogRoot.Span, targetHead.AppendLogMerkleRoot.Span) ||
                !FixedEquals(adf.TargetCurrentValueMapRoot.Span, targetHead.CurrentValueMapRoot.Span) ||
                !FixedEquals(adf.AuthorityXnaCoreReference.Span, targetHead.ExactXnaAuthorityCoreReference.Span) ||
                !FixedEquals(targetHead.WitnessPolicyHash.Span, authorizing.DirectoryWitnessPolicyHash.Span) ||
                targetHead.LogGeneration <= adf.CoveredLastAdhGeneration ||
                targetHead.MinimumReader > supportedReader ||
                targetHead.ValidFrom < authorizing.NotBefore || targetHead.ValidUntil > authorizing.ExpiresAt ||
                adf.IssuedAt < targetHead.ValidFrom || adf.IssuedAt >= targetHead.ValidUntil)
                Fail("InvalidForwardCheckpoint", "ADF1 does not bind one exact threshold-valid target ADH1 envelope.");
            VerifyAdhWitnessThreshold(authorizing, targetHead);

            var targetKey = Convert.ToHexString(adf.TargetAdh1CoreReference.Span);
            if (!targetReferences.Add(targetKey))
                Fail("InvalidForwardCheckpoint", "AFP1 contains a redundant or cyclic ADF1 target.");
            if (checkpointIndex != checkpoints.Length - 1 && FixedEquals(adf.TargetAdh1CoreReference.Span[6..], headHash))
                Fail("InvalidForwardCheckpoint", "AFP1 contains ADF1 records after the current target was already reached.");

            previous = adf;
            previousAuthorityIndex = authorityIndex;
        }

        var final = checkpoints[^1];
        var expectedTargetReference = AccountDirectoryCrypto.CreateReference(ProtocolMagicBytes.ADH1, 1, headHash);
        if (!FixedEquals(final.TargetAdh1CoreReference.Span, expectedTargetReference) ||
            final.TargetTreeSize != head.TreeSize ||
            !FixedEquals(final.TargetAppendLogRoot.Span, head.AppendLogMerkleRoot.Span) ||
            !FixedEquals(final.TargetCurrentValueMapRoot.Span, head.CurrentValueMapRoot.Span) ||
            !FixedEquals(final.AuthorityXnaCoreReference.Span, head.ExactXnaAuthorityCoreReference.Span) ||
            head.LogGeneration <= final.CoveredLastAdhGeneration ||
            previousAuthorityIndex != suppliedAuthorities.Length - 1 ||
            !FixedEquals(exactTargetHeads[^1].Span, AccountDirectoryAdh1Codec.Encode(head)))
            Fail("InvalidForwardCheckpoint", "The final ADF1 does not close the exact newer threshold-valid ADH1 target.");
    }

    private static void VerifyAdhWitnessThreshold(Xna1Record authority, AccountDirectoryAdh1 head,
        string unknownWitnessCode = "InvalidForwardCheckpoint",
        string invalidSignatureCode = "InvalidForwardCheckpoint",
        string thresholdCode = "InvalidForwardCheckpoint")
    {
        VerifyWitnessThresholdCore(authority.WitnessThreshold,
            authority.Witnesses.Select(static key =>
                ((ReadOnlyMemory<byte>)key.Id.ToArray(),
                 (ReadOnlyMemory<byte>)key.PublicKey.ToArray(),
                 (ReadOnlyMemory<byte>)key.FailureDomainHash.ToArray())),
            head.Witnesses.Select(static receipt => (receipt.WitnessId, receipt.Signature)),
            AccountDirectoryCrypto.ComputeAdh1SigningInput(head), ProtocolMagic.ADH1,
            unknownWitnessCode, invalidSignatureCode, thresholdCode);
    }

    private static int FindAuthorityIndex(
        IReadOnlyList<Xna1Record> authorities,
        ReadOnlySpan<byte> reference)
    {
        if (reference.Length != 38 || !reference[..4].SequenceEqual(ProtocolMagicBytes.XNA1) ||
            BinaryPrimitives.ReadUInt16BigEndian(reference[4..]) != 1)
            return -1;
        for (var index = 0; index < authorities.Count; index++)
            if (FixedEquals(authorities[index].CoreHash.Span, reference[6..])) return index;
        return -1;
    }

    private static byte[] ComputeCoveredHeadLeaf(
        ulong generation,
        ulong treeSize,
        ReadOnlySpan<byte> exactAdh1CoreHash)
    {
        if (exactAdh1CoreHash.Length != 32)
            Fail("InvalidForwardCheckpoint", "The protected ADH1 core hash has the wrong length.");
        Span<byte> preimage = stackalloc byte[49];
        preimage[0] = 0;
        BinaryPrimitives.WriteUInt64BigEndian(preimage[1..9], generation);
        BinaryPrimitives.WriteUInt64BigEndian(preimage[9..17], treeSize);
        exactAdh1CoreHash.CopyTo(preimage[17..]);
        return SHA256.HashData(preimage);
    }

    private static Xna1Record? FindAuthority(
        VerifiedXPointNetworkAuthority verified,
        ReadOnlySpan<byte> reference)
    {
        if (reference.Length != 38 || !reference[..4].SequenceEqual(ProtocolMagicBytes.XNA1) ||
            reference[4] != 0 || reference[5] != 1)
            return null;
        foreach (var candidate in verified.AuthorityChain)
            if (FixedEquals(candidate.CoreHash.Span, reference[6..])) return candidate;
        return null;
    }

    private static void VerifyRootThreshold(Xna1Record authority, AccountDirectoryAdf1 checkpoint)
    {
        var signingInput = AccountDirectoryCrypto.ComputeAdf1SigningInput(checkpoint);
        var valid = 0;
        foreach (var receipt in checkpoint.Receipts)
        {
            XPointRootKeyEntry? key = null;
            foreach (var candidate in authority.RootKeys)
                if (candidate.Id.Span.SequenceEqual(receipt.RootKeyId.Span)) { key = candidate; break; }
            if (key is null)
                Fail("InvalidForwardCheckpoint", "ADF1 contains a root signer outside its exact XNA1 authority.");
            bool verified;
            try
            {
                verified = PublicKeyAuth.VerifyDetached(
                    receipt.Signature.ToArray(), signingInput, key.PublicKey.ToArray());
            }
            catch (Exception)
            {
                verified = false;
            }
            if (!verified)
                Fail("InvalidForwardCheckpoint", "ADF1 contains an invalid root signature.");
            valid++;
        }
        if (valid < authority.RootThreshold)
            Fail("InvalidForwardCheckpoint", "ADF1 does not meet its exact XNA1 root threshold.");
    }

    private static byte[] VerifyResultClosure(
        AccountDirectoryAdp1 proof,
        ReadOnlySpan<byte> query,
        VerifiedAccountDirectoryCheckpoint? checkpoint,
        ulong trustedUpper,
        ushort supportedReader)
    {
        if (proof.ResultKind == AccountDirectoryAdp1ResultKind.NonMembership)
        {
            if (checkpoint is not null || proof.CurrentValue is not null)
                Fail("ResultKindMismatch", "NonMembership cannot carry a current ADC1 capability.");
            return [];
        }
        if (checkpoint is null || proof.CurrentValue is null)
            Fail("MissingCurrentCheckpoint", "CurrentValue requires the exact verified ADC1 artifact closure.");

        var current = proof.CurrentValue;
        var identity = checkpoint.Binding.Identity;
        if (!ReferenceEquals(identity, checkpoint.Directory.Identity) ||
            !FixedEquals(checkpoint.Checkpoint.DirectoryLeafKey.Span, query) ||
            !FixedEquals(AccountDirectoryAdc1Codec.Encode(current.Adc1),
                AccountDirectoryAdc1Codec.Encode(checkpoint.Checkpoint)) ||
            !FixedEquals(current.Dab1.CanonicalBytes.Span, checkpoint.Binding.Record.CanonicalBytes.Span) ||
            !FixedEquals(current.Dmd1.CanonicalBytes.Span, checkpoint.Directory.Record.CanonicalBytes.Span) ||
            !FixedEquals(current.Dpa1.CanonicalBytes.Span, identity.Account.Certificate.CanonicalBytes.Span) ||
            !FixedEquals(current.Drs1.CanonicalBytes.Span, identity.Revocations.Snapshot.CanonicalBytes.Span) ||
            !FixedEquals(current.ExactDid1Hash.Span, checkpoint.Binding.DeepId.RecordHash.Span) ||
            !FixedEquals(current.Did1AddressPublicKey.Span, checkpoint.Binding.DeepId.AddressPublicKey.Span))
            Fail("AdcSubstitution", "ADP1 CurrentValue differs from the exact verified ADC1 identity closure.");

        var active = identity.ActiveDevices.OrderBy(static device => device.Certificate.DeviceId.ToArray(), ByteArrayComparer.Instance).ToArray();
        if (active.Length != current.ExactDpd1Records.Count)
            Fail("AdcSubstitution", "ADP1 omits or adds an active DPD1 certificate.");
        for (var index = 0; index < active.Length; index++)
            if (!FixedEquals(active[index].Certificate.CanonicalBytes.Span, current.ExactDpd1Records[index].Span))
                Fail("AdcSubstitution", "ADP1 substitutes an active DPD1 certificate.");

        if (checkpoint.Checkpoint.MinimumReader > supportedReader || checkpoint.Checkpoint.IssuedAt > trustedUpper)
            Fail("AdcNotCurrent", "The exact ADC1 requires a newer reader or is future-dated.");
        return AccountDirectoryCrypto.CreateReference(
            ProtocolMagicBytes.ADC1, 1, AccountDirectoryCrypto.ComputeAdc1ArtifactHash(checkpoint.Checkpoint));
    }

    private static byte[] Join(IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        var result = new byte[checked(values.Count * 32)];
        for (var index = 0; index < values.Count; index++)
            values[index].Span.CopyTo(result.AsSpan(index * 32, 32));
        return result;
    }

    private static byte[] Own(ReadOnlyMemory<byte> value, string magic)
    {
        if (value.IsEmpty)
            Fail("InvalidAccountDirectoryProof", $"The exact {magic} input is empty.");
        return value.ToArray();
    }

    private static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new AccountDirectoryFreshnessVerificationException(code, message);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
