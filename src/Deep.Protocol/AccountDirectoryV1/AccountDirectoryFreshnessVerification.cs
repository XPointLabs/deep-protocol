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
/// Identity-neutral, verifier-minted ADH1/DTT1 time evidence consumed by the
/// XPoint network closure. It exposes no account, contact or message authority.
/// </summary>
internal interface IVerifiedDirectoryNetworkTime
{
    ReadOnlyMemory<byte> NetworkId { get; }
    ReadOnlyMemory<byte> ExactAdh1CoreReference { get; }
    ReadOnlyMemory<byte> ExactDtt1 { get; }
    ReadOnlyMemory<byte> ExactDtt1CoreHash { get; }
    ReadOnlyMemory<byte> BootId { get; }
    ulong ValidFromUnixSeconds { get; }
    ulong ExpiresAtUnixSeconds { get; }
    ulong TrustedLowerUnixSeconds { get; }
    ulong TrustedUpperUnixSeconds { get; }
    ulong MonotonicSample { get; }
    ulong FreshnessDeadlineMonotonicSeconds { get; }
    bool IsCurrentAtMonotonic(ReadOnlySpan<byte> currentBootId,
        ulong currentSample);
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

public static class AccountDirectoryCurrentProofVerifier
{
    public const ulong MaximumNonceRoundTripSeconds = 30;
    public const ulong RevocationFreshnessTtlSeconds = 86_400;
    private const ulong ArtifactBoundaryToleranceSeconds = 600;

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

    internal static void VerifyAdhAuthorityAndWitnessClosure(
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

    internal static void VerifyAuthorityClosure(
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

    internal static void VerifyWitnessThreshold(
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

    internal static (ulong Lower, ulong Upper) VerifyLiveTime(
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

    internal static void VerifyCurrentHeadTime(AccountDirectoryAdh1 head, ulong lower, ulong upper)
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

    internal static void VerifyForwardCheckpoint(
        VerifiedXPointNetworkAuthority authority,
        ReadOnlySpan<byte> exactAfp1,
        AccountDirectoryAdh1 head,
        ReadOnlySpan<byte> headHash,
        ReadOnlySpan<byte> dttHash,
        AccountDirectoryProtectedLkg lkg,
        ulong trustedUpper,
        ushort supportedReader,
        ushort minimumReaderFloor = 1)
    {
        AccountDirectoryAfp1 afp;
        try { afp = AccountDirectoryAfp1Codec.Decode(exactAfp1); }
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
            if (adf.MinimumReader < minimumReaderFloor ||
                adf.MinimumReader > supportedReader ||
                targetHead.MinimumReader < minimumReaderFloor ||
                adf.IssuedAt < authorizing.NotBefore ||
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

    internal static byte[] ComputeCoveredHeadLeaf(
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

    internal static byte[] Join(IReadOnlyList<ReadOnlyMemory<byte>> values)
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
