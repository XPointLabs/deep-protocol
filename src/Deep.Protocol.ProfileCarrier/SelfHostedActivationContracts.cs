using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Protocol.DeepExtension.SelfHostedProfiles;

public static class SelfHostedActivationContract
{
    public const string Identifier = "Deep.Protocol/SelfHostedActivation-v1";
    public const int HashLength = 32;
    public const int AccountGenerationLength = 32;
    public const int ConsentIdLength = 32;
}

public sealed class VerifiedSelfHostedSignerDescriptor
{
    private readonly byte[] signerId;
    private readonly byte[] publicKey;

    internal VerifiedSelfHostedSignerDescriptor(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey)
    {
        this.signerId = signerId.ToArray();
        this.publicKey = publicKey.ToArray();
    }

    public ReadOnlyMemory<byte> SignerId => signerId.ToArray();

    public ReadOnlyMemory<byte> PublicKey => publicKey.ToArray();

    public override string ToString() => nameof(VerifiedSelfHostedSignerDescriptor);
}

public sealed class VerifiedSelfHostedDelegationDescriptor
{
    private readonly byte[] statementCommitmentSha256;
    private readonly VerifiedSelfHostedSignerDescriptor[] onlineSigners;

    internal VerifiedSelfHostedDelegationDescriptor(
        ulong sequence,
        ReadOnlySpan<byte> statementCommitmentSha256,
        ulong validFromUnixSeconds,
        ulong validUntilUnixSeconds,
        ushort minimumProtocol,
        ushort maximumProtocol,
        ushort onlineThreshold,
        IEnumerable<VerifiedSelfHostedSignerDescriptor> onlineSigners)
    {
        Sequence = sequence;
        this.statementCommitmentSha256 = statementCommitmentSha256.ToArray();
        ValidFromUnixSeconds = validFromUnixSeconds;
        ValidUntilUnixSeconds = validUntilUnixSeconds;
        MinimumProtocol = minimumProtocol;
        MaximumProtocol = maximumProtocol;
        OnlineThreshold = onlineThreshold;
        this.onlineSigners = onlineSigners
            .Select(static signer => new VerifiedSelfHostedSignerDescriptor(
                signer.SignerId.Span,
                signer.PublicKey.Span))
            .ToArray();
    }

    public ulong Sequence { get; }

    public ReadOnlyMemory<byte> StatementCommitmentSha256 =>
        statementCommitmentSha256.ToArray();

    public ulong ValidFromUnixSeconds { get; }

    public ulong ValidUntilUnixSeconds { get; }

    public ushort MinimumProtocol { get; }

    public ushort MaximumProtocol { get; }

    public ushort OnlineThreshold { get; }

    public IReadOnlyList<VerifiedSelfHostedSignerDescriptor> OnlineSigners =>
        onlineSigners
            .Select(static signer => new VerifiedSelfHostedSignerDescriptor(
                signer.SignerId.Span,
                signer.PublicKey.Span))
            .ToArray();

    internal IReadOnlyList<VerifiedSelfHostedSignerDescriptor> SignerValues => onlineSigners;

    public override string ToString() => nameof(VerifiedSelfHostedDelegationDescriptor);
}

public sealed class VerifiedSelfHostedContactDescriptor
{
    private readonly byte[] entryId;

    internal VerifiedSelfHostedContactDescriptor(
        ReadOnlySpan<byte> entryId,
        string contact)
    {
        this.entryId = entryId.ToArray();
        Contact = contact;
    }

    public ReadOnlyMemory<byte> EntryId => entryId.ToArray();

    public string Contact { get; }

    public override string ToString() => nameof(VerifiedSelfHostedContactDescriptor);
}

public sealed class VerifiedSelfHostedActivationDescriptor
{
    private readonly byte[] exactDpfSha256;
    private readonly byte[] networkId;
    private readonly byte[] genesisFingerprintSha256;
    private readonly byte[] latestBridgeSha256;
    private readonly VerifiedSelfHostedContactDescriptor[] orderedContacts;

    internal VerifiedSelfHostedActivationDescriptor(
        ReadOnlySpan<byte> exactDpfSha256,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> genesisFingerprintSha256,
        ushort minimumProtocol,
        ushort maximumProtocol,
        VerifiedSelfHostedDelegationDescriptor latestVerifiedDelegation,
        ulong latestBridgeSequence,
        ReadOnlySpan<byte> latestBridgeSha256,
        IEnumerable<VerifiedSelfHostedContactDescriptor> orderedContacts)
    {
        this.exactDpfSha256 = exactDpfSha256.ToArray();
        this.networkId = networkId.ToArray();
        this.genesisFingerprintSha256 = genesisFingerprintSha256.ToArray();
        MinimumProtocol = minimumProtocol;
        MaximumProtocol = maximumProtocol;
        LatestVerifiedDelegation = new VerifiedSelfHostedDelegationDescriptor(
            latestVerifiedDelegation.Sequence,
            latestVerifiedDelegation.StatementCommitmentSha256.Span,
            latestVerifiedDelegation.ValidFromUnixSeconds,
            latestVerifiedDelegation.ValidUntilUnixSeconds,
            latestVerifiedDelegation.MinimumProtocol,
            latestVerifiedDelegation.MaximumProtocol,
            latestVerifiedDelegation.OnlineThreshold,
            latestVerifiedDelegation.OnlineSigners);
        LatestBridgeSequence = latestBridgeSequence;
        this.latestBridgeSha256 = latestBridgeSha256.ToArray();
        this.orderedContacts = orderedContacts
            .Select(static contact => new VerifiedSelfHostedContactDescriptor(
                contact.EntryId.Span,
                contact.Contact))
            .ToArray();
    }

    public ReadOnlyMemory<byte> ExactDpfSha256 => exactDpfSha256.ToArray();

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();

    public ReadOnlyMemory<byte> GenesisFingerprintSha256 =>
        genesisFingerprintSha256.ToArray();

    public ushort MinimumProtocol { get; }

    public ushort MaximumProtocol { get; }

    public VerifiedSelfHostedDelegationDescriptor LatestVerifiedDelegation { get; }

    public ulong LatestBridgeSequence { get; }

    public ReadOnlyMemory<byte> LatestBridgeSha256 => latestBridgeSha256.ToArray();

    public IReadOnlyList<VerifiedSelfHostedContactDescriptor> OrderedContacts =>
        orderedContacts
            .Select(static contact => new VerifiedSelfHostedContactDescriptor(
                contact.EntryId.Span,
                contact.Contact))
            .ToArray();

    public override string ToString() => "[verified-self-hosted-activation]";
}

internal static class SelfHostedActivationDescriptorVerifier
{
    public static VerifiedSelfHostedActivationDescriptor VerifyExact(
        ReadOnlySpan<byte> exactDpfPayload,
        ProfileCarrierVerificationOptions options,
        IMembershipSignatureVerifier verifier)
    {
        var frozen = FreezeExactDpf(exactDpfPayload);
        return VerifyFrozenExact(frozen, options, verifier);
    }

    internal static byte[] FreezeExactDpf(ReadOnlySpan<byte> exactDpfPayload)
    {
        if (exactDpfPayload.Length > ProfileCarrierLimits.MaximumFilePayloadBytes)
        {
            throw ProfileCarrierErrors.Bounds();
        }
        return exactDpfPayload.ToArray();
    }

    internal static VerifiedSelfHostedActivationDescriptor VerifyFrozenExact(
        byte[] frozenDpfPayload,
        ProfileCarrierVerificationOptions options,
        IMembershipSignatureVerifier verifier)
    {
        var generic = ProfileCarrierVerifier.VerifyExact(frozenDpfPayload, options, verifier);
        var components = ProfileCarrierFraming.Decode(frozenDpfPayload);
        if (components.Count < 4)
        {
            throw ProfileCarrierErrors.Framing();
        }

        var genesis = MembershipContractCodec.DecodeGenesis(components[0].Bytes);
        var delegation = MembershipContractCodec.DecodeSignedDelegation(components[2].Bytes);
        var latestBridge = MembershipContractCodec.DecodeSignedBridge(components[^1].Bytes);
        var dpfHash = SHA256.HashData(frozenDpfPayload);
        var genesisHash = MembershipContractHash.Sha256(components[0].Bytes);
        var delegationCommitment = MembershipContractHash.Sha256(
            MembershipContractCodec.GetDelegationSigningBytes(delegation));
        var bridgeHash = MembershipContractHash.Sha256(
            MembershipContractCodec.GetBridgeSigningBytes(latestBridge.Statement));
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    dpfHash,
                    generic.FilePayloadSha256.Span) ||
                !CryptographicOperations.FixedTimeEquals(
                    genesisHash,
                    ParseFingerprint(generic.Fingerprint)) ||
                !CryptographicOperations.FixedTimeEquals(
                    genesis.NetworkId.Span,
                    delegation.NetworkId.Span) ||
                !CryptographicOperations.FixedTimeEquals(
                    genesis.NetworkId.Span,
                    latestBridge.Statement.NetworkId.Span))
            {
                throw ProfileCarrierErrors.Verification();
            }

            var signers = delegation.OnlineSigners
                .OrderBy(static signer => signer.SignerId, SelfHostedByteMemoryComparer.Instance)
                .Select(static signer => new VerifiedSelfHostedSignerDescriptor(
                    signer.SignerId.Span,
                    signer.PublicKey.Span))
                .ToArray();
            var contacts = latestBridge.Statement.EntryContacts
                .OrderBy(static contact => contact.EntryId, SelfHostedByteMemoryComparer.Instance)
                .Select(static contact => new VerifiedSelfHostedContactDescriptor(
                    contact.EntryId.Span,
                    contact.Contact))
                .ToArray();
            var verifiedDelegation = new VerifiedSelfHostedDelegationDescriptor(
                delegation.Sequence,
                delegationCommitment,
                delegation.ValidFromUnixSeconds,
                delegation.ValidUntilUnixSeconds,
                delegation.MinimumProtocol,
                delegation.MaximumProtocol,
                genesis.Policy.OnlineThreshold,
                signers);
            return new VerifiedSelfHostedActivationDescriptor(
                dpfHash,
                genesis.NetworkId.Span,
                genesisHash,
                generic.MinimumProtocol,
                generic.MaximumProtocol,
                verifiedDelegation,
                latestBridge.Statement.Sequence,
                bridgeHash,
                contacts);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dpfHash);
            CryptographicOperations.ZeroMemory(genesisHash);
            CryptographicOperations.ZeroMemory(delegationCommitment);
            CryptographicOperations.ZeroMemory(bridgeHash);
        }
    }

    private static byte[] ParseFingerprint(string fingerprint)
    {
        const string prefix = "sha256:";
        if (!fingerprint.StartsWith(prefix, StringComparison.Ordinal) ||
            fingerprint.Length != prefix.Length + SelfHostedActivationContract.HashLength * 2)
        {
            throw ProfileCarrierErrors.Verification();
        }
        return Convert.FromHexString(fingerprint[prefix.Length..]);
    }
}

public sealed class SelfHostedSwitchConsent
{
    private readonly byte[] consentId;
    private readonly byte[] currentAccountGeneration;
    private readonly byte[] expectedCandidateDpfSha256;
    private readonly byte[] expectedCandidateGenesisSha256;

    public SelfHostedSwitchConsent(
        ReadOnlySpan<byte> consentId,
        ReadOnlySpan<byte> currentAccountGeneration,
        ReadOnlySpan<byte> expectedCandidateDpfSha256,
        ReadOnlySpan<byte> expectedCandidateGenesisSha256)
    {
        this.consentId = ExactNonzero(
            consentId,
            SelfHostedActivationContract.ConsentIdLength,
            nameof(consentId));
        this.currentAccountGeneration = ExactNonzero(
            currentAccountGeneration,
            SelfHostedActivationContract.AccountGenerationLength,
            nameof(currentAccountGeneration));
        this.expectedCandidateDpfSha256 = ExactNonzero(
            expectedCandidateDpfSha256,
            SelfHostedActivationContract.HashLength,
            nameof(expectedCandidateDpfSha256));
        this.expectedCandidateGenesisSha256 = ExactNonzero(
            expectedCandidateGenesisSha256,
            SelfHostedActivationContract.HashLength,
            nameof(expectedCandidateGenesisSha256));
    }

    public ReadOnlyMemory<byte> ConsentId => consentId.ToArray();

    public ReadOnlyMemory<byte> CurrentAccountGeneration => currentAccountGeneration.ToArray();

    public ReadOnlyMemory<byte> ExpectedCandidateDpfSha256 =>
        expectedCandidateDpfSha256.ToArray();

    public ReadOnlyMemory<byte> ExpectedCandidateGenesisSha256 =>
        expectedCandidateGenesisSha256.ToArray();

    private static byte[] ExactNonzero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("Self-hosted consent field is invalid.", name);
        }
        return value.ToArray();
    }
}

public enum SelfHostedActivationCommitKind
{
    Initial = 1,
    SameGenesisForward = 2,
    NetworkSwitch = 3,
    Idempotent = 4
}

public sealed class SelfHostedActivationCommit
{
    private readonly byte[] currentAccountGeneration;
    private readonly byte[] candidateExactDpf;

    internal SelfHostedActivationCommit(
        SelfHostedActivationCommitKind kind,
        ReadOnlySpan<byte> currentAccountGeneration,
        SelfHostedActivationLastKnownGood? expectedCurrent,
        ReadOnlySpan<byte> candidateExactDpf,
        VerifiedSelfHostedActivationDescriptor candidate,
        SelfHostedSwitchConsent? consent)
    {
        Kind = kind;
        this.currentAccountGeneration = currentAccountGeneration.ToArray();
        ExpectedCurrent = expectedCurrent;
        this.candidateExactDpf = candidateExactDpf.ToArray();
        CandidateLastKnownGood = new SelfHostedActivationLastKnownGood(
            currentAccountGeneration,
            candidate.ExactDpfSha256.Span,
            candidate.GenesisFingerprintSha256.Span,
            candidate.LatestBridgeSequence,
            candidate.LatestBridgeSha256.Span);
        Consent = consent;
    }

    public SelfHostedActivationCommitKind Kind { get; }
    public ReadOnlyMemory<byte> CurrentAccountGeneration => currentAccountGeneration.ToArray();
    public SelfHostedActivationLastKnownGood? ExpectedCurrent { get; }
    public ReadOnlyMemory<byte> CandidateExactDpf => candidateExactDpf.ToArray();
    public SelfHostedActivationLastKnownGood CandidateLastKnownGood { get; }
    public SelfHostedSwitchConsent? Consent { get; }
}

public interface ISelfHostedActivationCommitter
{
    ValueTask<bool> TryCommitAsync(
        SelfHostedActivationCommit commit,
        CancellationToken cancellationToken);
}

public sealed class SelfHostedActivationLastKnownGood
{
    private readonly byte[] accountGeneration;
    private readonly byte[] exactDpfSha256;
    private readonly byte[] genesisFingerprintSha256;
    private readonly byte[] latestBridgeSha256;

    public SelfHostedActivationLastKnownGood(
        ReadOnlySpan<byte> accountGeneration,
        ReadOnlySpan<byte> exactDpfSha256,
        ReadOnlySpan<byte> genesisFingerprintSha256,
        ulong latestBridgeSequence,
        ReadOnlySpan<byte> latestBridgeSha256)
    {
        this.accountGeneration = Copy(accountGeneration, SelfHostedActivationContract.AccountGenerationLength);
        this.exactDpfSha256 = Copy(exactDpfSha256, SelfHostedActivationContract.HashLength);
        this.genesisFingerprintSha256 = Copy(
            genesisFingerprintSha256,
            SelfHostedActivationContract.HashLength);
        if (latestBridgeSequence == 0 || latestBridgeSequence == ulong.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(latestBridgeSequence));
        }
        LatestBridgeSequence = latestBridgeSequence;
        this.latestBridgeSha256 = Copy(
            latestBridgeSha256,
            SelfHostedActivationContract.HashLength);
    }

    public ReadOnlyMemory<byte> AccountGeneration => accountGeneration.ToArray();
    public ReadOnlyMemory<byte> ExactDpfSha256 => exactDpfSha256.ToArray();
    public ReadOnlyMemory<byte> GenesisFingerprintSha256 => genesisFingerprintSha256.ToArray();
    public ulong LatestBridgeSequence { get; }
    public ReadOnlyMemory<byte> LatestBridgeSha256 => latestBridgeSha256.ToArray();

    private static byte[] Copy(ReadOnlySpan<byte> value, int length)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new ArgumentException("Self-hosted activation LKG field is invalid.");
        }
        return value.ToArray();
    }
}

internal sealed class SelfHostedByteMemoryComparer : IComparer<ReadOnlyMemory<byte>>
{
    public static SelfHostedByteMemoryComparer Instance { get; } = new();

    public int Compare(ReadOnlyMemory<byte> x, ReadOnlyMemory<byte> y) =>
        x.Span.SequenceCompareTo(y.Span);
}

public static class SelfHostedActivationGate
{
    public static async ValueTask<VerifiedSelfHostedActivationDescriptor> ActivateInitialAsync(
        ReadOnlyMemory<byte> candidateDpf,
        ProfileCarrierVerificationOptions candidateOptions,
        ReadOnlyMemory<byte> currentAccountGeneration,
        SelfHostedSwitchConsent consent,
        ISelfHostedActivationCommitter committer,
        IMembershipSignatureVerifier verifier,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(committer);
        var frozenCandidate = SelfHostedActivationDescriptorVerifier.FreezeExactDpf(candidateDpf.Span);
        var candidate = SelfHostedActivationDescriptorVerifier.VerifyFrozenExact(
            frozenCandidate,
            candidateOptions,
            verifier);
        RequireConsentExact(candidate, currentAccountGeneration.Span, consent);
        await CommitExactAsync(
            new SelfHostedActivationCommit(
                SelfHostedActivationCommitKind.Initial,
                currentAccountGeneration.Span,
                null,
                frozenCandidate,
                candidate,
                consent),
            committer,
            cancellationToken).ConfigureAwait(false);
        return candidate;
    }

    public static async ValueTask<VerifiedSelfHostedActivationDescriptor> ActivateUpdateAsync(
        ReadOnlyMemory<byte> currentDpf,
        ProfileCarrierVerificationOptions currentOptions,
        SelfHostedActivationLastKnownGood currentLkg,
        ReadOnlyMemory<byte> candidateDpf,
        ProfileCarrierVerificationOptions candidateOptions,
        ReadOnlyMemory<byte> currentAccountGeneration,
        SelfHostedSwitchConsent? switchConsent,
        ISelfHostedActivationCommitter committer,
        IMembershipSignatureVerifier verifier,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(currentLkg);
        ArgumentNullException.ThrowIfNull(committer);
        var frozenCurrent = SelfHostedActivationDescriptorVerifier.FreezeExactDpf(currentDpf.Span);
        var frozenCandidate = SelfHostedActivationDescriptorVerifier.FreezeExactDpf(candidateDpf.Span);
        var current = SelfHostedActivationDescriptorVerifier.VerifyFrozenExact(
            frozenCurrent,
            currentOptions,
            verifier);
        RequireCurrentLkg(current, currentLkg, currentAccountGeneration.Span);
        var candidate = SelfHostedActivationDescriptorVerifier.VerifyFrozenExact(
            frozenCandidate,
            candidateOptions,
            verifier);
        var decision = ProfileCarrierTransitionVerifier.VerifyExact(
            frozenCurrent,
            currentOptions,
            frozenCandidate,
            candidateOptions,
            verifier);
        if (decision == ProfileCarrierTransitionDecision.ForwardSameGenesis)
        {
            if (!CryptographicOperations.FixedTimeEquals(
                    current.GenesisFingerprintSha256.Span,
                    candidate.GenesisFingerprintSha256.Span) ||
                candidate.LatestBridgeSequence <= current.LatestBridgeSequence)
            {
                throw new InvalidDataException("Self-hosted DPF update did not advance exact LKG.");
            }
            await CommitExactAsync(
                new SelfHostedActivationCommit(
                    SelfHostedActivationCommitKind.SameGenesisForward,
                    currentAccountGeneration.Span,
                    currentLkg,
                    frozenCandidate,
                    candidate,
                    null),
                committer,
                cancellationToken).ConfigureAwait(false);
            return candidate;
        }
        if (decision == ProfileCarrierTransitionDecision.Idempotent)
        {
            await CommitExactAsync(
                new SelfHostedActivationCommit(
                    SelfHostedActivationCommitKind.Idempotent,
                    currentAccountGeneration.Span,
                    currentLkg,
                    frozenCandidate,
                    candidate,
                    null),
                committer,
                cancellationToken).ConfigureAwait(false);
            return candidate;
        }
        if (decision != ProfileCarrierTransitionDecision.ExplicitNetworkSwitchCandidate ||
            switchConsent is null)
        {
            throw new InvalidDataException("Self-hosted DPF transition was rejected.");
        }
        RequireConsentExact(candidate, currentAccountGeneration.Span, switchConsent);
        await CommitExactAsync(
            new SelfHostedActivationCommit(
                SelfHostedActivationCommitKind.NetworkSwitch,
                currentAccountGeneration.Span,
                currentLkg,
                frozenCandidate,
                candidate,
                switchConsent),
            committer,
            cancellationToken).ConfigureAwait(false);
        return candidate;
    }

    private static void RequireCurrentLkg(
        VerifiedSelfHostedActivationDescriptor current,
        SelfHostedActivationLastKnownGood lkg,
        ReadOnlySpan<byte> accountGeneration)
    {
        if (accountGeneration.Length != SelfHostedActivationContract.AccountGenerationLength ||
            !CryptographicOperations.FixedTimeEquals(accountGeneration, lkg.AccountGeneration.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                current.ExactDpfSha256.Span,
                lkg.ExactDpfSha256.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                current.GenesisFingerprintSha256.Span,
                lkg.GenesisFingerprintSha256.Span) ||
            current.LatestBridgeSequence != lkg.LatestBridgeSequence ||
            !CryptographicOperations.FixedTimeEquals(
                current.LatestBridgeSha256.Span,
                lkg.LatestBridgeSha256.Span))
        {
            throw new InvalidDataException("Self-hosted activation LKG does not match current state.");
        }
    }

    private static void RequireConsentExact(
        VerifiedSelfHostedActivationDescriptor candidate,
        ReadOnlySpan<byte> currentAccountGeneration,
        SelfHostedSwitchConsent consent)
    {
        ArgumentNullException.ThrowIfNull(consent);
        if (currentAccountGeneration.Length != SelfHostedActivationContract.AccountGenerationLength ||
            !CryptographicOperations.FixedTimeEquals(
                currentAccountGeneration,
                consent.CurrentAccountGeneration.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                candidate.ExactDpfSha256.Span,
                consent.ExpectedCandidateDpfSha256.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                candidate.GenesisFingerprintSha256.Span,
                consent.ExpectedCandidateGenesisSha256.Span))
        {
            throw new InvalidOperationException("Self-hosted switch consent is absent or mismatched.");
        }
    }

    private static async ValueTask CommitExactAsync(
        SelfHostedActivationCommit commit,
        ISelfHostedActivationCommitter committer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(committer);
        if (!await committer.TryCommitAsync(commit, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException(
                "Self-hosted activation atomic commit was rejected or already consumed.");
        }
    }
}
