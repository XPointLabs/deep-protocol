using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Exact nonce-bound V2 result. These bytes are issued only after the author
/// has verified the same full proof that an independent DID2 reader verifies.
/// </summary>
public sealed class AuthoredDeepIdV2DirectoryProofPackage
{
    private readonly byte[] nonce;
    private readonly byte[] bootId;
    private readonly byte[] leaf;
    private readonly byte[] adh;
    private readonly byte[] dtt;
    private readonly byte[] adp;

    internal AuthoredDeepIdV2DirectoryProofPackage(
        AccountDirectoryProofAuthoringRequest request,
        DeepIdV2DirectoryProofMaterial material,
        ReadOnlySpan<byte> exactDtt1, ReadOnlySpan<byte> exactAdp1V2)
    {
        nonce = request.Nonce.ToArray();
        bootId = request.BootId.ToArray();
        leaf = material.QueriedDirectoryLeafKey.ToArray();
        adh = request.ExactCurrentAdh1.ToArray();
        dtt = exactDtt1.ToArray();
        adp = exactAdp1V2.ToArray();
        ClientMonotonicSendSample = request.ClientMonotonicSendSample;
    }

    public ReadOnlyMemory<byte> Nonce => nonce.ToArray();
    public ReadOnlyMemory<byte> BootId => bootId.ToArray();
    public ReadOnlyMemory<byte> QueriedDirectoryLeafKey => leaf.ToArray();
    public ReadOnlyMemory<byte> ExactAdh1 => adh.ToArray();
    public ReadOnlyMemory<byte> ExactDtt1 => dtt.ToArray();
    public ReadOnlyMemory<byte> ExactAdp1V2 => adp.ToArray();
    public ulong ClientMonotonicSendSample { get; }
}

/// <summary>
/// Untrusted offline-root artifacts and exact successor heads for DID2 mode 2.
/// The proof issuer authenticates all of these inputs against the current
/// nonce-bound DTT1 before returning any package.
/// </summary>
public sealed class DeepIdV2ForwardTailAuthoringInput
{
    private readonly ReadOnlyMemory<byte>[] authorities;
    private readonly ReadOnlyMemory<byte>[] checkpoints;
    private readonly ReadOnlyMemory<byte>[] checkpointTargets;
    private readonly ReadOnlyMemory<byte>[] chainSourceMembership;
    private readonly ReadOnlyMemory<byte>[] sourceMembership;
    private readonly ReadOnlyMemory<byte>[] tailHeads;
    private readonly ReadOnlyMemory<byte>[] anchorConsistency;

    public DeepIdV2ForwardTailAuthoringInput(
        AccountDirectoryProtectedLkg chainSourceHead,
        IReadOnlyList<ReadOnlyMemory<byte>> exactAuthorityChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactAdf1Chain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactAdfTargetHeadChain,
        ulong chainSourceLeafIndex,
        IReadOnlyList<ReadOnlyMemory<byte>> chainSourceMembershipNodes,
        byte sourceCheckpointIndex, ulong sourceLeafIndex,
        IReadOnlyList<ReadOnlyMemory<byte>> sourceMembershipNodes,
        IReadOnlyList<ReadOnlyMemory<byte>> exactTailHeads,
        IReadOnlyList<ReadOnlyMemory<byte>> anchorConsistencyNodes)
    {
        ChainSourceHead = chainSourceHead ??
            throw new ArgumentNullException(nameof(chainSourceHead));
        authorities = Copy(exactAuthorityChain, 1, 64, 16_384);
        checkpoints = Copy(exactAdf1Chain, 1, 64, 16_384);
        checkpointTargets = Copy(exactAdfTargetHeadChain, 1, 64, 4096);
        chainSourceMembership = Copy(chainSourceMembershipNodes, 0, 64, 32);
        sourceMembership = Copy(sourceMembershipNodes, 0, 64, 32);
        tailHeads = Copy(exactTailHeads, 0, 64, 4096);
        anchorConsistency = Copy(anchorConsistencyNodes, 0, 64, 32);
        if (checkpoints.Length != checkpointTargets.Length ||
            sourceCheckpointIndex >= checkpoints.Length ||
            chainSourceMembership.Any(static value => value.Length != 32) ||
            sourceMembership.Any(static value => value.Length != 32) ||
            anchorConsistency.Any(static value => value.Length != 32))
            throw new ArgumentException("DID2 forward-tail authoring shape is invalid.");
        ChainSourceLeafIndex = chainSourceLeafIndex;
        SourceCheckpointIndex = sourceCheckpointIndex;
        SourceLeafIndex = sourceLeafIndex;
    }

    public AccountDirectoryProtectedLkg ChainSourceHead { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactAuthorityChain => Own(authorities);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactAdf1Chain => Own(checkpoints);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactAdfTargetHeadChain =>
        Own(checkpointTargets);
    public ulong ChainSourceLeafIndex { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> ChainSourceMembershipNodes =>
        Own(chainSourceMembership);
    public byte SourceCheckpointIndex { get; }
    public ulong SourceLeafIndex { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> SourceMembershipNodes =>
        Own(sourceMembership);
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactTailHeads => Own(tailHeads);
    public IReadOnlyList<ReadOnlyMemory<byte>> AnchorConsistencyNodes =>
        Own(anchorConsistency);

    private static ReadOnlyMemory<byte>[] Copy(
        IReadOnlyList<ReadOnlyMemory<byte>> values,
        int minimum, int maximum, int maximumLength)
    {
        ArgumentNullException.ThrowIfNull(values);
        if (values.Count < minimum || values.Count > maximum ||
            values.Any(value => value.Length is < 1 ||
                value.Length > maximumLength))
            throw new ArgumentException("DID2 forward-tail artifact list exceeds its bounds.");
        return Own(values);
    }

    private static ReadOnlyMemory<byte>[] Own(
        IReadOnlyList<ReadOnlyMemory<byte>> values) =>
        values.Select(static value =>
            (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
}

/// <summary>
/// DID2-only proof issuance. The shared DTT1/XNV1 witness primitives are
/// identity-neutral; the proof material, wire and self-verification are V2.
/// This cannot issue a V1 ADP1 or admit a DID1 account.
/// </summary>
public static class DeepIdV2DirectoryProofAuthor
{
    public static ValueTask<AuthoredDeepIdV2DirectoryProofPackage> IssueGenesisAsync(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProofAuthoringRequest request,
        DeepIdV2DirectoryProofMaterial material,
        IReadOnlyList<IAccountDirectoryDtt1WitnessSigner> witnessSigners,
        ushort deploymentProfileId,
        IDeepMlDsa65Verifier mlDsa65,
        CancellationToken cancellationToken = default) =>
        IssueCoreAsync(authority, request, material, null,
            witnessSigners, deploymentProfileId, mlDsa65, cancellationToken);

    public static ValueTask<AuthoredDeepIdV2DirectoryProofPackage>
        IssueWithForwardTailAsync(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProofAuthoringRequest request,
        DeepIdV2DirectoryProofMaterial material,
        DeepIdV2ForwardTailAuthoringInput forward,
        IReadOnlyList<IAccountDirectoryDtt1WitnessSigner> witnessSigners,
        ushort deploymentProfileId,
        IDeepMlDsa65Verifier mlDsa65,
        CancellationToken cancellationToken = default) =>
        IssueCoreAsync(authority, request, material,
            forward ?? throw new ArgumentNullException(nameof(forward)),
            witnessSigners, deploymentProfileId, mlDsa65,
            cancellationToken);

    private static async ValueTask<AuthoredDeepIdV2DirectoryProofPackage>
        IssueCoreAsync(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProofAuthoringRequest request,
        DeepIdV2DirectoryProofMaterial material,
        DeepIdV2ForwardTailAuthoringInput? forward,
        IReadOnlyList<IAccountDirectoryDtt1WitnessSigner> witnessSigners,
        ushort deploymentProfileId,
        IDeepMlDsa65Verifier mlDsa65,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(material);
        ArgumentNullException.ThrowIfNull(witnessSigners);
        ArgumentNullException.ThrowIfNull(mlDsa65);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var head = material.CurrentHead;
            if (request.SupportedReader < 2 || head.Head.MinimumReader < 2 ||
                deploymentProfileId == 0)
                Fail("UnsupportedReader", "DID2 proof issuance requires reader V2 and a deployment profile.");
            if (forward is not null && material.CallerProtectedLkg is null)
                Fail("ForwardFloorRequired",
                    "DID2 forward-tail issuance requires a protected caller floor.");
            if (!Fixed(authority.NetworkId.Span, request.NetworkId.Span) ||
                !Fixed(head.Head.NetworkId.Span, request.NetworkId.Span) ||
                !Fixed(request.ExactCurrentAdh1.Span, head.ExactAdh1.Span))
                Fail("ExactAdhMismatch", "The DID2 proof material and requested head differ.");
            request.IssuanceEpoch.RequireAuthority(authority);
            AccountDirectoryCurrentProofVerifier.VerifyAdhAuthorityAndWitnessClosure(
                authority, head.Head, requireCurrentAuthority: true);
            var lower = request.ObservedUnixTime >= request.UncertaintySeconds
                ? request.ObservedUnixTime - request.UncertaintySeconds : 0;
            var upper = checked(request.ObservedUnixTime + request.UncertaintySeconds);
            if (request.UncertaintySeconds > authority.MaximumWitnessUncertaintySeconds ||
                request.IssuedAtUnixTime < lower ||
                request.IssuedAtUnixTime > upper ||
                upper > request.ExpiresAtUnixTime ||
                request.IssuedAtUnixTime < authority.NotBefore ||
                request.ExpiresAtUnixTime > authority.ExpiresAt ||
                request.IssuedAtUnixTime < authority.Dts1NotBefore ||
                request.ExpiresAtUnixTime > authority.Dts1ExpiresAt ||
                head.Head.MinimumReader > request.SupportedReader)
                Fail("InvalidTimeOrReader", "DID2 DTT1 request exceeds the signed time or reader envelope.");
            AccountDirectoryCurrentProofVerifier.VerifyCurrentHeadTime(
                head.Head, lower, upper);
            var currentView = AccountDirectoryProofAuthor.ValidateCurrentView(
                authority, request, lower, upper);
            var signers = AccountDirectoryProofAuthor.ValidateSigners(
                authority, witnessSigners);
            var dtt = await AccountDirectoryProofAuthor.AuthorDtt1Async(
                    authority, head.Head, currentView, request, signers,
                    cancellationToken)
                .ConfigureAwait(false);
            var exactDtt = AccountDirectoryDtt1Codec.Encode(dtt);
            var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);
            var proof = forward is null
                ? DeepIdV2Adp1Codec.Author(material, dttHash)
                : AuthorForwardTail(material, forward, dttHash);
            var exactAdp = proof.CanonicalBytes.ToArray();

            _ = DeepIdV2DirectoryCurrentProofVerifier.VerifyExactLeafForAuthor(
                authority, head.ExactAdh1, exactDtt, exactAdp,
                request.Nonce.Span, material.QueriedDirectoryLeafKey.Span,
                new AccountDirectoryMonotonicRequestWindow(
                    request.BootId.Span,
                    request.ClientMonotonicSendSample,
                    request.ClientMonotonicSendSample,
                    request.ClientMonotonicSendSample),
                material.CallerProtectedLkg, deploymentProfileId,
                request.SupportedReader, mlDsa65);
            return new AuthoredDeepIdV2DirectoryProofPackage(request, material,
                exactDtt, exactAdp);
        }
        catch (OperationCanceledException) { throw; }
        catch (AccountDirectoryProofAuthoringException) { throw; }
        catch (Exception exception) when (exception is ArgumentException or
            FormatException or CryptographicException or OverflowException)
        {
            throw new AccountDirectoryProofAuthoringException("Did2ProofRejected",
                "The exact DID2 proof could not be issued and self-verified.", exception);
        }
    }

    private static ParsedAdp1V2 AuthorForwardTail(
        DeepIdV2DirectoryProofMaterial material,
        DeepIdV2ForwardTailAuthoringInput forward,
        ReadOnlySpan<byte> liveDtt1CoreHash)
    {
        var targetHead = AccountDirectoryAdh1Codec.Decode(
            forward.ExactAdfTargetHeadChain[^1].Span);
        var targetHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(
            targetHead);
        var source = forward.ChainSourceHead;
        var afp = new AccountDirectoryAfp1(
            material.CurrentHead.Head.NetworkId.Span,
            source.LogGeneration, source.TreeSize, source.CoreHash.Span,
            targetHash, forward.ExactAuthorityChain,
            forward.ExactAdf1Chain,
            forward.ExactAdfTargetHeadChain,
            forward.ChainSourceLeafIndex,
            forward.ChainSourceMembershipNodes,
            liveDtt1CoreHash);
        return DeepIdV2Adp1Codec.AuthorWithForwardTail(material,
            liveDtt1CoreHash, AccountDirectoryAfp1Codec.Encode(afp),
            source.ExactAdh1.Span,
            forward.SourceCheckpointIndex, forward.SourceLeafIndex,
            forward.SourceMembershipNodes, forward.ExactTailHeads,
            forward.AnchorConsistencyNodes);
    }

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) => left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new AccountDirectoryProofAuthoringException(code, message);
}
