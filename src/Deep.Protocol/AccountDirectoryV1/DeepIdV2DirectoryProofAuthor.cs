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
/// DID2-only proof issuance. The shared DTT1/XNV1 witness primitives are
/// identity-neutral; the proof material, wire and self-verification are V2.
/// This cannot issue a V1 ADP1 or admit a DID1 account.
/// </summary>
public static class DeepIdV2DirectoryProofAuthor
{
    public static async ValueTask<AuthoredDeepIdV2DirectoryProofPackage> IssueGenesisAsync(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProofAuthoringRequest request,
        DeepIdV2DirectoryProofMaterial material,
        IReadOnlyList<IAccountDirectoryDtt1WitnessSigner> witnessSigners,
        ushort deploymentProfileId,
        IDeepMlDsa65Verifier mlDsa65,
        CancellationToken cancellationToken = default)
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
            var proof = DeepIdV2Adp1Codec.Author(material,
                AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt));
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

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) => left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new AccountDirectoryProofAuthoringException(code, message);
}
