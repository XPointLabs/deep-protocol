using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.Identity;

/// <summary>
/// Reconstructs the same genesis-committed public Deep ID from a verified
/// 24-word phrase. It does not issue a new DAB2 binding during restore.
/// </summary>
public static class DeepIdV2Root
{
    public static ParsedDid2 DeriveDid2(VerifiedDeepRecoveryPhrase phrase)
    {
        ArgumentNullException.ThrowIfNull(phrase);
        using var pq = DeepMlDsa65NativeProvider.LoadCandidateForCurrentProcess();
        ParsedDid2? did = null;
        DeepPqRootRecoveryV2.UseRootMaterial(phrase, (edSeed, pqSeed, capability) =>
        {
            byte[]? edPublic = null;
            byte[]? pqPublic = null;
            try
            {
                edPublic = DeepIdentityCrypto.DeriveEd25519PublicKey(edSeed);
                pqPublic = pq.DerivePublicKey(pqSeed);
                did = DeepIdV2Codec.AuthorDid2(edPublic, pqPublic, capability);
            }
            finally
            {
                if (edPublic is not null) CryptographicOperations.ZeroMemory(edPublic);
                if (pqPublic is not null) CryptographicOperations.ZeroMemory(pqPublic);
            }
        });
        return did ?? throw new CryptographicException("DID2 root derivation did not complete.");
    }

    /// <summary>
    /// Restores a previously issued exact binding. Hedged ML-DSA signatures
    /// make re-authoring genesis from the same phrase a different DAB2 fork.
    /// </summary>
    public static Dab2LineageState RestoreExistingGenesisDab2(
        VerifiedDeepRecoveryPhrase phrase,
        ReadOnlySpan<byte> exactCanonicalDab2,
        VerifiedApplicationIdentityClosure identity,
        ushort deploymentProfileId)
    {
        ArgumentNullException.ThrowIfNull(phrase);
        ArgumentNullException.ThrowIfNull(identity);
        var did = DeriveDid2(phrase);
        var parsed = DeepIdV2Codec.DecodeDab2(exactCanonicalDab2);
        using var pq = DeepMlDsa65NativeProvider.LoadCandidateForCurrentProcess();
        var verified = DeepIdV2Verifier.VerifyDab2(
            parsed, did, identity, deploymentProfileId, pq);
        return DeepIdV2Verifier.StartDab2Lineage(verified).Next;
    }
}
