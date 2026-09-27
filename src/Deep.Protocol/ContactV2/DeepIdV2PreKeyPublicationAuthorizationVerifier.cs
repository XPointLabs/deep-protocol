using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Promotes a reassembled XPP1 only after its untrusted publisher hint and
/// complete inventory match the same current DID2 recipient authority.
/// Replica placement, durable commit and claim remain separate gates.
/// </summary>
public static class DeepIdV2PreKeyPublicationAuthorizationVerifier
{
    public static bool RuntimeActivation => false;

    public static void Verify(ParsedDid2 publisherHint, ParsedDcr1V2 closure,
        DeepIdV2CurrentContactAuthorization currentAuthorization,
        ParsedXpp1V2 publication, ReadOnlySpan<byte> currentBootId,
        ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(publisherHint);
        ArgumentNullException.ThrowIfNull(closure);
        ArgumentNullException.ThrowIfNull(currentAuthorization);
        ArgumentNullException.ThrowIfNull(publication);

        var authorizedDid2 = currentAuthorization.Authorization.Binding.DeepId;
        if (!CryptographicOperations.FixedTimeEquals(
                publisherHint.CanonicalBytes.Span,
                authorizedDid2.CanonicalBytes.Span))
            throw ApplicationCoreFormat.Error(
                ApplicationCoreValidationStage.CryptographicVerification,
                ApplicationCoreRejection.VerificationFailed,
                "XPP1 publisher hint differs from the current DID2 recipient.");

        DeepIdV2PreKeyInventoryVerifier.VerifyComplete(closure,
            currentAuthorization, publication.Manifest,
            publication.OneTimeMembers, publication.LastResortMember,
            currentBootId, currentMonotonicSample);
    }
}
