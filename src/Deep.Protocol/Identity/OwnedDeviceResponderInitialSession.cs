using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;

namespace Deep.Protocol.Identity;

public sealed partial class OwnedGenesisDeviceSecrets
{
    /// <summary>Prepares authenticated exact initial state under current DID2
    /// authority without exporting the owned device key or a factory. Only
    /// the atomic-store handoff escapes; this is not durable custody or ACK.</summary>
    public async ValueTask<ResponderInitialSessionCommitCapability> PrepareInitialSessionAsync(
        VerifiedDph2InitialClaim verifiedClaim, VerifiedDeepIdV2DirectoryFreshness recipientFreshness,
        VerifiedDeepIdV2DirectoryFreshness initiatorFreshness, RestoredDpk2PreKeySecretCapability restoredPreKeys,
        OnionTrustedTimeAuthority trustedTime, int maximumMessagesWithoutPqInjection,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(verifiedClaim); ArgumentNullException.ThrowIfNull(recipientFreshness);
        ArgumentNullException.ThrowIfNull(initiatorFreshness); ArgumentNullException.ThrowIfNull(restoredPreKeys);
        ArgumentNullException.ThrowIfNull(trustedTime);
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048)
            throw new ArgumentOutOfRangeException(nameof(maximumMessagesWithoutPqInjection));
        cancellationToken.ThrowIfCancellationRequested();
        var first = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var dph2 = verifiedClaim.Initiation.Record;
        RequirePreviewScope(dph2, recipientFreshness, initiatorFreshness, verifiedClaim.Claim.Offering, first);
        _ = DeepIdV2CurrentContactAuthorizationVerifier.Verify(recipientFreshness,
            verifiedClaim.Claim.RecipientAuthorization.Authorization, first.BootId.Span, first.SampleSeconds);
        verifiedClaim.Claim.RequireCurrentAt(first);
        ResponderInitialSessionMaterial? material = null;
        VerifiedDevicePreKeyClaimReservation? reservation = null;
        try
        {
            lock (sync)
            {
                ThrowIfDisposed();
                RequireOwnedInitialRecipient(dph2, recipientFreshness);
                using var lanes = verifiedClaim.BindForInitialSession();
                reservation = lanes.ConsumeForDevicePreKeyOwner();
                using var factory = new ManagedResponderInitialSessionFactory(agreementPrivateScalar, maximumMessagesWithoutPqInjection);
                material = factory.CreateAuthenticatedInitialSession(lanes, restoredPreKeys);
            }
            var exactFirst = material.FirstApplicationDmc2;
            try
            {
                if (exactFirst.Length != 0)
                {
                    var firstEvent = ApplicationCoreCodec.DecodeDmc2(exactFirst.Span);
                    if (firstEvent.ContentKind == Dmc2ContentKind.ContactHello)
                        await ApplicationCoreVerifier.RequireContactHelloEndpointBindingsAsync(firstEvent,
                            initiatorFreshness, recipientFreshness, trustedTime, cancellationToken).ConfigureAwait(false);
                }
            }
            finally { CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(exactFirst).Span); }
            var final = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (final.SampleSeconds < first.SampleSeconds || !final.BootId.Span.SequenceEqual(first.BootId.Span))
                throw new CryptographicException("Responder preparation crossed a protected clock discontinuity.");
            RequirePreviewScope(dph2, recipientFreshness, initiatorFreshness, verifiedClaim.Claim.Offering, final);
            _ = DeepIdV2CurrentContactAuthorizationVerifier.Verify(recipientFreshness,
                verifiedClaim.Claim.RecipientAuthorization.Authorization, final.BootId.Span, final.SampleSeconds);
            verifiedClaim.Claim.RequireCurrentAt(final);
            var capability = new ResponderInitialSessionCommitCapability(material, reservation);
            material = null; reservation = null;
            return capability;
        }
        finally { material?.Dispose(); reservation?.Dispose(); }
    }
}
