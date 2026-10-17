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
        using var prepared = await PrepareInitialCoreAsync(verifiedClaim, recipientFreshness, initiatorFreshness,
            restoredPreKeys, trustedTime, maximumMessagesWithoutPqInjection, false, cancellationToken).ConfigureAwait(false);
        return prepared.ConsumeLive();
    }

    /// <summary>Authenticated first-contact mailbox preparation with a separate
    /// terminal handoff for proven expired events. No expired live admission.</summary>
    public ValueTask<ResponderInitialMailboxPreparation> PrepareInitialMailboxSessionAsync(
        VerifiedDph2InitialClaim verifiedClaim, VerifiedDeepIdV2DirectoryFreshness recipientFreshness,
        VerifiedDeepIdV2DirectoryFreshness initiatorFreshness, RestoredDpk2PreKeySecretCapability restoredPreKeys,
        OnionTrustedTimeAuthority trustedTime, int maximumMessagesWithoutPqInjection,
        CancellationToken cancellationToken = default) =>
        PrepareInitialCoreAsync(verifiedClaim, recipientFreshness, initiatorFreshness, restoredPreKeys,
            trustedTime, maximumMessagesWithoutPqInjection, true, cancellationToken);

    private async ValueTask<ResponderInitialMailboxPreparation> PrepareInitialCoreAsync(
        VerifiedDph2InitialClaim verifiedClaim, VerifiedDeepIdV2DirectoryFreshness recipientFreshness,
        VerifiedDeepIdV2DirectoryFreshness initiatorFreshness, RestoredDpk2PreKeySecretCapability restoredPreKeys,
        OnionTrustedTimeAuthority trustedTime, int maximumMessagesWithoutPqInjection, bool allowTerminalDisposal,
        CancellationToken cancellationToken)
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
            var exactInit = material.SessionInitDmc2;
            var expired = false;
            ulong provenLower = 0;
            ulong initExpiry = 0, helloExpiry = 0;
            try
            {
                if (exactFirst.Length != 0)
                {
                    var firstEvent = ApplicationCoreCodec.DecodeDmc2(exactFirst.Span);
                    if (firstEvent.ContentKind == Dmc2ContentKind.ContactHello)
                    {
                        var initEvent = ApplicationCoreCodec.DecodeDmc2(exactInit.Span);
                        initExpiry = initEvent.ExpiresAtUnixMilliseconds;
                        helloExpiry = firstEvent.ExpiresAtUnixMilliseconds;
                        var lower = checked(recipientFreshness.TrustedLowerUnixSeconds + first.SampleSeconds - recipientFreshness.MonotonicSample);
                        var upper = checked(recipientFreshness.TrustedUpperUnixSeconds + first.SampleSeconds - recipientFreshness.MonotonicSample);
                        expired = allowTerminalDisposal && lower >= CeilingSeconds(initEvent.ExpiresAtUnixMilliseconds) &&
                            lower >= CeilingSeconds(firstEvent.ExpiresAtUnixMilliseconds);
                        if (expired)
                        {
                            await ApplicationCoreVerifier.RequireExpiredInitialHelloCreationBindingsAsync(firstEvent,
                                initiatorFreshness, recipientFreshness, trustedTime, cancellationToken).ConfigureAwait(false);
                            provenLower = lower;
                        }
                        else
                        {
                            if (upper >= initEvent.ExpiresAtUnixMilliseconds / 1000 || upper >= firstEvent.ExpiresAtUnixMilliseconds / 1000)
                                throw new CryptographicException("Initial contact has no wholly current lifetime or proven terminal expiry.");
                            await ApplicationCoreVerifier.RequireContactHelloEndpointBindingsAsync(firstEvent,
                                initiatorFreshness, recipientFreshness, trustedTime, cancellationToken).ConfigureAwait(false);
                        }
                    }
                }
                var final = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (final.SampleSeconds < first.SampleSeconds || !final.BootId.Span.SequenceEqual(first.BootId.Span))
                    throw new CryptographicException("Responder preparation crossed a protected clock discontinuity.");
                RequirePreviewScope(dph2, recipientFreshness, initiatorFreshness, verifiedClaim.Claim.Offering, final);
                _ = DeepIdV2CurrentContactAuthorizationVerifier.Verify(recipientFreshness,
                    verifiedClaim.Claim.RecipientAuthorization.Authorization, final.BootId.Span, final.SampleSeconds);
                verifiedClaim.Claim.RequireCurrentAt(final);
                if (!expired && helloExpiry != 0)
                {
                    var upper = checked(recipientFreshness.TrustedUpperUnixSeconds + final.SampleSeconds - recipientFreshness.MonotonicSample);
                    if (upper >= initExpiry / 1000 || upper >= helloExpiry / 1000)
                        throw new CryptographicException("Live Initial expired during responder preparation.");
                }
                if (expired)
                {
                    var exactState = material.ExactTrs1;
                    try
                    {
                        var payload = new ResponderExpiredInitialAtomicStorePayload(reservation, exactInit.Span,
                            exactFirst.Span, SHA256.HashData(exactState.Span), provenLower);
                        material.Dispose(); material = null; reservation = null;
                        return new ResponderInitialMailboxPreparation(payload);
                    }
                    finally { CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(exactState).Span); }
                }
                var capability = new ResponderInitialSessionCommitCapability(material, reservation);
                material = null; reservation = null;
                return new ResponderInitialMailboxPreparation(capability);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(exactFirst).Span);
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(exactInit).Span);
            }
        }
        finally { material?.Dispose(); reservation?.Dispose(); }
    }

    private static ulong CeilingSeconds(ulong milliseconds) => checked(milliseconds / 1000 + (milliseconds % 1000 == 0 ? 0UL : 1UL));
}
