using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingCrypto;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Identity;

public sealed partial class OwnedGenesisDeviceSecrets
{
    /// <summary>Opens unverified XPK1/XPC1 prefix evidence using an owned
    /// current DID2 device. No scalar/factory, application event or session
    /// authority escapes; inventory remains unreserved by this read.</summary>
    public async ValueTask<Dph2InitialClaimPreview> PreviewInitialClaimAsync(Dph2Record dph2,
        VerifiedDeepIdV2DirectoryFreshness recipientFreshness, VerifiedDeepIdV2DirectoryFreshness initiatorFreshness,
        VerifiedDpk2Offering offering, RestoredDpk2PreKeySecretCapability restoredPreKeys,
        OnionTrustedTimeAuthority trustedTime, int maximumMessagesWithoutPqInjection,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dph2); ArgumentNullException.ThrowIfNull(recipientFreshness);
        ArgumentNullException.ThrowIfNull(initiatorFreshness); ArgumentNullException.ThrowIfNull(offering);
        ArgumentNullException.ThrowIfNull(restoredPreKeys); ArgumentNullException.ThrowIfNull(trustedTime);
        if (maximumMessagesWithoutPqInjection is < 1 or > 2048)
            throw new ArgumentOutOfRangeException(nameof(maximumMessagesWithoutPqInjection));
        cancellationToken.ThrowIfCancellationRequested();
        var first = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        RequirePreviewScope(dph2, recipientFreshness, initiatorFreshness, offering, first);
        Dph2InitialClaimPreview preview;
        lock (sync)
        {
            ThrowIfDisposed();
            RequireOwnedInitialRecipient(dph2, recipientFreshness);
            using var factory = new ManagedResponderInitialSessionFactory(agreementPrivateScalar, maximumMessagesWithoutPqInjection);
            var directory = ApplicationCoreVerifier.StartDmd1Lineage(initiatorFreshness.CurrentCheckpoint!.Directory).Next;
            preview = factory.PreviewInitialClaim(dph2, offering, directory, restoredPreKeys);
        }
        var final = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (final.SampleSeconds < first.SampleSeconds || !final.BootId.Span.SequenceEqual(first.BootId.Span))
            throw new CryptographicException("Initial claim preview crossed a protected clock discontinuity.");
        RequirePreviewScope(dph2, recipientFreshness, initiatorFreshness, offering, final);
        return preview;
    }

    // Caller holds the owned-secret lock and has checked the current proof.
    private void RequireOwnedInitialRecipient(Dph2Record dph2, VerifiedDeepIdV2DirectoryFreshness recipient)
    {
        var device = recipient.CurrentCheckpoint!.Directory.Identity.ActiveDevices.SingleOrDefault(candidate =>
            candidate.Certificate.DeviceId.Span.SequenceEqual(DeviceId.Bytes.Span));
        if (device is null || !dph2.ResponderDeviceId.Span.SequenceEqual(DeviceId.Bytes.Span) ||
            !SigningPublicKey.Matches(device.Certificate.DeviceEd25519PublicKey.Span) ||
            !AgreementPublicKey.Matches(device.Certificate.DeviceX25519PublicKey.Span))
            throw new CryptographicException("The initial claim differs from the owned current DID2 device.");
    }

    private static void RequirePreviewScope(Dph2Record dph2, VerifiedDeepIdV2DirectoryFreshness recipient,
        VerifiedDeepIdV2DirectoryFreshness initiator, VerifiedDpk2Offering offering, OnionMonotonicReading reading)
    {
        var current = recipient.CurrentCheckpoint;
        if (recipient.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue || current is null ||
            !recipient.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds) ||
            !dph2.NetworkId.Span.SequenceEqual(recipient.NetworkId.Span) ||
            !dph2.ResponderAccountId.Span.SequenceEqual(current.Binding.Record.DeepAccountId.Span) ||
            dph2.ResponderAccountId.Span.SequenceEqual(dph2.InitiatorAccountId.Span))
            throw new CryptographicException("The initial claim preview has no distinct current recipient account.");
        var sender = initiator.CurrentCheckpoint ?? throw new CryptographicException("The initial preview has no current initiator checkpoint.");
        _ = Dph2InitialClaimPreview.RequireCurrentInitiator(dph2, sender.Directory.Record.RecordHash.Span,
            initiator, reading.BootId.Span, reading.SampleSeconds);
        var reverified = DeepIdV2Dpk2PreClaimVerifier.Verify(offering.ExactBytes.Span, recipient,
            reading.BootId.Span, reading.SampleSeconds);
        Dph2Codec.ValidateSelection(dph2, reverified);
    }
}
