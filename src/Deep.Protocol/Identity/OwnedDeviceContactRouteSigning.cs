using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Identity;

public sealed partial class OwnedGenesisDeviceSecrets
{
    // Closed, artifact-specific intents. No generic signing operation is exposed.
    internal byte[] SignCurrentContactRouteRecord(ContactRecord record, VerifiedDca1V2 authorization)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            var device = RequireCurrentRouteDevice(authorization);
            var referenceTag = record.Magic switch
            { ProtocolMagic.XRA1 => 15, ProtocolMagic.XRR1 => 18,
                _ => throw new CryptographicException("This record is not an owned route signing intent.") };
            if (!record.FieldSpan(1).SequenceEqual(authorization.Record.NetworkId.Span) ||
                !record.FieldSpan(referenceTag).SequenceEqual(new ContactArtifactReference(ProtocolMagic.DPD1, 1,
                    device.Certificate.CanonicalHash.Span).CanonicalBytes.Span) ||
                (record.Magic == ProtocolMagic.XRA1 && !record.FieldSpan(14).SequenceEqual(DeviceId.Bytes.Span)))
                throw new CryptographicException("The route signing intent differs from the owned authorized device.");
            return SignRouteIntent(record.SignatureInput.Span);
        }
    }

    internal byte[] SignCurrentContactInvite(ParsedXir1V2 invite, VerifiedDca1V2 authorization)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            var device = RequireCurrentRouteDevice(authorization);
            if (!invite.FieldSpan(1).SequenceEqual(authorization.Record.NetworkId.Span) ||
                !invite.FieldSpan(15).SequenceEqual(new ContactArtifactReference(ProtocolMagic.DPD1, 1,
                    device.Certificate.CanonicalHash.Span).CanonicalBytes.Span) ||
                !invite.FieldSpan(16).SequenceEqual(new ContactArtifactReference(ProtocolMagic.DCA1, 2,
                    authorization.Record.RecordHash.Span).CanonicalBytes.Span))
                throw new CryptographicException("The invite signing intent differs from exact current device/delegation custody.");
            return SignRouteIntent(invite.SignatureInput.Span);
        }
    }

    private VerifiedDevice RequireCurrentRouteDevice(VerifiedDca1V2 authorization)
    {
        var device = authorization.Binding.Identity.ActiveDevices.SingleOrDefault(candidate =>
            candidate.Certificate.DeviceId.Span.SequenceEqual(DeviceId.Bytes.Span));
        if (device is null || !authorization.Record.PublisherDeviceId.Span.SequenceEqual(DeviceId.Bytes.Span) ||
            !SigningPublicKey.Matches(device.Certificate.DeviceEd25519PublicKey.Span))
            throw new CryptographicException("Route custody is not the current authorized DID2 publisher device.");
        return device;
    }

    internal byte[] SignCurrentContactBundle(ParsedDcb1V2 bundle, VerifiedDca1V2 authorization)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            _ = RequireCurrentRouteDevice(authorization);
            if (!bundle.FieldSpan(6).SequenceEqual(authorization.Record.CanonicalBytes.Span) ||
                !bundle.FieldSpan(10).SequenceEqual(DeviceId.Bytes.Span) ||
                !bundle.FieldSpan(23).SequenceEqual(authorization.Binding.DeepId.CanonicalBytes.Span))
                throw new CryptographicException("The contact bundle is not the exact owned DID2 delegation.");
            return SignRouteIntent(bundle.SignatureInput.Span);
        }
    }

    internal byte[] SignCurrentContactPublicationRequest(
        ContactPublicationAuthorityWireRequest request, VerifiedDca1V2 authorization)
    {
        lock (sync)
        {
            ThrowIfDisposed();
            _ = RequireCurrentRouteDevice(authorization);
            if (!request.ExactDca1.Span.SequenceEqual(authorization.Record.CanonicalBytes.Span))
                throw new CryptographicException("Publication signing differs from owned current delegation.");
            var input = ContactPublicationAuthorityWireCodec.CreatePublisherSigningInput(request);
            try { return SignRouteIntent(input); }
            finally { CryptographicOperations.ZeroMemory(input); }
        }
    }

    private byte[] SignRouteIntent(ReadOnlySpan<byte> input)
    {
        var signature = new byte[OwnedSodiumEd25519.SignatureSize];
        Span<byte> temporaryPublic = stackalloc byte[OwnedSodiumEd25519.PublicKeySize];
        Span<byte> temporarySecret = stackalloc byte[OwnedSodiumEd25519.SecretKeySize];
        try
        {
            OwnedSodiumEd25519.SignDetached(signingSeed, input, signature, temporaryPublic, temporarySecret);
            return signature;
        }
        catch { CryptographicOperations.ZeroMemory(signature); throw; }
        finally
        {
            CryptographicOperations.ZeroMemory(temporaryPublic);
            CryptographicOperations.ZeroMemory(temporarySecret);
        }
    }
}
