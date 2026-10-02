using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.ContactV2;

public static partial class DeepIdV2ContactRouteAuthor
{
    /// <summary>Authors only the current threshold successor candidate. The
    /// private issuer must serialize exact lineage/winners durably before release.</summary>
    public static async ValueTask<ParsedDeepIdV2RouteThreshold> AuthorThresholdSuccessorAsync(
        DeepIdV2CurrentContactAuthorization currentAuthorization, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority networkAuthority, VerifiedDeepIdV2ContactRoutePredecessor predecessor,
        ReadOnlyMemory<byte> exactXra1, IReadOnlyList<IContactRouteAuthorityWitnessSigner> witnessSigners,
        ulong expiresAtUnixSeconds, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(predecessor); cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(witnessSigners);
        if (exactXra1.Length != 550) throw new CryptographicException("XRA1 must have its exact bounded size.");
        var signers = ValidateSigners(networkAuthority, witnessSigners);
        var owned = exactXra1.ToArray();
        try
        {
            predecessor.RequireAdvertisementSuccessor(ContactCodec.Decode(ProtocolMagic.XRA1, owned));
            var current = await DeepIdV2RouteContext.ReadAsync(currentAuthorization, network, networkAuthority,
                trustedTime, cancellationToken).ConfigureAwait(false);
            predecessor.RequireAtCurrentContext(current);
            return await AuthorThresholdCoreAsync(currentAuthorization, network, networkAuthority, owned,
                witnessSigners, current.Lower, expiresAtUnixSeconds, trustedTime, predecessor, signers, cancellationToken).ConfigureAwait(false);
        }
        finally { CryptographicOperations.ZeroMemory(owned); }
    }

    /// <summary>Completes the exact reusable route successor from current
    /// device custody. This does not publish/adopt it or authorize a mailbox.</summary>
    public static ValueTask<VerifiedDeepIdV2ContactRouteClosure> CompleteSuccessorAsync(
        DeepIdV2CurrentContactAuthorization currentAuthorization, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority networkAuthority, OwnedGenesisDeviceSecrets deviceSecrets,
        VerifiedDeepIdV2ContactRoutePredecessor predecessor, ReadOnlyMemory<byte> exactXra1,
        ParsedDeepIdV2RouteThreshold threshold, ushort minimumReader, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(predecessor);
        return CompleteCoreAsync(currentAuthorization, network, networkAuthority, deviceSecrets,
            exactXra1, threshold, minimumReader, trustedTime, predecessor, cancellationToken);
    }

    /// <summary>Authors only a device-signed XRA1 successor candidate. An expired
    /// predecessor remains expired; this does not renew a threshold, route,
    /// publication, dispatch permission or grant. Durable exact custody belongs
    /// to the account owner before any external coordination.</summary>
    public static async ValueTask<ContactRecord> AuthorAdvertisementSuccessorAsync(
        DeepIdV2CurrentContactAuthorization currentAuthorization, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority networkAuthority, OwnedGenesisDeviceSecrets deviceSecrets,
        ReadOnlyMemory<byte> exactPredecessorXra1, ReadOnlyMemory<byte> antiSpamPolicyHash32,
        ReadOnlyMemory<byte> metadataKeyId32, ReadOnlyMemory<byte> metadataX25519Public32,
        ulong expiresAtUnixSeconds, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(deviceSecrets); cancellationToken.ThrowIfCancellationRequested();
        if (exactPredecessorXra1.Length != 550)
            throw new CryptographicException("XRA1 predecessor must have its exact bounded size.");
        var predecessor = ContactCodec.Decode(ProtocolMagic.XRA1, exactPredecessorXra1.Span);
        var generation = DeepIdV2RouteContext.U64(predecessor.Field(3).Span);
        if (generation == ulong.MaxValue)
            throw new CryptographicException("The reachability generation cannot advance.");
        if (expiresAtUnixSeconds <= DeepIdV2RouteContext.U64(predecessor.Field(13).Span))
            throw new CryptographicException("Reachability renewal must advance the signed expiry.");
        Require32(antiSpamPolicyHash32.Span); Require32(metadataKeyId32.Span); Require32(metadataX25519Public32.Span);
        var policy = antiSpamPolicyHash32.ToArray(); var keyId = metadataKeyId32.ToArray();
        var publicKey = metadataX25519Public32.ToArray();
        ReadOnlyMemory<byte>[] fields = []; byte[]? signature = null;
        try
        {
            DeepIdV2ContactUpdateRendezvousAuthor.RequireAgreementKey(publicKey);
            var current = await DeepIdV2RouteContext.ReadAsync(currentAuthorization, network,
                networkAuthority, trustedTime, cancellationToken).ConfigureAwait(false);
            current.RequireAdvertisementPredecessor(predecessor);
            var issued = current.Lower;
            RequireLifetime(issued, expiresAtUnixSeconds, 2_592_000);
            current.Covers(issued, expiresAtUnixSeconds, DeepIdV2RouteTimeArtifact.Xra1);
            RequireAdvertisementLifetime(current, issued, expiresAtUnixSeconds);
            if (DeepIdV2RouteContext.Fixed(publicKey, current.Device.Certificate.DeviceX25519PublicKey.Span))
                throw new CryptographicException("Metadata sealing cannot reuse the device agreement key.");
            fields = [network.NetworkId, predecessor.Field(2), U64(generation + 1), predecessor.CoreHash,
                predecessor.Field(5), predecessor.Field(6), predecessor.Field(7), predecessor.Field(8),
                policy, keyId, publicKey, U64(issued), U64(expiresAtUnixSeconds), predecessor.Field(14),
                predecessor.Field(15), PlaceholderSignature()];
            var provisional = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XRA1, fields);
            signature = deviceSecrets.SignCurrentContactRouteRecord(provisional, currentAuthorization.Authorization);
            fields[15] = signature;
            var result = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XRA1, fields);
            var final = await current.RecheckAsync(cancellationToken).ConfigureAwait(false);
            final.RequireAdvertisementPredecessor(predecessor);
            final.RequireAdvertisement(result);
            cancellationToken.ThrowIfCancellationRequested(); return result;
        }
        finally
        {
            Clear(fields); Clear(policy, keyId, publicKey);
            if (signature is not null) Clear(signature);
        }
    }
}
