using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Direct DID2 route author. Genesis phases and successor candidates do not publish,
/// adopt durable custody, issue mailbox grants or establish contact consent.</summary>
public static partial class DeepIdV2ContactRouteAuthor
{
    public static async ValueTask<ContactRecord> AuthorAdvertisementAsync(
        DeepIdV2CurrentContactAuthorization currentAuthorization, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority networkAuthority, OwnedGenesisDeviceSecrets deviceSecrets,
        uint maximumAcceptedHellos, ReadOnlyMemory<byte> antiSpamPolicyHash32,
        ReadOnlyMemory<byte> metadataKeyId32, ReadOnlyMemory<byte> metadataX25519Public32,
        ulong issuedAtUnixSeconds, ulong expiresAtUnixSeconds, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(deviceSecrets);
        cancellationToken.ThrowIfCancellationRequested();
        if (maximumAcceptedHellos is < 1 or > 65_535)
            throw new ArgumentOutOfRangeException(nameof(maximumAcceptedHellos));
        RequireLifetime(issuedAtUnixSeconds, expiresAtUnixSeconds, 2_592_000);
        Require32(antiSpamPolicyHash32.Span); Require32(metadataKeyId32.Span); Require32(metadataX25519Public32.Span);
        // Own mutable caller input before clock/network awaits.
        var policy = antiSpamPolicyHash32.ToArray(); var keyId = metadataKeyId32.ToArray();
        var publicKey = metadataX25519Public32.ToArray();
        ReadOnlyMemory<byte>[] fields = []; byte[]? signature = null;
        try
        {
            DeepIdV2ContactUpdateRendezvousAuthor.RequireAgreementKey(publicKey);
            var current = await DeepIdV2RouteContext.ReadAsync(currentAuthorization, network,
                networkAuthority, trustedTime, cancellationToken).ConfigureAwait(false);
            current.Covers(issuedAtUnixSeconds, expiresAtUnixSeconds, DeepIdV2RouteTimeArtifact.Xra1);
            RequireAdvertisementLifetime(current, issuedAtUnixSeconds, expiresAtUnixSeconds);
            if (DeepIdV2RouteContext.Fixed(publicKey, current.Device.Certificate.DeviceX25519PublicKey.Span))
                throw new CryptographicException("Metadata sealing cannot reuse the device agreement key.");
            fields = [network.NetworkId, Random32(), U64(0), new byte[32], current.PmtReference,
                Random32(), U16(1), U32(maximumAcceptedHellos), policy, keyId, publicKey,
                U64(issuedAtUnixSeconds), U64(expiresAtUnixSeconds), current.Device.Certificate.DeviceId,
                current.DeviceReference, PlaceholderSignature()];
            var provisional = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XRA1, fields);
            signature = deviceSecrets.SignCurrentContactRouteRecord(provisional, currentAuthorization.Authorization);
            fields[15] = signature;
            var result = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XRA1, fields);
            var final = await current.RecheckAsync(cancellationToken).ConfigureAwait(false);
            final.RequireAdvertisement(result);
            return result;
        }
        finally { Clear(fields); Clear(policy, keyId, publicKey); if (signature is not null) Clear(signature); }
    }

    public static ValueTask<ParsedDeepIdV2RouteThreshold> AuthorThresholdAsync(
        DeepIdV2CurrentContactAuthorization currentAuthorization, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority networkAuthority, ReadOnlyMemory<byte> exactXra1,
        IReadOnlyList<IContactRouteAuthorityWitnessSigner> witnessSigners,
        ulong issuedAtUnixSeconds, ulong expiresAtUnixSeconds, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default) =>
        AuthorThresholdCoreAsync(currentAuthorization, network, networkAuthority, exactXra1, witnessSigners,
            issuedAtUnixSeconds, expiresAtUnixSeconds, trustedTime, null, null, cancellationToken);

    private static async ValueTask<ParsedDeepIdV2RouteThreshold> AuthorThresholdCoreAsync(
        DeepIdV2CurrentContactAuthorization currentAuthorization, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority networkAuthority, ReadOnlyMemory<byte> exactXra1,
        IReadOnlyList<IContactRouteAuthorityWitnessSigner> witnessSigners,
        ulong issuedAtUnixSeconds, ulong expiresAtUnixSeconds, OnionTrustedTimeAuthority trustedTime,
        VerifiedDeepIdV2ContactRoutePredecessor? predecessor, SignerBinding[]? signerSnapshot,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(witnessSigners);
        cancellationToken.ThrowIfCancellationRequested();
        RequireLifetime(issuedAtUnixSeconds, expiresAtUnixSeconds, 86_400);
        if (exactXra1.Length != 550) throw new CryptographicException("XRA1 must have its exact bounded size.");
        var xra = ContactCodec.Decode(ProtocolMagic.XRA1, exactXra1.Span);
        if (predecessor is null) RequireGenesis(xra, 3);
        else predecessor.RequireAdvertisementSuccessor(xra);
        // Snapshot signer identities and verify the whole set before any callback.
        var signers = signerSnapshot ?? ValidateSigners(networkAuthority, witnessSigners);
        var current = await DeepIdV2RouteContext.ReadAsync(currentAuthorization, network,
            networkAuthority, trustedTime, cancellationToken).ConfigureAwait(false);
        predecessor?.RequireAtCurrentContext(current);
        if (predecessor is not null && (DeepIdV2RouteContext.U64(predecessor.Route.Route.Field(3).Span) >= ulong.MaxValue - 1 ||
            expiresAtUnixSeconds <= DeepIdV2RouteContext.U64(predecessor.Route.Route.Field(18).Span)))
            throw new CryptographicException("The retained route generation or expiry cannot advance.");
        current.RequireAdvertisement(xra); current.Covers(issuedAtUnixSeconds, expiresAtUnixSeconds, DeepIdV2RouteTimeArtifact.ThresholdAuthoring);
        if (issuedAtUnixSeconds < DeepIdV2RouteContext.U64(xra.FieldSpan(12)) ||
            expiresAtUnixSeconds > DeepIdV2RouteContext.U64(xra.FieldSpan(13)) ||
            expiresAtUnixSeconds > network.Closure!.HardUpperUnixSeconds)
            throw new CryptographicException("The threshold route lifetime exceeds current advertisement/network custody.");
        var pmt = current.Pmt;
        var ranked = ContactRouteThresholdAuthor.RankReplicas(network.NetworkId.Span, current.PmtReference.Span,
            pmt.FieldSpan(6), xra.FieldSpan(6), pmt.FieldSpan(9), pmt.FieldSpan(7)[0]);
        var keyEpoch = network.ResolveNode(ranked.AsSpan(0, 32)).KeyEpoch;
        for (var offset = 0; offset < ranked.Length; offset += 32)
            if (network.ResolveNode(ranked.AsSpan(offset, 32)).KeyEpoch != keyEpoch)
                throw new CryptographicException("Selected mailbox replicas do not share a current traffic-key epoch.");
        ReadOnlyMemory<byte>[] selection = []; ReadOnlyMemory<byte>[] live = []; ReadOnlyMemory<byte>[] successor = [];
        try
        {
            selection = [network.NetworkId, current.PmtReference, xra.Field(6), pmt.Field(6),
                pmt.Field(7), ranked, Array.Empty<byte>(), U64(issuedAtUnixSeconds), U64(expiresAtUnixSeconds),
                new byte[] { checked((byte)signers.Length) }, PlaceholderReceipts(signers)];
            selection[6] = ContactCodec.Sha256Domain("Deep/XPoint/V1/PMS2/selection",
                ContactRouteThresholdAuthor.EncodeProjection(ProtocolMagic.PMS2, selection, 6));
            if (predecessor is not null)
                for (var tag = 1; tag <= 7; tag++)
                    if (!DeepIdV2RouteContext.Fixed(selection[tag - 1].Span, predecessor.Route.Selection.Field(tag).Span))
                        throw new CryptographicException("A route successor cannot change its selection projection.");
            var oldSelection = predecessor?.Route.Selection;
            var reuseSelection = oldSelection is not null &&
                DeepIdV2RouteContext.U64(oldSelection.Field(8).Span) <= current.Lower &&
                expiresAtUnixSeconds <= DeepIdV2RouteContext.U64(oldSelection.Field(9).Span);
            var pms = reuseSelection ? oldSelection! : await SignRecordAsync(current, ProtocolMagic.PMS2, selection, 10,
                ContactRouteAuthoritySignaturePurpose.Selection, signers, cancellationToken).ConfigureAwait(false);
            var priorRoute = predecessor?.Route.Route;
            var count = pms.FieldSpan(5)[0]; var replicas = priorRoute?.Field(15).ToArray() ?? new byte[count * 64];
            for (var index = 0; priorRoute is null && index < count; index++)
            {
                ranked.AsSpan(index * 32, 32).CopyTo(replicas.AsSpan(index * 64));
                var cap = Random32();
                try { cap.CopyTo(replicas, index * 64 + 32); } finally { Clear(cap); }
            }
            live = [network.NetworkId, priorRoute?.Field(2) ?? Random32(),
                U64(priorRoute is null ? 0 : DeepIdV2RouteContext.U64(priorRoute.Field(3).Span) + 1), priorRoute?.CoreHash ?? new byte[32],
                Reference(xra), current.PmtReference, pms.ArtifactHash, current.ViewReference, current.HeadReference,
                priorRoute?.Field(10) ?? Random32(), xra.Field(10), xra.Field(11), U64(keyEpoch), new byte[] { count },
                replicas,
                U64(issuedAtUnixSeconds), U64(issuedAtUnixSeconds), U64(expiresAtUnixSeconds), current.DirectoryReference,
                new byte[] { checked((byte)signers.Length) }, PlaceholderReceipts(signers)];
            var xrc = await SignRecordAsync(current, ProtocolMagic.XRC1, live, 20,
                ContactRouteAuthoritySignaturePurpose.LiveRoute, signers, cancellationToken).ConfigureAwait(false);
            successor = [network.NetworkId, xrc.Field(2), U64(DeepIdV2RouteContext.U64(xrc.Field(3).Span) + 1),
                priorRoute?.CoreHash ?? xrc.CoreHash, Reference(xrc), Reference(priorRoute ?? xrc),
                current.PmtReference, current.ViewReference, pms.ArtifactHash, U64(issuedAtUnixSeconds),
                U64(expiresAtUnixSeconds), current.DirectoryReference, new byte[] { checked((byte)signers.Length) },
                PlaceholderReceipts(signers)];
            var xss = await SignRecordAsync(current, ProtocolMagic.XSS1, successor, 13,
                ContactRouteAuthoritySignaturePurpose.SuccessorCheckpoint, signers, cancellationToken).ConfigureAwait(false);
            var final = await current.RecheckAsync(cancellationToken).ConfigureAwait(false);
            final.RequireAdvertisement(xra); final.RequireThreshold(xra, pms, xrc, xss);
            var result = new ParsedDeepIdV2RouteThreshold(pms.CanonicalBytes.Span, xrc.CanonicalBytes.Span, xss.CanonicalBytes.Span);
            predecessor?.RequireAtCurrentContext(final); predecessor?.RequireThresholdSuccessor(xra, result);
            return result;
        }
        finally { Clear(selection); Clear(live); Clear(successor); Clear(ranked); }
    }

    public static ValueTask<VerifiedDeepIdV2ContactRouteClosure> CompleteGenesisAsync(
        DeepIdV2CurrentContactAuthorization currentAuthorization, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority networkAuthority, OwnedGenesisDeviceSecrets deviceSecrets,
        ReadOnlyMemory<byte> exactXra1, ParsedDeepIdV2RouteThreshold threshold, ushort minimumReader,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default) =>
        CompleteCoreAsync(currentAuthorization, network, networkAuthority, deviceSecrets, exactXra1,
            threshold, minimumReader, trustedTime, null, cancellationToken);

    /// <summary>Owned one-time genesis; not a publication, redemption or contact consent.</summary>
    public static ValueTask<VerifiedDeepIdV2ContactRouteClosure> CompleteOneTimeGenesisAsync(
        DeepIdV2CurrentContactAuthorization currentAuthorization, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority networkAuthority, OwnedGenesisDeviceSecrets deviceSecrets,
        ReadOnlyMemory<byte> exactXra1, ParsedDeepIdV2RouteThreshold threshold, ushort minimumReader,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default) =>
        CompleteCoreAsync(currentAuthorization, network, networkAuthority, deviceSecrets, exactXra1,
            threshold, minimumReader, trustedTime, null, cancellationToken, inviteKind: 2);

    private static async ValueTask<VerifiedDeepIdV2ContactRouteClosure> CompleteCoreAsync(
        DeepIdV2CurrentContactAuthorization currentAuthorization, VerifiedOnionNetworkContext network,
        VerifiedXPointNetworkAuthority networkAuthority, OwnedGenesisDeviceSecrets deviceSecrets,
        ReadOnlyMemory<byte> exactXra1, ParsedDeepIdV2RouteThreshold threshold, ushort minimumReader,
        OnionTrustedTimeAuthority trustedTime, VerifiedDeepIdV2ContactRoutePredecessor? predecessor,
        CancellationToken cancellationToken, VerifiedDeepIdV2ContactRouteIssuance? issuance = null,
        byte inviteKind = 1)
    {
        ArgumentNullException.ThrowIfNull(deviceSecrets); ArgumentNullException.ThrowIfNull(threshold);
        cancellationToken.ThrowIfCancellationRequested();
        if (minimumReader is < 1 or > 256) throw new ArgumentOutOfRangeException(nameof(minimumReader));
        ArgumentNullException.ThrowIfNull(currentAuthorization);
        if (inviteKind is < 1 or > 2 || (inviteKind == 2 && (predecessor is not null || issuance is not null)) ||
            (predecessor is not null && predecessor.Invite.Field(9).Span[0] != 1))
            throw new CryptographicException("One-time invitation completion requires a new genesis route.");
        if ((currentAuthorization.Authorization.Record.AllowedInviteKindMask & (inviteKind == 1 ? 1 : 2)) == 0)
            throw new CryptographicException("This delegation does not authorize the requested invite kind.");
        if (exactXra1.Length != 550) throw new CryptographicException("XRA1 must have its exact bounded size.");
        var xra = ContactCodec.Decode(ProtocolMagic.XRA1, exactXra1.Span);
        if (predecessor is null) RequireGenesis(xra, 3);
        else predecessor.RequireThresholdSuccessor(xra, threshold);
        var current = await DeepIdV2RouteContext.ReadAsync(currentAuthorization, network,
            networkAuthority, trustedTime, cancellationToken).ConfigureAwait(false);
        predecessor?.RequireAtCurrentContext(current);
        current.RequireAdvertisement(xra);
        var pms = threshold.Selection; var xrc = threshold.LiveRoute; var xss = threshold.Successor;
        if (predecessor is null)
        {
            RequireGenesis(xrc, 3);
            if (DeepIdV2RouteContext.U64(xss.FieldSpan(3)) != 1)
                throw new CryptographicException("Genesis completion cannot adopt a successor route lineage.");
        }
        else if (DeepIdV2RouteContext.U64(predecessor.Route.Reachability.Field(3).Span) == ulong.MaxValue ||
                 DeepIdV2RouteContext.U64(predecessor.Invite.Field(3).Span) == ulong.MaxValue ||
                 minimumReader != BinaryPrimitives.ReadUInt16BigEndian(predecessor.Invite.Field(11).Span))
            throw new CryptographicException("Invite successor cannot advance or changes the retained reader policy.");
        if (issuance is null) current.RequireThreshold(xra, pms, xrc, xss);
        else issuance.RequireAtCurrentContext(current);
        ReadOnlyMemory<byte>[] reachability = []; ReadOnlyMemory<byte>[] invitation = [];
        byte[]? xrrSignature = null; byte[]? xirSignature = null; byte[]? closure = null;
        try
        {
            var priorReachability = predecessor?.Route.Reachability; var priorInvite = predecessor?.Invite;
            reachability = [network.NetworkId, priorReachability?.Field(2) ?? Random32(),
                U64(priorReachability is null ? 0 : DeepIdV2RouteContext.U64(priorReachability.Field(3).Span) + 1),
                priorReachability?.CoreHash ?? new byte[32], Reference(xra),
                Reference(xrc), Reference(xss), current.PmtReference, pms.ArtifactHash, xrc.Field(10), xra.Field(9),
                priorReachability?.Field(12) ?? new byte[] { 3 }, xra.Field(8), U16(minimumReader), xrc.Field(16), xrc.Field(17), xrc.Field(18),
                current.DeviceReference, PlaceholderSignature(), new byte[2]];
            var provisional = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XRR1, reachability);
            xrrSignature = deviceSecrets.SignCurrentContactRouteRecord(provisional, currentAuthorization.Authorization);
            reachability[18] = xrrSignature;
            var xrr = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XRR1, reachability);
            invitation = [network.NetworkId, priorInvite?.Field(2) ?? Random32(),
                U64(priorInvite is null ? 0 : DeepIdV2RouteContext.U64(priorInvite.Field(3).Span) + 1),
                priorInvite?.ObjectHash ?? new byte[32], current.PmtReference,
                xra.Field(6), xra.Field(10), xra.Field(11), new byte[] { inviteKind },
                U32(inviteKind == 1 ? 0u : 1u), U16(minimumReader),
                xra.Field(9), xra.Field(12), xra.Field(13), current.DeviceReference, current.DcaReference,
                PlaceholderSignature(), Reference(xra)];
            var inviteCandidate = DeepIdV2InviteRendezvousCodec.AuthorForOperationalAuthority(invitation);
            xirSignature = deviceSecrets.SignCurrentContactInvite(inviteCandidate, currentAuthorization.Authorization);
            invitation[16] = xirSignature;
            var invite = DeepIdV2InviteRendezvousCodec.AuthorForOperationalAuthority(invitation);
            var final = await current.RecheckAsync(cancellationToken).ConfigureAwait(false);
            predecessor?.RequireAtCurrentContext(final);
            issuance?.RequireAtCurrentContext(final);
            closure = ContactRouteClosureCodec.EncodeRecords([xrr, xra, xrc, xss, current.Pmt, pms]);
            return await DeepIdV2ContactRouteVerifier.VerifyAsync(currentAuthorization, network, networkAuthority,
                invite.CanonicalBytes, closure, trustedTime, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Clear(reachability); Clear(invitation);
            if (xrrSignature is not null) Clear(xrrSignature); if (xirSignature is not null) Clear(xirSignature);
            if (closure is not null) Clear(closure);
        }
    }

    private static void RequireAdvertisementLifetime(DeepIdV2RouteContext current, ulong issued, ulong expiry)
    {
        if (issued < current.Device.Certificate.IssuedAtUnixSeconds || expiry > current.Device.Certificate.ExpiresAtUnixSeconds ||
            issued < current.Recipient.Authorization.Record.NotBeforeUnixSeconds ||
            expiry > current.Recipient.Authorization.Record.ExpiresAtUnixSeconds)
            throw new CryptographicException("The advertisement lifetime exceeds the authorized device/delegation.");
    }

    private static SignerBinding[] ValidateSigners(VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<IContactRouteAuthorityWitnessSigner> signers)
    {
        ArgumentNullException.ThrowIfNull(authority);
        var count = signers.Count;
        if (count is < 2 or > 32) throw new CryptographicException("Route witnesses are outside the bounded set.");
        var ids = new HashSet<string>(StringComparer.Ordinal); var domains = new HashSet<string>(StringComparer.Ordinal);
        var result = new SignerBinding[count];
        for (var index = 0; index < result.Length; index++)
        {
            var signer = signers[index] ?? throw new CryptographicException("A route witness is absent.");
            var witnessId = signer.WitnessId;
            Require32(witnessId.Span); var id = witnessId.ToArray();
            var key = authority.WitnessKeys.SingleOrDefault(candidate => DeepIdV2RouteContext.Fixed(candidate.Id.Span, id));
            if (key is null || !ids.Add(Convert.ToHexString(id)) || !domains.Add(Convert.ToHexString(key.FailureDomainHash.Span)))
                throw new CryptographicException("A route witness is unknown or duplicates an identity/failure domain.");
            result[index] = new(signer, id, key.Ed25519PublicKey.ToArray());
        }
        if (result.Length < authority.WitnessThreshold) throw new CryptographicException("The route witness threshold is not met.");
        Array.Sort(result, static (a, b) => a.Id.AsSpan().SequenceCompareTo(b.Id));
        return result;
    }

    private static async ValueTask<ContactRecord> SignRecordAsync(DeepIdV2RouteContext current,
        string magic, ReadOnlyMemory<byte>[] fields, int receiptIndex, ContactRouteAuthoritySignaturePurpose purpose,
        SignerBinding[] signers, CancellationToken ct)
    {
        var provisional = ContactCodec.AuthorForOperationalAuthority(magic, fields);
        var rows = new byte[signers.Length * 96];
        try
        {
            foreach (var (signer, index) in signers.Select((signer, index) => (signer, index)))
            {
                ct.ThrowIfCancellationRequested();
                await current.RecheckAsync(ct).ConfigureAwait(false);
                signer.Id.CopyTo(rows, index * 96);
                var request = new ContactRouteAuthoritySigningRequest(purpose, current.Network.NetworkId.Span, provisional.SignatureInput.Span);
                try
                {
                    var signature = rows.AsMemory(index * 96 + 32, 64);
                    var written = await signer.Signer.SignAsync(request, signature, ct).ConfigureAwait(false);
                    ct.ThrowIfCancellationRequested();
                    if (written != 64 || !PublicKeyAuth.VerifyDetached(signature.ToArray(), provisional.SignatureInput.ToArray(), signer.PublicKey))
                        throw new CryptographicException("A route witness returned an invalid exact signature.");
                    await current.RecheckAsync(ct).ConfigureAwait(false);
                }
                finally { request.Clear(); }
            }
            fields[receiptIndex] = rows.ToArray();
            return ContactCodec.AuthorForOperationalAuthority(magic, fields);
        }
        finally { Clear(rows); }
    }

    private static byte[] PlaceholderReceipts(SignerBinding[] signers)
    {
        var rows = new byte[signers.Length * 96];
        for (var index = 0; index < signers.Length; index++)
        { signers[index].Id.CopyTo(rows, index * 96); rows[index * 96 + 32] = 1; }
        return rows;
    }
    private static ReadOnlyMemory<byte> Reference(ContactRecord record) => ContactCodec.ArtifactReference(record.Magic, record).CanonicalBytes;
    private static void RequireLifetime(ulong issued, ulong expiry, ulong maximum)
    { if (issued == 0 || expiry <= issued || expiry - issued > maximum) throw new ArgumentOutOfRangeException(nameof(expiry)); }
    private static void RequireGenesis(ContactRecord record, int tag)
    { if (DeepIdV2RouteContext.U64(record.FieldSpan(tag)) != 0) throw new CryptographicException("Genesis authoring cannot restart an existing route lineage."); }
    private static void Require32(ReadOnlySpan<byte> value)
    { if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("An exact nonzero 32-byte field is required."); }
    private static byte[] Random32()
    { var bytes = new byte[32]; do RandomNumberGenerator.Fill(bytes); while (bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0); return bytes; }
    private static byte[] PlaceholderSignature() { var bytes = new byte[64]; bytes[^1] = 1; return bytes; }
    private static byte[] U16(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
    private static byte[] U32(uint value) { var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes; }
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static void Clear(params byte[][] buffers) { foreach (var bytes in buffers) CryptographicOperations.ZeroMemory(bytes); }
    private static void Clear(IEnumerable<ReadOnlyMemory<byte>> fields)
    { foreach (var field in fields) if (!field.IsEmpty) CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(field).Span); }
    private sealed record SignerBinding(IContactRouteAuthorityWitnessSigner Signer, byte[] Id, byte[] PublicKey);
}
