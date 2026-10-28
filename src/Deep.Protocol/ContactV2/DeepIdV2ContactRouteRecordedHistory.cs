using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV2;

/// <summary>Authenticated expired positive proposal lineage only. No route, grant or dispatch authority.</summary>
public sealed class VerifiedDeepIdV2ContactRouteRecordedHistory
{
    internal VerifiedDeepIdV2ContactRouteRecordedHistory(VerifiedDeepIdV2ContactRoutePredecessor predecessor,
        DeepIdV2ContactRouteRecordedPair[] pairs)
    { Predecessor = predecessor; Pairs = Array.AsReadOnly(pairs); }
    public VerifiedDeepIdV2ContactRoutePredecessor Predecessor { get; }
    public IReadOnlyList<DeepIdV2ContactRouteRecordedPair> Pairs { get; }
    internal ContactRecord LastAdvertisement => ContactCodec.Decode(ProtocolMagic.XRA1, Pairs[^1].Request.ExactXra1.Span);
    internal ParsedDeepIdV2RouteThreshold LastThreshold => Threshold(Pairs[^1]);
    internal static ParsedDeepIdV2RouteThreshold Threshold(DeepIdV2ContactRouteRecordedPair pair) =>
        new(pair.Response.ExactPms2.Span, pair.Response.ExactXrc1.Span, pair.Response.ExactXss1.Span);
    internal VerifiedDeepIdV2ContactRoutePredecessor RequireExactPredecessor(VerifiedDeepIdV2ContactRoutePredecessor predecessor)
    {
        if (!DeepIdV2RouteContext.Fixed(Predecessor.ExactXir1V2.Span, predecessor.ExactXir1V2.Span) ||
            !DeepIdV2RouteContext.Fixed(Predecessor.ExactRouteClosure.Span, predecessor.ExactRouteClosure.Span))
            throw new CryptographicException("Recorded proposal history substituted its completed anchor.");
        return predecessor;
    }
    internal void RequireAtCurrentContext(DeepIdV2RouteContext current)
    {
        Predecessor.RequireAtCurrentContext(current);
        var previous = Predecessor;
        foreach (var pair in Pairs)
        {
            var request = pair.Request; var threshold = Threshold(pair);
            var xra = ContactCodec.Decode(ProtocolMagic.XRA1, request.ExactXra1.Span);
            if (!DeepIdV2RouteContext.Fixed(request.ExactPredecessorXir1V2.Span, Predecessor.ExactXir1V2.Span) ||
                !DeepIdV2RouteContext.Fixed(request.ExactPredecessorRouteClosure.Span, Predecessor.ExactRouteClosure.Span) ||
                !DeepIdV2RouteContext.Fixed(request.ExactDca1.Span, current.Recipient.Authorization.Record.CanonicalBytes.Span) ||
                !DeepIdV2RouteContext.Fixed(request.DirectoryLookupKey.Span, current.Recipient.Freshness.QueriedDirectoryLeafKey.Span))
                throw new CryptographicException("Recorded proposal changed its exact completed anchor or subject.");
            previous.RequireThresholdSuccessor(xra, threshold);
            current.RequireRetainedAdvertisementFacts(xra, Predecessor.Route.Projection);
            ContactCodec.ValidateThresholdRouteGraph(xra, threshold.LiveRoute, threshold.Successor, Predecessor.Route.Projection, threshold.Selection);
            var xrc = threshold.LiveRoute; var xss = threshold.Successor;
            var original = XPointOnionCapabilityProducer.RequireRetainedIssuanceAuthority(current.Network, current.Authority,
                xrc.Field(8), xrc.Field(9), DeepIdV2RouteContext.U64(xrc.Field(16).Span), DeepIdV2RouteContext.U64(xrc.Field(18).Span));
            foreach (var (record, signature, start, expiry) in new[] { (threshold.Selection,11,8,9),(xrc,21,16,18),(xss,14,10,11) })
            {
                var issued = DeepIdV2RouteContext.U64(record.Field(start).Span); var until = DeepIdV2RouteContext.U64(record.Field(expiry).Span);
                if (issued < original.NotBefore || until > original.ExpiresAt || issued > current.Lower)
                    throw new CryptographicException("Recorded threshold lies outside its original signed scope.");
                DeepIdV2RouteContext.VerifyWitnesses(record, signature, original);
            }
            var head = AccountDirectoryProtectedLkgFactory.Restore(current.Authority, pair.Response.ExactIssuanceAdh1, xrc.Field(19).Span[6..]);
            var floor = current.Recipient.Freshness.NextProtectedLkg;
            if (head.Head.MinimumReader != 2 || !DeepIdV2RouteContext.Fixed(head.Head.ExactXnaAuthorityCoreReference.Span,
                    XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNA1, original.CoreHash.Span)) ||
                !DeepIdV2RouteContext.Fixed(xrc.Field(19).Span, xss.Field(12).Span) ||
                head.LogGeneration < request.MinimumAdh1Generation || head.LogGeneration > floor.LogGeneration ||
                (head.LogGeneration == request.MinimumAdh1Generation && !DeepIdV2RouteContext.Fixed(head.CoreHash.Span, request.MinimumAdh1CoreHash.Span)) ||
                (head.LogGeneration == floor.LogGeneration && !DeepIdV2RouteContext.Fixed(head.CoreHash.Span, floor.CoreHash.Span)) ||
                DeepIdV2RouteContext.U64(xrc.Field(16).Span) < head.Head.ValidFrom || DeepIdV2RouteContext.U64(xrc.Field(16).Span) >= head.Head.ValidUntil ||
                DeepIdV2RouteContext.U64(xss.Field(10).Span) < head.Head.ValidFrom || DeepIdV2RouteContext.U64(xss.Field(10).Span) >= head.Head.ValidUntil)
                throw new CryptographicException("Recorded threshold differs from its original authenticated directory issuance.");
            var expiredAt = new[] { DeepIdV2RouteContext.U64(xra.Field(13).Span), DeepIdV2RouteContext.U64(threshold.Selection.Field(9).Span),
                DeepIdV2RouteContext.U64(xrc.Field(18).Span), DeepIdV2RouteContext.U64(xss.Field(11).Span) }.Min();
            if (current.Lower < expiredAt) throw new CryptographicException("Recorded proposal remains live.");
            previous = new(Predecessor.Invite, Predecessor.Route, xra, threshold);
        }
    }
    internal void RequireSuccessor(DeepIdV2RouteContext current, ContactRecord xra, ParsedDeepIdV2RouteThreshold threshold)
    { RequireAtCurrentContext(current); Predecessor.AfterRecordedHistory(this).RequireThresholdSuccessor(xra, threshold); }
}

public static partial class DeepIdV2ContactRouteVerifier
{
    public static async ValueTask VerifyExpiredAdvertisementForRecoveryAsync(DeepIdV2CurrentContactAuthorization recipient,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority, VerifiedDeepIdV2ContactRoutePredecessor predecessor,
        ReadOnlyMemory<byte> exactXra1, OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default,
        VerifiedDeepIdV2ContactRouteRecordedHistory? recordedHistory = null)
    {
        var xra = ContactCodec.Decode(ProtocolMagic.XRA1, exactXra1.Span);
        var effective = recordedHistory is null ? predecessor : recordedHistory.RequireExactPredecessor(predecessor).AfterRecordedHistory(recordedHistory);
        var first = await DeepIdV2RouteContext.ReadAsync(recipient,network,authority,trustedTime,cancellationToken).ConfigureAwait(false);
        Require(first); Require(await first.RecheckAsync(cancellationToken).ConfigureAwait(false)); cancellationToken.ThrowIfCancellationRequested();
        void Require(DeepIdV2RouteContext current)
        {
            effective.RequireAtCurrentContext(current); effective.RequireAdvertisementSuccessor(xra);
            current.RequireRetainedAdvertisementFacts(xra, predecessor.Route.Projection);
            if(current.Lower < DeepIdV2RouteContext.U64(xra.Field(13).Span)) throw new CryptographicException("Recovery requires authenticated advertisement expiry.");
        }
    }
    public static async ValueTask<VerifiedDeepIdV2ContactRouteRecordedHistory> VerifyRecordedHistoryAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        VerifiedDeepIdV2ContactRoutePredecessor predecessor, IReadOnlyList<DeepIdV2ContactRouteRecordedPair> pairs,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(predecessor); ArgumentNullException.ThrowIfNull(pairs);
        if (pairs.Count is < 1 or > 3) throw new CryptographicException("Recorded proposal history exceeds its bound.");
        var owned = pairs.Select(pair => new DeepIdV2ContactRouteRecordedPair(pair.ExactRequest.Span, pair.ExactResponse.Span)).ToArray();
        var result = new VerifiedDeepIdV2ContactRouteRecordedHistory(predecessor, owned);
        var current = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority, trustedTime, cancellationToken).ConfigureAwait(false);
        result.RequireAtCurrentContext(current); result.RequireAtCurrentContext(await current.RecheckAsync(cancellationToken).ConfigureAwait(false));
        cancellationToken.ThrowIfCancellationRequested(); return result;
    }

    public static async ValueTask VerifyRecoveryRequestAsync(DeepIdV2CurrentContactAuthorization recipient,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority, DeepIdV2ContactRouteRecoveryWireRequest request,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        request = DeepIdV2ContactRouteRecoveryWireCodec.DecodeRequest(request.CanonicalBytes.Span);
        var current = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority, trustedTime, cancellationToken).ConfigureAwait(false);
        Require(current); Require(await current.RecheckAsync(cancellationToken).ConfigureAwait(false)); cancellationToken.ThrowIfCancellationRequested();
        void Require(DeepIdV2RouteContext value)
        {
            var floor = value.Recipient.Freshness.NextProtectedLkg;
            if (!DeepIdV2RouteContext.Fixed(request.NetworkId.Span, network.NetworkId.Span) ||
                !DeepIdV2RouteContext.Fixed(request.ViewHash.Span, network.Closure!.View.CoreHash.Span) ||
                !DeepIdV2RouteContext.Fixed(request.DirectoryLookupKey.Span, recipient.Freshness.QueriedDirectoryLeafKey.Span) ||
                !DeepIdV2RouteContext.Fixed(request.BaseRequest.ExactDca1.Span, recipient.Authorization.Record.CanonicalBytes.Span) ||
                request.MinimumAdh1Generation > floor.LogGeneration || (request.MinimumAdh1Generation == floor.LogGeneration &&
                    !DeepIdV2RouteContext.Fixed(request.MinimumAdh1CoreHash.Span, floor.CoreHash.Span)) ||
                request.IssuedAtUnixSeconds > value.Lower || value.Upper >= request.ExpiresAtUnixSeconds ||
                request.IssuedAtUnixSeconds < authority.NotBefore || request.ExpiresAtUnixSeconds > value.LogicalRecordExpiryCeiling ||
                !PublicKeyAuth.VerifyDetached(request.DeviceSignature.ToArray(), DeepIdV2ContactRouteRecoveryWireCodec.SigningInput(request), value.Device.Certificate.DeviceEd25519PublicKey.ToArray()))
                throw new CryptographicException("Recovery wrapper differs from independently current subject, view, floor or time.");
        }
    }
    public static ValueTask VerifyAdvertisementAfterRecordedHistoryAsync(DeepIdV2CurrentContactAuthorization recipient,
        VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority, VerifiedDeepIdV2ContactRouteRecordedHistory history,
        ReadOnlyMemory<byte> exactXra1, OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default) =>
        VerifyAdvertisementSuccessorAsync(recipient, network, authority, history.Predecessor.AfterRecordedHistory(history), exactXra1, trustedTime, cancellationToken);
}

public static partial class DeepIdV2ContactRouteAuthor
{
    public static async ValueTask<ContactRecord> AuthorAdvertisementAfterRecordedHistoryAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OwnedGenesisDeviceSecrets device, VerifiedDeepIdV2ContactRouteRecordedHistory history,
        ReadOnlyMemory<byte> antiSpamPolicyHash32, ReadOnlyMemory<byte> metadataKeyId32, ReadOnlyMemory<byte> metadataX25519Public32,
        ulong expiresAtUnixSeconds, OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        var current = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority, trustedTime, cancellationToken).ConfigureAwait(false);
        history.RequireAtCurrentContext(current);
        var result = await AuthorAdvertisementSuccessorAsync(recipient, network, authority, device,
            history.LastAdvertisement.CanonicalBytes, antiSpamPolicyHash32, metadataKeyId32, metadataX25519Public32,
            expiresAtUnixSeconds, trustedTime, cancellationToken).ConfigureAwait(false);
        history.RequireAtCurrentContext(await current.RecheckAsync(cancellationToken).ConfigureAwait(false));
        return result;
    }
    public static ValueTask<ParsedDeepIdV2RouteThreshold> AuthorThresholdAfterRecordedHistoryAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        VerifiedDeepIdV2ContactRouteRecordedHistory history, ReadOnlyMemory<byte> exactXra1,
        IReadOnlyList<IContactRouteAuthorityWitnessSigner> witnesses, ulong expiresAtUnixSeconds,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default) =>
        AuthorThresholdSuccessorAsync(recipient, network, authority, history.Predecessor.AfterRecordedHistory(history), exactXra1,
            witnesses, expiresAtUnixSeconds, trustedTime, cancellationToken);

    public static async ValueTask<DeepIdV2ContactRouteRecoveryWireRequest> AuthorRecoveryRequestAsync(
        DeepIdV2CurrentContactAuthorization recipient, VerifiedOnionNetworkContext network, VerifiedXPointNetworkAuthority authority,
        OwnedGenesisDeviceSecrets device, DeepIdV2ContactRouteRecoveryMode mode, ContactRouteAuthorityWireRequest baseRequest,
        IReadOnlyList<DeepIdV2ContactRouteRecordedPair> history, OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        var original = ContactRouteAuthorityWireCodec.EncodeRequest(baseRequest);
        var pairs = history.Select(pair => new DeepIdV2ContactRouteRecordedPair(pair.ExactRequest.Span, pair.ExactResponse.Span)).ToArray();
        var current = await DeepIdV2RouteContext.ReadAsync(recipient, network, authority, trustedTime, cancellationToken).ConfigureAwait(false);
        var nonce = Random32(); var signature = PlaceholderSignature().ToArray();
        try
        {
            var floor = recipient.Freshness.NextProtectedLkg;
            var gateway = ContactServicePlacementFactory.Create(network, ContactServiceRequestKind.CoordinateContact,
                DeepIdV2ContactRouteRecoveryWireCodec.GatewayShard(network.NetworkId.Span, nonce));
            var proof = recipient.Freshness;
            var proofCeiling = checked(proof.TrustedLowerUnixSeconds + proof.FreshnessDeadlineMonotonicSeconds - proof.MonotonicSample);
            var expiry = new[] { checked(current.Lower + 120), current.LogicalRecordExpiryCeiling,
                proofCeiling, floor.Head.ValidUntil, gateway.ValidUntilUnixSeconds,
                network.MaximumRecordExpiryUnixSeconds, network.Closure!.View.ExpiresAt }.Min();
            if (expiry <= current.Upper)
                throw new CryptographicException("Current authority cannot cover a fresh route recovery interval.");
            var provisional = new DeepIdV2ContactRouteRecoveryWireRequest(mode, network.NetworkId.Span, nonce, baseRequest.DirectoryLookupKey.Span,
                floor.LogGeneration, floor.CoreHash.Span, network.Closure.View.CoreHash.Span, current.Lower, expiry, original, pairs, signature);
            signature = device.SignCurrentRouteRecovery(provisional, recipient.Authorization);
            var result = new DeepIdV2ContactRouteRecoveryWireRequest(mode, network.NetworkId.Span, nonce, baseRequest.DirectoryLookupKey.Span,
                floor.LogGeneration, floor.CoreHash.Span, network.Closure.View.CoreHash.Span, current.Lower, expiry, original, pairs, signature);
            await DeepIdV2ContactRouteVerifier.VerifyRecoveryRequestAsync(recipient, network, authority, result, trustedTime, cancellationToken).ConfigureAwait(false);
            return result;
        }
        finally { Clear(original, nonce, signature); }
    }
}
