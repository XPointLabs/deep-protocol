using System.Buffers.Binary;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.ContactV2;

// Parsed transport value, never current identity, placement, witness or dispatch authority.
public sealed class ParsedContactCoordinationOnionRequest
{
    private readonly byte[] canonical, network, nonce, projection, shard;
    internal ParsedContactCoordinationOnionRequest(ReadOnlySpan<byte> canonical, ContactCoordinationTarget target,
        ReadOnlySpan<byte> network, ReadOnlySpan<byte> nonce, ContactRecord advertisement, ulong expiry)
    {
        this.canonical = canonical.ToArray(); Target = target;
        this.network = network.ToArray(); this.nonce = nonce.ToArray();
        projection = advertisement.Field(5).ToArray(); shard = advertisement.Field(6).ToArray();
        ExpiresAtUnixSeconds = expiry;
    }
    internal ParsedContactCoordinationOnionRequest(ReadOnlySpan<byte> canonical, PublicationCurrentWireRequest request)
    {
        this.canonical = canonical.ToArray(); Target = ContactCoordinationTarget.PublicationCurrent;
        network = request.NetworkId.ToArray(); nonce = request.RequestNonce.ToArray();
        projection = []; shard = request.GatewayShard.ToArray(); ExpiresAtUnixSeconds = request.ExpiresAtUnixSeconds;
    }
    public ContactCoordinationTarget Target { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> ExactBody => canonical.AsSpan(ContactCoordinationOnionCodec.HeaderBytes).ToArray();
    public ReadOnlyMemory<byte> NetworkId => network.ToArray();
    public ReadOnlyMemory<byte> RequestNonce => nonce.ToArray();
    public ReadOnlyMemory<byte> ProjectionReference => projection.ToArray();
    public ReadOnlyMemory<byte> GatewayShard => shard.ToArray();
    public ulong ExpiresAtUnixSeconds { get; }
}

public static class ContactCoordinationOnionCodec
{
    public const int HeaderBytes = 12;
    public const int MaximumRequestBytes = HeaderBytes + DeepIdV2PublicationCurrentWireCodec.MaximumRequestBytes;
    public const int MaximumResponseBytes = HeaderBytes + DeepIdV2PublicationCurrentWireCodec.MaximumResponseBytes;

    public static byte[] EncodeRequest(ContactCoordinationTarget target, ReadOnlySpan<byte> exactBody)
    {
        RequireLength(target, exactBody.Length, response: false);
        var encoded = Wrap(ProtocolMagicBytes.XCA2, target, exactBody);
        _ = DecodeRequest(encoded); return encoded;
    }

    public static ParsedContactCoordinationOnionRequest DecodeRequest(ReadOnlySpan<byte> encoded)
    {
        var target = Header(encoded, ProtocolMagicBytes.XCA2, response: false);
        var body = encoded[HeaderBytes..];
        if (target == ContactCoordinationTarget.Route)
        {
            var request = ContactRouteAuthorityWireCodec.DecodeRequest(body);
            var advertisement = ContactCodec.Decode(ProtocolMagic.XRA1, request.ExactXra1.Span);
            return new(encoded, target, request.NetworkId.Span, request.RequestNonce.Span, advertisement,
                BinaryPrimitives.ReadUInt64BigEndian(advertisement.Field(13).Span));
        }
        if (target == ContactCoordinationTarget.PublicationCurrent)
            return new(encoded, DeepIdV2PublicationCurrentWireCodec.DecodeRequest(body));
        var publication = ContactPublicationAuthorityWireCodec.DecodeRequest(body);
        if (publication.PublicationKind != 2)
            throw new FormatException("Reusable publication requires its independently current submission.");
        var route = ContactRouteClosureCodec.Decode(publication.ExactRouteClosure.Span);
        return new(encoded, target, publication.NetworkId.Span, publication.RequestNonce.Span, route.Authorization,
            publication.ExpiresAtUnixSeconds);
    }

    public static byte[] EncodeResponse(ParsedContactCoordinationOnionRequest request, ReadOnlySpan<byte> exactResponseBody)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireLength(request.Target, exactResponseBody.Length, response: true);
        VerifyPair(request, exactResponseBody);
        return Wrap(ProtocolMagicBytes.XCS2, request.Target, exactResponseBody);
    }

    public static byte[] DecodeResponse(ParsedContactCoordinationOnionRequest request, ReadOnlySpan<byte> encoded)
    {
        ArgumentNullException.ThrowIfNull(request);
        var target = Header(encoded, ProtocolMagicBytes.XCS2, response: true);
        if (target != request.Target) throw new FormatException("Coordination target differs from the exact request.");
        VerifyPair(request, encoded[HeaderBytes..]);
        return encoded[HeaderBytes..].ToArray();
    }

    private static void VerifyPair(ParsedContactCoordinationOnionRequest request, ReadOnlySpan<byte> body)
    {
        var pending = request.ExactBody;
        if (request.Target == ContactCoordinationTarget.Route)
            _ = ContactRouteAuthorityWireCodec.DecodeResponse(ContactRouteAuthorityWireCodec.DecodeRequest(pending.Span), body);
        else if (request.Target == ContactCoordinationTarget.Publication)
            _ = ContactPublicationAuthorityWireCodec.DecodeResponse(ContactPublicationAuthorityWireCodec.DecodeRequest(pending.Span), body);
        else if (request.Target == ContactCoordinationTarget.PublicationCurrent)
            _ = DeepIdV2PublicationCurrentWireCodec.DecodeResponse(DeepIdV2PublicationCurrentWireCodec.DecodeRequest(pending.Span), body);
        else throw new FormatException("Unknown coordination target.");
    }

    private static ContactCoordinationTarget Header(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> magic, bool response)
    {
        // Target bounds are checked before any owned envelope/body allocation.
        if (encoded.Length < HeaderBytes || !encoded[..4].SequenceEqual(magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(encoded[4..6]) != 2 || encoded[7] != 0 ||
            BinaryPrimitives.ReadUInt32BigEndian(encoded[8..12]) != encoded.Length)
            throw new FormatException("Coordination wrapper is not canonical.");
        var target = (ContactCoordinationTarget)encoded[6];
        RequireLength(target, encoded.Length - HeaderBytes, response); return target;
    }

    private static void RequireLength(ContactCoordinationTarget target, int bytes, bool response)
    {
        var limits = (target, response) switch
        {
            (ContactCoordinationTarget.Route, false) => (ContactRouteAuthorityWireCodec.MinimumRequestBytes, ContactRouteAuthorityWireCodec.MaximumRequestBytes),
            (ContactCoordinationTarget.Route, true) => (ContactRouteAuthorityWireCodec.MinimumResponseBytes, ContactRouteAuthorityWireCodec.MaximumResponseBytes),
            (ContactCoordinationTarget.Publication, false) => (ContactPublicationAuthorityWireCodec.MinimumRequestBytes, ContactPublicationAuthorityWireCodec.MaximumRequestBytes),
            (ContactCoordinationTarget.Publication, true) => (ContactPublicationAuthorityWireCodec.MinimumResponseBytes, ContactPublicationAuthorityWireCodec.MaximumResponseBytes),
            (ContactCoordinationTarget.PublicationCurrent, false) => (DeepIdV2PublicationCurrentWireCodec.MinimumRequestBytes, DeepIdV2PublicationCurrentWireCodec.MaximumRequestBytes),
            (ContactCoordinationTarget.PublicationCurrent, true) => (DeepIdV2PublicationCurrentWireCodec.MinimumResponseBytes, DeepIdV2PublicationCurrentWireCodec.MaximumResponseBytes),
            _ => throw new FormatException("Unknown coordination target."),
        };
        if (bytes < limits.Item1 || bytes > limits.Item2) throw new FormatException("Coordination body exceeds its target bound.");
    }

    private static byte[] Wrap(ReadOnlySpan<byte> magic, ContactCoordinationTarget target, ReadOnlySpan<byte> body)
    {
        var encoded = new byte[checked(HeaderBytes + body.Length)]; magic.CopyTo(encoded);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(4), 2); encoded[6] = (byte)target;
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(8), checked((uint)encoded.Length));
        body.CopyTo(encoded.AsSpan(HeaderBytes)); return encoded;
    }
}
