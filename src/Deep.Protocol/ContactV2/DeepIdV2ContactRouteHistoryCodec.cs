using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Closed DR-0178 control modes. Parsing supplies no authority.</summary>
public enum DeepIdV2ContactRouteHistoryMode : byte
{
    Evidence = 1, Announcement = 2, EvidenceAndAnnouncement = 3, HistoryRequest = 4
}

/// <summary>Untrusted exact original public exchange and optional completed endpoint.</summary>
public sealed class ParsedDeepIdV2ContactRouteHistoryAtom
{
    internal ParsedDeepIdV2ContactRouteHistoryAtom(byte[] bytes, ContactRouteAuthorityWireResponse response)
    { Exact = bytes; Response = response; }
    internal byte[] Exact { get; }
    internal ContactRouteAuthorityWireResponse Response { get; }
    /// <summary>True only for kind2; it does not assert verification.</summary>
    public bool IsCompleted => Exact[0] == 2;
    /// <summary>Canonical atom without its enclosing LP32.</summary>
    public ReadOnlyMemory<byte> CanonicalBytes => Exact.ToArray();
    /// <summary>Original exact DCA, never a replacement from current authority.</summary>
    public ReadOnlyMemory<byte> ExactDca1 => Exact.AsMemory(73, 473).ToArray();
    /// <summary>Original exact advertisement.</summary>
    public ReadOnlyMemory<byte> ExactXra1 => Exact.AsMemory(578, 550).ToArray();
    /// <summary>Original ordinary V3 response.</summary>
    public ReadOnlyMemory<byte> ExactResponse => Exact.AsMemory(1132, ResponseLength).ToArray();
    /// <summary>Exact untrusted completed XIR, or empty for a proposal atom. No historical or current authority.</summary>
    public ReadOnlyMemory<byte> ExactCompletedXir1V2 => IsCompleted ? Invite.CanonicalBytes : ReadOnlyMemory<byte>.Empty;
    /// <summary>Exact untrusted completed six-record closure, or empty for a proposal atom. No live route authority.</summary>
    public ReadOnlyMemory<byte> ExactCompletedRoute => IsCompleted ? CompletedRoute.ExactBytes : ReadOnlyMemory<byte>.Empty;
    internal int ResponseLength => checked((int)BinaryPrimitives.ReadUInt32BigEndian(Exact.AsSpan(1128)));
    internal ParsedXir1V2 Invite => DeepIdV2InviteRendezvousCodec.Decode(Exact.AsSpan(1132 + ResponseLength, 611));
    internal ParsedContactRouteClosure CompletedRoute => ContactRouteClosureCodec.Decode(ContactRouteClosureCodec.EncodeRecords([
        ContactCodec.Decode(ProtocolMagic.XRR1, Exact.AsSpan(1743 + ResponseLength, 643)),
        ContactCodec.Decode(ProtocolMagic.XRA1, ExactXra1.Span),
        ContactCodec.Decode(ProtocolMagic.XRC1, Response.ExactXrc1.Span),
        ContactCodec.Decode(ProtocolMagic.XSS1, Response.ExactXss1.Span),
        ContactCodec.Decode(ProtocolMagic.PMT2, Exact.AsSpan(2390 + ResponseLength)),
        ContactCodec.Decode(ProtocolMagic.PMS2, Response.ExactPms2.Span)]));

    internal ContactRouteAuthorityWireRequest Reconstruct(ParsedXir1V2 anchor, ParsedContactRouteClosure route) =>
        new(anchor.Field(1).Span, Exact.AsSpan(1, 32), Exact.AsSpan(546, 32),
            BinaryPrimitives.ReadUInt64BigEndian(Exact.AsSpan(33)), Exact.AsSpan(41, 32), ExactDca1.Span,
            ExactXra1.Span, anchor.CanonicalBytes.Span, route.ExactBytes.Span);
}

/// <summary>Untrusted bounded count8 payload. Neither cursors nor records are permissions.</summary>
public sealed class ContactRouteHistoryDmc2Payload : Dmc2Payload
{
    internal ContactRouteHistoryDmc2Payload(byte[] bytes, ParsedDeepIdV2ContactRouteHistoryAtom[] atoms)
        : base(Dmc2ContentKind.ContactRouteUpdate, bytes) { Exact = bytes; Atoms = Array.AsReadOnly(atoms); }
    internal byte[] Exact { get; }
    /// <summary>The closed mode.</summary>
    public DeepIdV2ContactRouteHistoryMode Mode => (DeepIdV2ContactRouteHistoryMode)Exact[74];
    /// <summary>Claimed relationship, joined independently to native custody.</summary>
    public ReadOnlyMemory<byte> RelationshipId => Exact.AsMemory(0, 32).ToArray();
    /// <summary>Immutable original native Hello/Accept DMC hash.</summary>
    public ReadOnlyMemory<byte> OriginalAnchorHash => Exact.AsMemory(40, 32).ToArray();
    /// <summary>Untrusted response-selection hint or exact page left cursor.</summary>
    public ReadOnlyMemory<byte> LeftCursor => Exact.AsMemory(80, 112).ToArray();
    /// <summary>Claimed computed final cursor.</summary>
    public ReadOnlyMemory<byte> RightCursor => Exact.AsMemory(192, 112).ToArray();
    /// <summary>Exact carried completed left XIR.</summary>
    public ReadOnlyMemory<byte> ExactLeftXir1V2 => Exact.AsMemory(304, 611).ToArray();
    /// <summary>Exact request event hash, or zero for a request/unsolicited control.</summary>
    public ReadOnlyMemory<byte> RequestEventHash => Exact.AsMemory(915, 32).ToArray();
    /// <summary>At most three untrusted public evidence atoms.</summary>
    public IReadOnlyList<ParsedDeepIdV2ContactRouteHistoryAtom> Atoms { get; }
}

/// <summary>Canonical count8 grammar. All signatures, lineage and native custody require verification.</summary>
public static class DeepIdV2ContactRouteHistoryCodec
{
    public const int HeaderBytes = 1024, CursorBytes = 112, MaximumPayloadBytes = 32768;
    public const int MaximumAtoms = 3, MaximumProposalAtomBytes = 16311, MaximumCompletedAtomBytes = 28635;
    internal const int AtomPrefixBytes = 1132;

    /// <summary>Reconstructs an untrusted canonical original ordinary exchange from
    /// an atom and its independently selected exact completed anchor. This checks
    /// bounded framing/bindings only, never signatures, adjacency or native custody.</summary>
    /// <param name="atom">A parsed bounded count8 atom.</param>
    /// <param name="exactAnchorXir">The exact original completed-anchor XIR611.</param>
    /// <param name="exactAnchorRoute">Its exact six-record completed route closure.</param>
    /// <returns>Untrusted owned request/response bytes, without history, authoring or current authority.</returns>
    public static DeepIdV2ContactRouteRecordedPair ReconstructOriginalPair(ParsedDeepIdV2ContactRouteHistoryAtom atom,
        ReadOnlySpan<byte> exactAnchorXir, ReadOnlySpan<byte> exactAnchorRoute)
    {
        ArgumentNullException.ThrowIfNull(atom);
        if (exactAnchorXir.Length != DeepIdV2InviteRendezvousCodec.CanonicalLength ||
            exactAnchorRoute.Length is < ContactRouteClosureCodec.MinimumEncodedBytes or > ContactRouteClosureCodec.MaximumEncodedBytes)
            throw new FormatException("Original exchange reconstruction exceeds its exact anchor bounds.");
        var invite = DeepIdV2InviteRendezvousCodec.Decode(exactAnchorXir);
        var route = ContactRouteClosureCodec.Decode(exactAnchorRoute);
        if (!invite.Field(3).Span.SequenceEqual(route.Reachability.Field(3).Span))
            throw new FormatException("Original exchange reconstruction changed its completed anchor generation.");
        var request = atom.Reconstruct(invite, route);
        return new(ContactRouteAuthorityWireCodec.EncodeRequest(request), atom.ExactResponse.Span);
    }

    /// <summary>Decodes closed bounded wire data before any authority provider is called.</summary>
    public static ContactRouteHistoryDmc2Payload Decode(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> networkId16)
    {
        if (networkId16.Length != 16 || bytes.Length is < HeaderBytes or > MaximumPayloadBytes ||
            bytes[72] != 8 || bytes[73] != 1 || bytes[74] is < 1 or > 4 || bytes[75] > MaximumAtoms ||
            bytes.Slice(76, 4).IndexOfAnyExcept((byte)0) >= 0 || bytes.Slice(947, 77).IndexOfAnyExcept((byte)0) >= 0 ||
            bytes[..32].IndexOfAnyExcept((byte)0) < 0 || bytes.Slice(40, 32).IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("Route history header is not canonical.");
        var evidence = bytes[74] is 1 or 3;
        if (evidence != (bytes[75] != 0) || (!evidence && !bytes.Slice(80, 112).SequenceEqual(bytes.Slice(192, 112))) ||
            !bytes.Slice(32, 8).SequenceEqual(bytes.Slice(192, 8)) ||
            (bytes[74] == 4 && bytes.Slice(915, 32).IndexOfAnyExcept((byte)0) >= 0))
            throw new FormatException("Route history mode/cursor framing is invalid.");
        ValidateCursor(bytes.Slice(80, 112)); ValidateCursor(bytes.Slice(192, 112));
        // First scan every enclosing length; malformed aggregates cannot reach nested decoders.
        var offset = HeaderBytes;
        for (var index = 0; index < bytes[75]; index++) _ = ReadAtom(bytes, ref offset);
        if (offset != bytes.Length) throw new FormatException("Route history has trailing bytes.");
        var anchor = DeepIdV2InviteRendezvousCodec.Decode(bytes.Slice(304, 611));
        if (!anchor.Field(1).Span.SequenceEqual(networkId16) ||
            !anchor.Field(3).Span.SequenceEqual(bytes.Slice(80, 8)))
            throw new FormatException("Route history left anchor differs from network or cursor.");
        var atoms = new ParsedDeepIdV2ContactRouteHistoryAtom[bytes[75]]; offset = HeaderBytes;
        for (var index = 0; index < atoms.Length; index++)
            atoms[index] = DecodeAtom(ReadAtom(bytes, ref offset), networkId16);
        return new(bytes.ToArray(), atoms);
    }

    internal static ParsedDeepIdV2ContactRouteHistoryAtom DecodeAtom(ReadOnlySpan<byte> bytes, ReadOnlySpan<byte> network)
    {
        if (bytes.Length < AtomPrefixBytes + ContactRouteAuthorityWireCodec.MinimumResponseBytes || bytes[0] is < 1 or > 2 ||
            bytes.Length > (bytes[0] == 1 ? MaximumProposalAtomBytes : MaximumCompletedAtomBytes) ||
            bytes.Slice(1, 32).IndexOfAnyExcept((byte)0) < 0 || bytes.Slice(41, 32).IndexOfAnyExcept((byte)0) < 0 ||
            bytes.Slice(546, 32).IndexOfAnyExcept((byte)0) < 0)
            throw new FormatException("Route history atom prefix is invalid.");
        var size = BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(1128));
        if (size is < ContactRouteAuthorityWireCodec.MinimumResponseBytes or > ContactRouteAuthorityWireCodec.MaximumResponseBytes ||
            size > bytes.Length - AtomPrefixBytes) throw new FormatException("Route history response length is invalid.");
        var end = AtomPrefixBytes + (int)size;
        if (bytes[0] == 1 ? end != bytes.Length : bytes.Length < end + 1258)
            throw new FormatException("Route history atom tail is invalid.");
        var dca = DeepIdV2ContactAuthorizationCodec.Decode(bytes.Slice(73, 473));
        var xra = ContactCodec.Decode(ProtocolMagic.XRA1, bytes.Slice(578, 550));
        if (!dca.NetworkId.Span.SequenceEqual(network) || !xra.Field(1).Span.SequenceEqual(network))
            throw new FormatException("Route history atom crosses networks.");
        var response = ContactRouteAuthorityWireCodec.DecodeResponse(network, bytes.Slice(1, 32), bytes.Slice(1132, (int)size));
        if (bytes[0] == 2)
        {
            var pmtLength = BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(end + 1254));
            if (pmtLength is < 842 or > 11066 || pmtLength != bytes.Length - end - 1258)
                throw new FormatException("Route history PMT length is invalid.");
            var invite = DeepIdV2InviteRendezvousCodec.Decode(bytes.Slice(end, 611));
            var xrr = ContactCodec.Decode(ProtocolMagic.XRR1, bytes.Slice(end + 611, 643));
            var pmt = ContactCodec.Decode(ProtocolMagic.PMT2, bytes[(end + 1258)..]);
            if (!invite.Field(1).Span.SequenceEqual(network) || !xrr.Field(1).Span.SequenceEqual(network) || !pmt.Field(1).Span.SequenceEqual(network))
                throw new FormatException("Completed history crosses networks.");
        }
        var result = new ParsedDeepIdV2ContactRouteHistoryAtom(bytes.ToArray(), response);
        if (result.IsCompleted)
        {
            var route = result.CompletedRoute; var invite = result.Invite;
            if (!invite.Field(3).Span.SequenceEqual(route.Reachability.Field(3).Span) ||
                !dca.PublisherDeviceId.Span.SequenceEqual(xra.Field(14).Span))
                throw new FormatException("Completed history changes its original generation or publisher.");
            DeepIdV2ContactRouteVerifier.RequireIdentityBindings(invite, route, network,
                ContactCodec.ArtifactReference(ProtocolMagic.PMT2, route.Projection).CanonicalBytes.Span,
                invite.Field(15).Span, new ContactArtifactReference(ProtocolMagic.DCA1, 2, dca.RecordHash.Span).CanonicalBytes.Span);
        }
        return result;
    }

    internal static byte[] Cursor(ParsedContactRouteClosure route, ContactRecord proposal, ContactRecord threshold)
    {
        var bytes = new byte[CursorBytes]; route.Reachability.Field(3).Span.CopyTo(bytes);
        route.Reachability.CoreHash.Span.CopyTo(bytes.AsSpan(8)); proposal.Field(3).Span.CopyTo(bytes.AsSpan(40));
        proposal.CoreHash.Span.CopyTo(bytes.AsSpan(48)); threshold.CoreHash.Span.CopyTo(bytes.AsSpan(80)); return bytes;
    }
    private static void ValidateCursor(ReadOnlySpan<byte> bytes)
    {
        foreach (var offset in new[] { 8, 48, 80 })
            if (bytes.Slice(offset, 32).IndexOfAnyExcept((byte)0) < 0) throw new FormatException("Route cursor contains a zero hash.");
    }
    private static ReadOnlySpan<byte> ReadAtom(ReadOnlySpan<byte> bytes, ref int offset)
    {
        if (offset > bytes.Length - 4) throw new FormatException("Route history atom is truncated.");
        var size = BinaryPrimitives.ReadUInt32BigEndian(bytes[offset..]); offset += 4;
        if (size is < AtomPrefixBytes + ContactRouteAuthorityWireCodec.MinimumResponseBytes or > MaximumCompletedAtomBytes || size > bytes.Length - offset)
            throw new FormatException("Route history atom length is invalid.");
        var atom = bytes.Slice(offset, (int)size); offset += (int)size; return atom;
    }
}
