using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Untrusted compact positive-winner evidence carried inside one private route update.</summary>
public sealed class ParsedDeepIdV2ContactRouteRecoveryWitness
{
    private readonly byte[] exact;
    internal ParsedDeepIdV2ContactRouteRecoveryWitness(byte[] exact) => this.exact = exact;
    /// <summary>The canonical bounded witness bytes, without authority.</summary>
    public ReadOnlyMemory<byte> CanonicalBytes => exact.ToArray();
    /// <summary>The claimed signed completed anchor, independently joined to the actual previous route.</summary>
    public ReadOnlyMemory<byte> ExactCompletedAnchorXir1V2 => exact.AsMemory(4,611).ToArray();
    /// <summary>The number of exact positive proposal exchanges.</summary>
    public int PairCount => exact[1];
}

/// <summary>Compact kind14 evidence; it neither widens DMC2 nor creates a route capability.</summary>
public static class DeepIdV2ContactRouteRecoveryWitnessCodec
{
    public const int MinimumBytes = 3_825;
    public const int MaximumBytes = 28_549;
    private const int PrefixBytes = 615, PairPrefixBytes = 626;

    /// <summary>Encodes only the exact exchanges of an authenticated closed history.</summary>
    public static byte[] Encode(VerifiedDeepIdV2ContactRouteRecordedHistory history)
    {
        ArgumentNullException.ThrowIfNull(history);
        var size=checked(PrefixBytes+history.Pairs.Sum(pair=>PairPrefixBytes+pair.ExactResponse.Length));
        if(size>MaximumBytes)throw new CryptographicException("Private recovery witness exceeds the unchanged message capacity.");
        var bytes=new byte[size];bytes[0]=1;bytes[1]=checked((byte)history.Pairs.Count);
        history.Predecessor.ExactXir1V2.Span.CopyTo(bytes.AsSpan(4));var offset=PrefixBytes;
        foreach(var pair in history.Pairs)
        {
            var request=pair.Request;
            if(!DeepIdV2RouteContext.Fixed(request.ExactPredecessorXir1V2.Span,history.Predecessor.ExactXir1V2.Span)||
                !DeepIdV2RouteContext.Fixed(request.ExactPredecessorRouteClosure.Span,history.Predecessor.ExactRouteClosure.Span))
                throw new CryptographicException("Private recovery witness changed its exact completed anchor.");
            request.RequestNonce.Span.CopyTo(bytes.AsSpan(offset));BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(offset+32),request.MinimumAdh1Generation);
            request.MinimumAdh1CoreHash.Span.CopyTo(bytes.AsSpan(offset+40));request.ExactXra1.Span.CopyTo(bytes.AsSpan(offset+72));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset+622),checked((uint)pair.ExactResponse.Length));pair.ExactResponse.Span.CopyTo(bytes.AsSpan(offset+626));
            offset+=PairPrefixBytes+pair.ExactResponse.Length;
        }
        _=Decode(bytes);return bytes;
    }

    /// <summary>Parses bounded canonical data. All signatures and lineage still require independent verification.</summary>
    public static ParsedDeepIdV2ContactRouteRecoveryWitness Decode(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length is < MinimumBytes or > MaximumBytes||bytes[0]!=1||bytes[1] is <1 or >3||bytes[2]!=0||bytes[3]!=0)
            throw new FormatException("Private recovery witness framing is not canonical.");
        var anchor=DeepIdV2InviteRendezvousCodec.Decode(bytes.Slice(4,611));var offset=PrefixBytes;
        for(var index=0;index<bytes[1];index++)
        {
            var response=ReadPair(bytes,ref offset,out var start);
            if(bytes.Slice(start,32).IndexOfAnyExcept((byte)0)<0||bytes.Slice(start+40,32).IndexOfAnyExcept((byte)0)<0)
                throw new FormatException("Private recovery witness has a zero original request field.");
            var xra=ContactCodec.Decode(ProtocolMagic.XRA1,bytes.Slice(start+72,550));
            if(!DeepIdV2RouteContext.Fixed(xra.Field(1).Span,anchor.Field(1).Span))throw new FormatException("Private recovery witness crosses networks.");
            _=ContactRouteAuthorityWireCodec.DecodeResponse(anchor.Field(1).Span,bytes.Slice(start,32),response);
        }
        if(offset!=bytes.Length)throw new FormatException("Private recovery witness has trailing bytes.");
        return new(bytes.ToArray());
    }

    internal static VerifiedDeepIdV2ContactRouteRecordedHistory VerifyAtCurrentContext(
        ParsedDeepIdV2ContactRouteRecoveryWitness witness, ParsedContactRouteClosure previous, DeepIdV2RouteContext current)
    {
        var bytes=witness.CanonicalBytes;var anchor=DeepIdV2InviteRendezvousCodec.Decode(witness.ExactCompletedAnchorXir1V2.Span);
        if(DeepIdV2RouteContext.U64(anchor.Field(3).Span)!=DeepIdV2RouteContext.U64(previous.Reachability.Field(3).Span))
            throw new CryptographicException("Private recovery witness changed its actual completed generation.");
        DeepIdV2ContactRouteVerifier.RequirePredecessorBindings(anchor,previous,current);
        var predecessor=new VerifiedDeepIdV2ContactRoutePredecessor(anchor,previous);
        var pairs=new DeepIdV2ContactRouteRecordedPair[witness.PairCount];var offset=PrefixBytes;
        for(var index=0;index<pairs.Length;index++)
        {
            var response=ReadPair(bytes.Span,ref offset,out var start);
            var request=new ContactRouteAuthorityWireRequest(current.Network.NetworkId.Span,bytes.Span.Slice(start,32),
                current.Recipient.Freshness.QueriedDirectoryLeafKey.Span,BinaryPrimitives.ReadUInt64BigEndian(bytes.Span[(start+32)..]),bytes.Span.Slice(start+40,32),
                current.Recipient.Authorization.Record.CanonicalBytes.Span,bytes.Span.Slice(start+72,550),anchor.CanonicalBytes.Span,previous.ExactBytes.Span);
            pairs[index]=new(ContactRouteAuthorityWireCodec.EncodeRequest(request),response);
        }
        var history=new VerifiedDeepIdV2ContactRouteRecordedHistory(predecessor,pairs);history.RequireAtCurrentContext(current);return history;
    }

    private static ReadOnlySpan<byte> ReadPair(ReadOnlySpan<byte> bytes,ref int offset,out int start)
    {
        start=offset;if(offset>bytes.Length-PairPrefixBytes)throw new FormatException("Private recovery witness pair is truncated.");
        var size=BinaryPrimitives.ReadUInt32BigEndian(bytes[(offset+622)..]);
        if(size is <ContactRouteAuthorityWireCodec.MinimumResponseBytes or >ContactRouteAuthorityWireCodec.MaximumResponseBytes||size>bytes.Length-offset-PairPrefixBytes)
            throw new FormatException("Private recovery witness response length is invalid.");
        offset+=PairPrefixBytes+checked((int)size);return bytes.Slice(start+PairPrefixBytes,checked((int)size));
    }
}
