using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.Identity;

/// <summary>
/// Compact, transport-neutral V2 descriptor. It commits to the exact DID2
/// record but is not itself a credential or a source of root public keys.
/// </summary>
public sealed class DeepPermanentIdV2 : IEquatable<DeepPermanentIdV2>
{
    private readonly byte[] did2Hash;
    private readonly byte[] readCapability;

    private DeepPermanentIdV2(string canonicalText,
        ReadOnlySpan<byte> did2Hash, ReadOnlySpan<byte> readCapability)
    {
        CanonicalText = canonicalText;
        this.did2Hash = did2Hash.ToArray();
        this.readCapability = readCapability.ToArray();
    }

    public string CanonicalText { get; }
    public ReadOnlyMemory<byte> ExactDid2Hash => did2Hash.ToArray();
    public ReadOnlyMemory<byte> ResolverReadCapability => readCapability.ToArray();

    public static DeepPermanentIdV2 FromCredential(ParsedDid2 exactDid2,
        ReadOnlySpan<byte> resolverReadCapability16)
    {
        ArgumentNullException.ThrowIfNull(exactDid2);
        if (!exactDid2.MatchesResolverReadCapability(
                resolverReadCapability16))
            throw new ArgumentException(
                "The read capability does not match the exact DID2 commitment.",
                nameof(resolverReadCapability16));
        return new DeepPermanentIdV2(
            DeepIdText.Encode(2, exactDid2.RecordHash.Span,
                resolverReadCapability16), exactDid2.RecordHash.Span,
            resolverReadCapability16);
    }

    public static DeepPermanentIdV2 ParseCanonical(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var (hash, capability) = DeepIdV2Codec.DecodeDeepIdText(text);
        return new DeepPermanentIdV2(text, hash, capability);
    }

    public bool MatchesExactCredential(ParsedDid2 exactDid2) =>
        exactDid2 is not null &&
        did2Hash.AsSpan().SequenceEqual(exactDid2.RecordHash.Span) &&
        exactDid2.MatchesResolverReadCapability(readCapability);

    public bool Equals(DeepPermanentIdV2? other) =>
        other is not null &&
        StringComparer.Ordinal.Equals(CanonicalText, other.CanonicalText);

    public override bool Equals(object? obj) => Equals(obj as DeepPermanentIdV2);
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(CanonicalText);
    public override string ToString() => CanonicalText;
}
