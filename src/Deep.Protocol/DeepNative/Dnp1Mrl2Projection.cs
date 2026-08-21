using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// Internal non-artifact projection used only by the MRL2 leaf calculation. It deliberately has
/// no public model, parser, reference, or authority conversion.
/// </summary>
internal static class Mrl2Projection
{
    internal const int Length = 326;

    internal static void WriteFromFull(ReadOnlySpan<byte> canonicalFullMrl2, Span<byte> destination)
    {
        if (canonicalFullMrl2.Length != Length || destination.Length != Length)
            throw new RecordException(RecordError.InvalidLength,
                "The MRL2 projection requires one exact full 326-byte row.");
        CanonicalGrammar.Preflight(canonicalFullMrl2, RecordDefinitions.Mrl2);
        canonicalFullMrl2.CopyTo(destination);
        ZeroField(destination, 5);
        ZeroField(destination, 9);
    }

    private static void ZeroField(Span<byte> canonical, int oneBasedTag)
    {
        var offset = CanonicalGrammar.HeaderLength;
        for (var tag = 1; tag <= oneBasedTag; tag++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                canonical.Slice(offset + 4, 4)));
            offset += CanonicalGrammar.FieldHeaderLength;
            if (tag == oneBasedTag)
            {
                if (length != ArtifactReference.Length)
                    throw new RecordException(RecordError.InvalidLength,
                        "The MRL2 projection reference field is malformed.");
                canonical.Slice(offset, length).Clear();
                return;
            }
            offset = checked(offset + length);
        }
        throw new RecordException(RecordError.InvalidTag,
            "The MRL2 projection field is absent.");
    }
}
