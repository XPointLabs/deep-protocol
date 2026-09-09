using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// Internal, non-artifact DPD1/DNR1 pre-PoP projection. Projection bytes are
/// deliberately never exposed by a public model or parser.
/// </summary>
internal static class DxpSubjectProjection
{
    private const string Domain = "Deep/IdentityAuth/V1/x25519-pop-subject";

    internal static byte[] HashDevice(OwnedRecord record) =>
        Hash(EncodeDevice(record), X25519PossessionRole.Device);

    internal static byte[] EncodeDevice(OwnedRecord record) =>
        Encode(record, 21, 22, 23, 632);

    internal static byte[] HashRouter(OwnedRecord record) =>
        Hash(Encode(record, 19, 20, 21, 612), X25519PossessionRole.Router);

    private static byte[] Encode(
        OwnedRecord record,
        int transcriptTag,
        int firstOmittedTag,
        int secondOmittedTag,
        int expectedLength)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (record.Definition.Fields.Count != secondOmittedTag ||
            transcriptTag + 1 != firstOmittedTag || firstOmittedTag + 1 != secondOmittedTag)
            throw new RecordException(RecordError.InvalidField,
                "The DXP subject projection definition is invalid.");

        var fields = new ReadOnlyMemory<byte>[transcriptTag];
        for (var tag = 1; tag < transcriptTag; tag++) fields[tag - 1] = record.FieldCopy(tag);
        fields[transcriptTag - 1] = new byte[32];
        var definition = record.Definition with
        {
            Fields = record.Definition.Fields.Take(transcriptTag).ToArray(),
            MinimumLength = expectedLength,
            MaximumLength = expectedLength,
            OmittedSigningFieldIndexes = new HashSet<int>()
        };
        var projection = CanonicalGrammar.Encode(definition, fields);
        if (projection.Length != expectedLength)
            throw new RecordException(RecordError.InvalidLength,
                "The DXP subject projection length is invalid.");

        return projection;
    }

    private static byte[] Hash(ReadOnlySpan<byte> projection, X25519PossessionRole role)
    {
        var payload = new byte[1 + 4 + projection.Length];
        payload[0] = (byte)role;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1, 4), checked((uint)projection.Length));
        projection.CopyTo(payload.AsSpan(5));
        return CanonicalGrammar.Sha256Domain(Domain, payload);
    }
}
