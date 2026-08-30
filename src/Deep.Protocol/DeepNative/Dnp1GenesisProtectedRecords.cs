using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepNative;

internal static class GenesisProtectedRecords
{
    internal const int GriLength = 217;
    internal const int GrrLength = 381;
    internal const int GtiLength = 243;
    internal const int GasLength = 285;
    internal const int GqpLength = 461;
    internal const int GqsLength = 580;
    internal const int GajLength = 880;
    internal const int GflLength = 1176;

    internal const int GriKeyOffset = 153;
    internal const int GrrKeyOffset = 317;
    internal const int GtiKeyOffset = 179;
    internal const int GasKeyOffset = 221;
    internal const int GqpKeyOffset = 397;
    internal const int GqsKeyOffset = 516;
    internal const int GajKeyOffset = 816;
    internal const int GflKeyOffset = 1112;

    internal static void PreflightGri(ReadOnlySpan<byte> value)
    {
        Header(value, GriLength, ProtocolMagicBytes.GRI1);
        Nonzero(value.Slice(8, 32), "GRI1 logical-scope hash");
        Nonzero(value.Slice(40, 32), "GRI1 intent hash");
        Nonzero(value.Slice(72, 32), "GRI1 operation ID");
        Nonzero(value.Slice(104, 32), "GRI1 reservation hash");
        PositiveU64(value.Slice(136, 8), "GRI1 source revision");
        PositiveU64(value.Slice(144, 8), "GRI1 retention horizon");
        if (value[152] != 0) Invalid("GRI1 is permanently fork-latched.");
        ProtectedTail(value, GriKeyOffset, ProtocolMagic.GRI1);
    }

    internal static void PreflightGrr(ReadOnlySpan<byte> value)
    {
        Header(value, GrrLength, ProtocolMagicBytes.GRR1);
        var mode = value[8];
        if (mode is not (1 or 2)) Invalid("GRR1 reservation mode is invalid.");
        Nonzero(value.Slice(9, 16), "GRR1 network");
        Nonzero(value.Slice(57, 32), "GRR1 new account hash");
        PositiveU64(value.Slice(89, 8), "GRR1 account generation");
        Nonzero(value.Slice(135, 38), "GRR1 new DPA reference");
        Nonzero(value.Slice(243, 32), "GRR1 operation ID");
        Nonzero(value.Slice(275, 32), "GRR1 reserved reset ID");
        if (value[307] != 1 || value[316] != 0)
            Invalid("GRR1 state or fork latch is invalid.");
        PositiveU64(value.Slice(308, 8), "GRR1 source revision");
        if (mode == 1)
        {
            if (!CanonicalGrammar.IsZero(value.Slice(25, 32)) ||
                !CanonicalGrammar.IsZero(value.Slice(97, 38)) ||
                !CanonicalGrammar.IsZero(value.Slice(173, 38)) ||
                !CanonicalGrammar.IsZero(value.Slice(211, 32)))
                Invalid("First-deployment GRR1 contains predecessor state.");
        }
        else if (CanonicalGrammar.IsZero(value.Slice(25, 32)) ||
                 CanonicalGrammar.IsZero(value.Slice(97, 38)) ||
                 CanonicalGrammar.IsZero(value.Slice(211, 32)) ||
                 CanonicalGrammar.FixedEquals(value.Slice(211, 32), value.Slice(275, 32)))
            Invalid("Account-reset GRR1 predecessor state is invalid.");
        ProtectedTail(value, GrrKeyOffset, ProtocolMagic.GRR1);
    }

    internal static void PreflightGti(ReadOnlySpan<byte> value)
    {
        Header(value, GtiLength, ProtocolMagicBytes.GTI1);
        Scope122(value.Slice(8, 122), ProtocolMagic.GTI1);
        Nonzero(value.Slice(130, 32), "GTI1 transaction ID");
        PositiveU64(value.Slice(162, 8), "GTI1 source revision");
        PositiveU64(value.Slice(170, 8), "GTI1 retention horizon");
        if (value[178] != 0) Invalid("GTI1 is permanently fork-latched.");
        ProtectedTail(value, GtiKeyOffset, ProtocolMagic.GTI1);
    }

    internal static void PreflightGas(ReadOnlySpan<byte> value)
    {
        Header(value, GasLength, ProtocolMagicBytes.GAS1);
        CommonAuthorScope(value, 8, ProtocolMagic.GAS1);
        if (BinaryPrimitives.ReadUInt16BigEndian(value.Slice(130, 2)) != 7)
            Invalid("GAS1 must contain exactly seven artifacts.");
        Nonzero(value.Slice(132, 32), "GAS1 inventory hash");
        Nonzero(value.Slice(164, 32), "GAS1 candidate core fingerprint");
        var total = BinaryPrimitives.ReadUInt64BigEndian(value.Slice(196, 8));
        if (total == 0 || total > 33_558_991)
            Invalid("GAS1 total bytes are outside the exact bound.");
        PositiveU64(value.Slice(204, 8), "GAS1 store revision");
        PositiveU64(value.Slice(212, 8), "GAS1 retention horizon");
        if (value[220] != 1) Invalid("GAS1 state is not Durable.");
        ProtectedTail(value, GasKeyOffset, ProtocolMagic.GAS1);
    }

    internal static void PreflightGqp(ReadOnlySpan<byte> value)
    {
        Header(value, GqpLength, ProtocolMagicBytes.GQP1);
        CommonQuorum(value, ProtocolMagic.GQP1);
        var ids = value.Slice(251, 96);
        StrictRows(ids, 32, "GQP1 witness IDs");
        Nonzero(value.Slice(347, 32), "GQP1 operation hash");
        PositiveU64(value.Slice(379, 8), "GQP1 source revision");
        PositiveU64(value.Slice(387, 8), "GQP1 retention horizon");
        if (value[395] != 1 || value[396] != 0)
            Invalid("GQP1 Pending state or fork latch is invalid.");
        ProtectedTail(value, GqpKeyOffset, ProtocolMagic.GQP1);
    }

    internal static void PreflightGqs(ReadOnlySpan<byte> value)
    {
        Header(value, GqsLength, ProtocolMagicBytes.GQS1);
        CommonQuorum(value, ProtocolMagic.GQS1);
        Span<byte> ids = stackalloc byte[96];
        for (var index = 0; index < 3; index++)
        {
            var row = value.Slice(251 + index * 70, 70);
            row[..32].CopyTo(ids.Slice(index * 32, 32));
            Nonzero(row.Slice(32, 38), "GQS1 DCN reference");
        }
        StrictRows(ids, 32, "GQS1 witness IDs");
        Nonzero(value.Slice(461, 38), "GQS1 DCQ reference");
        PositiveU64(value.Slice(499, 8), "GQS1 source revision");
        PositiveU64(value.Slice(507, 8), "GQS1 retention horizon");
        if (value[515] != 0) Invalid("GQS1 is permanently fork-latched.");
        ProtectedTail(value, GqsKeyOffset, ProtocolMagic.GQS1);
    }

    internal static void PreflightGaj(ReadOnlySpan<byte> value, bool requireUnlatched = true)
    {
        Header(value, GajLength, ProtocolMagicBytes.GAJ1);
        CommonAuthorScope(value, 8, ProtocolMagic.GAJ1);
        Nonzero(value.Slice(130, 32), "GAJ1 operation ID");
        Nonzero(value.Slice(162, 32), "GAJ1 reservation hash");
        var phase = value[194];
        if (phase > 2) Invalid("GAJ1 phase is invalid.");
        Nonzero(value.Slice(195, 32), "GAJ1 RSM hash");
        Nonzero(value.Slice(227, 38), "GAJ1 DRC reference");
        DistinctRows(value.Slice(265, 152), 38, "GAJ1 DCP references");
        Nonzero(value.Slice(417, 38), "GAJ1 DCS reference");
        Nonzero(value.Slice(455, 38), "GAJ1 DCT reference");
        Nonzero(value.Slice(493, 32), "GAJ1 artifact-set receipt hash");
        Nonzero(value.Slice(525, 32), "GAJ1 quorum-pending hash");
        PositiveU64(value.Slice(557, 8), "GAJ1 quorum-pending revision");
        Nonzero(value.Slice(775, 32), "GAJ1 candidate core fingerprint");
        PositiveU64(value.Slice(807, 8), "GAJ1 revision");
        if (requireUnlatched ? value[815] != 0 : value[815] > 1)
            Invalid("GAJ1 fork-latch state is invalid.");
        if (phase == 0)
        {
            Zero(value.Slice(565, 32), "Created GAJ1 quorum selection");
            Zero(value.Slice(597, 38), "Created GAJ1 DCQ reference");
            Zero(value.Slice(635, 140), "Created GAJ1 candidate/local source slots");
        }
        else
        {
            Nonzero(value.Slice(565, 32), "GAJ1 quorum-selection hash");
            Nonzero(value.Slice(597, 38), "GAJ1 DCQ reference");
            Nonzero(value.Slice(635, 38), "GAJ1 candidate DPL reference");
            Nonzero(value.Slice(673, 32), "GAJ1 candidate source fingerprint");
            if (phase == 1)
                Zero(value.Slice(705, 70), "ExternalCommitted GAJ1 local source slots");
            else if (!CanonicalGrammar.FixedEquals(value.Slice(635, 38), value.Slice(705, 38)) ||
                     !CanonicalGrammar.FixedEquals(value.Slice(673, 32), value.Slice(743, 32)))
                Invalid("LocalCommitted GAJ1 local source differs from candidate.");
        }
        ProtectedTail(value, GajKeyOffset, ProtocolMagic.GAJ1);
    }

    internal static void PreflightGfl(ReadOnlySpan<byte> value)
    {
        Header(value, GflLength, ProtocolMagicBytes.GFL1);
        var transcript = value.Slice(8, 1056);
        if (transcript[122] is < 1 or > 3)
            Invalid("GFL1 mismatch reason is invalid.");
        Nonzero(transcript.Slice(123, 32), "GFL1 expected GAJ hash");
        PositiveU64(transcript.Slice(155, 8), "GFL1 expected GAJ revision");
        Nonzero(value.Slice(1064, 32), "GFL1 evidence hash");
        PositiveU64(value.Slice(1096, 8), "GFL1 latch revision");
        PositiveU64(value.Slice(1104, 8), "GFL1 observed time");
        ProtectedTail(value, GflKeyOffset, ProtocolMagic.GFL1);
    }

    internal static async ValueTask<byte[]> AuthorAsync(
        string domain,
        ReadOnlyMemory<byte> unsigned,
        ReadOnlyMemory<byte> keyId,
        int expectedLength,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        cancellationToken.ThrowIfCancellationRequested();
        if (unsigned.Length != expectedLength - 32 || keyId.Length != 32 ||
            CanonicalGrammar.IsZero(keyId.Span))
            Invalid("The protected genesis authoring transcript is invalid.");
        var tag = (await provider.ComputeTagAsync(new ProtectedHmacRequest(
            domain, ArtifactRegistry.ProtectedHmacSha256, keyId.Span, unsigned.Span),
            cancellationToken).ConfigureAwait(false)).ToArray();
        cancellationToken.ThrowIfCancellationRequested();
        if (tag.Length != 32) Invalid("The protected genesis provider returned a wrong-length tag.");
        var canonical = new byte[expectedLength];
        unsigned.Span.CopyTo(canonical);
        tag.CopyTo(canonical, expectedLength - 32);
        CryptographicOperations.ZeroMemory(tag);
        return canonical;
    }

    internal static async ValueTask VerifyAsync(
        string domain,
        ReadOnlyMemory<byte> canonical,
        int keyOffset,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        var owned = canonical.ToArray();
        var returned = (await provider.ComputeTagAsync(new ProtectedHmacRequest(
            domain, ArtifactRegistry.ProtectedHmacSha256,
            owned.AsSpan(keyOffset, 32), owned.AsSpan(0, owned.Length - 32)),
            cancellationToken).ConfigureAwait(false)).ToArray();
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            if (returned.Length != 32 ||
                !CanonicalGrammar.FixedEquals(returned, owned.AsSpan(owned.Length - 32, 32)))
                throw new RecordException(RecordError.InvalidSignature,
                    "The protected genesis record HMAC is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(returned);
            CryptographicOperations.ZeroMemory(owned);
        }
    }

    internal static byte[] ReservationHash(ReadOnlySpan<byte> grr) =>
        CanonicalGrammar.Sha256Domain("Deep/Cutover/V4/genesis-reset-reservation", grr);

    internal static byte[] ArtifactSetReceiptHash(ReadOnlySpan<byte> gas) =>
        CanonicalGrammar.Sha256Domain("Deep/Cutover/V4/genesis-artifact-set-receipt", gas);

    internal static byte[] QuorumPendingHash(ReadOnlySpan<byte> gqp)
    {
        Span<byte> framed = stackalloc byte[4 + GqpLength];
        BinaryPrimitives.WriteUInt32BigEndian(framed, GqpLength);
        gqp.CopyTo(framed[4..]);
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V6/genesis-quorum-pending", framed);
    }

    internal static byte[] QuorumSelectionHash(ReadOnlySpan<byte> gqs)
    {
        Span<byte> framed = stackalloc byte[4 + GqsLength];
        BinaryPrimitives.WriteUInt32BigEndian(framed, GqsLength);
        gqs.CopyTo(framed[4..]);
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V5/genesis-quorum-selection", framed);
    }

    private static void Header(ReadOnlySpan<byte> value, int length, ReadOnlySpan<byte> magic)
    {
        if (value.Length != length || !value[..4].SequenceEqual(magic) ||
            value[4] != 1 || value.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            Invalid("The protected genesis record header is invalid.");
    }

    private static void Scope122(ReadOnlySpan<byte> scope, string name)
    {
        if (scope.Length != 122 || CanonicalGrammar.IsZero(scope[..16]) ||
            CanonicalGrammar.IsZero(scope.Slice(16, 32)) ||
            !Enum.IsDefined((ComponentKind)BinaryPrimitives.ReadUInt16BigEndian(scope.Slice(48, 2))) ||
            BinaryPrimitives.ReadUInt16BigEndian(scope.Slice(48, 2)) == 0 ||
            CanonicalGrammar.IsZero(scope.Slice(50, 32)) ||
            BinaryPrimitives.ReadUInt64BigEndian(scope.Slice(82, 8)) == 0 ||
            CanonicalGrammar.IsZero(scope.Slice(90, 32)))
            Invalid($"{name} exact scope is invalid.");
    }

    private static void CommonAuthorScope(ReadOnlySpan<byte> value, int offset, string name)
    {
        Nonzero(value.Slice(offset, 16), $"{name} network");
        Nonzero(value.Slice(offset + 16, 32), $"{name} reset ID");
        var kind = BinaryPrimitives.ReadUInt16BigEndian(value.Slice(offset + 48, 2));
        if (!Enum.IsDefined((ComponentKind)kind) || kind == 0)
            Invalid($"{name} component kind is invalid.");
        Nonzero(value.Slice(offset + 50, 32), $"{name} component subject");
        PositiveU64(value.Slice(offset + 82, 8), $"{name} account generation");
        Nonzero(value.Slice(offset + 90, 32), $"{name} transaction ID");
    }

    private static void CommonQuorum(ReadOnlySpan<byte> value, string name)
    {
        Nonzero(value.Slice(8, 16), $"{name} network");
        Nonzero(value.Slice(24, 32), $"{name} reset ID");
        Nonzero(value.Slice(56, 32), $"{name} deployment subject");
        PositiveU64(value.Slice(88, 8), $"{name} account generation");
        Nonzero(value.Slice(96, 32), $"{name} transaction ID");
        Nonzero(value.Slice(128, 38), $"{name} DCT reference");
        Nonzero(value.Slice(166, 38), $"{name} DCS reference");
        Nonzero(value.Slice(204, 38), $"{name} DWD reference");
        PositiveU64(value.Slice(242, 8), $"{name} witness epoch");
        if (value[250] != 3) Invalid($"{name} must select exactly three witnesses.");
    }

    private static void ProtectedTail(ReadOnlySpan<byte> value, int keyOffset, string name)
    {
        Nonzero(value.Slice(keyOffset, 32), $"{name} protected key ID");
        Nonzero(value[^32..], $"{name} HMAC");
    }

    private static void StrictRows(ReadOnlySpan<byte> rows, int width, string name)
    {
        ReadOnlySpan<byte> previous = default;
        for (var offset = 0; offset < rows.Length; offset += width)
        {
            var current = rows.Slice(offset, width);
            Nonzero(current, name);
            if (offset != 0 && previous.SequenceCompareTo(current) >= 0)
                Invalid($"{name} are not strictly sorted and unique.");
            previous = current;
        }
    }

    private static void DistinctRows(ReadOnlySpan<byte> rows, int width, string name)
    {
        for (var offset = 0; offset < rows.Length; offset += width)
        {
            var current = rows.Slice(offset, width);
            Nonzero(current, name);
            for (var prior = 0; prior < offset; prior += width)
                if (CanonicalGrammar.FixedEquals(current, rows.Slice(prior, width)))
                    Invalid($"{name} contain a duplicate.");
        }
    }

    private static void Nonzero(ReadOnlySpan<byte> value, string name)
    {
        if (CanonicalGrammar.IsZero(value)) Invalid($"{name} is zero.");
    }

    private static void Zero(ReadOnlySpan<byte> value, string name)
    {
        if (!CanonicalGrammar.IsZero(value)) Invalid($"{name} is not zero.");
    }

    private static void PositiveU64(ReadOnlySpan<byte> value, string name)
    {
        if (BinaryPrimitives.ReadUInt64BigEndian(value) == 0) Invalid($"{name} is zero.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public sealed class GenesisResetReservationResult
{
    private readonly byte[] _reservationHash;
    internal readonly byte[] IndexBytes;
    internal readonly byte[] ReservationBytes;
    internal GenesisResetReservationRequest? Request { get; }

    internal GenesisResetReservationResult(
        ReadOnlySpan<byte> gri,
        ReadOnlySpan<byte> grr,
        GenesisResetReservationRequest? request = null)
    {
        GenesisProtectedRecords.PreflightGri(gri);
        GenesisProtectedRecords.PreflightGrr(grr);
        var hash = GenesisProtectedRecords.ReservationHash(grr);
        if (!CanonicalGrammar.FixedEquals(gri.Slice(104, 32), hash) ||
            !CanonicalGrammar.FixedEquals(gri.Slice(72, 32), grr.Slice(243, 32)) ||
            BinaryPrimitives.ReadUInt64BigEndian(gri.Slice(136, 8)) !=
                BinaryPrimitives.ReadUInt64BigEndian(grr.Slice(308, 8)) ||
            !CanonicalGrammar.FixedEquals(gri.Slice(153, 32), grr.Slice(317, 32)))
            throw new RecordException(RecordError.InvalidField,
                "GRI1 and GRR1 do not describe the same reservation.");
        IndexBytes = gri.ToArray();
        ReservationBytes = grr.ToArray();
        Request = request;
        _reservationHash = hash;
    }

    public ReadOnlyMemory<byte> ReservationHash => _reservationHash.ToArray();
    public bool NoAuthorityClaim => true;
    internal ReadOnlySpan<byte> ResetId => ReservationBytes.AsSpan(275, 32);
    internal ReadOnlySpan<byte> OperationId => ReservationBytes.AsSpan(243, 32);
    internal ReadOnlySpan<byte> ProtectedKeyId => ReservationBytes.AsSpan(317, 32);
    internal ulong SourceRevision => BinaryPrimitives.ReadUInt64BigEndian(
        ReservationBytes.AsSpan(308, 8));
}

public sealed class GenesisTransactionReservation
{
    internal readonly byte[] Canonical;
    internal GenesisTransactionReservation(ReadOnlySpan<byte> canonical)
    {
        GenesisProtectedRecords.PreflightGti(canonical);
        Canonical = canonical.ToArray();
    }
    public bool NoAuthorityClaim => true;
    internal ReadOnlySpan<byte> ExactScope => Canonical.AsSpan(8, 122);
    internal ReadOnlySpan<byte> TransactionId => Canonical.AsSpan(130, 32);
    internal ReadOnlySpan<byte> ProtectedKeyId => Canonical.AsSpan(179, 32);
    internal ulong SourceRevision => BinaryPrimitives.ReadUInt64BigEndian(Canonical.AsSpan(162, 8));
}

public sealed class GenesisArtifactSetReceipt
{
    private readonly byte[] _canonical;
    private readonly byte[] _hash;
    internal GenesisArtifactSetReceipt(ReadOnlySpan<byte> canonical)
    {
        GenesisProtectedRecords.PreflightGas(canonical);
        _canonical = canonical.ToArray();
        _hash = GenesisProtectedRecords.ArtifactSetReceiptHash(canonical);
    }
    public ReadOnlyMemory<byte> CanonicalReceipt => _canonical.ToArray();
    public ReadOnlyMemory<byte> ReceiptHash => _hash.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisQuorumPending
{
    private readonly byte[] _canonical;
    private readonly byte[] _hash;
    internal GenesisQuorumPending(ReadOnlySpan<byte> canonical)
    {
        GenesisProtectedRecords.PreflightGqp(canonical);
        _canonical = canonical.ToArray();
        _hash = GenesisProtectedRecords.QuorumPendingHash(canonical);
    }
    public ReadOnlyMemory<byte> CanonicalPending => _canonical.ToArray();
    public ReadOnlyMemory<byte> PendingHash => _hash.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisQuorumSelection
{
    private readonly byte[] _canonical;
    private readonly byte[] _hash;
    internal GenesisQuorumSelection(ReadOnlySpan<byte> canonical)
    {
        GenesisProtectedRecords.PreflightGqs(canonical);
        _canonical = canonical.ToArray();
        _hash = GenesisProtectedRecords.QuorumSelectionHash(canonical);
    }
    public ReadOnlyMemory<byte> CanonicalSelection => _canonical.ToArray();
    public ReadOnlyMemory<byte> SelectionHash => _hash.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class GenesisAuthorJournalSnapshot
{
    private readonly byte[] _canonical;
    internal GenesisAuthorJournalSnapshot(
        ReadOnlySpan<byte> canonical,
        bool requireUnlatched = true)
    {
        GenesisProtectedRecords.PreflightGaj(canonical, requireUnlatched);
        _canonical = canonical.ToArray();
    }
    public ReadOnlyMemory<byte> CanonicalJournal => _canonical.ToArray();
    public bool NoAuthorityClaim => true;
    internal byte Phase => _canonical[194];
    internal bool ForkLatched => _canonical[815] == 1;
    internal ReadOnlySpan<byte> ProtectedKeyId => _canonical.AsSpan(816, 32);
}

public sealed class GenesisResetReservationRequest
{
    private readonly byte[] _intent;
    private readonly byte[] _logicalKey;

    internal GenesisResetReservationRequest(
        ReadOnlySpan<byte> exactIntent235,
        ReadOnlySpan<byte> exactLogicalKey)
    {
        if (exactIntent235.Length != 235 ||
            exactLogicalKey.Length is not (49 or 57) ||
            exactIntent235[0] is not (1 or 2) ||
            exactLogicalKey[0] != exactIntent235[0])
            Invalid();

        var mode = exactIntent235[0];
        var network = exactIntent235.Slice(1, 16);
        var oldAccountHash = exactIntent235.Slice(17, 32);
        var newAccountHash = exactIntent235.Slice(49, 32);
        var newGeneration = BinaryPrimitives.ReadUInt64BigEndian(exactIntent235.Slice(81, 8));
        var oldDpa = exactIntent235.Slice(89, 38);
        var newDpa = exactIntent235.Slice(127, 38);
        var predecessorDcm = exactIntent235.Slice(165, 38);
        var oldResetId = exactIntent235.Slice(203, 32);
        if (CanonicalGrammar.IsZero(network) ||
            CanonicalGrammar.IsZero(newAccountHash) ||
            newGeneration == 0 ||
            !IsReference(newDpa, ArtifactType.Dpa1) ||
            !CanonicalGrammar.FixedEquals(network, exactLogicalKey.Slice(1, 16)))
            Invalid();

        if (mode == 1)
        {
            if (exactLogicalKey.Length != 49 ||
                !CanonicalGrammar.IsZero(oldAccountHash) ||
                !CanonicalGrammar.IsZero(oldDpa) ||
                !CanonicalGrammar.IsZero(predecessorDcm) ||
                !CanonicalGrammar.IsZero(oldResetId) ||
                CanonicalGrammar.IsZero(exactLogicalKey.Slice(17, 32)))
                Invalid();
        }
        else
        {
            if (exactLogicalKey.Length != 57 ||
                CanonicalGrammar.IsZero(oldAccountHash) ||
                CanonicalGrammar.FixedEquals(oldAccountHash, newAccountHash) ||
                !IsReference(oldDpa, ArtifactType.Dpa1) ||
                !CanonicalGrammar.IsZero(predecessorDcm) ||
                CanonicalGrammar.IsZero(oldResetId) ||
                newGeneration == 1 ||
                BinaryPrimitives.ReadUInt64BigEndian(exactLogicalKey.Slice(17, 8)) !=
                    newGeneration - 1 ||
                !CanonicalGrammar.FixedEquals(oldAccountHash,
                    exactLogicalKey.Slice(25, 32)))
                Invalid();
        }
        _intent = exactIntent235.ToArray();
        _logicalKey = exactLogicalKey.ToArray();

        static bool IsReference(ReadOnlySpan<byte> encoded, ArtifactType expected)
        {
            try
            {
                var reference = CanonicalGrammar.DecodeReference(encoded);
                return reference.Type == expected && reference.CanonicalLength != 0 &&
                       !CanonicalGrammar.IsZero(reference.CanonicalHash.Span);
            }
            catch (RecordException)
            {
                return false;
            }
        }

        static void Invalid() => throw new RecordException(RecordError.InvalidField,
            "The sealed genesis reset reservation request is invalid.");
    }

    public ReadOnlyMemory<byte> Intent => _intent.ToArray();
    public ReadOnlyMemory<byte> LogicalKey => _logicalKey.ToArray();
    public ReadOnlyMemory<byte> LogicalScopeHash => CanonicalGrammar.Sha256Domain(
        "Deep/Cutover/V6/genesis-reset-logical-scope", FrameU16(_logicalKey));
    public ReadOnlyMemory<byte> IntentHash => CanonicalGrammar.Sha256Domain(
        "Deep/Cutover/V6/genesis-reset-intent", FrameU16(_intent));

    private static byte[] FrameU16(ReadOnlySpan<byte> value)
    {
        var output = new byte[2 + value.Length];
        BinaryPrimitives.WriteUInt16BigEndian(output, checked((ushort)value.Length));
        value.CopyTo(output.AsSpan(2));
        return output;
    }
}

public sealed class GenesisResetReservationReadResult
{
    private readonly byte[] _index;
    private readonly byte[] _reservation;

    public GenesisResetReservationReadResult(
        ReadOnlySpan<byte> canonicalGri217,
        ReadOnlySpan<byte> canonicalGrr381,
        bool healthy)
    {
        _index = canonicalGri217.ToArray();
        _reservation = canonicalGrr381.ToArray();
        Healthy = healthy;
    }

    public ReadOnlyMemory<byte> CanonicalIndex => _index.ToArray();
    public ReadOnlyMemory<byte> CanonicalReservation => _reservation.ToArray();
    public bool Healthy { get; }
}

public abstract class GenesisResetReservationProvider
{
    public abstract ValueTask<GenesisResetReservationReadResult> RestoreOrReserveAsync(
        GenesisResetReservationRequest request,
        CancellationToken cancellationToken);
}

public sealed class GenesisTransactionReservationRequest
{
    private readonly byte[] _scope;
    internal GenesisTransactionReservationRequest(ReadOnlySpan<byte> exactScope122)
    {
        // Exercise the same exact field validation without introducing a second grammar.
        var probe = new byte[GenesisProtectedRecords.GtiLength];
        ProtocolMagicBytes.GTI1.CopyTo(probe); probe[4] = 1;
        exactScope122.CopyTo(probe.AsSpan(8));
        probe.AsSpan(130, 32).Fill(1);
        BinaryPrimitives.WriteUInt64BigEndian(probe.AsSpan(162, 8), 1);
        BinaryPrimitives.WriteUInt64BigEndian(probe.AsSpan(170, 8), 1);
        probe.AsSpan(179, 64).Fill(1);
        GenesisProtectedRecords.PreflightGti(probe);
        _scope = exactScope122.ToArray();
    }
    public ReadOnlyMemory<byte> ExactScope => _scope.ToArray();
    public ReadOnlyMemory<byte> LogicalScopeHash => CanonicalGrammar.Sha256Domain(
        "Deep/Cutover/V7/genesis-transaction-logical-scope", Frame(_scope));
    private static byte[] Frame(ReadOnlySpan<byte> value)
    {
        var output = new byte[2 + value.Length];
        BinaryPrimitives.WriteUInt16BigEndian(output, checked((ushort)value.Length));
        value.CopyTo(output.AsSpan(2));
        return output;
    }
}

public sealed class GenesisTransactionReservationReadResult
{
    private readonly byte[] _canonical;
    public GenesisTransactionReservationReadResult(ReadOnlySpan<byte> canonicalGti243, bool healthy)
    { _canonical = canonicalGti243.ToArray(); Healthy = healthy; }
    public ReadOnlyMemory<byte> CanonicalTransactionIntent => _canonical.ToArray();
    public bool Healthy { get; }
}

public abstract class GenesisTransactionReservationProvider
{
    public abstract ValueTask<GenesisTransactionReservationReadResult> RestoreOrReserveAsync(
        GenesisTransactionReservationRequest request,
        CancellationToken cancellationToken);
}

internal static class GenesisReservationVerifier
{
    internal static async ValueTask<GenesisResetReservationResult> RestoreResetAsync(
        GenesisResetReservationProvider provider,
        GenesisResetReservationRequest request,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(request);
        var result = await provider.RestoreOrReserveAsync(request, cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (result is null || !result.Healthy)
            Invalid("The genesis reset reservation provider is absent or unhealthy.");
        var gri = result!.CanonicalIndex.ToArray();
        var grr = result.CanonicalReservation.ToArray();
        GenesisProtectedRecords.PreflightGri(gri);
        GenesisProtectedRecords.PreflightGrr(grr);
        if (!CanonicalGrammar.FixedEquals(gri.AsSpan(8, 32), request.LogicalScopeHash.Span) ||
            !CanonicalGrammar.FixedEquals(gri.AsSpan(40, 32), request.IntentHash.Span) ||
            !CanonicalGrammar.FixedEquals(grr.AsSpan(8, 235), request.Intent.Span))
            Invalid("The reset reservation differs from its sealed request.");
        await GenesisProtectedRecords.VerifyAsync("Deep/ProtectedState/V1/GRI1", gri,
            GenesisProtectedRecords.GriKeyOffset, hmacProvider, cancellationToken)
            .ConfigureAwait(false);
        await GenesisProtectedRecords.VerifyAsync("Deep/ProtectedState/V1/GRR1", grr,
            GenesisProtectedRecords.GrrKeyOffset, hmacProvider, cancellationToken)
            .ConfigureAwait(false);
        return new GenesisResetReservationResult(gri, grr, request);
    }

    internal static async ValueTask<GenesisTransactionReservation> RestoreTransactionAsync(
        GenesisTransactionReservationProvider provider,
        GenesisTransactionReservationRequest request,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(request);
        var result = await provider.RestoreOrReserveAsync(request, cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (result is null || !result.Healthy)
            Invalid("The genesis transaction provider is absent or unhealthy.");
        var canonical = result!.CanonicalTransactionIntent.ToArray();
        GenesisProtectedRecords.PreflightGti(canonical);
        if (!CanonicalGrammar.FixedEquals(canonical.AsSpan(8, 122), request.ExactScope.Span))
            Invalid("GTI1 differs from its sealed transaction scope.");
        await GenesisProtectedRecords.VerifyAsync("Deep/ProtectedState/V1/GTI1", canonical,
            GenesisProtectedRecords.GtiKeyOffset, hmacProvider, cancellationToken)
            .ConfigureAwait(false);
        return new GenesisTransactionReservation(canonical);
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
