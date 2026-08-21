namespace Deep.Protocol.DeepNative;

internal static class GenesisAuthorReplayVerifier
{
    internal static async ValueTask<GenesisAuthorJournalSnapshot> VerifyJournalSnapshotAsync(
        GenesisIdentityContext identity,
        GenesisResetReservationResult reservation,
        GenesisReplayLocalHeadData local,
        IProtectedHmacProvider protectedHmacProvider,
        CancellationToken cancellationToken)
    {
        var canonical = local.CanonicalJournal.ToArray();
        try
        {
            GenesisProtectedRecords.PreflightGaj(canonical, requireUnlatched: false);
            if (local.JournalSourceRevision == 0 ||
                local.JournalSourceRevision != Binary(canonical.AsSpan(807, 8)) ||
                !CanonicalGrammar.FixedEquals(canonical.AsSpan(8, 122),
                    GenesisReplayPrimitives.Scope(identity)) ||
                !CanonicalGrammar.FixedEquals(canonical.AsSpan(130, 32),
                    reservation.OperationId) ||
                !CanonicalGrammar.FixedEquals(canonical.AsSpan(162, 32),
                    reservation.ReservationHash.Span) ||
                !CanonicalGrammar.FixedEquals(canonical.AsSpan(816, 32),
                    identity.ProtectedStateHmacKeyId))
                Invalid("The locked GAJ1 snapshot differs from its sealed replay scope.");
            await GenesisProtectedRecords.VerifyAsync(
                "Deep/ProtectedState/V1/GAJ1", canonical,
                GenesisProtectedRecords.GajKeyOffset, protectedHmacProvider,
                cancellationToken).ConfigureAwait(false);
            return new GenesisAuthorJournalSnapshot(
                canonical, requireUnlatched: false);
        }
        finally { Array.Clear(canonical); }
    }

    internal static void VerifyJournalBindings(
        VerifiedGenesisArtifactSet artifacts,
        GenesisQuorumPending pending,
        GenesisAuthorJournalSnapshot journal)
    {
        var bytes = journal.CanonicalJournal.Span;
        if (!Same(bytes.Slice(493, 32), artifacts.Receipt.ReceiptHash.Span) ||
            !Same(bytes.Slice(525, 32), pending.PendingHash.Span) ||
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(bytes.Slice(557, 8)) !=
                System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(
                    pending.CanonicalPending.Span.Slice(379, 8)) ||
            !Same(bytes.Slice(775, 32),
                artifacts.Receipt.CanonicalReceipt.Span.Slice(164, 32)))
            Invalid("GAJ1 differs from the reminted GAS1/GQP1 state.");
        var types = new[]
        {
            ArtifactType.Drc1, ArtifactType.Dcp1, ArtifactType.Dcp1,
            ArtifactType.Dcp1, ArtifactType.Dcp1, ArtifactType.Dcs1, ArtifactType.Dct1
        };
        var offsets = new[] { 227, 265, 303, 341, 379, 417, 455 };
        for (var index = 0; index < types.Length; index++)
        {
            var reference = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                types[index], artifacts.Artifacts[index].Span));
            if (!Same(bytes.Slice(offsets[index], 38), reference))
                Invalid("GAJ1 differs from one retained genesis artifact reference.");
        }
    }

    private static bool Same(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        CanonicalGrammar.FixedEquals(left, right);
    private static ulong Binary(ReadOnlySpan<byte> value) =>
        System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(value);
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
