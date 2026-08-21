using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// An HMAC-verified DWH1 matched byte-for-byte to one already signature-verified
/// ReleaseRoot/DWD ancestry. It carries no recovery, mutation, or activation authority.
/// </summary>
public sealed class VerifiedWitnessHeadHistoryRelative
{
    private readonly byte[] _hash;

    internal VerifiedWitnessHeadHistoryRelative(
        ReleaseRootRestoreRelative releaseRoot,
        ushort entryCount,
        ReadOnlySpan<byte> hash)
    {
        ReleaseRoot = releaseRoot;
        EntryCount = entryCount;
        _hash = hash.ToArray();
    }

    public ReleaseRootRestoreRelative ReleaseRoot { get; }
    public ushort EntryCount { get; }
    public ReadOnlyMemory<byte> WitnessHeadHistoryHash => _hash.ToArray();
    public bool NoAuthorityClaim => true;
}

internal static class WitnessHeadHistoryRelativeVerifier
{
    internal static async ValueTask<VerifiedWitnessHeadHistoryRelative> VerifyAsync(
        ReleaseRootRestoreRelative releaseRoot,
        NormalRecoveryStoreInput protectedContainers,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(releaseRoot);
        ArgumentNullException.ThrowIfNull(protectedContainers);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();

        var dwh = protectedContainers.Dwh.ToArray();
        if (dwh.Length < RecoveryManifestParser.DwhFixedLength ||
            dwh.Length > RecoveryManifestParser.DwhFixedLength +
                64 * RecoveryManifestParser.DwhEntryLength ||
            !dwh.AsSpan(0, 4).SequenceEqual("DWH1"u8) ||
            dwh[4] != 1 || dwh[5] != 0)
            Invalid("The relative DWH1 header or length is invalid.");
        var count = BinaryPrimitives.ReadUInt16BigEndian(dwh.AsSpan(166, 2));
        if (count > 64 || dwh.Length != checked(
                RecoveryManifestParser.DwhFixedLength +
                count * RecoveryManifestParser.DwhEntryLength))
            Invalid("The relative DWH1 count and length differ.");

        await GenesisProtectedRecords.VerifyAsync(
            "Deep/ProtectedState/V1/DWH1",
            dwh,
            dwh.Length - 64,
            hmacProvider,
            cancellationToken).ConfigureAwait(false);

        var dwdCanonicals = releaseRoot.OrderedDwdCanonicals;
        var predecessorHeads = releaseRoot.OrderedPredecessorHeads;
        if (dwdCanonicals.Count is < 1 or > 65 ||
            predecessorHeads.Count != dwdCanonicals.Count ||
            count != dwdCanonicals.Count - 1)
            Invalid("DWH1 does not match the verified ReleaseRoot ancestry count.");

        for (var index = 1; index < dwdCanonicals.Count; index++)
        {
            var entry = dwh.AsSpan(
                168 + (index - 1) * RecoveryManifestParser.DwhEntryLength,
                RecoveryManifestParser.DwhEntryLength);
            var current = CutoverCodec.DecodeWitnessDelegation(dwdCanonicals[index]);
            var previous = CutoverCodec.DecodeWitnessDelegation(dwdCanonicals[index - 1]);
            var currentReference = CanonicalGrammar.EncodeReference(
                CanonicalGrammar.ComputeReference(
                    ArtifactType.Dwd1, dwdCanonicals[index]));
            if (!CanonicalGrammar.FixedEquals(entry[..38], currentReference) ||
                BinaryPrimitives.ReadUInt64BigEndian(entry[38..46]) !=
                    current.DelegationGeneration ||
                BinaryPrimitives.ReadUInt64BigEndian(entry[46..54]) !=
                    previous.WitnessEpoch ||
                !CanonicalGrammar.FixedEquals(entry[54..342], predecessorHeads[index]))
                Invalid("A DWH1 row differs from the verified DWD ancestry.");
            RecoveryCandidatePlan.VerifyDwhHeads(previous, current, entry[54..342]);
        }

        return new VerifiedWitnessHeadHistoryRelative(
            releaseRoot,
            count,
            RecoveryShadow.ComputeWitnessHeadHistoryHash(dwh));
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<VerifiedWitnessHeadHistoryRelative>
        VerifyWitnessHeadHistoryRelativeAsync(
            ReleaseRootRestoreRelative releaseRoot,
            NormalRecoveryStoreInput protectedContainers,
            IProtectedHmacProvider hmacProvider,
            CancellationToken cancellationToken = default) =>
        await WitnessHeadHistoryRelativeVerifier.VerifyAsync(
            releaseRoot, protectedContainers, hmacProvider, cancellationToken)
            .ConfigureAwait(false);
}
