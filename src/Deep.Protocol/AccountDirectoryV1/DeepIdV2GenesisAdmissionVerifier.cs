using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Exact public DID2 genesis artifacts. This is an untrusted request until
/// promoted by the V2 admission verifier, and contains no private material.
/// </summary>
public sealed class DeepIdV2GenesisAdmissionRequest
{
    private readonly byte[] dpa;
    private readonly byte[] drs;
    private readonly ReadOnlyMemory<byte>[] devices;
    private readonly byte[] did;
    private readonly byte[] dab;
    private readonly byte[] dmd;
    private readonly byte[] adc;
    private readonly ReadOnlyMemory<byte>[] revokedIds;

    public DeepIdV2GenesisAdmissionRequest(ReadOnlySpan<byte> exactDpa1,
        ReadOnlySpan<byte> exactDrs1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactDpd1,
        ReadOnlySpan<byte> exactDid2, ReadOnlySpan<byte> exactDab2,
        ReadOnlySpan<byte> exactDmd1, ReadOnlySpan<byte> exactAdc1V2,
        IReadOnlyList<ReadOnlyMemory<byte>> revokedDcaAuthorizationIds)
    {
        ArgumentNullException.ThrowIfNull(exactDpd1);
        ArgumentNullException.ThrowIfNull(revokedDcaAuthorizationIds);
        if (exactDpd1.Count is < 1 or > 5 ||
            revokedDcaAuthorizationIds.Count > 4096)
            throw new ArgumentOutOfRangeException(nameof(exactDpd1));
        dpa = Copy(exactDpa1, 644, nameof(exactDpa1));
        drs = Bounded(exactDrs1, 1, 16_384, nameof(exactDrs1));
        devices = exactDpd1.Select(value =>
            (ReadOnlyMemory<byte>)Copy(value.Span, 776, nameof(exactDpd1))).ToArray();
        did = Copy(exactDid2, DeepIdV2Codec.Did2Length, nameof(exactDid2));
        dab = Copy(exactDab2, DeepIdV2Codec.Dab2Length, nameof(exactDab2));
        dmd = Bounded(exactDmd1, 1, 57_344, nameof(exactDmd1));
        adc = Copy(exactAdc1V2, DeepIdV2AccountDirectoryCodec.CanonicalLength,
            nameof(exactAdc1V2));
        revokedIds = revokedDcaAuthorizationIds.Select(value =>
            (ReadOnlyMemory<byte>)Copy(value.Span, 32,
                nameof(revokedDcaAuthorizationIds))).ToArray();
    }

    public ReadOnlyMemory<byte> ExactDpa1 => dpa.ToArray();
    public ReadOnlyMemory<byte> ExactDrs1 => drs.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactDpd1 => Copy(devices);
    public ReadOnlyMemory<byte> ExactDid2 => did.ToArray();
    public ReadOnlyMemory<byte> ExactDab2 => dab.ToArray();
    public ReadOnlyMemory<byte> ExactDmd1 => dmd.ToArray();
    public ReadOnlyMemory<byte> ExactAdc1V2 => adc.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> RevokedDcaAuthorizationIds =>
        Copy(revokedIds);

    private static byte[] Copy(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw new ArgumentException($"{name} must be exactly {length} bytes.", name);
        return value.ToArray();
    }

    private static byte[] Bounded(ReadOnlySpan<byte> value, int minimum,
        int maximum, string name)
    {
        if (value.Length < minimum || value.Length > maximum)
            throw new ArgumentOutOfRangeException(name);
        return value.ToArray();
    }

    private static IReadOnlyList<ReadOnlyMemory<byte>> Copy(
        IEnumerable<ReadOnlyMemory<byte>> values) =>
        values.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
}

/// <summary>
/// Candidate DID2-only first-admission cryptographic boundary. No V1 decode,
/// fallback provider, or capability issuance occurs before every check passes.
/// </summary>
public static class DeepIdV2GenesisAdmissionVerifier
{
    public static VerifiedAdc1V2 Verify(DeepIdV2GenesisAdmissionRequest request,
        ulong trustedUnixSeconds, ushort deploymentProfileId,
        ushort supportedReader, IDeepMlDsa65Verifier mlDsa65)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(mlDsa65);
        if (trustedUnixSeconds == 0 || deploymentProfileId == 0 ||
            supportedReader < DeepIdV2AccountDirectoryCodec.Version)
            throw new ArgumentOutOfRangeException(nameof(supportedReader));

        try
        {
            var identityVerifier = new IdentityRelativeVerifier();
            var identity = identityVerifier.VerifyGenesis(
                request.ExactDpa1.Span, request.ExactDrs1.Span, [],
                trustedUnixSeconds);
            var devices = request.ExactDpd1.Select(value =>
                    identityVerifier.RestoreDeviceFromRecovery(identity, value.Span,
                        trustedUnixSeconds))
                .OrderBy(static value => value.Certificate.DeviceId.ToArray(),
                    ByteArrayComparer.Instance)
                .ToArray();
            var closure = ApplicationCoreVerifier.CreateIdentityClosure(
                identity, devices);
            var did = DeepIdV2Codec.DecodeDid2(request.ExactDid2.Span);
            var dab = DeepIdV2Codec.DecodeDab2(request.ExactDab2.Span);
            var binding = DeepIdV2Verifier.VerifyDab2(dab, did, closure,
                deploymentProfileId, mlDsa65);
            _ = DeepIdV2Verifier.StartDab2Lineage(binding);
            var directory = ApplicationCoreVerifier.VerifyDmd1(
                ApplicationCoreCodec.DecodeDmd1(request.ExactDmd1.Span), closure);
            var checkpoint = DeepIdV2AccountDirectoryCodec.Verify(
                DeepIdV2AccountDirectoryCodec.Decode(request.ExactAdc1V2.Span),
                binding, directory, request.RevokedDcaAuthorizationIds,
                supportedReader);
            if (checkpoint.Checkpoint.CheckpointGeneration != 0 ||
                checkpoint.Checkpoint.PredecessorCheckpointHash.Span
                    .IndexOfAnyExcept((byte)0) >= 0)
                throw new AccountDirectoryGenesisAdmissionException("NotGenesis",
                    "The first DID2 directory admission must be ADC1 V2 generation zero.");
            if (checkpoint.Checkpoint.IssuedAtUnixSeconds > trustedUnixSeconds)
                throw new AccountDirectoryGenesisAdmissionException("FutureDated",
                    "The first DID2 directory admission is future-dated.");
            return checkpoint;
        }
        catch (AccountDirectoryGenesisAdmissionException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or
            FormatException or CryptographicException or RecordException or
            OverflowException)
        {
            throw new AccountDirectoryGenesisAdmissionException("AdmissionRejected",
                "The exact DID2 genesis admission closure failed verification.",
                exception);
        }
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) =>
            left.AsSpan().SequenceCompareTo(right);
    }
}
