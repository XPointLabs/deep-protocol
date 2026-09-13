using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryGenesisAdmissionException : CryptographicException
{
    internal AccountDirectoryGenesisAdmissionException(
        string code,
        string message,
        Exception? inner = null) : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Exact public artifacts supplied by an account for its first directory
/// admission. The object owns defensive copies and carries no verification or
/// authority claim.
/// </summary>
public sealed class AccountDirectoryGenesisAdmissionRequest
{
    private readonly byte[] exactDpa1;
    private readonly byte[] exactDrs1;
    private readonly ReadOnlyMemory<byte>[] exactDpd1;
    private readonly byte[] exactDid1;
    private readonly byte[] exactDab1;
    private readonly byte[] exactDmd1;
    private readonly byte[] exactAdc1;
    private readonly ReadOnlyMemory<byte>[] revokedDcaAuthorizationIds;

    public AccountDirectoryGenesisAdmissionRequest(
        ReadOnlySpan<byte> exactDpa1,
        ReadOnlySpan<byte> exactDrs1,
        IReadOnlyList<ReadOnlyMemory<byte>> exactDpd1,
        ReadOnlySpan<byte> exactDid1,
        ReadOnlySpan<byte> exactDab1,
        ReadOnlySpan<byte> exactDmd1,
        ReadOnlySpan<byte> exactAdc1,
        IReadOnlyList<ReadOnlyMemory<byte>> revokedDcaAuthorizationIds)
    {
        ArgumentNullException.ThrowIfNull(exactDpd1);
        ArgumentNullException.ThrowIfNull(revokedDcaAuthorizationIds);
        this.exactDpa1 = Bounded(exactDpa1, 1, 16_384, nameof(exactDpa1));
        this.exactDrs1 = Bounded(exactDrs1, 1, 16_384, nameof(exactDrs1));
        if (exactDpd1.Count is < 1 or > 5)
            throw new ArgumentOutOfRangeException(nameof(exactDpd1));
        this.exactDpd1 = exactDpd1.Select(value =>
            (ReadOnlyMemory<byte>)Bounded(value.Span, 1, 16_384, nameof(exactDpd1)))
            .ToArray();
        this.exactDid1 = Bounded(exactDid1, 1, 4_096, nameof(exactDid1));
        this.exactDab1 = Bounded(exactDab1, 1, 16_384, nameof(exactDab1));
        this.exactDmd1 = Bounded(exactDmd1, 1, 57_344, nameof(exactDmd1));
        this.exactAdc1 = Bounded(exactAdc1, 1, 16_384, nameof(exactAdc1));
        if (revokedDcaAuthorizationIds.Count >
            AccountDirectoryAdc1Verifier.MaximumRevokedDcaAuthorizationIds)
            throw new ArgumentOutOfRangeException(nameof(revokedDcaAuthorizationIds));
        this.revokedDcaAuthorizationIds = revokedDcaAuthorizationIds.Select(value =>
            (ReadOnlyMemory<byte>)ExactNonzero(value.Span, 32,
                nameof(revokedDcaAuthorizationIds))).ToArray();
    }

    public ReadOnlyMemory<byte> ExactDpa1 => exactDpa1.ToArray();
    public ReadOnlyMemory<byte> ExactDrs1 => exactDrs1.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactDpd1 => Copy(exactDpd1);
    public ReadOnlyMemory<byte> ExactDid1 => exactDid1.ToArray();
    public ReadOnlyMemory<byte> ExactDab1 => exactDab1.ToArray();
    public ReadOnlyMemory<byte> ExactDmd1 => exactDmd1.ToArray();
    public ReadOnlyMemory<byte> ExactAdc1 => exactAdc1.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> RevokedDcaAuthorizationIds =>
        Copy(revokedDcaAuthorizationIds);

    private static IReadOnlyList<ReadOnlyMemory<byte>> Copy(
        IEnumerable<ReadOnlyMemory<byte>> values) =>
        values.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();

    private static byte[] Bounded(
        ReadOnlySpan<byte> value,
        int minimum,
        int maximum,
        string name)
    {
        if (value.Length < minimum || value.Length > maximum)
            throw new ArgumentOutOfRangeException(name);
        return value.ToArray();
    }

    private static byte[] ExactNonzero(
        ReadOnlySpan<byte> value,
        int length,
        string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException(
                $"{name} entries must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }
}

/// <summary>
/// Re-verifies a first-admission closure from exact public artifacts. DPD1
/// restore here is intentionally contained inside this protocol-owned boundary:
/// both DPD1 signatures and its retained non-zero issuance possession binding
/// are verified, while no general possession-bypass API is exposed.
/// </summary>
public static class AccountDirectoryGenesisAdmissionVerifier
{
    public static VerifiedAccountDirectoryCheckpoint Verify(
        AccountDirectoryGenesisAdmissionRequest request,
        ulong trustedUnixSeconds,
        ushort deploymentProfileId,
        ushort supportedReader)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (trustedUnixSeconds == 0)
            throw new ArgumentOutOfRangeException(nameof(trustedUnixSeconds));
        if (deploymentProfileId == 0)
            throw new ArgumentOutOfRangeException(nameof(deploymentProfileId));
        if (supportedReader == 0)
            throw new ArgumentOutOfRangeException(nameof(supportedReader));

        try
        {
            var verifier = new IdentityRelativeVerifier();
            var identity = verifier.VerifyGenesis(
                request.ExactDpa1.Span,
                request.ExactDrs1.Span,
                [],
                trustedUnixSeconds);
            var devices = request.ExactDpd1
                .Select(value => verifier.RestoreDeviceFromRecovery(
                    identity,
                    value.Span,
                    trustedUnixSeconds))
                .OrderBy(static value => value.Certificate.DeviceId.ToArray(),
                    ByteArrayComparer.Instance)
                .ToArray();
            var closure = ApplicationCoreVerifier.CreateIdentityClosure(
                identity,
                devices);
            var did = ApplicationCoreCodec.DecodeDid1(request.ExactDid1.Span);
            var binding = ApplicationCoreVerifier.VerifyDab1(
                ApplicationCoreCodec.DecodeDab1(request.ExactDab1.Span),
                did,
                closure,
                deploymentProfileId);
            var directory = ApplicationCoreVerifier.VerifyDmd1(
                ApplicationCoreCodec.DecodeDmd1(request.ExactDmd1.Span),
                closure);
            var checkpoint = AccountDirectoryAdc1Verifier.Verify(
                AccountDirectoryAdc1Codec.Decode(request.ExactAdc1.Span),
                binding,
                directory,
                request.RevokedDcaAuthorizationIds,
                supportedReader);

            if (checkpoint.Checkpoint.CheckpointGeneration != 0 ||
                checkpoint.Checkpoint.PredecessorCheckpointHash.Span
                    .IndexOfAnyExcept((byte)0) >= 0)
                Reject("NotGenesis", "The first directory admission must be ADC1 generation zero.");
            if (checkpoint.Checkpoint.IssuedAt > trustedUnixSeconds)
                Reject("FutureDated", "The first directory admission is future-dated.");
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
            throw new AccountDirectoryGenesisAdmissionException(
                "AdmissionRejected",
                "The exact genesis account-directory closure failed verification.",
                exception);
        }
    }

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Reject(string code, string message) =>
        throw new AccountDirectoryGenesisAdmissionException(code, message);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) =>
            left.AsSpan().SequenceCompareTo(right);
    }
}
