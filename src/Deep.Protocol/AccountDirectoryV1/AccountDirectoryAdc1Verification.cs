using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Sodium;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryAdc1VerificationException(string message)
    : CryptographicException(message);

public static class AccountDirectoryAdc1Verifier
{
    public const int MaximumRevokedDcaAuthorizationIds = 4096;
    internal const string RevokedDcaAuthorizationIdsDomain =
        "Deep/AccountDirectory/V1/revoked-DCA-authorization-ids";

    internal static byte[] ComputeRevokedDcaAuthorizationIdsHash(
        IReadOnlyList<ReadOnlyMemory<byte>> revokedDcaAuthorizationIds) =>
        ComputeRevokedDcaAuthorizationIdsHash(
            CopyAndValidateRevokedDcaAuthorizationIds(revokedDcaAuthorizationIds));

    private static byte[] ComputeRevokedDcaAuthorizationIdsHash(IReadOnlyList<byte[]> revoked)
    {
        var preimage = new byte[checked(4 + revoked.Count * 32)];
        BinaryPrimitives.WriteUInt32BigEndian(preimage, checked((uint)revoked.Count));
        for (var index = 0; index < revoked.Count; index++)
            revoked[index].CopyTo(preimage, 4 + index * 32);
        return AccountDirectoryCrypto.Sha256Domain(RevokedDcaAuthorizationIdsDomain, preimage);
    }

    private static byte[][] CopyAndValidateRevokedDcaAuthorizationIds(
        IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        if (values.Count > MaximumRevokedDcaAuthorizationIds)
            Reject($"ADC1 revoked DCA authorization ID count exceeds {MaximumRevokedDcaAuthorizationIds}.");
        var result = new byte[values.Count][];
        for (var index = 0; index < values.Count; index++)
        {
            var current = values[index].ToArray();
            if (current.Length != 32 || current.AsSpan().IndexOfAnyExcept((byte)0) < 0)
                Reject("Each revoked DCA authorization ID must be exactly 32 non-zero bytes.");
            if (index != 0 && result[index - 1].AsSpan().SequenceCompareTo(current) >= 0)
                Reject("Revoked DCA authorization IDs must be unique and strictly lexicographically sorted.");
            result[index] = current;
        }
        return result;
    }

    private static byte[] CreateExactDnp1Reference(
        ReadOnlySpan<byte> magic,
        ReadOnlySpan<byte> canonicalArtifactHash) =>
        AccountDirectoryCrypto.CreateReference(magic, 1, canonicalArtifactHash);

    private static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static void Reject(string message) =>
        throw new AccountDirectoryAdc1VerificationException(message);
}
