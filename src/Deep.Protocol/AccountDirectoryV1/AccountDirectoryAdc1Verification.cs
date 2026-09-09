using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Sodium;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryAdc1VerificationException(string message)
    : CryptographicException(message);

/// <summary>
/// A checkpoint whose account identity closure, revocation list and device-issuer
/// signature have all been verified by the protocol-owned ADC1 verifier.
/// </summary>
public sealed class VerifiedAccountDirectoryCheckpoint
{
    private readonly byte[][] revokedDcaAuthorizationIds;

    internal VerifiedAccountDirectoryCheckpoint(
        AccountDirectoryAdc1 checkpoint,
        VerifiedDab1 binding,
        VerifiedDmd1 directory,
        IReadOnlyList<byte[]> revokedDcaAuthorizationIds)
    {
        Checkpoint = checkpoint;
        Binding = binding;
        Directory = directory;
        this.revokedDcaAuthorizationIds = revokedDcaAuthorizationIds
            .Select(static value => value.ToArray()).ToArray();
    }

    public AccountDirectoryAdc1 Checkpoint { get; }
    public VerifiedDab1 Binding { get; }
    public VerifiedDmd1 Directory { get; }
    public int RevokedDcaAuthorizationCount => revokedDcaAuthorizationIds.Length;

    public bool IsDcaAuthorizationRevoked(ReadOnlySpan<byte> authorizationId)
    {
        if (authorizationId.Length != 32 || authorizationId.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException(
                "A DCA authorization ID must be exactly 32 non-zero bytes.",
                nameof(authorizationId));

        var found = false;
        foreach (var revoked in revokedDcaAuthorizationIds)
            found |= CryptographicOperations.FixedTimeEquals(revoked, authorizationId);
        return found;
    }
}

public static class AccountDirectoryAdc1Verifier
{
    public const int MaximumRevokedDcaAuthorizationIds = 4096;
    internal const string LookupDomain = "Deep/AccountDirectory/V1/lookup";
    internal const string LeafDomain = "Deep/AccountDirectory/V1/leaf";
    internal const string RevokedDcaAuthorizationIdsDomain =
        "Deep/AccountDirectory/V1/revoked-DCA-authorization-ids";

    public static VerifiedAccountDirectoryCheckpoint Verify(
        AccountDirectoryAdc1 checkpoint,
        VerifiedDab1 binding,
        VerifiedDmd1 directory,
        IReadOnlyList<ReadOnlyMemory<byte>> revokedDcaAuthorizationIds,
        ushort supportedReader)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(directory);
        ArgumentNullException.ThrowIfNull(revokedDcaAuthorizationIds);
        if (supportedReader == 0)
            Reject("The caller supported reader version must be non-zero.");
        if (!ReferenceEquals(binding.Identity, directory.Identity))
            Reject("DAB1 and DMD1 do not share the exact verified identity instance.");

        var identity = binding.Identity;
        var account = identity.Account;
        if (!FixedEquals(checkpoint.NetworkId.Span, account.Certificate.NetworkId.Span) ||
            checkpoint.AccountGeneration != account.Certificate.AccountGeneration ||
            checkpoint.AccountGeneration != binding.Record.AccountGeneration ||
            checkpoint.AccountGeneration != directory.Record.AccountGeneration)
            Reject("ADC1 network or account generation differs from the verified identity closure.");

        var expectedLeaf = ComputeDirectoryLeafKey(
            account.Certificate.NetworkId.Span,
            binding.DeepId.CanonicalBytes.Span);
        if (!FixedEquals(checkpoint.DirectoryLeafKey.Span, expectedLeaf))
            Reject("ADC1 directory leaf does not derive from the exact DID1 canonical bytes.");

        var expectedDpaReference = CreateExactDnp1Reference(
            ProtocolMagicBytes.DPA1, account.Certificate.CanonicalHash.Span);
        var expectedDrsReference = CreateExactDnp1Reference(
            ProtocolMagicBytes.DRS1, identity.Revocations.Snapshot.CanonicalHash.Span);
        if (!FixedEquals(checkpoint.ExactDpa1Reference.Span, expectedDpaReference) ||
            !FixedEquals(checkpoint.ExactDrs1Reference.Span, expectedDrsReference))
            Reject("ADC1 does not contain the exact canonical DPA1/DRS1 external references.");
        if (!FixedEquals(checkpoint.ExactDmd1Hash.Span, directory.Record.RecordHash.Span) ||
            !FixedEquals(checkpoint.ExactDab1Hash.Span, binding.Record.RecordHash.Span))
            Reject("ADC1 DMD1/DAB1 hashes differ from the verified protocol record hashes.");

        var revoked = CopyAndValidateRevokedDcaAuthorizationIds(revokedDcaAuthorizationIds);
        var revokedHash = ComputeRevokedDcaAuthorizationIdsHash(revoked);
        if (!FixedEquals(checkpoint.RevokedDcaAuthorizationIdsHash.Span, revokedHash))
            Reject("ADC1 revoked DCA authorization IDs hash differs from the exact supplied list.");
        if (checkpoint.MinimumReader > supportedReader)
            Reject("ADC1 requires a newer reader than the caller supports.");

        try
        {
            if (!PublicKeyAuth.VerifyDetached(
                    checkpoint.DeviceIssuerSignature.ToArray(),
                    AccountDirectoryCrypto.ComputeAdc1SigningInput(checkpoint),
                    account.Certificate.DeviceIssuerEd25519PublicKey.ToArray()))
                Reject("ADC1 device-issuer signature is invalid.");
        }
        catch (Exception exception) when (exception is not AccountDirectoryAdc1VerificationException)
        {
            throw new AccountDirectoryAdc1VerificationException(
                $"ADC1 device-issuer signature verification failed: {exception.Message}");
        }

        return new VerifiedAccountDirectoryCheckpoint(checkpoint, binding, directory, revoked);
    }

    internal static byte[] ComputeDirectoryLeafKey(
        ReadOnlySpan<byte> networkId16,
        ReadOnlySpan<byte> exactDid1Canonical)
    {
        if (networkId16.Length != 16 || networkId16.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("Network ID must be exactly 16 non-zero bytes.", nameof(networkId16));
        if (exactDid1Canonical.IsEmpty)
            throw new ArgumentException("Exact DID1 canonical bytes may not be empty.", nameof(exactDid1Canonical));
        var lookupPreimage = new byte[checked(16 + exactDid1Canonical.Length)];
        networkId16.CopyTo(lookupPreimage);
        exactDid1Canonical.CopyTo(lookupPreimage.AsSpan(16));
        var lookup = AccountDirectoryCrypto.Sha256Domain(LookupDomain, lookupPreimage);
        return AccountDirectoryCrypto.Sha256Domain(LeafDomain, lookup);
    }

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
