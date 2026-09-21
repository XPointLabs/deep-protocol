using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.ContactV1;

/// <summary>
/// Verified, device-authored generation-zero XUR1.  Raw ContactCodec.Author
/// remains disabled; this is the sole production authoring boundary for the
/// ContactHello update rendezvous.
/// </summary>
public sealed class VerifiedContactUpdateRendezvous
{
    internal VerifiedContactUpdateRendezvous(
        ContactRecord record,
        Dab1LineageState addressBinding,
        Dmd1LineageState directory)
    {
        Record = record;
        AddressBinding = addressBinding;
        Directory = directory;
    }

    public ContactRecord Record { get; }
    public Dab1LineageState AddressBinding { get; }
    public Dmd1LineageState Directory { get; }
    public ReadOnlyMemory<byte> ExactXur1 => Record.CanonicalBytes;
}

public static class ContactUpdateRendezvousAuthor
{
    /// <summary>
    /// Restores an author-minted XUR1 from protected local storage. The exact
    /// record is rebound to the current local identity, directory, confirmed
    /// publication route and metadata public key before the non-forgeable
    /// capability is returned.
    /// </summary>
    public static VerifiedContactUpdateRendezvous RecoverCurrent(
        ReadOnlySpan<byte> exactXur1,
        Dab1LineageState addressBinding,
        Dmd1LineageState directory,
        ParsedContactRouteClosure confirmedRoute,
        ReadOnlySpan<byte> metadataSealingKeyId,
        ReadOnlySpan<byte> metadataSealingX25519PublicKey,
        ulong trustedUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(addressBinding);
        ArgumentNullException.ThrowIfNull(directory);
        ArgumentNullException.ThrowIfNull(confirmedRoute);
        Require32(metadataSealingKeyId, nameof(metadataSealingKeyId));
        Require32(metadataSealingX25519PublicKey,
            nameof(metadataSealingX25519PublicKey));
        if (trustedUnixSeconds == 0 || addressBinding.ForkLatched ||
            directory.ForkLatched)
            throw new CryptographicException(
                "A current non-forked local authority is required to recover XUR1.");

        var record = ContactCodec.Decode(ProtocolMagic.XUR1, exactXur1);
        var account = addressBinding.Head.Identity.Account;
        var network = account.Certificate.NetworkId.Span;
        var accountId = account.DeepAccountIdHash.Span;
        var deviceId = record.Field(13).ToArray();
        var device = directory.Head.Identity.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.Certificate.DeviceId.Span, deviceId));
        var directoryEntry = directory.Head.Record.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.DeviceId.Span, deviceId));
        var expectedPmt2 = ContactCodec.ArtifactReference(
            ProtocolMagic.PMT2, confirmedRoute.Projection).CanonicalBytes;
        var expectedDpd1 = confirmedRoute.Authorization.Field(15);
        if (device is null || directoryEntry is null ||
            !Fixed(record.Field(1).Span, network) ||
            !Fixed(directory.Head.Record.NetworkId.Span, network) ||
            !Fixed(directory.Head.Record.DeepAccountId.Span, accountId) ||
            !Fixed(confirmedRoute.Authorization.Field(1).Span, network) ||
            !Fixed(confirmedRoute.Authorization.Field(14).Span, deviceId) ||
            !Fixed(record.Field(14).Span, expectedDpd1.Span) ||
            !Fixed(record.Field(6).Span, expectedPmt2.Span) ||
            !Fixed(record.Field(8).Span, metadataSealingKeyId) ||
            !Fixed(record.Field(9).Span, metadataSealingX25519PublicKey) ||
            BinaryPrimitives.ReadUInt64BigEndian(record.Field(4).Span) != 0 ||
            record.Field(5).Span.IndexOfAnyExcept((byte)0) >= 0 ||
            BinaryPrimitives.ReadUInt16BigEndian(record.Field(10).Span) != 0x0007 ||
            trustedUnixSeconds < ReadU64(record.Field(11).Span) ||
            trustedUnixSeconds > ReadU64(record.Field(12).Span))
        {
            throw new CryptographicException(
                "The protected XUR1 differs from the current local publication authority.");
        }

        try
        {
            ContactCodec.VerifyDeviceSignature(
                record, device.Certificate.DeviceEd25519PublicKey.Span);
            return new VerifiedContactUpdateRendezvous(
                record, addressBinding, directory);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(deviceId);
        }
    }

    public static async ValueTask<VerifiedContactUpdateRendezvous> AuthorGenesisAsync(
        Dab1LineageState addressBinding,
        Dmd1LineageState directory,
        VerifiedContactRouteClosure route,
        ReadOnlyMemory<byte> metadataSealingKeyId,
        ReadOnlyMemory<byte> metadataSealingX25519PublicKey,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        IContactDeviceCustodySigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(addressBinding);
        ArgumentNullException.ThrowIfNull(directory);
        ArgumentNullException.ThrowIfNull(route);
        ArgumentNullException.ThrowIfNull(signer);
        cancellationToken.ThrowIfCancellationRequested();
        if (addressBinding.ForkLatched || directory.ForkLatched)
            throw new CryptographicException(
                "A forked local identity cannot author XUR1.");
        Require32(metadataSealingKeyId.Span, nameof(metadataSealingKeyId));
        Require32(metadataSealingX25519PublicKey.Span,
            nameof(metadataSealingX25519PublicKey));
        if (issuedAtUnixSeconds == 0 || issuedAtUnixSeconds >= expiresAtUnixSeconds ||
            expiresAtUnixSeconds - issuedAtUnixSeconds > 2_592_000)
            throw new ArgumentOutOfRangeException(nameof(expiresAtUnixSeconds));

        var localAccount = addressBinding.Head.Identity.Account;
        var currentDirectory = directory.Head;
        var network = localAccount.Certificate.NetworkId.Span;
        var accountId = localAccount.DeepAccountIdHash.Span;
        var device = currentDirectory.Identity.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.Certificate.DeviceId.Span, signer.DeviceId.Span));
        var directoryEntry = currentDirectory.Record.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.DeviceId.Span, signer.DeviceId.Span));
        var dpd1Reference = route.Authorization.Field(15);
        var devicePublicKey = device is null
            ? ReadOnlyMemory<byte>.Empty
            : device.Certificate.DeviceEd25519PublicKey;
        var differences = new List<string>();
        if (device is null) differences.Add("device");
        if (directoryEntry is null) differences.Add("directory-entry");
        if (!Fixed(currentDirectory.Record.NetworkId.Span, network))
            differences.Add("directory-network");
        if (!Fixed(currentDirectory.Record.DeepAccountId.Span, accountId))
            differences.Add("directory-account");
        if (!Fixed(route.Reachability.Field(1).Span, network))
            differences.Add("route-network");
        if (!Fixed(route.Authorization.Field(1).Span, network))
            differences.Add("authorization-network");
        if (!Fixed(route.Authorization.Field(14).Span, signer.DeviceId.Span))
            differences.Add("authorization-device");
        if (!Fixed(signer.Ed25519PublicKey.Span, devicePublicKey.Span))
            differences.Add("custody-key");
        var routeNotBefore = ReadU64(route.Authorization.Field(12).Span);
        var routeExpires = Math.Min(
            ReadU64(route.Authorization.Field(13).Span),
            ReadU64(route.Reachability.Field(17).Span));
        if (differences.Count != 0 || issuedAtUnixSeconds < routeNotBefore ||
            expiresAtUnixSeconds > routeExpires)
            throw new CryptographicException(
                differences.Count != 0
                    ? $"The XUR1 authoring request differs from the current route/device authority ({string.Join(',', differences)})."
                    : "The XUR1 validity interval is outside the current route authority.");

        var fields = new ReadOnlyMemory<byte>[]
        {
            network.ToArray(),
            RandomNonZero32(),
            RandomNonZero32(),
            U64(0),
            new byte[32],
            ContactCodec.ArtifactReference(ProtocolMagic.PMT2, route.Projection)
                .CanonicalBytes,
            RandomNonZero32(),
            metadataSealingKeyId.ToArray(),
            metadataSealingX25519PublicKey.ToArray(),
            U16(0x0007),
            U64(issuedAtUnixSeconds),
            U64(expiresAtUnixSeconds),
            signer.DeviceId.ToArray(),
            dpd1Reference,
            PlaceholderSignature()
        };
        var provisional = ContactCodec.AuthorForOperationalAuthority(
            ProtocolMagic.XUR1, fields);
        var request = new ContactDeviceSigningRequest(
            ContactDeviceSignaturePurpose.UpdateRendezvous,
            network,
            accountId,
            signer.DeviceId.Span,
            signer.CustodyDomainHash.Span,
            provisional.SignatureInput.Span);
        var signature = new byte[64];
        try
        {
            var written = await signer.SignAsync(
                    request, signature, cancellationToken)
                .ConfigureAwait(false);
            if (written != 64 || signature.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !PublicKeyAuth.VerifyDetached(
                    signature,
                    provisional.SignatureInput.ToArray(),
                    signer.Ed25519PublicKey.ToArray()))
                throw new CryptographicException(
                    "The XUR1 device custody signature is invalid.");
            fields[14] = signature.ToArray();
            var record = ContactCodec.AuthorForOperationalAuthority(
                ProtocolMagic.XUR1, fields);
        ContactCodec.VerifyDeviceSignature(
            record, device!.Certificate.DeviceEd25519PublicKey.Span);
            return new VerifiedContactUpdateRendezvous(
                record, addressBinding, directory);
        }
        finally
        {
            request.Clear();
            CryptographicOperations.ZeroMemory(signature);
            foreach (var field in fields)
            {
                if (!field.IsEmpty)
                    CryptographicOperations.ZeroMemory(
                        MemoryMarshal.AsMemory(field).Span);
            }
        }
    }

    private static byte[] RandomNonZero32()
    {
        var result = new byte[32];
        do RandomNumberGenerator.Fill(result);
        while (result.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return result;
    }

    private static byte[] PlaceholderSignature()
    {
        var value = new byte[64];
        value[^1] = 1;
        return value;
    }

    private static byte[] U16(ushort value)
    {
        var result = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static ulong ReadU64(ReadOnlySpan<byte> value) =>
        value.Length == sizeof(ulong)
            ? BinaryPrimitives.ReadUInt64BigEndian(value)
            : throw new CryptographicException("The verified route time is malformed.");

    private static void Require32(ReadOnlySpan<byte> value, string name)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException(
                "XUR1 metadata key material must be 32 nonzero bytes.", name);
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);
}
