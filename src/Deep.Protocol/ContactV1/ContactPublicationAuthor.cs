using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.ContactV1;

public enum ContactDeviceSignaturePurpose : byte
{
    PreKeyService = 1,
    ContactBundle = 2,
    RouteAdvertisement = 3,
    RouteReachability = 4,
    InviteRoute = 5,
    PermanentAddressPublication = 6,
    UpdateRendezvous = 7,
}

public sealed class ContactPublicationAuthoringException : CryptographicException
{
    internal ContactPublicationAuthoringException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>Custody boundary for one verified active Contact publisher device.</summary>
public interface IContactDeviceCustodySigner
{
    ReadOnlyMemory<byte> DeviceId { get; }
    ReadOnlyMemory<byte> Ed25519PublicKey { get; }
    ReadOnlyMemory<byte> CustodyDomainHash { get; }
    ValueTask<int> SignAsync(
        ContactDeviceSigningRequest request,
        Memory<byte> signature64,
        CancellationToken cancellationToken);
}

public sealed class ContactDeviceSigningRequest
{
    private readonly byte[] networkId;
    private readonly byte[] accountId;
    private readonly byte[] deviceId;
    private readonly byte[] custodyDomainHash;
    private readonly byte[] signingInput;
    private readonly byte[] signingInputHash;

    internal ContactDeviceSigningRequest(
        ContactDeviceSignaturePurpose purpose,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> accountId,
        ReadOnlySpan<byte> deviceId,
        ReadOnlySpan<byte> custodyDomainHash,
        ReadOnlySpan<byte> signingInput)
    {
        Purpose = purpose;
        this.networkId = networkId.ToArray();
        this.accountId = accountId.ToArray();
        this.deviceId = deviceId.ToArray();
        this.custodyDomainHash = custodyDomainHash.ToArray();
        this.signingInput = signingInput.ToArray();
        signingInputHash = SHA256.HashData(signingInput);
    }

    public ContactDeviceSignaturePurpose Purpose { get; }
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> AccountId => accountId.ToArray();
    public ReadOnlyMemory<byte> DeviceId => deviceId.ToArray();
    public ReadOnlyMemory<byte> CustodyDomainHash => custodyDomainHash.ToArray();
    public ReadOnlyMemory<byte> SigningInput => signingInput;
    public ReadOnlyMemory<byte> SigningInputSha256 => signingInputHash;

    internal void Clear()
    {
        CryptographicOperations.ZeroMemory(signingInput);
        CryptographicOperations.ZeroMemory(signingInputHash);
    }
}

/// <summary>Non-forgeable, device-signed exact XPS1 publication capability.</summary>
public sealed class VerifiedContactPreKeyService
{
    private readonly byte[] exactXps1;
    private readonly byte[] xps1Reference;
    private readonly byte[] networkId;
    private readonly byte[] serviceCapability;
    private readonly byte[] deviceId;
    private readonly byte[] dpd1Reference;

    internal VerifiedContactPreKeyService(
        ReadOnlySpan<byte> exactXps1,
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> serviceCapability,
        ReadOnlySpan<byte> deviceId,
        ReadOnlySpan<byte> dpd1Reference,
        ulong generation,
        ushort minimumOneTimeInventory,
        ushort lastResortReuseLimit,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds)
    {
        this.exactXps1 = exactXps1.ToArray();
        xps1Reference = CreateReference(SHA256.HashData(exactXps1));
        this.networkId = networkId.ToArray();
        this.serviceCapability = serviceCapability.ToArray();
        this.deviceId = deviceId.ToArray();
        this.dpd1Reference = dpd1Reference.ToArray();
        Generation = generation;
        MinimumOneTimeInventory = minimumOneTimeInventory;
        LastResortReuseLimit = lastResortReuseLimit;
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }

    public ReadOnlyMemory<byte> ExactXps1 => exactXps1.ToArray();
    public ReadOnlyMemory<byte> Xps1Reference => xps1Reference.ToArray();
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> ServiceCapability => serviceCapability.ToArray();
    public ReadOnlyMemory<byte> DeviceId => deviceId.ToArray();
    public ReadOnlyMemory<byte> Dpd1Reference => dpd1Reference.ToArray();
    public ulong Generation { get; }
    public ushort MinimumOneTimeInventory { get; }
    public ushort LastResortReuseLimit { get; }
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }

    private static byte[] CreateReference(ReadOnlySpan<byte> hash)
    {
        var result = new byte[38];
        ProtocolMagicBytes.XPS1.CopyTo(result);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash.CopyTo(result.AsSpan(6));
        return result;
    }
}

/// <summary>
/// CONTACT-PUBLICATION-AUTHOR-01. Authors only from verifier-minted identity,
/// directory freshness and route capabilities plus a bound device-custody signer.
/// </summary>
public static class ContactPublicationAuthor
{
    private const ushort Suite = 0x0201;

    private static void RequireSigner(IContactDeviceCustodySigner signer, DeviceCertificate device)
    {
        if (!Fixed(signer.DeviceId.Span, device.DeviceId.Span) ||
            !Fixed(signer.Ed25519PublicKey.Span, device.DeviceEd25519PublicKey.Span) ||
            signer.CustodyDomainHash.Length != 32 || IsZero(signer.CustodyDomainHash.Span))
            Fail("CustodySignerMismatch", "The Contact custody signer does not bind the verified device.");
    }

    private static async ValueTask<byte[]> SignAsync(
        ContactDeviceSignaturePurpose purpose,
        DeviceCertificate device,
        IContactDeviceCustodySigner signer,
        ReadOnlyMemory<byte> signingInput,
        CancellationToken cancellationToken)
    {
        var request = new ContactDeviceSigningRequest(
            purpose, device.NetworkId.Span, device.AccountHash.Span, device.DeviceId.Span,
            signer.CustodyDomainHash.Span, signingInput.Span);
        var signature = new byte[64];
        try
        {
            var written = await signer.SignAsync(request, signature, cancellationToken)
                .ConfigureAwait(false);
            if (written != signature.Length || IsZero(signature))
                Fail("InvalidCustodySignature", "The custody signer did not return one exact Ed25519 signature.");
            return signature;
        }
        finally
        {
            request.Clear();
        }
    }

    private static byte[] EncodeXps1(IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        if (fields.Count != 12)
            throw new ArgumentException("XPS1 requires exactly 12 fields.", nameof(fields));
        var total = checked(12 + fields.Sum(field => 8 + field.Length));
        var value = new byte[total];
        ProtocolMagicBytes.XPS1.CopyTo(value);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(6), Suite);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(8), 12);
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].Span.CopyTo(value.AsSpan(offset));
            offset += fields[index].Length;
        }
        _ = ContactCodec.DecodeXps1(value);
        return value;
    }

    private static byte[] ProjectXps1(ReadOnlySpan<byte> exact)
    {
        var end = 12;
        for (var tag = 1; tag <= 11; tag++)
            end = checked(end + 8 + (int)BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(end + 4, 4)));
        var projection = exact[..end].ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(projection.AsSpan(8), 11);
        return projection;
    }

    private static byte[] EncodeXpsList(IReadOnlyList<VerifiedContactPreKeyService> services)
    {
        var value = new byte[checked(1 + services.Sum(service => 4 + service.ExactXps1.Length))];
        value[0] = checked((byte)services.Count);
        var offset = 1;
        foreach (var service in services)
        {
            BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(offset), checked((uint)service.ExactXps1.Length));
            offset += 4;
            service.ExactXps1.Span.CopyTo(value.AsSpan(offset));
            offset += service.ExactXps1.Length;
        }
        return value;
    }

    private static byte[] EncodeReachability(ContactRecord exactXir1)
    {
        if (!StringComparer.Ordinal.Equals(exactXir1.Magic, ProtocolMagic.XIR1) ||
            exactXir1.CanonicalBytes.Length != 611)
            Fail("InvalidReachabilityDescriptor", "DCB1 requires one exact verified XIR1.");
        var value = new byte[651];
        BinaryPrimitives.WriteUInt16BigEndian(value, 1);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(2), 1);
        exactXir1.ArtifactHash.Span.CopyTo(value.AsSpan(4));
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(36), 611);
        exactXir1.CanonicalBytes.Span.CopyTo(value.AsSpan(40));
        return value;
    }

    private static byte[] EncodeSupport(VerifiedApplicationIdentityClosure identity)
    {
        var entries = new List<(ushort Kind, byte[] Hash, byte[] Exact)>
        {
            (1, identity.Revocations.Snapshot.CanonicalHash.ToArray(),
                identity.Revocations.Snapshot.CanonicalBytes.ToArray()),
        };
        entries.AddRange(identity.ActiveDevices.Select(device =>
            (Kind: (ushort)2, Hash: device.Certificate.CanonicalHash.ToArray(),
                Exact: device.Certificate.CanonicalBytes.ToArray())));
        entries.Sort(static (left, right) =>
        {
            var kind = left.Kind.CompareTo(right.Kind);
            return kind != 0 ? kind : left.Hash.AsSpan().SequenceCompareTo(right.Hash);
        });
        var value = new byte[checked(entries.Sum(entry => 6 + entry.Exact.Length))];
        var offset = 0;
        foreach (var entry in entries)
        {
            BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(offset), entry.Kind);
            BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(offset + 2), checked((uint)entry.Exact.Length));
            entry.Exact.CopyTo(value, offset + 6);
            offset += 6 + entry.Exact.Length;
        }
        return value;
    }

    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash)
    {
        var value = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        hash.CopyTo(value.AsSpan(6));
        return value;
    }

    private static byte[] RandomNonZero(int length)
    {
        var value = new byte[length];
        do RandomNumberGenerator.Fill(value); while (IsZero(value));
        return value;
    }

    private static byte[] PlaceholderSignature()
    {
        var value = new byte[64];
        value[0] = 1;
        return value;
    }

    private static byte[] Join(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        var value = new byte[checked(left.Length + right.Length)];
        left.CopyTo(value);
        right.CopyTo(value.AsSpan(left.Length));
        return value;
    }

    private static byte[] U16(ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] U32(uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static bool IsZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;

    private static ContactPublicationAuthoringException Error(string code, string message) =>
        new(code, message);

    private static void Fail(string code, string message) => throw Error(code, message);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static ByteArrayComparer Instance { get; } = new();
        public int Compare(byte[]? left, byte[]? right) =>
            left is null ? right is null ? 0 : -1 : right is null ? 1 : left.AsSpan().SequenceCompareTo(right);
    }
}
