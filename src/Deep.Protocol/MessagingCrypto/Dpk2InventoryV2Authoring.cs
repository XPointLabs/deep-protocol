using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;

namespace Deep.Protocol.MessagingCrypto;

/// <summary>
/// An exact DID2 inventory and its exclusive private pre-key capabilities.
/// This is local authoring output, not a replica commit or publication receipt.
/// The caller must durably seal every offering before dispatching ExactXpp1.
/// </summary>
public sealed class AuthoredDpk2InventoryV2 : IDisposable
{
    private readonly byte[] exactXpi1;
    private readonly byte[] exactXpp1;
    private readonly IReadOnlyList<AuthoredDpk2Offering> oneTime;
    private readonly AuthoredDpk2Offering lastResort;
    private int disposed;

    internal AuthoredDpk2InventoryV2(byte[] exactXpi1, byte[] exactXpp1,
        AuthoredDpk2Offering[] oneTime, AuthoredDpk2Offering lastResort)
    {
        this.exactXpi1 = exactXpi1;
        this.exactXpp1 = exactXpp1;
        this.oneTime = Array.AsReadOnly(oneTime);
        this.lastResort = lastResort;
    }

    ~AuthoredDpk2InventoryV2() => Dispose();

    public ReadOnlyMemory<byte> ExactXpi1 => exactXpi1.ToArray();
    public ReadOnlyMemory<byte> ExactXpp1 => exactXpp1.ToArray();
    public IReadOnlyList<AuthoredDpk2Offering> OneTimeOfferings => oneTime;
    public AuthoredDpk2Offering LastResortOffering => lastResort;

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        foreach (var offering in oneTime) offering.Dispose();
        lastResort.Dispose();
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Public DID2 device-signed XPS1 V2 support for one inventory generation.
/// It contains no pre-key private material or network publication authority.
/// </summary>
public sealed class AuthoredDeepIdV2PreKeyService
{
    private readonly byte[] exact;
    private readonly byte[] capability;
    private readonly byte[] reference;

    internal AuthoredDeepIdV2PreKeyService(byte[] exact,
        byte[] capability)
    {
        this.exact = exact.ToArray();
        this.capability = capability.ToArray();
        reference = new byte[38];
        ProtocolMagicBytes.XPS1.CopyTo(reference);
        BinaryPrimitives.WriteUInt16BigEndian(reference.AsSpan(4), 2);
        SHA256.HashData(exact).CopyTo(reference, 6);
    }

    public ReadOnlyMemory<byte> ExactXps1 => exact.ToArray();
    public ReadOnlyMemory<byte> ServiceCapability => capability.ToArray();
    public ReadOnlyMemory<byte> Xps1Reference => reference.ToArray();
}

public sealed partial class Dpk2AuthoringAuthority
{
    /// <summary>
    /// Authors XPS1 V2 under the same locally protected DPD1 signing seed as
    /// the DID2 inventory. Initial generation is one; a successor retains the
    /// capability and names the exact signed predecessor.
    /// </summary>
    public AuthoredDeepIdV2PreKeyService AuthorPreKeyServiceV2(
        Dpk2AuthoringContext context, VerifiedDab2 did2Binding,
        ushort minimumOneTimeInventory, ushort lastResortReuseLimit,
        ReadOnlySpan<byte> exactPredecessorXps1 = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(did2Binding);
        if (minimumOneTimeInventory is < 1 or > 4096 ||
            lastResortReuseLimit is < 1 or > 64 ||
            context.PrekeyServiceGeneration == 0)
            throw new ArgumentException(
                "The DID2 pre-key service policy is outside its closed bound.");
        lock (_gate)
        {
            ThrowIfDisposed();
            var current = _deviceAgreement
                .RequireActiveDirectoryForProtocolOperation(
                    context.CurrentDirectory);
            if (!current.Identity.Account.Certificate.CanonicalBytes.Span
                    .SequenceEqual(did2Binding.Identity.Account.Certificate
                        .CanonicalBytes.Span) ||
                !current.Record.DeepAccountId.Span.SequenceEqual(
                    did2Binding.Record.DeepAccountId.Span) ||
                !current.Record.NetworkId.Span.SequenceEqual(
                    did2Binding.Identity.Account.Certificate.NetworkId.Span))
                throw new CryptographicException(
                    "The DID2 pre-key service is outside the active account.");
            var certificate = current.Identity.ActiveDevices.Single(device =>
                device.Certificate.DeviceId.Span.SequenceEqual(
                    _deviceAgreement.DeviceId.Span)).Certificate;
            byte[] capability;
            byte[] predecessorHash;
            if (exactPredecessorXps1.IsEmpty)
            {
                if (context.PrekeyServiceGeneration != 1)
                    throw new CryptographicException(
                        "An XPS1 V2 successor requires its exact predecessor.");
                capability = RandomNonzero32();
                predecessorHash = new byte[32];
            }
            else
            {
                var predecessor = DeepIdV2PreKeyServiceCodec.Decode(
                    exactPredecessorXps1);
                DeepIdV2PreKeyServiceCodec.VerifyDeviceSignature(predecessor,
                    certificate.DeviceEd25519PublicKey.Span);
                if (!predecessor.Field(1).Span.SequenceEqual(
                        current.Record.NetworkId.Span) ||
                    !predecessor.Field(3).Span.SequenceEqual(
                        certificate.DeviceId.Span) ||
                    !predecessor.Field(4).Span.SequenceEqual(
                        Dpd1Reference(certificate.CanonicalHash.Span)) ||
                    BinaryPrimitives.ReadUInt64BigEndian(
                        predecessor.Field(5).Span) + 1 !=
                        context.PrekeyServiceGeneration)
                    throw new CryptographicException(
                        "The XPS1 V2 predecessor is outside this device lineage.");
                capability = predecessor.Field(2).ToArray();
                predecessorHash = SHA256.HashData(exactPredecessorXps1);
            }
            ReadOnlyMemory<byte>[] fields =
            [
                current.Record.NetworkId, capability, certificate.DeviceId,
                Dpd1Reference(certificate.CanonicalHash.Span),
                U64(context.PrekeyServiceGeneration), predecessorHash,
                U16(DeepIdV2Codec.Suite), U16(minimumOneTimeInventory),
                U16(lastResortReuseLimit), U64(context.IssuedAtUnixSeconds),
                U64(context.ExpiresAtUnixSeconds)
            ];
            var signature = Sign(DeepIdV2PreKeyServiceCodec
                .CreateSignatureInput(fields));
            try
            {
                var exact = DeepIdV2PreKeyServiceCodec.Encode(fields,
                    signature);
                DeepIdV2PreKeyServiceCodec.VerifyDeviceSignature(
                    DeepIdV2PreKeyServiceCodec.Decode(exact),
                    certificate.DeviceEd25519PublicKey.Span);
                return new AuthoredDeepIdV2PreKeyService(exact, capability);
            }
            finally { CryptographicOperations.ZeroMemory(signature); }
        }
    }

    /// <summary>
    /// Authors one complete DID2-only V2 inventory from the exact active DMD1
    /// and one signed XPS1 V2 service object. Separate raw capability and
    /// reference inputs are not accepted. No V1 codec, caller-supplied signer,
    /// raw private key or network write is involved. The result is not safe to dispatch before all
    /// private capabilities are durably committed by the account owner.
    /// </summary>
    public AuthoredDpk2InventoryV2 AuthorInventoryV2(
        Dpk2AuthoringContext context,
        VerifiedDab2 did2Binding,
        AuthoredDeepIdV2PreKeyService service,
        ReadOnlySpan<byte> currentDrs1Reference38,
        ReadOnlySpan<byte> predecessorXpi1Hash32,
        ReadOnlySpan<byte> publicationOperationId32,
        ReadOnlySpan<byte> placementHash32,
        ushort oneTimePreKeyCount,
        ushort lastResortReuseLimit)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(did2Binding);
        ArgumentNullException.ThrowIfNull(service);
        if (oneTimePreKeyCount is < 32 or > 4096 ||
            lastResortReuseLimit is < 1 or > 64 ||
            context.PrekeyServiceGeneration == 0 ||
            context.InventoryEpoch is < 1 or > 14)
            throw new ArgumentException("The DID2 inventory policy is outside its closed bound.");
        Reference(currentDrs1Reference38, ProtocolMagicBytes.DRS1,
            nameof(currentDrs1Reference38));
        Nonzero(publicationOperationId32, 32,
            nameof(publicationOperationId32));
        Nonzero(placementHash32, 32, nameof(placementHash32));
        if (predecessorXpi1Hash32.Length != 32 ||
            (predecessorXpi1Hash32.IndexOfAnyExcept((byte)0) < 0) !=
            (context.InventoryEpoch == 1))
            throw new ArgumentException("The DID2 inventory predecessor is invalid.",
                nameof(predecessorXpi1Hash32));

        lock (_gate)
        {
            ThrowIfDisposed();
            var current = _deviceAgreement.RequireActiveDirectoryForProtocolOperation(
                context.CurrentDirectory);
            if (!current.Identity.Account.Certificate.CanonicalBytes.Span
                    .SequenceEqual(did2Binding.Identity.Account.Certificate
                        .CanonicalBytes.Span) ||
                !current.Record.DeepAccountId.Span.SequenceEqual(
                    did2Binding.Record.DeepAccountId.Span) ||
                !current.Record.NetworkId.Span.SequenceEqual(
                    did2Binding.Identity.Account.Certificate.NetworkId.Span))
                throw new CryptographicException(
                    "The DID2 binding is outside the active inventory account.");
            var certificate = current.Identity.ActiveDevices.Single(device =>
                device.Certificate.DeviceId.Span.SequenceEqual(DeviceId.Span))
                .Certificate;
            var descriptor = DeepIdV2PreKeyServiceCodec.Decode(
                service.ExactXps1.Span);
            DeepIdV2PreKeyServiceCodec.VerifyDeviceSignature(descriptor,
                certificate.DeviceEd25519PublicKey.Span);
            if (!descriptor.Field(1).Span.SequenceEqual(current.Record.NetworkId.Span) ||
                !descriptor.Field(2).Span.SequenceEqual(service.ServiceCapability.Span) ||
                !descriptor.Field(3).Span.SequenceEqual(DeviceId.Span) ||
                !descriptor.Field(4).Span.SequenceEqual(
                    Dpd1Reference(certificate.CanonicalHash.Span)) ||
                BinaryPrimitives.ReadUInt64BigEndian(descriptor.Field(5).Span) !=
                    context.PrekeyServiceGeneration ||
                BinaryPrimitives.ReadUInt16BigEndian(descriptor.Field(8).Span) >
                    oneTimePreKeyCount ||
                BinaryPrimitives.ReadUInt16BigEndian(descriptor.Field(9).Span) <
                    lastResortReuseLimit ||
                BinaryPrimitives.ReadUInt64BigEndian(descriptor.Field(10).Span) >
                    context.NotBeforeUnixSeconds ||
                BinaryPrimitives.ReadUInt64BigEndian(descriptor.Field(11).Span) <
                    context.ExpiresAtUnixSeconds)
                throw new CryptographicException(
                    "The DID2 inventory is outside its exact signed XPS1 V2 service.");
            var offerings = new List<AuthoredDpk2Offering>(oneTimePreKeyCount);
            AuthoredDpk2Offering? last = null;
            try
            {
                for (var index = 0; index < oneTimePreKeyCount; index++)
                    offerings.Add(AuthorOneTimeV2(context));
                offerings.Sort(static (left, right) =>
                    left.Record.OneTimeX25519PrekeyId.Span.SequenceCompareTo(
                        right.Record.OneTimeX25519PrekeyId.Span));
                for (var index = 1; index < offerings.Count; index++)
                    if (offerings[index - 1].Record.OneTimeX25519PrekeyId.Span
                        .SequenceEqual(offerings[index].Record.OneTimeX25519PrekeyId.Span))
                        throw new CryptographicException(
                            "The DID2 inventory repeated a one-time pre-key ID.");
                last = AuthorLastResortV2(context, lastResortReuseLimit);
                var hashes = offerings.Select(static offering =>
                    offering.ExactDpk2Hash.ToArray()).ToArray();
                var root = DeepIdV2PreKeyInventoryVerifier.ComputeRoot(hashes);
                var fields = new ReadOnlyMemory<byte>[]
                {
                    current.Record.NetworkId,
                    service.ServiceCapability,
                    DeviceId,
                    offerings[0].Record.ResponderDpd1Ref,
                    U64(context.PrekeyServiceGeneration),
                    service.Xps1Reference,
                    U64(context.InventoryEpoch),
                    predecessorXpi1Hash32.ToArray(),
                    U16(oneTimePreKeyCount),
                    root,
                    last.ExactDpk2Hash,
                    current.Record.RecordHash,
                    currentDrs1Reference38.ToArray(),
                    U64(context.NotBeforeUnixSeconds),
                    U64(context.ExpiresAtUnixSeconds)
                };
                var signature = Sign(DeepIdV2PreKeyManifestCodec
                    .CreateSignatureInput(fields));
                var exactXpi1 = DeepIdV2PreKeyManifestCodec.Encode(fields,
                    signature);
                var manifest = DeepIdV2PreKeyManifestCodec.Decode(exactXpi1);
                var members = offerings.Select(static offering =>
                    DeepIdV2Dpk2Codec.Decode(offering.ExactDpk2.Span)).ToArray();
                var lastMember = DeepIdV2Dpk2Codec.Decode(last.ExactDpk2.Span);
                var exactXpp1 = DeepIdV2PreKeyPublicationCodec.Encode(
                    current.Record.NetworkId.Span, publicationOperationId32,
                    placementHash32, manifest, members, lastMember);
                return new AuthoredDpk2InventoryV2(exactXpi1, exactXpp1,
                    offerings.ToArray(), last);
            }
            catch
            {
                foreach (var offering in offerings) offering.Dispose();
                last?.Dispose();
                throw;
            }
        }
    }

    private static void Nonzero(ReadOnlySpan<byte> value, int length,
        string parameter)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The DID2 inventory field is invalid.",
                parameter);
    }

    private static void Reference(ReadOnlySpan<byte> value,
        ReadOnlySpan<byte> magic, string parameter)
    {
        if (value.Length != 38 || !value[..4].SequenceEqual(magic) ||
            BinaryPrimitives.ReadUInt16BigEndian(value[4..6]) !=
                (magic.SequenceEqual(ProtocolMagicBytes.XPS1) ? 2 : 1) ||
            value[6..].IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("The DID2 inventory reference is invalid.",
                parameter);
    }

    private static byte[] U64(ulong value)
    {
        var encoded = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(encoded, value);
        return encoded;
    }

    private static byte[] U16(ushort value)
    {
        var encoded = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(encoded, value);
        return encoded;
    }
}
