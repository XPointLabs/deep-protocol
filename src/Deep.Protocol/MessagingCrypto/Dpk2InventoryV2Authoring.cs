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

public sealed partial class Dpk2AuthoringAuthority
{
    /// <summary>
    /// Authors one complete DID2-only V2 inventory from the exact active DMD1.
    /// No V1 codec, caller-supplied signer, raw private key or network write is
    /// involved. The returned publication is not safe to dispatch before all
    /// private capabilities are durably committed by the account owner.
    /// </summary>
    public AuthoredDpk2InventoryV2 AuthorInventoryV2(
        Dpk2AuthoringContext context,
        VerifiedDab2 did2Binding,
        ReadOnlySpan<byte> serviceCapability32,
        ReadOnlySpan<byte> xps1Reference38,
        ReadOnlySpan<byte> currentDrs1Reference38,
        ReadOnlySpan<byte> predecessorXpi1Hash32,
        ReadOnlySpan<byte> publicationOperationId32,
        ReadOnlySpan<byte> placementHash32,
        ushort oneTimePreKeyCount,
        ushort lastResortReuseLimit)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(did2Binding);
        if (oneTimePreKeyCount is < 32 or > 4096 ||
            lastResortReuseLimit is < 1 or > 64 ||
            context.PrekeyServiceGeneration == 0 ||
            context.InventoryEpoch is < 1 or > 14)
            throw new ArgumentException("The DID2 inventory policy is outside its closed bound.");
        Nonzero(serviceCapability32, 32, nameof(serviceCapability32));
        Reference(xps1Reference38, ProtocolMagicBytes.XPS1,
            nameof(xps1Reference38));
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
                    serviceCapability32.ToArray(),
                    DeviceId,
                    offerings[0].Record.ResponderDpd1Ref,
                    U64(context.PrekeyServiceGeneration),
                    xps1Reference38.ToArray(),
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
            BinaryPrimitives.ReadUInt16BigEndian(value[4..6]) != 1 ||
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
