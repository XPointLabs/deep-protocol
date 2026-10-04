using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.XPointNetworkV1;

/// <summary>Owned canonical signing reservation data, not a signed snapshot or admission capability.
/// The issuer must commit SigningInput to its scoped journal before calling the signer.</summary>
public sealed class PreparedMailboxGrantRevocationV1
{
    internal PreparedMailboxGrantRevocationV1(VerifiedMailboxHostAuthorityV2 host, ParsedMailboxGrantRevocationV1 unsigned)
    { Host = host; Unsigned = unsigned; }
    internal VerifiedMailboxHostAuthorityV2 Host { get; }
    internal ParsedMailboxGrantRevocationV1 Unsigned { get; }
    public ReadOnlyMemory<byte> SigningInput => Unsigned.SignatureInput;
    public ReadOnlyMemory<byte> CoreHash => Unsigned.CoreHash;
    public ReadOnlyMemory<byte> NetworkId => Unsigned.Field(1);
    public ReadOnlyMemory<byte> PolicyReference => Unsigned.Field(2);
    public ReadOnlyMemory<byte> IssuerPublicKey => Unsigned.Field(4);
    public MailboxCapabilityDomain Domain => Unsigned.Domain;
    public ulong Generation => Unsigned.Generation;
    public ulong ExpiresAt => Unsigned.ExpiresAt;
}

public static class MailboxGrantRevocationV1Author
{
    public static bool RuntimeActivation => false;
    private const string SignatureDomain = "Deep/XPoint/V1/MGR1/issuer";

    /// <summary>Prepare genesis only for an explicitly provisioned issuer ledger,
    /// otherwise one successor of its actual restored signed winner. Does not reserve or sign.</summary>
    public static async ValueTask<PreparedMailboxGrantRevocationV1> PrepareCurrentAsync(
        VerifiedMailboxHostAuthorityV2 host, MailboxCapabilityDomain domain,
        ReadOnlyMemory<byte> exactProtectedPredecessor,
        IReadOnlyList<ReadOnlyMemory<byte>> cumulativeSerials, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(host); ArgumentNullException.ThrowIfNull(cumulativeSerials);
        cancellationToken.ThrowIfCancellationRequested();
        if (domain is not (MailboxCapabilityDomain.Deposit or MailboxCapabilityDomain.Retrieve))
            throw new ArgumentOutOfRangeException(nameof(domain));
        var count = cumulativeSerials.Count;
        if (count > MailboxGrantRevocationV1Codec.MaximumSerials || count < 0)
            throw new ArgumentException("MGR1 cumulative ledger exceeds its closed capacity.");
        var serials = new byte[checked(count * 16)];
        for (var index = 0; index < count; index++)
        {
            var row = cumulativeSerials[index];
            if (row.Length != 16) throw new ArgumentException("MGR1 serial must be exactly 16 bytes.");
            row.Span.CopyTo(serials.AsSpan(index * 16, 16));
            if (serials.AsSpan(index * 16, 16).IndexOfAnyExcept((byte)0) < 0 ||
                index > 0 && serials.AsSpan((index - 1) * 16, 16).SequenceCompareTo(serials.AsSpan(index * 16, 16)) >= 0)
                throw new ArgumentException("MGR1 serial ledger must be nonzero and strictly ordered.");
        }
        var prior = exactProtectedPredecessor.IsEmpty ? null : MailboxGrantRevocationV1Codec.Decode(exactProtectedPredecessor.Span);
        var before = await host.ReadAsync(cancellationToken).ConfigureAwait(false);
        if (prior is not null)
        {
            MailboxGrantRevocationV1Verifier.RequireSnapshot(prior, host, before, true);
            if (prior.Domain != domain || prior.Generation == ulong.MaxValue || prior.IssuedAt > before.Lower)
                throw new CryptographicException("MGR1 predecessor cannot authorize this issuer successor.");
        }
        var policy = before.Policy;
        var issuer = policy.ResolveIssuer(domain);
        var expiry = before.Lower + Math.Min(MailboxGrantRevocationV1Codec.MaximumLifetimeSeconds,
            policy.ExpiresAtUnixSeconds - before.Lower);
        ReadOnlyMemory<byte>[] fields = [host.NetworkId,
            XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.PMA2, policy.CoreHash.Span),
            new byte[] { (byte)domain }, issuer.PublicKey, U64(prior is null ? 1 : prior.Generation + 1),
            prior is null ? new byte[32] : prior.CoreHash, U64(before.Lower), U64(before.Lower), U64(expiry),
            U32(checked((uint)count)), serials];
        var unsigned = Unsigned(fields);
        if (prior is not null)
            for (var index = 0; index < prior.SerialCount; index++)
                if (!unsigned.ContainsSerial(prior.FieldSpan(11).Slice(index * 16, 16)))
                    throw new CryptographicException("MGR1 issuer successor cannot remove a retained revocation.");
        MailboxGrantRevocationV1Verifier.RequireSnapshotContext(unsigned, host, before, false);
        var after = await host.ReadAsync(cancellationToken).ConfigureAwait(false);
        MailboxGrantRevocationV1Verifier.RequireSnapshotContext(unsigned, host, after, false);
        if (prior is not null) MailboxGrantRevocationV1Verifier.RequireSnapshot(prior, host, after, true);
        return new(host, unsigned);
    }

    /// <summary>Restore the journal's exact existing SIGINPUT. May be expired;
    /// this permits only identical signing completion, never current admission.</summary>
    public static async ValueTask<PreparedMailboxGrantRevocationV1> RestoreReservedAsync(
        VerifiedMailboxHostAuthorityV2 host, ReadOnlyMemory<byte> exactReservedSigningInput,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(host); cancellationToken.ThrowIfCancellationRequested();
        var unsigned = DecodeSigningInput(exactReservedSigningInput.Span);
        RequireReservedContext(unsigned, host, await host.ReadAsync(cancellationToken).ConfigureAwait(false));
        RequireReservedContext(unsigned, host, await host.ReadAsync(cancellationToken).ConfigureAwait(false));
        return new(host, unsigned);
    }

    /// <summary>Complete only an already durable reservation. Signed bytes are not a
    /// committed issuer winner, protected native floor or dispatch capability.</summary>
    public static async ValueTask<ReadOnlyMemory<byte>> CompleteReservedAsync(
        PreparedMailboxGrantRevocationV1 reservation, IMailboxGrantIssuerSigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reservation); ArgumentNullException.ThrowIfNull(signer);
        cancellationToken.ThrowIfCancellationRequested();
        var host = reservation.Host; var unsigned = reservation.Unsigned;
        RequireReservedContext(unsigned, host, await host.ReadAsync(cancellationToken).ConfigureAwait(false));
        if (!Fixed(signer.Ed25519PublicKey.Span, unsigned.FieldSpan(4)))
            throw new CryptographicException("MGR1 signer differs from the reserved PMA2 role.");
        var signature = await signer.SignAsync(unsigned.SignatureInput, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (signature.Length != 64 || !Fixed(signer.Ed25519PublicKey.Span, unsigned.FieldSpan(4)))
            throw new CryptographicException("MGR1 signer returned an invalid signature or changed role key.");
        var exact = MailboxGrantRevocationV1Codec.Encode(Enumerable.Range(1, 11).Select(unsigned.Field).ToArray(), signature.Span);
        await VerifyReservedCompletionAsync(reservation, exact, cancellationToken).ConfigureAwait(false);
        return exact;
    }

    /// <summary>Verify the journal's exact signed winner against its retained reservation.
    /// Expired completion proves history only; this returns no current admission capability.</summary>
    public static async ValueTask VerifyReservedCompletionAsync(PreparedMailboxGrantRevocationV1 reservation,
        ReadOnlyMemory<byte> exactSignedWinner, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reservation); cancellationToken.ThrowIfCancellationRequested();
        var signed = MailboxGrantRevocationV1Codec.Decode(exactSignedWinner.Span);
        if (!Fixed(signed.SignatureInput.Span, reservation.SigningInput.Span))
            throw new CryptographicException("MGR1 signed winner differs from its exact reserved input.");
        var before = await reservation.Host.ReadAsync(cancellationToken).ConfigureAwait(false);
        MailboxGrantRevocationV1Verifier.RequireSnapshot(signed, reservation.Host, before, true);
        if (signed.NotBefore > before.Lower) throw new CryptographicException("MGR1 winner starts in the future.");
        var after = await reservation.Host.ReadAsync(cancellationToken).ConfigureAwait(false);
        MailboxGrantRevocationV1Verifier.RequireSnapshot(signed, reservation.Host, after, true);
        if (signed.NotBefore > after.Lower) throw new CryptographicException("MGR1 winner starts in the future.");
    }

    private static void RequireReservedContext(ParsedMailboxGrantRevocationV1 unsigned,
        VerifiedMailboxHostAuthorityV2 host, (VerifiedMailboxAuthorityV2 Policy, ulong Lower, ulong Upper) current)
    {
        MailboxGrantRevocationV1Verifier.RequireSnapshotContext(unsigned, host, current, true);
        if (unsigned.NotBefore > current.Lower) throw new CryptographicException("MGR1 reservation starts in the future.");
    }

    private static ParsedMailboxGrantRevocationV1 DecodeSigningInput(ReadOnlySpan<byte> input)
    {
        var prefix = ApplicationCoreFormat.SignatureInput(SignatureDomain, []).Length;
        if (input.Length < prefix + MailboxGrantRevocationV1Codec.MinimumBytes - 72 ||
            input.Length > prefix + MailboxGrantRevocationV1Codec.MaximumBytes - 72)
            throw new ArgumentException("MGR1 reserved signing input exceeds its closed bound.");
        var unsigned = input[prefix..];
        if (!Fixed(input, ApplicationCoreFormat.SignatureInput(SignatureDomain, unsigned)))
            throw new CryptographicException("MGR1 reservation has a foreign signing domain, suite or length.");
        Span<ApplicationFieldSlice> slices = stackalloc ApplicationFieldSlice[11];
        ApplicationCoreFormat.Preflight(unsigned, ProtocolMagicBytes.MGR1, 11,
            MailboxGrantRevocationV1Codec.MinimumBytes - 72, MailboxGrantRevocationV1Codec.MaximumBytes - 72, slices);
        ReadOnlyMemory<byte>[] fields = new ReadOnlyMemory<byte>[11];
        for (var tag = 1; tag <= 11; tag++) fields[tag - 1] = ApplicationCoreFormat.Field(unsigned, slices, tag).ToArray();
        var parsed = Unsigned(fields);
        if (!Fixed(input, parsed.SignatureInput.Span)) throw new CryptographicException("MGR1 reservation is not canonical.");
        return parsed;
    }

    // Placeholder remains private and is used only to reuse the sole canonical
    // field grammar. It is never signed evidence, exposed as a snapshot or distributed.
    private static ParsedMailboxGrantRevocationV1 Unsigned(IReadOnlyList<ReadOnlyMemory<byte>> fields) =>
        MailboxGrantRevocationV1Codec.Decode(MailboxGrantRevocationV1Codec.Encode(fields, Enumerable.Repeat((byte)1, 64).ToArray()));
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
    private static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static byte[] U32(uint value) { var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes; }
}
