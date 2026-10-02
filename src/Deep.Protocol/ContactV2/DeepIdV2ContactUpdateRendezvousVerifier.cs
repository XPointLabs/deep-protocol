using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Protocol.ContactV2;

/// <summary>Current DID2 issuer/time verification only, not route, contact,
/// publication, session, delivery or ACK authority.</summary>
public sealed class VerifiedDeepIdV2ContactUpdateRendezvous
{
    internal VerifiedDeepIdV2ContactUpdateRendezvous(ContactRecord record,
        VerifiedDeepIdV2DirectoryFreshness freshness)
    {
        Record = record;
        Freshness = freshness;
    }

    public ContactRecord Record { get; }
    public VerifiedDeepIdV2DirectoryFreshness Freshness { get; }
    public ReadOnlyMemory<byte> ExactXur1 => Record.CanonicalBytes;
    internal void RequireCurrentAt(OnionMonotonicReading reading) =>
        DeepIdV2ContactUpdateRendezvousVerifier.RequireCurrentIssuer(Record, Freshness, reading);
}

public static class DeepIdV2ContactUpdateRendezvousVerifier
{
    public static bool RuntimeActivation => false;

    public static async ValueTask<VerifiedDeepIdV2ContactUpdateRendezvous> VerifyAsync(
        ReadOnlyMemory<byte> exactXur1, VerifiedDeepIdV2DirectoryFreshness freshness,
        OnionTrustedTimeAuthority trustedTime, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(freshness);
        ArgumentNullException.ThrowIfNull(trustedTime);
        cancellationToken.ThrowIfCancellationRequested();
        if (exactXur1.Length != 538)
            throw new ArgumentException("An exact bounded inbound XUR1 is required.", nameof(exactXur1));
        // The decoder owns all fields before any asynchronous clock read.
        // XUR1 is identity-neutral; no retired identity author/verifier is used.
        var record = ContactCodec.Decode(ProtocolMagic.XUR1, exactXur1.Span);
        var first = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        RequireCurrentIssuer(record, freshness, first);
        var final = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (final.SampleSeconds < first.SampleSeconds ||
            !Fixed(final.BootId.Span, first.BootId.Span))
            throw new CryptographicException("Contact rendezvous verification crossed a clock discontinuity.");
        RequireCurrentIssuer(record, freshness, final);
        return new VerifiedDeepIdV2ContactUpdateRendezvous(record, freshness);
    }

    internal static void RequireCurrentIssuer(ContactRecord record,
        VerifiedDeepIdV2DirectoryFreshness freshness, OnionMonotonicReading reading)
    {
        if (freshness.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue ||
            !freshness.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds))
            throw new CryptographicException("A fresh current DID2 directory checkpoint is required for the rendezvous.");
        var checkpoint = freshness.CurrentCheckpoint ??
            throw new CryptographicException("The rendezvous has no current DID2 checkpoint.");
        var directory = checkpoint.Directory.Record;
        var device = checkpoint.Directory.Identity.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.Certificate.DeviceId.Span, record.FieldSpan(13)));
        var entry = directory.ActiveDevices.SingleOrDefault(candidate =>
            Fixed(candidate.DeviceId.Span, record.FieldSpan(13)));
        if (device is null || entry is null ||
            !Fixed(record.FieldSpan(1), freshness.NetworkId.Span) ||
            !Fixed(directory.NetworkId.Span, freshness.NetworkId.Span) ||
            !Fixed(directory.DeepAccountId.Span, checkpoint.Binding.Record.DeepAccountId.Span) ||
            !Fixed(entry.Dpd1Reference.CanonicalHash.Span, device.Certificate.CanonicalHash.Span) ||
            !Fixed(record.FieldSpan(14), new ContactArtifactReference(ProtocolMagic.DPD1, 1,
                device.Certificate.CanonicalHash.Span).CanonicalBytes.Span) ||
            U64(record.FieldSpan(4)) != 0 || record.FieldSpan(5).IndexOfAnyExcept((byte)0) >= 0 ||
            BinaryPrimitives.ReadUInt16BigEndian(record.FieldSpan(10)) != 0x0007)
            throw new CryptographicException("The inbound rendezvous differs from its current DID2 device authority.");
        ulong lower, upper;
        try
        {
            var elapsed = checked(reading.SampleSeconds - freshness.MonotonicSample);
            lower = checked(freshness.TrustedLowerUnixSeconds + elapsed);
            upper = checked(freshness.TrustedUpperUnixSeconds + elapsed);
        }
        catch (OverflowException exception)
        {
            throw new CryptographicException("The rendezvous trusted-time interval overflowed.", exception);
        }
        if (U64(record.FieldSpan(11)) > lower || U64(record.FieldSpan(12)) <= upper)
            throw new CryptographicException("The inbound rendezvous does not cover the entire authenticated time interval.");
        try { ContactCodec.VerifyDeviceSignature(record, device.Certificate.DeviceEd25519PublicKey.Span); }
        catch (ContactFormatException exception)
        {
            throw new CryptographicException("The inbound rendezvous current device signature is invalid.", exception);
        }
    }

    private static ulong U64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);
    private static bool Fixed(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second) =>
        first.Length == second.Length && CryptographicOperations.FixedTimeEquals(first, second);
}
