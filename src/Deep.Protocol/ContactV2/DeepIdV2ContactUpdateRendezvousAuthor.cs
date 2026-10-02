using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.ContactV2;

/// <summary>Owned DID2 device author. Result grants issuer/time only; Shared
/// must retain exact custody before Hello, and independently verify routing.</summary>
public static class DeepIdV2ContactUpdateRendezvousAuthor
{
    public static async ValueTask<VerifiedDeepIdV2ContactUpdateRendezvous> AuthorGenesisAsync(
        VerifiedDeepIdV2DirectoryFreshness freshness, VerifiedOnionNetworkContext network,
        OwnedGenesisDeviceSecrets deviceSecrets, ReadOnlyMemory<byte> metadataKeyId32,
        ReadOnlyMemory<byte> metadataX25519PublicKey32, ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds, OnionTrustedTimeAuthority trustedTime,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(freshness);
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(deviceSecrets);
        ArgumentNullException.ThrowIfNull(trustedTime);
        cancellationToken.ThrowIfCancellationRequested();
        RequireMetadata(metadataKeyId32.Span);
        RequireMetadata(metadataX25519PublicKey32.Span);
        if (issuedAtUnixSeconds == 0 || expiresAtUnixSeconds <= issuedAtUnixSeconds ||
            expiresAtUnixSeconds - issuedAtUnixSeconds > 2_592_000)
            throw new ArgumentOutOfRangeException(nameof(expiresAtUnixSeconds));
        var keyId = metadataKeyId32.ToArray(); var publicKey = metadataX25519PublicKey32.ToArray();
        ReadOnlyMemory<byte>[] fields = [];
        byte[]? signature = null;
        try
        {
            RequireAgreementKey(publicKey);
            var first = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            RequireCurrent(freshness, network, first);
            var elapsed = checked(first.SampleSeconds - freshness.MonotonicSample);
            if (issuedAtUnixSeconds > checked(freshness.TrustedLowerUnixSeconds + elapsed) ||
                expiresAtUnixSeconds <= checked(freshness.TrustedUpperUnixSeconds + elapsed))
                throw new CryptographicException("The rendezvous does not cover the entire authenticated time interval.");
            var checkpoint = freshness.CurrentCheckpoint!;
            var device = checkpoint.Directory.Identity.ActiveDevices.SingleOrDefault(candidate =>
                candidate.Certificate.DeviceId.Span.SequenceEqual(deviceSecrets.DeviceId.Bytes.Span)) ??
                throw new CryptographicException("The owned device is not active in this current DID2 proof.");
            if (issuedAtUnixSeconds < device.Certificate.IssuedAtUnixSeconds ||
                expiresAtUnixSeconds > device.Certificate.ExpiresAtUnixSeconds ||
                expiresAtUnixSeconds > network.Closure!.HardUpperUnixSeconds ||
                publicKey.AsSpan().SequenceEqual(device.Certificate.DeviceX25519PublicKey.Span))
                throw new CryptographicException("The rendezvous validity/key role differs from current authority.");
            var placeholder = new byte[64]; placeholder[^1] = 1;
            fields = [freshness.NetworkId, Random32(), Random32(), U64(0), new byte[32],
                network.Closure.PmtArtifactReference.ToArray(), Random32(), keyId, publicKey, new byte[] { 0, 7 },
                U64(issuedAtUnixSeconds), U64(expiresAtUnixSeconds), device.Certificate.DeviceId,
                new ContactArtifactReference(ProtocolMagic.DPD1, 1, device.Certificate.CanonicalHash.Span).CanonicalBytes,
                placeholder];
            var provisional = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XUR1, fields);
            signature = deviceSecrets.SignContactUpdateRendezvous(provisional, freshness);
            fields[14] = signature;
            var record = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XUR1, fields);
            DeepIdV2ContactUpdateRendezvousVerifier.RequireCurrentIssuer(record, freshness, first);
            var final = await trustedTime.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (final.SampleSeconds < first.SampleSeconds || !final.BootId.Span.SequenceEqual(first.BootId.Span))
                throw new CryptographicException("Rendezvous authoring crossed a protected clock discontinuity.");
            RequireCurrent(freshness, network, final);
            DeepIdV2ContactUpdateRendezvousVerifier.RequireCurrentIssuer(record, freshness, final);
            return new VerifiedDeepIdV2ContactUpdateRendezvous(record, freshness);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyId); CryptographicOperations.ZeroMemory(publicKey);
            if (signature is not null) CryptographicOperations.ZeroMemory(signature);
            // Only zero locally owned arrays; capability properties are copies.
            foreach (var field in fields)
                if (!field.IsEmpty) CryptographicOperations.ZeroMemory(MemoryMarshal.AsMemory(field).Span);
        }
    }

    private static void RequireCurrent(VerifiedDeepIdV2DirectoryFreshness proof,
        VerifiedOnionNetworkContext network, OnionMonotonicReading reading)
    {
        network.EnsureCurrent();
        var closure = network.Closure!;
        var time = (IVerifiedDirectoryNetworkTime)proof;
        if (proof.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue || proof.CurrentCheckpoint is null ||
            !proof.IsCurrentAtMonotonic(reading.BootId.Span, reading.SampleSeconds) ||
            !proof.NetworkId.Span.SequenceEqual(network.NetworkId.Span) ||
            !time.ExactAdh1CoreReference.Span.SequenceEqual(closure.Adh1CoreReference) ||
            !time.ExactDtt1CoreHash.Span.SequenceEqual(closure.Dtt1CoreHash) ||
            !reading.BootId.Span.SequenceEqual(closure.FreshnessBootId) ||
            reading.SampleSeconds < closure.FreshnessMonotonicSample ||
            reading.SampleSeconds >= closure.FreshnessDeadlineMonotonicSeconds)
            throw new CryptographicException("The rendezvous network and current DID2 proof do not close over the same live head/time.");
    }

    private static void RequireMetadata(ReadOnlySpan<byte> value)
    {
        if (value.Length != 32 || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException("An exact independent nonzero metadata key is required.");
    }
    internal static void RequireAgreementKey(ReadOnlySpan<byte> publicKey)
    {
        Span<byte> probeScalar = stackalloc byte[32];
        Span<byte> shared = stackalloc byte[32];
        try
        {
            RandomNumberGenerator.Fill(probeScalar);
            if (probeScalar.IndexOfAnyExcept((byte)0) < 0) probeScalar[0] = 1;
            OwnedSodiumX25519.Agree(probeScalar, publicKey, shared);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(probeScalar);
            CryptographicOperations.ZeroMemory(shared);
        }
    }
    private static byte[] Random32()
    {
        var value = new byte[32];
        do RandomNumberGenerator.Fill(value); while (value.AsSpan().IndexOfAnyExcept((byte)0) < 0);
        return value;
    }
    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes;
    }
}
