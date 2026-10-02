using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.Identity;

namespace Deep.Protocol.ContactV2;

/// <summary>A local signed/encrypted candidate, not publication, a grant or delivery.</summary>
public sealed class AuthoredDeepIdV2ContactObject
{
    private readonly byte[] ciphertext, locator;
    internal AuthoredDeepIdV2ContactObject(ParsedDcr1V2 closure, byte[] ciphertext, byte[] locator)
    { Closure = closure; this.ciphertext = ciphertext.ToArray(); this.locator = locator.ToArray(); }
    public ParsedDcr1V2 Closure { get; }
    public ReadOnlyMemory<byte> ProtectedDcr1 => ciphertext.ToArray();
    public ReadOnlyMemory<byte> LocatorHash => locator.ToArray();
}

/// <summary>Owned reusable genesis only. No caller clock or generic signing surface.</summary>
public static class DeepIdV2ContactObjectAuthor
{
    public static async ValueTask<AuthoredDeepIdV2ContactObject> AuthorGenesisAsync(
        VerifiedDeepIdV2ContactRouteClosure route, OwnedGenesisDeviceSecrets device,
        IReadOnlyList<ParsedXps1V2> preKeyServices, string profileName,
        ReadOnlyMemory<byte> resolverReadCapability16, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(route); ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(preKeyServices); ArgumentNullException.ThrowIfNull(profileName);
        cancellationToken.ThrowIfCancellationRequested();
        if (resolverReadCapability16.Length != 16) throw new ArgumentException("An exact resolver capability is required.", nameof(resolverReadCapability16));
        // Own every caller input before the first asynchronous clock read.
        if (profileName.Length > 128) throw new ArgumentException("Contact profile exceeds its character bound.", nameof(profileName));
        var name = ApplicationCoreFormat.StrictUtf8.GetBytes(profileName);
        if (name.Length > 128) throw new ArgumentException("Contact profile exceeds its UTF-8 bound.", nameof(profileName));
        var serviceCount = preKeyServices.Count;
        if (serviceCount is < 1 or > 16) throw new ArgumentException("An exact active-device service set is required.", nameof(preKeyServices));
        var services = new ParsedXps1V2[serviceCount];
        for (var i = 0; i < serviceCount; i++)
            services[i] = DeepIdV2PreKeyServiceCodec.Decode((preKeyServices[i] ??
                throw new ArgumentException("A prekey descriptor is absent.", nameof(preKeyServices))).CanonicalBytes.Span);
        if (services.Select(value => Convert.ToHexString(value.Field(3).Span)).Distinct(StringComparer.Ordinal).Count() != serviceCount)
            throw new CryptographicException("Duplicate device prekey descriptors are forbidden.");
        var capability = resolverReadCapability16.ToArray();
        byte[]? protectedBytes = null;
        try
        {
            var binding = route.Recipient.Authorization.Binding;
            using var resolution = DeepIdV2PermanentContactResolutionDerivation.Derive(
                route.Network.NetworkId.Span, binding.DeepId, capability);
            var window = await route.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
            if (!Fixed(route.Route.Route.Field(19).Span[6..], route.Recipient.Freshness.NextProtectedLkg.CoreHash.Span))
                throw new CryptographicException("New contact issuance requires a route anchored at the current verified directory head.");
            var dca = route.Recipient.Authorization;
            var directory = dca.Directory.Record;
            if (route.Invite.Field(9).Span[0] != 1 || directory.ActiveDevices.Count != services.Length ||
                U64(route.Invite.Field(3).Span) != 0 ||
                BinaryPrimitives.ReadUInt64BigEndian(route.Route.Authorization.Field(3).Span) != 0)
                throw new CryptographicException("Only the exact reusable genesis route is supported.");
            var issued = window.LowerUnixSeconds;
            var expiry = Math.Min(dca.Record.ExpiresAtUnixSeconds, U64(route.Invite.Field(14).Span));
            var ordered = new List<ParsedXps1V2>(services.Length);
            foreach (var entry in directory.ActiveDevices)
            {
                var service = services.SingleOrDefault(value => Fixed(value.Field(3).Span, entry.DeviceId.Span)) ??
                    throw new CryptographicException("The exact active-device prekey descriptor is absent.");
                var verifiedDevice = binding.Identity.ActiveDevices.Single(value => Fixed(value.Certificate.DeviceId.Span, entry.DeviceId.Span));
                if (!Fixed(service.Field(1).Span, dca.Record.NetworkId.Span) ||
                    !Fixed(service.Field(4).Span, Reference(ProtocolMagicBytes.DPD1, verifiedDevice.Certificate.CanonicalHash.Span)) ||
                    U64(service.Field(5).Span) != 1 || U64(service.Field(10).Span) > issued)
                    throw new CryptographicException("The prekey descriptor is not the exact current genesis service.");
                DeepIdV2PreKeyServiceCodec.VerifyDeviceSignature(service, verifiedDevice.Certificate.DeviceEd25519PublicKey.Span);
                expiry = Math.Min(expiry, U64(service.Field(11).Span)); ordered.Add(service);
            }
            if (issued >= expiry || window.UpperUnixSeconds >= expiry)
                throw new CryptographicException("Contact validity cannot cover the complete trusted time interval.");
            var head = route.Recipient.Freshness.NextProtectedLkg;
            var lookup = DeepIdV2AccountDirectoryLookupCodec.Author(binding.DeepId, dca.Record.NetworkId.Span,
                head.LogGeneration, head.CoreHash.Span, 1, new byte[38], new byte[32]);
            var minimumHead = new byte[40]; U64Bytes(head.LogGeneration).CopyTo(minimumHead, 0);
            head.CoreHash.Span.CopyTo(minimumHead.AsSpan(8));
            var descriptor = new byte[651]; BinaryPrimitives.WriteUInt16BigEndian(descriptor, 1);
            BinaryPrimitives.WriteUInt16BigEndian(descriptor.AsSpan(2), 1);
            SHA256.HashData(route.ExactXir1V2.Span).CopyTo(descriptor, 4);
            BinaryPrimitives.WriteUInt32BigEndian(descriptor.AsSpan(36), 611);
            route.ExactXir1V2.Span.CopyTo(descriptor.AsSpan(40));
            var list = new byte[1 + 356 * ordered.Count]; list[0] = checked((byte)ordered.Count);
            for (var i = 0; i < ordered.Count; i++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(list.AsSpan(1 + 356 * i), 352);
                ordered[i].CanonicalBytes.Span.CopyTo(list.AsSpan(5 + 356 * i));
            }
            var placeholder = new byte[64]; placeholder.AsSpan().Fill(1);
            ReadOnlyMemory<byte>[] fields = [dca.Record.NetworkId, dca.Record.DeepAccountId,
                binding.Identity.Account.Certificate.CanonicalBytes,
                Reference(ProtocolMagicBytes.DRS1, binding.Identity.Revocations.Snapshot.CanonicalHash.Span),
                directory.CanonicalBytes, dca.Record.CanonicalBytes, RandomNonzero32(), U64Bytes(0), new byte[32],
                dca.Record.PublisherDeviceId, new byte[] { checked((byte)services.Length) }, list, new byte[] { 1 },
                descriptor, name, new byte[] { 0, 0, 0, 9 }, U64Bytes(issued), U64Bytes(expiry), placeholder,
                lookup.CanonicalBytes, minimumHead, binding.DeepId.RecordHash, binding.DeepId.CanonicalBytes,
                binding.Record.CanonicalBytes];
            var unsigned = EncodeBundle(fields);
            var signature = device.SignCurrentContactBundle(unsigned, dca);
            ParsedDcb1V2 bundle;
            try { fields[18] = signature; bundle = EncodeBundle(fields); }
            finally { CryptographicOperations.ZeroMemory(signature); }
            var closure = CloseSupport(bundle, dca);
            var final = await route.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
            RequireContinuous(window, final);
            RequireObject(route, closure, final);
            protectedBytes = DeepIdV2ResolverObjectProtection.Seal(closure, route.Network.NetworkId.Span, binding.DeepId, resolution);
            cancellationToken.ThrowIfCancellationRequested();
            return new(closure, protectedBytes, resolution.LocatorHash.ToArray());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(capability);
            if (protectedBytes is not null) CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    public static async ValueTask<AuthoredDeepIdV2ContactObject> RestoreAsync(
        VerifiedDeepIdV2ContactRouteClosure route, ReadOnlyMemory<byte> exactDcr1,
        ReadOnlyMemory<byte> protectedDcr1, ReadOnlyMemory<byte> resolverReadCapability16,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(route); cancellationToken.ThrowIfCancellationRequested();
        if (resolverReadCapability16.Length != 16) throw new ArgumentException("An exact resolver capability is required.", nameof(resolverReadCapability16));
        var closure = DeepIdV2ResolverClosureCodec.Decode(exactDcr1.Span);
        if (protectedDcr1.Length != closure.CanonicalBytes.Length + 40)
            throw new CryptographicException("The encrypted contact object length is not exact.");
        var ciphertext = protectedDcr1.ToArray(); var capability = resolverReadCapability16.ToArray();
        try
        {
            using var resolution = DeepIdV2PermanentContactResolutionDerivation.Derive(route.Network.NetworkId.Span,
                route.Recipient.Authorization.Binding.DeepId, capability);
            var first = await route.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
            RequireObject(route, closure, first);
            var opened = DeepIdV2ResolverObjectProtection.Open(ciphertext, route.Network.NetworkId.Span,
                route.Recipient.Authorization.Binding.DeepId, resolution);
            if (!Fixed(opened.CanonicalBytes.Span, closure.CanonicalBytes.Span))
                throw new CryptographicException("The encrypted object differs from exact retained contact custody.");
            var final = await route.ReadCurrentTimeAsync(cancellationToken).ConfigureAwait(false);
            RequireContinuous(first, final);
            RequireObject(route, closure, final); cancellationToken.ThrowIfCancellationRequested();
            return new(closure, ciphertext, resolution.LocatorHash.ToArray());
        }
        finally { CryptographicOperations.ZeroMemory(capability); CryptographicOperations.ZeroMemory(ciphertext); }
    }

    private static void RequireObject(VerifiedDeepIdV2ContactRouteClosure route, ParsedDcr1V2 closure,
        DeepIdV2ContactRouteTimeWindow window)
    {
        var bundle = closure.Bundle;
        DeepIdV2ContactRouteVerifier.RequireBundleIssuanceAnchor(route, bundle);
        if (!Fixed(bundle.Field(14).Span[40..], route.ExactXir1V2.Span) || U64(bundle.Field(8).Span) != 0 ||
            U64(route.Invite.Field(3).Span) != 0 ||
            BinaryPrimitives.ReadUInt32BigEndian(bundle.Field(16).Span) != 9 ||
            U64(bundle.Field(17).Span) > window.LowerUnixSeconds)
            throw new CryptographicException("The contact object is not the exact reusable genesis route.");
        DeepIdV2ResolverClosureCodec.VerifyIdentityAndSupport(closure, route.Recipient.Authorization, window.UpperUnixSeconds);
    }

    private static void RequireContinuous(DeepIdV2ContactRouteTimeWindow first, DeepIdV2ContactRouteTimeWindow final)
    {
        if (final.LowerUnixSeconds < first.LowerUnixSeconds || final.UpperUnixSeconds < first.UpperUnixSeconds)
            throw new CryptographicException("Contact authoring crossed a trusted clock discontinuity.");
    }

    private static ParsedDcb1V2 EncodeBundle(ReadOnlyMemory<byte>[] fields)
    {
        var bytes = new byte[12 + fields.Sum(value => 8 + value.Length)];
        var writer = new ApplicationRecordWriter(bytes, ProtocolMagicBytes.DCB1, 24, 2, DeepIdV2Codec.Suite);
        for (ushort tag = 1; tag <= 24; tag++) writer.Write(tag, fields[tag - 1].Span);
        writer.Complete(); return DeepIdV2ContactBundleCodec.Decode(bytes);
    }

    private static ParsedDcr1V2 CloseSupport(ParsedDcb1V2 bundle, VerifiedDca1V2 dca)
    {
        var identity = dca.Binding.Identity;
        var dpds = identity.ActiveDevices.OrderBy(value => Convert.ToHexString(value.Certificate.CanonicalHash.Span), StringComparer.Ordinal)
            .Select(value => value.Certificate.CanonicalBytes).ToArray();
        ReadOnlyMemory<byte>[] artifacts = [identity.Revocations.Snapshot.CanonicalBytes, .. dpds];
        var support = new byte[artifacts.Sum(value => 6 + value.Length)]; var offset = 0;
        for (var i = 0; i < artifacts.Length; i++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(support.AsSpan(offset), (ushort)(i == 0 ? 1 : 2));
            BinaryPrimitives.WriteUInt32BigEndian(support.AsSpan(offset + 2), checked((uint)artifacts[i].Length));
            artifacts[i].Span.CopyTo(support.AsSpan(offset + 6)); offset += 6 + artifacts[i].Length;
        }
        var bytes = new byte[62 + bundle.CanonicalBytes.Length + support.Length];
        var writer = new ApplicationRecordWriter(bytes, ProtocolMagicBytes.DCR1, 4, 2, DeepIdV2Codec.Suite);
        var count = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(count, checked((ushort)artifacts.Length));
        writer.Write(1, dca.Record.NetworkId.Span); writer.Write(2, bundle.CanonicalBytes.Span);
        writer.Write(3, count); writer.Write(4, support); writer.Complete();
        return DeepIdV2ResolverClosureCodec.Decode(bytes);
    }
    private static byte[] Reference(ReadOnlySpan<byte> magic, ReadOnlySpan<byte> hash)
    { var bytes = new byte[38]; magic.CopyTo(bytes); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1); hash.CopyTo(bytes.AsSpan(6)); return bytes; }
    private static byte[] U64Bytes(ulong value)
    { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
    private static ulong U64(ReadOnlySpan<byte> bytes) => BinaryPrimitives.ReadUInt64BigEndian(bytes);
    private static byte[] RandomNonzero32()
    { var bytes = new byte[32]; do RandomNumberGenerator.Fill(bytes); while (bytes.AsSpan().IndexOfAnyExcept((byte)0) < 0); return bytes; }
    private static bool Fixed(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
