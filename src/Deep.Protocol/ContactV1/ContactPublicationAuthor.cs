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

public sealed class ContactPreKeyServiceAuthoringRequest
{
    public ContactPreKeyServiceAuthoringRequest(
        VerifiedDevice device,
        CurrentlyAuthoritativeDca1 authorization,
        ushort minimumOneTimeInventory,
        ushort lastResortReuseLimit,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        VerifiedContactPreKeyService? predecessor = null)
    {
        Device = device ?? throw new ArgumentNullException(nameof(device));
        Authorization = authorization ?? throw new ArgumentNullException(nameof(authorization));
        if (minimumOneTimeInventory == 0)
            throw new ArgumentOutOfRangeException(nameof(minimumOneTimeInventory));
        if (lastResortReuseLimit == 0)
            throw new ArgumentOutOfRangeException(nameof(lastResortReuseLimit));
        if (issuedAtUnixSeconds == 0 || issuedAtUnixSeconds >= expiresAtUnixSeconds)
            throw new ArgumentOutOfRangeException(nameof(issuedAtUnixSeconds));
        MinimumOneTimeInventory = minimumOneTimeInventory;
        LastResortReuseLimit = lastResortReuseLimit;
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
        Predecessor = predecessor;
    }

    public VerifiedDevice Device { get; }
    public CurrentlyAuthoritativeDca1 Authorization { get; }
    public ushort MinimumOneTimeInventory { get; }
    public ushort LastResortReuseLimit { get; }
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public VerifiedContactPreKeyService? Predecessor { get; }
}

/// <summary>Non-forgeable, device-signed exact XPS1 publication capability.</summary>
public sealed class VerifiedContactPreKeyService
{
    private readonly byte[] exactXps1;
    private readonly byte[] serviceCapability;
    private readonly byte[] deviceId;

    internal VerifiedContactPreKeyService(
        ReadOnlySpan<byte> exactXps1,
        ReadOnlySpan<byte> serviceCapability,
        ReadOnlySpan<byte> deviceId,
        ulong generation,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds)
    {
        this.exactXps1 = exactXps1.ToArray();
        this.serviceCapability = serviceCapability.ToArray();
        this.deviceId = deviceId.ToArray();
        Generation = generation;
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
    }

    public ReadOnlyMemory<byte> ExactXps1 => exactXps1.ToArray();
    public ReadOnlyMemory<byte> ServiceCapability => serviceCapability.ToArray();
    public ReadOnlyMemory<byte> DeviceId => deviceId.ToArray();
    public ulong Generation { get; }
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
}

public sealed class ContactBundleAuthoringRequest
{
    public ContactBundleAuthoringRequest(
        CurrentlyAuthoritativeDca1 authorization,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedContactRouteClosure route,
        IReadOnlyList<VerifiedContactPreKeyService> preKeyServices,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        ReadOnlySpan<byte> currentBootId,
        ulong currentMonotonicSample,
        string profileName = "",
        uint unsolicitedPolicy = 0x0000000b,
        AuthoredPermanentContactPublication? predecessor = null)
    {
        Authorization = authorization ?? throw new ArgumentNullException(nameof(authorization));
        Freshness = freshness ?? throw new ArgumentNullException(nameof(freshness));
        Route = route ?? throw new ArgumentNullException(nameof(route));
        PreKeyServices = preKeyServices?.ToArray()
            ?? throw new ArgumentNullException(nameof(preKeyServices));
        if (PreKeyServices.Count is < 1 or > 16)
            throw new ArgumentOutOfRangeException(nameof(preKeyServices));
        if (issuedAtUnixSeconds == 0 || issuedAtUnixSeconds >= expiresAtUnixSeconds)
            throw new ArgumentOutOfRangeException(nameof(issuedAtUnixSeconds));
        if (currentBootId.Length != 16 || IsZero(currentBootId))
            throw new ArgumentException("The current boot ID must be exactly 16 non-zero bytes.", nameof(currentBootId));
        ArgumentNullException.ThrowIfNull(profileName);
        if (!profileName.IsNormalized(NormalizationForm.FormC) || profileName.Contains('\0') ||
            Encoding.UTF8.GetByteCount(profileName) > 128)
            throw new ArgumentException("The profile name must be canonical NFC UTF-8 of at most 128 bytes.", nameof(profileName));
        if (unsolicitedPolicy == 0 || (unsolicitedPolicy & ~0x0000000bU) != 0 ||
            (unsolicitedPolicy & 0x00000004U) != 0)
            throw new ArgumentOutOfRangeException(nameof(unsolicitedPolicy));

        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
        CurrentBootId = currentBootId.ToArray();
        CurrentMonotonicSample = currentMonotonicSample;
        ProfileName = profileName;
        UnsolicitedPolicy = unsolicitedPolicy;
        Predecessor = predecessor;
    }

    public CurrentlyAuthoritativeDca1 Authorization { get; }
    public VerifiedAccountDirectoryFreshness Freshness { get; }
    public VerifiedContactRouteClosure Route { get; }
    public IReadOnlyList<VerifiedContactPreKeyService> PreKeyServices { get; }
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> CurrentBootId { get; }
    public ulong CurrentMonotonicSample { get; }
    public string ProfileName { get; }
    public uint UnsolicitedPolicy { get; }
    public AuthoredPermanentContactPublication? Predecessor { get; }

    private static bool IsZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;
}

public sealed class AuthoredPermanentContactPublication
{
    private readonly byte[] protectedDcr1;
    private readonly byte[] locatorHash;

    internal AuthoredPermanentContactPublication(
        VerifiedContactBundleClosure verified,
        ReadOnlySpan<byte> protectedDcr1,
        ReadOnlySpan<byte> locatorHash)
    {
        Verified = verified;
        this.protectedDcr1 = protectedDcr1.ToArray();
        this.locatorHash = locatorHash.ToArray();
    }

    public VerifiedContactBundleClosure Verified { get; }
    public ContactRecord Bundle => Verified.Bundle;
    public ContactRecord ResolverResponse => Verified.ResolverResponse;
    public ReadOnlyMemory<byte> ProtectedDcr1 => protectedDcr1.ToArray();
    public ReadOnlyMemory<byte> LocatorHash => locatorHash.ToArray();
    public ulong Generation => BinaryPrimitives.ReadUInt64BigEndian(Bundle.Field(8).Span);
}

/// <summary>
/// CONTACT-PUBLICATION-AUTHOR-01. Authors only from verifier-minted identity,
/// directory freshness and route capabilities plus a bound device-custody signer.
/// </summary>
public static class ContactPublicationAuthor
{
    private const ushort Suite = 0x0201;

    public static async ValueTask<VerifiedContactPreKeyService> AuthorPreKeyServiceAsync(
        ContactPreKeyServiceAuthoringRequest request,
        IContactDeviceCustodySigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(signer);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var device = request.Device.Certificate;
            var identity = request.Authorization.Verified.Directory.Identity;
            if (!ReferenceEquals(identity, request.Authorization.Verified.Binding.Identity) ||
                !identity.ActiveDevices.Contains(request.Device) ||
                !Fixed(device.AccountHash.Span, identity.Account.DeepAccountIdHash.Span) ||
                !Fixed(device.NetworkId.Span, identity.Account.Certificate.NetworkId.Span))
                Fail("IdentityClosureMismatch", "XPS1 requires the exact active device in the authorized directory closure.");
            RequireSigner(signer, device);
            RequireWindow(request.IssuedAtUnixSeconds, request.ExpiresAtUnixSeconds,
                request.Authorization, device);

            byte[] capability;
            ulong generation;
            byte[] predecessorHash;
            if (request.Predecessor is null)
            {
                capability = RandomNonZero(32);
                generation = 0;
                predecessorHash = new byte[32];
            }
            else
            {
                capability = request.Predecessor.ServiceCapability.ToArray();
                generation = checked(request.Predecessor.Generation + 1);
                predecessorHash = SHA256.HashData(request.Predecessor.ExactXps1.Span);
                if (!Fixed(request.Predecessor.DeviceId.Span, device.DeviceId.Span))
                    Fail("PredecessorDeviceMismatch", "An XPS1 successor must preserve its verified device.");
            }

            var fields = new ReadOnlyMemory<byte>[]
            {
                device.NetworkId,
                capability,
                device.DeviceId,
                Reference(ProtocolMagic.DPD1, device.CanonicalHash.Span),
                U64(generation),
                predecessorHash,
                U16(Suite),
                U16(request.MinimumOneTimeInventory),
                U16(request.LastResortReuseLimit),
                U64(request.IssuedAtUnixSeconds),
                U64(request.ExpiresAtUnixSeconds),
                PlaceholderSignature(),
            };
            var provisional = EncodeXps1(fields);
            var input = ContactCodec.SignatureInput(
                "Deep/ContactResolver/V1/prekey-service", ProjectXps1(provisional));
            fields[11] = await SignAsync(
                ContactDeviceSignaturePurpose.PreKeyService, device, signer, input,
                cancellationToken).ConfigureAwait(false);
            var exact = EncodeXps1(fields);
            var parsed = ContactCodec.DecodeXps1(exact);
            if (!PublicKeyAuth.VerifyDetached(
                    fields[11].ToArray(), input, device.DeviceEd25519PublicKey.ToArray()))
                Fail("InvalidCustodySignature", "The custody signer returned an invalid XPS1 signature.");
            return new VerifiedContactPreKeyService(
                exact, parsed.ServiceCapability, parsed.DeviceId, parsed.ServiceGeneration,
                parsed.IssuedAtUnixSeconds, parsed.ExpiresAtUnixSeconds);
        }
        catch (ContactPublicationAuthoringException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or
            CryptographicException or OverflowException)
        {
            throw new ContactPublicationAuthoringException(
                "InvalidPreKeyServiceAuthoringInput",
                "The exact XPS1 authoring inputs are invalid.", exception);
        }
    }

    public static async ValueTask<AuthoredPermanentContactPublication> AuthorPermanentAsync(
        ContactBundleAuthoringRequest request,
        IContactDeviceCustodySigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(signer);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var authorization = request.Authorization;
            var directory = authorization.Verified.Directory;
            var binding = authorization.Verified.Binding;
            var identity = directory.Identity;
            var publisher = identity.ActiveDevices.SingleOrDefault(device =>
                Fixed(device.Certificate.DeviceId.Span,
                    authorization.Verified.Record.PublisherDeviceId.Span))
                ?? throw Error("PublisherNotActive", "The authorized Contact publisher is not active.");
            RequireSigner(signer, publisher.Certificate);
            RequirePublicationClosure(request, publisher);

            var orderedServices = request.PreKeyServices
                .OrderBy(service => service.DeviceId.ToArray(), ByteArrayComparer.Instance)
                .ToArray();
            var orderedDevices = identity.ActiveDevices
                .OrderBy(device => device.Certificate.DeviceId.ToArray(), ByteArrayComparer.Instance)
                .ToArray();
            if (orderedServices.Length != orderedDevices.Length)
                Fail("IncompletePreKeyServiceSet", "DCB1 requires one exact XPS1 for every active device.");
            for (var index = 0; index < orderedDevices.Length; index++)
            {
                var service = orderedServices[index];
                var device = orderedDevices[index].Certificate;
                if (!Fixed(service.DeviceId.Span, device.DeviceId.Span) ||
                    service.IssuedAtUnixSeconds > request.Freshness.TrustedLowerUnixSeconds ||
                    service.ExpiresAtUnixSeconds <= request.Freshness.TrustedUpperUnixSeconds)
                    Fail("InvalidPreKeyServiceSet", "An XPS1 does not bind and cover its exact active device.");
            }

            var bundleId = request.Predecessor is null
                ? RandomNonZero(32)
                : request.Predecessor.Bundle.Field(7).ToArray();
            var generation = request.Predecessor is null
                ? 0UL
                : checked(request.Predecessor.Generation + 1);
            var predecessorHash = request.Predecessor is null
                ? new byte[32]
                : request.Predecessor.Bundle.ArtifactHash.ToArray();
            if (generation > authorization.Verified.Record.MaximumBundleGeneration)
                Fail("BundleGenerationNotAuthorized", "The DCB1 generation exceeds DCA1 authority.");

            var xpsList = EncodeXpsList(orderedServices);
            var reachability = EncodeReachability(request.Route.Invite);
            var account = identity.Account.Certificate;
            var revocations = identity.Revocations.Snapshot;
            var lookupPreimage = Join(account.NetworkId.Span, binding.DeepId.CanonicalBytes.Span);
            var directoryLookupKey = AccountDirectoryCrypto.Sha256Domain(
                AccountDirectoryAdc1Verifier.LookupDomain, lookupPreimage);
            var adl = AccountDirectoryAdl1Codec.Encode(new AccountDirectoryAdl1(
                account.NetworkId.Span, directoryLookupKey,
                request.Freshness.AdhGeneration, request.Freshness.ExactAdh1CoreHash.Span,
                1, new byte[38], new byte[32]));

            var fields = new ReadOnlyMemory<byte>[]
            {
                account.NetworkId,
                identity.Account.DeepAccountIdHash,
                account.CanonicalBytes,
                Reference(ProtocolMagic.DRS1, revocations.CanonicalHash.Span),
                directory.Record.CanonicalBytes,
                authorization.Verified.Record.CanonicalBytes,
                bundleId,
                U64(generation),
                predecessorHash,
                publisher.Certificate.DeviceId,
                new[] { checked((byte)orderedServices.Length) },
                xpsList,
                new byte[] { 1 },
                reachability,
                Encoding.UTF8.GetBytes(request.ProfileName),
                U32(request.UnsolicitedPolicy),
                U64(request.IssuedAtUnixSeconds),
                U64(request.ExpiresAtUnixSeconds),
                PlaceholderSignature(),
                adl,
                Join(U64(request.Freshness.AdhGeneration), request.Freshness.ExactAdh1CoreHash.Span),
                binding.DeepId.RecordHash,
                binding.DeepId.AddressPublicKey,
                binding.Record.CanonicalBytes,
            };
            var provisional = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.DCB1, fields);
            fields[18] = await SignAsync(
                ContactDeviceSignaturePurpose.ContactBundle, publisher.Certificate, signer,
                provisional.SignatureInput, cancellationToken).ConfigureAwait(false);
            var bundle = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.DCB1, fields);
            if (!PublicKeyAuth.VerifyDetached(
                    fields[18].ToArray(), bundle.SignatureInput.ToArray(),
                    publisher.Certificate.DeviceEd25519PublicKey.ToArray()))
                Fail("InvalidCustodySignature", "The custody signer returned an invalid DCB1 signature.");

            var support = EncodeSupport(identity);
            var dcr = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.DCR1,
            [
                account.NetworkId,
                bundle.CanonicalBytes,
                U16(checked((ushort)(identity.ActiveDevices.Count + 1))),
                support,
            ]);
            var verified = ContactCodec.VerifyDcr1Closure(
                dcr, authorization, request.Freshness, request.CurrentBootId.Span,
                request.CurrentMonotonicSample);
            using var resolution = PermanentContactResolutionDerivation.Derive(
                account.NetworkId.Span, binding.DeepId);
            var protectedDcr = Dcr1ObjectProtectionCodec.SealPermanent(
                dcr, account.NetworkId.Span, binding.DeepId, resolution);
            return new AuthoredPermanentContactPublication(
                verified, protectedDcr, resolution.LocatorHash.Span);
        }
        catch (ContactPublicationAuthoringException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or
            CryptographicException or OverflowException or InvalidOperationException)
        {
            throw new ContactPublicationAuthoringException(
                "InvalidContactPublicationAuthoringInput",
                "The exact permanent Contact publication inputs are invalid.", exception);
        }
    }

    private static void RequirePublicationClosure(
        ContactBundleAuthoringRequest request,
        VerifiedDevice publisher)
    {
        var authorization = request.Authorization.Verified.Record;
        var authority = request.Route.Authority;
        var invite = request.Route.Invite;
        var network = publisher.Certificate.NetworkId.Span;
        if (!Fixed(authority.NetworkId.Span, network) ||
            !Fixed(authority.RecipientDeviceId.Span, publisher.Certificate.DeviceId.Span) ||
            !Fixed(authority.Dca1Reference.Span,
                Reference(ProtocolMagic.DCA1, authorization.RecordHash.Span)) ||
            !Fixed(invite.Field(15).Span,
                Reference(ProtocolMagic.DPD1, publisher.Certificate.CanonicalHash.Span)) ||
            !Fixed(invite.Field(16).Span, authority.Dca1Reference.Span))
            Fail("RouteAuthorityMismatch", "The verified route does not belong to the exact Contact publisher.");
        if (request.Freshness.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue ||
            request.Freshness.CurrentCheckpoint is null ||
            !request.Freshness.IsCurrentAtMonotonic(
                request.CurrentBootId.Span, request.CurrentMonotonicSample))
            Fail("DirectoryFreshnessExpired", "The Contact publication requires a current account-directory proof.");
        if (request.IssuedAtUnixSeconds > request.Freshness.TrustedLowerUnixSeconds ||
            request.ExpiresAtUnixSeconds <= request.Freshness.TrustedUpperUnixSeconds ||
            request.IssuedAtUnixSeconds < authorization.NotBeforeUnixSeconds ||
            request.ExpiresAtUnixSeconds > authorization.ExpiresAtUnixSeconds ||
            request.IssuedAtUnixSeconds < publisher.Certificate.IssuedAtUnixSeconds ||
            request.ExpiresAtUnixSeconds > publisher.Certificate.ExpiresAtUnixSeconds ||
            request.IssuedAtUnixSeconds < BinaryPrimitives.ReadUInt64BigEndian(invite.Field(13).Span) ||
            request.ExpiresAtUnixSeconds > BinaryPrimitives.ReadUInt64BigEndian(invite.Field(14).Span))
            Fail("PublicationWindowMismatch", "The DCB1 lifetime exceeds its verified authority closure.");
    }

    private static void RequireWindow(
        ulong issuedAt,
        ulong expiresAt,
        CurrentlyAuthoritativeDca1 authorization,
        DeviceCertificate device)
    {
        if (issuedAt > authorization.TrustedUnixSeconds ||
            expiresAt <= authorization.TrustedUnixSeconds ||
            issuedAt < authorization.Verified.Record.NotBeforeUnixSeconds ||
            expiresAt > authorization.Verified.Record.ExpiresAtUnixSeconds ||
            issuedAt < device.IssuedAtUnixSeconds || expiresAt > device.ExpiresAtUnixSeconds)
            Fail("PreKeyServiceWindowMismatch", "XPS1 lifetime exceeds its verified device/DCA1 authority.");
    }

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
