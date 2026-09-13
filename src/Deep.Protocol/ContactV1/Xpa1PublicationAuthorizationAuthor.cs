using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV1;

public sealed class Xpa1PublicationAuthorizationAuthoringException : CryptographicException
{
    internal Xpa1PublicationAuthorizationAuthoringException(
        string code,
        string message,
        Exception? inner = null) : base(message, inner) => Code = code;

    public string Code { get; }
}

public interface IXpa1PublicationAuthorizationWitnessSigner
{
    ReadOnlyMemory<byte> WitnessId { get; }

    ValueTask<ReadOnlyMemory<byte>> SignXpa1Async(
        ReadOnlyMemory<byte> signingInput,
        CancellationToken cancellationToken);
}

public sealed class PermanentAddressPublicationAuthorizationRequest
{
    private readonly byte[] operationId;
    private readonly byte[] predecessorObjectHash;
    private readonly byte[] objectCiphertext;
    private readonly byte[] publisherSignature;

    public PermanentAddressPublicationAuthorizationRequest(
        ReadOnlySpan<byte> operationId,
        ulong generation,
        ReadOnlySpan<byte> predecessorObjectHash,
        ReadOnlySpan<byte> objectCiphertext,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        ulong effectiveExpiresAtUnixSeconds,
        ReadOnlySpan<byte> publisherSignature)
    {
        this.operationId = Required(operationId, 32, nameof(operationId));
        this.predecessorObjectHash = Exact(predecessorObjectHash, 32, nameof(predecessorObjectHash));
        if ((generation == 0) != IsZero(this.predecessorObjectHash))
            throw new ArgumentException(
                "The predecessor object hash must be zero exactly at publication generation zero.",
                nameof(predecessorObjectHash));
        if (objectCiphertext.Length is < 40 or > 65_575)
            throw new ArgumentOutOfRangeException(nameof(objectCiphertext));
        this.objectCiphertext = objectCiphertext.ToArray();
        if (issuedAtUnixSeconds == 0 || expiresAtUnixSeconds <= issuedAtUnixSeconds ||
            effectiveExpiresAtUnixSeconds < expiresAtUnixSeconds)
            throw new ArgumentOutOfRangeException(nameof(expiresAtUnixSeconds));
        this.publisherSignature = Required(publisherSignature, 64, nameof(publisherSignature));
        Generation = generation;
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
        EffectiveExpiresAtUnixSeconds = effectiveExpiresAtUnixSeconds;
    }

    public ReadOnlyMemory<byte> OperationId => operationId.ToArray();
    public ulong Generation { get; }
    public ReadOnlyMemory<byte> PredecessorObjectHash => predecessorObjectHash.ToArray();
    public ReadOnlyMemory<byte> ObjectCiphertext => objectCiphertext.ToArray();
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ulong EffectiveExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> PublisherSignature => publisherSignature.ToArray();

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        var result = Exact(value, length, name);
        if (IsZero(result))
            throw new ArgumentException($"{name} must be nonzero.", name);
        return result;
    }

    private static byte[] Exact(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw new ArgumentException($"{name} must be exactly {length} bytes.", name);
        return value.ToArray();
    }

    private static bool IsZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;
}

public sealed class AuthoredPermanentAddressPublication
{
    private readonly byte[] exactXpa1;
    private readonly byte[] exactXpu1;

    internal AuthoredPermanentAddressPublication(
        ReadOnlySpan<byte> exactXpa1,
        Xpu1Request request,
        VerifiedXpa1PublicationAuthorization authorization)
    {
        this.exactXpa1 = exactXpa1.ToArray();
        exactXpu1 = request.CanonicalBytes.ToArray();
        Request = request;
        Authorization = authorization;
    }

    public ReadOnlyMemory<byte> ExactXpa1 => exactXpa1.ToArray();
    public ReadOnlyMemory<byte> ExactXpu1 => exactXpu1.ToArray();
    public Xpu1Request Request { get; }
    public VerifiedXpa1PublicationAuthorization Authorization { get; }
}

/// <summary>
/// Authors the invite-store-safe XPA1 projection only after receiving a fully
/// verified current account/contact closure and a device signature over the
/// publication tuple. DID/account/device bytes never enter the returned XPA1.
/// </summary>
public static class Xpa1PublicationAuthorizationAuthor
{
    private const string WitnessDomain = "Deep/ContactResolver/V1/publication-authorization";
    private const string PublisherDomain = "Deep/ContactResolver/V1/publisher-publication";
    private const string PolicyDomain = "Deep/ContactResolver/V1/publication-policy";
    private const string AuthorizationIdDomain = "Deep/ContactResolver/V1/publication-authorization-id";

    public static byte[] CreatePublisherSigningInput(
        ReadOnlySpan<byte> locatorHash,
        ReadOnlySpan<byte> exactDcr1Hash,
        ReadOnlySpan<byte> objectCiphertextHash,
        ReadOnlySpan<byte> routeClosureHash,
        ulong generation,
        ReadOnlySpan<byte> predecessorObjectHash,
        ulong effectiveExpiresAtUnixSeconds)
    {
        Require(locatorHash, 32, nameof(locatorHash), nonzero: true);
        Require(exactDcr1Hash, 32, nameof(exactDcr1Hash), nonzero: true);
        Require(objectCiphertextHash, 32, nameof(objectCiphertextHash), nonzero: true);
        Require(routeClosureHash, 32, nameof(routeClosureHash), nonzero: true);
        Require(predecessorObjectHash, 32, nameof(predecessorObjectHash), nonzero: generation != 0);
        if ((generation == 0) != IsZero(predecessorObjectHash) || effectiveExpiresAtUnixSeconds == 0)
            throw new ArgumentException("The publication generation, predecessor, or expiry is invalid.");
        var tuple = new byte[176];
        locatorHash.CopyTo(tuple);
        exactDcr1Hash.CopyTo(tuple.AsSpan(32));
        objectCiphertextHash.CopyTo(tuple.AsSpan(64));
        routeClosureHash.CopyTo(tuple.AsSpan(96));
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(128), generation);
        predecessorObjectHash.CopyTo(tuple.AsSpan(136));
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(168), effectiveExpiresAtUnixSeconds);
        try
        {
            return ContactCodec.SignatureInput(PublisherDomain, tuple);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tuple);
        }
    }

    public static async ValueTask<AuthoredPermanentAddressPublication> AuthorPermanentAsync(
        PermanentAddressPublicationAuthorizationRequest request,
        VerifiedContactBundleClosure contact,
        VerifiedContactRouteClosure route,
        VerifiedXPointNetworkAuthority authority,
        VerifiedContactServicePlacement placement,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        IReadOnlyList<IXpa1PublicationAuthorizationWitnessSigner> witnessSigners,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(contact);
        ArgumentNullException.ThrowIfNull(route);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(placement);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority);
        ArgumentNullException.ThrowIfNull(witnessSigners);
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var freshness = contact.Freshness;
            if (!ReferenceEquals(freshness.CurrentCheckpoint?.Binding, contact.Binding) ||
                !ReferenceEquals(freshness.CurrentCheckpoint.Directory, contact.Directory) ||
                !Fixed(authority.NetworkId.Span, contact.Bundle.Field(1).Span) ||
                !Fixed(authority.NetworkId.Span, freshness.NetworkId.Span) ||
                placement.RequestKind != ContactServiceRequestKind.PublishInvite ||
                placement.ServiceClass != ContactServiceClass.InviteResolver)
                Fail("ClosureMismatch", "The account, contact, directory, network, and placement capabilities do not share one closure.");

            using var resolution = PermanentContactResolutionDerivation.Derive(
                authority.NetworkId.Span, contact.Binding.DeepId);
            var locator = resolution.LocatorHash.ToArray();
            if (!placement.Binds(ContactServiceRequestKind.PublishInvite, locator))
                Fail("PlacementMismatch", "The verified placement does not bind the permanent locator.");

            var dcrHash = contact.ResolverResponse.ArtifactHash.ToArray();
            var dcbHash = contact.Bundle.ArtifactHash.ToArray();
            var descriptor = contact.Bundle.Field(14).ToArray();
            if (descriptor.Length != 651)
                Fail("ContactDescriptorMismatch", "The verified DCB1 reachability descriptor has an invalid shape.");
            var xirHash = descriptor.AsSpan(4, 32).ToArray();
            var exactRouteClosure = ContactRouteClosureCodec.Encode(route);
            var routeClosureHash = SHA256.HashData(exactRouteClosure);
            var embeddedInvite = ContactCodec.Decode(
                ProtocolMagic.XIR1, descriptor.AsSpan(40, 611));
            if (!Fixed(route.Invite.CanonicalBytes.Span, embeddedInvite.CanonicalBytes.Span) ||
                !Fixed(route.Invite.ArtifactHash.Span, xirHash) ||
                !Fixed(route.Authority.NetworkId.Span, authority.NetworkId.Span) ||
                !Fixed(route.Authority.AuthorityCoreReference.Span,
                    authority.AuthorityCoreReference.Span) ||
                !Fixed(route.Authority.WitnessPolicyHash.Span,
                    authority.DirectoryWitnessPolicyHash.Span) ||
                !Fixed(route.Authority.RecipientDeviceId.Span, contact.Bundle.Field(10).Span) ||
                !Fixed(route.Authority.Dca1Reference.Span,
                    ContactReference(ProtocolMagic.DCA1,
                        contact.Authorization.Verified.Record.RecordHash.Span)))
                Fail("RouteClosureMismatch", "The verified route closure does not belong to the exact DCB1 publisher.");
            var ciphertextHash = SHA256.HashData(request.ObjectCiphertext.Span);
            var publisherInput = CreatePublisherSigningInput(
                locator,
                dcrHash,
                ciphertextHash,
                routeClosureHash,
                request.Generation,
                request.PredecessorObjectHash.Span,
                request.EffectiveExpiresAtUnixSeconds);
            try
            {
                var publisherDeviceId = contact.Bundle.Field(10).ToArray();
                var publisher = contact.Directory.Identity.ActiveDevices.SingleOrDefault(device =>
                    Fixed(device.Certificate.DeviceId.Span, publisherDeviceId));
                if (publisher is null || !PublicKeyAuth.VerifyDetached(
                        request.PublisherSignature.ToArray(),
                        publisherInput,
                        publisher.Certificate.DeviceEd25519PublicKey.ToArray()))
                    Fail("PublisherSignatureInvalid", "The current publisher device did not authorize the exact XPU1 body tuple.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publisherInput);
            }

            var policyHash = ContactCodec.Sha256Domain(
                PolicyDomain,
                contact.Authorization.Verified.Record.CanonicalBytes.Span);
            var bodyHash = Xpu1Codec.ComputeAuthorizedBodyHash(
                authority.NetworkId.Span,
                request.OperationId.Span,
                placement.ViewHash.Span,
                placement.PlacementHash.Span,
                request.IssuedAtUnixSeconds,
                request.ExpiresAtUnixSeconds,
                locator,
                xirHash,
                request.Generation,
                request.PredecessorObjectHash.Span,
                request.ObjectCiphertext.Span,
                0,
                request.EffectiveExpiresAtUnixSeconds,
                exactRouteClosure);
            var authorizationId = ContactCodec.Sha256Domain(
                AuthorizationIdDomain,
                Join(request.OperationId.ToArray(), bodyHash, freshness.ExactAdh1CoreHash.ToArray()));
            var signers = ValidateSigners(authority, witnessSigners);
            ReadOnlyMemory<byte>[] fields =
            [
                authority.NetworkId.ToArray(), authorizationId, request.OperationId.ToArray(), locator,
                new byte[] { (byte)Xpa1PublicationKind.PermanentAddress }, dcrHash, dcbHash, xirHash,
                U64(request.Generation), request.PredecessorObjectHash.ToArray(), ciphertextHash,
                U32(0), U64(request.EffectiveExpiresAtUnixSeconds), policyHash,
                U64(request.IssuedAtUnixSeconds), U64(request.IssuedAtUnixSeconds),
                U64(request.ExpiresAtUnixSeconds), freshness.ExactAdh1CoreHash.ToArray(), bodyHash,
                new byte[] { checked((byte)signers.Length) },
            ];
            var unsigned = ServiceWire.Project(
                ProtocolMagic.XPA1,
                fields.Select((field, index) =>
                    (checked((ushort)(index + 1)), field.ToArray())).ToArray());
            var signingInput = ContactCodec.SignatureInput(WitnessDomain, unsigned);
            var rows = new List<byte[]>(signers.Length);
            try
            {
                foreach (var signer in signers)
                {
                    var returned = await signer.Signer.SignXpa1Async(
                        signingInput.ToArray(), cancellationToken).ConfigureAwait(false);
                    var signature = returned.ToArray();
                    try
                    {
                        if (signature.Length != 64 || signature.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                            !PublicKeyAuth.VerifyDetached(signature, signingInput, signer.PublicKey))
                            Fail("InvalidSignerResult", "A configured witness returned an invalid XPA1 signature.");
                        rows.Add(Join(signer.Id, signature));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(signature);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(signingInput);
            }
            fields = fields.Append<ReadOnlyMemory<byte>>(Join(rows.ToArray())).ToArray();
            var xpa = ServiceWire.Project(
                ProtocolMagic.XPA1,
                fields.Select((field, index) =>
                    (checked((ushort)(index + 1)), field.ToArray())).ToArray());
            var exactXpu = Xpu1Codec.Encode(
                authority.NetworkId.Span,
                request.OperationId.Span,
                placement.ViewHash.Span,
                placement.PlacementHash.Span,
                request.IssuedAtUnixSeconds,
                request.ExpiresAtUnixSeconds,
                locator,
                xirHash,
                request.Generation,
                request.PredecessorObjectHash.Span,
                request.ObjectCiphertext.Span,
                0,
                request.EffectiveExpiresAtUnixSeconds,
                exactRouteClosure,
                xpa);
            var xpu = Xpu1Codec.Decode(exactXpu);
            var verified = await Xpa1PublicationAuthorizationVerifier.VerifyAsync(
                xpu,
                authority,
                freshness,
                placement,
                trustedTimeAuthority,
                cancellationToken).ConfigureAwait(false);
            return new AuthoredPermanentAddressPublication(xpa, xpu, verified);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Xpa1PublicationAuthorizationAuthoringException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or
            CryptographicException or OverflowException)
        {
            throw new Xpa1PublicationAuthorizationAuthoringException(
                "AuthoringRejected",
                "The permanent-address XPA1 authoring request failed closed.",
                exception);
        }
    }

    private static SignerBinding[] ValidateSigners(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<IXpa1PublicationAuthorizationWitnessSigner> signers)
    {
        if (signers.Count is < 1 or > 32)
            Fail("InsufficientSigners", "XPA1 requires between one and 32 configured witnesses.");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        var result = new SignerBinding[signers.Count];
        for (var index = 0; index < signers.Count; index++)
        {
            var signer = signers[index] ?? throw new Xpa1PublicationAuthorizationAuthoringException(
                "UnknownSigner", "A configured XPA1 signer is null.");
            var id = signer.WitnessId.ToArray();
            if (id.Length != 32 || id.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !ids.Add(Convert.ToHexString(id)))
                Fail("DuplicateOrInvalidSigner", "XPA1 witness IDs must be exact, nonzero, and unique.");
            var key = authority.WitnessKeys.SingleOrDefault(candidate => Fixed(candidate.Id.Span, id));
            if (key is null)
                Fail("UnknownSigner", "An XPA1 signer is outside the exact current witness set.");
            domains.Add(Convert.ToHexString(key.FailureDomainHash.Span));
            result[index] = new SignerBinding(signer, id, key.Ed25519PublicKey.ToArray());
        }
        if (result.Length < authority.WitnessThreshold || domains.Count < authority.WitnessThreshold)
            Fail("InsufficientSigners", "Configured XPA1 witnesses do not satisfy the current threshold.");
        Array.Sort(result, static (left, right) => left.Id.AsSpan().SequenceCompareTo(right.Id));
        return result;
    }

    private static byte[] Join(params byte[][] values)
    {
        var result = new byte[checked(values.Sum(static value => value.Length))];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(result.AsSpan(offset));
            offset += value.Length;
        }
        return result;
    }

    private static byte[] ContactReference(string magic, ReadOnlySpan<byte> hash)
    {
        var value = new byte[38];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(4), 1);
        hash.CopyTo(value.AsSpan(6));
        return value;
    }

    private static byte[] U32(uint value)
    {
        var result = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(result, value);
        return result;
    }

    private static byte[] U64(ulong value)
    {
        var result = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(result, value);
        return result;
    }

    private static void Require(ReadOnlySpan<byte> value, int length, string name, bool nonzero)
    {
        if (value.Length != length || nonzero && IsZero(value))
            throw new ArgumentException($"{name} must be exactly {length} bytes{(nonzero ? " and nonzero" : string.Empty)}.", name);
    }

    private static bool IsZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new Xpa1PublicationAuthorizationAuthoringException(code, message);

    private sealed record SignerBinding(
        IXpa1PublicationAuthorizationWitnessSigner Signer,
        byte[] Id,
        byte[] PublicKey);
}
