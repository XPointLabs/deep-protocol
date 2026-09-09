using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.DeepNative;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV1;

public sealed class PermanentContactResolveException : CryptographicException
{
    internal PermanentContactResolveException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Non-forgeable result of one permanent DID1 lookup. It closes an exact
/// non-consuming XIS1 response, two current resolver replicas, the protected
/// DCR1 object and the current account-directory identity/device state.
/// </summary>
public sealed class VerifiedPermanentContactResolveClosure
{
    private readonly byte[] _exactProtectedDcr1;
    private readonly byte[] _exactRouteClosure;
    private readonly byte[][] _replicaNodeIds;

    internal VerifiedPermanentContactResolveClosure(
        ParsedDid1 permanentDeepId,
        Xiq1Request request,
        Xis1Result result,
        ReadOnlySpan<byte> exactProtectedDcr1,
        VerifiedContactBundleClosure contact,
        VerifiedDevice publisherDevice,
        IReadOnlyList<VerifiedNetworkNode> replicas)
    {
        PermanentDeepId = permanentDeepId;
        Request = request;
        Result = result;
        _exactProtectedDcr1 = exactProtectedDcr1.ToArray();
        _exactRouteClosure = result.FieldSpan(21).ToArray();
        Contact = contact;
        PublisherDevice = publisherDevice;
        PublicationGeneration = ServiceWire.U64(result.FieldSpan(16));
        PublicationExpiresAtUnixSeconds = ServiceWire.U64(result.FieldSpan(17));
        ServerTimeUnixSeconds = result.ServerTimeUnixSeconds;
        _replicaNodeIds = replicas
            .OrderBy(static replica => replica.NodeId, ByteArrayComparer.Instance)
            .Select(static replica => replica.NodeId.ToArray())
            .ToArray();
    }

    public ParsedDid1 PermanentDeepId { get; }
    public Xiq1Request Request { get; }
    public Xis1Result Result { get; }
    public ReadOnlyMemory<byte> ExactProtectedDcr1 => _exactProtectedDcr1.ToArray();
    public ReadOnlyMemory<byte> ExactRouteClosure => _exactRouteClosure.ToArray();
    public VerifiedContactBundleClosure Contact { get; }
    public CurrentlyAuthoritativeDca1 Authorization => Contact.Authorization;
    public VerifiedDevice PublisherDevice { get; }
    public ulong PublicationGeneration { get; }
    public ulong PublicationExpiresAtUnixSeconds { get; }
    public ulong ServerTimeUnixSeconds { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> ReplicaNodeIds =>
        Array.AsReadOnly(_replicaNodeIds
            .Select(static value => (ReadOnlyMemory<byte>)value.ToArray())
            .ToArray());

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}

/// <summary>
/// Clean-break production producer for permanent Deep ID resolution. Trust is
/// derived only from sealed Protocol capabilities and exact canonical records;
/// callers cannot inject replica keys, a VerifiedDevice or a trust boolean.
/// </summary>
public static class PermanentContactResolveVerifier
{
    private const string SignatureDomain = "Deep/ContactResolver/V1/permanent-read-result";
    private const int ReceiptCount = 2;
    private const int ReceiptWidth = 96;
    private const int ReceiptContainerLength = 1 + (ReceiptCount * ReceiptWidth);
    private const int TranscriptLength = 152;

    public static VerifiedPermanentContactResolveClosure Verify(
        ParsedDid1 exactPermanentDeepId,
        Xiq1Request exactRequest,
        Xis1Result exactResult,
        ReadOnlyMemory<byte> exactProtectedDcr1,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedContactServicePlacement placement,
        ReadOnlySpan<byte> currentBootId,
        ulong currentMonotonicSample)
    {
        ArgumentNullException.ThrowIfNull(exactPermanentDeepId);
        ArgumentNullException.ThrowIfNull(exactRequest);
        ArgumentNullException.ThrowIfNull(exactResult);
        ArgumentNullException.ThrowIfNull(freshness);
        ArgumentNullException.ThrowIfNull(placement);

        try
        {
            var checkpoint = VerifyCurrentAuthority(
                exactPermanentDeepId, exactRequest, exactResult, freshness, placement,
                currentBootId, currentMonotonicSample);
            using var resolution = PermanentContactResolutionDerivation.Derive(
                exactRequest.NetworkId.Span, exactPermanentDeepId);
            if (!Fixed(resolution.LocatorHash.Span, exactRequest.LocatorHash.Span))
                Fail("PermanentLocatorMismatch", "XIQ1 does not use the locator derived from the exact permanent DID1.");
            if (!Fixed(exactProtectedDcr1.Span, exactResult.FieldSpan(19)))
                Fail("ProtectedObjectMismatch", "The protected DCR1 object is not the exact object authenticated by XIS1.");

            var replicas = VerifyReplicaReceipts(exactRequest, exactResult, placement);
            var dcr1 = Dcr1ObjectProtectionCodec.OpenPermanent(
                exactProtectedDcr1.Span, exactRequest.NetworkId.Span,
                exactPermanentDeepId, resolution);
            var bundle = ContactCodec.Decode(ProtocolMagic.DCB1, dcr1.FieldSpan(2));
            var publicationGeneration = ServiceWire.U64(exactResult.FieldSpan(16));
            if (ServiceWire.U64(bundle.FieldSpan(8)) != publicationGeneration)
                Fail("PublicationGenerationMismatch", "XIS1 and the authenticated DCB1 do not identify the same publication generation.");

            var dca1 = ApplicationCoreCodec.DecodeDca1(bundle.FieldSpan(6));
            var verifiedDca1 = ApplicationCoreVerifier.VerifyDca1(
                dca1, checkpoint.Binding, checkpoint.Directory);
            var authorization = ApplicationCoreVerifier.RequireDca1CurrentlyAuthoritative(
                verifiedDca1, exactResult.ServerTimeUnixSeconds);
            var contact = ContactCodec.VerifyDcr1Closure(
                dcr1, authorization, freshness, currentBootId, currentMonotonicSample);

            if (!Fixed(contact.Binding.DeepId.CanonicalBytes.Span, exactPermanentDeepId.CanonicalBytes.Span))
                Fail("PermanentIdentityMismatch", "The verified DCR1 identity is not the exact requested permanent DID1.");
            var publisherId = contact.Bundle.Field(10);
            var publisher = contact.Directory.Identity.ActiveDevices.SingleOrDefault(device =>
                Fixed(device.Certificate.DeviceId.Span, publisherId.Span));
            if (publisher is null)
                Fail("PublisherDeviceMissing", "The DCR1 publisher is not an active device in the current verified directory.");

            return new VerifiedPermanentContactResolveClosure(
                exactPermanentDeepId, exactRequest, exactResult, exactProtectedDcr1.Span,
                contact, publisher, replicas);
        }
        catch (PermanentContactResolveException)
        {
            throw;
        }
        catch (OnionBoundaryException exception)
        {
            throw new PermanentContactResolveException(
                "PlacementNotCurrent", "The permanent lookup placement is not current.", exception);
        }
        catch (Exception exception) when (
            exception is FormatException or ArgumentException or CryptographicException or OverflowException)
        {
            throw new PermanentContactResolveException(
                "PermanentResolveRejected",
                "The exact permanent DID1/XIS1/DCR1 identity closure was rejected.", exception);
        }
    }

    private static VerifiedAccountDirectoryCheckpoint VerifyCurrentAuthority(
        ParsedDid1 did1,
        Xiq1Request request,
        Xis1Result result,
        VerifiedAccountDirectoryFreshness freshness,
        VerifiedContactServicePlacement placement,
        ReadOnlySpan<byte> currentBootId,
        ulong currentMonotonicSample)
    {
        var checkpoint = freshness.CurrentCheckpoint;
        if (freshness.ResultKind != AccountDirectoryAdp1ResultKind.CurrentValue || checkpoint is null)
            Fail("CurrentDirectoryCheckpointRequired", "Permanent resolution requires an exact current ADC1 checkpoint.");
        if (!freshness.IsCurrentAtMonotonic(currentBootId, currentMonotonicSample))
            Fail("DirectoryFreshnessExpired", "The account-directory proof is not current at the supplied monotonic sample.");
        placement.Network.TrustedTime?.EnsureLive();
        if (placement.Network.TrustedTime is null)
            Fail("PlacementTimeMissing", "The verified resolver placement has no trusted-time lease.");

        if (!Fixed(did1.CanonicalBytes.Span, checkpoint.Binding.DeepId.CanonicalBytes.Span) ||
            !Fixed(did1.RecordHash.Span, checkpoint.Binding.DeepId.RecordHash.Span))
            Fail("PermanentIdentityMismatch", "The current ADC1 checkpoint does not bind the exact requested DID1.");
        if (!Fixed(request.NetworkId.Span, freshness.NetworkId.Span) ||
            !Fixed(request.NetworkId.Span, placement.Network.NetworkId.Span) ||
            !Fixed(result.NetworkId.Span, request.NetworkId.Span))
            Fail("NetworkMismatch", "DID1 directory, placement, request and result do not bind one network.");
        if (placement.RequestKind != ContactServiceRequestKind.ResolveInvite ||
            placement.ServiceClass != ContactServiceClass.InviteResolver ||
            !placement.Binds(ContactServiceRequestKind.ResolveInvite, request.LocatorHash) ||
            !Fixed(request.ViewHash.Span, placement.ViewHash.Span) ||
            !Fixed(request.PlacementHash.Span, placement.PlacementHash.Span))
            Fail("PlacementMismatch", "XIQ1 is not bound to the exact current permanent resolver placement.");
        if (!Fixed(result.OperationId.Span, request.OperationId.Span) ||
            !Fixed(result.RequestHash.Span, request.RequestHash.Span))
            Fail("RequestCorrelationMismatch", "XIS1 does not authenticate the exact supplied XIQ1 request.");

        if (result.Status != Xis1Status.Success ||
            result.MutationOutcome != ContactServiceMutationOutcome.None ||
            result.RetryAfterSeconds != 0 ||
            result.Field(22).Length != ReceiptContainerLength ||
            result.Field(23).Length != 0)
            Fail("NotPermanentRead", "Only a successful non-consuming XIS1 with permanent-read replica receipts is accepted.");

        var generation = ServiceWire.U64(result.FieldSpan(16));
        var publicationExpiresAt = ServiceWire.U64(result.FieldSpan(17));
        if (request.RequestedGeneration != 0 && request.RequestedGeneration != generation)
            Fail("PublicationGenerationMismatch", "XIS1 does not return the exact requested permanent publication generation.");
        if (request.IssuedAtUnixSeconds > result.ServerTimeUnixSeconds ||
            result.ServerTimeUnixSeconds >= request.ExpiresAtUnixSeconds ||
            request.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds ||
            result.ServerTimeUnixSeconds < freshness.TrustedLowerUnixSeconds ||
            result.ServerTimeUnixSeconds > freshness.TrustedUpperUnixSeconds ||
            publicationExpiresAt <= freshness.TrustedUpperUnixSeconds)
            Fail("PermanentReadTimeInvalid", "The signed permanent read is stale or outside the current trusted interval.");
        return checkpoint;
    }

    private static VerifiedNetworkNode[] VerifyReplicaReceipts(
        Xiq1Request request,
        Xis1Result result,
        VerifiedContactServicePlacement placement)
    {
        var selected = placement.ResolveSelectedReplicas();
        if (selected.Length != ReceiptCount)
            Fail("ReplicaSetMismatch", "The exact permanent resolver placement must select exactly two replicas.");
        var replicas = selected.OrderBy(static replica => replica.NodeId, ByteArrayComparer.Instance).ToArray();
        if (Fixed(replicas[0].NodeId, replicas[1].NodeId) ||
            Fixed(replicas[0].FailureDomainHash, replicas[1].FailureDomainHash))
            Fail("ReplicaDiversityInvalid", "Permanent-read replicas must have distinct node and failure-domain identities.");

        var receipts = result.FieldSpan(22);
        if (receipts.Length != ReceiptContainerLength || receipts[0] != ReceiptCount)
            Fail("ReplicaReceiptShapeInvalid", "XIS1 must contain exactly two canonical permanent-read receipt rows.");
        var transcript = new byte[TranscriptLength];
        byte[]? signingInput = null;
        try
        {
            var offset = 0;
            request.RequestHash.Span.CopyTo(transcript.AsSpan(offset, 32)); offset += 32;
            request.LocatorHash.Span.CopyTo(transcript.AsSpan(offset, 32)); offset += 32;
            BinaryPrimitives.WriteUInt64BigEndian(transcript.AsSpan(offset, 8), ServiceWire.U64(result.FieldSpan(16))); offset += 8;
            BinaryPrimitives.WriteUInt64BigEndian(transcript.AsSpan(offset, 8), ServiceWire.U64(result.FieldSpan(17))); offset += 8;
            result.FieldSpan(18).CopyTo(transcript.AsSpan(offset, 32)); offset += 32;
            result.FieldSpan(20).CopyTo(transcript.AsSpan(offset, 32)); offset += 32;
            BinaryPrimitives.WriteUInt64BigEndian(transcript.AsSpan(offset, 8), result.ServerTimeUnixSeconds);
            signingInput = ContactCodec.SignatureInput(SignatureDomain, transcript);

            for (var index = 0; index < ReceiptCount; index++)
            {
                var row = receipts.Slice(1 + (index * ReceiptWidth), ReceiptWidth);
                if (!Fixed(row[..32], replicas[index].NodeId))
                    Fail("ReplicaSetMismatch", "A permanent-read receipt signer is not the corresponding selected replica.");
                var publicKey = replicas[index].IdentityPublicKey;
                if (publicKey is not { Length: 32 })
                    Fail("ReplicaIdentityKeyMissing", "A selected replica has no NETCODEC-verified identity key.");
                bool valid;
                try
                {
                    valid = PublicKeyAuth.VerifyDetached(
                        row[32..].ToArray(), signingInput, publicKey.ToArray());
                }
                catch (Exception exception) when (exception is ArgumentException or CryptographicException)
                {
                    throw new PermanentContactResolveException(
                        "InvalidReplicaSignature", "A permanent-read replica signature is invalid.", exception);
                }
                if (!valid)
                    Fail("InvalidReplicaSignature", "A permanent-read replica signature is invalid.");
            }
            return replicas;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(transcript);
            if (signingInput is not null) CryptographicOperations.ZeroMemory(signingInput);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    [DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new PermanentContactResolveException(code, message);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
