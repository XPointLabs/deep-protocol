using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.ContactV1;

public sealed class Xis1InviteClaimReceiptException : CryptographicException
{
    internal Xis1InviteClaimReceiptException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Non-serializable proof that the two replicas selected by an exact current
/// ResolveInvite placement authenticated one durable, one-time XIS1 claim.
/// </summary>
public sealed class VerifiedXis1InviteClaimReceipt
{
    private readonly byte[] _exactXiq1;
    private readonly byte[] _exactXis1;
    private readonly byte[] _networkId;
    private readonly byte[] _operationId;
    private readonly byte[] _requestHash;
    private readonly byte[] _locatorHash;
    private readonly byte[] _viewHash;
    private readonly byte[] _placementHash;
    private readonly byte[] _objectCiphertextHash;
    private readonly byte[] _objectCiphertext;
    private readonly byte[] _routeClosureHash;
    private readonly byte[] _exactRouteClosure;
    private readonly byte[][] _replicaNodeIds;

    internal VerifiedXis1InviteClaimReceipt(
        Xiq1Request request,
        Xis1Result result,
        IReadOnlyList<VerifiedNetworkNode> replicas)
    {
        _exactXiq1 = request.CanonicalBytes.ToArray();
        _exactXis1 = result.CanonicalBytes.ToArray();
        _networkId = request.NetworkId.ToArray();
        _operationId = request.OperationId.ToArray();
        _requestHash = request.RequestHash.ToArray();
        _locatorHash = request.LocatorHash.ToArray();
        _viewHash = request.ViewHash.ToArray();
        _placementHash = request.PlacementHash.ToArray();
        PublicationGeneration = ServiceWire.U64(result.FieldSpan(16));
        CurrentPublicationExpiresAtUnixSeconds = ServiceWire.U64(result.FieldSpan(17));
        _objectCiphertextHash = result.FieldSpan(18).ToArray();
        _objectCiphertext = result.FieldSpan(19).ToArray();
        _routeClosureHash = result.FieldSpan(20).ToArray();
        _exactRouteClosure = result.FieldSpan(21).ToArray();
        ClaimCommitGeneration = ServiceWire.U64(result.FieldSpan(22));
        ServerTimeUnixSeconds = result.ServerTimeUnixSeconds;
        _replicaNodeIds = replicas
            .OrderBy(static replica => replica.NodeId, ByteArrayComparer.Instance)
            .Select(static replica => replica.NodeId.ToArray())
            .ToArray();
    }

    public ReadOnlyMemory<byte> ExactXiq1 => _exactXiq1.ToArray();
    public ReadOnlyMemory<byte> ExactXis1 => _exactXis1.ToArray();
    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> OperationId => _operationId.ToArray();
    public ReadOnlyMemory<byte> RequestHash => _requestHash.ToArray();
    public ReadOnlyMemory<byte> LocatorHash => _locatorHash.ToArray();
    public ReadOnlyMemory<byte> ViewHash => _viewHash.ToArray();
    public ReadOnlyMemory<byte> PlacementHash => _placementHash.ToArray();
    public ulong PublicationGeneration { get; }
    public ulong CurrentPublicationExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> ObjectCiphertextHash => _objectCiphertextHash.ToArray();
    public ReadOnlyMemory<byte> ObjectCiphertext => _objectCiphertext.ToArray();
    public ReadOnlyMemory<byte> RouteClosureHash => _routeClosureHash.ToArray();
    public ReadOnlyMemory<byte> ExactRouteClosure => _exactRouteClosure.ToArray();
    public ulong ClaimCommitGeneration { get; }
    public ulong ServerTimeUnixSeconds { get; }
    public IReadOnlyList<ReadOnlyMemory<byte>> ReplicaNodeIds =>
        Array.AsReadOnly(_replicaNodeIds.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}

public static class Xis1InviteClaimReceiptVerifier
{
    private const string SignatureDomain = "Deep/ContactResolver/V1/invite-claim-commit";
    private const int ReceiptCount = 2;
    private const int ReceiptWidth = 96;
    private const int ReceiptContainerLength = 1 + (ReceiptCount * ReceiptWidth);
    private const int TranscriptLength = 160;

    public static VerifiedXis1InviteClaimReceipt Verify(
        Xiq1Request request,
        Xis1Result result,
        VerifiedContactServicePlacement placement)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(placement);

        try
        {
            VerifyPlacementAndCorrelation(request, result, placement);
            VerifyOneTimeShapeAndHashes(request, result, placement);
            var replicas = placement.ResolveSelectedReplicas();
            VerifyReplicaReceipts(request, result, replicas);
            return new VerifiedXis1InviteClaimReceipt(request, result, replicas);
        }
        catch (Xis1InviteClaimReceiptException)
        {
            throw;
        }
        catch (OnionBoundaryException exception)
        {
            throw new Xis1InviteClaimReceiptException(
                "PlacementNotCurrent", "The verified resolver placement is unavailable or no longer current.", exception);
        }
        catch (Exception exception) when (exception is ArgumentException or CryptographicException or OverflowException)
        {
            throw new Xis1InviteClaimReceiptException(
                "InvalidInviteClaimReceipt", "The XIS1 one-time invite claim receipt is invalid.", exception);
        }
    }

    private static void VerifyPlacementAndCorrelation(
        Xiq1Request request,
        Xis1Result result,
        VerifiedContactServicePlacement placement)
    {
        var trustedTime = placement.Network.TrustedTime ??
            throw new Xis1InviteClaimReceiptException(
                "PlacementTimeMissing", "The verified resolver placement has no production trusted-time lease.");
        try
        {
            trustedTime.EnsureLive();
        }
        catch (OnionBoundaryException exception)
        {
            throw new Xis1InviteClaimReceiptException(
                "PlacementNotCurrent", "The verified resolver placement trusted-time lease has expired.", exception);
        }

        if (!placement.Binds(ContactServiceRequestKind.ResolveInvite, request.LocatorHash) ||
            placement.RequestKind != ContactServiceRequestKind.ResolveInvite ||
            placement.ServiceClass != ContactServiceClass.InviteResolver ||
            !Fixed(request.NetworkId.Span, placement.Network.NetworkId.Span) ||
            !Fixed(request.ViewHash.Span, placement.ViewHash.Span) ||
            !Fixed(request.PlacementHash.Span, placement.PlacementHash.Span))
            Fail("PlacementMismatch", "XIQ1 is not bound to the exact current ResolveInvite placement and shard.");

        if (!Fixed(result.NetworkId.Span, request.NetworkId.Span) ||
            !Fixed(result.OperationId.Span, request.OperationId.Span) ||
            !Fixed(result.RequestHash.Span, request.RequestHash.Span))
            Fail("RequestCorrelationMismatch", "XIS1 does not authenticate the exact supplied XIQ1 request.");
    }

    private static void VerifyOneTimeShapeAndHashes(
        Xiq1Request request,
        Xis1Result result,
        VerifiedContactServicePlacement placement)
    {
        if (result.Status != Xis1Status.Success ||
            result.MutationOutcome != ContactServiceMutationOutcome.DurablyCommitted ||
            result.RetryAfterSeconds != 0 ||
            result.Field(22).Length != sizeof(ulong) ||
            result.Field(23).Length != ReceiptContainerLength)
            Fail("NotOneTimeClaim", "Only a durably committed XIS1 Success with the exact one-time claim fields is accepted.");

        var publicationGeneration = ServiceWire.U64(result.FieldSpan(16));
        var currentPublicationExpiresAt = ServiceWire.U64(result.FieldSpan(17));
        var claimCommitGeneration = ServiceWire.U64(result.FieldSpan(22));
        if ((request.RequestedGeneration != 0 && request.RequestedGeneration != publicationGeneration) ||
            claimCommitGeneration == 0)
            Fail("ClaimGenerationMismatch", "The claimed publication or claim commit generation is invalid.");

        if (request.IssuedAtUnixSeconds > result.ServerTimeUnixSeconds ||
            result.ServerTimeUnixSeconds >= request.ExpiresAtUnixSeconds ||
            request.ExpiresAtUnixSeconds > placement.ValidUntilUnixSeconds ||
            result.ServerTimeUnixSeconds >= placement.ValidUntilUnixSeconds ||
            result.ServerTimeUnixSeconds >= currentPublicationExpiresAt)
            Fail("ClaimTimeInvalid", "The request, signed server time, publication and placement windows do not overlap.");

        var objectHash = SHA256.HashData(result.FieldSpan(19));
        var routeHash = SHA256.HashData(result.FieldSpan(21));
        try
        {
            if (!Fixed(objectHash, result.FieldSpan(18)))
                Fail("ObjectCiphertextHashMismatch", "The exact returned object ciphertext does not match XIS1 tag 18.");
            if (!Fixed(routeHash, result.FieldSpan(20)))
                Fail("RouteClosureHashMismatch", "The exact returned route closure does not match XIS1 tag 20.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(objectHash);
            CryptographicOperations.ZeroMemory(routeHash);
        }
    }

    private static void VerifyReplicaReceipts(
        Xiq1Request request,
        Xis1Result result,
        IReadOnlyList<VerifiedNetworkNode> selectedReplicas)
    {
        if (selectedReplicas.Count != ReceiptCount)
            Fail("ReplicaSetMismatch", "The exact verified placement must select exactly two resolver replicas.");

        var replicas = selectedReplicas
            .OrderBy(static replica => replica.NodeId, ByteArrayComparer.Instance)
            .ToArray();
        if (Fixed(replicas[0].NodeId, replicas[1].NodeId) ||
            Fixed(replicas[0].FailureDomainHash, replicas[1].FailureDomainHash))
            Fail("ReplicaDiversityInvalid", "The two selected replicas must have distinct node and failure-domain identities.");

        var receiptMemory = result.Field(23);
        var receipts = receiptMemory.Span;
        if (receipts.Length != ReceiptContainerLength || receipts[0] != ReceiptCount)
            Fail("ReplicaReceiptShapeInvalid", "XIS1 must contain exactly two canonical replica receipt rows.");

        var tuple = new byte[TranscriptLength];
        byte[]? signingInput = null;
        try
        {
            var offset = 0;
            request.RequestHash.Span.CopyTo(tuple.AsSpan(offset, 32)); offset += 32;
            request.LocatorHash.Span.CopyTo(tuple.AsSpan(offset, 32)); offset += 32;
            BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(offset, 8), ServiceWire.U64(result.FieldSpan(16))); offset += 8;
            BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(offset, 8), ServiceWire.U64(result.FieldSpan(17))); offset += 8;
            result.FieldSpan(18).CopyTo(tuple.AsSpan(offset, 32)); offset += 32;
            result.FieldSpan(20).CopyTo(tuple.AsSpan(offset, 32)); offset += 32;
            BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(offset, 8), ServiceWire.U64(result.FieldSpan(22))); offset += 8;
            BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(offset, 8), result.ServerTimeUnixSeconds);
            signingInput = ContactCodec.SignatureInput(SignatureDomain, tuple);

            for (var index = 0; index < ReceiptCount; index++)
            {
                var row = receipts.Slice(1 + (index * ReceiptWidth), ReceiptWidth);
                if (!Fixed(row[..32], replicas[index].NodeId))
                    Fail("ReplicaSetMismatch", "A receipt signer is not the corresponding selected placement replica.");

                bool valid;
                try
                {
                    var identityPublicKey = replicas[index].IdentityPublicKey;
                    if (identityPublicKey is not { Length: 32 })
                        Fail("ReplicaIdentityKeyMissing", "A selected replica has no NETCODEC-verified XND1 identity key.");
                    valid = PublicKeyAuth.VerifyDetached(
                        row[32..].ToArray(), signingInput, identityPublicKey!.ToArray());
                }
                catch (Exception exception) when (exception is ArgumentException or CryptographicException)
                {
                    throw new Xis1InviteClaimReceiptException(
                        "InvalidReplicaSignature", "A selected replica XND1 identity signature is invalid.", exception);
                }
                if (!valid)
                    Fail("InvalidReplicaSignature", "A selected replica XND1 identity signature is invalid.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tuple);
            if (signingInput is not null) CryptographicOperations.ZeroMemory(signingInput);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    [DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new Xis1InviteClaimReceiptException(code, message);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
