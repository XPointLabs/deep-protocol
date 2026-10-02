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
