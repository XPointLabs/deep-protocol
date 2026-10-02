using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.AccountDirectoryV1;

public sealed class AccountDirectoryProofAuthoringException : CryptographicException
{
    internal AccountDirectoryProofAuthoringException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Threshold witness boundary. Implementations own custody and policy; the protocol author only
/// supplies a short-lived canonical DTT1 signing input and verifies the returned signature.
/// </summary>
public interface IAccountDirectoryDtt1WitnessSigner
{
    ReadOnlyMemory<byte> WitnessId { get; }

    ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(
        ReadOnlyMemory<byte> signingInput,
        CancellationToken cancellationToken);
}

/// <summary>Exact request and trusted-time inputs for one nonce-bound directory response.</summary>
public sealed class AccountDirectoryProofAuthoringRequest
{
    private readonly byte[] networkId;
    private readonly byte[] nonce;
    private readonly byte[] bootId;
    private readonly byte[] exactCurrentAdh1;
    private readonly byte[] exactCurrentXnv1;

    public AccountDirectoryProofAuthoringRequest(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> bootId,
        ulong clientMonotonicSendSample,
        ReadOnlySpan<byte> exactCurrentAdh1,
        ReadOnlySpan<byte> exactCurrentXnv1,
        ulong observedUnixTime,
        uint uncertaintySeconds,
        ulong issuedAtUnixTime,
        ulong expiresAtUnixTime,
        AccountDirectoryDtt1IssuanceEpoch issuanceEpoch,
        ushort supportedReader)
    {
        this.networkId = Required(networkId, 16, nameof(networkId));
        this.nonce = Required(nonce, 32, nameof(nonce));
        this.bootId = Required(bootId, 16, nameof(bootId));
        this.exactCurrentAdh1 = Bounded(exactCurrentAdh1, nameof(exactCurrentAdh1));
        this.exactCurrentXnv1 = Bounded(exactCurrentXnv1, nameof(exactCurrentXnv1));
        ClientMonotonicSendSample = clientMonotonicSendSample;
        ObservedUnixTime = observedUnixTime;
        if (uncertaintySeconds > 30)
            throw new ArgumentOutOfRangeException(nameof(uncertaintySeconds));
        UncertaintySeconds = uncertaintySeconds;
        IssuedAtUnixTime = issuedAtUnixTime;
        ExpiresAtUnixTime = expiresAtUnixTime;
        if (expiresAtUnixTime <= issuedAtUnixTime || expiresAtUnixTime - issuedAtUnixTime > 60)
            throw new ArgumentException("The issued DTT1 interval must be non-empty and at most 60 seconds.", nameof(expiresAtUnixTime));
        IssuanceEpoch = issuanceEpoch ?? throw new ArgumentNullException(nameof(issuanceEpoch));
        IssuanceEpoch.RequireRequest(
            networkId, observedUnixTime, uncertaintySeconds, issuedAtUnixTime, expiresAtUnixTime);
        if (supportedReader == 0)
            throw new ArgumentOutOfRangeException(nameof(supportedReader));
        SupportedReader = supportedReader;
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> Nonce => nonce.ToArray();
    public ReadOnlyMemory<byte> BootId => bootId.ToArray();
    public ulong ClientMonotonicSendSample { get; }
    public ReadOnlyMemory<byte> ExactCurrentAdh1 => exactCurrentAdh1.ToArray();
    public ReadOnlyMemory<byte> ExactCurrentXnv1 => exactCurrentXnv1.ToArray();
    public ulong ObservedUnixTime { get; }
    public uint UncertaintySeconds { get; }
    public ulong IssuedAtUnixTime { get; }
    public ulong ExpiresAtUnixTime { get; }
    public AccountDirectoryDtt1IssuanceEpoch IssuanceEpoch { get; }
    public ushort SupportedReader { get; }

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }

    private static byte[] Bounded(ReadOnlySpan<byte> value, string name)
    {
        if (value.IsEmpty || value.Length > 65_535)
            throw new ArgumentException($"{name} must contain 1..65535 canonical bytes.", name);
        return value.ToArray();
    }
}

public static class AccountDirectoryProofAuthor
{

    /// <summary>
    /// Read-only issuance-context check for readiness. Performs the same head,
    /// time, authority and signed-view checks as proof authoring, but does not
    /// sign, consume a nonce, create a proof or mint a mutation capability.
    /// </summary>
    public static void RequireIssuanceReady(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProtectedLkg currentHead,
        AccountDirectoryProofAuthoringRequest request)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(currentHead);
        ArgumentNullException.ThrowIfNull(request);
        _ = ValidateIssuanceContext(authority, currentHead, request);
    }

    private static Xnv1Record ValidateIssuanceContext(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProtectedLkg currentHead,
        AccountDirectoryProofAuthoringRequest request)
    {
        if (!Fixed(authority.NetworkId.Span, request.NetworkId.Span) ||
            !Fixed(authority.NetworkId.Span, currentHead.Head.NetworkId.Span))
            Fail("NetworkMismatch", "The authority, request and current ADH1 network IDs differ.");
        request.IssuanceEpoch.RequireAuthority(authority);
        if (!Fixed(currentHead.ExactAdh1.Span, request.ExactCurrentAdh1.Span))
            Fail("ExactAdhMismatch", "The supplied exact ADH1 differs from the verified current-head capability.");
        if (!Fixed(currentHead.Head.ExactXnaAuthorityCoreReference.Span, authority.AuthorityCoreReference.Span) ||
            !Fixed(currentHead.Head.WitnessPolicyHash.Span, authority.DirectoryWitnessPolicyHash.Span))
            Fail("AuthorityMismatch", "The current ADH1 is not bound to the exact current XPoint authority and witness policy.");
        if (request.UncertaintySeconds > authority.MaximumWitnessUncertaintySeconds)
            Fail("UncertaintyExceeded", "The DTT1 uncertainty exceeds the exact authority policy.");

        var lower = request.ObservedUnixTime >= request.UncertaintySeconds
            ? request.ObservedUnixTime - request.UncertaintySeconds
            : 0;
        ulong upper;
        try { upper = checked(request.ObservedUnixTime + request.UncertaintySeconds); }
        catch (OverflowException) { Fail("InvalidTimeInterval", "The observed time interval overflows."); throw; }
        if (request.IssuedAtUnixTime < lower || request.IssuedAtUnixTime > upper || upper > request.ExpiresAtUnixTime ||
            lower < currentHead.Head.ValidFrom || upper >= currentHead.Head.ValidUntil ||
            request.IssuedAtUnixTime < authority.NotBefore || request.ExpiresAtUnixTime > authority.ExpiresAt ||
            request.IssuedAtUnixTime < authority.Dts1NotBefore || request.ExpiresAtUnixTime > authority.Dts1ExpiresAt)
            Fail("InvalidTimeInterval", "The DTT1 interval is outside the exact ADH1/XNA1/DTS1 bounds.");
        if (currentHead.Head.MinimumReader > request.SupportedReader)
            Fail("UnsupportedReader", "The current ADH1 requires a newer reader.");

        return ValidateCurrentView(authority, request, lower, upper);
    }

    internal static Xnv1Record ValidateCurrentView(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryProofAuthoringRequest request,
        ulong trustedLower,
        ulong trustedUpper)
    {
        var exact = request.ExactCurrentXnv1.ToArray();
        var view = XPointNetworkCodec.Parse<Xnv1Record>(exact);
        if (!Fixed(view.CanonicalSpan, exact) ||
            !Fixed(view.NetworkId.Span, request.NetworkId.Span) ||
            !Fixed(view.AuthorizingXna.Encode(), authority.AuthorityCoreReference.Span) ||
            !Fixed(view.DirectoryWitnessPolicyHash.Span, authority.DirectoryWitnessPolicyHash.Span))
            Fail("CurrentViewMismatch", "The exact XNV1 is not bound to the request and current authority.");
        if (view.NotBefore > trustedLower || trustedUpper >= view.ExpiresAt ||
            request.IssuedAtUnixTime < view.NotBefore || request.ExpiresAtUnixTime > view.ExpiresAt)
            Fail("CurrentViewTimeMismatch", "The exact XNV1 does not cover the complete issued interval.");

        var keys = authority.WitnessKeys.ToDictionary(
            static key => Convert.ToHexString(key.Id.Span), StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var signingInput = XPointNetworkCrypto.ComputeSigningInput(view);
        try
        {
            foreach (var receipt in view.WitnessSignatures)
            {
                var id = Convert.ToHexString(receipt.Id.Span);
                if (!seen.Add(id))
                    Fail("CurrentViewWitnessInvalid", "XNV1 contains a duplicate witness receipt.");
                if (!keys.TryGetValue(id, out var key))
                    Fail("CurrentViewWitnessInvalid", "XNV1 contains an unknown witness receipt.");
                if (!PublicKeyAuth.VerifyDetached(
                        receipt.Signature.ToArray(), signingInput, key.Ed25519PublicKey.ToArray()))
                    Fail("CurrentViewWitnessInvalid", "XNV1 contains an unknown, duplicate or invalid witness receipt.");
                domains.Add(Convert.ToHexString(key.FailureDomainHash.Span));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingInput);
        }
        if (seen.Count < authority.WitnessThreshold || domains.Count < authority.WitnessThreshold)
            Fail("CurrentViewThresholdInvalid", "XNV1 does not meet the exact witness and failure-domain threshold.");
        return view;
    }

    internal static SignerBinding[] ValidateSigners(
        VerifiedXPointNetworkAuthority authority,
        IReadOnlyList<IAccountDirectoryDtt1WitnessSigner> signers)
    {
        if (signers.Count is < 1 or > 32)
            Fail("InsufficientSigners", "DTT1 requires between one and 32 configured witness signers.");
        var result = new SignerBinding[signers.Count];
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < signers.Count; index++)
        {
            var signer = signers[index] ?? throw new AccountDirectoryProofAuthoringException(
                "UnknownSigner", "A configured DTT1 witness signer is null.");
            var id = signer.WitnessId.ToArray();
            if (id.Length != 32 || id.AsSpan().IndexOfAnyExcept((byte)0) < 0 || !ids.Add(Convert.ToHexString(id)))
                Fail("DuplicateOrInvalidSigner", "Witness signer IDs must be non-zero, exact and unique.");
            var key = authority.WitnessKeys.FirstOrDefault(candidate => Fixed(candidate.Id.Span, id));
            if (key is null)
                Fail("UnknownSigner", "A configured signer is outside the exact XPoint authority witness set.");
            domains.Add(Convert.ToHexString(key.FailureDomainHash.Span));
            result[index] = new SignerBinding(signer, id, key.Ed25519PublicKey.ToArray());
        }
        if (result.Length < authority.WitnessThreshold || domains.Count < authority.WitnessThreshold)
            Fail("InsufficientSigners", "Configured witnesses do not meet the exact signer and failure-domain threshold.");
        Array.Sort(result, static (left, right) => left.Id.AsSpan().SequenceCompareTo(right.Id));
        return result;
    }

    internal static async ValueTask<AccountDirectoryDtt1> AuthorDtt1Async(
        VerifiedXPointNetworkAuthority authority,
        AccountDirectoryAdh1 head,
        Xnv1Record currentView,
        AccountDirectoryProofAuthoringRequest request,
        IReadOnlyList<SignerBinding> signers,
        CancellationToken cancellationToken)
    {
        var placeholders = signers.Select(static signer =>
            new AccountDirectoryDtt1WitnessReceipt(signer.Id, Enumerable.Repeat((byte)1, 64).ToArray())).ToArray();
        var unsigned = new AccountDirectoryDtt1(
            request.NetworkId.Span,
            request.Nonce.Span,
            request.ObservedUnixTime,
            request.UncertaintySeconds,
            AccountDirectoryCrypto.ComputeAdh1CoreHash(head),
            head.LogGeneration,
            currentView.CoreHash.Span,
            currentView.ViewGeneration,
            authority.AuthorityCoreReference.Span,
            authority.DirectoryWitnessPolicyHash.Span,
            request.IssuedAtUnixTime,
            request.ExpiresAtUnixTime,
            request.IssuanceEpoch.Id.Span,
            placeholders);

        var signingInput = AccountDirectoryCrypto.ComputeDtt1SigningInput(unsigned);
        var receipts = new AccountDirectoryDtt1WitnessReceipt[signers.Count];
        try
        {
            for (var index = 0; index < signers.Count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var perSignerInput = signingInput.ToArray();
                byte[] signature;
                try
                {
                    var returned = await signers[index].Signer
                        .SignDtt1Async(perSignerInput, cancellationToken)
                        .ConfigureAwait(false);
                    signature = returned.ToArray();
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    throw new AccountDirectoryProofAuthoringException(
                        "SignerFailed", "A configured DTT1 witness signer failed.", exception);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(perSignerInput);
                }

                try
                {
                    if (signature.Length != 64 || signature.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                        !PublicKeyAuth.VerifyDetached(signature, signingInput, signers[index].PublicKey))
                        Fail("InvalidSignerResult", "A configured witness returned an invalid DTT1 signature.");
                    receipts[index] = new AccountDirectoryDtt1WitnessReceipt(signers[index].Id, signature);
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

        return new AccountDirectoryDtt1(
            request.NetworkId.Span,
            request.Nonce.Span,
            request.ObservedUnixTime,
            request.UncertaintySeconds,
            AccountDirectoryCrypto.ComputeAdh1CoreHash(head),
            head.LogGeneration,
            currentView.CoreHash.Span,
            currentView.ViewGeneration,
            authority.AuthorityCoreReference.Span,
            authority.DirectoryWitnessPolicyHash.Span,
            request.IssuedAtUnixTime,
            request.ExpiresAtUnixTime,
            request.IssuanceEpoch.Id.Span,
            receipts);
    }

    private static byte[] WriteEnvelope(IReadOnlyList<byte[]> fields)
    {
        var length = checked(12 + fields.Sum(static value => 8 + value.Length));
        if (length > AccountDirectoryAdp1Codec.MaximumLength)
            Fail("ProofTooLarge", "The canonical ADP1 exceeds its protocol bound.");
        var output = new byte[length];
        ProtocolMagicBytes.ADP1.CopyTo(output);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), AccountDirectoryAdp1Codec.Version);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), AccountDirectoryAdp1Codec.Suite);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].CopyTo(output, offset);
            offset += fields[index].Length;
        }
        return output;
    }

    private static byte[] Flatten(IReadOnlyList<ReadOnlyMemory<byte>> values)
    {
        var output = new byte[checked(values.Sum(static value => value.Length))];
        var offset = 0;
        foreach (var value in values)
        {
            value.Span.CopyTo(output.AsSpan(offset));
            offset += value.Length;
        }
        return output;
    }

    private static byte[] Flatten(IReadOnlyList<byte[]> values)
    {
        var output = new byte[checked(values.Sum(static value => value.Length))];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }
        return output;
    }

    private static byte[] Lp32(ReadOnlySpan<byte> value)
    {
        var output = new byte[checked(4 + value.Length)];
        BinaryPrimitives.WriteUInt32BigEndian(output, checked((uint)value.Length));
        value.CopyTo(output.AsSpan(4));
        return output;
    }

    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new AccountDirectoryProofAuthoringException(code, message);

    internal sealed record SignerBinding(
        IAccountDirectoryDtt1WitnessSigner Signer,
        byte[] Id,
        byte[] PublicKey);

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
