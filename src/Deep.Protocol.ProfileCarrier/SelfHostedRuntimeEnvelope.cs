using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.Membership;
using Sodium;

namespace Deep.Protocol.DeepExtension.SelfHostedProfiles;

public static class SelfHostedRuntimeEnvelopeContract
{
    public const string Identifier = "Deep.Protocol/UserManagedRuntime-v1";
    public const int MaximumEncodedBytes = 64 * 1024;
    public const int MaximumCapabilities = 16;
    public const int MaximumCapabilityBytes = 64;
    public const int MaximumOriginBytes = 512;
    public const int MaximumSignatures = 32;
    public const int MaximumSignatureBytes = 512;
    public const int HashLength = 32;
    public const int SpkiHashLength = 32;
    public const int MaximumValiditySeconds = 365 * 24 * 60 * 60;
    internal const int SigningDomainLength = 16;
    internal static ReadOnlySpan<byte> SigningDomain => "DEEP-SHR-V1\0\0\0\0\0"u8;
}

public sealed class SelfHostedRuntimeEndpoint
{
    private readonly byte[] currentSpkiSha256;
    private readonly byte[] nextSpkiSha256;

    public SelfHostedRuntimeEndpoint(
        string origin,
        ReadOnlySpan<byte> currentSpkiSha256,
        ReadOnlySpan<byte> nextSpkiSha256)
    {
        ArgumentNullException.ThrowIfNull(origin);
        if (new UTF8Encoding(false, true).GetByteCount(origin) >
                SelfHostedRuntimeEnvelopeContract.MaximumOriginBytes ||
            currentSpkiSha256.Length != SelfHostedRuntimeEnvelopeContract.SpkiHashLength ||
            nextSpkiSha256.Length != SelfHostedRuntimeEnvelopeContract.SpkiHashLength)
        {
            throw new ArgumentException("Self-hosted runtime endpoint exceeds its bounds.");
        }
        Origin = origin;
        this.currentSpkiSha256 = currentSpkiSha256.ToArray();
        this.nextSpkiSha256 = nextSpkiSha256.ToArray();
    }

    public string Origin { get; }
    public ReadOnlyMemory<byte> CurrentSpkiSha256 => currentSpkiSha256.ToArray();
    public ReadOnlyMemory<byte> NextSpkiSha256 => nextSpkiSha256.ToArray();
}

public sealed record SelfHostedRuntimeEpoch(
    ulong Epoch,
    ulong Generation,
    ulong NotBeforeUnixSeconds,
    ulong NotAfterUnixSeconds);

public sealed class SelfHostedRuntimeSignature
{
    private readonly byte[] signerId;
    private readonly byte[] signature;

    public SelfHostedRuntimeSignature(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> signature)
    {
        if (signerId.Length != MembershipLimits.SignerIdLength ||
            signature.Length is 0 or > SelfHostedRuntimeEnvelopeContract.MaximumSignatureBytes)
        {
            throw new ArgumentException("Self-hosted runtime signature exceeds its bounds.");
        }
        this.signerId = signerId.ToArray();
        this.signature = signature.ToArray();
    }

    public ReadOnlyMemory<byte> SignerId => signerId.ToArray();
    public ReadOnlyMemory<byte> Signature => signature.ToArray();
}

public sealed class SelfHostedRuntimeEnvelope
{
    private readonly byte[] networkId;
    private readonly byte[] exactDpfSha256;
    private readonly byte[] genesisFingerprintSha256;
    private readonly byte[] delegationCommitmentSha256;
    private readonly byte[] previousEnvelopeSha256;
    private readonly byte[] topologySha256;
    private readonly byte[] previousRevocationHeadSha256;
    private readonly byte[] revocationHeadSha256;
    private readonly string[] capabilities;
    private readonly SelfHostedRuntimeSignature[] signatures;

    public SelfHostedRuntimeEnvelope(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> exactDpfSha256,
        ReadOnlySpan<byte> genesisFingerprintSha256,
        ulong delegationSequence,
        ReadOnlySpan<byte> delegationCommitmentSha256,
        ulong generation,
        ReadOnlySpan<byte> previousEnvelopeSha256,
        ulong issuedAtUnixSeconds,
        ulong validFromUnixSeconds,
        ulong validUntilUnixSeconds,
        ushort minimumProtocol,
        ushort maximumProtocol,
        SelfHostedRuntimeEndpoint coordinator,
        SelfHostedRuntimeEndpoint mau2Ingress,
        ulong topologyGeneration,
        ReadOnlySpan<byte> topologySha256,
        ulong revocationGeneration,
        ReadOnlySpan<byte> previousRevocationHeadSha256,
        ReadOnlySpan<byte> revocationHeadSha256,
        ulong revocationIssuedAtUnixSeconds,
        ulong revocationExpiresAtUnixSeconds,
        SelfHostedRuntimeEpoch currentEpoch,
        SelfHostedRuntimeEpoch nextEpoch,
        IEnumerable<string>? capabilities,
        IEnumerable<SelfHostedRuntimeSignature>? signatures)
    {
        RequireFixed(networkId, MembershipLimits.NetworkIdLength, nameof(networkId));
        RequireFixed(exactDpfSha256, SelfHostedRuntimeEnvelopeContract.HashLength, nameof(exactDpfSha256));
        RequireFixed(genesisFingerprintSha256, SelfHostedRuntimeEnvelopeContract.HashLength, nameof(genesisFingerprintSha256));
        RequireFixed(delegationCommitmentSha256, SelfHostedRuntimeEnvelopeContract.HashLength, nameof(delegationCommitmentSha256));
        RequireFixed(previousEnvelopeSha256, SelfHostedRuntimeEnvelopeContract.HashLength, nameof(previousEnvelopeSha256));
        RequireFixed(topologySha256, SelfHostedRuntimeEnvelopeContract.HashLength, nameof(topologySha256));
        RequireFixed(previousRevocationHeadSha256, SelfHostedRuntimeEnvelopeContract.HashLength, nameof(previousRevocationHeadSha256));
        RequireFixed(revocationHeadSha256, SelfHostedRuntimeEnvelopeContract.HashLength, nameof(revocationHeadSha256));
        ArgumentNullException.ThrowIfNull(coordinator);
        ArgumentNullException.ThrowIfNull(mau2Ingress);
        ArgumentNullException.ThrowIfNull(currentEpoch);
        ArgumentNullException.ThrowIfNull(nextEpoch);
        var frozenCapabilities = FreezeCapabilities(capabilities);
        var frozenSignatures = FreezeSignatures(signatures);
        this.networkId = networkId.ToArray();
        this.exactDpfSha256 = exactDpfSha256.ToArray();
        this.genesisFingerprintSha256 = genesisFingerprintSha256.ToArray();
        DelegationSequence = delegationSequence;
        this.delegationCommitmentSha256 = delegationCommitmentSha256.ToArray();
        Generation = generation;
        this.previousEnvelopeSha256 = previousEnvelopeSha256.ToArray();
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        ValidFromUnixSeconds = validFromUnixSeconds;
        ValidUntilUnixSeconds = validUntilUnixSeconds;
        MinimumProtocol = minimumProtocol;
        MaximumProtocol = maximumProtocol;
        Coordinator = Copy(coordinator);
        Mau2Ingress = Copy(mau2Ingress);
        TopologyGeneration = topologyGeneration;
        this.topologySha256 = topologySha256.ToArray();
        RevocationGeneration = revocationGeneration;
        this.previousRevocationHeadSha256 = previousRevocationHeadSha256.ToArray();
        this.revocationHeadSha256 = revocationHeadSha256.ToArray();
        RevocationIssuedAtUnixSeconds = revocationIssuedAtUnixSeconds;
        RevocationExpiresAtUnixSeconds = revocationExpiresAtUnixSeconds;
        CurrentEpoch = currentEpoch;
        NextEpoch = nextEpoch;
        this.capabilities = frozenCapabilities;
        this.signatures = frozenSignatures;
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> ExactDpfSha256 => exactDpfSha256.ToArray();
    public ReadOnlyMemory<byte> GenesisFingerprintSha256 => genesisFingerprintSha256.ToArray();
    public ulong DelegationSequence { get; }
    public ReadOnlyMemory<byte> DelegationCommitmentSha256 => delegationCommitmentSha256.ToArray();
    public ulong Generation { get; }
    public ReadOnlyMemory<byte> PreviousEnvelopeSha256 => previousEnvelopeSha256.ToArray();
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ValidFromUnixSeconds { get; }
    public ulong ValidUntilUnixSeconds { get; }
    public ushort MinimumProtocol { get; }
    public ushort MaximumProtocol { get; }
    public SelfHostedRuntimeEndpoint Coordinator { get; }
    public SelfHostedRuntimeEndpoint Mau2Ingress { get; }
    public ulong TopologyGeneration { get; }
    public ReadOnlyMemory<byte> TopologySha256 => topologySha256.ToArray();
    public ulong RevocationGeneration { get; }
    public ReadOnlyMemory<byte> PreviousRevocationHeadSha256 =>
        previousRevocationHeadSha256.ToArray();
    public ReadOnlyMemory<byte> RevocationHeadSha256 => revocationHeadSha256.ToArray();
    public ulong RevocationIssuedAtUnixSeconds { get; }
    public ulong RevocationExpiresAtUnixSeconds { get; }
    public SelfHostedRuntimeEpoch CurrentEpoch { get; }
    public SelfHostedRuntimeEpoch NextEpoch { get; }
    public IReadOnlyList<string> Capabilities => capabilities.ToArray();
    public IReadOnlyList<SelfHostedRuntimeSignature> Signatures => signatures
        .Select(static signature => new SelfHostedRuntimeSignature(
            signature.SignerId.Span,
            signature.Signature.Span))
        .ToArray();

    internal IReadOnlyList<SelfHostedRuntimeSignature> SignatureValues => signatures;

    internal SelfHostedRuntimeEnvelope WithoutSignatures() => new(
        networkId,
        exactDpfSha256,
        genesisFingerprintSha256,
        DelegationSequence,
        delegationCommitmentSha256,
        Generation,
        previousEnvelopeSha256,
        IssuedAtUnixSeconds,
        ValidFromUnixSeconds,
        ValidUntilUnixSeconds,
        MinimumProtocol,
        MaximumProtocol,
        Coordinator,
        Mau2Ingress,
        TopologyGeneration,
        topologySha256,
        RevocationGeneration,
        previousRevocationHeadSha256,
        revocationHeadSha256,
        RevocationIssuedAtUnixSeconds,
        RevocationExpiresAtUnixSeconds,
        CurrentEpoch,
        NextEpoch,
        capabilities,
        []);

    private static SelfHostedRuntimeEndpoint Copy(SelfHostedRuntimeEndpoint value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new(value.Origin, value.CurrentSpkiSha256.Span, value.NextSpkiSha256.Span);
    }

    private static void RequireFixed(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length)
        {
            throw new ArgumentException("Self-hosted runtime fixed field length is invalid.", name);
        }
    }

    private static string[] FreezeCapabilities(IEnumerable<string>? values)
    {
        if (values is null)
        {
            return [];
        }
        var result = new List<string>(SelfHostedRuntimeEnvelopeContract.MaximumCapabilities);
        foreach (var value in values)
        {
            if (result.Count == SelfHostedRuntimeEnvelopeContract.MaximumCapabilities)
            {
                throw new ArgumentException("Self-hosted runtime capability count exceeds its bound.");
            }
            ArgumentNullException.ThrowIfNull(value);
            if (new UTF8Encoding(false, true).GetByteCount(value) >
                    SelfHostedRuntimeEnvelopeContract.MaximumCapabilityBytes)
            {
                throw new ArgumentException("Self-hosted runtime capability exceeds its bound.");
            }
            result.Add(value);
        }
        return result.ToArray();
    }

    private static SelfHostedRuntimeSignature[] FreezeSignatures(
        IEnumerable<SelfHostedRuntimeSignature>? values)
    {
        if (values is null)
        {
            return [];
        }
        var result = new List<SelfHostedRuntimeSignature>(
            SelfHostedRuntimeEnvelopeContract.MaximumSignatures);
        foreach (var value in values)
        {
            if (result.Count == SelfHostedRuntimeEnvelopeContract.MaximumSignatures)
            {
                throw new ArgumentException("Self-hosted runtime signature count exceeds its bound.");
            }
            ArgumentNullException.ThrowIfNull(value);
            result.Add(new SelfHostedRuntimeSignature(
                value.SignerId.Span,
                value.Signature.Span));
        }
        return result.ToArray();
    }
}

public enum SelfHostedRuntimeTransitionDecision
{
    GenesisAccepted = 1,
    Idempotent = 2,
    Forward = 3
}

public sealed class SelfHostedRuntimeLastKnownGood
{
    private readonly byte[] networkId;
    private readonly byte[] genesisFingerprintSha256;
    private readonly byte[] envelopeSha256;
    private readonly byte[] topologySha256;
    private readonly byte[] previousRevocationHeadSha256;
    private readonly byte[] revocationHeadSha256;
    private readonly SelfHostedRuntimeEndpoint coordinator;
    private readonly SelfHostedRuntimeEndpoint mau2Ingress;

    public SelfHostedRuntimeLastKnownGood(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> genesisFingerprintSha256,
        ulong generation,
        ReadOnlySpan<byte> envelopeSha256,
        ulong topologyGeneration,
        ReadOnlySpan<byte> topologySha256,
        ulong revocationGeneration,
        ReadOnlySpan<byte> previousRevocationHeadSha256,
        ReadOnlySpan<byte> revocationHeadSha256,
        ulong revocationIssuedAtUnixSeconds,
        ulong revocationExpiresAtUnixSeconds,
        SelfHostedRuntimeEndpoint coordinator,
        SelfHostedRuntimeEndpoint mau2Ingress,
        SelfHostedRuntimeEpoch currentEpoch,
        SelfHostedRuntimeEpoch nextEpoch)
    {
        if (networkId.Length != MembershipLimits.NetworkIdLength ||
            networkId.IndexOfAnyExcept((byte)0) < 0 ||
            genesisFingerprintSha256.Length != SelfHostedRuntimeEnvelopeContract.HashLength ||
            genesisFingerprintSha256.IndexOfAnyExcept((byte)0) < 0 ||
            generation is 0 or ulong.MaxValue ||
            envelopeSha256.Length != SelfHostedRuntimeEnvelopeContract.HashLength ||
            envelopeSha256.IndexOfAnyExcept((byte)0) < 0 ||
            topologyGeneration is 0 or ulong.MaxValue ||
            topologySha256.Length != SelfHostedRuntimeEnvelopeContract.HashLength ||
            topologySha256.IndexOfAnyExcept((byte)0) < 0 ||
            revocationGeneration is 0 or ulong.MaxValue ||
            previousRevocationHeadSha256.Length != SelfHostedRuntimeEnvelopeContract.HashLength ||
            (revocationGeneration == 1
                ? previousRevocationHeadSha256.IndexOfAnyExcept((byte)0) >= 0
                : previousRevocationHeadSha256.IndexOfAnyExcept((byte)0) < 0) ||
            revocationHeadSha256.Length != SelfHostedRuntimeEnvelopeContract.HashLength ||
            revocationHeadSha256.IndexOfAnyExcept((byte)0) < 0 ||
            revocationIssuedAtUnixSeconds == 0 ||
            revocationIssuedAtUnixSeconds >= revocationExpiresAtUnixSeconds)
        {
            throw new ArgumentException("Self-hosted runtime LKG is invalid.");
        }
        this.networkId = networkId.ToArray();
        this.genesisFingerprintSha256 = genesisFingerprintSha256.ToArray();
        Generation = generation;
        this.envelopeSha256 = envelopeSha256.ToArray();
        TopologyGeneration = topologyGeneration;
        this.topologySha256 = topologySha256.ToArray();
        RevocationGeneration = revocationGeneration;
        this.previousRevocationHeadSha256 = previousRevocationHeadSha256.ToArray();
        this.revocationHeadSha256 = revocationHeadSha256.ToArray();
        RevocationIssuedAtUnixSeconds = revocationIssuedAtUnixSeconds;
        RevocationExpiresAtUnixSeconds = revocationExpiresAtUnixSeconds;
        this.coordinator = CopyEndpoint(coordinator);
        this.mau2Ingress = CopyEndpoint(mau2Ingress);
        CurrentEpoch = currentEpoch ?? throw new ArgumentNullException(nameof(currentEpoch));
        NextEpoch = nextEpoch ?? throw new ArgumentNullException(nameof(nextEpoch));
        SelfHostedRuntimeEnvelopeValidator.ValidatePersistedClosure(this);
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> GenesisFingerprintSha256 => genesisFingerprintSha256.ToArray();
    public ulong Generation { get; }
    public ReadOnlyMemory<byte> EnvelopeSha256 => envelopeSha256.ToArray();
    public ulong TopologyGeneration { get; }
    public ReadOnlyMemory<byte> TopologySha256 => topologySha256.ToArray();
    public ulong RevocationGeneration { get; }
    public ReadOnlyMemory<byte> PreviousRevocationHeadSha256 =>
        previousRevocationHeadSha256.ToArray();
    public ReadOnlyMemory<byte> RevocationHeadSha256 => revocationHeadSha256.ToArray();
    public ulong RevocationIssuedAtUnixSeconds { get; }
    public ulong RevocationExpiresAtUnixSeconds { get; }
    public SelfHostedRuntimeEndpoint Coordinator => CopyEndpoint(coordinator);
    public SelfHostedRuntimeEndpoint Mau2Ingress => CopyEndpoint(mau2Ingress);
    public SelfHostedRuntimeEpoch CurrentEpoch { get; }
    public SelfHostedRuntimeEpoch NextEpoch { get; }

    private static SelfHostedRuntimeEndpoint CopyEndpoint(SelfHostedRuntimeEndpoint value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new(value.Origin, value.CurrentSpkiSha256.Span, value.NextSpkiSha256.Span);
    }
}

public sealed class VerifiedSelfHostedRuntimeEnvelope
{
    private readonly byte[] envelopeSha256;

    internal VerifiedSelfHostedRuntimeEnvelope(
        SelfHostedRuntimeEnvelope envelope,
        ReadOnlySpan<byte> envelopeSha256,
        SelfHostedRuntimeTransitionDecision decision)
    {
        Envelope = envelope;
        this.envelopeSha256 = envelopeSha256.ToArray();
        Decision = decision;
    }

    public SelfHostedRuntimeEnvelope Envelope { get; }
    public ReadOnlyMemory<byte> EnvelopeSha256 => envelopeSha256.ToArray();
    public SelfHostedRuntimeTransitionDecision Decision { get; }
    public SelfHostedRuntimeLastKnownGood ToLastKnownGood() => new(
        Envelope.NetworkId.Span,
        Envelope.GenesisFingerprintSha256.Span,
        Envelope.Generation,
        envelopeSha256,
        Envelope.TopologyGeneration,
        Envelope.TopologySha256.Span,
        Envelope.RevocationGeneration,
        Envelope.PreviousRevocationHeadSha256.Span,
        Envelope.RevocationHeadSha256.Span,
        Envelope.RevocationIssuedAtUnixSeconds,
        Envelope.RevocationExpiresAtUnixSeconds,
        Envelope.Coordinator,
        Envelope.Mau2Ingress,
        Envelope.CurrentEpoch,
        Envelope.NextEpoch);
    public override string ToString() => "[verified-user-managed-runtime]";
}

public interface ISelfHostedRuntimeSignatureVerifier
{
    bool Verify(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature);
}

public sealed class SodiumEd25519SelfHostedRuntimeSignatureVerifier :
    ISelfHostedRuntimeSignatureVerifier
{
    public bool Verify(
        ReadOnlySpan<byte> signerId,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature)
    {
        if (signerId.Length != MembershipLimits.SignerIdLength ||
            publicKey.Length != MembershipLimits.PublicKeyLength ||
            signature.Length != 64 ||
            signingBytes.Length < SelfHostedRuntimeEnvelopeContract.SigningDomainLength ||
            !signingBytes[..SelfHostedRuntimeEnvelopeContract.SigningDomainLength]
                .SequenceEqual(SelfHostedRuntimeEnvelopeContract.SigningDomain))
        {
            return false;
        }
        try
        {
            return PublicKeyAuth.VerifyDetached(
                signature.ToArray(),
                signingBytes.ToArray(),
                publicKey.ToArray());
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            return false;
        }
    }
}

public static class SelfHostedRuntimeEnvelopeCodec
{
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.SHR1;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static byte[] Encode(SelfHostedRuntimeEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        SelfHostedRuntimeEnvelopeValidator.ValidateShape(envelope, validateSignatures: true);
        var writer = new ArrayBufferWriter<byte>();
        WritePayload(writer, envelope);
        WriteByte(writer, checked((byte)envelope.SignatureValues.Count));
        foreach (var signature in envelope.SignatureValues
                     .OrderBy(static value => value.SignerId, SelfHostedByteMemoryComparer.Instance))
        {
            WriteFixed(writer, signature.SignerId.Span, MembershipLimits.SignerIdLength);
            WriteUInt16(writer, checked((ushort)signature.Signature.Length));
            Write(writer, signature.Signature.Span);
        }
        if (writer.WrittenCount > SelfHostedRuntimeEnvelopeContract.MaximumEncodedBytes)
        {
            throw new InvalidDataException("Self-hosted runtime envelope exceeds its bound.");
        }
        return writer.WrittenSpan.ToArray();
    }

    public static SelfHostedRuntimeEnvelope Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is <= 0 or > SelfHostedRuntimeEnvelopeContract.MaximumEncodedBytes)
        {
            throw new InvalidDataException("Self-hosted runtime envelope length is invalid.");
        }
        try
        {
            var reader = new RuntimeReader(encoded);
            if (!reader.Fixed(4).SequenceEqual(Magic) || reader.Byte() != 1)
            {
                throw new InvalidDataException("Self-hosted runtime envelope framing is invalid.");
            }
            var network = reader.Fixed(MembershipLimits.NetworkIdLength).ToArray();
            var dpf = reader.Fixed(32).ToArray();
            var genesis = reader.Fixed(32).ToArray();
            var delegationSequence = reader.UInt64();
            var delegation = reader.Fixed(32).ToArray();
            var generation = reader.UInt64();
            var previous = reader.Fixed(32).ToArray();
            var issued = reader.UInt64();
            var from = reader.UInt64();
            var until = reader.UInt64();
            var minimumProtocol = reader.UInt16();
            var maximumProtocol = reader.UInt16();
            var coordinator = ReadEndpoint(ref reader);
            var ingress = ReadEndpoint(ref reader);
            var topologyGeneration = reader.UInt64();
            var topology = reader.Fixed(32).ToArray();
            var revocationGeneration = reader.UInt64();
            var previousRevocation = reader.Fixed(32).ToArray();
            var revocation = reader.Fixed(32).ToArray();
            var revocationIssued = reader.UInt64();
            var revocationExpires = reader.UInt64();
            var currentEpoch = ReadEpoch(ref reader);
            var nextEpoch = ReadEpoch(ref reader);
            var capabilityCount = reader.Byte();
            if (capabilityCount > SelfHostedRuntimeEnvelopeContract.MaximumCapabilities)
            {
                throw new InvalidDataException("Self-hosted runtime capability count is invalid.");
            }
            var capabilities = new string[capabilityCount];
            for (var index = 0; index < capabilities.Length; index++)
            {
                capabilities[index] = reader.String(
                    SelfHostedRuntimeEnvelopeContract.MaximumCapabilityBytes);
            }
            var signatureCount = reader.Byte();
            if (signatureCount is 0 or > SelfHostedRuntimeEnvelopeContract.MaximumSignatures)
            {
                throw new InvalidDataException("Self-hosted runtime signature count is invalid.");
            }
            var signatures = new SelfHostedRuntimeSignature[signatureCount];
            for (var index = 0; index < signatures.Length; index++)
            {
                signatures[index] = new SelfHostedRuntimeSignature(
                    reader.Fixed(MembershipLimits.SignerIdLength),
                    reader.Bytes(SelfHostedRuntimeEnvelopeContract.MaximumSignatureBytes));
            }
            if (!reader.End)
            {
                throw new InvalidDataException("Self-hosted runtime envelope has trailing bytes.");
            }
            var result = new SelfHostedRuntimeEnvelope(
                network, dpf, genesis, delegationSequence, delegation,
                generation, previous, issued, from, until, minimumProtocol,
                maximumProtocol, coordinator, ingress, topologyGeneration,
                topology, revocationGeneration, previousRevocation, revocation,
                revocationIssued, revocationExpires, currentEpoch, nextEpoch,
                capabilities, signatures);
            SelfHostedRuntimeEnvelopeValidator.ValidateShape(result, validateSignatures: true);
            if (!Encode(result).AsSpan().SequenceEqual(encoded))
            {
                throw new InvalidDataException("Self-hosted runtime envelope is not canonical.");
            }
            return result;
        }
        catch (Exception exception) when (exception is EndOfStreamException or
            DecoderFallbackException or OverflowException or UriFormatException)
        {
            throw new InvalidDataException("Self-hosted runtime envelope is malformed.", exception);
        }
    }

    internal static byte[] GetSigningBytes(SelfHostedRuntimeEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        SelfHostedRuntimeEnvelopeValidator.ValidateShape(envelope, validateSignatures: false);
        var writer = new ArrayBufferWriter<byte>();
        Write(writer, SelfHostedRuntimeEnvelopeContract.SigningDomain);
        WritePayload(writer, envelope);
        return writer.WrittenSpan.ToArray();
    }

    private static void WritePayload(ArrayBufferWriter<byte> writer, SelfHostedRuntimeEnvelope value)
    {
        Write(writer, Magic);
        WriteByte(writer, 1);
        WriteFixed(writer, value.NetworkId.Span, MembershipLimits.NetworkIdLength);
        WriteFixed(writer, value.ExactDpfSha256.Span, 32);
        WriteFixed(writer, value.GenesisFingerprintSha256.Span, 32);
        WriteUInt64(writer, value.DelegationSequence);
        WriteFixed(writer, value.DelegationCommitmentSha256.Span, 32);
        WriteUInt64(writer, value.Generation);
        WriteFixed(writer, value.PreviousEnvelopeSha256.Span, 32);
        WriteUInt64(writer, value.IssuedAtUnixSeconds);
        WriteUInt64(writer, value.ValidFromUnixSeconds);
        WriteUInt64(writer, value.ValidUntilUnixSeconds);
        WriteUInt16(writer, value.MinimumProtocol);
        WriteUInt16(writer, value.MaximumProtocol);
        WriteEndpoint(writer, value.Coordinator);
        WriteEndpoint(writer, value.Mau2Ingress);
        WriteUInt64(writer, value.TopologyGeneration);
        WriteFixed(writer, value.TopologySha256.Span, 32);
        WriteUInt64(writer, value.RevocationGeneration);
        WriteFixed(writer, value.PreviousRevocationHeadSha256.Span, 32);
        WriteFixed(writer, value.RevocationHeadSha256.Span, 32);
        WriteUInt64(writer, value.RevocationIssuedAtUnixSeconds);
        WriteUInt64(writer, value.RevocationExpiresAtUnixSeconds);
        WriteEpoch(writer, value.CurrentEpoch);
        WriteEpoch(writer, value.NextEpoch);
        WriteByte(writer, checked((byte)value.Capabilities.Count));
        foreach (var capability in value.Capabilities.Order(StringComparer.Ordinal))
        {
            WriteString(writer, capability);
        }
    }

    private static void WriteEndpoint(ArrayBufferWriter<byte> writer, SelfHostedRuntimeEndpoint endpoint)
    {
        WriteString(writer, endpoint.Origin);
        WriteFixed(writer, endpoint.CurrentSpkiSha256.Span, 32);
        WriteFixed(writer, endpoint.NextSpkiSha256.Span, 32);
    }

    private static SelfHostedRuntimeEndpoint ReadEndpoint(ref RuntimeReader reader) => new(
        reader.String(SelfHostedRuntimeEnvelopeContract.MaximumOriginBytes),
        reader.Fixed(32),
        reader.Fixed(32));

    private static void WriteEpoch(ArrayBufferWriter<byte> writer, SelfHostedRuntimeEpoch epoch)
    {
        WriteUInt64(writer, epoch.Epoch);
        WriteUInt64(writer, epoch.Generation);
        WriteUInt64(writer, epoch.NotBeforeUnixSeconds);
        WriteUInt64(writer, epoch.NotAfterUnixSeconds);
    }

    private static SelfHostedRuntimeEpoch ReadEpoch(ref RuntimeReader reader) => new(
        reader.UInt64(), reader.UInt64(), reader.UInt64(), reader.UInt64());

    private static void WriteString(ArrayBufferWriter<byte> writer, string value)
    {
        var encoded = StrictUtf8.GetBytes(value);
        WriteUInt16(writer, checked((ushort)encoded.Length));
        Write(writer, encoded);
    }

    private static void WriteFixed(ArrayBufferWriter<byte> writer, ReadOnlySpan<byte> value, int length)
    {
        if (value.Length != length)
        {
            throw new InvalidDataException("Self-hosted runtime fixed field length is invalid.");
        }
        Write(writer, value);
    }

    private static void WriteByte(ArrayBufferWriter<byte> writer, byte value)
    {
        writer.GetSpan(1)[0] = value;
        writer.Advance(1);
    }

    private static void WriteUInt16(ArrayBufferWriter<byte> writer, ushort value)
    {
        BinaryPrimitives.WriteUInt16BigEndian(writer.GetSpan(2), value);
        writer.Advance(2);
    }

    private static void WriteUInt64(ArrayBufferWriter<byte> writer, ulong value)
    {
        BinaryPrimitives.WriteUInt64BigEndian(writer.GetSpan(8), value);
        writer.Advance(8);
    }

    private static void Write(ArrayBufferWriter<byte> writer, ReadOnlySpan<byte> value)
    {
        value.CopyTo(writer.GetSpan(value.Length));
        writer.Advance(value.Length);
    }

    private ref struct RuntimeReader
    {
        private ReadOnlySpan<byte> remaining;

        public RuntimeReader(ReadOnlySpan<byte> encoded) => remaining = encoded;
        public bool End => remaining.IsEmpty;
        public byte Byte() => Fixed(1)[0];
        public ushort UInt16() => BinaryPrimitives.ReadUInt16BigEndian(Fixed(2));
        public ulong UInt64() => BinaryPrimitives.ReadUInt64BigEndian(Fixed(8));
        public ReadOnlySpan<byte> Bytes(int maximum)
        {
            var length = UInt16();
            if (length is 0 || length > maximum)
            {
                throw new InvalidDataException("Self-hosted runtime byte field length is invalid.");
            }
            return Fixed(length);
        }
        public string String(int maximum)
        {
            var bytes = Bytes(maximum);
            return StrictUtf8.GetString(bytes);
        }
        public ReadOnlySpan<byte> Fixed(int length)
        {
            if (length < 0 || remaining.Length < length)
            {
                throw new EndOfStreamException();
            }
            var value = remaining[..length];
            remaining = remaining[length..];
            return value;
        }
    }
}

public static class SelfHostedRuntimeEnvelopeVerifier
{
    public static VerifiedSelfHostedRuntimeEnvelope VerifyExact(
        ReadOnlySpan<byte> encoded,
        VerifiedSelfHostedActivationDescriptor descriptor,
        ulong verificationTimeUnixSeconds,
        ushort protocol,
        ISelfHostedRuntimeSignatureVerifier signatureVerifier,
        SelfHostedRuntimeLastKnownGood? lastKnownGood = null)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        if (encoded.Length is <= 0 or > SelfHostedRuntimeEnvelopeContract.MaximumEncodedBytes)
        {
            throw new InvalidDataException("Self-hosted runtime envelope length is invalid.");
        }
        var frozen = encoded.ToArray();
        var envelope = SelfHostedRuntimeEnvelopeCodec.Decode(frozen);
        SelfHostedRuntimeEnvelopeValidator.ValidateBound(
            envelope,
            descriptor,
            verificationTimeUnixSeconds,
            protocol);
        var signingBytes = SelfHostedRuntimeEnvelopeCodec.GetSigningBytes(envelope);
        try
        {
            VerifyQuorum(envelope, descriptor.LatestVerifiedDelegation, signingBytes, signatureVerifier);
            var envelopeHash = SHA256.HashData(frozen);
            var decision = VerifyTransition(envelope, envelopeHash, lastKnownGood);
            return new VerifiedSelfHostedRuntimeEnvelope(envelope, envelopeHash, decision);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingBytes);
        }
    }

    private static void VerifyQuorum(
        SelfHostedRuntimeEnvelope envelope,
        VerifiedSelfHostedDelegationDescriptor delegation,
        ReadOnlySpan<byte> signingBytes,
        ISelfHostedRuntimeSignatureVerifier verifier)
    {
        if (envelope.SignatureValues.Count != delegation.OnlineThreshold)
        {
            throw new InvalidDataException("Self-hosted runtime signature quorum is not exact.");
        }
        var signers = delegation.SignerValues.ToDictionary(
            signer => Convert.ToHexString(signer.SignerId.Span),
            StringComparer.Ordinal);
        foreach (var signature in envelope.SignatureValues)
        {
            if (!signers.TryGetValue(
                    Convert.ToHexString(signature.SignerId.Span),
                    out var signer) ||
                !verifier.Verify(
                    signature.SignerId.Span,
                    signer.PublicKey.Span,
                    signingBytes,
                    signature.Signature.Span))
            {
                throw new InvalidDataException("Self-hosted runtime signature is invalid.");
            }
        }
    }

    private static SelfHostedRuntimeTransitionDecision VerifyTransition(
        SelfHostedRuntimeEnvelope envelope,
        ReadOnlySpan<byte> envelopeHash,
        SelfHostedRuntimeLastKnownGood? lkg)
    {
        if (lkg is null)
        {
            if (envelope.Generation != 1 ||
                envelope.PreviousEnvelopeSha256.Span.IndexOfAnyExcept((byte)0) >= 0)
            {
                throw new InvalidDataException("Self-hosted runtime genesis is invalid.");
            }
            return SelfHostedRuntimeTransitionDecision.GenesisAccepted;
        }
        if (!CryptographicOperations.FixedTimeEquals(envelope.NetworkId.Span, lkg.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                envelope.GenesisFingerprintSha256.Span,
                lkg.GenesisFingerprintSha256.Span))
        {
            throw new InvalidDataException("Self-hosted runtime crossed its activation authority.");
        }
        if (envelope.Generation < lkg.Generation)
        {
            throw new InvalidDataException("Self-hosted runtime rollback was rejected.");
        }
        if (envelope.Generation == lkg.Generation)
        {
            if (!CryptographicOperations.FixedTimeEquals(envelopeHash, lkg.EnvelopeSha256.Span))
            {
                throw new InvalidDataException("Self-hosted runtime same-generation fork was rejected.");
            }
            RequireExactClosure(envelope, lkg);
            return SelfHostedRuntimeTransitionDecision.Idempotent;
        }
        if (lkg.Generation == ulong.MaxValue || envelope.Generation != lkg.Generation + 1 ||
            !CryptographicOperations.FixedTimeEquals(
                envelope.PreviousEnvelopeSha256.Span,
                lkg.EnvelopeSha256.Span))
        {
            throw new InvalidDataException("Self-hosted runtime successor fork was rejected.");
        }
        RequireForwardClosure(envelope, lkg);
        return SelfHostedRuntimeTransitionDecision.Forward;
    }

    private static void RequireExactClosure(
        SelfHostedRuntimeEnvelope envelope,
        SelfHostedRuntimeLastKnownGood lkg)
    {
        if (envelope.TopologyGeneration != lkg.TopologyGeneration ||
            !Equal(envelope.TopologySha256, lkg.TopologySha256) ||
            envelope.RevocationGeneration != lkg.RevocationGeneration ||
            !Equal(envelope.PreviousRevocationHeadSha256, lkg.PreviousRevocationHeadSha256) ||
            !Equal(envelope.RevocationHeadSha256, lkg.RevocationHeadSha256) ||
            envelope.RevocationIssuedAtUnixSeconds != lkg.RevocationIssuedAtUnixSeconds ||
            envelope.RevocationExpiresAtUnixSeconds != lkg.RevocationExpiresAtUnixSeconds ||
            !EndpointEqual(envelope.Coordinator, lkg.Coordinator) ||
            !EndpointEqual(envelope.Mau2Ingress, lkg.Mau2Ingress) ||
            envelope.CurrentEpoch != lkg.CurrentEpoch ||
            envelope.NextEpoch != lkg.NextEpoch)
        {
            throw new InvalidDataException("Self-hosted runtime LKG closure is inconsistent.");
        }
    }

    private static void RequireForwardClosure(
        SelfHostedRuntimeEnvelope envelope,
        SelfHostedRuntimeLastKnownGood lkg)
    {
        var topologyExact = envelope.TopologyGeneration == lkg.TopologyGeneration &&
            Equal(envelope.TopologySha256, lkg.TopologySha256);
        var topologyForward = lkg.TopologyGeneration != ulong.MaxValue &&
            envelope.TopologyGeneration == lkg.TopologyGeneration + 1 &&
            !Equal(envelope.TopologySha256, lkg.TopologySha256);

        var revocationExact = envelope.RevocationGeneration == lkg.RevocationGeneration &&
            Equal(envelope.PreviousRevocationHeadSha256, lkg.PreviousRevocationHeadSha256) &&
            Equal(envelope.RevocationHeadSha256, lkg.RevocationHeadSha256) &&
            envelope.RevocationIssuedAtUnixSeconds == lkg.RevocationIssuedAtUnixSeconds &&
            envelope.RevocationExpiresAtUnixSeconds == lkg.RevocationExpiresAtUnixSeconds;
        var revocationForward = lkg.RevocationGeneration != ulong.MaxValue &&
            envelope.RevocationGeneration == lkg.RevocationGeneration + 1 &&
            Equal(envelope.PreviousRevocationHeadSha256, lkg.RevocationHeadSha256) &&
            !Equal(envelope.RevocationHeadSha256, lkg.RevocationHeadSha256) &&
            envelope.RevocationIssuedAtUnixSeconds > lkg.RevocationIssuedAtUnixSeconds;

        var epochsExact = envelope.CurrentEpoch == lkg.CurrentEpoch &&
            envelope.NextEpoch == lkg.NextEpoch;
        var epochsForward = envelope.CurrentEpoch == lkg.NextEpoch &&
            lkg.NextEpoch.Epoch != ulong.MaxValue &&
            lkg.NextEpoch.Generation != ulong.MaxValue &&
            envelope.NextEpoch.Epoch == lkg.NextEpoch.Epoch + 1 &&
            envelope.NextEpoch.Generation == lkg.NextEpoch.Generation + 1;

        if ((!topologyExact && !topologyForward) ||
            (!revocationExact && !revocationForward) ||
            (!epochsExact && !epochsForward) ||
            !EndpointIsSafeSuccessor(envelope.Coordinator, lkg.Coordinator) ||
            !EndpointIsSafeSuccessor(envelope.Mau2Ingress, lkg.Mau2Ingress))
        {
            throw new InvalidDataException("Self-hosted runtime security state regressed or forked.");
        }
    }

    private static bool EndpointIsSafeSuccessor(
        SelfHostedRuntimeEndpoint candidate,
        SelfHostedRuntimeEndpoint current)
    {
        if (!string.Equals(candidate.Origin, current.Origin, StringComparison.Ordinal))
        {
            return false;
        }
        if (Equal(candidate.CurrentSpkiSha256, current.CurrentSpkiSha256) &&
            Equal(candidate.NextSpkiSha256, current.NextSpkiSha256))
        {
            return true;
        }
        return Equal(candidate.CurrentSpkiSha256, current.NextSpkiSha256) &&
            !Equal(candidate.NextSpkiSha256, current.CurrentSpkiSha256);
    }

    private static bool EndpointEqual(
        SelfHostedRuntimeEndpoint left,
        SelfHostedRuntimeEndpoint right) =>
        string.Equals(left.Origin, right.Origin, StringComparison.Ordinal) &&
        Equal(left.CurrentSpkiSha256, right.CurrentSpkiSha256) &&
        Equal(left.NextSpkiSha256, right.NextSpkiSha256);

    private static bool Equal(ReadOnlyMemory<byte> left, ReadOnlyMemory<byte> right) =>
        CryptographicOperations.FixedTimeEquals(left.Span, right.Span);
}

internal static class SelfHostedRuntimeEnvelopeValidator
{
    public static void ValidatePersistedClosure(SelfHostedRuntimeLastKnownGood value)
    {
        ValidateEndpoint(value.Coordinator);
        ValidateEndpoint(value.Mau2Ingress);
        if (Origin(value.Coordinator.Origin) == Origin(value.Mau2Ingress.Origin))
        {
            throw new ArgumentException("Persisted runtime origins must differ.");
        }
        try
        {
            ValidateEpochs(
                value.CurrentEpoch,
                value.NextEpoch,
                value.CurrentEpoch.NotBeforeUnixSeconds,
                value.NextEpoch.NotAfterUnixSeconds);
        }
        catch (InvalidDataException exception)
        {
            throw new ArgumentException("Persisted runtime epochs are invalid.", exception);
        }
    }

    public static void ValidateShape(SelfHostedRuntimeEnvelope value, bool validateSignatures)
    {
        ExactNonzero(value.NetworkId.Span, MembershipLimits.NetworkIdLength, "network ID");
        ExactNonzero(value.ExactDpfSha256.Span, 32, "DPF hash");
        ExactNonzero(value.GenesisFingerprintSha256.Span, 32, "genesis fingerprint");
        ExactNonzero(value.DelegationCommitmentSha256.Span, 32, "delegation commitment");
        if (value.DelegationSequence == 0 || value.Generation is 0 or ulong.MaxValue ||
            value.IssuedAtUnixSeconds == 0 || value.ValidFromUnixSeconds == 0 ||
            value.ValidFromUnixSeconds > value.IssuedAtUnixSeconds ||
            value.IssuedAtUnixSeconds >= value.ValidUntilUnixSeconds ||
            value.ValidUntilUnixSeconds - value.ValidFromUnixSeconds >
                SelfHostedRuntimeEnvelopeContract.MaximumValiditySeconds ||
            value.MinimumProtocol == 0 || value.MinimumProtocol > value.MaximumProtocol)
        {
            throw new InvalidDataException("Self-hosted runtime validity or protocol range is invalid.");
        }
        if (value.Generation == 1)
        {
            ExactZero(value.PreviousEnvelopeSha256.Span, 32, "previous envelope hash");
        }
        else
        {
            ExactNonzero(value.PreviousEnvelopeSha256.Span, 32, "previous envelope hash");
        }
        ValidateEndpoint(value.Coordinator);
        ValidateEndpoint(value.Mau2Ingress);
        if (Origin(value.Coordinator.Origin) == Origin(value.Mau2Ingress.Origin))
        {
            throw new InvalidDataException("Coordinator and MAU2 ingress origins must differ.");
        }
        if (value.TopologyGeneration is 0 or ulong.MaxValue ||
            value.RevocationGeneration is 0 or ulong.MaxValue)
        {
            throw new InvalidDataException("Self-hosted topology or revocation generation is invalid.");
        }
        ExactNonzero(value.TopologySha256.Span, 32, "topology hash");
        if (value.RevocationGeneration == 1)
        {
            ExactZero(value.PreviousRevocationHeadSha256.Span, 32, "previous revocation head");
        }
        else
        {
            ExactNonzero(value.PreviousRevocationHeadSha256.Span, 32, "previous revocation head");
        }
        ExactNonzero(value.RevocationHeadSha256.Span, 32, "revocation head");
        if (value.RevocationIssuedAtUnixSeconds == 0 ||
            value.RevocationIssuedAtUnixSeconds >= value.RevocationExpiresAtUnixSeconds ||
            value.RevocationExpiresAtUnixSeconds > value.ValidUntilUnixSeconds)
        {
            throw new InvalidDataException("Self-hosted revocation window is invalid.");
        }
        ValidateEpochs(value.CurrentEpoch, value.NextEpoch, value.ValidFromUnixSeconds, value.ValidUntilUnixSeconds);
        var capabilities = value.Capabilities.ToArray();
        if (capabilities.Length > SelfHostedRuntimeEnvelopeContract.MaximumCapabilities ||
            capabilities.Distinct(StringComparer.Ordinal).Count() != capabilities.Length ||
            !capabilities.SequenceEqual(capabilities.Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
            capabilities.Any(static capability => !IsCapability(capability)))
        {
            throw new InvalidDataException("Self-hosted runtime capabilities are not canonical.");
        }
        if (!validateSignatures)
        {
            return;
        }
        var signatures = value.SignatureValues;
        if (signatures.Count is 0 or > SelfHostedRuntimeEnvelopeContract.MaximumSignatures ||
            signatures.Select(static signature => Convert.ToHexString(signature.SignerId.Span))
                .Distinct(StringComparer.Ordinal).Count() != signatures.Count ||
            !signatures.SequenceEqual(
                signatures.OrderBy(
                    static signature => signature.SignerId,
                    SelfHostedByteMemoryComparer.Instance),
                RuntimeSignatureComparer.Instance))
        {
            throw new InvalidDataException("Self-hosted runtime signatures are not canonical.");
        }
        foreach (var signature in signatures)
        {
            ExactNonzero(signature.SignerId.Span, MembershipLimits.SignerIdLength, "signer ID");
            if (signature.Signature.Length is 0 or >
                    SelfHostedRuntimeEnvelopeContract.MaximumSignatureBytes)
            {
                throw new InvalidDataException("Self-hosted runtime signature length is invalid.");
            }
        }
    }

    public static void ValidateBound(
        SelfHostedRuntimeEnvelope value,
        VerifiedSelfHostedActivationDescriptor descriptor,
        ulong now,
        ushort protocol)
    {
        if (now == 0 || protocol == 0 ||
            !CryptographicOperations.FixedTimeEquals(value.NetworkId.Span, descriptor.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(value.ExactDpfSha256.Span, descriptor.ExactDpfSha256.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                value.GenesisFingerprintSha256.Span,
                descriptor.GenesisFingerprintSha256.Span) ||
            value.DelegationSequence != descriptor.LatestVerifiedDelegation.Sequence ||
            !CryptographicOperations.FixedTimeEquals(
                value.DelegationCommitmentSha256.Span,
                descriptor.LatestVerifiedDelegation.StatementCommitmentSha256.Span) ||
            value.MinimumProtocol < descriptor.MinimumProtocol ||
            value.MaximumProtocol > descriptor.MaximumProtocol ||
            protocol < value.MinimumProtocol || protocol > value.MaximumProtocol ||
            value.IssuedAtUnixSeconds > now ||
            now < value.ValidFromUnixSeconds || now > value.ValidUntilUnixSeconds ||
            value.ValidFromUnixSeconds < descriptor.LatestVerifiedDelegation.ValidFromUnixSeconds ||
            value.ValidUntilUnixSeconds > descriptor.LatestVerifiedDelegation.ValidUntilUnixSeconds ||
            value.RevocationIssuedAtUnixSeconds > now ||
            now > value.RevocationExpiresAtUnixSeconds ||
            now < value.CurrentEpoch.NotBeforeUnixSeconds ||
            now > value.CurrentEpoch.NotAfterUnixSeconds)
        {
            throw new InvalidDataException("Self-hosted runtime envelope is not bound to the verified DPF or current time.");
        }
    }

    private static void ValidateEpochs(
        SelfHostedRuntimeEpoch current,
        SelfHostedRuntimeEpoch next,
        ulong validFrom,
        ulong validUntil)
    {
        if (current.Epoch == 0 || current.Generation == 0 ||
            current.NotBeforeUnixSeconds < validFrom ||
            current.NotBeforeUnixSeconds >= current.NotAfterUnixSeconds ||
            current.NotAfterUnixSeconds > validUntil ||
            current.Epoch == ulong.MaxValue || current.Generation == ulong.MaxValue ||
            next.Epoch != current.Epoch + 1 || next.Generation != current.Generation + 1 ||
            next.Epoch == ulong.MaxValue || next.Generation == ulong.MaxValue ||
            next.NotBeforeUnixSeconds < current.NotBeforeUnixSeconds ||
            next.NotBeforeUnixSeconds > current.NotAfterUnixSeconds ||
            next.NotBeforeUnixSeconds >= next.NotAfterUnixSeconds ||
            next.NotAfterUnixSeconds > validUntil)
        {
            throw new InvalidDataException("Self-hosted runtime epoch pair is invalid.");
        }
    }

    private static void ValidateEndpoint(SelfHostedRuntimeEndpoint endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!Uri.TryCreate(endpoint.Origin, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            uri.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment) ||
            !string.Equals(endpoint.Origin, uri.GetComponents(
                UriComponents.SchemeAndServer,
                UriFormat.UriEscaped) + "/", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Self-hosted runtime endpoint is not a canonical HTTPS origin.");
        }
        if (StrictLength(endpoint.Origin) > SelfHostedRuntimeEnvelopeContract.MaximumOriginBytes)
        {
            throw new InvalidDataException("Self-hosted runtime endpoint exceeds its bound.");
        }
        ExactNonzero(endpoint.CurrentSpkiSha256.Span, 32, "current SPKI");
        ExactNonzero(endpoint.NextSpkiSha256.Span, 32, "next SPKI");
        if (CryptographicOperations.FixedTimeEquals(
                endpoint.CurrentSpkiSha256.Span,
                endpoint.NextSpkiSha256.Span))
        {
            throw new InvalidDataException("Self-hosted runtime SPKI rotation must advance.");
        }
    }

    private static string Origin(string value) => new Uri(value).GetComponents(
        UriComponents.SchemeAndServer,
        UriFormat.UriEscaped);

    private static int StrictLength(string value) => new UTF8Encoding(false, true).GetByteCount(value);

    private static bool IsCapability(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length >
                SelfHostedRuntimeEnvelopeContract.MaximumCapabilityBytes ||
            StrictLength(value) > SelfHostedRuntimeEnvelopeContract.MaximumCapabilityBytes)
        {
            return false;
        }
        return value.All(static character =>
            character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-');
    }

    private static void ExactNonzero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
        {
            throw new InvalidDataException($"Self-hosted runtime {name} is invalid.");
        }
    }

    private static void ExactZero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) >= 0)
        {
            throw new InvalidDataException($"Self-hosted runtime {name} is invalid.");
        }
    }

    private sealed class RuntimeSignatureComparer : IEqualityComparer<SelfHostedRuntimeSignature>
    {
        public static RuntimeSignatureComparer Instance { get; } = new();
        public bool Equals(SelfHostedRuntimeSignature? x, SelfHostedRuntimeSignature? y) =>
            x is not null && y is not null &&
            x.SignerId.Span.SequenceEqual(y.SignerId.Span) &&
            x.Signature.Span.SequenceEqual(y.Signature.Span);
        public int GetHashCode(SelfHostedRuntimeSignature obj) => 0;
    }
}
