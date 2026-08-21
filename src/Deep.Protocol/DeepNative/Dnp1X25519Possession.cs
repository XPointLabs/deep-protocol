using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Sodium;

namespace Deep.Protocol.DeepNative;

internal sealed class X25519Possession
{
    private readonly byte[] _transcriptHash;

    internal X25519Possession(
        X25519PossessionRole role,
        ReadOnlySpan<byte> transcriptHash)
    {
        Role = role;
        _transcriptHash = transcriptHash.ToArray();
    }

    public X25519PossessionRole Role { get; }
    public ReadOnlyMemory<byte> TranscriptHash => _transcriptHash.ToArray();
}

internal static class X25519PossessionVerifier
{
    internal const int TranscriptLength = 168;
    private const ulong MaximumWindowSeconds = 300;
    private const string SaltDomain = "Deep/IdentityAuth/V1/x25519-pop-salt";
    private const string DeviceKeyDomain = "Deep/IdentityAuth/V1/x25519-pop-key/device";
    private const string RouterKeyDomain = "Deep/IdentityAuth/V1/x25519-pop-key/router";
    private const string TranscriptHashDomain = "Deep/IdentityAuth/V1/x25519-pop-transcript-hash";

    internal static X25519Possession Verify(
        ReadOnlySpan<byte> transcript,
        ReadOnlySpan<byte> proof,
        ReadOnlySpan<byte> issuerEphemeralPrivateKey,
        X25519PossessionRole expectedRole,
        ReadOnlySpan<byte> expectedNetwork,
        ReadOnlySpan<byte> expectedSubjectUnsignedHash,
        ReadOnlySpan<byte> expectedHolderPublicKey,
        ulong verificationTimeUnixSeconds)
    {
        if (transcript.Length != TranscriptLength || proof.Length != 32)
            Invalid("The DXP1 transcript or proof length is invalid.");
        var frozen = transcript.ToArray();
        var frozenProof = proof.ToArray();
        ValidatePublicShape(
            frozen,
            frozenProof,
            expectedRole,
            expectedNetwork,
            expectedSubjectUnsignedHash,
            expectedHolderPublicKey,
            verificationTimeUnixSeconds);
        if (issuerEphemeralPrivateKey.Length != 32 ||
            CanonicalGrammar.IsZero(issuerEphemeralPrivateKey))
            Invalid("The DXP1 issuer ephemeral private key is invalid.");

        var privateKey = issuerEphemeralPrivateKey.ToArray();
        byte[]? derivedPublic = null;
        byte[]? shared = null;
        byte[]? key = null;
        byte[]? expectedProof = null;
        try
        {
            derivedPublic = ScalarMult.Base(privateKey);
            if (!CanonicalGrammar.FixedEquals(derivedPublic, frozen.AsSpan(88, 32)))
                Invalid("The DXP1 issuer ephemeral key pair does not match.");
            shared = ScalarMult.Mult(privateKey, frozen.AsSpan(56, 32).ToArray());
            if (shared.Length != 32 || CanonicalGrammar.IsZero(shared))
                Invalid("The DXP1 X25519 result is invalid.");
            key = DeriveKey(frozen, shared, expectedRole);
            expectedProof = ComputeProof(key, frozen);
            if (!CanonicalGrammar.FixedEquals(expectedProof, frozenProof))
                throw new RecordException(RecordError.InvalidSignature, "The DXP1 proof is invalid.");
            var transcriptHash = ComputeTranscriptHash(frozen, expectedProof);
            return new X25519Possession(expectedRole, transcriptHash);
        }
        catch (CryptographicException exception)
        {
            throw new RecordException(
                RecordError.InvalidField,
                $"The DXP1 X25519 agreement failed: {exception.Message}");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            if (derivedPublic is not null) CryptographicOperations.ZeroMemory(derivedPublic);
            if (shared is not null) CryptographicOperations.ZeroMemory(shared);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (expectedProof is not null) CryptographicOperations.ZeroMemory(expectedProof);
            CryptographicOperations.ZeroMemory(frozenProof);
        }
    }

    internal static (byte[] Proof, byte[] TranscriptHash) CreateProof(
        ReadOnlySpan<byte> transcript,
        ReadOnlySpan<byte> holderPrivateKey)
    {
        if (transcript.Length != TranscriptLength || holderPrivateKey.Length != 32)
            Invalid("The DXP1 proof input is malformed.");
        var frozen = transcript.ToArray();
        var role = ParseRole(frozen[5]);
        ValidateTranscript(frozen, role, ulong.MaxValue, requireLiveNow: false);
        var privateKey = holderPrivateKey.ToArray();
        byte[]? derivedPublic = null;
        byte[]? shared = null;
        byte[]? key = null;
        try
        {
            derivedPublic = ScalarMult.Base(privateKey);
            if (!CanonicalGrammar.FixedEquals(derivedPublic, frozen.AsSpan(56, 32)))
                Invalid("The DXP1 holder key pair does not match.");
            shared = ScalarMult.Mult(privateKey, frozen.AsSpan(88, 32).ToArray());
            if (CanonicalGrammar.IsZero(shared)) Invalid("The DXP1 X25519 result is invalid.");
            key = DeriveKey(frozen, shared, role);
            var proof = ComputeProof(key, frozen);
            return (proof, ComputeTranscriptHash(frozen, proof));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
            if (derivedPublic is not null) CryptographicOperations.ZeroMemory(derivedPublic);
            if (shared is not null) CryptographicOperations.ZeroMemory(shared);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
        }
    }

    internal static byte[] GetNonceLedgerKey(ReadOnlySpan<byte> transcript)
    {
        Span<byte> value = stackalloc byte[16 + 1 + 32];
        transcript.Slice(8, 16).CopyTo(value);
        value[16] = transcript[5];
        transcript.Slice(120, 32).CopyTo(value[17..]);
        return SHA256.HashData(value);
    }

    private static void ValidatePublicShape(
        ReadOnlySpan<byte> transcript,
        ReadOnlySpan<byte> proof,
        X25519PossessionRole expectedRole,
        ReadOnlySpan<byte> expectedNetwork,
        ReadOnlySpan<byte> expectedSubjectUnsignedHash,
        ReadOnlySpan<byte> expectedHolderPublicKey,
        ulong now)
    {
        if (transcript.Length != TranscriptLength || proof.Length != 32 ||
            expectedNetwork.Length != 16 || expectedSubjectUnsignedHash.Length != 32 ||
            expectedHolderPublicKey.Length != 32)
            Invalid("The DXP1 transcript or proof length is invalid.");
        ValidateTranscript(transcript, expectedRole, now, requireLiveNow: true);
        Equal(transcript.Slice(8, 16), expectedNetwork, "network");
        Equal(transcript.Slice(24, 32), expectedSubjectUnsignedHash, "subject hash");
        Equal(transcript.Slice(56, 32), expectedHolderPublicKey, "holder public key");
    }

    private static void ValidateTranscript(
        ReadOnlySpan<byte> transcript,
        X25519PossessionRole expectedRole,
        ulong now,
        bool requireLiveNow)
    {
        if (!transcript[..4].SequenceEqual("DXP1"u8) || transcript[4] != 1 ||
            ParseRole(transcript[5]) != expectedRole || transcript[6] != 0 || transcript[7] != 0)
            Invalid("The DXP1 fixed header is invalid.");
        if (CanonicalGrammar.IsZero(transcript.Slice(8, 16)) ||
            CanonicalGrammar.IsZero(transcript.Slice(24, 32)) ||
            CanonicalGrammar.IsZero(transcript.Slice(56, 32)) ||
            CanonicalGrammar.IsZero(transcript.Slice(88, 32)) ||
            CanonicalGrammar.IsZero(transcript.Slice(120, 32)))
            Invalid("A required DXP1 value is zero.");
        var issued = BinaryPrimitives.ReadUInt64BigEndian(transcript.Slice(168 - 16, 8));
        var expires = BinaryPrimitives.ReadUInt64BigEndian(transcript.Slice(168 - 8, 8));
        if (issued == 0 || expires <= issued || expires - issued > MaximumWindowSeconds ||
            requireLiveNow && (now < issued || now >= expires))
            throw new RecordException(RecordError.Expired, "The DXP1 strict live window is invalid.");
    }

    private static byte[] DeriveKey(
        ReadOnlySpan<byte> transcript,
        ReadOnlySpan<byte> shared,
        X25519PossessionRole role)
    {
        var saltDomain = Encoding.ASCII.GetBytes(SaltDomain);
        var saltInput = new byte[2 + saltDomain.Length + 16 + 1 + 32 + 32 + 32 + 32];
        BinaryPrimitives.WriteUInt16BigEndian(saltInput, checked((ushort)saltDomain.Length));
        saltDomain.CopyTo(saltInput, 2);
        var offset = 2 + saltDomain.Length;
        transcript.Slice(8, 16).CopyTo(saltInput.AsSpan(offset)); offset += 16;
        saltInput[offset++] = (byte)role;
        transcript.Slice(24, 32).CopyTo(saltInput.AsSpan(offset)); offset += 32;
        transcript.Slice(120, 32).CopyTo(saltInput.AsSpan(offset)); offset += 32;
        transcript.Slice(88, 32).CopyTo(saltInput.AsSpan(offset)); offset += 32;
        transcript.Slice(56, 32).CopyTo(saltInput.AsSpan(offset));
        var salt = SHA256.HashData(saltInput);
        var prk = new byte[32];
        var roleDomain = Encoding.ASCII.GetBytes(role == X25519PossessionRole.Device
            ? DeviceKeyDomain
            : RouterKeyDomain);
        var info = new byte[2 + roleDomain.Length + 4 + TranscriptLength];
        BinaryPrimitives.WriteUInt16BigEndian(info, checked((ushort)roleDomain.Length));
        roleDomain.CopyTo(info, 2);
        BinaryPrimitives.WriteUInt32BigEndian(info.AsSpan(2 + roleDomain.Length), TranscriptLength);
        transcript.CopyTo(info.AsSpan(6 + roleDomain.Length));
        var key = new byte[32];
        try
        {
            if (HKDF.Extract(HashAlgorithmName.SHA256, shared, salt, prk) != prk.Length)
                throw new CryptographicException("HKDF Extract returned an unexpected length.");
            HKDF.Expand(HashAlgorithmName.SHA256, prk, key, info);
            return key;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(saltInput);
        }
    }

    private static byte[] ComputeProof(ReadOnlySpan<byte> key, ReadOnlySpan<byte> transcript)
    {
        var input = new byte[4 + TranscriptLength];
        BinaryPrimitives.WriteUInt32BigEndian(input, TranscriptLength);
        transcript.CopyTo(input.AsSpan(4));
        return HMACSHA256.HashData(key, input);
    }

    private static byte[] ComputeTranscriptHash(ReadOnlySpan<byte> transcript, ReadOnlySpan<byte> proof)
    {
        var payload = new byte[4 + TranscriptLength + 4 + 32];
        BinaryPrimitives.WriteUInt32BigEndian(payload, TranscriptLength);
        transcript.CopyTo(payload.AsSpan(4));
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(4 + TranscriptLength), 32);
        proof.CopyTo(payload.AsSpan(8 + TranscriptLength));
        return CanonicalGrammar.Sha256Domain(TranscriptHashDomain, payload);
    }

    private static X25519PossessionRole ParseRole(byte value)
    {
        if (value is not ((byte)X25519PossessionRole.Device or (byte)X25519PossessionRole.Router))
            Invalid("The DXP1 role is invalid.");
        return (X25519PossessionRole)value;
    }

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string name)
    {
        if (!CanonicalGrammar.FixedEquals(actual, expected)) Invalid($"The DXP1 {name} does not match.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
