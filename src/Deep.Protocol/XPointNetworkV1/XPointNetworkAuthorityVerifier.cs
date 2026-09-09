using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

public sealed class XPointNetworkAuthorityVerificationException : FormatException
{
    internal XPointNetworkAuthorityVerificationException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    public string Code { get; }
}

public sealed class XPointNetworkGenesisPin
{
    private readonly byte[] networkId;
    private readonly byte[] authorityCoreHash;

    public XPointNetworkGenesisPin(ReadOnlySpan<byte> networkId, ReadOnlySpan<byte> generationZeroAuthorityCoreHash)
    {
        this.networkId = Required(networkId, 16, nameof(networkId));
        authorityCoreHash = Required(generationZeroAuthorityCoreHash, 32, nameof(generationZeroAuthorityCoreHash));
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ulong AuthorityGeneration => 0;
    public ReadOnlyMemory<byte> AuthorityCoreHash => authorityCoreHash.ToArray();

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }
}

public sealed class XPointNetworkRootKey
{
    private readonly byte[] id;
    private readonly byte[] publicKey;

    internal XPointNetworkRootKey(ReadOnlySpan<byte> id, ulong generation, ReadOnlySpan<byte> publicKey)
    {
        this.id = id.ToArray();
        Generation = generation;
        this.publicKey = publicKey.ToArray();
    }

    public ReadOnlyMemory<byte> Id => id.ToArray();
    public ulong Generation { get; }
    public ReadOnlyMemory<byte> Ed25519PublicKey => publicKey.ToArray();
}

public sealed class XPointNetworkWitnessKey
{
    private readonly byte[] id;
    private readonly byte[] publicKey;
    private readonly byte[] failureDomainHash;

    internal XPointNetworkWitnessKey(
        ReadOnlySpan<byte> id,
        ulong generation,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> failureDomainHash)
    {
        this.id = id.ToArray();
        Generation = generation;
        this.publicKey = publicKey.ToArray();
        this.failureDomainHash = failureDomainHash.ToArray();
    }

    public ReadOnlyMemory<byte> Id => id.ToArray();
    public ulong Generation { get; }
    public ReadOnlyMemory<byte> Ed25519PublicKey => publicKey.ToArray();
    public ReadOnlyMemory<byte> FailureDomainHash => failureDomainHash.ToArray();
}

public sealed class VerifiedXPointNetworkAuthority
{
    private readonly byte[] networkId;
    private readonly byte[] authorityCoreHash;
    private readonly byte[] authorityCoreReference;
    private readonly byte[] directoryWitnessPolicyHash;
    private readonly byte[] dts1PolicyCoreReference;
    private readonly byte[] timeSourcePolicyHash;
    private readonly XPointNetworkRootKey[] rootKeys;
    private readonly XPointNetworkWitnessKey[] witnessKeys;
    private readonly Xna1Record[] authorityChain;

    internal VerifiedXPointNetworkAuthority(
        Xna1Record authority,
        AccountDirectoryDts1 dts1,
        IReadOnlyList<Xna1Record> verifiedAuthorityChain)
    {
        networkId = authority.NetworkId.ToArray();
        AuthorityGeneration = authority.AuthorityGeneration;
        authorityCoreHash = authority.CoreHash.ToArray();
        authorityCoreReference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNA1, authority.CoreHash.Span);
        DirectoryWitnessPolicyGeneration = authority.UInt64(7);
        directoryWitnessPolicyHash = authority.DirectoryWitnessPolicyHash.ToArray();
        dts1PolicyCoreReference = authority.FieldSpan(12).ToArray();
        timeSourcePolicyHash = authority.FieldSpan(13).ToArray();
        MaximumWitnessUncertaintySeconds = authority.UInt32(14);
        MinimumClientGeneration = authority.UInt64(15);
        IssuedAt = authority.IssuedAt;
        NotBefore = authority.NotBefore;
        ExpiresAt = authority.ExpiresAt;
        RootThreshold = authority.RootThreshold;
        rootKeys = authority.RootKeys
            .Select(static key => new XPointNetworkRootKey(key.Id.Span, key.Generation, key.PublicKey.Span))
            .ToArray();
        WitnessThreshold = authority.WitnessThreshold;
        witnessKeys = authority.Witnesses
            .Select(static key => new XPointNetworkWitnessKey(
                key.Id.Span, key.Generation, key.PublicKey.Span, key.FailureDomainHash.Span))
            .ToArray();
        Dts1PolicyGeneration = dts1.PolicyGeneration;
        Dts1NotBefore = dts1.NotBefore;
        Dts1ExpiresAt = dts1.ExpiresAt;
        authorityChain = verifiedAuthorityChain.ToArray();
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ulong AuthorityGeneration { get; }
    public ReadOnlyMemory<byte> AuthorityCoreHash => authorityCoreHash.ToArray();
    public ReadOnlyMemory<byte> AuthorityCoreReference => authorityCoreReference.ToArray();
    public ulong DirectoryWitnessPolicyGeneration { get; }
    public ReadOnlyMemory<byte> DirectoryWitnessPolicyHash => directoryWitnessPolicyHash.ToArray();
    public ReadOnlyMemory<byte> Dts1PolicyCoreReference => dts1PolicyCoreReference.ToArray();
    public ReadOnlyMemory<byte> TimeSourcePolicyHash => timeSourcePolicyHash.ToArray();
    public uint MaximumWitnessUncertaintySeconds { get; }
    public ulong MinimumClientGeneration { get; }
    public ulong IssuedAt { get; }
    public ulong NotBefore { get; }
    public ulong ExpiresAt { get; }
    public byte RootThreshold { get; }
    public IReadOnlyList<XPointNetworkRootKey> RootKeys => Array.AsReadOnly(rootKeys.ToArray());
    public byte WitnessThreshold { get; }
    public IReadOnlyList<XPointNetworkWitnessKey> WitnessKeys => Array.AsReadOnly(witnessKeys.ToArray());
    public ulong Dts1PolicyGeneration { get; }
    public ulong Dts1NotBefore { get; }
    public ulong Dts1ExpiresAt { get; }

    internal IReadOnlyList<Xna1Record> AuthorityChain => authorityChain;
}

public static class XPointNetworkAuthorityVerifier
{
    public static VerifiedXPointNetworkAuthority Verify(
        XPointNetworkGenesisPin genesisPin,
        IReadOnlyList<ReadOnlyMemory<byte>> exactXna1AuthorityChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactDts1PolicyChain)
    {
        ArgumentNullException.ThrowIfNull(genesisPin);
        ArgumentNullException.ThrowIfNull(exactXna1AuthorityChain);
        ArgumentNullException.ThrowIfNull(exactDts1PolicyChain);
        if (exactXna1AuthorityChain.Count == 0 || exactXna1AuthorityChain.Count != exactDts1PolicyChain.Count)
            Fail("IncompleteAuthorityClosure", "XNA1 and DTS1 chains must be non-empty, complete and positionally paired.");

        var xnaBytes = Own(exactXna1AuthorityChain, ProtocolMagic.XNA1);
        var dtsBytes = Own(exactDts1PolicyChain, ProtocolMagic.DTS1);
        try
        {
            Xna1Record? predecessor = null;
            AccountDirectoryDts1? predecessorDts = null;
            byte[]? predecessorPolicyHash = null;
            Xna1Record? current = null;
            AccountDirectoryDts1? currentDts = null;
            var verifiedAuthorities = new List<Xna1Record>(xnaBytes.Length);
            var signatures = SodiumVerifier.Instance;

            for (var index = 0; index < xnaBytes.Length; index++)
            {
                current = XPointNetworkCodec.Parse<Xna1Record>(xnaBytes[index]);
                currentDts = AccountDirectoryDts1Codec.Decode(dtsBytes[index]);
                if (!current.NetworkId.Span.SequenceEqual(genesisPin.NetworkId.Span) ||
                    !currentDts.NetworkId.Span.SequenceEqual(genesisPin.NetworkId.Span))
                    Fail("NetworkMismatch", "The pinned network, XNA1 and DTS1 networks differ.");

                if (index == 0)
                {
                    if (current.AuthorityGeneration != 0 ||
                        !CryptographicOperations.FixedTimeEquals(current.CoreHash.Span, genesisPin.AuthorityCoreHash.Span))
                        Fail("GenesisPinMismatch", "The first XNA1 is not the exact pinned generation-zero authority core.");
                    if (currentDts.PolicyGeneration != 0)
                        Fail("MissingDtsPredecessor", "The complete DTS1 policy chain must begin at generation zero.");
                }
                else
                {
                    VerifyDtsSuccessor(predecessorDts!, predecessorPolicyHash!, currentDts);
                }

                var policyHash = AccountDirectoryCrypto.ComputeDts1PolicyHash(currentDts);
                var resolver = new ExactDtsResolver(current, currentDts, policyHash);
                XPointNetworkVerifier.Verify(current, new XPointVerificationContext(
                    resolver,
                    signatures,
                    predecessor,
                    index == 0 ? new XPointBytes(genesisPin.AuthorityCoreHash.Span) : default));
                VerifyDtsAuthority(current, currentDts, policyHash, signatures);

                predecessor = current;
                predecessorDts = currentDts;
                predecessorPolicyHash = policyHash;
                verifiedAuthorities.Add(current);
            }

            return new VerifiedXPointNetworkAuthority(current!, currentDts!, verifiedAuthorities);
        }
        catch (XPointNetworkAuthorityVerificationException)
        {
            throw;
        }
        catch (XPointValidationException exception)
        {
            throw new XPointNetworkAuthorityVerificationException(exception.Error, exception.Message, exception);
        }
        catch (AccountDirectoryDts1FormatException exception)
        {
            throw new XPointNetworkAuthorityVerificationException("InvalidDts1", exception.Message, exception);
        }
        catch (ArgumentException exception)
        {
            throw new XPointNetworkAuthorityVerificationException("InvalidAuthorityClosure", exception.Message, exception);
        }
    }

    private static byte[][] Own(IReadOnlyList<ReadOnlyMemory<byte>> values, string magic)
    {
        var result = new byte[values.Count][];
        for (var index = 0; index < values.Count; index++)
        {
            var value = values[index];
            if (value.IsEmpty)
                Fail("IncompleteAuthorityClosure", $"The exact {magic} chain contains an empty entry.");
            result[index] = value.ToArray();
        }
        return result;
    }

    private static void VerifyDtsSuccessor(
        AccountDirectoryDts1 predecessor,
        ReadOnlySpan<byte> predecessorPolicyHash,
        AccountDirectoryDts1 candidate)
    {
        if (predecessor.PolicyGeneration == ulong.MaxValue ||
            candidate.PolicyGeneration != predecessor.PolicyGeneration + 1 ||
            !CryptographicOperations.FixedTimeEquals(candidate.PredecessorPolicyHash.Span, predecessorPolicyHash))
            Fail("DtsPredecessorMismatch", "DTS1 policy entries must form an exact generation-by-generation predecessor chain.");
    }

    private static void VerifyDtsAuthority(
        Xna1Record authority,
        AccountDirectoryDts1 dts,
        ReadOnlySpan<byte> policyHash,
        IXPointSignatureVerifier signatures)
    {
        if (dts.RootAuthorityGeneration != authority.AuthorityGeneration)
            Fail("DtsAuthorityGenerationMismatch", "DTS1 root-authority generation does not equal its exact XNA1 generation.");
        if (!CryptographicOperations.FixedTimeEquals(policyHash, authority.FieldSpan(13)))
            Fail("DtsPolicyHashMismatch", "DTS1 policy hash does not equal XNA1 tag 13.");
        var expectedReference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.DTS1, policyHash);
        if (!CryptographicOperations.FixedTimeEquals(expectedReference, authority.FieldSpan(12)))
            Fail("DtsPolicyReferenceMismatch", "DTS1 policy core reference does not equal XNA1 tag 12.");

        var signingInput = AccountDirectoryCrypto.ComputeDts1SigningInput(dts);
        var valid = 0;
        foreach (var receipt in dts.RootReceipts)
        {
            XPointRootKeyEntry? key = null;
            foreach (var candidate in authority.RootKeys)
            {
                if (!candidate.Id.Span.SequenceEqual(receipt.RootKeyId.Span)) continue;
                key = candidate;
                break;
            }
            if (key is null)
                Fail("UnknownDtsSigner", "A DTS1 receipt signer is absent from the exact XNA1 root-key set.");
            if (!signatures.VerifyEd25519(key.PublicKey.Span, signingInput, receipt.Signature.Span))
                Fail("InvalidDtsSignature", "A DTS1 root receipt signature is invalid.");
            valid++;
        }
        if (valid < authority.RootThreshold)
            Fail("WrongDtsThreshold", "DTS1 root receipts do not meet the exact XNA1 root threshold.");
    }

    private sealed class SodiumVerifier : IXPointSignatureVerifier
    {
        internal static readonly SodiumVerifier Instance = new();

        public bool VerifyEd25519(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            if (publicKey.Length != 32 || signature.Length != 64) return false;
            try { return PublicKeyAuth.VerifyDetached(signature.ToArray(), message.ToArray(), publicKey.ToArray()); }
            catch (Exception) { return false; }
        }
    }

    private sealed class ExactDtsResolver(
        Xna1Record authority,
        AccountDirectoryDts1 dts,
        ReadOnlySpan<byte> policyHash) : IXPointClosureResolver
    {
        private readonly byte[] hash = policyHash.ToArray();

        public XPointExternalEvidence ResolveExternalCore(XPointCoreReference reference)
        {
            if (reference.Magic != ProtocolMagic.DTS1 || reference.Version != 1 ||
                !CryptographicOperations.FixedTimeEquals(reference.Hash.Span, hash))
                Fail("DtsPolicyReferenceMismatch", "XNA1 does not reference the exact paired DTS1 policy core.");
            return new XPointExternalEvidence(
                ProtocolMagic.DTS1,
                new XPointBytes(dts.NetworkId.Span),
                default,
                dts.NotBefore,
                dts.ExpiresAt,
                new XPointBytes(hash),
                dts.MaximumIntervalWidthSeconds,
                authority.CoreReferenceValue);
        }

        public XPointParsedRecord ResolveCore(XPointCoreReference reference) => throw Unreachable();
        public XPointParsedRecord ResolveArtifact(XPointArtifactReference reference) => throw Unreachable();
        public Xnd1Record ResolveNodeDescriptor(XPointBytes nodeId) => throw Unreachable();
        public bool IsNodeActiveAndUnrevoked(XPointBytes nodeId) => throw Unreachable();
        public XPointExternalEvidence ResolveExternalArtifact(XPointArtifactReference reference) => throw Unreachable();
        private static InvalidOperationException Unreachable() => new("The XNA1 relative verifier requested unrelated closure.");
    }

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new XPointNetworkAuthorityVerificationException(code, message);
}
