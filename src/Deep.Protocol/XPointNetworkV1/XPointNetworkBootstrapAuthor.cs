using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

public enum XPointNetworkRootSignaturePurpose : byte
{
    GenesisAuthority = 1,
    DirectoryTimeSourcePolicy = 2,
    NetworkPolicy = 3,
}

public sealed class XPointNetworkBootstrapAuthoringException : CryptographicException
{
    internal XPointNetworkBootstrapAuthoringException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// Custody boundary for an offline XPoint root key. Implementations keep private key material
/// outside Deep.Protocol and sign only the exact, short-lived request supplied by the author.
/// </summary>
public interface IXPointNetworkBootstrapRootSigner
{
    ReadOnlyMemory<byte> RootKeyId { get; }
    ulong KeyGeneration { get; }
    ReadOnlyMemory<byte> Ed25519PublicKey { get; }
    ReadOnlyMemory<byte> CustodyDomainHash { get; }

    ValueTask<int> SignAsync(
        XPointNetworkRootSigningRequest request,
        Memory<byte> signature64,
        CancellationToken cancellationToken);
}

public sealed class XPointNetworkRootSigningRequest
{
    private readonly byte[] ceremonyId;
    private readonly byte[] networkId;
    private readonly byte[] rootKeyId;
    private readonly byte[] expectedPublicKey;
    private readonly byte[] custodyDomainHash;
    private readonly byte[] signingInput;
    private readonly byte[] signingInputHash;

    internal XPointNetworkRootSigningRequest(
        ReadOnlySpan<byte> ceremonyId,
        XPointNetworkRootSignaturePurpose purpose,
        ReadOnlySpan<byte> networkId,
        ulong authorityGeneration,
        ReadOnlySpan<byte> rootKeyId,
        ulong keyGeneration,
        ReadOnlySpan<byte> expectedPublicKey,
        ReadOnlySpan<byte> custodyDomainHash,
        ReadOnlySpan<byte> signingInput)
    {
        this.ceremonyId = ceremonyId.ToArray();
        Purpose = purpose;
        this.networkId = networkId.ToArray();
        AuthorityGeneration = authorityGeneration;
        this.rootKeyId = rootKeyId.ToArray();
        KeyGeneration = keyGeneration;
        this.expectedPublicKey = expectedPublicKey.ToArray();
        this.custodyDomainHash = custodyDomainHash.ToArray();
        this.signingInput = signingInput.ToArray();
        signingInputHash = SHA256.HashData(signingInput);
    }

    public ReadOnlyMemory<byte> CeremonyId => ceremonyId.ToArray();
    public XPointNetworkRootSignaturePurpose Purpose { get; }
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ulong AuthorityGeneration { get; }
    public ReadOnlyMemory<byte> RootKeyId => rootKeyId.ToArray();
    public ulong KeyGeneration { get; }
    public ReadOnlyMemory<byte> ExpectedEd25519PublicKey => expectedPublicKey.ToArray();
    public ReadOnlyMemory<byte> CustodyDomainHash => custodyDomainHash.ToArray();
    /// <summary>The exact signing input. It is valid only for the duration of SignAsync.</summary>
    public ReadOnlyMemory<byte> SigningInput => signingInput;
    /// <summary>SHA-256 of SigningInput, cleared together with the signing request.</summary>
    public ReadOnlyMemory<byte> SigningInputSha256 => signingInputHash;

    internal void Clear()
    {
        CryptographicOperations.ZeroMemory(signingInput);
        CryptographicOperations.ZeroMemory(signingInputHash);
    }
}

public sealed class XPointNetworkBootstrapRootKey
{
    private readonly byte[] id;
    private readonly byte[] publicKey;
    private readonly byte[] custodyDomainHash;

    public XPointNetworkBootstrapRootKey(
        ReadOnlySpan<byte> rootKeyId,
        ulong keyGeneration,
        ReadOnlySpan<byte> ed25519PublicKey,
        ReadOnlySpan<byte> custodyDomainHash)
    {
        id = RequiredNonZero(rootKeyId, 32, nameof(rootKeyId));
        KeyGeneration = keyGeneration;
        publicKey = RequiredNonZero(ed25519PublicKey, 32, nameof(ed25519PublicKey));
        this.custodyDomainHash = RequiredNonZero(custodyDomainHash, 32, nameof(custodyDomainHash));
    }

    public ReadOnlyMemory<byte> RootKeyId => id.ToArray();
    public ulong KeyGeneration { get; }
    public ReadOnlyMemory<byte> Ed25519PublicKey => publicKey.ToArray();
    public ReadOnlyMemory<byte> CustodyDomainHash => custodyDomainHash.ToArray();

    private static byte[] RequiredNonZero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }
}

public sealed class XPointNetworkBootstrapWitnessKey
{
    private readonly byte[] id;
    private readonly byte[] publicKey;
    private readonly byte[] failureDomainHash;

    public XPointNetworkBootstrapWitnessKey(
        ReadOnlySpan<byte> witnessId,
        ulong keyGeneration,
        ReadOnlySpan<byte> ed25519PublicKey,
        ReadOnlySpan<byte> failureDomainHash)
    {
        id = RequiredNonZero(witnessId, 32, nameof(witnessId));
        KeyGeneration = keyGeneration;
        publicKey = RequiredNonZero(ed25519PublicKey, 32, nameof(ed25519PublicKey));
        this.failureDomainHash = RequiredNonZero(failureDomainHash, 32, nameof(failureDomainHash));
    }

    public ReadOnlyMemory<byte> WitnessId => id.ToArray();
    public ulong KeyGeneration { get; }
    public ReadOnlyMemory<byte> Ed25519PublicKey => publicKey.ToArray();
    public ReadOnlyMemory<byte> FailureDomainHash => failureDomainHash.ToArray();

    private static byte[] RequiredNonZero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }
}

public sealed class XPointNetworkGenesisAuthoringRequest
{
    private readonly byte[] ceremonyId;
    private readonly byte[] networkId;
    private readonly XPointNetworkBootstrapRootKey[] rootKeys;
    private readonly XPointNetworkBootstrapWitnessKey[] witnessKeys;
    private readonly AccountDirectoryDts1Source[] timeSources;

    public XPointNetworkGenesisAuthoringRequest(
        ReadOnlySpan<byte> ceremonyId,
        ReadOnlySpan<byte> networkId,
        IReadOnlyList<XPointNetworkBootstrapRootKey> rootKeys,
        byte rootThreshold,
        IReadOnlyList<XPointNetworkBootstrapWitnessKey> witnessKeys,
        byte witnessThreshold,
        IReadOnlyList<AccountDirectoryDts1Source> timeSources,
        ushort maximumTimeSourceSampleAgeSeconds,
        uint maximumWitnessUncertaintySeconds,
        ulong authorityIssuedAtUnixSeconds,
        ulong authorityNotBeforeUnixSeconds,
        ulong authorityExpiresAtUnixSeconds,
        ulong timePolicyNotBeforeUnixSeconds,
        ulong timePolicyExpiresAtUnixSeconds,
        ushort minimumReader,
        ulong minimumClientGeneration)
    {
        this.ceremonyId = RequiredNonZero(ceremonyId, 32, nameof(ceremonyId));
        this.networkId = RequiredNonZero(networkId, 16, nameof(networkId));
        ArgumentNullException.ThrowIfNull(rootKeys);
        ArgumentNullException.ThrowIfNull(witnessKeys);
        ArgumentNullException.ThrowIfNull(timeSources);

        this.rootKeys = rootKeys.Select(static value =>
        {
            ArgumentNullException.ThrowIfNull(value);
            return new XPointNetworkBootstrapRootKey(
                value.RootKeyId.Span, value.KeyGeneration, value.Ed25519PublicKey.Span,
                value.CustodyDomainHash.Span);
        }).ToArray();
        RootThreshold = rootThreshold;
        this.witnessKeys = witnessKeys.Select(static value =>
        {
            ArgumentNullException.ThrowIfNull(value);
            return new XPointNetworkBootstrapWitnessKey(
                value.WitnessId.Span, value.KeyGeneration, value.Ed25519PublicKey.Span,
                value.FailureDomainHash.Span);
        }).ToArray();
        WitnessThreshold = witnessThreshold;
        this.timeSources = timeSources.Select(static value =>
        {
            ArgumentNullException.ThrowIfNull(value);
            return new AccountDirectoryDts1Source(
                value.SourceId.Span, value.FailureFamilyHash.Span, value.Protocol,
                value.HostAscii, value.Port, value.TlsSpkiSha256.Span,
                value.MaximumRadiusSeconds);
        }).ToArray();
        MaximumTimeSourceSampleAgeSeconds = maximumTimeSourceSampleAgeSeconds;
        MaximumWitnessUncertaintySeconds = maximumWitnessUncertaintySeconds;
        AuthorityIssuedAtUnixSeconds = authorityIssuedAtUnixSeconds;
        AuthorityNotBeforeUnixSeconds = authorityNotBeforeUnixSeconds;
        AuthorityExpiresAtUnixSeconds = authorityExpiresAtUnixSeconds;
        TimePolicyNotBeforeUnixSeconds = timePolicyNotBeforeUnixSeconds;
        TimePolicyExpiresAtUnixSeconds = timePolicyExpiresAtUnixSeconds;
        MinimumReader = minimumReader;
        MinimumClientGeneration = minimumClientGeneration;
    }

    public ReadOnlyMemory<byte> CeremonyId => ceremonyId.ToArray();
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public IReadOnlyList<XPointNetworkBootstrapRootKey> RootKeys => Array.AsReadOnly(rootKeys.ToArray());
    public byte RootThreshold { get; }
    public IReadOnlyList<XPointNetworkBootstrapWitnessKey> WitnessKeys => Array.AsReadOnly(witnessKeys.ToArray());
    public byte WitnessThreshold { get; }
    public IReadOnlyList<AccountDirectoryDts1Source> TimeSources => Array.AsReadOnly(timeSources.ToArray());
    public ushort MaximumTimeSourceSampleAgeSeconds { get; }
    public uint MaximumWitnessUncertaintySeconds { get; }
    public ulong AuthorityIssuedAtUnixSeconds { get; }
    public ulong AuthorityNotBeforeUnixSeconds { get; }
    public ulong AuthorityExpiresAtUnixSeconds { get; }
    public ulong TimePolicyNotBeforeUnixSeconds { get; }
    public ulong TimePolicyExpiresAtUnixSeconds { get; }
    public ushort MinimumReader { get; }
    public ulong MinimumClientGeneration { get; }

    private static byte[] RequiredNonZero(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }
}

public sealed class VerifiedXPointNetworkBootstrap
{
    private readonly byte[] exactXna1;
    private readonly byte[] exactDts1;

    internal VerifiedXPointNetworkBootstrap(
        ReadOnlySpan<byte> exactXna1,
        ReadOnlySpan<byte> exactDts1,
        XPointNetworkGenesisPin genesisPin,
        VerifiedXPointNetworkAuthority authority)
    {
        this.exactXna1 = exactXna1.ToArray();
        this.exactDts1 = exactDts1.ToArray();
        GenesisPin = genesisPin;
        Authority = authority;
    }

    public ReadOnlyMemory<byte> ExactXna1 => exactXna1.ToArray();
    public ReadOnlyMemory<byte> ExactDts1 => exactDts1.ToArray();
    public XPointNetworkGenesisPin GenesisPin { get; }
    public VerifiedXPointNetworkAuthority Authority { get; }
}

public static class XPointNetworkBootstrapAuthor
{
    /// <summary>
    /// Restores an immutable, already-authored generation-zero bootstrap only after the same
    /// verifier and explicit release pin used by clients accept its exact XNA1/DTS1 bytes.
    /// This is the renewal boundary for short-lived operational views; it never re-signs or
    /// silently derives a new genesis pin from caller-provided artifacts.
    /// </summary>
    public static VerifiedXPointNetworkBootstrap VerifyExistingGenesis(
        ReadOnlySpan<byte> exactXna1,
        ReadOnlySpan<byte> exactDts1,
        XPointNetworkGenesisPin expectedGenesisPin)
    {
        ArgumentNullException.ThrowIfNull(expectedGenesisPin);
        if (exactXna1.IsEmpty || exactDts1.IsEmpty)
            throw new ArgumentException("Exact generation-zero XNA1 and DTS1 are required.");

        var xna = exactXna1.ToArray();
        var dts = exactDts1.ToArray();
        var authority = XPointNetworkAuthorityVerifier.Verify(
            expectedGenesisPin,
            new ReadOnlyMemory<byte>[] { xna },
            new ReadOnlyMemory<byte>[] { dts });
        if (authority.AuthorityGeneration != 0)
            throw new XPointNetworkAuthorityVerificationException(
                "GenesisGenerationMismatch",
                "An existing bootstrap must resolve to authority generation zero.");
        return new VerifiedXPointNetworkBootstrap(xna, dts, expectedGenesisPin, authority);
    }

    public static async ValueTask<VerifiedXPointNetworkBootstrap> AuthorGenesisAsync(
        XPointNetworkGenesisAuthoringRequest request,
        IReadOnlyList<IXPointNetworkBootstrapRootSigner> rootSigners,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(rootSigners);

        try
        {
            var roots = ValidateRoots(request);
            var witnesses = ValidateWitnesses(request);
            var sources = ValidateSources(request);
            var signers = ValidateSigners(roots, request.RootThreshold, rootSigners);
            ValidateIntervals(request);

            var placeholderReceipts = signers.Select(static signer =>
                new AccountDirectoryDts1RootReceipt(signer.Id, NonZeroPlaceholder(64))).ToArray();
            var unsignedDts = new AccountDirectoryDts1(
                request.NetworkId.Span,
                0,
                new byte[32],
                sources,
                2,
                2,
                30,
                request.MaximumTimeSourceSampleAgeSeconds,
                request.TimePolicyNotBeforeUnixSeconds,
                request.TimePolicyExpiresAtUnixSeconds,
                request.MinimumReader,
                0,
                placeholderReceipts);

            byte[]? dtsSigningInput = null;
            byte[]? dtsPolicyHash = null;
            byte[]? xnaSigningInput = null;
            try
            {
                dtsSigningInput = AccountDirectoryCrypto.ComputeDts1SigningInput(unsignedDts);
                dtsPolicyHash = AccountDirectoryCrypto.ComputeDts1PolicyHash(unsignedDts);
                var xnaFields = CreateUnsignedXnaFields(request, roots, witnesses, signers, dtsPolicyHash);
                var provisionalXna = XPointNetworkCodec.Parse<Xna1Record>(
                    XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, xnaFields));
                xnaSigningInput = XPointNetworkCrypto.ComputeSigningInput(provisionalXna);

                var xnaReceipts = await SignAllAsync(
                    request, signers, XPointNetworkRootSignaturePurpose.GenesisAuthority,
                    xnaSigningInput, cancellationToken).ConfigureAwait(false);
                var dtsReceipts = await SignAllAsync(
                    request, signers, XPointNetworkRootSignaturePurpose.DirectoryTimeSourcePolicy,
                    dtsSigningInput, cancellationToken).ConfigureAwait(false);

                xnaFields[19] = EncodeSignatureEntries(xnaReceipts);
                var exactXna1 = XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, xnaFields);
                var exactDts1 = AccountDirectoryDts1Codec.Encode(new AccountDirectoryDts1(
                    request.NetworkId.Span,
                    0,
                    new byte[32],
                    sources,
                    2,
                    2,
                    30,
                    request.MaximumTimeSourceSampleAgeSeconds,
                    request.TimePolicyNotBeforeUnixSeconds,
                    request.TimePolicyExpiresAtUnixSeconds,
                    request.MinimumReader,
                    0,
                    dtsReceipts.Select(static receipt =>
                        new AccountDirectoryDts1RootReceipt(receipt.Id, receipt.Signature)).ToArray()));

                var finalXna = XPointNetworkCodec.Parse<Xna1Record>(exactXna1);
                var pin = new XPointNetworkGenesisPin(request.NetworkId.Span, finalXna.CoreHash.Span);
                var authority = XPointNetworkAuthorityVerifier.Verify(
                    pin,
                    new ReadOnlyMemory<byte>[] { exactXna1 },
                    new ReadOnlyMemory<byte>[] { exactDts1 });
                return new VerifiedXPointNetworkBootstrap(exactXna1, exactDts1, pin, authority);
            }
            finally
            {
                if (xnaSigningInput is not null) CryptographicOperations.ZeroMemory(xnaSigningInput);
                if (dtsSigningInput is not null) CryptographicOperations.ZeroMemory(dtsSigningInput);
                if (dtsPolicyHash is not null) CryptographicOperations.ZeroMemory(dtsPolicyHash);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (XPointNetworkBootstrapAuthoringException)
        {
            throw;
        }
        catch (Exception exception) when (exception is ArgumentException or
                                          XPointValidationException or
                                          AccountDirectoryDts1FormatException or
                                          XPointNetworkAuthorityVerificationException)
        {
            throw new XPointNetworkBootstrapAuthoringException(
                "InvalidBootstrapInput", "The XPoint bootstrap input or resulting closure is invalid.", exception);
        }
    }

    private static RootBinding[] ValidateRoots(XPointNetworkGenesisAuthoringRequest request)
    {
        if (request.RootKeys.Count is < 1 or > 8 ||
            request.RootThreshold is < 1 || request.RootThreshold > request.RootKeys.Count)
            Fail("InvalidRootPolicy", "Genesis requires one to eight root keys and a satisfiable threshold.");

        var ids = new HashSet<string>(StringComparer.Ordinal);
        var keys = new HashSet<string>(StringComparer.Ordinal);
        var custodyDomains = new HashSet<string>(StringComparer.Ordinal);
        var roots = new RootBinding[request.RootKeys.Count];
        for (var index = 0; index < roots.Length; index++)
        {
            var source = request.RootKeys[index];
            var id = source.RootKeyId.ToArray();
            var publicKey = source.Ed25519PublicKey.ToArray();
            var custodyDomain = source.CustodyDomainHash.ToArray();
            if (source.KeyGeneration != 0)
                Fail("InvalidGenesisKeyGeneration", "Every genesis root key generation must be zero.");
            if (!ids.Add(Convert.ToHexString(id)) ||
                !keys.Add(Convert.ToHexString(publicKey)) ||
                !custodyDomains.Add(Convert.ToHexString(custodyDomain)))
                Fail("DuplicateRootBoundary", "Genesis root key IDs, public keys and custody domains must be unique.");
            roots[index] = new RootBinding(id, source.KeyGeneration, publicKey, custodyDomain);
        }
        Array.Sort(roots, static (left, right) => left.Id.AsSpan().SequenceCompareTo(right.Id));
        return roots;
    }

    private static WitnessBinding[] ValidateWitnesses(XPointNetworkGenesisAuthoringRequest request)
    {
        if (request.WitnessKeys.Count is < 3 or > 32 ||
            request.WitnessThreshold is < 2 || request.WitnessThreshold > request.WitnessKeys.Count)
            Fail("InvalidWitnessPolicy", "Genesis requires three to 32 witnesses and a satisfiable threshold of at least two.");

        var ids = new HashSet<string>(StringComparer.Ordinal);
        var keys = new HashSet<string>(StringComparer.Ordinal);
        var domains = new HashSet<string>(StringComparer.Ordinal);
        var witnesses = new WitnessBinding[request.WitnessKeys.Count];
        for (var index = 0; index < witnesses.Length; index++)
        {
            var source = request.WitnessKeys[index];
            var id = source.WitnessId.ToArray();
            var publicKey = source.Ed25519PublicKey.ToArray();
            var domain = source.FailureDomainHash.ToArray();
            if (source.KeyGeneration != 0)
                Fail("InvalidGenesisKeyGeneration", "Every genesis witness key generation must be zero.");
            if (!ids.Add(Convert.ToHexString(id)) ||
                !keys.Add(Convert.ToHexString(publicKey)) ||
                !domains.Add(Convert.ToHexString(domain)))
                Fail("DuplicateWitnessBoundary", "Genesis witness IDs, public keys and failure domains must be unique.");
            witnesses[index] = new WitnessBinding(id, source.KeyGeneration, publicKey, domain);
        }
        if (domains.Count < request.WitnessThreshold)
            Fail("InsufficientWitnessFailureDomains", "Witnesses do not meet the distinct failure-domain threshold.");
        Array.Sort(witnesses, static (left, right) => left.Id.AsSpan().SequenceCompareTo(right.Id));
        return witnesses;
    }

    private static AccountDirectoryDts1Source[] ValidateSources(XPointNetworkGenesisAuthoringRequest request)
    {
        var sources = request.TimeSources.Select(static source => new AccountDirectoryDts1Source(
            source.SourceId.Span, source.FailureFamilyHash.Span, source.Protocol,
            source.HostAscii, source.Port, source.TlsSpkiSha256.Span,
            source.MaximumRadiusSeconds)).ToArray();
        Array.Sort(sources, static (left, right) =>
            left.SourceId.Span.SequenceCompareTo(right.SourceId.Span));
        return sources;
    }

    private static SignerBinding[] ValidateSigners(
        IReadOnlyList<RootBinding> roots,
        int threshold,
        IReadOnlyList<IXPointNetworkBootstrapRootSigner> signers)
    {
        if (signers.Count is < 1 or > 8)
            Fail("InsufficientRootSigners", "Genesis requires between one and eight configured root signers.");
        var result = new SignerBinding[signers.Count];
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var custodyDomains = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < signers.Count; index++)
        {
            var signer = signers[index] ?? throw new XPointNetworkBootstrapAuthoringException(
                "UnknownRootSigner", "A configured root signer is null.");
            var id = signer.RootKeyId.ToArray();
            var publicKey = signer.Ed25519PublicKey.ToArray();
            var custodyDomain = signer.CustodyDomainHash.ToArray();
            if (id.Length != 32 || id.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                publicKey.Length != 32 || publicKey.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                custodyDomain.Length != 32 || custodyDomain.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                !ids.Add(Convert.ToHexString(id)))
                Fail("DuplicateOrInvalidRootSigner", "Root signer identities must be exact, non-zero and unique.");
            var root = roots.FirstOrDefault(candidate => Fixed(candidate.Id, id));
            if (root is null || root.Generation != signer.KeyGeneration ||
                !Fixed(root.PublicKey, publicKey) || !Fixed(root.CustodyDomainHash, custodyDomain))
                Fail("UnknownRootSigner", "A root signer does not match one exact genesis root-key entry.");
            custodyDomains.Add(Convert.ToHexString(custodyDomain));
            result[index] = new SignerBinding(signer, id, root.Generation, publicKey, custodyDomain);
        }
        if (result.Length < threshold || custodyDomains.Count < threshold)
            Fail("InsufficientRootSigners", "Configured root signers do not meet the key and custody-domain threshold.");
        Array.Sort(result, static (left, right) => left.Id.AsSpan().SequenceCompareTo(right.Id));
        return result;
    }

    private static void ValidateIntervals(XPointNetworkGenesisAuthoringRequest request)
    {
        if (request.MinimumReader == 0 || request.MinimumClientGeneration == 0)
            Fail("InvalidReaderFloor", "Reader and client generation floors must be non-zero.");
        if (request.AuthorityIssuedAtUnixSeconds == 0 ||
            request.AuthorityIssuedAtUnixSeconds > request.AuthorityNotBeforeUnixSeconds ||
            request.AuthorityNotBeforeUnixSeconds >= request.AuthorityExpiresAtUnixSeconds ||
            request.AuthorityExpiresAtUnixSeconds - request.AuthorityNotBeforeUnixSeconds > 34_560_000)
            Fail("InvalidAuthorityInterval", "The genesis authority interval is invalid or exceeds 400 days.");
        if (request.TimePolicyNotBeforeUnixSeconds < request.AuthorityNotBeforeUnixSeconds ||
            request.TimePolicyNotBeforeUnixSeconds >= request.TimePolicyExpiresAtUnixSeconds ||
            request.TimePolicyExpiresAtUnixSeconds - request.TimePolicyNotBeforeUnixSeconds > 2_592_000 ||
            request.TimePolicyExpiresAtUnixSeconds > request.AuthorityExpiresAtUnixSeconds)
            Fail("InvalidTimePolicyInterval", "The DTS1 interval must be non-empty, at most 30 days and covered by XNA1.");
        if (request.MaximumTimeSourceSampleAgeSeconds is < 1 or > 30 ||
            request.MaximumWitnessUncertaintySeconds is < 1 or > 30)
            Fail("InvalidTimePolicy", "The genesis authenticated-time bounds are invalid.");
    }

    private static ReadOnlyMemory<byte>[] CreateUnsignedXnaFields(
        XPointNetworkGenesisAuthoringRequest request,
        IReadOnlyList<RootBinding> roots,
        IReadOnlyList<WitnessBinding> witnesses,
        IReadOnlyList<SignerBinding> signers,
        ReadOnlySpan<byte> dtsPolicyHash)
    {
        return
        [
            request.NetworkId.ToArray(),
            U64(0),
            new byte[32],
            new byte[] { checked((byte)roots.Count) },
            EncodeRootEntries(roots),
            new byte[] { request.RootThreshold },
            U64(0),
            U16(1),
            new byte[] { checked((byte)witnesses.Count) },
            EncodeWitnessEntries(witnesses),
            new byte[] { request.WitnessThreshold },
            XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.DTS1, dtsPolicyHash),
            dtsPolicyHash.ToArray(),
            U32(request.MaximumWitnessUncertaintySeconds),
            U64(request.MinimumClientGeneration),
            U64(request.AuthorityIssuedAtUnixSeconds),
            U64(request.AuthorityNotBeforeUnixSeconds),
            U64(request.AuthorityExpiresAtUnixSeconds),
            new byte[] { checked((byte)signers.Count) },
            EncodeSignatureEntries(signers.Select(static (signer, index) =>
                new SignatureBinding(signer.Id, NonZeroPlaceholder(64, checked((byte)(index + 1))))).ToArray()),
        ];
    }

    private static async ValueTask<SignatureBinding[]> SignAllAsync(
        XPointNetworkGenesisAuthoringRequest authoring,
        IReadOnlyList<SignerBinding> signers,
        XPointNetworkRootSignaturePurpose purpose,
        byte[] signingInput,
        CancellationToken cancellationToken)
    {
        var receipts = new SignatureBinding[signers.Count];
        for (var index = 0; index < signers.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var signature = new byte[64];
            var signingRequest = new XPointNetworkRootSigningRequest(
                authoring.CeremonyId.Span,
                purpose,
                authoring.NetworkId.Span,
                0,
                signers[index].Id,
                signers[index].Generation,
                signers[index].PublicKey,
                signers[index].CustodyDomainHash,
                signingInput);
            try
            {
                int written;
                try
                {
                    written = await signers[index].Signer
                        .SignAsync(signingRequest, signature, cancellationToken)
                        .ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    throw new XPointNetworkBootstrapAuthoringException(
                        "RootSignerFailed", "A configured root signer failed.", exception);
                }

                if (written != 64 || signature.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                    !VerifySignature(signature, signingInput, signers[index].PublicKey))
                    Fail("InvalidRootSignerResult", "A configured root signer returned an invalid signature.");
                receipts[index] = new SignatureBinding(signers[index].Id, signature.ToArray());
            }
            finally
            {
                signingRequest.Clear();
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        return receipts;
    }

    private static bool VerifySignature(byte[] signature, byte[] signingInput, byte[] publicKey)
    {
        try
        {
            return PublicKeyAuth.VerifyDetached(signature, signingInput, publicKey);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static byte[] EncodeRootEntries(IReadOnlyList<RootBinding> roots)
    {
        var output = new byte[checked(roots.Count * 72)];
        for (var index = 0; index < roots.Count; index++)
        {
            roots[index].Id.CopyTo(output, index * 72);
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(index * 72 + 32), roots[index].Generation);
            roots[index].PublicKey.CopyTo(output, index * 72 + 40);
        }
        return output;
    }

    private static byte[] EncodeWitnessEntries(IReadOnlyList<WitnessBinding> witnesses)
    {
        var output = new byte[checked(witnesses.Count * 104)];
        for (var index = 0; index < witnesses.Count; index++)
        {
            witnesses[index].Id.CopyTo(output, index * 104);
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(index * 104 + 32), witnesses[index].Generation);
            witnesses[index].PublicKey.CopyTo(output, index * 104 + 40);
            witnesses[index].FailureDomainHash.CopyTo(output, index * 104 + 72);
        }
        return output;
    }

    private static byte[] EncodeSignatureEntries(IReadOnlyList<SignatureBinding> signatures)
    {
        var output = new byte[checked(signatures.Count * 96)];
        for (var index = 0; index < signatures.Count; index++)
        {
            signatures[index].Id.CopyTo(output, index * 96);
            signatures[index].Signature.CopyTo(output, index * 96 + 32);
        }
        return output;
    }

    private static byte[] NonZeroPlaceholder(int length, byte discriminator = 1)
    {
        var output = new byte[length];
        output[0] = discriminator;
        return output;
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] U32(uint value)
    {
        var output = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(output, value);
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new XPointNetworkBootstrapAuthoringException(code, message);

    private sealed record RootBinding(byte[] Id, ulong Generation, byte[] PublicKey, byte[] CustodyDomainHash);
    private sealed record WitnessBinding(byte[] Id, ulong Generation, byte[] PublicKey, byte[] FailureDomainHash);
    private sealed record SignerBinding(
        IXPointNetworkBootstrapRootSigner Signer,
        byte[] Id,
        ulong Generation,
        byte[] PublicKey,
        byte[] CustodyDomainHash);
    private sealed record SignatureBinding(byte[] Id, byte[] Signature);
}
