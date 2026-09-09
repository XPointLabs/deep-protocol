using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Protocol.DeepNative;

internal enum DxpIdentityIssuanceSourceKind : byte
{
    OfflineAccountDeviceGenesis = 1,
    CurrentCutoverRouter = 2
}

/// <summary>
/// A sealed identity-issuance source. It is minted only from an already verified
/// identity or cutover capability and carries no signing or persistence authority.
/// </summary>
public sealed class DxpIdentityIssuanceSource
{
    private readonly byte[] _network;
    private readonly byte[] _accountHash;
    private readonly byte[] _identityIssuanceSource;
    private readonly byte[] _issuanceScope;
    private readonly byte[] _drsHead;
    private readonly byte[] _drsReference;

    internal DxpIdentityIssuanceSource(
        DxpIdentityIssuanceSourceKind kind,
        X25519PossessionRole role,
        ReadOnlySpan<byte> network16,
        ReadOnlySpan<byte> accountHash32,
        ulong accountGeneration,
        ReadOnlySpan<byte> identityIssuanceSource32,
        ReadOnlySpan<byte> issuanceScope32,
        ulong drsRevision,
        ulong drsCount,
        ReadOnlySpan<byte> drsHead32,
        ReadOnlySpan<byte> drsRef38)
    {
        if (!Enum.IsDefined(kind) ||
            (kind == DxpIdentityIssuanceSourceKind.OfflineAccountDeviceGenesis &&
                role != X25519PossessionRole.Device) ||
            (kind == DxpIdentityIssuanceSourceKind.CurrentCutoverRouter &&
                role != X25519PossessionRole.Router) ||
            network16.Length != 16 || accountHash32.Length != 32 ||
            identityIssuanceSource32.Length != 32 || issuanceScope32.Length != 32 ||
            drsHead32.Length != 32 || drsRef38.Length != 38 ||
            accountGeneration == 0 || drsRevision == 0 ||
            (drsCount == 0) != CanonicalGrammar.IsZero(drsHead32) ||
            CanonicalGrammar.IsZero(network16) || CanonicalGrammar.IsZero(accountHash32) ||
            CanonicalGrammar.IsZero(identityIssuanceSource32) ||
            CanonicalGrammar.IsZero(issuanceScope32) || CanonicalGrammar.IsZero(drsRef38))
            Invalid("The sealed DXP identity-issuance source is malformed.");

        Kind = kind;
        Role = role;
        _network = network16.ToArray();
        _accountHash = accountHash32.ToArray();
        AccountGeneration = accountGeneration;
        _identityIssuanceSource = identityIssuanceSource32.ToArray();
        _issuanceScope = issuanceScope32.ToArray();
        DrsRevision = drsRevision;
        DrsCount = drsCount;
        _drsHead = drsHead32.ToArray();
        _drsReference = drsRef38.ToArray();
    }

    internal DxpIdentityIssuanceSourceKind Kind { get; }
    internal X25519PossessionRole Role { get; }
    internal ReadOnlySpan<byte> Network => _network;
    internal ReadOnlySpan<byte> AccountHash => _accountHash;
    internal ulong AccountGeneration { get; }
    internal ReadOnlySpan<byte> TrustedIdentityIssuanceSource => _identityIssuanceSource;
    internal ReadOnlySpan<byte> TrustedIssuanceScope => _issuanceScope;
    internal ulong DrsRevision { get; }
    internal ulong DrsCount { get; }
    internal ReadOnlySpan<byte> DrsHead => _drsHead;
    internal ReadOnlySpan<byte> DrsReference => _drsReference;
    public ReadOnlyMemory<byte> IdentityIssuanceSource => _identityIssuanceSource.ToArray();
    public ReadOnlyMemory<byte> IssuanceScope => _issuanceScope.ToArray();
    public bool NoAuthorityClaim => true;

    internal bool SameBase(DxpIdentityIssuanceSource other) =>
        Kind == other.Kind && Role == other.Role &&
        AccountGeneration == other.AccountGeneration &&
        DrsRevision == other.DrsRevision && DrsCount == other.DrsCount &&
        Equal(Network, other.Network) && Equal(AccountHash, other.AccountHash) &&
        Equal(TrustedIdentityIssuanceSource, other.TrustedIdentityIssuanceSource) &&
        Equal(TrustedIssuanceScope, other.TrustedIssuanceScope) &&
        Equal(DrsHead, other.DrsHead) && Equal(DrsReference, other.DrsReference);

    private static bool Equal(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        CanonicalGrammar.FixedEquals(left, right);

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

/// <summary>Derives sealed DXP issuance sources from verified exact evidence.</summary>
public sealed class DxpIdentityIssuanceSourceVerifier
{
    private const string OfflineSourceDomain =
        "Deep/IdentityAuth/V2/offline-genesis-identity-issuance-source";
    private const string AccountDeviceScopeDomain =
        "Deep/IdentityAuth/V2/account-device-issuance-scope";
    private const string CutoverScopeDomain =
        "Deep/IdentityAuth/V2/current-cutover-router-issuance-scope";

    public DxpIdentityIssuanceSource CreateOfflineAccountDeviceGenesis(
        VerifiedIdentityRelative identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var account = identity.Account;
        var dpa = account.Certificate;
        var drs = identity.Revocations.Snapshot;
        if (identity.ForkLatched || identity.IsTerminal ||
            identity.Authority.OrderedTransitions.Count != 0 ||
            dpa.AccountGeneration != 1 || dpa.CertificateGeneration != 1 ||
            drs.AccountGeneration != 1 || drs.Revision != 1 || drs.EntryCount != 0 ||
            !CanonicalGrammar.IsZero(drs.CurrentHead.Span) ||
            !CanonicalGrammar.FixedEquals(dpa.NetworkId.Span, drs.NetworkId.Span) ||
            !CanonicalGrammar.FixedEquals(account.DeepAccountIdHash.Span, drs.AccountHash.Span))
            Invalid("Offline DXP genesis requires one nonterminal generation-1 DPA1 and its exact empty revision-1 DRS1.");

        var dpaRef = Reference(ArtifactType.Dpa1, dpa.CanonicalBytes.Span);
        var drsRef = Reference(ArtifactType.Drs1, drs.CanonicalBytes.Span);
        var source = new byte[180];
        var offset = 0;
        Put(dpa.NetworkId.Span); Put(account.DeepAccountIdHash.Span); Put(U64(1));
        Put(dpaRef); Put(U64(1)); Put(U64(0)); Put(drs.CurrentHead.Span); Put(drsRef);
        if (offset != source.Length) Invalid("The offline DXP source transcript length is invalid.");
        var identitySource = CanonicalGrammar.Sha256Domain(OfflineSourceDomain, source);

        var scope = new byte[94];
        dpa.NetworkId.Span.CopyTo(scope);
        account.DeepAccountIdHash.Span.CopyTo(scope.AsSpan(16));
        BinaryPrimitives.WriteUInt64BigEndian(scope.AsSpan(48, 8), 1);
        dpaRef.CopyTo(scope, 56);
        var issuanceScope = CanonicalGrammar.Sha256Domain(AccountDeviceScopeDomain, scope);
        return new DxpIdentityIssuanceSource(
            DxpIdentityIssuanceSourceKind.OfflineAccountDeviceGenesis,
            X25519PossessionRole.Device,
            dpa.NetworkId.Span,
            account.DeepAccountIdHash.Span,
            1,
            identitySource,
            issuanceScope,
            1,
            0,
            drs.CurrentHead.Span,
            drsRef);

        void Put(ReadOnlySpan<byte> value)
        {
            value.CopyTo(source.AsSpan(offset));
            offset += value.Length;
        }
    }

    internal static DxpIdentityIssuanceSource CreateCurrentCutoverRouter(
        CurrentCutoverRelative cutover)
    {
        ArgumentNullException.ThrowIfNull(cutover);
        var scope = new byte[90];
        cutover.TrustedNetwork.CopyTo(scope);
        cutover.TrustedResetId.CopyTo(scope.AsSpan(16));
        BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(48, 2),
            (ushort)cutover.ComponentKind);
        cutover.TrustedAccountHash.CopyTo(scope.AsSpan(50));
        BinaryPrimitives.WriteUInt64BigEndian(scope.AsSpan(82, 8),
            cutover.AccountGeneration);
        return new DxpIdentityIssuanceSource(
            DxpIdentityIssuanceSourceKind.CurrentCutoverRouter,
            X25519PossessionRole.Router,
            cutover.TrustedNetwork,
            cutover.TrustedAccountHash,
            cutover.AccountGeneration,
            cutover.SourceFingerprint.Span,
            CanonicalGrammar.Sha256Domain(CutoverScopeDomain, scope),
            cutover.DrsRevision,
            cutover.DrsCount,
            cutover.TrustedDrsHead,
            cutover.TrustedDrsRef);
    }

    private static byte[] Reference(ArtifactType type, ReadOnlySpan<byte> canonical) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, canonical));

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidTransition, message);
}

/// <summary>A derived durable nonce-ledger selector with no key material.</summary>
internal sealed class DxpNonceLedgerBinding
{
    private readonly byte[] _ledgerKey;
    private readonly byte[] _indexKeyId;

    internal DxpNonceLedgerBinding(ReadOnlySpan<byte> ledgerKey32, ReadOnlySpan<byte> indexKeyId32)
    {
        _ledgerKey = ledgerKey32.ToArray();
        _indexKeyId = indexKeyId32.ToArray();
    }

    internal ReadOnlyMemory<byte> LedgerKey => _ledgerKey.ToArray();
    internal ReadOnlyMemory<byte> IndexKeyId => _indexKeyId.ToArray();
    internal bool NoAuthorityClaim => true;
}

/// <summary>Derives restart-stable nonce selectors from one sealed issuance scope.</summary>
internal sealed class DxpNonceLedgerVerifier
{
    private const string LedgerDomain = "Deep/ProtectedState/V2/DXP1-nonce-ledger-key";
    private const string IndexKeyIdDomain = "Deep/ProtectedState/V2/DXP1-nonce-index-key-id";

    internal DxpNonceLedgerBinding Derive(
        DxpIdentityIssuanceSource source,
        ReadOnlySpan<byte> nonce32,
        ReadOnlySpan<byte> nonceIndexKey32)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (nonce32.Length != 32 || nonceIndexKey32.Length != 32 ||
            CanonicalGrammar.IsZero(nonce32) || CanonicalGrammar.IsZero(nonceIndexKey32))
            throw new RecordException(RecordError.InvalidField,
                "The DXP nonce-ledger input is malformed.");

        var domain = Encoding.ASCII.GetBytes(LedgerDomain);
        var ledgerInput = new byte[2 + domain.Length + 1 + 16 + 32 + 1 + 32];
        BinaryPrimitives.WriteUInt16BigEndian(ledgerInput, checked((ushort)domain.Length));
        domain.CopyTo(ledgerInput, 2);
        var offset = 2 + domain.Length;
        ledgerInput[offset++] = (byte)source.Kind;
        source.Network.CopyTo(ledgerInput.AsSpan(offset)); offset += 16;
        source.TrustedIssuanceScope.CopyTo(ledgerInput.AsSpan(offset)); offset += 32;
        ledgerInput[offset++] = (byte)source.Role;
        nonce32.CopyTo(ledgerInput.AsSpan(offset));
        var ledgerKey = HMACSHA256.HashData(nonceIndexKey32, ledgerInput);

        var idInput = new byte[1 + 16 + 32 + 32];
        try
        {
            idInput[0] = (byte)source.Kind;
            source.Network.CopyTo(idInput.AsSpan(1));
            source.TrustedIssuanceScope.CopyTo(idInput.AsSpan(17));
            nonceIndexKey32.CopyTo(idInput.AsSpan(49));
            var keyId = CanonicalGrammar.Sha256Domain(IndexKeyIdDomain, idInput);
            try
            {
                return new DxpNonceLedgerBinding(ledgerKey, keyId);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyId);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(idInput);
        }
    }
}
