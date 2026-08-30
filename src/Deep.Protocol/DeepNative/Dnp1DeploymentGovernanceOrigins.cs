using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// Sealed provider lookup for one immutable deployment-governance epoch. The index is a
/// non-authority digest; callers cannot construct or cross-feed one.
/// </summary>
public sealed class DeploymentGovernanceRequest
{
    private readonly byte[] _environmentIndex;

    internal DeploymentGovernanceRequest(ReadOnlySpan<byte> environmentIndex)
    {
        _environmentIndex = environmentIndex.ToArray();
    }

    public ReadOnlyMemory<byte> EnvironmentIndex => _environmentIndex.ToArray();
    public bool NoAuthorityClaim => true;
}

/// <summary>Defensively-owned untrusted DGO1/DGI1 provider bytes.</summary>
public sealed class DeploymentGovernanceReadResult
{
    private readonly byte[] _dgo;
    private readonly byte[] _dgi;

    public DeploymentGovernanceReadResult(
        ReadOnlyMemory<byte> exactDgo282,
        ReadOnlyMemory<byte> exactDgi160,
        bool sourceHealthy)
    {
        _dgo = exactDgo282.ToArray();
        _dgi = exactDgi160.ToArray();
        SourceHealthy = sourceHealthy;
    }

    public ReadOnlyMemory<byte> ExactDgo => _dgo.ToArray();
    public ReadOnlyMemory<byte> ExactDgi => _dgi.ToArray();
    public bool SourceHealthy { get; }
    public bool NoAuthorityClaim => true;
}

/// <summary>
/// Consumer-owned immutable governance source boundary. RestoreOrCreate is the one durable
/// mutation boundary: the stable environment index selects one retained DGO/DGI/source tuple,
/// exact replay returns it byte-identically, and a changed tuple at that index permanently
/// fork-latches. Read is a fresh nonmutating reread of that same retained tuple.
/// </summary>
public abstract class DeploymentGovernanceProvider
{
    public abstract ValueTask<DeploymentGovernanceReadResult> RestoreOrCreateAsync(
        DeploymentGovernanceRequest request,
        CancellationToken cancellationToken);

    public abstract ValueTask<DeploymentGovernanceReadResult> ReadAsync(
        DeploymentGovernanceRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// HMAC- and signature-bound deployment governance context. It carries no mutation,
/// publication, signing, or deployment authority.
/// </summary>
public sealed class VerifiedDeploymentGovernanceContext
{
    private readonly byte[] _dgo;
    private readonly byte[] _dgi;
    private readonly byte[] _governanceHash;
    private readonly byte[] _environmentIndex;

    internal VerifiedDeploymentGovernanceContext(
        ReleaseRootRelativeFact releaseRoot,
        ReadOnlySpan<byte> dgo,
        ReadOnlySpan<byte> dgi,
        ReadOnlySpan<byte> governanceHash,
        ReadOnlySpan<byte> environmentIndex)
    {
        ReleaseRoot = releaseRoot;
        _dgo = dgo.ToArray();
        _dgi = dgi.ToArray();
        _governanceHash = governanceHash.ToArray();
        _environmentIndex = environmentIndex.ToArray();
    }

    public ReleaseRootRelativeFact ReleaseRoot { get; }
    public ReadOnlyMemory<byte> DeploymentGovernanceBootstrapHash => _governanceHash.ToArray();
    public ReadOnlyMemory<byte> EnvironmentIndex => _environmentIndex.ToArray();
    public ulong SourceRevision => BinaryPrimitives.ReadUInt64BigEndian(_dgi.AsSpan(78, 8));
    public ulong RetainUntilUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(_dgi.AsSpan(86, 8));
    public bool NoAuthorityClaim => true;

    internal ReadOnlySpan<byte> ExactDgo => _dgo;
    internal ReadOnlySpan<byte> ExactDgi => _dgi;
    internal ReadOnlySpan<byte> Network => _dgo.AsSpan(8, 16);
    internal ulong ActivationAtUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(_dgo.AsSpan(64, 8));
    internal ReadOnlySpan<byte> ComponentSchemaRows => _dgo.AsSpan(82, 168);
}

internal sealed record VerifiedDeploymentGovernanceRelative(
    ReleaseRootRelativeFact ReleaseRoot,
    byte[] ExactDgo,
    byte[] DgoHash,
    byte[] RrmReference,
    byte[] GovernanceHash,
    byte[] EnvironmentIndex);

public static class DeploymentGovernanceVerifier
{
    public static async ValueTask<VerifiedDeploymentGovernanceContext>
        RestoreDeploymentGovernanceAsync(
            ReleaseRootRelativeFact releaseRoot,
            DeploymentGovernanceProvider provider,
            IProtectedHmacProvider hmacProvider,
            ulong transactionTimeUnixSeconds,
            CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(releaseRoot);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();

        var rrm = releaseRoot.Manifest.Record;
        var environmentIndex = DeploymentGovernanceRecords.EnvironmentIndex(
            rrm.FieldSpan(1), rrm.FieldSpan(3), rrm.FieldSpan(9));
        var request = new DeploymentGovernanceRequest(environmentIndex);
        var first = await provider.RestoreOrCreateAsync(request, cancellationToken)
            .ConfigureAwait(false);
        var context = await VerifyAsync(releaseRoot, first, hmacProvider,
            transactionTimeUnixSeconds, cancellationToken).ConfigureAwait(false);
        var second = await provider.ReadAsync(request, cancellationToken).ConfigureAwait(false);
        if (!second.SourceHealthy ||
            !CanonicalGrammar.FixedEquals(first.ExactDgo.Span, second.ExactDgo.Span) ||
            !CanonicalGrammar.FixedEquals(first.ExactDgi.Span, second.ExactDgi.Span))
            throw new RecordException(RecordError.InvalidField,
                "Deployment governance moved during verification.");
        return context;
    }

    private static async ValueTask<VerifiedDeploymentGovernanceContext> VerifyAsync(
        ReleaseRootRelativeFact releaseRoot,
        DeploymentGovernanceReadResult result,
        IProtectedHmacProvider hmacProvider,
        ulong transactionTimeUnixSeconds,
        CancellationToken cancellationToken)
    {
        if (!result.SourceHealthy)
            throw new RecordException(RecordError.InvalidField,
                "The deployment-governance source is unhealthy.");
        var dgo = result.ExactDgo.ToArray();
        var dgi = result.ExactDgi.ToArray();
        try
        {
            var relative = VerifyRelative(releaseRoot, dgo);
            DeploymentGovernanceRecords.PreflightDgi(dgi, transactionTimeUnixSeconds);
            Equal(dgi.AsSpan(8, 38), relative.RrmReference, "DGI1 RRM reference");
            Equal(dgi.AsSpan(46, 32), relative.DgoHash, "DGI1 DGO hash");
            await GenesisProtectedRecords.VerifyAsync("Deep/ProtectedState/V1/DGI1",
                dgi, 96, hmacProvider, cancellationToken).ConfigureAwait(false);
            return new VerifiedDeploymentGovernanceContext(
                releaseRoot, dgo, dgi, relative.GovernanceHash, relative.EnvironmentIndex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dgo);
            CryptographicOperations.ZeroMemory(dgi);
        }
    }

    internal static VerifiedDeploymentGovernanceRelative VerifyRelative(
        ReleaseRootRelativeFact releaseRoot,
        ReadOnlySpan<byte> exactDgo282)
    {
        ArgumentNullException.ThrowIfNull(releaseRoot);
        DeploymentGovernanceRecords.PreflightDgo(exactDgo282);
        var rrm = releaseRoot.Manifest.Record;
        Equal(exactDgo282.Slice(8, 16), rrm.FieldSpan(1), "DGO1 network");
        Equal(exactDgo282.Slice(24, 8), rrm.FieldSpan(2), "DGO1 manifest generation");
        Equal(exactDgo282.Slice(32, 32), rrm.FieldSpan(3), "DGO1 environment reset ID");
        Equal(exactDgo282.Slice(64, 8), rrm.FieldSpan(6), "DGO1 activation time");
        Equal(exactDgo282.Slice(72, 8), rrm.FieldSpan(7), "DGO1 component mask");
        Equal(exactDgo282.Slice(250, 32),
            releaseRoot.Pin.ManifestSignerEd25519PublicKey.Span,
            "DGO1 manifest signer public key");
        Equal(CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V1/release-manifest-key-id", exactDgo282.Slice(250, 32)),
            rrm.FieldSpan(9), "DGO1 signer key ID");
        var dgoHash = DeploymentGovernanceRecords.DgoHash(exactDgo282);
        Equal(dgoHash, rrm.FieldSpan(8), "DGO1 signed schema fingerprint");
        var rrmRef = CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
            ArtifactType.Rrm1, rrm.CanonicalSpan));
        var governanceHash = DeploymentGovernanceRecords.BootstrapHash(
            exactDgo282, rrm.FieldSpan(9), dgoHash, rrmRef);
        var environmentIndex = DeploymentGovernanceRecords.EnvironmentIndex(
            rrm.FieldSpan(1), rrm.FieldSpan(3), rrm.FieldSpan(9));
        return new VerifiedDeploymentGovernanceRelative(
            releaseRoot, exactDgo282.ToArray(), dgoHash, rrmRef, governanceHash, environmentIndex);
    }

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string name)
    {
        if (!CanonicalGrammar.FixedEquals(actual, expected))
            throw new RecordException(RecordError.InvalidField, $"{name} differs from signed RRM1.");
    }
}

internal static class DeploymentGovernanceRecords
{
    internal const int DgoLength = 282;
    internal const int DgiLength = 160;
    internal const int GarLength = 742;
    internal const int GdiLength = 1031;
    internal const int GraLength = 980;
    internal const int GmdLength = 447;

    internal const int GarKeyOffset = 678;
    internal const int GdiKeyOffset = 967;
    internal const int GraKeyOffset = 916;
    internal const int GmdKeyOffset = 383;

    internal static void PreflightDgo(ReadOnlySpan<byte> value)
    {
        Header(value, DgoLength, ProtocolMagicBytes.DGO1);
        Nonzero(value.Slice(8, 16), "DGO1 network");
        Positive(value.Slice(32, 32), "DGO1 environment reset ID");
        PositiveU64(value.Slice(64, 8), "DGO1 activation time");
        if (BinaryPrimitives.ReadUInt64BigEndian(value.Slice(72, 8)) != 15 ||
            BinaryPrimitives.ReadUInt16BigEndian(value.Slice(80, 2)) != 4)
            Invalid("DGO1 component mask or count is invalid.");
        for (var index = 0; index < 4; index++)
        {
            var row = value.Slice(82 + index * 42, 42);
            if (BinaryPrimitives.ReadUInt16BigEndian(row[..2]) != index + 1 ||
                BinaryPrimitives.ReadUInt64BigEndian(row.Slice(2, 8)) == 0 ||
                CanonicalGrammar.IsZero(row.Slice(10, 32)))
                Invalid("DGO1 schema rows are not exact kinds 1 through 4.");
        }
        Positive(value.Slice(250, 32), "DGO1 manifest signer public key");
    }

    internal static void PreflightDgi(ReadOnlySpan<byte> value, ulong transactionTimeUnixSeconds)
    {
        Header(value, DgiLength, ProtocolMagicBytes.DGI1);
        Reference(value.Slice(8, 38), ArtifactType.Rrm1, 332, "DGI1 RRM");
        Positive(value.Slice(46, 32), "DGI1 DGO hash");
        PositiveU64(value.Slice(78, 8), "DGI1 source revision");
        var retainUntil = BinaryPrimitives.ReadUInt64BigEndian(value.Slice(86, 8));
        if (retainUntil == 0 || retainUntil <= transactionTimeUnixSeconds ||
            value[94] != 1 || value[95] != 0)
            Invalid("DGI1 retention, state, or fork latch is invalid.");
        Positive(value.Slice(96, 32), "DGI1 protected key ID");
    }

    internal static void PreflightGar(ReadOnlySpan<byte> value, ulong transactionTimeUnixSeconds)
    {
        Header(value, GarLength, ProtocolMagicBytes.GAR1);
        Positive(value.Slice(8, 588), "GAR1 verified reset transcript");
        var originHash = HashU16("Deep/Cutover/V10/account-reset-origin", value.Slice(8, 588));
        if (!CanonicalGrammar.FixedEquals(value.Slice(596, 32), originHash))
            Invalid("GAR1 account-reset origin hash is invalid.");
        Positive(value.Slice(628, 32), "GAR1 operation ID");
        PositiveU64(value.Slice(660, 8), "GAR1 source revision");
        Retained(value, 668, 676, 677, transactionTimeUnixSeconds, ProtocolMagic.GAR1);
        Positive(value.Slice(GarKeyOffset, 32), "GAR1 protected key ID");
    }

    internal static void PreflightGdi(ReadOnlySpan<byte> value, ulong transactionTimeUnixSeconds)
    {
        Header(value, GdiLength, ProtocolMagicBytes.GDI1);
        var branch = Branch(value[8], value.Slice(9, 32), ProtocolMagic.GDI1);
        var reservation = value.Slice(41, 32);
        if (branch == 2 ? !CanonicalGrammar.IsZero(reservation) : CanonicalGrammar.IsZero(reservation))
            Invalid("GDI1 reservation shape is invalid for its branch.");

        var dcm = CanonicalGrammar.DecodeOwned(value.Slice(73, 812), RecordDefinitions.Dcm1);
        PhaseSignatures(value[965], dcm.FieldSpan(18), dcm.FieldSpan(19), ProtocolMagic.GDI1);
        Positive(value.Slice(885, 32), "GDI1 governance hash");
        Positive(value.Slice(917, 32), "GDI1 operation ID");
        PositiveU64(value.Slice(949, 8), "GDI1 source revision");
        RetainedPhase(value, 957, 965, 966, transactionTimeUnixSeconds, ProtocolMagic.GDI1);
        Positive(value.Slice(GdiKeyOffset, 32), "GDI1 protected key ID");
    }

    internal static void PreflightGra(ReadOnlySpan<byte> value, ulong transactionTimeUnixSeconds)
    {
        Header(value, GraLength, ProtocolMagicBytes.GRA1);
        Positive(value.Slice(8, 32), "GRA1 GAR receipt hash");
        Reference(value.Slice(40, 38), ArtifactType.Dcm1, 812, "GRA1 new DCM");
        var dra = CanonicalGrammar.DecodeOwned(value.Slice(78, 788), RecordDefinitions.Dra1);
        PhaseSignatures(value[914], dra.FieldSpan(19), dra.FieldSpan(20), dra.FieldSpan(21), ProtocolMagic.GRA1);
        Positive(value.Slice(866, 32), "GRA1 operation ID");
        PositiveU64(value.Slice(898, 8), "GRA1 source revision");
        RetainedPhase(value, 906, 914, 915, transactionTimeUnixSeconds, ProtocolMagic.GRA1);
        Positive(value.Slice(GraKeyOffset, 32), "GRA1 protected key ID");
    }

    internal static void PreflightGmd(ReadOnlySpan<byte> value, ulong transactionTimeUnixSeconds)
    {
        Header(value, GmdLength, ProtocolMagicBytes.GMD1);
        var branch = Branch(value[8], value.Slice(9, 32), ProtocolMagic.GMD1);
        Positive(value.Slice(41, 32), "GMD1 author-set hash");
        PositiveU64(value.Slice(73, 8), "GMD1 account generation");
        Positive(value.Slice(81, 32), "GMD1 account hash");
        Positive(value.Slice(113, 32), "GMD1 reset ID");
        PositiveU64(value.Slice(145, 8), "GMD1 reset generation");
        Reference(value.Slice(153, 38), ArtifactType.Dcm1, 812, "GMD1 DCM");

        var predecessor = value.Slice(191, 38);
        var dra = value.Slice(229, 38);
        if (branch == 2)
            Reference(predecessor, ArtifactType.Dcm1, 812, "GMD1 predecessor DCM");
        else
            Zero(predecessor, "GMD1 predecessor DCM");
        if (branch == 3)
            Reference(dra, ArtifactType.Dra1, 788, "GMD1 DRA");
        else
            Zero(dra, "GMD1 DRA");

        Positive(value.Slice(267, 32), "GMD1 governance hash");
        if (value[299] != 4 || (value[300] & 0xf0) != 0)
            Invalid("GMD1 component count or delivery bitmap is invalid.");
        var bitmap = value[300];
        for (var index = 0; index < 4; index++)
        {
            var revision = BinaryPrimitives.ReadUInt64BigEndian(value.Slice(301 + index * 8, 8));
            if (((bitmap >> index) & 1) == 0 ? revision != 0 : revision == 0)
                Invalid("GMD1 delivery bitmap and component revision differ.");
        }
        Positive(value.Slice(333, 32), "GMD1 operation ID");
        PositiveU64(value.Slice(365, 8), "GMD1 source revision");
        var retainUntil = BinaryPrimitives.ReadUInt64BigEndian(value.Slice(373, 8));
        var phase = value[381];
        if (retainUntil == 0 || retainUntil <= transactionTimeUnixSeconds ||
            phase is not (1 or 2) || value[382] != 0 || (phase == 2 && bitmap != 0x0f))
            Invalid("GMD1 retention, phase, bitmap, or fork latch is invalid.");
        Positive(value.Slice(GmdKeyOffset, 32), "GMD1 protected key ID");
    }

    internal static byte[] DgoHash(ReadOnlySpan<byte> dgo) => HashU16(
        "Deep/Cutover/V10/deployment-governance-origin", dgo);

    internal static byte[] BranchHash(byte branchKind, ReadOnlySpan<byte> exactBranch)
    {
        var expectedLength = branchKind switch { 1 => 197, 2 => 203, 3 => 65, _ => 0 };
        if (expectedLength == 0 || exactBranch.Length != expectedLength || exactBranch[0] != branchKind)
            Invalid("The cutover branch transcript is invalid.");
        var domain = branchKind switch
        {
            1 => "Deep/Cutover/V10/first-deployment-cutover-branch",
            2 => "Deep/Cutover/V10/same-account-cutover-branch",
            _ => "Deep/Cutover/V10/account-reset-cutover-branch"
        };
        return HashU16(domain, exactBranch);
    }

    internal static byte[] GarReceiptHash(ReadOnlySpan<byte> gar) => HashU32(
        "Deep/Cutover/V10/account-reset-origin-receipt", gar, GarLength);

    internal static byte[] SignedGdiHash(ReadOnlySpan<byte> gdi) => HashU32(
        "Deep/Cutover/V10/genesis-dcm-authoring-record", gdi, GdiLength);

    internal static byte[] SignedGraHash(ReadOnlySpan<byte> gra) => HashU32(
        "Deep/Cutover/V10/genesis-reset-authoring-record", gra, GraLength);

    internal static byte[] AuthorSetHash(byte branchKind, ReadOnlySpan<byte> signedGdiHash,
        ReadOnlySpan<byte> signedGraHashOrZero)
    {
        if (branchKind is < 1 or > 3 || signedGdiHash.Length != 32 ||
            signedGraHashOrZero.Length != 32 || CanonicalGrammar.IsZero(signedGdiHash) ||
            (branchKind == 3 ? CanonicalGrammar.IsZero(signedGraHashOrZero) :
                !CanonicalGrammar.IsZero(signedGraHashOrZero)))
            Invalid("The genesis author-set transcript is invalid.");
        Span<byte> transcript = stackalloc byte[65];
        transcript[0] = branchKind;
        signedGdiHash.CopyTo(transcript[1..]);
        signedGraHashOrZero.CopyTo(transcript[33..]);
        return HashU16("Deep/Cutover/V10/genesis-author-set", transcript);
    }

    internal static byte[] BootstrapHash(
        ReadOnlySpan<byte> dgo,
        ReadOnlySpan<byte> signerKeyId,
        ReadOnlySpan<byte> dgoHash,
        ReadOnlySpan<byte> rrmRef)
    {
        Span<byte> payload = stackalloc byte[166];
        dgo.Slice(8, 16).CopyTo(payload);
        dgo.Slice(32, 32).CopyTo(payload[16..]);
        signerKeyId.CopyTo(payload[48..]);
        dgo.Slice(24, 8).CopyTo(payload[80..]);
        dgo.Slice(72, 8).CopyTo(payload[88..]);
        dgoHash.CopyTo(payload[96..]);
        rrmRef.CopyTo(payload[128..]);
        return HashU16("Deep/Cutover/V10/deployment-governance-bootstrap", payload);
    }

    internal static byte[] EnvironmentIndex(
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> environmentResetId,
        ReadOnlySpan<byte> signerKeyId)
    {
        Span<byte> payload = stackalloc byte[80];
        network.CopyTo(payload);
        environmentResetId.CopyTo(payload[16..]);
        signerKeyId.CopyTo(payload[48..]);
        return CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V10/deployment-governance-environment-index", payload);
    }

    internal static byte[] HashU16(string domain, ReadOnlySpan<byte> value)
    {
        var payload = new byte[checked(2 + value.Length)];
        BinaryPrimitives.WriteUInt16BigEndian(payload, checked((ushort)value.Length));
        value.CopyTo(payload.AsSpan(2));
        return CanonicalGrammar.Sha256Domain(domain, payload);
    }

    internal static byte[] HashU32(string domain, ReadOnlySpan<byte> value, int exactLength)
    {
        if (value.Length != exactLength) Invalid("A protected origin record length is invalid.");
        var payload = new byte[checked(4 + value.Length)];
        BinaryPrimitives.WriteUInt32BigEndian(payload, checked((uint)value.Length));
        value.CopyTo(payload.AsSpan(4));
        return CanonicalGrammar.Sha256Domain(domain, payload);
    }

    private static byte Branch(byte branch, ReadOnlySpan<byte> hash, string name)
    {
        if (branch is < 1 or > 3 || CanonicalGrammar.IsZero(hash))
            Invalid($"{name} branch kind or hash is invalid.");
        return branch;
    }

    private static void PhaseSignatures(byte phase, ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second, string name)
    {
        if (phase == 1)
        {
            if (!CanonicalGrammar.IsZero(first) || !CanonicalGrammar.IsZero(second))
                Invalid($"Prepared {name} contains a signature.");
        }
        else if (phase == 2)
        {
            if (CanonicalGrammar.IsZero(first) || CanonicalGrammar.IsZero(second))
                Invalid($"Signed {name} has an absent signature.");
        }
        else Invalid($"{name} phase is invalid.");
    }

    private static void PhaseSignatures(byte phase, ReadOnlySpan<byte> first,
        ReadOnlySpan<byte> second, ReadOnlySpan<byte> third, string name)
    {
        if (phase == 1)
        {
            if (!CanonicalGrammar.IsZero(first) || !CanonicalGrammar.IsZero(second) ||
                !CanonicalGrammar.IsZero(third))
                Invalid($"Prepared {name} contains a signature.");
        }
        else if (phase == 2)
        {
            if (CanonicalGrammar.IsZero(first) || CanonicalGrammar.IsZero(second) ||
                CanonicalGrammar.IsZero(third))
                Invalid($"Signed {name} has an absent signature.");
        }
        else Invalid($"{name} phase is invalid.");
    }

    private static void Retained(ReadOnlySpan<byte> value, int retainOffset, int stateOffset,
        int forkOffset, ulong transactionTimeUnixSeconds, string name)
    {
        var retainUntil = BinaryPrimitives.ReadUInt64BigEndian(value.Slice(retainOffset, 8));
        if (retainUntil == 0 || retainUntil <= transactionTimeUnixSeconds ||
            value[stateOffset] != 1 || value[forkOffset] != 0)
            Invalid($"{name} retention, state, or fork latch is invalid.");
    }

    private static void RetainedPhase(ReadOnlySpan<byte> value, int retainOffset,
        int phaseOffset, int forkOffset, ulong transactionTimeUnixSeconds, string name)
    {
        var retainUntil = BinaryPrimitives.ReadUInt64BigEndian(value.Slice(retainOffset, 8));
        if (retainUntil == 0 || retainUntil <= transactionTimeUnixSeconds ||
            value[phaseOffset] is not (1 or 2) || value[forkOffset] != 0)
            Invalid($"{name} retention, phase, or fork latch is invalid.");
    }

    private static void Header(ReadOnlySpan<byte> value, int length, ReadOnlySpan<byte> magic)
    {
        if (value.Length != length || !value[..4].SequenceEqual(magic) || value[4] != 1 ||
            value.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            Invalid("A deployment-governance record header is invalid.");
    }

    private static void Reference(
        ReadOnlySpan<byte> value,
        ArtifactType type,
        int length,
        string name)
    {
        var reference = CanonicalGrammar.DecodeReference(value);
        if (reference.Type != type || reference.CanonicalLength != length)
            Invalid($"{name} reference is invalid.");
    }

    private static void Positive(ReadOnlySpan<byte> value, string name)
    {
        if (CanonicalGrammar.IsZero(value)) Invalid($"{name} is zero.");
    }

    private static void Nonzero(ReadOnlySpan<byte> value, string name) => Positive(value, name);

    private static void PositiveU64(ReadOnlySpan<byte> value, string name)
    {
        if (BinaryPrimitives.ReadUInt64BigEndian(value) == 0) Invalid($"{name} is zero.");
    }

    private static void Zero(ReadOnlySpan<byte> value, string name)
    {
        if (!CanonicalGrammar.IsZero(value)) Invalid($"{name} is not zero.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
