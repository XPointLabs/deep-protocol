using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

public sealed class XPointNetworkForwardCheckpointVerificationException : FormatException
{
    internal XPointNetworkForwardCheckpointVerificationException(
        string code,
        string message,
        Exception? inner = null) : base(message, inner) => Code = code;

    public string Code { get; }
}

/// <summary>
/// A caller-protected release checkpoint or last-known-good network tuple.
/// Construction validates shape only; the caller remains responsible for
/// authenticating and protecting these bytes before supplying them here.
/// </summary>
public sealed class XPointNetworkProtectedLkg
{
    private readonly byte[] networkId;
    private readonly byte[] headCoreReference;
    private readonly byte[] headRoot;
    private readonly byte[] viewCoreReference;
    private readonly byte[] authorityCoreReference;
    private readonly byte[]? lastForwardCheckpointCoreReference;

    public XPointNetworkProtectedLkg(
        ReadOnlyMemory<byte> networkId,
        ReadOnlyMemory<byte> headCoreReference,
        ulong headTreeSize,
        ReadOnlyMemory<byte> headRoot,
        ReadOnlyMemory<byte> viewCoreReference,
        ulong viewGeneration,
        ReadOnlyMemory<byte> authorityCoreReference,
        ReadOnlyMemory<byte> lastForwardCheckpointCoreReference = default,
        ulong? lastForwardCheckpointGeneration = null)
    {
        this.networkId = RequiredBytes(networkId, 16, nameof(networkId));
        this.headCoreReference = RequiredReference(headCoreReference, ProtocolMagic.XNH1, nameof(headCoreReference));
        if (headTreeSize == 0) throw new ArgumentOutOfRangeException(nameof(headTreeSize));
        if (viewGeneration == ulong.MaxValue || headTreeSize != viewGeneration + 1)
            throw new ArgumentException(
                "The protected XNH1 tree size must equal the protected XNV1 generation plus one.",
                nameof(headTreeSize));
        HeadTreeSize = headTreeSize;
        this.headRoot = RequiredBytes(headRoot, 32, nameof(headRoot));
        this.viewCoreReference = RequiredReference(viewCoreReference, ProtocolMagic.XNV1, nameof(viewCoreReference));
        ViewGeneration = viewGeneration;
        this.authorityCoreReference = RequiredReference(authorityCoreReference, ProtocolMagic.XNA1, nameof(authorityCoreReference));

        if (lastForwardCheckpointCoreReference.IsEmpty != !lastForwardCheckpointGeneration.HasValue)
            throw new ArgumentException(
                "The protected XNF1 reference and generation must either both be present or both be absent.",
                nameof(lastForwardCheckpointCoreReference));
        if (!lastForwardCheckpointCoreReference.IsEmpty)
        {
            this.lastForwardCheckpointCoreReference = RequiredReference(
                lastForwardCheckpointCoreReference, ProtocolMagic.XNF1, nameof(lastForwardCheckpointCoreReference));
            LastForwardCheckpointGeneration = lastForwardCheckpointGeneration;
        }
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> HeadCoreReference => headCoreReference.ToArray();
    public ulong HeadTreeSize { get; }
    public ReadOnlyMemory<byte> HeadRoot => headRoot.ToArray();
    public ReadOnlyMemory<byte> ViewCoreReference => viewCoreReference.ToArray();
    public ulong ViewGeneration { get; }
    public ReadOnlyMemory<byte> AuthorityCoreReference => authorityCoreReference.ToArray();
    public ReadOnlyMemory<byte> LastForwardCheckpointCoreReference =>
        lastForwardCheckpointCoreReference?.ToArray() ?? ReadOnlyMemory<byte>.Empty;
    public ulong? LastForwardCheckpointGeneration { get; }

    internal XPointProtectedNetworkLkg ToInternal() => new(
        new XPointBytes(networkId),
        XPointNetworkCodec.DecodeCoreReference(headCoreReference),
        HeadTreeSize,
        new XPointBytes(headRoot),
        XPointNetworkCodec.DecodeCoreReference(viewCoreReference),
        ViewGeneration,
        XPointNetworkCodec.DecodeCoreReference(authorityCoreReference));

    private static byte[] RequiredBytes(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }

    private static byte[] RequiredReference(ReadOnlyMemory<byte> value, string magic, string name)
    {
        if (value.Length != XPointCoreReference.Length ||
            !value.Span[..4].SequenceEqual(System.Text.Encoding.ASCII.GetBytes(magic)) ||
            BinaryPrimitives.ReadUInt16BigEndian(value.Span[4..6]) != 1 ||
            value.Span[6..].IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be an exact non-zero {magic} version-1 core reference.", name);
        return value.ToArray();
    }
}

/// <summary>
/// Non-forgeable result of validating one bounded NFP1/XNF1 reset package.
/// It advances network trust only; it does not authorize routes, PMT2 state,
/// mailbox operations, or retained content by itself.
/// </summary>
public sealed class VerifiedXPointNetworkForwardCheckpoint
{
    private readonly byte[] exactNfp1;
    private readonly byte[][] exactXnf1Chain;
    private readonly byte[] exactTargetXnv1;
    private readonly byte[] exactTargetXnh1;
    private readonly byte[] targetViewCoreReference;
    private readonly byte[] targetHeadRoot;
    private readonly byte[] targetHeadCoreReference;
    private readonly byte[] terminalCheckpointCoreReference;
    private readonly byte[] dttCoreHash;

    internal VerifiedXPointNetworkForwardCheckpoint(
        byte[] exactNfp1,
        byte[][] exactXnf1Chain,
        Xnv1Record targetView,
        Xnh1Record targetHead,
        Xnf1Record terminalCheckpoint,
        XPointNetworkProtectedLkg priorProtectedLkg,
        XPointNetworkProtectedLkg nextProtectedLkg,
        OnionTrustedTimeLease trustedTime,
        ReadOnlySpan<byte> dttCoreHash,
        ulong validUntilUnixSeconds)
    {
        this.exactNfp1 = exactNfp1.ToArray();
        this.exactXnf1Chain = exactXnf1Chain.Select(static value => value.ToArray()).ToArray();
        exactTargetXnv1 = targetView.CanonicalCopy();
        exactTargetXnh1 = targetHead.CanonicalCopy();
        TargetViewGeneration = targetView.ViewGeneration;
        targetViewCoreReference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, targetView.CoreHash.Span);
        TargetHeadTreeSize = targetHead.TreeSize;
        targetHeadRoot = targetHead.Root.ToArray();
        targetHeadCoreReference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNH1, targetHead.CoreHash.Span);
        TerminalCheckpointGeneration = terminalCheckpoint.CheckpointGeneration;
        terminalCheckpointCoreReference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNF1, terminalCheckpoint.CoreHash.Span);
        this.dttCoreHash = dttCoreHash.ToArray();
        PriorProtectedLkg = Copy(priorProtectedLkg);
        NextProtectedLkg = Copy(nextProtectedLkg);
        TrustedTime = trustedTime;
        ValidUntilUnixSeconds = validUntilUnixSeconds;
    }

    public ReadOnlyMemory<byte> ExactNfp1 => exactNfp1.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> ExactOrderedXnf1Chain => Array.AsReadOnly(
        exactXnf1Chain.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
    public ReadOnlyMemory<byte> ExactTargetXnv1 => exactTargetXnv1.ToArray();
    public ReadOnlyMemory<byte> ExactTargetXnh1 => exactTargetXnh1.ToArray();
    public ulong TargetViewGeneration { get; }
    public ReadOnlyMemory<byte> TargetViewCoreReference => targetViewCoreReference.ToArray();
    public ulong TargetHeadTreeSize { get; }
    public ReadOnlyMemory<byte> TargetHeadRoot => targetHeadRoot.ToArray();
    public ReadOnlyMemory<byte> TargetHeadCoreReference => targetHeadCoreReference.ToArray();
    public ulong TerminalCheckpointGeneration { get; }
    public ReadOnlyMemory<byte> TerminalCheckpointCoreReference => terminalCheckpointCoreReference.ToArray();
    public ulong ValidUntilUnixSeconds { get; }
    public XPointNetworkProtectedLkg PriorProtectedLkg { get; }
    public XPointNetworkProtectedLkg NextProtectedLkg { get; }

    public void EnsureCurrent() => TrustedTime.EnsureLive();

    internal OnionTrustedTimeLease TrustedTime { get; }

    private static XPointNetworkProtectedLkg Copy(XPointNetworkProtectedLkg value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new XPointNetworkProtectedLkg(
            value.NetworkId,
            value.HeadCoreReference,
            value.HeadTreeSize,
            value.HeadRoot,
            value.ViewCoreReference,
            value.ViewGeneration,
            value.AuthorityCoreReference,
            value.LastForwardCheckpointCoreReference,
            value.LastForwardCheckpointGeneration);
    }

    internal void EnsureUsable(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness freshness)
    {
        TrustedTime.EnsureLive();
        if (!CryptographicOperations.FixedTimeEquals(NextProtectedLkg.NetworkId.Span, authority.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(
                NextProtectedLkg.AuthorityCoreReference.Span, authority.AuthorityCoreReference.Span) ||
            !CryptographicOperations.FixedTimeEquals(freshness.NetworkId.Span, authority.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(freshness.ExactDtt1CoreHash.Span, dttCoreHash))
            throw new XPointNetworkForwardCheckpointVerificationException(
                "forward-capability-mismatch",
                "The forward checkpoint capability is not bound to this exact authority and live DTT1.");
    }
}

public static class XPointNetworkForwardCheckpointVerifier
{
    private const int MaximumChainCount = 64;
    private const int MaximumPackageBytes = 560 * 1024;

    public static async ValueTask<VerifiedXPointNetworkForwardCheckpoint> VerifyAsync(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness trustedFreshness,
        XPointNetworkProtectedLkg protectedLkg,
        IReadOnlyList<ReadOnlyMemory<byte>> exactXna1AuthorityChain,
        IReadOnlyList<ReadOnlyMemory<byte>> exactOrderedXnf1Chain,
        ReadOnlyMemory<byte> exactNfp1,
        ReadOnlyMemory<byte> exactTargetXnv1,
        ReadOnlyMemory<byte> exactTargetXnh1,
        OnionTrustedTimeAuthority trustedTimeAuthority,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(trustedFreshness);
        ArgumentNullException.ThrowIfNull(protectedLkg);
        ArgumentNullException.ThrowIfNull(exactXna1AuthorityChain);
        ArgumentNullException.ThrowIfNull(exactOrderedXnf1Chain);
        ArgumentNullException.ThrowIfNull(trustedTimeAuthority);
        cancellationToken.ThrowIfCancellationRequested();

        var authorityBytes = OwnChain(exactXna1AuthorityChain, XPointNetworkRegistry.Xna1, ProtocolMagic.XNA1);
        var checkpointBytes = OwnChain(exactOrderedXnf1Chain, XPointNetworkRegistry.Xnf1, ProtocolMagic.XNF1);
        var nfpBytes = Own(exactNfp1, XPointNetworkRegistry.Nfp1, ProtocolMagic.NFP1);
        var viewBytes = Own(exactTargetXnv1, XPointNetworkRegistry.Xnv1, ProtocolMagic.XNV1);
        var headBytes = Own(exactTargetXnh1, XPointNetworkRegistry.Xnh1, ProtocolMagic.XNH1);
        var dttBytes = trustedFreshness.ExactDtt1.ToArray();
        var total = authorityBytes.Sum(static value => (long)value.Length) +
            checkpointBytes.Sum(static value => (long)value.Length) + nfpBytes.Length +
            viewBytes.Length + headBytes.Length + dttBytes.Length;
        if (total > MaximumPackageBytes)
            Fail("forward-package-too-large", "The exact reset package exceeds the 560 KiB verification budget.");

        try
        {
            var authorities = authorityBytes.Select(static value => XPointNetworkCodec.Parse<Xna1Record>(value)).ToArray();
            var checkpoints = checkpointBytes.Select(static value => XPointNetworkCodec.Parse<Xnf1Record>(value)).ToArray();
            var nfp = XPointNetworkCodec.Parse<Nfp1Record>(nfpBytes);
            var targetView = XPointNetworkCodec.Parse<Xnv1Record>(viewBytes);
            var targetHead = XPointNetworkCodec.Parse<Xnh1Record>(headBytes);
            var dtt = AccountDirectoryDtt1Codec.Decode(dttBytes);

            VerifyAuthorityChain(authority, authorities, nfp);
            VerifyReferenceList(nfp.FieldSpan(12), checkpoints, ProtocolMagic.XNF1, "checkpoint-chain-mismatch");
            VerifyDtt(authority, trustedFreshness, nfp, targetView, dtt, dttBytes);

            var resolver = new ForwardResolver(authorities, checkpoints, targetView, targetHead, dtt,
                trustedFreshness.ExactDtt1CoreHash.Span);
            var context = new XPointVerificationContext(
                resolver,
                SodiumVerifier.Instance,
                ProtectedLkg: protectedLkg.ToInternal());
            XPointNetworkVerifier.Verify(nfp, context);
            VerifyPriorCheckpoint(protectedLkg, checkpoints[0]);
            XPointNetworkVerifier.VerifyForwardTarget(targetView, targetHead, authorities[^1], context);

            var terminal = checkpoints[^1];
            if (!terminal.AuthorizingXna.Equals(authorities[^1].CoreReferenceValue))
                Fail("target-authority-mismatch", "The terminal XNF1 is not authorized by the terminal exact XNA1.");

            var hardUpper = new[]
            {
                authority.ExpiresAt,
                trustedFreshness.ExpiresAtUnixSeconds,
                targetView.ExpiresAt,
                targetHead.ValidUntil,
                dtt.ExpiresAt,
            }.Min();
            var trustedTime = await trustedTimeAuthority.MintAsync(
                trustedFreshness, hardUpper, cancellationToken).ConfigureAwait(false);

            var next = new XPointNetworkProtectedLkg(
                targetView.NetworkId.ToArray(),
                XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNH1, targetHead.CoreHash.Span),
                targetHead.TreeSize,
                targetHead.Root.ToArray(),
                XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNV1, targetView.CoreHash.Span),
                targetView.ViewGeneration,
                XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNA1, authorities[^1].CoreHash.Span),
                XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.XNF1, terminal.CoreHash.Span),
                terminal.CheckpointGeneration);
            return new VerifiedXPointNetworkForwardCheckpoint(
                nfpBytes, checkpointBytes, targetView, targetHead, terminal,
                protectedLkg, next, trustedTime,
                trustedFreshness.ExactDtt1CoreHash.Span, hardUpper);
        }
        catch (XPointNetworkForwardCheckpointVerificationException) { throw; }
        catch (OperationCanceledException) { throw; }
        catch (XPointValidationException exception)
        {
            throw new XPointNetworkForwardCheckpointVerificationException(exception.Error, exception.Message, exception);
        }
        catch (AccountDirectoryDtt1FormatException exception)
        {
            throw new XPointNetworkForwardCheckpointVerificationException("dtt-invalid", exception.Message, exception);
        }
        catch (OnionBoundaryException exception)
        {
            throw new XPointNetworkForwardCheckpointVerificationException(exception.Code, exception.Message, exception);
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException or CryptographicException or OverflowException)
        {
            throw new XPointNetworkForwardCheckpointVerificationException(
                "forward-package-invalid", "The exact NFP1/XNF1 reset package is invalid.", exception);
        }
    }

    private static void VerifyAuthorityChain(
        VerifiedXPointNetworkAuthority verified,
        IReadOnlyList<Xna1Record> supplied,
        Nfp1Record nfp)
    {
        VerifyReferenceList(nfp.FieldSpan(10), supplied, ProtocolMagic.XNA1, "authority-chain-mismatch");
        var trusted = verified.AuthorityChain;
        var start = -1;
        for (var index = 0; index < trusted.Count; index++)
        {
            if (!trusted[index].CoreHash.Equals(supplied[0].CoreHash) ||
                !trusted[index].CanonicalSpan.SequenceEqual(supplied[0].CanonicalSpan)) continue;
            start = index;
            break;
        }
        if (start < 0 || start + supplied.Count > trusted.Count)
            Fail("authority-chain-mismatch", "The supplied XNA1 chain is not a contiguous part of the verified authority lineage.");
        for (var index = 0; index < supplied.Count; index++)
            if (!trusted[start + index].CanonicalSpan.SequenceEqual(supplied[index].CanonicalSpan))
                Fail("authority-chain-mismatch", "The supplied XNA1 chain differs from the verified authority lineage.");
        if (start + supplied.Count != trusted.Count ||
            !supplied[^1].CoreHash.Span.SequenceEqual(verified.AuthorityCoreHash.Span))
            Fail("authority-chain-mismatch", "The reset authority chain must terminate at the current verified authority.");
    }

    private static void VerifyReferenceList<T>(
        ReadOnlySpan<byte> encoded,
        IReadOnlyList<T> records,
        string magic,
        string code) where T : XPointParsedRecord
    {
        if (encoded.Length != records.Count * XPointCoreReference.Length)
            Fail(code, $"The NFP1 {magic} reference count differs from the separately supplied exact records.");
        for (var index = 0; index < records.Count; index++)
        {
            var expected = XPointNetworkCodec.EncodeCoreReference(magic, records[index].CoreHash.Span);
            if (!CryptographicOperations.FixedTimeEquals(
                    encoded.Slice(index * XPointCoreReference.Length, XPointCoreReference.Length), expected))
                Fail(code, $"An NFP1 {magic} reference does not match its separately supplied exact record.");
        }
    }

    private static void VerifyDtt(
        VerifiedXPointNetworkAuthority authority,
        VerifiedAccountDirectoryFreshness freshness,
        Nfp1Record nfp,
        Xnv1Record targetView,
        AccountDirectoryDtt1 dtt,
        ReadOnlySpan<byte> exactDtt)
    {
        var dttHash = AccountDirectoryCrypto.ComputeDtt1CoreHash(dtt);
        var dttReference = XPointNetworkCodec.EncodeCoreReference(ProtocolMagic.DTT1, dttHash);
        if (!CryptographicOperations.FixedTimeEquals(AccountDirectoryDtt1Codec.Encode(dtt), exactDtt) ||
            !CryptographicOperations.FixedTimeEquals(dttHash, freshness.ExactDtt1CoreHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(dttReference, nfp.FieldSpan(15)) ||
            !CryptographicOperations.FixedTimeEquals(dtt.NetworkId.Span, authority.NetworkId.Span) ||
            !CryptographicOperations.FixedTimeEquals(freshness.NetworkId.Span, authority.NetworkId.Span) ||
            dtt.CurrentXnv1Generation != targetView.ViewGeneration ||
            !CryptographicOperations.FixedTimeEquals(dtt.CurrentXnv1CoreHash.Span, targetView.CoreHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(dtt.AuthorizingXna1CoreReference.Span, authority.AuthorityCoreReference.Span) ||
            !CryptographicOperations.FixedTimeEquals(dtt.WitnessPolicyHash.Span, authority.DirectoryWitnessPolicyHash.Span) ||
            !CryptographicOperations.FixedTimeEquals(targetView.AuthorizingXna.Encode(), authority.AuthorityCoreReference.Span) ||
            !CryptographicOperations.FixedTimeEquals(targetView.DirectoryWitnessPolicyHash.Span, authority.DirectoryWitnessPolicyHash.Span))
            Fail("dtt-target-mismatch", "The live DTT1 does not authenticate the exact reset target and authority.");
    }

    private static void VerifyPriorCheckpoint(XPointNetworkProtectedLkg lkg, Xnf1Record first)
    {
        if (!lkg.LastForwardCheckpointGeneration.HasValue) return;
        var previous = XPointNetworkCodec.DecodeCoreReference(lkg.LastForwardCheckpointCoreReference.Span);
        if (lkg.LastForwardCheckpointGeneration == ulong.MaxValue ||
            first.CheckpointGeneration != lkg.LastForwardCheckpointGeneration.Value + 1 ||
            !first.FieldSpan(3).SequenceEqual(previous.Hash.Span))
            Fail("checkpoint-lineage-mismatch", "The first XNF1 is not the exact successor of the protected checkpoint LKG.");
    }

    private static byte[] Own(ReadOnlyMemory<byte> value, XPointRecordDefinition definition, string name)
    {
        if (value.Length < definition.MinimumBytes || value.Length > definition.MaximumBytes)
            throw new ArgumentException($"The exact {name} record is outside its frozen byte bounds.", name);
        return value.ToArray();
    }

    private static byte[][] OwnChain(
        IReadOnlyList<ReadOnlyMemory<byte>> values,
        XPointRecordDefinition definition,
        string name)
    {
        if (values.Count is < 1 or > MaximumChainCount)
            throw new ArgumentException($"The exact {name} chain must contain 1..{MaximumChainCount} records.", name);
        var result = new byte[values.Count][];
        for (var index = 0; index < result.Length; index++)
            result[index] = Own(values[index], definition, name);
        return result;
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

    private sealed class ForwardResolver : IXPointClosureResolver
    {
        private readonly Dictionary<string, XPointParsedRecord> coreRecords = new(StringComparer.Ordinal);
        private readonly Dictionary<string, XPointExternalEvidence> externalRecords = new(StringComparer.Ordinal);

        internal ForwardResolver(
            IReadOnlyList<Xna1Record> authorities,
            IReadOnlyList<Xnf1Record> checkpoints,
            Xnv1Record targetView,
            Xnh1Record targetHead,
            AccountDirectoryDtt1 dtt,
            ReadOnlySpan<byte> dttHash)
        {
            foreach (var record in authorities.Cast<XPointParsedRecord>()
                         .Concat(checkpoints)
                         .Append(targetView)
                         .Append(targetHead))
                coreRecords.Add(Key(record.CoreReferenceValue), record);

            foreach (var authority in authorities)
            {
                var reference = authority.CoreReference(12);
                externalRecords[Key(reference)] = new XPointExternalEvidence(
                    ProtocolMagic.DTS1, authority.NetworkId, default, authority.NotBefore, authority.ExpiresAt,
                    authority.FieldBytes(13), authority.UInt32(14), authority.CoreReferenceValue);
            }
            var currentView = new XPointCoreReference(ProtocolMagic.XNV1, 1, new XPointBytes(dtt.CurrentXnv1CoreHash.Span));
            var dttReference = new XPointCoreReference(ProtocolMagic.DTT1, 1, new XPointBytes(dttHash));
            externalRecords.Add(Key(dttReference), new XPointExternalEvidence(
                ProtocolMagic.DTT1, new XPointBytes(dtt.NetworkId.Span), default, dtt.IssuedAt, dtt.ExpiresAt,
                new XPointBytes(dttHash), dtt.UncertaintySeconds, currentView));
        }

        public XPointParsedRecord ResolveCore(XPointCoreReference reference) =>
            coreRecords.TryGetValue(Key(reference), out var record)
                ? record
                : throw new XPointNetworkForwardCheckpointVerificationException(
                    "reference-missing", "A typed core reference is absent from the exact reset package.");

        public XPointExternalEvidence ResolveExternalCore(XPointCoreReference reference) =>
            externalRecords.TryGetValue(Key(reference), out var evidence)
                ? evidence
                : throw new XPointNetworkForwardCheckpointVerificationException(
                    "reference-missing", "An external typed core reference is absent from the exact reset package.");

        public XPointParsedRecord ResolveArtifact(XPointArtifactReference reference) => throw Unreachable();
        public Xnd1Record ResolveNodeDescriptor(XPointBytes nodeId) => throw Unreachable();
        public bool IsNodeActiveAndUnrevoked(XPointBytes nodeId) => throw Unreachable();
        public XPointExternalEvidence ResolveExternalArtifact(XPointArtifactReference reference) => throw Unreachable();

        private static string Key(XPointCoreReference reference) =>
            $"{reference.Magic}:{reference.Version}:{Convert.ToHexString(reference.Hash.Span)}";
        private static InvalidOperationException Unreachable() =>
            new("The XNF1/NFP1 verifier requested unrelated closure material.");
    }

    [System.Diagnostics.CodeAnalysis.DoesNotReturn]
    private static void Fail(string code, string message) =>
        throw new XPointNetworkForwardCheckpointVerificationException(code, message);
}
