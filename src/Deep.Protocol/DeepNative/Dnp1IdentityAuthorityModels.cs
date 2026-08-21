namespace Deep.Protocol.DeepNative;

public sealed class RevocationTarget : CanonicalIdentityArtifact
{
    internal RevocationTarget(OwnedRecord record) : base(record, ArtifactType.Drt1) { }

    public ReadOnlyMemory<byte> AccountHash => Record.FieldCopy(1);
    public RevocationTargetKind TargetKind => (RevocationTargetKind)Record.FieldSpan(2)[0];
    public ReadOnlyMemory<byte> RandomRevocationHandle => Record.FieldCopy(3);
    public ulong TargetGeneration => Scalars.UInt64(Record.FieldSpan(4));
    public ArtifactReference CertificateReference =>
        CanonicalGrammar.DecodeReference(Record.FieldSpan(5));
    public ulong TargetNotAfterUnixSeconds => Scalars.UInt64(Record.FieldSpan(6));
}

public sealed class KeyRotation : CanonicalIdentityArtifact
{
    internal KeyRotation(OwnedRecord record) : base(record, ArtifactType.Krt1) { }
    public KeyScope Scope => (KeyScope)Record.FieldSpan(2)[0];
    public ulong TransitionGeneration => Scalars.UInt64(Record.FieldSpan(5));
    public ArtifactReference PredecessorReference =>
        CanonicalGrammar.DecodeReference(Record.FieldSpan(6));
    public ReadOnlyMemory<byte> NewEd25519PublicKey => Record.FieldCopy(8);
    public ulong EffectiveAtUnixSeconds => Scalars.UInt64(Record.FieldSpan(9));
}

public sealed class KeyRevocation : CanonicalIdentityArtifact
{
    internal KeyRevocation(OwnedRecord record) : base(record, ArtifactType.Krf1) { }
    public KeyScope Scope => (KeyScope)Record.FieldSpan(2)[0];
    public ulong TransitionGeneration => Scalars.UInt64(Record.FieldSpan(5));
    public ArtifactReference PredecessorReference =>
        CanonicalGrammar.DecodeReference(Record.FieldSpan(6));
    public ulong EffectiveAtUnixSeconds => Scalars.UInt64(Record.FieldSpan(8));
}

internal sealed class RevocationCatalogSource
{
    private readonly byte[] _target;
    private readonly byte[] _certificate;
    private readonly byte[] _predecessorDrs;

    public RevocationCatalogSource(
        ReadOnlySpan<byte> revocationTargetCanonical,
        ReadOnlySpan<byte> targetCertificateCanonical,
        ReadOnlySpan<byte> predecessorDrsCanonical = default)
    {
        _target = revocationTargetCanonical.ToArray();
        _certificate = targetCertificateCanonical.ToArray();
        _predecessorDrs = predecessorDrsCanonical.ToArray();
    }

    internal ReadOnlySpan<byte> TargetSpan => _target;
    internal ReadOnlySpan<byte> CertificateSpan => _certificate;
    internal ReadOnlySpan<byte> PredecessorDrsSpan => _predecessorDrs;
}

/// <summary>Exact private DRT1 and target-certificate evidence supplied for one DRS row.</summary>
public sealed class RevocationCatalogInput
{
    internal RevocationCatalogSource Source { get; }

    public RevocationCatalogInput(
        ReadOnlySpan<byte> revocationTargetCanonical,
        ReadOnlySpan<byte> targetCertificateCanonical)
    {
        Source = new RevocationCatalogSource(
            revocationTargetCanonical,
            targetCertificateCanonical);
    }

    public RevocationCatalogInput(
        ReadOnlySpan<byte> revocationTargetCanonical,
        ReadOnlySpan<byte> targetCertificateCanonical,
        ReadOnlySpan<byte> predecessorDrsCanonical)
    {
        Source = new RevocationCatalogSource(
            revocationTargetCanonical,
            targetCertificateCanonical,
            predecessorDrsCanonical);
    }
}

internal sealed class RevocationCatalogEntry
{
    private readonly byte[] _certificate;
    private readonly byte[] _predecessorDrs;
    internal RevocationCatalogEntry(
        RevocationTarget target,
        ulong revokedAt,
        RevocationReason reason,
        ReadOnlySpan<byte> certificate,
        ReadOnlySpan<byte> predecessorDrs)
    {
        Target = target;
        RevokedAtUnixSeconds = revokedAt;
        Reason = reason;
        _certificate = certificate.ToArray();
        _predecessorDrs = predecessorDrs.ToArray();
    }

    public RevocationTarget Target { get; }
    public ulong RevokedAtUnixSeconds { get; }
    public RevocationReason Reason { get; }
    internal ReadOnlySpan<byte> CertificateCanonical => _certificate;
    internal ReadOnlySpan<byte> PredecessorDrsCanonical => _predecessorDrs;
}

internal sealed class RevocationCatalog
{
    private readonly RevocationCatalogEntry[] _entries;

    internal RevocationCatalog(IEnumerable<RevocationCatalogEntry> entries)
    {
        _entries = entries.ToArray();
    }

    public IReadOnlyList<RevocationCatalogEntry> Entries =>
        Array.AsReadOnly(_entries.ToArray());
    public bool IsAccountTerminal =>
        _entries.Length != 0 && _entries[^1].Target.TargetKind == RevocationTargetKind.AccountTerminal;

    internal bool Contains(ArtifactType type, ReadOnlySpan<byte> canonicalHash)
    {
        foreach (var entry in _entries)
        {
            var reference = entry.Target.CertificateReference;
            if (reference.Type == type &&
                CanonicalGrammar.FixedEquals(reference.CanonicalHash.Span, canonicalHash))
                return true;
        }
        return false;
    }
}

internal sealed class VerifiedKeyAuthority
{
    private readonly byte[] _publicKey;
    private readonly byte[] _transitionHash;

    internal VerifiedKeyAuthority(
        KeyScope scope,
        ulong generation,
        ReadOnlySpan<byte> publicKey,
        ArtifactReference transitionReference,
        ReadOnlySpan<byte> transitionCanonicalHash,
        bool terminal)
    {
        Scope = scope;
        Generation = generation;
        _publicKey = publicKey.ToArray();
        TransitionReference = transitionReference;
        _transitionHash = transitionCanonicalHash.ToArray();
        IsTerminal = terminal;
    }

    public KeyScope Scope { get; }
    public ulong Generation { get; }
    public ReadOnlyMemory<byte> CurrentEd25519PublicKey => _publicKey.ToArray();
    public ArtifactReference TransitionReference { get; }
    public bool IsTerminal { get; }
    internal ReadOnlySpan<byte> TransitionCanonicalHash => _transitionHash;
}

internal sealed class VerifiedIdentityAuthority
{
    private readonly object _gate = new();
    private readonly Dictionary<KeyScope, VerifiedKeyAuthority> _keys;
    private bool _forkLatched;
    private readonly List<(ArtifactType Type, KeyScope Scope, ulong Generation,
        ArtifactReference Reference, byte[] Canonical)> _transitions = [];

    internal VerifiedIdentityAuthority(
        VerifiedAccount account,
        VerifiedRevocationState revocations,
        IEnumerable<VerifiedKeyAuthority> keys)
    {
        Account = account;
        Revocations = revocations;
        _keys = keys.ToDictionary(static key => key.Scope);
    }

    public VerifiedAccount Account { get; }
    public VerifiedRevocationState Revocations { get; internal set; }
    public bool IsAccountTerminal => Revocations.Catalog.IsAccountTerminal;
    public bool ForkLatched { get { lock (_gate) return _forkLatched; } }

    public VerifiedKeyAuthority GetKeyAuthority(KeyScope scope)
    {
        lock (_gate)
            return _keys.TryGetValue(scope, out var authority)
                ? authority
                : throw new RecordException(
                    RecordError.InvalidField,
                    "ReleaseRoot authority is not carried by an account identity capability.");
    }

    internal object Gate => _gate;
    internal void EnsureUsable()
    {
        if (_forkLatched)
            throw new RecordException(RecordError.ForkDetected, "The identity authority is fork-latched.");
        if (IsAccountTerminal)
            throw new RecordException(RecordError.Revoked, "The account is terminally revoked.");
    }
    internal void LatchFork() => _forkLatched = true;
    internal void SetKey(VerifiedKeyAuthority authority) => _keys[authority.Scope] = authority;
    internal void RecordTransition(
        ArtifactType type,
        VerifiedKeyAuthority authority,
        ReadOnlySpan<byte> canonical)
    {
        if (_transitions.Any(value => value.Type == type && value.Scope == authority.Scope &&
            value.Generation == authority.Generation && value.Reference.Equals(authority.TransitionReference)))
            return;
        _transitions.Add((type, authority.Scope, authority.Generation,
            authority.TransitionReference, canonical.ToArray()));
    }
    internal IReadOnlyList<(ArtifactType Type, KeyScope Scope, ulong Generation,
        ArtifactReference Reference)> OrderedTransitions
    {
        get
        {
            lock (_gate)
                return _transitions.OrderBy(static value => (byte)value.Scope)
                    .ThenBy(static value => value.Generation)
                    .Select(static value => (value.Type, value.Scope, value.Generation, value.Reference))
                    .ToArray();
            }
    }
    internal IReadOnlyList<ReadOnlyMemory<byte>> OrderedTransitionCanonicals
    {
        get
        {
            lock (_gate)
                return _transitions.OrderBy(static value => (byte)value.Scope)
                    .ThenBy(static value => value.Generation)
                    .Select(static value => (ReadOnlyMemory<byte>)value.Canonical.ToArray())
                    .ToArray();
        }
    }
}

/// <summary>
/// A defensively owned identity verification result. It is relative to the supplied
/// canonical evidence and carries no deployment, persistence, or commit authority.
/// </summary>
public sealed class VerifiedIdentityRelative
{
    internal VerifiedIdentityRelative(VerifiedIdentityAuthority authority) => Authority = authority;
    internal VerifiedIdentityAuthority Authority { get; }
    public VerifiedAccount Account => Authority.Account;
    public VerifiedRevocationState Revocations => Authority.Revocations;
    public bool IsTerminal => Authority.IsAccountTerminal;
    public bool ForkLatched => Authority.ForkLatched;
    public bool NoAuthorityClaim => true;
}

/// <summary>A device verification fact relative to one exact current identity result.</summary>
public sealed class VerifiedDeviceRelative
{
    internal VerifiedDeviceRelative(VerifiedIdentityRelative identity, VerifiedDevice device)
    {
        Identity = identity;
        Device = device;
    }
    internal VerifiedDevice Device { get; }
    public VerifiedIdentityRelative Identity { get; }
    public DeviceCertificate Certificate => Device.Certificate;
    public bool NoAuthorityClaim => true;
}

/// <summary>A mailbox-role verification fact relative to one exact device and DRS result.</summary>
public sealed class VerifiedMailboxRelative
{
    internal VerifiedMailboxRelative(VerifiedDeviceRelative device, VerifiedMailboxRole mailbox)
    {
        Device = device;
        Mailbox = mailbox;
    }
    internal VerifiedMailboxRole Mailbox { get; }
    public VerifiedDeviceRelative Device { get; }
    public MailboxRoleCertificate Certificate => Mailbox.Certificate;
    public bool NoAuthorityClaim => true;
}

/// <summary>A complete immutable ReleaseRoot manifest pin value. It is not authority.</summary>
public sealed class ReleaseRootManifestPin
{
    private readonly byte[] _network;
    private readonly byte[] _signerKeyId;
    private readonly byte[] _signerPublicKey;

    public ReleaseRootManifestPin(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> manifestSignerKeyId,
        ReadOnlySpan<byte> manifestSignerEd25519PublicKey,
        ulong minimumManifestGeneration,
        ArtifactReference expectedManifestReference)
    {
        if (networkId.Length != 16 || manifestSignerKeyId.Length != 32 ||
            manifestSignerEd25519PublicKey.Length != 32 ||
            CanonicalGrammar.IsZero(networkId) ||
            CanonicalGrammar.IsZero(manifestSignerKeyId) ||
            CanonicalGrammar.IsZero(manifestSignerEd25519PublicKey) ||
            minimumManifestGeneration != 0 ||
            expectedManifestReference.Type != ArtifactType.Rrm1 ||
            expectedManifestReference.CanonicalLength != 332 ||
            expectedManifestReference.CanonicalHash.Length != 32 ||
            CanonicalGrammar.IsZero(expectedManifestReference.CanonicalHash.Span))
            throw new RecordException(RecordError.InvalidField,
                "The complete ReleaseRoot manifest pin is malformed.");
        _network = networkId.ToArray();
        _signerKeyId = manifestSignerKeyId.ToArray();
        _signerPublicKey = manifestSignerEd25519PublicKey.ToArray();
        MinimumManifestGeneration = minimumManifestGeneration;
        ExpectedManifestReference = expectedManifestReference;
    }

    public ReadOnlyMemory<byte> NetworkId => _network.ToArray();
    public ReadOnlyMemory<byte> ManifestSignerKeyId => _signerKeyId.ToArray();
    public ReadOnlyMemory<byte> ManifestSignerEd25519PublicKey => _signerPublicKey.ToArray();
    public ulong MinimumManifestGeneration { get; }
    public ArtifactReference ExpectedManifestReference { get; }
    public bool NoAuthorityClaim => true;
}

/// <summary>A signature-relative ReleaseRoot chain fact with no durable authority.</summary>
public sealed class ReleaseRootRelativeFact
{
    private readonly byte[] _currentPublic;
    private readonly ArtifactReference[] _transitions;
    private readonly byte[][] _transitionCanonicals;

    internal ReleaseRootRelativeFact(
        ReleaseRootManifest manifest,
        ReleaseRootManifestPin pin,
        ulong generation,
        ReadOnlySpan<byte> currentPublic,
        ArtifactReference transitionReference,
        IEnumerable<ArtifactReference> transitions,
        IEnumerable<ReadOnlyMemory<byte>> transitionCanonicals,
        KeyRevocation? pendingTerminalRevocation)
    {
        Manifest = manifest;
        Pin = pin;
        CurrentGeneration = generation;
        _currentPublic = currentPublic.ToArray();
        CurrentTransitionReference = transitionReference;
        _transitions = transitions.ToArray();
        _transitionCanonicals = transitionCanonicals.Select(static value => value.ToArray()).ToArray();
        if (_transitionCanonicals.Length != _transitions.Length)
            throw new RecordException(RecordError.InvalidField,
                "ReleaseRoot transition references and canonical bytes differ in count.");
        PendingTerminalRevocation = pendingTerminalRevocation;
    }

    public ReleaseRootManifest Manifest { get; }
    public ReleaseRootManifestPin Pin { get; }
    public ulong CurrentGeneration { get; }
    public ReadOnlyMemory<byte> CurrentEd25519PublicKey => _currentPublic.ToArray();
    public ArtifactReference CurrentTransitionReference { get; }
    public KeyRevocation? PendingTerminalRevocation { get; }
    public bool IsTerminalCandidate => PendingTerminalRevocation is not null;
    public bool NoAuthorityClaim => true;
    internal IReadOnlyList<ArtifactReference> Transitions => _transitions;
    internal IReadOnlyList<ReadOnlyMemory<byte>> TransitionCanonicals =>
        _transitionCanonicals.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray();
}

public sealed class WitnessDescriptorRelative
{
    private readonly byte[] _id;
    private readonly byte[] _publicKey;
    private readonly byte[] _address;
    private readonly byte[] _tlsSpki;

    internal WitnessDescriptorRelative(ReadOnlySpan<byte> row)
    {
        _id = row[..32].ToArray();
        _publicKey = row.Slice(32, 32).ToArray();
        EndpointKind = (WitnessEndpointKind)row[64];
        _address = row.Slice(66, 16).ToArray();
        Port = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(row.Slice(82, 2));
        _tlsSpki = row.Slice(84, 32).ToArray();
    }

    public ReadOnlyMemory<byte> WitnessId => _id.ToArray();
    public ReadOnlyMemory<byte> Ed25519PublicKey => _publicKey.ToArray();
    public WitnessEndpointKind EndpointKind { get; }
    public ReadOnlyMemory<byte> Address => _address.ToArray();
    public ushort Port { get; }
    public ReadOnlyMemory<byte> TlsSpkiSha256 => _tlsSpki.ToArray();
}

/// <summary>A DWD1 verification fact relative to an exact ReleaseRoot chain fact.</summary>
public sealed class WitnessDelegationRelativeFact
{
    private readonly WitnessDescriptorRelative[] _descriptors;

    internal WitnessDelegationRelativeFact(
        WitnessDelegation delegation,
        ReleaseRootRelativeFact releaseRoot,
        IEnumerable<WitnessDescriptorRelative> descriptors)
    {
        Delegation = delegation;
        ReleaseRoot = releaseRoot;
        _descriptors = descriptors.ToArray();
    }

    public WitnessDelegation Delegation { get; }
    public ReleaseRootRelativeFact ReleaseRoot { get; }
    public IReadOnlyList<WitnessDescriptorRelative> Descriptors =>
        Array.AsReadOnly(_descriptors.ToArray());
    public bool NoAuthorityClaim => true;
}

/// <summary>Terminal witness evidence relative to exact KRF1 and prior DWD1 facts.</summary>
public sealed class WitnessTerminationRelativeFact
{
    internal WitnessTerminationRelativeFact(
        WitnessTermination termination,
        ReleaseRootRelativeFact releaseRoot,
        WitnessDelegationRelativeFact priorDelegation)
    {
        Termination = termination;
        ReleaseRoot = releaseRoot;
        PriorDelegation = priorDelegation;
    }
    public WitnessTermination Termination { get; }
    public ReleaseRootRelativeFact ReleaseRoot { get; }
    public WitnessDelegationRelativeFact PriorDelegation { get; }
    public bool NoAuthorityClaim => true;
}

/// <summary>One owned DWD1 ancestry row and the exact predecessor-head evidence it commits.</summary>
public sealed class WitnessAncestryInput
{
    private readonly byte[] _canonical;
    private readonly byte[] _predecessorFinalHeads;

    public WitnessAncestryInput(
        ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> predecessorFinalHeads288)
    {
        if (canonical.Length != 1217 || predecessorFinalHeads288.Length != 288)
            throw new RecordException(RecordError.InvalidLength,
                "A DWD1 ancestry input must own exactly 1,217 canonical bytes and 288 predecessor-head bytes.");
        _canonical = canonical.ToArray();
        _predecessorFinalHeads = predecessorFinalHeads288.ToArray();
    }

    public ReadOnlyMemory<byte> CanonicalDwd => _canonical.ToArray();
    public ReadOnlyMemory<byte> PredecessorFinalHeads => _predecessorFinalHeads.ToArray();
    public bool NoAuthorityClaim => true;
}

/// <summary>
/// Complete bounded ReleaseRoot restore evidence. The two tail values are mutually
/// exclusive: terminal evidence has DWT1 only; nonterminal evidence has fresh DCL1 only.
/// </summary>
public sealed class ReleaseRootRestoreInput
{
    private readonly byte[] _manifest;
    private readonly byte[][] _transitions;
    private readonly WitnessAncestryInput[] _delegations;
    private readonly byte[] _terminalDwt;
    private readonly byte[] _freshDcl;

    public ReleaseRootRestoreInput(
        ReleaseRootManifestPin pin,
        ReadOnlyMemory<byte> manifestCanonical,
        IReadOnlyList<ReadOnlyMemory<byte>> rootTransitions,
        IReadOnlyList<WitnessAncestryInput> witnessDelegations,
        ReadOnlyMemory<byte> terminalDwtCanonical = default,
        ReadOnlyMemory<byte> freshDclCanonical = default)
    {
        ArgumentNullException.ThrowIfNull(pin);
        ArgumentNullException.ThrowIfNull(rootTransitions);
        ArgumentNullException.ThrowIfNull(witnessDelegations);
        if (manifestCanonical.Length != 332 || rootTransitions.Count > 64 ||
            witnessDelegations.Count is < 1 or > 65)
            throw new RecordException(RecordError.InvalidLength,
                "ReleaseRoot restore evidence exceeds the exact RRM/KRT-KRF/DWD bounds.");
        if (terminalDwtCanonical.IsEmpty == freshDclCanonical.IsEmpty ||
            (!terminalDwtCanonical.IsEmpty && terminalDwtCanonical.Length != 714) ||
            (!freshDclCanonical.IsEmpty && freshDclCanonical.Length is < 409 or > 5623))
            throw new RecordException(RecordError.InvalidLength,
                "ReleaseRoot restore requires exactly one bounded DWT1-or-DCL1 tail.");
        for (var index = 0; index < rootTransitions.Count; index++)
            if (rootTransitions[index].Length is not (300 or 412))
                throw new RecordException(RecordError.InvalidLength,
                    "A ReleaseRoot transition is not an exact KRT1 or KRF1 length.");
        for (var index = 0; index < witnessDelegations.Count; index++)
            ArgumentNullException.ThrowIfNull(witnessDelegations[index]);

        Pin = pin;
        _manifest = manifestCanonical.ToArray();
        _transitions = rootTransitions.Select(static value => value.ToArray()).ToArray();
        _delegations = witnessDelegations.ToArray();
        _terminalDwt = terminalDwtCanonical.ToArray();
        _freshDcl = freshDclCanonical.ToArray();
    }

    public ReleaseRootManifestPin Pin { get; }
    public ReadOnlyMemory<byte> ManifestCanonical => _manifest.ToArray();
    public IReadOnlyList<ReadOnlyMemory<byte>> RootTransitions =>
        Array.AsReadOnly(_transitions.Select(static value => (ReadOnlyMemory<byte>)value.ToArray()).ToArray());
    public IReadOnlyList<WitnessAncestryInput> WitnessDelegations =>
        Array.AsReadOnly(_delegations.ToArray());
    public ReadOnlyMemory<byte> TerminalDwtCanonical => _terminalDwt.ToArray();
    public ReadOnlyMemory<byte> FreshDclCanonical => _freshDcl.ToArray();
    public bool IsTerminal => _terminalDwt.Length != 0;
    public bool NoAuthorityClaim => true;
}

/// <summary>A complete signature-relative restore result; never durable or use authority.</summary>
public sealed class ReleaseRootRestoreRelative
{
    private readonly byte[][] _orderedDwdCanonicals;
    private readonly byte[][] _orderedPredecessorHeads;

    internal ReleaseRootRestoreRelative(
        ReleaseRootRelativeFact releaseRoot,
        WitnessDelegationRelativeFact latestDelegation,
        ReleaseRootAuthorityTuple authorityTuple,
        WitnessTerminationRelativeFact? termination,
        QuorumLease? freshLease,
        bool exactReplay,
        IReadOnlyList<byte[]>? orderedDwdCanonicals = null,
        IReadOnlyList<byte[]>? orderedPredecessorHeads = null)
    {
        ReleaseRoot = releaseRoot;
        LatestDelegation = latestDelegation;
        AuthorityTuple = authorityTuple;
        Termination = termination;
        FreshLease = freshLease;
        IsExactReplay = exactReplay;
        _orderedDwdCanonicals = orderedDwdCanonicals?.Select(static value => value.ToArray()).ToArray() ??
            [latestDelegation.Delegation.CanonicalBytes.ToArray()];
        _orderedPredecessorHeads = orderedPredecessorHeads?.Select(static value => value.ToArray()).ToArray() ??
            [new byte[288]];
        if (_orderedPredecessorHeads.Length != _orderedDwdCanonicals.Length ||
            _orderedPredecessorHeads.Any(static value => value.Length != 288))
            throw new RecordException(RecordError.InvalidLength,
                "ReleaseRoot restore predecessor-head evidence is incomplete.");
    }

    public ReleaseRootRelativeFact ReleaseRoot { get; }
    public WitnessDelegationRelativeFact LatestDelegation { get; }
    public ReleaseRootAuthorityTuple AuthorityTuple { get; }
    public WitnessTerminationRelativeFact? Termination { get; }
    public QuorumLease? FreshLease { get; }
    public bool IsTerminal => Termination is not null;
    public bool IsUsable => !IsTerminal && FreshLease is not null;
    public bool IsExactReplay { get; }
    public bool NoAuthorityClaim => true;
    internal IReadOnlyList<byte[]> OrderedDwdCanonicals =>
        _orderedDwdCanonicals.Select(static value => value.ToArray()).ToArray();
    internal IReadOnlyList<byte[]> OrderedPredecessorHeads =>
        _orderedPredecessorHeads.Select(static value => value.ToArray()).ToArray();
}

/// <summary>The exact unsigned RRL1 HMAC transcript; contains no HMAC key.</summary>
public sealed class ReleaseRootLkgHmacTranscript
{
    private readonly byte[] _unsigned;
    private readonly byte[] _keyId;
    private readonly byte[] _storedTag;

    internal ReleaseRootLkgHmacTranscript(
        ReadOnlySpan<byte> unsigned,
        ReadOnlySpan<byte> keyId,
        ReadOnlySpan<byte> storedTag)
    {
        _unsigned = unsigned.ToArray();
        _keyId = keyId.ToArray();
        _storedTag = storedTag.ToArray();
    }

    public string Domain => "Deep/ProtectedState/V1/RRL1";
    public ushort Suite => ArtifactRegistry.ProtectedHmacSha256;
    public ReadOnlyMemory<byte> UnsignedCanonical => _unsigned.ToArray();
    public ReadOnlyMemory<byte> ProtectedStateKeyId => _keyId.ToArray();
    public bool NoAuthorityClaim => true;

    internal ReleaseRootLkgHmacMatch MatchComputedTag(ReadOnlySpan<byte> computedTag)
    {
        if (computedTag.Length != 32 ||
            !CanonicalGrammar.FixedEquals(computedTag, _storedTag))
            throw new RecordException(RecordError.InvalidSignature,
                "The computed RRL1 HMAC does not match the owned stored tag.");
        return new ReleaseRootLkgHmacMatch(this, computedTag);
    }
}

/// <summary>
/// Owned protected-record HMAC request. It contains a key identifier and exact
/// transcript only, never key material or an authority claim.
/// </summary>
public sealed class ProtectedHmacRequest
{
    private readonly byte[] _keyId;
    private readonly byte[] _unsigned;

    internal ProtectedHmacRequest(
        string domain,
        ushort suite,
        ReadOnlySpan<byte> keyId,
        ReadOnlySpan<byte> unsignedCanonical)
    {
        Domain = domain;
        Suite = suite;
        _keyId = keyId.ToArray();
        _unsigned = unsignedCanonical.ToArray();
    }

    public string Domain { get; }
    public ushort Suite { get; }
    public ReadOnlyMemory<byte> ProtectedStateKeyId => _keyId.ToArray();
    public ReadOnlyMemory<byte> UnsignedCanonical => _unsigned.ToArray();
    public bool NoAuthorityClaim => true;
}

/// <summary>Consumer-owned key custody boundary; Protocol never receives the HMAC key.</summary>
public interface IProtectedHmacProvider
{
    ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
        ProtectedHmacRequest request,
        CancellationToken cancellationToken);
}

public sealed class ReleaseRootLkgHmacMatch
{
    private readonly byte[] _tag;
    internal ReleaseRootLkgHmacMatch(
        ReleaseRootLkgHmacTranscript transcript,
        ReadOnlySpan<byte> tag)
    {
        Transcript = transcript;
        _tag = tag.ToArray();
    }
    public ReleaseRootLkgHmacTranscript Transcript { get; }
    public ReadOnlyMemory<byte> VerifiedTag => _tag.ToArray();
    public bool NoAuthorityClaim => true;
}

public sealed class ReleaseRootAuthorityTuple
{
    private readonly byte[] _canonical;
    internal ReleaseRootAuthorityTuple(ReadOnlySpan<byte> canonical) => _canonical = canonical.ToArray();
    public ReadOnlyMemory<byte> CanonicalTuple => _canonical.ToArray();
    public bool NoAuthorityClaim => true;
}

/// <summary>Exact old-to-new tuple data for a consumer-owned CAS; it is not commit authorization.</summary>
public sealed class ReleaseRootTransitionPlan
{
    internal ReleaseRootTransitionPlan(
        ReleaseRootAuthorityTuple oldTuple,
        ReleaseRootAuthorityTuple newTuple)
    {
        OldTuple = oldTuple;
        NewTuple = newTuple;
    }
    public ReleaseRootAuthorityTuple OldTuple { get; }
    public ReleaseRootAuthorityTuple NewTuple { get; }
    public bool NoAuthorityClaim => true;
}
