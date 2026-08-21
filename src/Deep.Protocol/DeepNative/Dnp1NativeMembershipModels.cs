using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// A defensively owned membership/routing closure. Instances are minted only after the complete
/// MRLC membership and mailbox-authority closures have been verified.
/// </summary>
public sealed class VerifiedMembershipRoutingLkg
{
    private readonly byte[] _networkId;
    private readonly byte[] _resetId;
    private readonly byte[] _membershipRoot;
    private readonly byte[] _placementCommitment;
    private readonly byte[] _compositeSelection;
    private readonly byte[] _mrlcReference;
    private readonly VerifiedRouterEntry[] _routers;

    internal VerifiedMembershipRoutingLkg(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> resetId,
        ulong membershipSequence,
        ulong epoch,
        ulong epochExpiresAtUnixSeconds,
        ReadOnlySpan<byte> membershipRoot,
        ReadOnlySpan<byte> placementCommitment,
        IReadOnlyList<VerifiedRouterEntry> routers,
        MembershipHeadRelative? membershipHead = null,
        MailboxAuthorityHeadRelative? mailboxAuthorityHead = null,
        ReadOnlySpan<byte> compositeSelection = default,
        ReadOnlySpan<byte> mrlcReference = default,
        VerifiedMembershipAuthorityChain? authorityChain = null)
    {
        _networkId = networkId.ToArray();
        _resetId = resetId.ToArray();
        MembershipSequence = membershipSequence;
        Epoch = epoch;
        EpochExpiresAtUnixSeconds = epochExpiresAtUnixSeconds;
        _membershipRoot = membershipRoot.ToArray();
        _placementCommitment = placementCommitment.ToArray();
        _compositeSelection = compositeSelection.ToArray();
        _mrlcReference = mrlcReference.ToArray();
        _routers = routers.Select(static value => value.Clone()).ToArray();
        MembershipHead = membershipHead;
        MailboxAuthorityHead = mailboxAuthorityHead;
        AuthorityChain = authorityChain;
    }

    public ReadOnlyMemory<byte> NetworkId => _networkId.ToArray();
    public ReadOnlyMemory<byte> ResetId => _resetId.ToArray();
    public ulong MembershipSequence { get; }
    public ulong Epoch { get; }
    public ulong EpochExpiresAtUnixSeconds { get; }
    public uint MemberCount => checked((uint)_routers.Length);
    public ReadOnlyMemory<byte> MembershipRoot => _membershipRoot.ToArray();
    public ReadOnlyMemory<byte> PlacementCommitment => _placementCommitment.ToArray();
    public ReadOnlyMemory<byte> CompositeSelection => _compositeSelection.ToArray();
    public ReadOnlyMemory<byte> MrlcArtifactReference => _mrlcReference.ToArray();
    public MembershipHeadRelative? MembershipHead { get; }
    public MailboxAuthorityHeadRelative? MailboxAuthorityHead { get; }
    public bool NoAuthorityClaim => true;

    internal ReadOnlySpan<byte> TrustedNetworkId => _networkId;
    internal ReadOnlySpan<byte> TrustedResetId => _resetId;
    internal ReadOnlySpan<byte> TrustedMembershipRoot => _membershipRoot;
    internal ReadOnlySpan<byte> TrustedPlacementCommitment => _placementCommitment;
    internal IReadOnlyList<VerifiedRouterEntry> TrustedRouters => _routers;
    internal VerifiedMembershipAuthorityChain? AuthorityChain { get; }
}

internal sealed class VerifiedMembershipAuthorityChain
{
    private readonly byte[] _transitionHash;
    private readonly ReadOnlyMemory<byte>[] _revokedDelegationHashes;

    internal VerifiedMembershipAuthorityChain(
        ReadOnlySpan<byte> transitionHash,
        SignerDelegation activeDelegation,
        VerifiedSignerDelegation verifiedDelegation,
        MembershipLastKnownGood delegationLastKnownGood,
        IReadOnlyList<ReadOnlyMemory<byte>> revokedDelegationHashes)
    {
        _transitionHash = transitionHash.ToArray();
        ActiveDelegation = Clone(activeDelegation);
        VerifiedDelegation = new VerifiedSignerDelegation
        {
            Statement = ActiveDelegation,
            CanonicalHash = verifiedDelegation.CanonicalHash.ToArray(),
            NextAuthorityLastKnownGood = Clone(
                verifiedDelegation.NextAuthorityLastKnownGood)
        };
        DelegationLastKnownGood = Clone(delegationLastKnownGood);
        _revokedDelegationHashes = revokedDelegationHashes
            .Select(static value => (ReadOnlyMemory<byte>)value.ToArray())
            .ToArray();
    }

    internal ReadOnlySpan<byte> TransitionHash => _transitionHash;
    internal SignerDelegation ActiveDelegation { get; }
    internal VerifiedSignerDelegation VerifiedDelegation { get; }
    internal MembershipLastKnownGood DelegationLastKnownGood { get; }
    internal IReadOnlyList<ReadOnlyMemory<byte>> RevokedDelegationHashes =>
        _revokedDelegationHashes;

    private static SignerDelegation Clone(SignerDelegation value) => new()
    {
        NetworkId = value.NetworkId.ToArray(),
        Sequence = value.Sequence,
        PreviousHash = value.PreviousHash.ToArray(),
        IssuedAtUnixSeconds = value.IssuedAtUnixSeconds,
        ValidFromUnixSeconds = value.ValidFromUnixSeconds,
        ValidUntilUnixSeconds = value.ValidUntilUnixSeconds,
        MinimumProtocol = value.MinimumProtocol,
        MaximumProtocol = value.MaximumProtocol,
        PolicyVersion = value.PolicyVersion,
        OnlineSigners = value.OnlineSigners.Select(static signer =>
            new MembershipSignerDescriptor
            {
                SignerId = signer.SignerId.ToArray(),
                Role = signer.Role,
                PublicKey = signer.PublicKey.ToArray()
            }).ToArray(),
        Signatures = value.Signatures.Select(static signature =>
            new MembershipSignature
            {
                SignerId = signature.SignerId.ToArray(),
                Domain = signature.Domain,
                Signature = signature.Signature.ToArray()
            }).ToArray()
    };

    private static MembershipLastKnownGood Clone(MembershipLastKnownGood value) =>
        new()
        {
            NetworkId = value.NetworkId.ToArray(),
            PolicyVersion = value.PolicyVersion,
            Sequence = value.Sequence,
            CanonicalHash = value.CanonicalHash.ToArray()
        };
}

internal sealed class VerifiedRouterEntry
{
    private readonly byte[] _routerId;
    private readonly byte[] _routerEd25519PublicKey;
    private readonly byte[] _dnrReference;
    private readonly byte[] _mrl2;
    private readonly byte[] _fullMrlReference;
    private readonly byte[] _anchorDpcReference;
    private readonly byte[] _dnrcSource;

    internal VerifiedRouterEntry(
        ReadOnlySpan<byte> routerId,
        ReadOnlySpan<byte> routerEd25519PublicKey,
        ReadOnlySpan<byte> dnrReference,
        ReadOnlySpan<byte> mrl2,
        ulong descriptorGeneration,
        RouterRoles roles,
        RouterCapabilities capabilities,
        ReadOnlySpan<byte> dnrcSource = default)
    {
        _routerId = routerId.ToArray();
        _routerEd25519PublicKey = routerEd25519PublicKey.ToArray();
        _dnrReference = dnrReference.ToArray();
        _mrl2 = mrl2.ToArray();
        var record = CanonicalGrammar.DecodeOwned(mrl2, RecordDefinitions.Mrl2);
        _fullMrlReference = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Mrl2, record.CanonicalSpan));
        _anchorDpcReference = record.FieldCopy(9);
        _dnrcSource = dnrcSource.ToArray();
        DescriptorGeneration = descriptorGeneration;
        Roles = roles;
        Capabilities = capabilities;
    }

    internal ReadOnlySpan<byte> RouterId => _routerId;
    internal ReadOnlySpan<byte> RouterEd25519PublicKey => _routerEd25519PublicKey;
    internal ReadOnlySpan<byte> DnrReference => _dnrReference;
    internal ReadOnlySpan<byte> Mrl2 => _mrl2;
    internal ReadOnlySpan<byte> FullMrlReference => _fullMrlReference;
    internal ReadOnlySpan<byte> AnchorDpcReference => _anchorDpcReference;
    internal ReadOnlySpan<byte> DnrcSource => _dnrcSource;
    internal ulong DescriptorGeneration { get; }
    internal RouterRoles Roles { get; }
    internal RouterCapabilities Capabilities { get; }

    internal VerifiedRouterEntry Clone() => new(
        _routerId, _routerEd25519PublicKey, _dnrReference, _mrl2,
        DescriptorGeneration, Roles, Capabilities, _dnrcSource);
}

/// <summary>A router certificate verified relative to exact mailbox, PMA and PMR facts.</summary>
public sealed class VerifiedRouterCertificateRelative
{
    private readonly byte[] _canonical;
    private readonly byte[] _reference;
    private readonly byte[] _routerId;
    private readonly byte[] _routerEd;
    private readonly byte[] _routerX;

    internal VerifiedRouterCertificateRelative(OwnedRecord record)
    {
        _canonical = record.CanonicalCopy();
        _reference = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Dnr1, record.CanonicalSpan));
        _routerId = record.FieldCopy(9);
        _routerEd = record.FieldCopy(11);
        _routerX = record.FieldCopy(12);
        RouterGeneration = Scalars.UInt64(record.FieldSpan(10));
        Roles = (RouterRoles)Scalars.UInt64(record.FieldSpan(14));
        Capabilities = (RouterCapabilities)Scalars.UInt64(record.FieldSpan(15));
        IssuedAtUnixSeconds = Scalars.UInt64(record.FieldSpan(16));
        ExpiresAtUnixSeconds = Scalars.UInt64(record.FieldSpan(17));
    }

    public ReadOnlyMemory<byte> CanonicalBytes => _canonical.ToArray();
    public ReadOnlyMemory<byte> ArtifactReference => _reference.ToArray();
    public ReadOnlyMemory<byte> RouterId => _routerId.ToArray();
    public ReadOnlyMemory<byte> RouterEd25519PublicKey => _routerEd.ToArray();
    public ReadOnlyMemory<byte> RouterX25519PublicKey => _routerX.ToArray();
    public ulong RouterGeneration { get; }
    public RouterRoles Roles { get; }
    public RouterCapabilities Capabilities { get; }
    public bool NoAuthorityClaim => true;
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
}

/// <summary>Sealed proof that one exact MRL2 row belongs to one exact verified MRLC root.</summary>
public sealed class VerifiedMrl2Membership
{
    private readonly byte[] _canonicalMailboxProof;
    private readonly byte[] _canonicalMrl2;
    private readonly byte[] _routerId;
    private readonly byte[] _routerEd25519PublicKey;
    private readonly byte[] _projectedLeaf;
    private readonly byte[] _fullMrlReference;

    internal VerifiedMrl2Membership(
        ReadOnlySpan<byte> canonicalMailboxProof,
        ReadOnlySpan<byte> canonicalMrl2,
        ReadOnlySpan<byte> routerId,
        ReadOnlySpan<byte> routerEd25519PublicKey,
        ReadOnlySpan<byte> projectedLeaf,
        ReadOnlySpan<byte> fullMrlReference,
        ulong epoch,
        ulong descriptorGeneration,
        RouterRoles roles,
        RouterCapabilities capabilities)
    {
        _canonicalMailboxProof = canonicalMailboxProof.ToArray();
        _canonicalMrl2 = canonicalMrl2.ToArray();
        _routerId = routerId.ToArray();
        _routerEd25519PublicKey = routerEd25519PublicKey.ToArray();
        _projectedLeaf = projectedLeaf.ToArray();
        _fullMrlReference = fullMrlReference.ToArray();
        Epoch = epoch;
        DescriptorGeneration = descriptorGeneration;
        Roles = roles;
        Capabilities = capabilities;
    }

    public ReadOnlyMemory<byte> CanonicalMailboxProof => _canonicalMailboxProof.ToArray();
    public ReadOnlyMemory<byte> CanonicalMrl2 => _canonicalMrl2.ToArray();
    public ReadOnlyMemory<byte> RouterId => _routerId.ToArray();
    public ReadOnlyMemory<byte> RouterEd25519PublicKey => _routerEd25519PublicKey.ToArray();
    public ReadOnlyMemory<byte> ProjectedLeafHash => _projectedLeaf.ToArray();
    public ReadOnlyMemory<byte> FullMrl2ArtifactReference => _fullMrlReference.ToArray();
    public ulong Epoch { get; }
    public ulong DescriptorGeneration { get; }
    public RouterRoles Roles { get; }
    public RouterCapabilities Capabilities { get; }
    public bool NoAuthorityClaim => true;

    internal ReadOnlySpan<byte> TrustedMrl2 => _canonicalMrl2;
    internal ReadOnlySpan<byte> TrustedRouterId => _routerId;
    internal ReadOnlySpan<byte> TrustedRouterEd25519PublicKey => _routerEd25519PublicKey;
}

/// <summary>Sealed exact DPC1 contact in one verified MRL2 contact chain.</summary>
public sealed class VerifiedRouterContact
{
    private readonly byte[] _canonical;
    private readonly byte[] _reference;
    private readonly byte[] _routerId;
    private readonly byte[] _address;
    private readonly byte[] _currentSpki;
    private readonly byte[] _nextSpki;
    private readonly byte[] _anchorReference;

    internal VerifiedRouterContact(
        OwnedRecord record,
        ReadOnlySpan<byte> anchorReference,
        ulong anchorGeneration)
    {
        _canonical = record.CanonicalCopy();
        _reference = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Dpc1, record.CanonicalSpan));
        _routerId = record.FieldCopy(2);
        Generation = Scalars.UInt64(record.FieldSpan(4));
        IssuedAtUnixSeconds = Scalars.UInt64(record.FieldSpan(6));
        ExpiresAtUnixSeconds = Scalars.UInt64(record.FieldSpan(7));
        Capabilities = (RouterCapabilities)Scalars.UInt64(record.FieldSpan(8));
        EndpointKind = (EndpointKind)record.FieldSpan(9)[0];
        _address = record.FieldCopy(10);
        Port = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(record.FieldSpan(11));
        _currentSpki = record.FieldCopy(12);
        _nextSpki = record.FieldCopy(13);
        _anchorReference = anchorReference.ToArray();
        AnchorGeneration = anchorGeneration;
        Flags = Scalars.UInt64(record.FieldSpan(14));
    }

    public ReadOnlyMemory<byte> CanonicalBytes => _canonical.ToArray();
    public ReadOnlyMemory<byte> ArtifactReference => _reference.ToArray();
    public ReadOnlyMemory<byte> RouterId => _routerId.ToArray();
    public ulong Generation { get; }
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public RouterCapabilities Capabilities { get; }
    public EndpointKind EndpointKind { get; }
    public ReadOnlyMemory<byte> Address => _address.ToArray();
    public ushort Port { get; }
    public ReadOnlyMemory<byte> CurrentTlsSpkiSha256 => _currentSpki.ToArray();
    public ReadOnlyMemory<byte> NextTlsSpkiSha256 => _nextSpki.ToArray();
    public ulong Flags { get; }

    internal ReadOnlySpan<byte> TrustedCanonical => _canonical;
    internal ReadOnlySpan<byte> TrustedReference => _reference;
    internal ReadOnlySpan<byte> TrustedAnchorReference => _anchorReference;
    internal ulong AnchorGeneration { get; }
}
