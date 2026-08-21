using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.Membership;
using Sodium;

namespace Deep.Protocol.DeepNative;

/// <summary>Genesis evidence verified relative to the existing P04 self-hosted pin contract.</summary>
public sealed class MembershipGenesisRelative
{
    private readonly byte[] _canonical;
    internal MembershipGenesisRelative(NetworkGenesis genesis, ReadOnlySpan<byte> canonical)
    {
        Genesis = genesis;
        _canonical = canonical.ToArray();
    }
    internal NetworkGenesis Genesis { get; }
    internal ReadOnlySpan<byte> TrustedCanonical => _canonical;
    public ReadOnlyMemory<byte> CanonicalGenesis => _canonical.ToArray();
    public bool NoAuthorityClaim => true;
}

/// <summary>Restores the exact independent membership and mailbox closures and joins them at MRL2.</summary>
public sealed class MembershipClosureVerifier
{
    private const string TransitionContainerDomain = "Deep/NativeRouting/V2/membership-transition-container";
    private const string MembershipClosureDomain = "Deep/NativeRouting/V2/membership-closure";
    private const string CompositeSelectionDomain = "Deep/NativeRouting/V2/composite-selection";
    private const string RouterCertificateDomain = "Deep/NativeRouting/V1/router-certificate";
    private const string RouterIdDomain = "Deep/NativeRouting/V1/router-id";

    public MembershipGenesisRelative VerifyGenesis(
        ReadOnlySpan<byte> canonicalGenesis,
        ReadOnlySpan<byte> expectedNetworkId,
        ReadOnlySpan<byte> expectedCanonicalGenesisSha256,
        IReadOnlyList<MembershipSignature> signatures,
        IMembershipSignatureVerifier signatureVerifier)
    {
        var frozen = canonicalGenesis.ToArray();
        var genesis = MembershipContractVerifier.ImportSelfHostedGenesis(
            frozen,
            expectedNetworkId,
            expectedCanonicalGenesisSha256,
            signatures,
            signatureVerifier);
        return new MembershipGenesisRelative(genesis, frozen);
    }

    public async ValueTask<VerifiedMembershipRoutingLkg> RestoreCurrentCompositeLkgAsync(
        ReadOnlyMemory<byte> canonicalMrlc,
        ReadOnlyMemory<byte> protectedStateKeyId32,
        RoutingHeadRestoreInput expectedCurrentHeads,
        CurrentCutoverRelative currentCutover,
        CurrentMailboxRoleRelative currentMailbox,
        IReadOnlyList<CurrentDnrcRelative> currentRouters,
        MembershipGenesisRelative genesis,
        VerifiedProductionMailboxAuthority mailboxAuthority,
        VerifiedProductionMailboxRevocationSnapshot mailboxRevocations,
        ulong transactionTimeUnixSeconds,
        uint allowedClockSkewSeconds,
        ushort protocolVersion,
        IMembershipSignatureVerifier membershipSignatureVerifier,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(expectedCurrentHeads);
        var result = await VerifyCompositeCoreAsync(
            canonicalMrlc, protectedStateKeyId32, currentCutover, currentMailbox, currentRouters,
            genesis, mailboxAuthority, mailboxRevocations, transactionTimeUnixSeconds,
            allowedClockSkewSeconds, protocolVersion, membershipSignatureVerifier, hmacProvider,
            cancellationToken, priorMembership: null, priorMailboxAuthority: null,
            restoreExpected: expectedCurrentHeads).ConfigureAwait(false);
        return result.Lkg;
    }

    public async ValueTask<CompositeRoutingCommitPlan> VerifyNextCompositeLkgAsync(
        ReadOnlyMemory<byte> canonicalMrlc,
        ReadOnlyMemory<byte> protectedStateKeyId32,
        VerifiedMembershipRoutingLkg current,
        CurrentCutoverRelative currentCutover,
        CurrentMailboxRoleRelative currentMailbox,
        IReadOnlyList<CurrentDnrcRelative> currentRouters,
        MembershipGenesisRelative genesis,
        VerifiedProductionMailboxAuthority mailboxAuthority,
        VerifiedProductionMailboxRevocationSnapshot mailboxRevocations,
        ulong transactionTimeUnixSeconds,
        uint allowedClockSkewSeconds,
        ushort protocolVersion,
        IMembershipSignatureVerifier membershipSignatureVerifier,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(current);
        if (current.MembershipHead is null || current.MailboxAuthorityHead is null)
            Invalid("The predecessor does not carry sealed routing heads.");
        var currentMembership = current.MembershipHead!;
        var currentMailboxAuthority = current.MailboxAuthorityHead!;
        var result = await VerifyCompositeCoreAsync(
            canonicalMrlc, protectedStateKeyId32, currentCutover, currentMailbox, currentRouters,
            genesis, mailboxAuthority, mailboxRevocations, transactionTimeUnixSeconds,
            allowedClockSkewSeconds, protocolVersion, membershipSignatureVerifier, hmacProvider,
            cancellationToken, currentMembership, currentMailboxAuthority,
            restoreExpected: null, predecessor: current).ConfigureAwait(false);
        return new CompositeRoutingCommitPlan(
            currentMembership, result.MembershipHead,
            currentMailboxAuthority, result.MailboxAuthorityHead,
            currentCutover, result.CurrentRouters, result.Lkg);
    }

    private async ValueTask<CompositeVerificationResult> VerifyCompositeCoreAsync(
        ReadOnlyMemory<byte> canonicalMrlc,
        ReadOnlyMemory<byte> protectedStateKeyId32,
        CurrentCutoverRelative currentCutover,
        CurrentMailboxRoleRelative currentMailbox,
        IReadOnlyList<CurrentDnrcRelative> currentRouters,
        MembershipGenesisRelative genesis,
        VerifiedProductionMailboxAuthority mailboxAuthority,
        VerifiedProductionMailboxRevocationSnapshot mailboxRevocations,
        ulong transactionTimeUnixSeconds,
        uint allowedClockSkewSeconds,
        ushort protocolVersion,
        IMembershipSignatureVerifier membershipSignatureVerifier,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken,
        MembershipHeadRelative? priorMembership,
        MailboxAuthorityHeadRelative? priorMailboxAuthority,
        RoutingHeadRestoreInput? restoreExpected,
        VerifiedMembershipRoutingLkg? predecessor = null)
    {
        ArgumentNullException.ThrowIfNull(currentCutover);
        ArgumentNullException.ThrowIfNull(currentMailbox);
        ArgumentNullException.ThrowIfNull(currentRouters);
        ArgumentNullException.ThrowIfNull(genesis);
        ArgumentNullException.ThrowIfNull(mailboxAuthority);
        ArgumentNullException.ThrowIfNull(mailboxRevocations);
        ArgumentNullException.ThrowIfNull(membershipSignatureVerifier);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();

        // Complete outer and MRC framing is bounded and frozen before any signature/HMAC callback.
        var pending = MembershipCatalogEnvelopeVerifier.Parse(
            canonicalMrlc.Span,
            protectedStateKeyId32.Span);
        var record = pending.Record;
        var catalog = pending.Catalog;
        Equal(record.FieldSpan(1), genesis.Genesis.NetworkId.Span, "MRLC network/genesis mismatch.");
        Equal(catalog.RowBytes(0), genesis.TrustedCanonical, "MRLC MNG1 bytes mismatch.");
        var orderedCurrentRouters = BindCurrentSourcesBeforeCallbacks(
            record, catalog, currentCutover, currentMailbox, currentRouters);
        if (predecessor is not null)
        {
            Equal(record.FieldSpan(1), predecessor.TrustedNetworkId,
                "MRLC predecessor network mismatch.");
            Equal(record.FieldSpan(2), predecessor.TrustedResetId,
                "MRLC predecessor reset mismatch.");
        }

        // Cold protected state is authenticated before any membership signature callback.
        _ = await MembershipCatalogEnvelopeVerifier.VerifyPendingAsync(
            pending,
            hmacProvider,
            cancellationToken).ConfigureAwait(false);

        var memberCount = BinaryPrimitives.ReadUInt32BigEndian(record.FieldSpan(13));
        var transitionCount = checked(catalog.Rows.Count - 5 - checked((int)(3 * memberCount)));
        var tail = 1 + transitionCount;
        var mmcBytes = catalog.RowBytes(tail);
        var msmBytes = catalog.RowBytes(tail + 1);
        var statement = MembershipContractCodec.DecodeMembershipSigningBytes(mmcBytes);
        var signed = MembershipContractCodec.DecodeSignedMembership(msmBytes);
        Equal(
            MembershipContractCodec.GetMembershipSigningBytes(signed.Statement),
            mmcBytes,
            "MRLC MMC1/MSM1 statement mismatch.");
        if (signed.Statement.Sequence == 0)
            Invalid("MRLC MSM1 sequence cannot be zero.");

        var pmaBytes = catalog.RowBytes(tail + 2);
        var pmrBytes = catalog.RowBytes(tail + 3);
        Equal(pmaBytes, ProductionMailboxAuthorityCodec.Encode(mailboxAuthority.Authority),
            "MRLC PMA1 bytes mismatch.");
        Equal(pmrBytes, ProductionMailboxRevocationSnapshotCodec.Encode(mailboxRevocations.Snapshot),
            "MRLC PMR1 bytes mismatch.");
        var pma = mailboxAuthority.Authority;
        var pmr = mailboxRevocations.Snapshot;
        Equal(record.FieldSpan(1), pma.NetworkId.Span, "MRLC PMA network mismatch.");
        Equal(record.FieldSpan(1), pmr.NetworkId.Span, "MRLC PMR network mismatch.");
        var pmaRef = RetainedReference(ArtifactType.Pma1, pmaBytes);
        var pmrRef = RetainedReference(ArtifactType.Pmr1, pmrBytes);
        Equal(record.FieldSpan(15), CanonicalGrammar.EncodeReference(pmaRef), "MRLC PMA reference mismatch.");
        Equal(record.FieldSpan(18), CanonicalGrammar.EncodeReference(pmrRef), "MRLC PMR reference mismatch.");
        if (Scalars.UInt64(record.FieldSpan(16)) != pma.AuthorityGeneration ||
            Scalars.UInt64(record.FieldSpan(17)) != pma.CurrentEpoch.Epoch ||
            Scalars.UInt64(record.FieldSpan(19)) != pmr.RevocationGeneration ||
            pmr.AuthorityGeneration != pma.AuthorityGeneration)
            Invalid("MRLC PMA/PMR scalar mismatch.");
        Equal(record.FieldSpan(20), pmr.RevocationHeadHash.Span, "MRLC PMR head mismatch.");
        Equal(record.FieldSpan(21), mailboxRevocations.CanonicalSnapshotHash.Span,
            "MRLC PMR snapshot hash mismatch.");

        var transitionHash = ComputeTransitionContainerHash(catalog, transitionCount);
        var mngRef = RetainedReference(ArtifactType.Mng1, genesis.TrustedCanonical);
        var msmRef = RetainedReference(ArtifactType.Msm1, msmBytes);
        var membershipHead = CreateMembershipHead(
            record.FieldSpan(1), mngRef, transitionHash, signed.Statement.Sequence,
            MembershipContractHash.Sha256(mmcBytes), msmRef);
        var mailboxHead = CreateMailboxAuthorityHead(record.FieldSpan(1), pmaRef, pma, pmrRef,
            pmr, mailboxAuthority.CanonicalAuthorityHash.Span,
            mailboxRevocations.CanonicalSnapshotHash.Span);
        ValidateMembershipHeadMode(priorMembership, restoreExpected, membershipHead);
        ValidateMailboxHeadMode(priorMailboxAuthority, restoreExpected, mailboxHead, pma, pmr);

        SignerDelegation currentDelegation;
        VerifiedSignerDelegation currentVerifiedDelegation;
        MembershipLastKnownGood currentDelegationLkg;
        IReadOnlyList<ReadOnlyMemory<byte>> revokedDelegations;
        VerifiedMembershipAuthorityChain authorityChain;
        var retainedAuthority = predecessor?.AuthorityChain;
        if (retainedAuthority is not null && CanonicalGrammar.FixedEquals(
                retainedAuthority.TransitionHash, transitionHash))
        {
            currentDelegation = retainedAuthority.ActiveDelegation;
            currentVerifiedDelegation = retainedAuthority.VerifiedDelegation;
            currentDelegationLkg = retainedAuthority.DelegationLastKnownGood;
            revokedDelegations = retainedAuthority.RevokedDelegationHashes;
            authorityChain = retainedAuthority;
        }
        else
        {
            var authorityLkg = new MembershipLastKnownGood
            {
                NetworkId = genesis.Genesis.NetworkId.ToArray(),
                PolicyVersion = genesis.Genesis.PolicyVersion,
                Sequence = genesis.Genesis.GenesisSequence,
                CanonicalHash = SHA256.HashData(genesis.TrustedCanonical)
            };
            SignerDelegation? activeDelegation = null;
            VerifiedSignerDelegation? activeVerifiedDelegation = null;
            MembershipLastKnownGood? activeDelegationLkg = null;
            var revoked = new List<ReadOnlyMemory<byte>>();
            for (var index = 0; index < transitionCount; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var rowIndex = 1 + index;
                var bytes = catalog.RowBytes(rowIndex);
                if (catalog.Rows[rowIndex].Type == ArtifactType.Mdg1)
                {
                    var delegation = MembershipContractCodec.DecodeSignedDelegation(bytes);
                    var verified = MembershipContractVerifier.VerifyDelegation(
                        delegation,
                        genesis.Genesis,
                        authorityLkg,
                        transactionTimeUnixSeconds,
                        allowedClockSkewSeconds,
                        protocolVersion,
                        membershipSignatureVerifier);
                    authorityLkg = verified.NextAuthorityLastKnownGood;
                    activeDelegation = verified.Statement;
                    activeVerifiedDelegation = verified;
                    activeDelegationLkg = new MembershipLastKnownGood
                    {
                        NetworkId = authorityLkg.NetworkId.ToArray(),
                        PolicyVersion = authorityLkg.PolicyVersion,
                        Sequence = authorityLkg.Sequence,
                        CanonicalHash = authorityLkg.CanonicalHash.ToArray()
                    };
                }
                else
                {
                    var revocation = MembershipContractCodec.DecodeSignedRevocation(bytes);
                    var verified = MembershipContractVerifier.VerifyRevocation(
                        revocation,
                        genesis.Genesis,
                        authorityLkg,
                        transactionTimeUnixSeconds,
                        allowedClockSkewSeconds,
                        protocolVersion,
                        membershipSignatureVerifier);
                    authorityLkg = verified.NextAuthorityLastKnownGood;
                    revoked.Add(verified.Statement.DelegationHash.ToArray());
                }
            }
            if (activeDelegation is null || activeVerifiedDelegation is null ||
                activeDelegationLkg is null)
                Invalid("MRLC has no active membership signer delegation.");
            currentDelegation = activeDelegation!;
            currentVerifiedDelegation = activeVerifiedDelegation!;
            currentDelegationLkg = activeDelegationLkg!;
            revokedDelegations = revoked;
            authorityChain = new VerifiedMembershipAuthorityChain(
                transitionHash, currentDelegation, currentVerifiedDelegation,
                currentDelegationLkg, revokedDelegations);
        }

        var membershipLkg = new MembershipLastKnownGood
        {
            NetworkId = signed.Statement.NetworkId.ToArray(),
            PolicyVersion = signed.Statement.PolicyVersion,
            Sequence = priorMembership?.Sequence ?? membershipHead.Sequence,
            CanonicalHash = priorMembership?.CanonicalHash.ToArray() ?? membershipHead.CanonicalHash.ToArray()
        };
        var membershipContext = new MembershipVerificationContext
            {
                Genesis = genesis.Genesis,
                ActiveDelegation = currentDelegation,
                // The complete transition chain was already walked above. The retained P04
                // verifier pins the signer to the delegation row itself, while the separate
                // revoked set carries every later MRV1 decision.
                AuthorityLastKnownGood = currentDelegationLkg,
                RevokedDelegationHashes = revokedDelegations,
                LastKnownGood = membershipLkg,
                VerificationTimeUnixSeconds = transactionTimeUnixSeconds,
                AllowedClockSkewSeconds = allowedClockSkewSeconds,
                ClientProtocol = protocolVersion
            };
        var verifiedMembership = restoreExpected is null
            ? MembershipContractVerifier.VerifyMembershipFromVerifiedDelegation(
                signed, membershipContext, currentVerifiedDelegation,
                membershipSignatureVerifier)
            : MembershipContractVerifier.RestoreCurrentMembership(
                signed, membershipContext, currentVerifiedDelegation,
                membershipHead.Sequence,
                membershipHead.CanonicalHash, membershipSignatureVerifier);
        Equal(
            MembershipContractCodec.GetMembershipSigningBytes(verifiedMembership.Statement),
            MembershipContractCodec.GetMembershipSigningBytes(statement),
            "MRLC membership statement mismatch.");

        Equal(record.FieldSpan(9), CanonicalGrammar.EncodeReference(mngRef), "MRLC MNG1 reference mismatch.");
        Equal(record.FieldSpan(11), CanonicalGrammar.EncodeReference(msmRef), "MRLC MSM1 reference mismatch.");
        if (Scalars.UInt64(record.FieldSpan(12)) != signed.Statement.Sequence ||
            memberCount != signed.Statement.MemberCount)
            Invalid("MRLC MSM sequence or member count mismatch.");
        Equal(record.FieldSpan(14), signed.Statement.MerkleRoot.Span, "MRLC MRL root mismatch.");
        Equal(pma.CurrentEpoch.MembershipCommitment.Span, signed.Statement.MerkleRoot.Span,
            "The independent membership and PMA closures do not join at the MRL2 root.");
        Span<byte> membershipClosureInput = stackalloc byte[108];
        CanonicalGrammar.EncodeReference(mngRef).CopyTo(membershipClosureInput[..38]);
        transitionHash.CopyTo(membershipClosureInput[38..70]);
        CanonicalGrammar.EncodeReference(msmRef).CopyTo(membershipClosureInput[70..108]);
        Equal(record.FieldSpan(10), CanonicalGrammar.Sha256Domain(
            MembershipClosureDomain,
            membershipClosureInput), "MRLC membership closure hash mismatch.");

        var routers = new List<VerifiedRouterEntry>(checked((int)memberCount));
        const int memberTupleLength = 32 + ArtifactReference.Length * 3;
        var memberTuples = new byte[checked(memberCount * memberTupleLength)];
        ReadOnlySpan<byte> previousRouter = default;
        for (var member = 0; member < memberCount; member++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var rowIndex = tail + 4 + checked((int)(member * 3));
            var dnrBytes = catalog.RowBytes(rowIndex);
            var mrlBytes = catalog.RowBytes(rowIndex + 1);
            var dpcBytes = catalog.RowBytes(rowIndex + 2);
            var dnr = VerifyCatalogRouterCertificate(dnrBytes, pma, pmr, pmaRef, pmrRef,
                transactionTimeUnixSeconds);
            var currentDnrc = orderedCurrentRouters[checked((int)member)];
            Equal(dnrBytes, currentDnrc.Certificate.CanonicalBytes.Span,
                "MRLC DNR1 differs from its sealed current DNRC fact.");
            if (!ReferenceEquals(currentDnrc.Mailbox, currentMailbox) ||
                !CanonicalGrammar.FixedEquals(
                    currentDnrc.MailboxAuthorityHead.TrustedTuple,
                    mailboxHead.TrustedTuple))
                Invalid("MRLC DNRC facts belong to a different sealed source.");
            var mrl = CanonicalGrammar.DecodeOwned(mrlBytes, RecordDefinitions.Mrl2);
            Equal(mrl.FieldSpan(1), record.FieldSpan(1), "MRL2 network mismatch.");
            if (Scalars.UInt64(mrl.FieldSpan(2)) != pma.CurrentEpoch.Epoch ||
                Scalars.UInt64(mrl.FieldSpan(3)) != dnr.RouterGeneration)
                Invalid("MRL2 epoch or generation mismatch.");
            Equal(mrl.FieldSpan(4), dnr.RouterId.Span, "MRL2 router ID mismatch.");
            Equal(mrl.FieldSpan(5), dnr.ArtifactReference.Span, "MRL2 DNR1 reference mismatch.");
            if (Scalars.UInt64(mrl.FieldSpan(6)) != (ulong)dnr.Roles ||
                Scalars.UInt64(mrl.FieldSpan(7)) != (ulong)dnr.Capabilities)
                Invalid("MRL2 roles/capabilities mismatch.");
            ValidateMrlPredecessor(mrl, dnr.RouterId.Span, predecessor);
            if (member != 0 && previousRouter.SequenceCompareTo(dnr.RouterId.Span) >= 0)
                Invalid("MRLC router tuples are not strictly router-ID sorted.");
            previousRouter = dnr.RouterId.Span;
            var tuple = memberTuples.AsSpan(
                checked((int)member * memberTupleLength), memberTupleLength);
            dnr.RouterId.Span.CopyTo(tuple[..32]);
            dnr.ArtifactReference.Span.CopyTo(tuple[32..70]);
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Mrl2, mrlBytes)).CopyTo(tuple[70..108]);
            mrl.FieldSpan(9).CopyTo(tuple[108..146]);
            var proofFact = new VerifiedMrl2Membership(
                Array.Empty<byte>(), mrlBytes, dnr.RouterId.Span, dnr.RouterEd25519PublicKey.Span,
                NativeMembershipVerifier.RealLeaf(
                    record.FieldSpan(2), pma.CurrentEpoch.Epoch, dnr.RouterGeneration,
                    checked((uint)member), mrlBytes),
                CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                    ArtifactType.Mrl2, mrlBytes)),
                pma.CurrentEpoch.Epoch, dnr.RouterGeneration, dnr.Roles, dnr.Capabilities);
            _ = new NativeRoutingVerifier().VerifyAnchorContact(
                proofFact,
                dpcBytes,
                transactionTimeUnixSeconds);
            routers.Add(new VerifiedRouterEntry(
                dnr.RouterId.Span,
                dnr.RouterEd25519PublicKey.Span,
                dnr.ArtifactReference.Span,
                mrlBytes,
                dnr.RouterGeneration,
                dnr.Roles,
                dnr.Capabilities,
                currentDnrc.SourceFingerprint.Span));
        }

        var computedRoot = ComputeMrlRoot(record.FieldSpan(2), pma.CurrentEpoch.Epoch, routers);
        Equal(computedRoot, record.FieldSpan(14), "MRLC recomputed MRL2 root mismatch.");
        var selection = ComputeCompositeSelection(record, msmRef, pmaRef, pmrRef, memberTuples);
        Equal(selection, record.FieldSpan(22), "MRLC composite selection mismatch.");
        var mrlcRef = CanonicalGrammar.EncodeReference(
            CanonicalGrammar.ComputeReference(ArtifactType.Mrlc, record.CanonicalSpan));
        var lkg = new VerifiedMembershipRoutingLkg(
            record.FieldSpan(1),
            record.FieldSpan(2),
            signed.Statement.Sequence,
            pma.CurrentEpoch.Epoch,
            pma.CurrentEpoch.NotAfterUnixSeconds,
            record.FieldSpan(14),
            pma.CurrentEpoch.TopologyPlacementCommitment.Span,
            routers,
            membershipHead,
            mailboxHead,
            selection,
            mrlcRef,
            authorityChain);
        return new CompositeVerificationResult(lkg, membershipHead, mailboxHead, orderedCurrentRouters);
    }

    private static CurrentDnrcRelative[] BindCurrentSourcesBeforeCallbacks(
        OwnedRecord record,
        OwnedMembershipCatalog catalog,
        CurrentCutoverRelative cutover,
        CurrentMailboxRoleRelative mailbox,
        IReadOnlyList<CurrentDnrcRelative> routers)
    {
        VerifyCurrentCutoverSourceAxes(
            cutover,
            mailbox,
            record.FieldSpan(1),
            record.FieldSpan(2),
            record.FieldSpan(3),
            record.FieldSpan(4),
            record.FieldSpan(5),
            record.FieldSpan(6),
            record.FieldSpan(7),
            record.FieldSpan(8));
        var memberCount = BinaryPrimitives.ReadUInt32BigEndian(record.FieldSpan(13));
        var transitionCount = checked(catalog.Rows.Count - 5 - checked((int)(3 * memberCount)));
        var firstRouter = 1 + transitionCount + 4;
        return BindCurrentRouterFactSetBeforeCallbacks(
            memberCount, catalog, firstRouter, cutover, mailbox, routers);
    }

    internal static CurrentDnrcRelative[] BindCurrentRouterFactSetBeforeCallbacks(
        uint memberCount,
        OwnedMembershipCatalog catalog,
        int firstRouter,
        CurrentCutoverRelative cutover,
        CurrentMailboxRoleRelative mailbox,
        IReadOnlyList<CurrentDnrcRelative> routers)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(cutover);
        ArgumentNullException.ThrowIfNull(mailbox);
        ArgumentNullException.ThrowIfNull(routers);
        if (memberCount is < 1 or > 4_096 || routers.Count != (int)memberCount)
            Invalid("MRLC current DNRC fact count mismatch.");
        if (firstRouter < 0 ||
            firstRouter > catalog.Rows.Count - checked((int)(3 * memberCount)))
            Invalid("MRLC current DNRC catalog range is invalid.");
        var byReference = new Dictionary<string, CurrentDnrcRelative>(StringComparer.Ordinal);
        foreach (var fact in routers)
        {
            var current = fact ?? throw new RecordException(
                RecordError.InvalidField, "A current DNRC fact is null.");
            if (!ReferenceEquals(current.Mailbox, mailbox) || !ReferenceEquals(current.Mailbox.Cutover, cutover))
                Invalid("A current DNRC fact belongs to a mixed source.");
            var key = Convert.ToHexString(current.DnrArtifactReference.Span);
            if (!byReference.TryAdd(key, current)) Invalid("Current DNRC facts contain a duplicate.");
        }
        var ordered = new CurrentDnrcRelative[routers.Count];
        for (var index = 0; index < ordered.Length; index++)
        {
            var dnrBytes = catalog.RowBytes(firstRouter + index * 3);
            var reference = CanonicalGrammar.EncodeReference(
                CanonicalGrammar.ComputeReference(ArtifactType.Dnr1, dnrBytes));
            if (!byReference.Remove(Convert.ToHexString(reference), out var current))
                Invalid("The catalog has no matching current DNRC fact.");
            var exactCurrent = current!;
            Equal(dnrBytes, exactCurrent.Certificate.CanonicalBytes.Span,
                "A current DNRC fact does not match the exact catalog DNR1.");
            ordered[index] = exactCurrent;
        }
        if (byReference.Count != 0) Invalid("An unused current DNRC fact was supplied.");
        return ordered;
    }

    internal static void VerifyCurrentCutoverSourceAxes(
        CurrentCutoverRelative cutover,
        CurrentMailboxRoleRelative mailbox,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> resetId,
        ReadOnlySpan<byte> dcpRef,
        ReadOnlySpan<byte> dcsRef,
        ReadOnlySpan<byte> dcqRef,
        ReadOnlySpan<byte> dwlRef,
        ReadOnlySpan<byte> drsRevision,
        ReadOnlySpan<byte> drsRef)
    {
        if (!ReferenceEquals(mailbox.Cutover, cutover))
            Invalid("The current mailbox fact belongs to a different cutover source.");
        Equal(network, cutover.TrustedNetwork, "MRLC cutover network mismatch.");
        Equal(resetId, cutover.TrustedResetId, "MRLC cutover reset mismatch.");
        Equal(dcpRef, cutover.TrustedDcpRef, "MRLC DCP mismatch.");
        Equal(dcsRef, cutover.TrustedDcsRef, "MRLC DCS mismatch.");
        Equal(dcqRef, cutover.TrustedDcqRef, "MRLC DCQ mismatch.");
        Equal(dwlRef, cutover.TrustedDwlRef, "MRLC DWL mismatch.");
        if (Scalars.UInt64(drsRevision) != cutover.DrsRevision)
            Invalid("MRLC DRS revision mismatch.");
        Equal(drsRef, cutover.TrustedDrsRef, "MRLC DRS reference mismatch.");
    }

    private static MembershipHeadRelative CreateMembershipHead(
        ReadOnlySpan<byte> network,
        ArtifactReference mng,
        ReadOnlySpan<byte> transitionHash,
        ulong sequence,
        ReadOnlySpan<byte> canonicalHash,
        ArtifactReference msm)
    {
        var tuple = new byte[164];
        network.CopyTo(tuple);
        CanonicalGrammar.EncodeReference(mng).CopyTo(tuple, 16);
        transitionHash.CopyTo(tuple.AsSpan(54));
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(86, 8), sequence);
        canonicalHash.CopyTo(tuple.AsSpan(94));
        CanonicalGrammar.EncodeReference(msm).CopyTo(tuple, 126);
        return new MembershipHeadRelative(tuple);
    }

    private static MailboxAuthorityHeadRelative CreateMailboxAuthorityHead(
        ReadOnlySpan<byte> network,
        ArtifactReference pmaRef,
        ProductionMailboxAuthority pma,
        ArtifactReference pmrRef,
        ProductionMailboxRevocationSnapshot pmr,
        ReadOnlySpan<byte> pmaHash,
        ReadOnlySpan<byte> pmrHash)
    {
        var tuple = new byte[204];
        network.CopyTo(tuple);
        CanonicalGrammar.EncodeReference(pmaRef).CopyTo(tuple, 16);
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(54, 8), pma.AuthorityGeneration);
        pmaHash.CopyTo(tuple.AsSpan(62));
        CanonicalGrammar.EncodeReference(pmrRef).CopyTo(tuple, 94);
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(132, 8), pmr.RevocationGeneration);
        pmr.RevocationHeadHash.Span.CopyTo(tuple.AsSpan(140));
        pmrHash.CopyTo(tuple.AsSpan(172));
        return new MailboxAuthorityHeadRelative(tuple);
    }

    private static void ValidateMembershipHeadMode(
        MembershipHeadRelative? prior,
        RoutingHeadRestoreInput? restore,
        MembershipHeadRelative candidate)
    {
        if (restore is not null)
        {
            Equal(candidate.TrustedTuple, restore.MembershipTuple,
                "MRLC current membership head differs from protected restore state.");
            return;
        }
        if (prior is null || prior.Sequence == ulong.MaxValue || candidate.Sequence != prior.Sequence + 1)
            Invalid("MRLC membership head does not advance by exactly one.");
    }

    private static void ValidateMailboxHeadMode(
        MailboxAuthorityHeadRelative? prior,
        RoutingHeadRestoreInput? restore,
        MailboxAuthorityHeadRelative candidate,
        ProductionMailboxAuthority pma,
        ProductionMailboxRevocationSnapshot pmr)
    {
        if (restore is not null)
        {
            Equal(candidate.TrustedTuple, restore.MailboxAuthorityTuple,
                "MRLC current mailbox authority head differs from protected restore state.");
            return;
        }
        if (prior is null || prior.PmaGeneration == ulong.MaxValue ||
            candidate.PmaGeneration != prior.PmaGeneration + 1 ||
            !CanonicalGrammar.FixedEquals(pma.PreviousAuthorityHash.Span, prior.PmaCanonicalHash))
            Invalid("MRLC PMA head does not advance from the exact predecessor.");
        var exactPrior = prior!;
        if (candidate.PmrGeneration == exactPrior.PmrGeneration)
        {
            if (!CanonicalGrammar.FixedEquals(candidate.PmrHead, exactPrior.PmrHead))
                Invalid("MRLC same-generation PMR head changed.");
        }
        else if (exactPrior.PmrGeneration == ulong.MaxValue || candidate.PmrGeneration != exactPrior.PmrGeneration + 1 ||
                 !CanonicalGrammar.FixedEquals(pmr.PreviousRevocationHeadHash.Span, exactPrior.PmrHead))
            Invalid("MRLC PMR head neither replays nor advances from the exact predecessor.");
    }

    private sealed record CompositeVerificationResult(
        VerifiedMembershipRoutingLkg Lkg,
        MembershipHeadRelative MembershipHead,
        MailboxAuthorityHeadRelative MailboxAuthorityHead,
        IReadOnlyList<CurrentDnrcRelative> CurrentRouters);

    private static VerifiedRouterCertificateRelative VerifyCatalogRouterCertificate(
        ReadOnlySpan<byte> canonical,
        ProductionMailboxAuthority pma,
        ProductionMailboxRevocationSnapshot pmr,
        ArtifactReference pmaRef,
        ArtifactReference pmrRef,
        ulong now)
    {
        var record = CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dnr1);
        VerifyRouterAuthorityBindingBeforeSignatures(
            record,
            pma.NetworkId.Span,
            CanonicalGrammar.EncodeReference(pmaRef),
            pma.AuthorityGeneration,
            CanonicalGrammar.EncodeReference(pmrRef),
            pmr.RevocationGeneration,
            pma.MailboxIssuerEd25519PublicKey.Span);
        Span<byte> idInput = stackalloc byte[88];
        record.FieldSpan(1).CopyTo(idInput[..16]);
        record.FieldSpan(2).CopyTo(idInput[16..48]);
        record.FieldSpan(10).CopyTo(idInput[48..56]);
        record.FieldSpan(11).CopyTo(idInput[56..88]);
        Equal(record.FieldSpan(9), CanonicalGrammar.Sha256Domain(RouterIdDomain, idInput),
            "DNR1 router ID mismatch.");
        var issued = Scalars.UInt64(record.FieldSpan(16));
        var expires = Scalars.UInt64(record.FieldSpan(17));
        if (issued >= expires || issued < Math.Max(pma.CurrentEpoch.NotBeforeUnixSeconds, pmr.IssuedAtUnixSeconds) ||
            expires > Math.Min(pma.CurrentEpoch.NotAfterUnixSeconds, pmr.ExpiresAtUnixSeconds) ||
            now < issued || now >= expires)
            throw new RecordException(RecordError.Expired, "DNR1 is outside the closure window.");
        var signing = CanonicalGrammar.GetSigningBytes(record, RouterCertificateDomain);
        VerifyDetached(record.FieldSpan(20), signing, record.FieldSpan(11));
        VerifyDetached(record.FieldSpan(21), signing, pma.MailboxIssuerEd25519PublicKey.Span);
        return new VerifiedRouterCertificateRelative(record);
    }

    internal static void VerifyRouterAuthorityBindingBeforeSignatures(
        OwnedRecord record,
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> pmaReference,
        ulong pmaGeneration,
        ReadOnlySpan<byte> pmrReference,
        ulong pmrGeneration,
        ReadOnlySpan<byte> mailboxIssuerEd25519PublicKey)
    {
        ArgumentNullException.ThrowIfNull(record);
        Equal(record.FieldSpan(1), network, "DNR1 network mismatch.");
        Equal(record.FieldSpan(4), pmaReference, "DNR1 PMA mismatch.");
        Equal(record.FieldSpan(6), pmrReference, "DNR1 PMR mismatch.");
        if (Scalars.UInt64(record.FieldSpan(5)) != pmaGeneration ||
            Scalars.UInt64(record.FieldSpan(7)) != pmrGeneration)
            Invalid("DNR1 authority generation mismatch.");
        Equal(record.FieldSpan(8), SHA256.HashData(mailboxIssuerEd25519PublicKey),
            "DNR1 issuer-key hash mismatch.");
    }

    private static byte[] ComputeMrlRoot(
        ReadOnlySpan<byte> resetId,
        ulong epoch,
        IReadOnlyList<VerifiedRouterEntry> routers)
    {
        var padded = 1;
        while (padded < routers.Count) padded <<= 1;
        var level = new byte[padded][];
        for (var index = 0; index < padded; index++)
            level[index] = index < routers.Count
                ? NativeMembershipVerifier.RealLeaf(
                    resetId, epoch, routers[index].DescriptorGeneration,
                    checked((uint)index), routers[index].Mrl2)
                : NativeMembershipVerifier.EmptyLeaf(resetId, epoch, checked((uint)index));
        ushort treeLevel = 0;
        while (level.Length > 1)
        {
            var next = new byte[level.Length / 2][];
            for (var index = 0; index < next.Length; index++)
                next[index] = NativeMembershipVerifier.Node(
                    treeLevel,
                    checked((uint)index),
                    level[index * 2],
                    level[index * 2 + 1]);
            level = next;
            treeLevel++;
        }
        return NativeMembershipVerifier.Root(
            resetId, epoch, checked((uint)routers.Count), checked((uint)padded), level[0]);
    }

    private static void ValidateMrlPredecessor(
        OwnedRecord mrl,
        ReadOnlySpan<byte> routerId,
        VerifiedMembershipRoutingLkg? predecessor)
    {
        var generation = Scalars.UInt64(mrl.FieldSpan(3));
        if (generation == 0)
            Invalid("MRL2 descriptor generation is zero.");
        if (generation == 1)
        {
            if (!CanonicalGrammar.IsZero(mrl.FieldSpan(12)))
                Invalid("A genesis MRL2 has a predecessor.");
            return;
        }
        if (predecessor is null)
            Invalid("A successor MRL2 requires the sealed prior full-MRL2 LKG.");
        VerifiedRouterEntry? previous = null;
        foreach (var candidate in predecessor!.TrustedRouters)
        {
            if (!CanonicalGrammar.FixedEquals(candidate.RouterId, routerId)) continue;
            if (previous is not null) Invalid("The predecessor LKG has a duplicate router ID.");
            previous = candidate;
        }
        if (previous is null || previous.DescriptorGeneration == ulong.MaxValue ||
            generation != previous.DescriptorGeneration + 1)
            Invalid("MRL2 does not advance the sealed descriptor generation by one.");
        Equal(mrl.FieldSpan(12), previous!.FullMrlReference,
            "MRL2 predecessor does not match the exact prior full row.");
    }

    private static byte[] ComputeTransitionContainerHash(
        OwnedMembershipCatalog catalog,
        int transitionCount)
    {
        var payloadLength = 2;
        for (var index = 0; index < transitionCount; index++)
            payloadLength = checked(payloadLength + 38 + catalog.RowBytes(index + 1).Length);
        using var hash = DomainHash(TransitionContainerDomain, checked((uint)payloadLength));
        Span<byte> scalar = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(scalar[..2], checked((ushort)transitionCount));
        hash.AppendData(scalar[..2]);
        for (var index = 0; index < transitionCount; index++)
        {
            var row = catalog.Rows[index + 1];
            BinaryPrimitives.WriteUInt16BigEndian(scalar[..2], (ushort)row.Type);
            hash.AppendData(scalar[..2]);
            BinaryPrimitives.WriteUInt32BigEndian(scalar, checked((uint)row.CanonicalLength));
            hash.AppendData(scalar);
            hash.AppendData(row.CanonicalHash.Span);
            hash.AppendData(catalog.RowBytes(index + 1));
        }
        return hash.GetHashAndReset();
    }

    private static byte[] ComputeCompositeSelection(
        OwnedRecord record,
        ArtifactReference msm,
        ArtifactReference pma,
        ArtifactReference pmr,
        ReadOnlySpan<byte> orderedMemberTuples)
        => ComputeCompositeSelectionTranscript(
            record.FieldSpan(1),
            CanonicalGrammar.EncodeReference(msm),
            record.FieldSpan(12),
            record.FieldSpan(13),
            record.FieldSpan(14),
            CanonicalGrammar.EncodeReference(pma),
            record.FieldSpan(16),
            record.FieldSpan(17),
            CanonicalGrammar.EncodeReference(pmr),
            record.FieldSpan(19),
            record.FieldSpan(20),
            record.FieldSpan(21),
            orderedMemberTuples);

    internal static byte[] ComputeCompositeSelectionTranscript(
        ReadOnlySpan<byte> network,
        ReadOnlySpan<byte> msmRef,
        ReadOnlySpan<byte> sequence,
        ReadOnlySpan<byte> memberCount,
        ReadOnlySpan<byte> root,
        ReadOnlySpan<byte> pmaRef,
        ReadOnlySpan<byte> pmaGeneration,
        ReadOnlySpan<byte> pmaEpoch,
        ReadOnlySpan<byte> pmrRef,
        ReadOnlySpan<byte> pmrGeneration,
        ReadOnlySpan<byte> pmrHead,
        ReadOnlySpan<byte> pmrSnapshot,
        ReadOnlySpan<byte> orderedMemberTuples)
    {
        const int memberTupleLength = 32 + ArtifactReference.Length * 3;
        if (network.Length != 16 || msmRef.Length != ArtifactReference.Length ||
            sequence.Length != 8 || memberCount.Length != 4 || root.Length != 32 ||
            pmaRef.Length != ArtifactReference.Length || pmaGeneration.Length != 8 ||
            pmaEpoch.Length != 8 || pmrRef.Length != ArtifactReference.Length ||
            pmrGeneration.Length != 8 || pmrHead.Length != 32 || pmrSnapshot.Length != 32)
            Invalid("The composite-selection transcript width is invalid.");
        var count = BinaryPrimitives.ReadUInt32BigEndian(memberCount);
        if (count > int.MaxValue || orderedMemberTuples.Length !=
            checked((int)count * memberTupleLength))
            Invalid("The composite-selection member tuple count is invalid.");
        ReadOnlySpan<byte> priorRouter = default;
        for (var index = 0; index < count; index++)
        {
            var tuple = orderedMemberTuples.Slice(checked((int)index * memberTupleLength),
                memberTupleLength);
            var router = tuple[..32];
            if (CanonicalGrammar.IsZero(router) ||
                !priorRouter.IsEmpty && priorRouter.SequenceCompareTo(router) >= 0 ||
                CanonicalGrammar.DecodeReference(tuple.Slice(32, 38)).Type != ArtifactType.Dnr1 ||
                CanonicalGrammar.DecodeReference(tuple.Slice(70, 38)).Type != ArtifactType.Mrl2 ||
                CanonicalGrammar.DecodeReference(tuple.Slice(108, 38)).Type != ArtifactType.Dpc1)
                Invalid("The composite-selection member tuple is not closed and ordered.");
            priorRouter = router;
        }
        var length = checked(16 + 38 + 8 + 4 + 32 + 38 + 8 + 8 + 38 + 8 + 32 + 32 +
            orderedMemberTuples.Length);
        using var hash = DomainHash(CompositeSelectionDomain, checked((uint)length));
        hash.AppendData(network);
        hash.AppendData(msmRef);
        hash.AppendData(sequence);
        hash.AppendData(memberCount);
        hash.AppendData(root);
        hash.AppendData(pmaRef);
        hash.AppendData(pmaGeneration);
        hash.AppendData(pmaEpoch);
        hash.AppendData(pmrRef);
        hash.AppendData(pmrGeneration);
        hash.AppendData(pmrHead);
        hash.AppendData(pmrSnapshot);
        hash.AppendData(orderedMemberTuples);
        return hash.GetHashAndReset();
    }

    private static IncrementalHash DomainHash(string domain, uint payloadLength)
    {
        var domainBytes = Encoding.ASCII.GetBytes(domain);
        var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> scalar = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(scalar[..2], checked((ushort)domainBytes.Length));
        hash.AppendData(scalar[..2]);
        hash.AppendData(domainBytes);
        BinaryPrimitives.WriteUInt32BigEndian(scalar, payloadLength);
        hash.AppendData(scalar);
        return hash;
    }

    private static ArtifactReference RetainedReference(ArtifactType type, ReadOnlySpan<byte> bytes) =>
        new(type, checked((uint)bytes.Length), SHA256.HashData(bytes));

    private static void VerifyDetached(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> publicKey)
    {
        try
        {
            if (!PublicKeyAuth.VerifyDetached(signature.ToArray(), message.ToArray(), publicKey.ToArray()))
                throw new CryptographicException();
        }
        catch (CryptographicException)
        {
            throw new RecordException(RecordError.InvalidSignature,
                "A native routing signature is invalid.");
        }
    }

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string message)
    {
        if (!CanonicalGrammar.FixedEquals(actual, expected)) Invalid(message);
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
