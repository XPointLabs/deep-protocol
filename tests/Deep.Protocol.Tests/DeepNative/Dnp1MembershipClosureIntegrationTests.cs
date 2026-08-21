using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.Tests.DeepExtension;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class MembershipClosureIntegrationTests
{
    private const ulong Now = 1010;
    private static readonly byte[] HmacKey = Bytes(0xe1,32);

    [Fact]
    public void CompositeSelection_RequiresFullOrderedRouterDnrMrlAndDpcTuples()
    {
        var network = Bytes(1, 16);
        var msm = Ref(ArtifactType.Msm1, 512, 2);
        var pma = Ref(ArtifactType.Pma1, 256, 3);
        var pmr = Ref(ArtifactType.Pmr1, 192, 4);
        var tuples = Combine(
            Bytes(0x10, 32), Ref(ArtifactType.Dnr1, 756, 0x11),
            Ref(ArtifactType.Mrl2, 298, 0x12), Ref(ArtifactType.Dpc1, 430, 0x13),
            Bytes(0x20, 32), Ref(ArtifactType.Dnr1, 756, 0x21),
            Ref(ArtifactType.Mrl2, 298, 0x22), Ref(ArtifactType.Dpc1, 430, 0x23));
        var expected = MembershipClosureVerifier.ComputeCompositeSelectionTranscript(
            network, msm, U64(7), U32(2), Bytes(5, 32), pma, U64(7), U64(9),
            pmr, U64(6), Bytes(6, 32), Bytes(7, 32), tuples);

        // A DNR-only reduced identity is not the governed 146-byte member tuple.
        Assert.Equal(RecordError.InvalidField, Assert.Throws<RecordException>(() =>
            MembershipClosureVerifier.ComputeCompositeSelectionTranscript(
                network, msm, U64(7), U32(2), Bytes(5, 32), pma, U64(7), U64(9),
                pmr, U64(6), Bytes(6, 32), Bytes(7, 32),
                Combine(Bytes(0x10, 32), Ref(ArtifactType.Dnr1, 756, 0x11),
                    Bytes(0x20, 32), Ref(ArtifactType.Dnr1, 756, 0x21)))).Error);

        foreach (var offset in new[] { 0, 38, 76, 114 })
        {
            var substituted = tuples.ToArray();
            substituted[offset] ^= 0x01;
            var actual = MembershipClosureVerifier.ComputeCompositeSelectionTranscript(
                network, msm, U64(7), U32(2), Bytes(5, 32), pma, U64(7), U64(9),
                pmr, U64(6), Bytes(6, 32), Bytes(7, 32), substituted);
            Assert.NotEqual(expected, actual);
        }

        var reordered = Combine(tuples.AsSpan(146, 146).ToArray(), tuples.AsSpan(0, 146).ToArray());
        Assert.Equal(RecordError.InvalidField, Assert.Throws<RecordException>(() =>
            MembershipClosureVerifier.ComputeCompositeSelectionTranscript(
                network, msm, U64(7), U32(2), Bytes(5, 32), pma, U64(7), U64(9),
                pmr, U64(6), Bytes(6, 32), Bytes(7, 32), reordered)).Error);
    }

    [Fact]
    public void CurrentCutoverSourceAxes_RejectEveryCrossFeedBeforeCallbacks()
    {
        var network = Bytes(0x31, 16);
        var reset = Bytes(0x32, 32);
        var mailbox = CurrentMailbox(network, reset, out var cutover, out _, out _);
        var exact = new[]
        {
            cutover.TrustedNetwork.ToArray(),
            cutover.TrustedResetId.ToArray(),
            cutover.TrustedDcpRef.ToArray(),
            cutover.TrustedDcsRef.ToArray(),
            cutover.TrustedDcqRef.ToArray(),
            cutover.TrustedDwlRef.ToArray(),
            U64(cutover.DrsRevision),
            cutover.TrustedDrsRef.ToArray()
        };

        VerifyCurrentCutoverSourceAxes(cutover, mailbox, exact);
        for (var field = 0; field < exact.Length; field++)
        {
            var crossed = exact.Select(static value => value.ToArray()).ToArray();
            crossed[field][0] ^= 0x01;
            Assert.Equal(RecordError.InvalidField, Assert.Throws<RecordException>(() =>
                VerifyCurrentCutoverSourceAxes(cutover, mailbox, crossed)).Error);
        }

        var otherMailbox = CurrentMailbox(network, reset, out _, out _, out _);
        Assert.Equal(RecordError.InvalidField, Assert.Throws<RecordException>(() =>
            VerifyCurrentCutoverSourceAxes(cutover, otherMailbox, exact)).Error);
    }

    private static void VerifyCurrentCutoverSourceAxes(
        CurrentCutoverRelative cutover,
        CurrentMailboxRoleRelative mailbox,
        byte[][] axes) =>
        MembershipClosureVerifier.VerifyCurrentCutoverSourceAxes(
            cutover, mailbox, axes[0], axes[1], axes[2], axes[3],
            axes[4], axes[5], axes[6], axes[7]);

    [Fact]
    public async Task RestoreCurrent_RealCompositeClosure_BindsProjectionFullRefsAndCurrentSources()
    {
        var network = MembershipFixtures.Genesis().NetworkId.ToArray();
        var reset = Bytes(0x91,32);
        var routerEd = PublicKeyAuth.GenerateKeyPair();
        var routerXPrivate = Bytes(0x92,32);
        var routerX = ScalarMult.Base(routerXPrivate);
        var mailbox = CurrentMailbox(network, reset, out var cutover, out _, out _);
        var projectedRouterId = Domain("Deep/NativeRouting/V1/router-id",
            Combine(network,mailbox.MailboxOwnerId.ToArray(),U64(1),routerEd.PublicKey));
        var projectedMrl = Mrl(network, projectedRouterId,
            Ref(ArtifactType.Dnr1,756,0x94), Ref(ArtifactType.Dpc1,430,0x95));
        var projectedLeaf = NativeMembershipVerifier.RealLeaf(reset,9,1,0,projectedMrl);
        var root = NativeMembershipVerifier.Root(reset,9,1,1,projectedLeaf);
        var mailboxIssuer = PublicKeyAuth.GenerateKeyPair();
        var (authority, revocations) = MailboxAuthority(network,root,mailboxIssuer);
        var mailboxHead = RoutingClosureSourceVerifier.CreateMailboxHead(authority,revocations);

        var transcriptHash = Bytes(0x96,32);
        var dnr = Dnr(network, mailbox, authority, revocations, mailboxIssuer.PrivateKey,
            routerEd, routerX, transcriptHash);
        var dnrRef = NewRef(ArtifactType.Dnr1,dnr);
        var routerId = CanonicalGrammar
            .DecodeOwned(dnr,RecordDefinitions.Dnr1)
            .FieldCopy(9);
        var dpc = DpcFor(network,routerId,dnrRef,routerEd);
        var dpcRef = NewRef(ArtifactType.Dpc1,dpc);
        var fullMrl = Mrl(network,
            CanonicalGrammar.DecodeOwned(dnr,RecordDefinitions.Dnr1).FieldCopy(9),
            dnrRef,dpcRef);
        Assert.Equal(projectedLeaf,NativeMembershipVerifier.RealLeaf(reset,9,1,0,fullMrl));

        var sourceVerifier = new RoutingClosureSourceVerifier();
        var source = sourceVerifier.CreateVerifiedRouterDxpSource(
            cutover,mailbox,dnr,Bytes(0xa1,32),Bytes(0xa2,32));
        var dxr = Dxr(dnr,source,transcriptHash,cutover.TrustedDxrKeyId);
        var receipt = await new DxpReceiptVerifier().RestoreAsync(
            dxr,source,new HmacProvider(HmacKey));
        var dnrc = new NativeRoutingVerifier().VerifyCurrentRouterCertificate(
            mailbox,authority,revocations,mailboxHead,receipt,dnr,Now);
        var genesisRouter = new NativeRoutingVerifier().VerifyGenesisRouterCertificate(
            mailbox.Mailbox, authority, revocations, mailboxHead, receipt, dnr, Now);
        Assert.True(genesisRouter.NoAuthorityClaim);
        Assert.Empty(typeof(VerifiedGenesisRouterRelative).GetConstructors());

        var membershipVerifier = new DeterministicMembershipVerifier();
        var genesis = MembershipFixtures.Genesis();
        var genesisBytes = MembershipContractCodec.EncodeGenesis(genesis);
        var genesisRelative = new MembershipClosureVerifier().VerifyGenesis(
            genesisBytes,network,SHA256.HashData(genesisBytes),
            MembershipFixtures.GenesisSignatures(genesis,membershipVerifier),membershipVerifier);
        var delegation = MembershipFixtures.SignedDelegation(membershipVerifier);
        var mdg = MembershipContractCodec.EncodeSignedDelegation(delegation);
        var statement = new NodeMembershipCommitment
        {
            NetworkId=network,Sequence=7,PreviousHash=Bytes(0xa0,32),
            IssuedAtUnixSeconds=1000,ValidFromUnixSeconds=1000,ValidUntilUnixSeconds=1200,
            MinimumProtocol=1,MaximumProtocol=3,PolicyVersion=1,MemberCount=1,MerkleRoot=root
        };
        var mmc = MembershipContractCodec.GetMembershipSigningBytes(statement);
        var signatures = delegation.OnlineSigners.Take(2).Select(s=>new MembershipSignature
        {
            SignerId=s.SignerId.ToArray(),Domain=MembershipSignatureDomain.Membership,
            Signature=membershipVerifier.Sign(s.SignerId.Span,s.PublicKey.Span,
                MembershipSignatureDomain.Membership,mmc)
        }).ToArray();
        var msm = MembershipContractCodec.EncodeSignedMembership(new SignedMembershipCommitment
            {Statement=statement,Signatures=signatures});
        var pma = ProductionMailboxAuthorityCodec.Encode(authority.Authority);
        var pmr = ProductionMailboxRevocationSnapshotCodec.Encode(revocations.Snapshot);
        var rows = new[]
        {
            Row(ArtifactType.Mng1,genesisBytes),Row(ArtifactType.Mdg1,mdg),
            Row(ArtifactType.Mmc1,mmc),Row(ArtifactType.Msm1,msm),
            Row(ArtifactType.Pma1,pma),Row(ArtifactType.Pmr1,pmr),
            Row(ArtifactType.Dnr1,dnr),Row(ArtifactType.Mrl2,fullMrl),
            Row(ArtifactType.Dpc1,dpc)
        };
        var catalog = Catalog(rows);
        var transitionHash = TransitionHash(catalog,1);
        var mngRef=RetainedRef(ArtifactType.Mng1,genesisBytes);
        var msmRef=RetainedRef(ArtifactType.Msm1,msm);
        var pmaRef=RetainedRef(ArtifactType.Pma1,pma);
        var pmrRef=RetainedRef(ArtifactType.Pmr1,pmr);
        var membershipClosure=Domain("Deep/NativeRouting/V2/membership-closure",
            Combine(mngRef,transitionHash,msmRef));
        var memberTuple=Combine(
            CanonicalGrammar.DecodeOwned(dnr,RecordDefinitions.Dnr1).FieldCopy(9),
            dnrRef,NewRef(ArtifactType.Mrl2,fullMrl),dpcRef);
        var selection=Composite(network,msmRef,7,1,root,pmaRef,7,9,pmrRef,6,
            revocations.Snapshot.RevocationHeadHash.ToArray(),
            revocations.CanonicalSnapshotHash.ToArray(),memberTuple);
        var mrlc=Mrlc(cutover,catalog,mngRef,membershipClosure,msmRef,root,pmaRef,pmrRef,
            authority,revocations,selection);
        var membershipHead=MembershipHead(network,mngRef,transitionHash,7,
            MembershipContractHash.Sha256(mmc),msmRef);
        var restoreHeads=new RoutingHeadRestoreInput(
            membershipHead,mailboxHead.CanonicalTuple.Span);

        foreach (var candidateDerived in new[]
        {
            MutateMembershipHead(membershipHead, sequence: 6, statement.PreviousHash.Span),
            MutateMembershipHead(membershipHead, sequence: 7, statement.PreviousHash.Span)
        })
        {
            var counter = new CountingMembershipVerifier(membershipVerifier);
            await Assert.ThrowsAsync<RecordException>(() =>
                new MembershipClosureVerifier().RestoreCurrentCompositeLkgAsync(
                    mrlc,cutover.TrustedMrlcKeyId.ToArray(),
                    new RoutingHeadRestoreInput(candidateDerived,mailboxHead.CanonicalTuple.Span),
                    cutover,mailbox,[dnrc],genesisRelative,authority,revocations,Now,0,2,
                    counter,new HmacProvider(HmacKey)).AsTask());
            Assert.Equal(0, counter.Calls);
        }

        var exactMailboxHead = mailboxHead.CanonicalTuple.ToArray();
        var candidatePma = exactMailboxHead.ToArray();
        BinaryPrimitives.WriteUInt64BigEndian(candidatePma.AsSpan(54,8), 6);
        authority.Authority.PreviousAuthorityHash.Span.CopyTo(candidatePma.AsSpan(62,32));
        var candidatePmr = exactMailboxHead.ToArray();
        BinaryPrimitives.WriteUInt64BigEndian(candidatePmr.AsSpan(132,8), 5);
        revocations.Snapshot.PreviousRevocationHeadHash.Span.CopyTo(candidatePmr.AsSpan(140,32));
        var skippedPma = exactMailboxHead.ToArray();
        BinaryPrimitives.WriteUInt64BigEndian(skippedPma.AsSpan(54,8), 9);
        var alternateSameGeneration = exactMailboxHead.ToArray();
        alternateSameGeneration[62] ^= 1;
        var crossNetwork = exactMailboxHead.ToArray();
        crossNetwork[0] ^= 1;
        foreach (var invalidMailboxHead in new[]
        {
            candidatePma, candidatePmr, skippedPma, alternateSameGeneration, crossNetwork
        })
        {
            var counter = new CountingMembershipVerifier(membershipVerifier);
            await Assert.ThrowsAsync<RecordException>(() =>
                new MembershipClosureVerifier().RestoreCurrentCompositeLkgAsync(
                    mrlc,cutover.TrustedMrlcKeyId.ToArray(),
                    new RoutingHeadRestoreInput(membershipHead,invalidMailboxHead),
                    cutover,mailbox,[dnrc],genesisRelative,authority,revocations,Now,0,2,
                    counter,new HmacProvider(HmacKey)).AsTask());
            Assert.Equal(0, counter.Calls);
        }

        var validCounter = new CountingMembershipVerifier(membershipVerifier);
        var verified=await new MembershipClosureVerifier().RestoreCurrentCompositeLkgAsync(
            mrlc,cutover.TrustedMrlcKeyId.ToArray(),restoreHeads,cutover,mailbox,[dnrc],
            genesisRelative,authority,revocations,Now,0,2,validCounter,
            new HmacProvider(HmacKey));

        Assert.Equal(5, validCounter.Calls);
        Assert.Equal(root,verified.MembershipRoot.ToArray());
        Assert.Equal(selection,verified.CompositeSelection.ToArray());
        Assert.Equal((uint)1,verified.MemberCount);
        Assert.NotNull(verified.MembershipHead);
        Assert.True(verified.NoAuthorityClaim);
    }

    [Fact]
    public Task CandidateDerivedMembershipHeadRejectsBeforeSignatureCallbacks() =>
        RestoreCurrent_RealCompositeClosure_BindsProjectionFullRefsAndCurrentSources();

    [Fact]
    public Task CandidateDerivedMailboxHeadsRejectBeforeSignatureCallbacks() =>
        RestoreCurrent_RealCompositeClosure_BindsProjectionFullRefsAndCurrentSources();

    [Fact]
    public Task MembershipAndMailboxAuthoritiesVerifyIndependentlyThenJoinExactRoot() =>
        RestoreCurrent_RealCompositeClosure_BindsProjectionFullRefsAndCurrentSources();

    [Fact]
    public async Task MembershipSuccessor_ReusesExactRetainedAuthorityAndVerifiesOnlyTwoOnlineSignatures()
    {
        var network = MembershipFixtures.Genesis().NetworkId.ToArray();
        var reset = Bytes(0x91, 32);
        var routerEd = PublicKeyAuth.GenerateKeyPair();
        var routerX = ScalarMult.Base(Bytes(0x92, 32));
        var mailbox = CurrentMailbox(network, reset, out var cutover, out _, out _);
        var routerId = Domain("Deep/NativeRouting/V1/router-id",
            Combine(network, mailbox.MailboxOwnerId.ToArray(), U64(1), routerEd.PublicKey));
        var projectedMrl = Mrl(network, routerId,
            Ref(ArtifactType.Dnr1, 756, 0x94), Ref(ArtifactType.Dpc1, 430, 0x95));
        var projectedLeaf = NativeMembershipVerifier.RealLeaf(reset, 9, 1, 0, projectedMrl);
        var root = NativeMembershipVerifier.Root(reset, 9, 1, 1, projectedLeaf);
        var mailboxIssuer = PublicKeyAuth.GenerateKeyPair();
        var currentAuthority = MailboxAuthorityWithSigner(network, root, mailboxIssuer);
        var authority = currentAuthority.Authority;
        var revocations = currentAuthority.Revocations;
        var mailboxHead = RoutingClosureSourceVerifier.CreateMailboxHead(authority, revocations);
        var transcriptHash = Bytes(0x96, 32);
        var dnr = Dnr(network, mailbox, authority, revocations,
            mailboxIssuer.PrivateKey, routerEd, routerX, transcriptHash);
        var dnrRef = NewRef(ArtifactType.Dnr1, dnr);
        var dpc = DpcFor(network, routerId, dnrRef, routerEd);
        var dpcRef = NewRef(ArtifactType.Dpc1, dpc);
        var fullMrl = Mrl(network, routerId, dnrRef, dpcRef);
        Assert.Equal(projectedLeaf,
            NativeMembershipVerifier.RealLeaf(reset, 9, 1, 0, fullMrl));
        var source = new RoutingClosureSourceVerifier().CreateVerifiedRouterDxpSource(
            cutover, mailbox, dnr, Bytes(0xa1, 32), Bytes(0xa2, 32));
        var dxr = Dxr(dnr, source, transcriptHash, cutover.TrustedDxrKeyId);
        var receipt = await new DxpReceiptVerifier().RestoreAsync(
            dxr, source, new HmacProvider(HmacKey));
        var dnrc = new NativeRoutingVerifier().VerifyCurrentRouterCertificate(
            mailbox, authority, revocations, mailboxHead, receipt, dnr, Now);

        var membershipVerifier = new DeterministicMembershipVerifier();
        var genesis = MembershipFixtures.Genesis();
        var genesisBytes = MembershipContractCodec.EncodeGenesis(genesis);
        var closureVerifier = new MembershipClosureVerifier();
        var genesisRelative = closureVerifier.VerifyGenesis(
            genesisBytes, network, SHA256.HashData(genesisBytes),
            MembershipFixtures.GenesisSignatures(genesis, membershipVerifier),
            membershipVerifier);
        var delegation = MembershipFixtures.SignedDelegation(membershipVerifier);
        var mdg = MembershipContractCodec.EncodeSignedDelegation(delegation);
        var currentStatement = new NodeMembershipCommitment
        {
            NetworkId = network,
            Sequence = 7,
            PreviousHash = Bytes(0xa0, 32),
            IssuedAtUnixSeconds = 1000,
            ValidFromUnixSeconds = 1000,
            ValidUntilUnixSeconds = 1200,
            MinimumProtocol = 1,
            MaximumProtocol = 3,
            PolicyVersion = 1,
            MemberCount = 1,
            MerkleRoot = root
        };
        var currentMmc = MembershipContractCodec.GetMembershipSigningBytes(currentStatement);
        var currentMsm = SignedMembership(delegation, currentStatement,
            currentMmc, membershipVerifier);
        var currentPma = ProductionMailboxAuthorityCodec.Encode(authority.Authority);
        var currentPmr = ProductionMailboxRevocationSnapshotCodec.Encode(revocations.Snapshot);
        var currentCatalog = Catalog([
            Row(ArtifactType.Mng1, genesisBytes), Row(ArtifactType.Mdg1, mdg),
            Row(ArtifactType.Mmc1, currentMmc), Row(ArtifactType.Msm1, currentMsm),
            Row(ArtifactType.Pma1, currentPma), Row(ArtifactType.Pmr1, currentPmr),
            Row(ArtifactType.Dnr1, dnr), Row(ArtifactType.Mrl2, fullMrl),
            Row(ArtifactType.Dpc1, dpc)
        ]);
        var transitionHash = TransitionHash(currentCatalog, 1);
        var mngRef = RetainedRef(ArtifactType.Mng1, genesisBytes);
        var currentMsmRef = RetainedRef(ArtifactType.Msm1, currentMsm);
        var currentPmaRef = RetainedRef(ArtifactType.Pma1, currentPma);
        var currentPmrRef = RetainedRef(ArtifactType.Pmr1, currentPmr);
        var currentClosure = Domain("Deep/NativeRouting/V2/membership-closure",
            Combine(mngRef, transitionHash, currentMsmRef));
        var currentTuple = Combine(routerId, dnrRef,
            NewRef(ArtifactType.Mrl2, fullMrl), dpcRef);
        var currentSelection = Composite(network, currentMsmRef, 7, 1, root,
            currentPmaRef, 7, 9, currentPmrRef, 6,
            revocations.Snapshot.RevocationHeadHash.ToArray(),
            revocations.CanonicalSnapshotHash.ToArray(), currentTuple);
        var currentMrlc = Mrlc(cutover, currentCatalog, mngRef, currentClosure,
            currentMsmRef, root, currentPmaRef, currentPmrRef,
            authority, revocations, currentSelection);
        var currentHead = MembershipHead(network, mngRef, transitionHash, 7,
            MembershipContractHash.Sha256(currentMmc), currentMsmRef);
        var current = await closureVerifier.RestoreCurrentCompositeLkgAsync(
            currentMrlc, cutover.TrustedMrlcKeyId.ToArray(),
            new RoutingHeadRestoreInput(currentHead, mailboxHead.CanonicalTuple.Span),
            cutover, mailbox, [dnrc], genesisRelative, authority, revocations,
            Now, 0, 2, membershipVerifier, new HmacProvider(HmacKey));

        var (nextAuthority, nextRevocations) = MailboxAuthoritySuccessor(
            network, root, mailboxIssuer, currentAuthority.MrX, authority, revocations);
        var nextMailboxHead = RoutingClosureSourceVerifier.CreateMailboxHead(
            nextAuthority, nextRevocations);
        var nextDnr = Dnr(network, mailbox, nextAuthority, nextRevocations,
            mailboxIssuer.PrivateKey, routerEd, routerX, transcriptHash);
        var nextDnrRef = NewRef(ArtifactType.Dnr1, nextDnr);
        var nextDpc = DpcFor(network, routerId, nextDnrRef, routerEd);
        var nextDpcRef = NewRef(ArtifactType.Dpc1, nextDpc);
        var nextMrl = Mrl(network, routerId, nextDnrRef, nextDpcRef);
        var nextSource = new RoutingClosureSourceVerifier().CreateVerifiedRouterDxpSource(
            cutover, mailbox, nextDnr, Bytes(0xa1, 32), Bytes(0xa2, 32));
        var nextDxr = Dxr(nextDnr, nextSource, transcriptHash, cutover.TrustedDxrKeyId);
        var nextReceipt = await new DxpReceiptVerifier().RestoreAsync(
            nextDxr, nextSource, new HmacProvider(HmacKey));
        var nextDnrc = new NativeRoutingVerifier().VerifyCurrentRouterCertificate(
            mailbox, nextAuthority, nextRevocations, nextMailboxHead,
            nextReceipt, nextDnr, Now);
        var nextStatement = currentStatement with
        {
            Sequence = 8,
            PreviousHash = MembershipContractHash.Sha256(currentMmc)
        };
        var nextMmc = MembershipContractCodec.GetMembershipSigningBytes(nextStatement);
        var nextMsm = SignedMembership(delegation, nextStatement, nextMmc,
            membershipVerifier);
        var nextPma = ProductionMailboxAuthorityCodec.Encode(nextAuthority.Authority);
        var nextPmr = ProductionMailboxRevocationSnapshotCodec.Encode(nextRevocations.Snapshot);
        var nextCatalog = Catalog([
            Row(ArtifactType.Mng1, genesisBytes), Row(ArtifactType.Mdg1, mdg),
            Row(ArtifactType.Mmc1, nextMmc), Row(ArtifactType.Msm1, nextMsm),
            Row(ArtifactType.Pma1, nextPma), Row(ArtifactType.Pmr1, nextPmr),
            Row(ArtifactType.Dnr1, nextDnr), Row(ArtifactType.Mrl2, nextMrl),
            Row(ArtifactType.Dpc1, nextDpc)
        ]);
        Assert.Equal(transitionHash, TransitionHash(nextCatalog, 1));
        var nextMsmRef = RetainedRef(ArtifactType.Msm1, nextMsm);
        var nextPmaRef = RetainedRef(ArtifactType.Pma1, nextPma);
        var nextPmrRef = RetainedRef(ArtifactType.Pmr1, nextPmr);
        var nextClosure = Domain("Deep/NativeRouting/V2/membership-closure",
            Combine(mngRef, transitionHash, nextMsmRef));
        var nextTuple = Combine(routerId, nextDnrRef,
            NewRef(ArtifactType.Mrl2, nextMrl), nextDpcRef);
        var nextSelection = Composite(network, nextMsmRef, 8, 1, root,
            nextPmaRef, 8, 9, nextPmrRef, 7,
            nextRevocations.Snapshot.RevocationHeadHash.ToArray(),
            nextRevocations.CanonicalSnapshotHash.ToArray(), nextTuple);
        var nextMrlc = Mrlc(cutover, nextCatalog, mngRef, nextClosure,
            nextMsmRef, root, nextPmaRef, nextPmrRef,
            nextAuthority, nextRevocations, nextSelection, membershipSequence: 8);
        var counter = new CountingMembershipVerifier(membershipVerifier);

        var plan = await closureVerifier.VerifyNextCompositeLkgAsync(
            nextMrlc, cutover.TrustedMrlcKeyId.ToArray(), current,
            cutover, mailbox, [nextDnrc], genesisRelative,
            nextAuthority, nextRevocations, Now, 0, 2, counter,
            new HmacProvider(HmacKey));

        var headStore = new RoutingHeadStore(
            current.MembershipHead!.CanonicalTuple.Span,
            current.MailboxAuthorityHead!.CanonicalTuple.Span);
        headStore.Commit(plan);

        Assert.Equal(2, counter.Calls);
        Assert.Equal(1, headStore.Mutations);
        Assert.Equal((ulong)7, BinaryPrimitives.ReadUInt64BigEndian(
            plan.CurrentMembershipHead.CanonicalTuple.Span.Slice(86, 8)));
        Assert.Equal((ulong)8, plan.NextLkg.MembershipSequence);
        Assert.Equal(current.MembershipHead!.CanonicalTuple.ToArray(),
            plan.CurrentMembershipHead.CanonicalTuple.ToArray());
        Assert.Equal(nextMailboxHead.CanonicalTuple.ToArray(),
            plan.NextMailboxAuthorityHead.CanonicalTuple.ToArray());
        Assert.Equal(plan.NextMembershipHead.CanonicalTuple.ToArray(),
            headStore.MembershipHead);
        Assert.Equal(plan.NextMailboxAuthorityHead.CanonicalTuple.ToArray(),
            headStore.MailboxAuthorityHead);
        Assert.True(plan.NoAuthorityClaim);
    }

    private sealed class RoutingHeadStore
    {
        private byte[] _membershipHead;
        private byte[] _mailboxAuthorityHead;

        internal RoutingHeadStore(
            ReadOnlySpan<byte> membershipHead,
            ReadOnlySpan<byte> mailboxAuthorityHead)
        {
            _membershipHead = membershipHead.ToArray();
            _mailboxAuthorityHead = mailboxAuthorityHead.ToArray();
        }

        internal int Mutations { get; private set; }
        internal byte[] MembershipHead => _membershipHead.ToArray();
        internal byte[] MailboxAuthorityHead => _mailboxAuthorityHead.ToArray();

        internal void Commit(CompositeRoutingCommitPlan plan)
        {
            ArgumentNullException.ThrowIfNull(plan);
            if (!CryptographicOperations.FixedTimeEquals(
                    _membershipHead, plan.CurrentMembershipHead.CanonicalTuple.Span) ||
                !CryptographicOperations.FixedTimeEquals(
                    _mailboxAuthorityHead,
                    plan.CurrentMailboxAuthorityHead.CanonicalTuple.Span))
                throw new InvalidOperationException("The routing heads changed before commit.");

            _membershipHead = plan.NextMembershipHead.CanonicalTuple.ToArray();
            _mailboxAuthorityHead =
                plan.NextMailboxAuthorityHead.CanonicalTuple.ToArray();
            Mutations++;
        }
    }

    internal sealed record GenesisRoutingFacts(
        VerifiedIdentityRelative Identity,
        VerifiedDeviceRelative Device,
        VerifiedMailboxRelative Mailbox,
        VerifiedGenesisRouterRelative Router,
        KeyPair AccountSigner,
        KeyPair ResetSigner);

    internal sealed record TransportRoutingFacts(
        CurrentCutoverRelative Cutover,
        CurrentDnrcRelative Dnrc,
        VerifiedMembershipRoutingLkg Membership,
        VerifiedRouterContact Contact);

    internal static async Task<TransportRoutingFacts> CreateTransportRoutingFactsAsync(
        bool dnsEndpoint = false)
    {
        var network = MembershipFixtures.Genesis().NetworkId.ToArray();
        var reset = Bytes(0x91,32);
        var routerEd = PublicKeyAuth.GenerateKeyPair();
        var routerXPrivate = Bytes(0x92,32);
        var routerX = ScalarMult.Base(routerXPrivate);
        var mailbox = CurrentMailbox(network, reset, out var cutover, out _, out _);
        var projectedRouterId = Domain("Deep/NativeRouting/V1/router-id",
            Combine(network,mailbox.MailboxOwnerId.ToArray(),U64(1),routerEd.PublicKey));
        var projectedMrl = Mrl(network, projectedRouterId,
            Ref(ArtifactType.Dnr1,756,0x94), Ref(ArtifactType.Dpc1,430,0x95));
        var projectedLeaf = NativeMembershipVerifier.RealLeaf(reset,9,1,0,projectedMrl);
        var root = NativeMembershipVerifier.Root(reset,9,1,1,projectedLeaf);
        var mailboxIssuer = PublicKeyAuth.GenerateKeyPair();
        var (authority, revocations) = MailboxAuthority(network,root,mailboxIssuer);
        var mailboxHead = RoutingClosureSourceVerifier.CreateMailboxHead(authority,revocations);
        var transcriptHash = Bytes(0x96,32);
        var dnr = Dnr(network, mailbox, authority, revocations, mailboxIssuer.PrivateKey,
            routerEd, routerX, transcriptHash);
        var dnrRef = NewRef(ArtifactType.Dnr1,dnr);
        var routerId = CanonicalGrammar.DecodeOwned(dnr,RecordDefinitions.Dnr1).FieldCopy(9);
        var dpc = DpcFor(network,routerId,dnrRef,routerEd,dnsEndpoint);
        var dpcRef = NewRef(ArtifactType.Dpc1,dpc);
        var fullMrl = Mrl(network,routerId,dnrRef,dpcRef);
        var mrlRef = NewRef(ArtifactType.Mrl2,fullMrl);
        var source = new RoutingClosureSourceVerifier().CreateVerifiedRouterDxpSource(
            cutover,mailbox,dnr,Bytes(0xa1,32),Bytes(0xa2,32));
        var dxr = Dxr(dnr,source,transcriptHash,cutover.TrustedDxrKeyId);
        var receipt = await new DxpReceiptVerifier().RestoreAsync(
            dxr,source,new HmacProvider(HmacKey));
        var dnrc = new NativeRoutingVerifier().VerifyCurrentRouterCertificate(
            mailbox,authority,revocations,mailboxHead,receipt,dnr,Now);
        var contactProof = new VerifiedMrl2Membership(
            Array.Empty<byte>(), fullMrl, routerId, routerEd.PublicKey, projectedLeaf,
            mrlRef, 9, 1, (RouterRoles)1, (RouterCapabilities)17);
        var contact = new NativeRoutingVerifier().VerifyAnchorContact(contactProof,dpc,Now);

        var membershipVerifier = new DeterministicMembershipVerifier();
        var genesis = MembershipFixtures.Genesis();
        var genesisBytes = MembershipContractCodec.EncodeGenesis(genesis);
        var genesisRelative = new MembershipClosureVerifier().VerifyGenesis(
            genesisBytes,network,SHA256.HashData(genesisBytes),
            MembershipFixtures.GenesisSignatures(genesis,membershipVerifier),membershipVerifier);
        var delegation = MembershipFixtures.SignedDelegation(membershipVerifier);
        var mdg = MembershipContractCodec.EncodeSignedDelegation(delegation);
        var statement = new NodeMembershipCommitment
        {
            NetworkId=network,Sequence=7,PreviousHash=Bytes(0xa0,32),
            IssuedAtUnixSeconds=1000,ValidFromUnixSeconds=1000,ValidUntilUnixSeconds=1200,
            MinimumProtocol=1,MaximumProtocol=3,PolicyVersion=1,MemberCount=1,MerkleRoot=root
        };
        var mmc = MembershipContractCodec.GetMembershipSigningBytes(statement);
        var signatures = delegation.OnlineSigners.Take(2).Select(s=>new MembershipSignature
        {
            SignerId=s.SignerId.ToArray(),Domain=MembershipSignatureDomain.Membership,
            Signature=membershipVerifier.Sign(s.SignerId.Span,s.PublicKey.Span,
                MembershipSignatureDomain.Membership,mmc)
        }).ToArray();
        var msm = MembershipContractCodec.EncodeSignedMembership(new SignedMembershipCommitment
            {Statement=statement,Signatures=signatures});
        var pma = ProductionMailboxAuthorityCodec.Encode(authority.Authority);
        var pmr = ProductionMailboxRevocationSnapshotCodec.Encode(revocations.Snapshot);
        var rows = new[]
        {
            Row(ArtifactType.Mng1,genesisBytes),Row(ArtifactType.Mdg1,mdg),
            Row(ArtifactType.Mmc1,mmc),Row(ArtifactType.Msm1,msm),
            Row(ArtifactType.Pma1,pma),Row(ArtifactType.Pmr1,pmr),
            Row(ArtifactType.Dnr1,dnr),Row(ArtifactType.Mrl2,fullMrl),
            Row(ArtifactType.Dpc1,dpc)
        };
        var catalog = Catalog(rows);
        var transitionHash = TransitionHash(catalog,1);
        var mngRef=RetainedRef(ArtifactType.Mng1,genesisBytes);
        var msmRef=RetainedRef(ArtifactType.Msm1,msm);
        var pmaRef=RetainedRef(ArtifactType.Pma1,pma);
        var pmrRef=RetainedRef(ArtifactType.Pmr1,pmr);
        var membershipClosure=Domain("Deep/NativeRouting/V2/membership-closure",
            Combine(mngRef,transitionHash,msmRef));
        var memberTuple=Combine(routerId,dnrRef,mrlRef,dpcRef);
        var selection=Composite(network,msmRef,7,1,root,pmaRef,7,9,pmrRef,6,
            revocations.Snapshot.RevocationHeadHash.ToArray(),
            revocations.CanonicalSnapshotHash.ToArray(),memberTuple);
        var mrlc=Mrlc(cutover,catalog,mngRef,membershipClosure,msmRef,root,pmaRef,pmrRef,
            authority,revocations,selection);
        var membershipHead=MembershipHead(network,mngRef,transitionHash,7,
            MembershipContractHash.Sha256(mmc),msmRef);
        var restoreHeads=new RoutingHeadRestoreInput(
            membershipHead,mailboxHead.CanonicalTuple.Span);
        var verified=await new MembershipClosureVerifier().RestoreCurrentCompositeLkgAsync(
            mrlc,cutover.TrustedMrlcKeyId.ToArray(),restoreHeads,cutover,mailbox,[dnrc],
            genesisRelative,authority,revocations,Now,0,2,membershipVerifier,
            new HmacProvider(HmacKey));
        return new TransportRoutingFacts(cutover,dnrc,verified,contact);
    }

    private sealed class CountingMembershipVerifier(IMembershipSignatureVerifier inner)
        : IMembershipSignatureVerifier
    {
        internal int Calls { get; private set; }

        public bool Verify(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            Calls++;
            return inner.Verify(signerId, publicKey, domain, signingBytes, signature);
        }
    }

    private static byte[] MutateMembershipHead(
        ReadOnlySpan<byte> exact,
        ulong sequence,
        ReadOnlySpan<byte> canonicalHash)
    {
        var result = exact.ToArray();
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(86,8), sequence);
        canonicalHash.CopyTo(result.AsSpan(94,32));
        return result;
    }

    internal static async Task<GenesisRoutingFacts> CreateGenesisRoutingFactsAsync(
        byte[] network)
    {
        var priorReset = Bytes(0x91, 32);
        var routerEd = PublicKeyAuth.GenerateKeyPair();
        var routerXPrivate = Bytes(0x92, 32);
        var routerX = ScalarMult.Base(routerXPrivate);
        var current = CurrentMailbox(network, priorReset, out var cutover,
            out var accountSigner, out var resetSigner);
        var projectedRouterId = Domain("Deep/NativeRouting/V1/router-id",
            Combine(network, current.MailboxOwnerId.ToArray(), U64(1), routerEd.PublicKey));
        var projectedMrl = Mrl(network, projectedRouterId,
            Ref(ArtifactType.Dnr1, 756, 0x94), Ref(ArtifactType.Dpc1, 430, 0x95));
        var projectedLeaf = NativeMembershipVerifier.RealLeaf(priorReset, 9, 1, 0,
            projectedMrl);
        var root = NativeMembershipVerifier.Root(priorReset, 9, 1, 1, projectedLeaf);
        var mailboxIssuer = PublicKeyAuth.GenerateKeyPair();
        var (authority, revocations) = MailboxAuthority(network, root, mailboxIssuer);
        var mailboxHead = RoutingClosureSourceVerifier.CreateMailboxHead(authority, revocations);
        var transcriptHash = Bytes(0x96, 32);
        var dnr = Dnr(network, current, authority, revocations,
            mailboxIssuer.PrivateKey, routerEd, routerX, transcriptHash);
        var source = new RoutingClosureSourceVerifier().CreateVerifiedRouterDxpSource(
            cutover, current, dnr, Bytes(0xa1, 32), Bytes(0xa2, 32));
        var dxr = Dxr(dnr, source, transcriptHash, cutover.TrustedDxrKeyId);
        var receipt = await new DxpReceiptVerifier().RestoreAsync(
            dxr, source, new HmacProvider(HmacKey));
        var mailbox = current.Mailbox;
        var router = new NativeRoutingVerifier().VerifyGenesisRouterCertificate(
            mailbox, authority, revocations, mailboxHead, receipt, dnr, Now);
        return new GenesisRoutingFacts(
            mailbox.Device.Identity, mailbox.Device, mailbox, router,
            accountSigner, resetSigner);
    }

    private static (VerifiedProductionMailboxAuthority,VerifiedProductionMailboxRevocationSnapshot)
        MailboxAuthority(byte[] network,byte[] root,KeyPair issuer)
    {
        var result = MailboxAuthorityWithSigner(network, root, issuer);
        return (result.Authority, result.Revocations);
    }

    private static (VerifiedProductionMailboxAuthority Authority,
        VerifiedProductionMailboxRevocationSnapshot Revocations, KeyPair MrX)
        MailboxAuthorityWithSigner(byte[] network, byte[] root, KeyPair issuer)
    {
        var mrx=PublicKeyAuth.GenerateKeyPair();
        var draft=new ProductionMailboxAuthority
        {
            DevelopmentOnly=false,Environment=ProductionMailboxAuthorityEnvironment.Production,
            Transport=ProductionMailboxAuthorityTransport.AuthenticatedMau2,
            Ownership=ProductionMailboxAuthorityOwnership.OfficialManaged,
            EndpointPolicy=ProductionMailboxAuthorityEndpointPolicy.PublicHttpsOnly,
            NetworkId=network,AuthorityGeneration=7,PreviousAuthorityHash=Bytes(2,32),
            MailboxIssuerEd25519PublicKey=issuer.PublicKey,MrXApprovalEd25519PublicKey=mrx.PublicKey,
            Coordinator=Endpoint("https://coord.example.net/",4),
            NodeIngress=Endpoint("https://ingress.example.net/mau2/",6),
            CurrentEpoch=Epoch(9,70,900,1200,root),NextEpoch=Epoch(10,71,1100,1500,Bytes(10,32)),
            Revocation=new ProductionMailboxAuthorityRevocation{SnapshotHash=Bytes(12,32),HeadHash=Bytes(13,32),
                PreviousHeadHash=Bytes(22,32),Generation=6,IssuedAtUnixSeconds=990,ExpiresAtUnixSeconds=1180},
            MrXApproval=new ProductionMailboxAuthorityApproval{AuthorityPayloadHash=Bytes(14,32),
                AllowedAndroidSigningCertificateSha256=[Bytes(15,32)],AllowedWindowsSigningCertificateSha256=[Bytes(16,32)],
                AndroidReleaseBuildArtifactSha256=[Bytes(17,32)],WindowsReleaseBuildArtifactSha256=[Bytes(18,32)],
                RolloutNotBeforeUnixSeconds=900,RolloutNotAfterUnixSeconds=1150},Signature=new byte[64]
        };
        var unsignedSnapshot=new ProductionMailboxRevocationSnapshot
        {
            NetworkId=network,AuthorityGeneration=7,
            AuthorityBindingHash=ProductionMailboxRevocationSnapshotCodec.ComputeAuthorityBindingHash(draft),
            RevocationGeneration=6,RevocationHeadHash=Bytes(13,32),PreviousRevocationHeadHash=Bytes(22,32),
            IssuedAtUnixSeconds=990,ExpiresAtUnixSeconds=1180,RevokedGrantSerials=[],IssuerSignature=new byte[64]
        };
        var snapshot=unsignedSnapshot with{IssuerSignature=PublicKeyAuth.SignDetached(
            ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(unsignedSnapshot),issuer.PrivateKey)};
        var encoded=ProductionMailboxRevocationSnapshotCodec.Encode(snapshot);
        var withBinding=draft with{Revocation=draft.Revocation with{SnapshotHash=SHA256.HashData(encoded)}};
        withBinding=withBinding with{MrXApproval=withBinding.MrXApproval with{
            AuthorityPayloadHash=ProductionMailboxAuthorityCodec.ComputePayloadHash(withBinding)}};
        var signed=withBinding with{Signature=PublicKeyAuth.SignDetached(
            ProductionMailboxAuthorityCodec.GetSigningBytes(withBinding),mrx.PrivateKey)};
        var verified=ProductionMailboxAuthorityVerifier.Verify(signed,new ProductionMailboxAuthorityVerificationContext
        {
            PinnedMrXPublicKeySha256=SHA256.HashData(mrx.PublicKey),ExpectedNetworkId=network,
            LastCommittedGeneration=6,LastCommittedAuthorityHash=Bytes(2,32),LastCommittedRevocationGeneration=5,
            LastCommittedRevocationHeadHash=Bytes(22,32),LastCommittedRevocationSnapshotHash=Bytes(23,32),
            NowUnixSeconds=Now,ClockSkewSeconds=0
        },new SodiumProductionMailboxAuthoritySignatureVerifier());
        var verifiedSnapshot=ProductionMailboxRevocationSnapshotVerifier.Verify(encoded,verified,Now,0,
            new SodiumProductionMailboxRevocationSnapshotSignatureVerifier());
        return(verified,verifiedSnapshot,mrx);
    }

    private static (VerifiedProductionMailboxAuthority, VerifiedProductionMailboxRevocationSnapshot)
        MailboxAuthoritySuccessor(
            byte[] network,
            byte[] root,
            KeyPair issuer,
            KeyPair mrx,
            VerifiedProductionMailboxAuthority priorAuthority,
            VerifiedProductionMailboxRevocationSnapshot priorRevocations)
    {
        var authorityGeneration = checked(priorAuthority.Authority.AuthorityGeneration + 1);
        var revocationGeneration = checked(priorRevocations.Snapshot.RevocationGeneration + 1);
        var revocationHead = Bytes(0x24, 32);
        var draft = priorAuthority.Authority with
        {
            AuthorityGeneration = authorityGeneration,
            PreviousAuthorityHash = priorAuthority.CanonicalAuthorityHash.ToArray(),
            CurrentEpoch = Epoch(9, 71, 900, 1200, root),
            NextEpoch = Epoch(10, 72, 1100, 1500, Bytes(10, 32)),
            Revocation = priorAuthority.Authority.Revocation with
            {
                SnapshotHash = Bytes(0x25, 32),
                HeadHash = revocationHead,
                PreviousHeadHash = priorRevocations.Snapshot.RevocationHeadHash.ToArray(),
                Generation = revocationGeneration,
                IssuedAtUnixSeconds = 1000,
                ExpiresAtUnixSeconds = 1180
            },
            MrXApproval = priorAuthority.Authority.MrXApproval with
            {
                AuthorityPayloadHash = Bytes(0x26, 32)
            },
            Signature = new byte[64]
        };
        var unsignedSnapshot = new ProductionMailboxRevocationSnapshot
        {
            NetworkId = network,
            AuthorityGeneration = authorityGeneration,
            AuthorityBindingHash = ProductionMailboxRevocationSnapshotCodec
                .ComputeAuthorityBindingHash(draft),
            RevocationGeneration = revocationGeneration,
            RevocationHeadHash = revocationHead,
            PreviousRevocationHeadHash = priorRevocations.Snapshot
                .RevocationHeadHash.ToArray(),
            IssuedAtUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1180,
            RevokedGrantSerials = [],
            IssuerSignature = new byte[64]
        };
        var snapshot = unsignedSnapshot with
        {
            IssuerSignature = PublicKeyAuth.SignDetached(
                ProductionMailboxRevocationSnapshotCodec.GetSigningBytes(unsignedSnapshot),
                issuer.PrivateKey)
        };
        var encodedSnapshot = ProductionMailboxRevocationSnapshotCodec.Encode(snapshot);
        var bound = draft with
        {
            Revocation = draft.Revocation with
            {
                SnapshotHash = SHA256.HashData(encodedSnapshot)
            }
        };
        bound = bound with
        {
            MrXApproval = bound.MrXApproval with
            {
                AuthorityPayloadHash = ProductionMailboxAuthorityCodec.ComputePayloadHash(bound)
            }
        };
        var signed = bound with
        {
            Signature = PublicKeyAuth.SignDetached(
                ProductionMailboxAuthorityCodec.GetSigningBytes(bound), mrx.PrivateKey)
        };
        var verified = ProductionMailboxAuthorityVerifier.Verify(
            signed,
            new ProductionMailboxAuthorityVerificationContext
            {
                PinnedMrXPublicKeySha256 = SHA256.HashData(mrx.PublicKey),
                ExpectedNetworkId = network,
                LastCommittedGeneration = priorAuthority.Authority.AuthorityGeneration,
                LastCommittedAuthorityHash = priorAuthority.CanonicalAuthorityHash,
                LastCommittedRevocationGeneration = priorRevocations.Snapshot.RevocationGeneration,
                LastCommittedRevocationHeadHash = priorRevocations.Snapshot.RevocationHeadHash,
                LastCommittedRevocationSnapshotHash = priorRevocations.CanonicalSnapshotHash,
                NowUnixSeconds = Now,
                ClockSkewSeconds = 0
            },
            new SodiumProductionMailboxAuthoritySignatureVerifier());
        var verifiedSnapshot = ProductionMailboxRevocationSnapshotVerifier.Verify(
            encodedSnapshot, verified, Now, 0,
            new SodiumProductionMailboxRevocationSnapshotSignatureVerifier());
        return (verified, verifiedSnapshot);
    }

    private static CurrentMailboxRoleRelative CurrentMailbox(
        byte[] network, byte[] reset, out CurrentCutoverRelative cutover,
        out KeyPair accountEd, out KeyPair resetKey)
    {
        accountEd=PublicKeyAuth.GenerateKeyPair(); var deviceIssuer=PublicKeyAuth.GenerateKeyPair();
        var revocationKey=PublicKeyAuth.GenerateKeyPair(); resetKey=PublicKeyAuth.GenerateKeyPair();
        var f=Min(RecordDefinitions.Dpa1); f[0]=network;f[1]=U64(1);f[2]=U64(1);f[4]=accountEd.PublicKey;
        f[5]=deviceIssuer.PublicKey;f[6]=revocationKey.PublicKey;f[7]=resetKey.PublicKey;f[8]=Bytes(0xb1,32);
        f[9]=U64(800);f[10]=U64(1);f[11]=U16(1);
        var carrier=CanonicalGrammar.Encode(RecordDefinitions.Dpa1,f);
        var rec=CanonicalGrammar.DecodeOwned(carrier,RecordDefinitions.Dpa1);
        var signing=CanonicalGrammar.GetSigningBytes(rec,"Deep/IdentityAuth/V1/account-certificate");
        f[12]=PublicKeyAuth.SignDetached(signing,accountEd.PrivateKey);f[13]=PublicKeyAuth.SignDetached(signing,deviceIssuer.PrivateKey);
        f[14]=PublicKeyAuth.SignDetached(signing,revocationKey.PrivateKey);f[15]=PublicKeyAuth.SignDetached(signing,resetKey.PrivateKey);
        var dpa=CanonicalGrammar.Encode(RecordDefinitions.Dpa1,f);
        var account=IdentityVerifier.VerifyAccountCertificate(dpa);
        var drf=Min(RecordDefinitions.Drs1);drf[0]=network;drf[1]=account.DeepAccountIdHash;drf[2]=U64(1);
        drf[3]=U64(1);drf[4]=U64(900);
        drf[7]=IdentityKeyHash(network,KeyScope.AccountRevocation,
            account.DeepAccountIdHash.Span,1,revocationKey.PublicKey);
        drf[8]=U16(0);drf[10]=new byte[32];
        var unsignedDrs=CanonicalGrammar.Encode(RecordDefinitions.Drs1,drf);
        drf[11]=PublicKeyAuth.SignDetached(CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(unsignedDrs,RecordDefinitions.Drs1),
            "Deep/IdentityAuth/V1/revocation-snapshot"),revocationKey.PrivateKey);
        var drsBytes=CanonicalGrammar.Encode(RecordDefinitions.Drs1,drf);
        var identityVerifier=new IdentityRelativeVerifier();
        var identity=identityVerifier.RestoreCurrent(dpa,drsBytes,[],[],Now);
        var drs=identity.Authority.Revocations.Snapshot;
        var deviceEd=PublicKeyAuth.GenerateKeyPair(); var deviceFields=Min(RecordDefinitions.Dpd1);
        deviceFields[0]=network;deviceFields[1]=account.DeepAccountIdHash;deviceFields[2]=U64(1);deviceFields[3]=Bytes(0xb4,32);
        deviceFields[4]=U64(1);deviceFields[5]=deviceEd.PublicKey;deviceFields[6]=Bytes(0xb5,32);deviceFields[7]=Bytes(0xb6,32);
        deviceFields[10]=IdentityKeyHash(network,KeyScope.DeviceCertificateIssuer,
            account.DeepAccountIdHash.Span,1,deviceIssuer.PublicKey);
        deviceFields[11]=U64(1);deviceFields[12]=NewRef(ArtifactType.Drs1,drs.CanonicalBytes.Span);
        deviceFields[14]=drs.Record.FieldCopy(11);deviceFields[20]=Bytes(0xb9,32);
        deviceFields[15]=U64(900);deviceFields[16]=U64(1200);deviceFields[17]=U64(1);deviceFields[18]=U16(1);
        var unsignedDevice=CanonicalGrammar.Encode(RecordDefinitions.Dpd1,deviceFields);
        var deviceSigning=CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(unsignedDevice,RecordDefinitions.Dpd1),
            "Deep/IdentityAuth/V1/device-certificate");
        deviceFields[21]=PublicKeyAuth.SignDetached(deviceSigning,deviceEd.PrivateKey);
        deviceFields[22]=PublicKeyAuth.SignDetached(deviceSigning,deviceIssuer.PrivateKey);
        var deviceBytes=CanonicalGrammar.Encode(RecordDefinitions.Dpd1,deviceFields);
        var deviceRelative=identityVerifier.RestoreDeviceFromRecovery(identity,deviceBytes,Now);
        var device=deviceRelative.Device.Certificate;
        var mailboxKey=PublicKeyAuth.GenerateKeyPair();var mf=Min(RecordDefinitions.Dpm1);
        mf[0]=network;mf[1]=account.DeepAccountIdHash;mf[2]=U64(1);mf[3]=device.DeviceId;
        mf[4]=NewRef(ArtifactType.Dpd1,device.CanonicalBytes.Span);
        mf[5]=Domain("Deep/IdentityAuth/V1/mailbox-owner-id",Combine(network,account.DeepAccountIdHash.ToArray(),mailboxKey.PublicKey));
        mf[6]=U64(1);mf[7]=mailboxKey.PublicKey;mf[8]=Bytes(0xb8,32);mf[9]=U64(1);mf[10]=NewRef(ArtifactType.Drs1,drs.CanonicalBytes.Span);
        mf[12]=drs.Record.FieldCopy(11);mf[13]=U64(900);mf[14]=U64(1200);mf[15]=U64(3);
        var unsignedMailbox=CanonicalGrammar.Encode(RecordDefinitions.Dpm1,mf);
        var mailboxSigning=CanonicalGrammar.GetSigningBytes(
            CanonicalGrammar.DecodeOwned(unsignedMailbox,RecordDefinitions.Dpm1),
            "Deep/IdentityAuth/V1/mailbox-role-certificate");
        mf[17]=PublicKeyAuth.SignDetached(mailboxSigning,deviceEd.PrivateKey);
        mf[18]=PublicKeyAuth.SignDetached(mailboxSigning,mailboxKey.PrivateKey);
        var mailbox=identityVerifier.VerifyMailboxRole(identity,
            CanonicalGrammar.Encode(RecordDefinitions.Dpm1,mf),deviceRelative,Now);
        var drsRef=NewRef(ArtifactType.Drs1,drs.CanonicalBytes.Span);
        cutover=new CurrentCutoverRelative(network,reset,ComponentKind.Registry,account.DeepAccountIdHash.Span,1,1,
            Ref(ArtifactType.Dcm1,812,0xc1),Ref(ArtifactType.Dcp1,706,0xc2),Ref(ArtifactType.Dcs1,839,0xc3),
            Ref(ArtifactType.Dcq1,375,0xc4),Ref(ArtifactType.Dwl1,708,0xc5),Ref(ArtifactType.Dcl1,409,0xc6),
            Ref(ArtifactType.Dpl1,576,0xc7),Bytes(0xc8,32),1,0,drs.Record.FieldCopy(11),drsRef,1150,
            Bytes(0xc9,32),Bytes(0xca,32),Bytes(0xcb,32),Bytes(0xcc,32),Bytes(0xcd,32),Bytes(0xce,32));
        return new RoutingClosureSourceVerifier().BindCurrentMailboxRole(cutover,mailbox);
    }

    private static byte[] IdentityKeyHash(
        ReadOnlySpan<byte> network,KeyScope scope,ReadOnlySpan<byte> accountHash,
        ulong accountGeneration,ReadOnlySpan<byte> publicKey)
    {
        var payload=new byte[89];network.CopyTo(payload);payload[16]=(byte)scope;
        accountHash.CopyTo(payload.AsSpan(17));U64(accountGeneration).CopyTo(payload,49);
        publicKey.CopyTo(payload.AsSpan(57));
        return Domain("Deep/IdentityAuth/V1/key-hash",payload);
    }

    private static byte[] Dnr(byte[] network,CurrentMailboxRoleRelative mailbox,
        VerifiedProductionMailboxAuthority authority,VerifiedProductionMailboxRevocationSnapshot revocations,
        byte[] issuerPrivate,KeyPair routerEd,byte[] routerX,byte[] transcript)
    {
        var f=Min(RecordDefinitions.Dnr1);f[0]=network;f[1]=mailbox.MailboxOwnerId;f[2]=mailbox.CurrentDpmcReference;
        var pma=ProductionMailboxAuthorityCodec.Encode(authority.Authority);var pmr=ProductionMailboxRevocationSnapshotCodec.Encode(revocations.Snapshot);
        f[3]=RetainedRef(ArtifactType.Pma1,pma);f[4]=U64(authority.Authority.AuthorityGeneration);
        f[5]=RetainedRef(ArtifactType.Pmr1,pmr);f[6]=U64(revocations.Snapshot.RevocationGeneration);
        f[7]=SHA256.HashData(authority.Authority.MailboxIssuerEd25519PublicKey.Span);f[9]=U64(1);f[10]=routerEd.PublicKey;f[11]=routerX;
        f[12]=Bytes(0xd1,32);f[13]=U64(1);f[14]=U64(17);f[15]=U64(1000);f[16]=U64(1150);f[18]=transcript;
        f[8]=Domain("Deep/NativeRouting/V1/router-id",Combine(network,mailbox.MailboxOwnerId.ToArray(),U64(1),routerEd.PublicKey));
        var record=CanonicalGrammar.DecodeOwned(CanonicalGrammar.Encode(RecordDefinitions.Dnr1,f),RecordDefinitions.Dnr1);
        var signing=CanonicalGrammar.GetSigningBytes(record,"Deep/NativeRouting/V1/router-certificate");
        f[19]=PublicKeyAuth.SignDetached(signing,routerEd.PrivateKey);f[20]=PublicKeyAuth.SignDetached(signing,issuerPrivate);
        return CanonicalGrammar.Encode(RecordDefinitions.Dnr1,f);
    }

    private static byte[] Mrl(byte[] network,byte[] router,byte[] dnr,byte[] dpc)
    {var f=Min(RecordDefinitions.Mrl2);f[0]=network;f[1]=U64(9);f[2]=U64(1);f[3]=router;f[4]=dnr;f[5]=U64(1);f[6]=U64(17);f[7]=U64(1);f[8]=dpc;f[9]=U64(1000);f[10]=U64(1150);return CanonicalGrammar.Encode(RecordDefinitions.Mrl2,f);}

    private static byte[] Dxr(byte[] dnr,DxpOperationSource source,byte[] transcript,ReadOnlySpan<byte> keyId)
    {var r=CanonicalGrammar.DecodeOwned(dnr,RecordDefinitions.Dnr1);var f=Min(RecordDefinitions.Dxr1);f[0]=new byte[]{1};f[1]=new byte[]{2};f[2]=r.FieldCopy(1);f[3]=Bytes(0xe2,32);f[4]=DxpSubjectProjection.HashRouter(r);f[5]=r.FieldCopy(12);f[6]=Bytes(0xe3,32);f[7]=Bytes(0xe4,32);f[8]=Bytes(0xe5,32);f[9]=U64(1000);f[10]=U64(1150);f[11]=U64(1010);f[12]=transcript;f[13]=NewRef(ArtifactType.Dnr1,dnr);f[14]=source.Fingerprint.ToArray();f[15]=keyId.ToArray();f[17]=U64(1300);return Protect(RecordDefinitions.Dxr1,f);}

    private static byte[] Mrlc(CurrentCutoverRelative c,byte[] catalog,byte[] mng,byte[] closure,byte[] msm,byte[] root,byte[] pma,byte[] pmr,VerifiedProductionMailboxAuthority a,VerifiedProductionMailboxRevocationSnapshot r,byte[] selection,ulong membershipSequence=7)
    {var f=Min(RecordDefinitions.Mrlc);f[0]=c.TrustedNetwork.ToArray();f[1]=c.TrustedResetId.ToArray();f[2]=c.TrustedDcpRef.ToArray();f[3]=c.TrustedDcsRef.ToArray();f[4]=c.TrustedDcqRef.ToArray();f[5]=c.TrustedDwlRef.ToArray();f[6]=U64(c.DrsRevision);f[7]=c.TrustedDrsRef.ToArray();f[8]=mng;f[9]=closure;f[10]=msm;f[11]=U64(membershipSequence);f[12]=U32(1);f[13]=root;f[14]=pma;f[15]=U64(a.Authority.AuthorityGeneration);f[16]=U64(a.Authority.CurrentEpoch.Epoch);f[17]=pmr;f[18]=U64(r.Snapshot.RevocationGeneration);f[19]=r.Snapshot.RevocationHeadHash;f[20]=r.CanonicalSnapshotHash;f[21]=selection;f[22]=U32(9);f[23]=U64((ulong)catalog.Length);f[24]=Domain("Deep/NativeRouting/V2/catalog-hash",Combine(U32(9),U64((ulong)catalog.Length),catalog));f[25]=catalog;return Protect(RecordDefinitions.Mrlc,f);}

    private static byte[] DpcFor(byte[] network,byte[] routerId,byte[] dnrRef,KeyPair router,
        bool dnsEndpoint = false)
    {var f=Min(RecordDefinitions.Dpc1);f[0]=network;f[1]=routerId;f[2]=dnrRef;f[3]=U64(1);f[5]=U64(1000);f[6]=U64(1150);f[7]=U64(17);f[8]=new byte[]{dnsEndpoint?(byte)3:(byte)1};f[9]=dnsEndpoint?"router.example"u8.ToArray():new byte[]{8,8,8,8};f[10]=U16(443);f[11]=Bytes(0xd2,32);f[13]=U64(1);var rec=CanonicalGrammar.DecodeOwned(CanonicalGrammar.Encode(RecordDefinitions.Dpc1,f),RecordDefinitions.Dpc1);f[14]=PublicKeyAuth.SignDetached(CanonicalGrammar.GetSigningBytes(rec,"Deep/NativeRouting/V1/contact"),router.PrivateKey);return CanonicalGrammar.Encode(RecordDefinitions.Dpc1,f);}

    private static byte[] SignedMembership(
        SignerDelegation delegation,
        NodeMembershipCommitment statement,
        byte[] signingBytes,
        DeterministicMembershipVerifier verifier)
    {
        var signatures = delegation.OnlineSigners.Take(2).Select(signer =>
            new MembershipSignature
            {
                SignerId = signer.SignerId.ToArray(),
                Domain = MembershipSignatureDomain.Membership,
                Signature = verifier.Sign(
                    signer.SignerId.Span, signer.PublicKey.Span,
                    MembershipSignatureDomain.Membership, signingBytes)
            }).ToArray();
        return MembershipContractCodec.EncodeSignedMembership(
            new SignedMembershipCommitment
            {
                Statement = statement,
                Signatures = signatures
            });
    }

    private static byte[] Row(ArtifactType t,byte[] b){var r=ArtifactRegistry.IsRetained(t)?RetainedRef(t,b):NewRef(t,b);return Combine(U16((ushort)t),U32((uint)b.Length),r[6..],b);}
    private static byte[] Catalog(byte[][] rows)=>Combine(Encoding.ASCII.GetBytes("MRC1"),new byte[]{1,0},U32((uint)rows.Length),Combine(rows));
    private static byte[] TransitionHash(byte[] canonical,int count)
    {
        var catalog=MembershipCatalogParser.DecodeOwned(canonical,9,1);
        var payload=new List<byte>();payload.AddRange(U16(checked((ushort)count)));
        for(var index=0;index<count;index++)
        {
            var row=catalog.Rows[index+1];
            payload.AddRange(U16((ushort)row.Type));
            payload.AddRange(U32(checked((uint)row.CanonicalLength)));
            payload.AddRange(row.CanonicalHash.ToArray());
            payload.AddRange(catalog.RowBytes(index+1).ToArray());
        }
        return Domain("Deep/NativeRouting/V2/membership-transition-container",payload.ToArray());
    }
    private static byte[] MembershipHead(byte[] n,byte[] mng,byte[] trans,ulong seq,byte[] hash,byte[] msm)=>Combine(n,mng,trans,U64(seq),hash,msm);
    private static byte[] Composite(byte[] n,byte[] msm,ulong seq,uint count,byte[] root,byte[] pma,ulong pmaGen,ulong epoch,byte[] pmr,ulong pmrGen,byte[] head,byte[] snap,byte[] members)=>Domain("Deep/NativeRouting/V2/composite-selection",Combine(n,msm,U64(seq),U32(count),root,pma,U64(pmaGen),U64(epoch),pmr,U64(pmrGen),head,snap,members));
    private static byte[] Protect(RecordDefinition d,ReadOnlyMemory<byte>[] f){var unsignedDef=d with{Fields=d.Fields.Take(d.Fields.Count-1).ToArray(),MinimumLength=12,MaximumLength=d.MaximumLength,OmittedSigningFieldIndexes=new HashSet<int>()};var unsigned=CanonicalGrammar.Encode(unsignedDef,f.Take(f.Length-1).ToArray());f[^1]=Tag(ArtifactRegistry.GetProtectedDomain(d.Magic),unsigned);return CanonicalGrammar.Encode(d,f);}
    private static byte[] Tag(string domain,byte[] unsigned){var db=Encoding.ASCII.GetBytes(domain);var input=Combine(U16((ushort)db.Length),db,U16(0x8001),U32((uint)unsigned.Length),unsigned);return HMACSHA256.HashData(HmacKey,input);}
    private static byte[] NewRef(ArtifactType t,ReadOnlySpan<byte> b)=>CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(t,b));
    private static byte[] RetainedRef(ArtifactType t,ReadOnlySpan<byte> b)=>CanonicalGrammar.EncodeReference(new ArtifactReference(t,(uint)b.Length,SHA256.HashData(b)));
    private static byte[] Ref(ArtifactType t,uint l,byte v)=>CanonicalGrammar.EncodeReference(new ArtifactReference(t,l,Bytes(v,32)));
    private static byte[] Domain(string d,byte[] p)=>CanonicalGrammar.Sha256Domain(d,p);
    private static ReadOnlyMemory<byte>[] Min(RecordDefinition d)=>d.Fields.Select(x=>(ReadOnlyMemory<byte>)new byte[x.MinimumLength]).ToArray();
    private static byte[] Combine(params byte[][] values){var b=new byte[values.Sum(x=>x.Length)];var o=0;foreach(var v in values){v.CopyTo(b,o);o+=v.Length;}return b;}
    private static byte[] Bytes(byte v,int l)=>Enumerable.Repeat(v,l).ToArray();
    private static byte[] U16(ushort v){var b=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(b,v);return b;}
    private static byte[] U32(uint v){var b=new byte[4];BinaryPrimitives.WriteUInt32BigEndian(b,v);return b;}
    private static byte[] U64(ulong v){var b=new byte[8];BinaryPrimitives.WriteUInt64BigEndian(b,v);return b;}
    private static ProductionMailboxAuthorityEndpoint Endpoint(string uri,byte seed)=>new(){Uri=uri,CurrentSpkiSha256=Bytes(seed,32),NextSpkiSha256=Bytes((byte)(seed+1),32)};
    private static ProductionMailboxAuthorityEpoch Epoch(ulong e,ulong g,ulong f,ulong u,byte[] root)=>new(){Epoch=e,Generation=g,MembershipCommitment=root,TopologyPlacementCommitment=Bytes(0x71,32),NotBeforeUnixSeconds=f,NotAfterUnixSeconds=u};
    private sealed class HmacProvider(byte[] key):IProtectedHmacProvider{public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(ProtectedHmacRequest r,CancellationToken c){var d=Encoding.ASCII.GetBytes(r.Domain);return ValueTask.FromResult<ReadOnlyMemory<byte>>(HMACSHA256.HashData(key,Combine(U16((ushort)d.Length),d,U16(r.Suite),U32((uint)r.UnsignedCanonical.Length),r.UnsignedCanonical.ToArray())));}}
}
