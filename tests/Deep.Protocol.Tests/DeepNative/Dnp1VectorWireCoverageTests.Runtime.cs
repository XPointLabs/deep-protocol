using System.Buffers.Binary;
using System.Reflection;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class VectorWireCoverageTestsRuntime
{
    [Fact]
    public void MembershipMrl2ProjectionCycleBreak() =>
        new NativeMembershipVerifierTests().Mrl2Projection_ZerosOnlyDnrAndAnchorReferences();

    [Fact]
    public void MembershipMrl2FullLeafReject() =>
        new NativeMembershipVerifierTests().FullMrl2LeafFormula_DiffersFromRequiredProjection();

    [Fact]
    public void MembershipMrl2ProjectionSubstitutionCrossFeed() =>
        new NativeMembershipVerifierTests().Mrl2Leaf_UsesProjectionButRetainsEveryOtherFullRowByte();

    [Fact]
    public void MembershipMrlV1V2CrossFeed()
    {
        new NativeMembershipVerifierTests()
            .Mrl2Leaf_UsesProjectionButRetainsEveryOtherFullRowByte();
        var carrier = new MailboxMembershipCarrierTests();
        carrier.LegacyInnerMagic_RejectsBeforeOwnership("MRL1");
        carrier.LegacyInnerMagic_RejectsBeforeOwnership("RIP1");
    }

    [Fact]
    public void MembershipMrl2ZeroFullRefs() =>
        new NativeMembershipVerifierTests().Mrl2Projection_RejectsPartialOrMalformedFullRows();

    [Fact]
    public void MembershipRip2Valid() =>
        new NativeMembershipVerifierTests().SingleMemberRip2_VerifiesAndReturnsDefensiveSealedCapability();

    [Fact]
    public void MembershipRip2LegacyReject()
    {
        var tests = new MailboxMembershipCarrierTests();
        tests.LegacyInnerMagic_RejectsBeforeOwnership("RIP1");
        tests.LegacyInnerMagic_RejectsBeforeOwnership("MRL1");
    }

    [Fact]
    public void MembershipMailboxP04Mip1CrossFeed() =>
        new MailboxMembershipCarrierTests().P04MembershipContractMip1_IsNotTheMailboxCarrier();

    [Fact]
    public void MembershipMrlcCanonicalContainer()
    {
        var tests = new MembershipCatalogTests();
        tests.ExactEightRowCatalog_PreflightsOwnsAndVerifiesReferences();
        tests.OrderOrLateHashMutation_Rejects();
        tests.HostileIntMaxRowLength_IsNormalizedBeforeOwnership();
    }

    [Fact]
    public async Task MembershipMrlcColdRestore() =>
        await new MembershipClosureIntegrationTests()
            .RestoreCurrent_RealCompositeClosure_BindsProjectionFullRefsAndCurrentSources();

    [Fact]
    public async Task MembershipMrlcHmacCatalogCorrupt() =>
        await new MembershipCatalogEnvelopeTests().ZeroKeyIdOrCatalogHashMix_Rejects();

    [Fact]
    public void MembershipMrcMemberEntryCounts()
    {
        var catalog = MembershipCatalogTests.Catalog();
        Assert.Throws<RecordException>(() =>
            MembershipCatalogParser.Preflight(catalog, 7, 1));
        Assert.Throws<RecordException>(() =>
            MembershipCatalogParser.Preflight(catalog, 8, 0));
        Assert.Throws<RecordException>(() =>
            MembershipCatalogParser.Preflight(catalog, 8, 2));

        var transitionMaxPlusOne = new byte[10];
        "MRC1"u8.CopyTo(transitionMaxPlusOne);
        transitionMaxPlusOne[4] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(transitionMaxPlusOne.AsSpan(6), 4_105);
        Assert.Throws<RecordException>(() =>
            MembershipCatalogParser.Preflight(transitionMaxPlusOne, 4_105, 1));

        var entryMaxPlusOne = transitionMaxPlusOne.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(entryMaxPlusOne.AsSpan(6),
            checked((uint)MembershipCatalogParser.MaximumEntries + 1));
        Assert.Throws<RecordException>(() =>
            MembershipCatalogParser.Preflight(
                entryMaxPlusOne,
                checked((uint)MembershipCatalogParser.MaximumEntries + 1),
                1));
    }

    [Fact]
    public void MembershipRip2CountIndexCrossFeed()
    {
        var fixture = MembershipFixture();
        foreach (var mutation in new (int Tag, byte[] Value)[]
        {
            (1, WireBytes(90, 16)),
            (2, WireBytes(91, 32)),
            (3, WireU64(12)),
            (4, WireU64(8)),
            (6, WireU64(10)),
            (7, WireU32(0)),
            (8, WireU32(2)),
            (9, WireU32(1)),
            (10, WireBytes(92, 32))
        })
        {
            var rip = fixture.Rip.ToArray();
            mutation.Value.CopyTo(rip, WireFieldOffset(rip, mutation.Tag));
            var outer = MailboxPeerReplicationCodec.EncodeMembershipProof(
                fixture.Proof with { CanonicalInclusionProof = rip });
            var exception = Record.Exception(() =>
                NativeMembershipVerifier.VerifyMailboxMembership(outer, fixture.Lkg));
            Assert.True(exception is RecordException,
                $"RIP2 cross-feed tag {mutation.Tag} unexpectedly verified.");
        }
    }

    [Fact]
    public void MembershipRip2SealedFullTuple()
    {
        var fixture = MembershipFixture();
        var valid = MailboxPeerReplicationCodec.EncodeMembershipProof(fixture.Proof);
        NativeMembershipVerifier.VerifyMailboxMembership(valid, fixture.Lkg);

        var changedDnr = fixture.Dnr.ToArray();
        changedDnr[6] ^= 1;
        var dnrLkg = MembershipLkg(
            fixture.Network, fixture.Reset, fixture.Router, fixture.Key,
            changedDnr, fixture.Mrl, fixture.Root);
        Assert.Throws<RecordException>(() =>
            NativeMembershipVerifier.VerifyMailboxMembership(valid, dnrLkg));

        var changedMrl = fixture.Mrl.ToArray();
        changedMrl[WireFieldOffset(changedMrl, 9) + 6] ^= 1;
        var dpcLkg = MembershipLkg(
            fixture.Network, fixture.Reset, fixture.Router, fixture.Key,
            fixture.Dnr, changedMrl, fixture.Root);
        Assert.Throws<RecordException>(() =>
            NativeMembershipVerifier.VerifyMailboxMembership(valid, dpcLkg));
    }

    [Fact]
    public void MembershipMrl2PriorFullLkg()
    {
        var fixture = MembershipFixture();
        var prior = fixture.Lkg.TrustedRouters[0];
        var validate = (ValidateMrlPredecessorDelegate)typeof(MembershipClosureVerifier)
            .GetMethod("ValidateMrlPredecessor", BindingFlags.Static | BindingFlags.NonPublic)!
            .CreateDelegate(typeof(ValidateMrlPredecessorDelegate));

        var valid = MembershipMrlCandidate(
            fixture.Network, fixture.Router, fixture.Dnr, 10, prior.FullMrlReference);
        validate(CanonicalGrammar.DecodeOwned(valid, RecordDefinitions.Mrl2),
            fixture.Router, fixture.Lkg);

        Assert.Throws<RecordException>(() => validate(
            CanonicalGrammar.DecodeOwned(valid, RecordDefinitions.Mrl2),
            fixture.Router, null));

        var skipped = MembershipMrlCandidate(
            fixture.Network, fixture.Router, fixture.Dnr, 11, prior.FullMrlReference);
        Assert.Throws<RecordException>(() => validate(
            CanonicalGrammar.DecodeOwned(skipped, RecordDefinitions.Mrl2),
            fixture.Router, fixture.Lkg));

        var alternate = prior.FullMrlReference.ToArray();
        alternate[6] ^= 1;
        var substituted = MembershipMrlCandidate(
            fixture.Network, fixture.Router, fixture.Dnr, 10, alternate);
        Assert.Throws<RecordException>(() => validate(
            CanonicalGrammar.DecodeOwned(substituted, RecordDefinitions.Mrl2),
            fixture.Router, fixture.Lkg));

        var invalidGenesis = MembershipMrlCandidate(
            fixture.Network, fixture.Router, fixture.Dnr, 1, prior.FullMrlReference);
        Assert.Throws<RecordException>(() => validate(
            CanonicalGrammar.DecodeOwned(invalidGenesis, RecordDefinitions.Mrl2),
            fixture.Router, null));
    }

    [Fact]
    public void RoutingDpcAnchorAndSuccessor() =>
        new NativeRoutingVerifierTests().AnchorAndSuccessor_VerifyExactMrlBindingAndDefensiveOwnership();

    [Fact]
    public void RoutingPublicAddressClosedTable() =>
        new OuterPeerJournalTests().AddressPolicy_NormalizesMappedAndRejectsEveryNamedPrivateBoundary();

    [Fact]
    public void RoutingRoleCapabilityFlags()
    {
        var network = WireBytes(1, 16);
        var router = WireBytes(2, 32);
        var dnr = WireReference(ArtifactType.Dnr1, 756, 3);

        var mailboxOnly = RouterCapabilities.ClientMailboxIngressV2;
        var invalidRoleContact = RoutingContact(
            network, router, dnr, mailboxOnly, noNext: true, nextPinMarker: 0);
        var invalidRoleMrl = RoutingMrl(
            network, router, dnr, RouterRoles.PeerIngress, mailboxOnly,
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Dpc1, invalidRoleContact)));
        var invalidRoleMembership = RoutingMembership(
            invalidRoleMrl, router, RouterRoles.PeerIngress, mailboxOnly);
        Assert.Equal(RecordError.InvalidField,
            Assert.Throws<RecordException>(() =>
                new NativeRoutingVerifier().VerifyAnchorContact(
                    invalidRoleMembership, invalidRoleContact, 20)).Error);

        var native = RouterCapabilities.NativePeerMailboxV2;
        var invalidPins = RoutingContact(
            network, router, dnr, native, noNext: false, nextPinMarker: 0);
        var invalidPinMrl = RoutingMrl(
            network, router, dnr, RouterRoles.MailboxReplica, native,
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Dpc1, invalidPins)));
        var invalidPinMembership = RoutingMembership(
            invalidPinMrl, router, RouterRoles.MailboxReplica, native);
        Assert.Equal(RecordError.InvalidField,
            Assert.Throws<RecordException>(() =>
                new NativeRoutingVerifier().VerifyAnchorContact(
                    invalidPinMembership, invalidPins, 20)).Error);
    }

    [Fact]
    public void PeerOuterRequestHashTranscript() =>
        new OuterPeerJournalTests().RequestAndOutcomeHashes_UseExactNormativeFrameOrder();

    [Fact]
    public void PeerOuterOutcomeHashTranscript() =>
        new OuterPeerJournalTests().RequestAndOutcomeHashes_UseExactNormativeFrameOrder();

    [Fact]
    public async Task PeerOuterJournalForkStale() =>
        await new OuterPeerJournalTests().SameLiveIndexWithChangedRequestHash_LatchesForkBeforeInnerCallback();

    [Fact]
    public async Task PeerOuterJournalTerminalShape() =>
        await new OuterPeerJournalTests().EqualityAtExpiry_IsTerminalAndInvokesNoInnerCallback();

    [Fact]
    public void PeerSenderRecipientDpcSwap()
    {
        var fixtureType = typeof(NativePeerVerifierTests).GetNestedType(
            "Fixture", BindingFlags.NonPublic)!;
        var fixture = fixtureType.GetMethod(
            "Create", BindingFlags.Static | BindingFlags.NonPublic)!.Invoke(null, null)!;
        var frame = PeerFixtureValue<byte[]>(fixtureType, fixture, "Frame").ToArray();
        var dpr = frame.AsSpan(4, NativePeerVerifier.DprLength);
        var senderOffset = WireFieldOffset(dpr, 4);
        var recipientOffset = WireFieldOffset(dpr, 5);
        var sender = dpr.Slice(senderOffset, 38).ToArray();
        dpr.Slice(recipientOffset, 38).CopyTo(dpr.Slice(senderOffset, 38));
        sender.CopyTo(dpr.Slice(recipientOffset, 38));

        var error = Assert.Throws<RecordException>(() =>
            NativePeerVerifier.VerifyRequest(
                frame,
                PeerFixtureValue<VerifiedMembershipRoutingLkg>(fixtureType, fixture, "Lkg"),
                PeerFixtureValue<VerifiedRouterContact>(fixtureType, fixture, "SenderContact"),
                PeerFixtureValue<VerifiedRouterContact>(fixtureType, fixture, "RecipientContact"),
                PeerFixtureValue<BlindedPlacementId>(fixtureType, fixture, "PlacementId"),
                1050));
        Assert.Equal(RecordError.InvalidField, error.Error);
    }

    [Fact]
    public void PeerPrqRequestIdWindowHash() =>
        new NativePeerVerifierTests()
            .OuterInnerRequestBindings_RejectBeforeInvalidOuterSignature();

    [Fact]
    public void PeerOuterInnerOperationDiscriminators() =>
        new NativePeerVerifierTests()
            .OuterInnerOperationDiscriminators_RejectBeforeParsingOrSignature();

    [Fact]
    public async Task RecoveryNonceReuseLatch() =>
        await new RecoveryProviderTests().NonceMismatchOrFork_RejectsBeforeOpen();

    [Fact]
    public async Task RecoveryDrmOrderRowCorrupt() =>
        await new RecoveryProviderTests().MalformedOpenedManifest_RejectsAfterExactlyOneAeadOpen();

    private static MembershipVectorFixture MembershipFixture()
    {
        var network = WireBytes(1, 16);
        var reset = WireBytes(2, 32);
        var router = WireBytes(3, 32);
        var key = WireBytes(4, 32);
        var dnr = WireReference(ArtifactType.Dnr1, 756, 5);
        var mrl = MembershipMrl(network, router, dnr);
        var root = NativeMembershipVerifier.Root(
            reset, 7, 1, 1,
            NativeMembershipVerifier.RealLeaf(reset, 7, 9, 0, mrl));
        var rip = MembershipRip(network, reset, root, mrl);
        var proof = new MailboxReplicaMembershipProof
        {
            ReplicaId = router,
            SigningPublicKey = key,
            Epoch = 7,
            MembershipCommitment = root,
            CanonicalInclusionProof = rip
        };
        return new MembershipVectorFixture(
            network, reset, router, key, dnr, mrl, root, rip, proof,
            MembershipLkg(network, reset, router, key, dnr, mrl, root));
    }

    private static VerifiedMembershipRoutingLkg MembershipLkg(
        byte[] network, byte[] reset, byte[] router, byte[] key,
        byte[] dnr, byte[] mrl, byte[] root) => new(
            network, reset, 11, 7, 100, root, WireBytes(9, 32),
            [new VerifiedRouterEntry(
                router, key, dnr, mrl, 9,
                RouterRoles.MailboxReplica,
                RouterCapabilities.NativePeerMailboxV2)]);

    private static byte[] MembershipMrl(byte[] network, byte[] router, byte[] dnr)
    {
        var fields = WireFields(RecordDefinitions.Mrl2);
        fields[0] = network; fields[1] = WireU64(7); fields[2] = WireU64(9);
        fields[3] = router; fields[4] = dnr;
        fields[5] = WireU64((ulong)RouterRoles.MailboxReplica);
        fields[6] = WireU64((ulong)RouterCapabilities.NativePeerMailboxV2);
        fields[7] = WireU64(1);
        fields[8] = WireReference(ArtifactType.Dpc1, 431, 6);
        fields[9] = WireU64(1); fields[10] = WireU64(100); fields[11] = new byte[38];
        return CanonicalGrammar.Encode(RecordDefinitions.Mrl2, fields);
    }

    private static byte[] MembershipRip(byte[] network, byte[] reset, byte[] root, byte[] mrl)
    {
        var fields = WireFields(RecordDefinitions.Rip2);
        fields[0] = network; fields[1] = reset; fields[2] = WireU64(11);
        fields[3] = WireU64(7); fields[4] = WireU16(2); fields[5] = WireU64(9);
        fields[6] = WireU32(1); fields[7] = WireU32(1); fields[8] = WireU32(0);
        fields[9] = root; fields[10] = WireU32(326); fields[11] = mrl;
        fields[12] = new byte[] { 0 }; fields[13] = Array.Empty<byte>();
        return CanonicalGrammar.Encode(RecordDefinitions.Rip2, fields);
    }

    private static byte[] MembershipMrlCandidate(
        byte[] network, byte[] router, byte[] dnr, ulong generation,
        ReadOnlySpan<byte> predecessor)
    {
        var fields = WireFields(RecordDefinitions.Mrl2);
        fields[0] = network; fields[1] = WireU64(7); fields[2] = WireU64(generation);
        fields[3] = router; fields[4] = dnr;
        fields[5] = WireU64((ulong)RouterRoles.MailboxReplica);
        fields[6] = WireU64((ulong)RouterCapabilities.NativePeerMailboxV2);
        fields[7] = WireU64(1);
        fields[8] = WireReference(ArtifactType.Dpc1, 431, 6);
        fields[9] = WireU64(1); fields[10] = WireU64(100);
        fields[11] = predecessor.ToArray();
        return CanonicalGrammar.Encode(RecordDefinitions.Mrl2, fields);
    }

    private static byte[] RoutingContact(
        byte[] network, byte[] router, byte[] dnr,
        RouterCapabilities capabilities, bool noNext, byte nextPinMarker)
    {
        var fields = WireFields(RecordDefinitions.Dpc1);
        fields[0] = network; fields[1] = router; fields[2] = dnr;
        fields[3] = WireU64(4); fields[4] = new byte[38];
        fields[5] = WireU64(10); fields[6] = WireU64(50);
        fields[7] = WireU64((ulong)capabilities); fields[8] = new byte[] { 1 };
        fields[9] = new byte[] { 8, 8, 8, 8 }; fields[10] = WireU16(443);
        fields[11] = WireBytes(8, 32);
        fields[12] = nextPinMarker == 0 ? new byte[32] : WireBytes(nextPinMarker, 32);
        fields[13] = WireU64(noNext ? 1UL : 0UL); fields[14] = new byte[64];
        return CanonicalGrammar.Encode(RecordDefinitions.Dpc1, fields);
    }

    private static byte[] RoutingMrl(
        byte[] network, byte[] router, byte[] dnr,
        RouterRoles roles, RouterCapabilities capabilities, byte[] anchor)
    {
        var fields = WireFields(RecordDefinitions.Mrl2);
        fields[0] = network; fields[1] = WireU64(7); fields[2] = WireU64(9);
        fields[3] = router; fields[4] = dnr; fields[5] = WireU64((ulong)roles);
        fields[6] = WireU64((ulong)capabilities); fields[7] = WireU64(4);
        fields[8] = anchor; fields[9] = WireU64(10); fields[10] = WireU64(100);
        fields[11] = new byte[38];
        return CanonicalGrammar.Encode(RecordDefinitions.Mrl2, fields);
    }

    private static VerifiedMrl2Membership RoutingMembership(
        byte[] mrl, byte[] router, RouterRoles roles, RouterCapabilities capabilities) =>
        new(new byte[693], mrl, router, WireBytes(4, 32),
            NativeMembershipVerifier.RealLeaf(new byte[32], 7, 9, 0, mrl),
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Mrl2, mrl)), 7, 9, roles, capabilities);

    private static ReadOnlyMemory<byte>[] WireFields(RecordDefinition definition) =>
        definition.Fields.Select(field =>
            (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();

    private static int WireFieldOffset(ReadOnlySpan<byte> canonical, int tag)
    {
        var offset = CanonicalGrammar.HeaderLength;
        for (var current = 1; current <= tag; current++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(
                canonical.Slice(offset + 4, 4)));
            offset += CanonicalGrammar.FieldHeaderLength;
            if (current == tag) return offset;
            offset += length;
        }
        throw new ArgumentOutOfRangeException(nameof(tag));
    }

    private static byte[] WireReference(ArtifactType type, uint length, byte marker)
    {
        var value = new byte[38];
        BinaryPrimitives.WriteUInt16BigEndian(value, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(2), length);
        value[6] = marker;
        return value;
    }

    private static byte[] WireBytes(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private static T PeerFixtureValue<T>(Type fixtureType, object fixture, string name) =>
        (T)fixtureType.GetProperty(
            name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!.GetValue(fixture)!;
    private static byte[] WireU16(ushort value)
    {
        var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes;
    }
    private static byte[] WireU32(uint value)
    {
        var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes;
    }
    private static byte[] WireU64(ulong value)
    {
        var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes;
    }

    private sealed record MembershipVectorFixture(
        byte[] Network,
        byte[] Reset,
        byte[] Router,
        byte[] Key,
        byte[] Dnr,
        byte[] Mrl,
        byte[] Root,
        byte[] Rip,
        MailboxReplicaMembershipProof Proof,
        VerifiedMembershipRoutingLkg Lkg);

    private delegate void ValidateMrlPredecessorDelegate(
        OwnedRecord mrl,
        ReadOnlySpan<byte> routerId,
        VerifiedMembershipRoutingLkg? predecessor);

}
