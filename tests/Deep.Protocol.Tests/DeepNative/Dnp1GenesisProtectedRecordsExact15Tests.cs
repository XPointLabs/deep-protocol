using System.Buffers.Binary;
using System.Reflection;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisProtectedRecordsExact15Tests
{
    [Fact]
    public void ExactWireLayouts_AcceptNormativeLengthsAndOffsets()
    {
        var grr = Grr();
        var gri = Gri(grr);
        var gti = Gti();
        var gas = Gas(33_558_991);
        var gqp = Gqp();
        var gqs = Gqs();
        var created = Gaj(0);
        var external = Gaj(1);
        var local = Gaj(2);

        GenesisProtectedRecords.PreflightGri(gri);
        GenesisProtectedRecords.PreflightGrr(grr);
        GenesisProtectedRecords.PreflightGti(gti);
        GenesisProtectedRecords.PreflightGas(gas);
        GenesisProtectedRecords.PreflightGqp(gqp);
        GenesisProtectedRecords.PreflightGqs(gqs);
        GenesisProtectedRecords.PreflightGaj(created);
        GenesisProtectedRecords.PreflightGaj(external);
        GenesisProtectedRecords.PreflightGaj(local);

        Assert.Equal(217, gri.Length);
        Assert.Equal(381, grr.Length);
        Assert.Equal(243, gti.Length);
        Assert.Equal(285, gas.Length);
        Assert.Equal(461, gqp.Length);
        Assert.Equal(580, gqs.Length);
        Assert.Equal(880, created.Length);
        Assert.Equal((byte)1, grr[307]);
        Assert.Equal((byte)1, gas[220]);
        Assert.Equal((byte)1, gqp[395]);
        Assert.Equal((byte)0, created[194]);
        Assert.Equal((byte)1, external[194]);
        Assert.Equal((byte)2, local[194]);
    }

    [Fact]
    public void ArtifactReceipt_EnforcesExactSevenAndMax33558991()
    {
        GenesisProtectedRecords.PreflightGas(Gas(33_558_991));

        var wrongCount = Gas(1);
        BinaryPrimitives.WriteUInt16BigEndian(wrongCount.AsSpan(130, 2), 6);
        Assert.Throws<RecordException>(() => GenesisProtectedRecords.PreflightGas(wrongCount));

        Assert.Throws<RecordException>(() =>
            GenesisProtectedRecords.PreflightGas(Gas(33_558_992)));
    }

    [Fact]
    public void ResetReservation_StateIsImmutableReservedOne()
    {
        GenesisProtectedRecords.PreflightGrr(Grr());
        foreach (var state in new byte[] { 0, 2, 255 })
        {
            var changed = Grr();
            changed[307] = state;
            Assert.Throws<RecordException>(() => GenesisProtectedRecords.PreflightGrr(changed));
        }

        var forked = Grr();
        forked[316] = 1;
        Assert.Throws<RecordException>(() => GenesisProtectedRecords.PreflightGrr(forked));
    }

    [Fact]
    public async Task ResetReservationResult_VerifiesExact381ShapeAndHasNoPublicRawIdsOrAuthorityConversion()
    {
        var grr = Grr();
        var logicalKey = new byte[49];
        logicalKey[0] = 1;
        grr.AsSpan(9, 16).CopyTo(logicalKey.AsSpan(1));
        logicalKey.AsSpan(17, 32).Fill(0x29);
        var request = new GenesisResetReservationRequest(grr.AsSpan(8, 235), logicalKey);
        var gri = Gri(grr);
        request.LogicalScopeHash.Span.CopyTo(gri.AsSpan(8, 32));
        request.IntentHash.Span.CopyTo(gri.AsSpan(40, 32));
        var provider = new ResetProvider(gri, grr);
        var hmac = new MatchingHmac();

        var result = await GenesisReservationVerifier.RestoreResetAsync(
            provider, request, hmac, default);

        Assert.True(result.NoAuthorityClaim);
        Assert.Equal(381, grr.Length);
        Assert.Equal(GenesisProtectedRecords.ReservationHash(grr),
            result.ReservationHash.ToArray());
        Assert.Equal(1, provider.Calls);
        Assert.Equal(new[]
        {
            "Deep/ProtectedState/V1/GRI1",
            "Deep/ProtectedState/V1/GRR1"
        }, hmac.Domains);

        var type = result.GetType();
        var members = type.GetMembers(BindingFlags.Public | BindingFlags.Instance |
                                      BindingFlags.Static | BindingFlags.DeclaredOnly);
        Assert.True(type.IsSealed);
        Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(members, member =>
            member.Name.Contains("ResetId", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("OperationId", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("Parse", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("Authority", StringComparison.OrdinalIgnoreCase) &&
            member.Name is not ("NoAuthorityClaim" or "get_NoAuthorityClaim"));
    }

    [Fact]
    public void ResetReservationRequestShape_RejectsEveryMalformedAxisBeforeProvider()
    {
        var firstIntent = new byte[235];
        firstIntent[0] = 1;
        Fill(firstIntent, 1, 16, 0x31);
        Fill(firstIntent, 49, 32, 0x32);
        U64(firstIntent, 81, 1);
        DpaReference(0x33).CopyTo(firstIntent, 127);
        var firstLogical = new byte[49];
        firstLogical[0] = 1;
        firstIntent.AsSpan(1, 16).CopyTo(firstLogical.AsSpan(1));
        Fill(firstLogical, 17, 32, 0x34);

        var first = new GenesisResetReservationRequest(firstIntent, firstLogical);
        var operationId = Enumerable.Repeat((byte)0x35, 32).ToArray();
        var expanded = first.Intent.ToArray().Concat(operationId).ToArray();
        Assert.Equal(235, first.Intent.Length);
        Assert.Equal(49, first.LogicalKey.Length);
        Assert.Equal(267, expanded.Length);
        Assert.Equal(operationId, expanded[235..]);

        var resetIntent = new byte[235];
        resetIntent[0] = 2;
        Fill(resetIntent, 1, 16, 0x41);
        Fill(resetIntent, 17, 32, 0x42);
        Fill(resetIntent, 49, 32, 0x43);
        U64(resetIntent, 81, 2);
        DpaReference(0x44).CopyTo(resetIntent, 89);
        DpaReference(0x45).CopyTo(resetIntent, 127);
        Fill(resetIntent, 203, 32, 0x46);
        var resetLogical = new byte[57];
        resetLogical[0] = 2;
        resetIntent.AsSpan(1, 16).CopyTo(resetLogical.AsSpan(1));
        U64(resetLogical, 17, 1);
        resetIntent.AsSpan(17, 32).CopyTo(resetLogical.AsSpan(25));
        var reset = new GenesisResetReservationRequest(resetIntent, resetLogical);
        Assert.Equal(235, reset.Intent.Length);
        Assert.Equal(57, reset.LogicalKey.Length);

        Assert.Empty(typeof(GenesisResetReservationRequest).GetConstructors(
            BindingFlags.Public | BindingFlags.Instance));

        Invalid(firstIntent[..234], firstLogical);
        Mutate(firstIntent, firstLogical, static (intent, _) => intent[0] = 3);
        Mutate(firstIntent, firstLogical, static (intent, _) => intent.AsSpan(1, 16).Clear());
        Mutate(firstIntent, firstLogical, static (intent, _) => intent.AsSpan(49, 32).Clear());
        Mutate(firstIntent, firstLogical, static (intent, _) => intent.AsSpan(81, 8).Clear());
        Mutate(firstIntent, firstLogical, static (intent, _) => intent.AsSpan(127, 38).Clear());
        Mutate(firstIntent, firstLogical, static (intent, _) => intent[127] = 0xff);
        Mutate(firstIntent, firstLogical, static (intent, _) => intent[17] = 1);
        Mutate(firstIntent, firstLogical, static (intent, _) => intent[165] = 1);
        Mutate(firstIntent, firstLogical, static (intent, _) => intent[203] = 1);
        Mutate(firstIntent, firstLogical, static (_, logical) => logical.AsSpan(17, 32).Clear());
        Mutate(firstIntent, firstLogical, static (_, logical) => logical[1] ^= 1);

        Mutate(resetIntent, resetLogical, static (intent, _) => intent.AsSpan(17, 32).Clear());
        Mutate(resetIntent, resetLogical, static (intent, _) =>
            intent.AsSpan(49, 32).CopyTo(intent.AsSpan(17, 32)));
        Mutate(resetIntent, resetLogical, static (intent, _) => intent.AsSpan(89, 38).Clear());
        Mutate(resetIntent, resetLogical, static (intent, _) => intent[165] = 1);
        Mutate(resetIntent, resetLogical, static (intent, _) => intent.AsSpan(203, 32).Clear());
        Mutate(resetIntent, resetLogical, static (intent, _) => U64(intent, 81, 1));
        Mutate(resetIntent, resetLogical, static (_, logical) => U64(logical, 17, 2));
        Mutate(resetIntent, resetLogical, static (_, logical) => logical[25] ^= 1);
        Invalid(resetIntent, resetLogical[..49]);

        static void Mutate(byte[] validIntent, byte[] validLogical,
            Action<byte[], byte[]> mutation)
        {
            var intent = validIntent.ToArray();
            var logical = validLogical.ToArray();
            mutation(intent, logical);
            Invalid(intent, logical);
        }

        static void Invalid(byte[] intent, byte[] logical) =>
            Assert.Throws<RecordException>(() =>
                new GenesisResetReservationRequest(intent, logical));
    }

    [Fact]
    public async Task ResetReservationRequestMismatch_RejectsBeforeHmac()
    {
        var grr = Grr();
        var intent = grr.AsSpan(8, 235).ToArray();
        var logicalKey = new byte[49];
        logicalKey[0] = 1;
        logicalKey.AsSpan(1, 16).Fill(0x21);
        logicalKey.AsSpan(17).Fill(0x29);
        var request = new GenesisResetReservationRequest(intent, logicalKey);
        var gri = Gri(grr);
        request.LogicalScopeHash.Span.CopyTo(gri.AsSpan(8, 32));
        request.IntentHash.Span.CopyTo(gri.AsSpan(40, 32));
        grr[57] ^= 1;
        var provider = new ResetProvider(gri, grr);
        var hmac = new MatchingHmac();

        await Assert.ThrowsAsync<RecordException>(() =>
            GenesisReservationVerifier.RestoreResetAsync(
                provider, request, hmac, default).AsTask());

        Assert.Equal(1, provider.Calls);
        Assert.Empty(hmac.Domains);
    }

    [Fact]
    public async Task TransactionReservation_VerifiesExactScopeAndGtiHmac()
    {
        var gti = Gti();
        var request = new GenesisTransactionReservationRequest(gti.AsSpan(8, 122));
        var provider = new TransactionProvider(gti);
        var hmac = new MatchingHmac();

        var result = await GenesisReservationVerifier.RestoreTransactionAsync(
            provider, request, hmac, default);

        Assert.True(result.NoAuthorityClaim);
        Assert.Equal(1, provider.Calls);
        Assert.Equal(new[] { "Deep/ProtectedState/V1/GTI1" }, hmac.Domains);
        var framed = new byte[124];
        BinaryPrimitives.WriteUInt16BigEndian(framed, 122);
        gti.AsSpan(8, 122).CopyTo(framed.AsSpan(2));
        Assert.Equal(CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V7/genesis-transaction-logical-scope", framed),
            request.LogicalScopeHash.ToArray());
    }

    [Fact]
    public async Task TransactionScopeMismatch_RejectsBeforeHmac()
    {
        var gti = Gti();
        var request = new GenesisTransactionReservationRequest(gti.AsSpan(8, 122));
        var changed = gti.ToArray();
        changed[8] ^= 1;
        var provider = new TransactionProvider(changed);
        var hmac = new MatchingHmac();

        await Assert.ThrowsAsync<RecordException>(() =>
            GenesisReservationVerifier.RestoreTransactionAsync(
                provider, request, hmac, default).AsTask());

        Assert.Equal(1, provider.Calls);
        Assert.Empty(hmac.Domains);
    }

    [Fact]
    public void QuorumPendingAndSelection_RequireExactThreeStrictlyOrderedRows()
    {
        GenesisProtectedRecords.PreflightGqp(Gqp());
        GenesisProtectedRecords.PreflightGqs(Gqs());

        var pendingFour = Gqp();
        pendingFour[250] = 4;
        Assert.Throws<RecordException>(() => GenesisProtectedRecords.PreflightGqp(pendingFour));

        var pendingDuplicate = Gqp();
        pendingDuplicate.AsSpan(251, 32).CopyTo(pendingDuplicate.AsSpan(283, 32));
        Assert.Throws<RecordException>(() => GenesisProtectedRecords.PreflightGqp(pendingDuplicate));

        var selectionReversed = Gqs();
        selectionReversed.AsSpan(251, 70).CopyTo(selectionReversed.AsSpan(391, 70));
        Assert.Throws<RecordException>(() => GenesisProtectedRecords.PreflightGqs(selectionReversed));

        var selectionWithoutDcq = Gqs();
        selectionWithoutDcq.AsSpan(461, 38).Clear();
        Assert.Throws<RecordException>(() => GenesisProtectedRecords.PreflightGqs(selectionWithoutDcq));
    }

    [Fact]
    public void QuorumSelectionHash_UsesOneExactU32Be580Frame()
    {
        var selection = Gqs();
        var actual = GenesisProtectedRecords.QuorumSelectionHash(selection);
        var framed = new byte[4 + selection.Length];
        BinaryPrimitives.WriteUInt32BigEndian(framed, 580);
        selection.CopyTo(framed, 4);
        var expected = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V5/genesis-quorum-selection", framed);

        Assert.Equal(expected, actual);
        Assert.NotEqual(
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V5/genesis-quorum-selection", selection),
            actual);
        BinaryPrimitives.WriteUInt32BigEndian(framed, 579);
        Assert.NotEqual(
            CanonicalGrammar.Sha256Domain(
                "Deep/Cutover/V5/genesis-quorum-selection", framed),
            actual);
    }

    [Fact]
    public void AuthorJournal_PhaseShapesRejectUnknownSkippedOrMismatchedSlots()
    {
        foreach (var phase in new byte[] { 0, 1, 2 })
            GenesisProtectedRecords.PreflightGaj(Gaj(phase));

        var unknown = Gaj(0);
        unknown[194] = 3;
        Assert.Throws<RecordException>(() => GenesisProtectedRecords.PreflightGaj(unknown));

        var createdWithCandidate = Gaj(0);
        createdWithCandidate.AsSpan(635, 38).Fill(0x71);
        Assert.Throws<RecordException>(() =>
            GenesisProtectedRecords.PreflightGaj(createdWithCandidate));

        var externalWithoutSelection = Gaj(1);
        externalWithoutSelection.AsSpan(565, 32).Clear();
        Assert.Throws<RecordException>(() =>
            GenesisProtectedRecords.PreflightGaj(externalWithoutSelection));

        var localMismatch = Gaj(2);
        localMismatch[705] ^= 1;
        Assert.Throws<RecordException>(() =>
            GenesisProtectedRecords.PreflightGaj(localMismatch));
    }

    [Fact]
    public void ProtectedCapabilities_AreSealedAndHaveNoPublicRawConstruction()
    {
        var types = new[]
        {
            typeof(GenesisResetReservationResult),
            typeof(GenesisTransactionReservation),
            typeof(GenesisArtifactSetReceipt),
            typeof(GenesisQuorumPending),
            typeof(GenesisQuorumSelection),
            typeof(GenesisAuthorJournalSnapshot),
            typeof(GenesisWitnessHeadRequest),
            typeof(GenesisVerifiedQuorumReceipt)
        };

        foreach (var type in types)
        {
            Assert.True(type.IsSealed);
            Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
            Assert.DoesNotContain(type.GetInterfaces(), candidate =>
                candidate == typeof(System.Runtime.Serialization.ISerializable));
            Assert.DoesNotContain(
                type.GetMethods(BindingFlags.Public | BindingFlags.Static |
                                BindingFlags.DeclaredOnly),
                method => method.Name.Contains("Parse", StringComparison.OrdinalIgnoreCase) ||
                          method.Name.Contains("Create", StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public void WitnessHeadReadResult_PreflightsBoundsAndOwnsAllUntrustedBytes()
    {
        var dwd = Enumerable.Repeat((byte)0x31, 1217).ToArray();
        var rrl = Enumerable.Repeat((byte)0x32, 502).ToArray();
        var whl = new byte[222];
        "WHL1"u8.CopyTo(whl);
        whl[4] = 1;
        Enumerable.Repeat((byte)0x33, 32).ToArray().CopyTo(whl, whl.Length - 64);
        var result = new GenesisWitnessHeadReadResult(dwd, rrl, whl, 1, healthy: true);
        var retainedDwd = result.CanonicalDwd.ToArray();
        var retainedRrl = result.CanonicalReleaseRootLkg.ToArray();
        var retainedWhl = result.CanonicalWitnessHeadHistoryLkg.ToArray();

        dwd[0] ^= 1;
        rrl[0] ^= 1;
        whl[0] ^= 1;

        Assert.Equal(retainedDwd, result.CanonicalDwd.ToArray());
        Assert.Equal(retainedRrl, result.CanonicalReleaseRootLkg.ToArray());
        Assert.Equal(retainedWhl, result.CanonicalWitnessHeadHistoryLkg.ToArray());
        Assert.Throws<RecordException>(() =>
        {
            _ = new GenesisWitnessHeadReadResult(new byte[1216], rrl, retainedWhl, 1, true);
        });
        Assert.Throws<RecordException>(() =>
        {
            _ = new GenesisWitnessHeadReadResult(retainedDwd, new byte[501], retainedWhl, 1, true);
        });
        var oversized = new byte[222 + 342 * 65];
        "WHL1"u8.CopyTo(oversized);
        oversized[4] = 1;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(
            oversized.AsSpan(156, 2), 65);
        Assert.Throws<RecordException>(() =>
        {
            _ = new GenesisWitnessHeadReadResult(retainedDwd, retainedRrl, oversized, 1, true);
        });
    }

    [Fact]
    public void AuthorJournalSnapshot_HasNoPublicRawPhaseOrBytesToCapability()
    {
        var type = typeof(GenesisAuthorJournalSnapshot);
        var publicMembers = type.GetMembers(BindingFlags.Public | BindingFlags.Instance |
                                            BindingFlags.Static | BindingFlags.DeclaredOnly);

        Assert.True(type.IsSealed);
        Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(publicMembers, member =>
            member.Name.Contains("Phase", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("Parse", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("Create", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("FromBytes", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("Authority", StringComparison.OrdinalIgnoreCase) &&
            member.Name is not ("NoAuthorityClaim" or "get_NoAuthorityClaim"));
        Assert.DoesNotContain(type.GetMethods(BindingFlags.Public | BindingFlags.Static |
                                              BindingFlags.DeclaredOnly), method =>
            method.GetParameters().Any(parameter =>
                parameter.ParameterType == typeof(byte[]) ||
                parameter.ParameterType == typeof(ReadOnlyMemory<byte>)));
    }

    [Fact]
    public void PreJournalReplayTypes_AreSealedNonconstructibleAndExposeNoRawScope()
    {
        var scopeType = typeof(GenesisPreJournalScopeV1);
        Assert.True(scopeType.IsSealed);
        Assert.Empty(scopeType.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Equal(new[] { "NoAuthorityClaim" }, scopeType
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(static property => property.Name));
        var callback = typeof(GenesisPreJournalHeadProvider).GetMethod(nameof(
            GenesisPreJournalHeadProvider.ReadAsync));
        Assert.NotNull(callback);
        Assert.Equal(scopeType, callback!.GetParameters()[0].ParameterType);
        Assert.DoesNotContain(scopeType.GetMembers(BindingFlags.Public | BindingFlags.Instance |
                                                   BindingFlags.Static | BindingFlags.DeclaredOnly), member =>
            member.Name.Contains("Scope", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("Parse", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("Create", StringComparison.OrdinalIgnoreCase) ||
            member.Name.Contains("FromBytes", StringComparison.OrdinalIgnoreCase));

        Assert.True(typeof(GenesisPreJournalRestorePlan).IsAbstract);
        Assert.True(typeof(IDisposable).IsAssignableFrom(typeof(GenesisPreJournalRestorePlan)));
        foreach (var type in new[] { typeof(GenesisAfterGas), typeof(GenesisAfterGqp) })
        {
            Assert.True(type.IsSealed);
            Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
            Assert.DoesNotContain(type.GetMembers(BindingFlags.Public | BindingFlags.Instance |
                                                  BindingFlags.Static | BindingFlags.DeclaredOnly), member =>
                member.Name.Contains("Parse", StringComparison.OrdinalIgnoreCase) ||
                member.Name.Contains("Create", StringComparison.OrdinalIgnoreCase) ||
                member.Name.Contains("FromBytes", StringComparison.OrdinalIgnoreCase) ||
                member.Name.Contains("Authority", StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public void PreJournalHeadDto_PreflightsClosedBoundsAndDefensivelyOwnsBytes()
    {
        var externalRef = Enumerable.Repeat((byte)0x11, 38).ToArray();
        var externalSource = Enumerable.Repeat((byte)0x12, 32).ToArray();
        var localDpl = Enumerable.Repeat((byte)0x13, 576).ToArray();
        var localRef = Enumerable.Repeat((byte)0x14, 38).ToArray();
        var localSource = Enumerable.Repeat((byte)0x15, 32).ToArray();
        var value = new GenesisPreJournalHeadReadResult(
            true, 1, externalRef, externalSource, localDpl, localRef, localSource, 2, 3, 4);

        externalRef[0] = externalSource[0] = localDpl[0] = localRef[0] = localSource[0] = 0xff;
        Assert.Equal(0x11, value.ExternalDplReference.Span[0]);
        Assert.Equal(0x12, value.ExternalSourceFingerprint.Span[0]);
        Assert.Equal(0x13, value.CanonicalLocalDpl.Span[0]);
        Assert.Equal(0x14, value.LocalDplReference.Span[0]);
        Assert.Equal(0x15, value.LocalSourceFingerprint.Span[0]);

        var returned = value.CanonicalLocalDpl.ToArray();
        returned[0] = 0;
        Assert.Equal(0x13, value.CanonicalLocalDpl.Span[0]);

        Assert.Throws<RecordException>(() => new GenesisPreJournalHeadReadResult(
            false, 0, new byte[37], new byte[32], [], new byte[38], new byte[32], 1, 1, 1));
        Assert.Throws<RecordException>(() => new GenesisPreJournalHeadReadResult(
            false, 0, new byte[38], new byte[32], new byte[575], new byte[38], new byte[32], 1, 1, 1));
        Assert.Throws<RecordException>(() => new GenesisPreJournalHeadReadResult(
            false, 0, new byte[38], new byte[32], new byte[577], new byte[38], new byte[32], 1, 1, 1));
    }

    private static byte[] Gri(byte[] grr)
    {
        var value = Header("GRI1", GenesisProtectedRecords.GriLength);
        Fill(value, 8, 32, 0x11);
        Fill(value, 40, 32, 0x12);
        grr.AsSpan(243, 32).CopyTo(value.AsSpan(72));
        GenesisProtectedRecords.ReservationHash(grr).CopyTo(value, 104);
        U64(value, 136, 7);
        U64(value, 144, 900);
        grr.AsSpan(317, 32).CopyTo(value.AsSpan(153));
        Fill(value, 185, 32, 0x7f);
        return value;
    }

    private static byte[] Grr()
    {
        var value = Header("GRR1", GenesisProtectedRecords.GrrLength);
        value[8] = 1;
        Fill(value, 9, 16, 0x21);
        Fill(value, 57, 32, 0x22);
        U64(value, 89, 9);
        CanonicalGrammar.EncodeReference(new ArtifactReference(
            ArtifactType.Dpa1, 1, Enumerable.Repeat((byte)0x23, 32).ToArray()))
            .CopyTo(value, 135);
        Fill(value, 243, 32, 0x24);
        Fill(value, 275, 32, 0x25);
        value[307] = 1;
        U64(value, 308, 7);
        Fill(value, 317, 32, 0x26);
        Fill(value, 349, 32, 0x27);
        return value;
    }

    private static byte[] DpaReference(byte marker) =>
        CanonicalGrammar.EncodeReference(new ArtifactReference(
            ArtifactType.Dpa1, 1, Enumerable.Repeat(marker, 32).ToArray()));

    private static byte[] Gti()
    {
        var value = Header("GTI1", GenesisProtectedRecords.GtiLength);
        Scope122(value.AsSpan(8, 122));
        Fill(value, 130, 32, 0x31);
        U64(value, 162, 8);
        U64(value, 170, 901);
        Fill(value, 179, 32, 0x32);
        Fill(value, 211, 32, 0x33);
        return value;
    }

    private static byte[] Gas(ulong total)
    {
        var value = Header("GAS1", GenesisProtectedRecords.GasLength);
        CommonAuthorScope(value);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(130, 2), 7);
        Fill(value, 132, 32, 0x41);
        Fill(value, 164, 32, 0x42);
        U64(value, 196, total);
        U64(value, 204, 10);
        U64(value, 212, 902);
        value[220] = 1;
        Fill(value, 221, 32, 0x43);
        Fill(value, 253, 32, 0x44);
        return value;
    }

    private static byte[] Gqp()
    {
        var value = Header("GQP1", GenesisProtectedRecords.GqpLength);
        CommonQuorum(value);
        value[250] = 3;
        Fill(value, 251, 32, 0x51);
        Fill(value, 283, 32, 0x52);
        Fill(value, 315, 32, 0x53);
        Fill(value, 347, 32, 0x54);
        U64(value, 379, 11);
        U64(value, 387, 903);
        value[395] = 1;
        Fill(value, 397, 32, 0x55);
        Fill(value, 429, 32, 0x56);
        return value;
    }

    private static byte[] Gqs()
    {
        var value = Header("GQS1", GenesisProtectedRecords.GqsLength);
        CommonQuorum(value);
        value[250] = 3;
        for (var index = 0; index < 3; index++)
        {
            Fill(value, 251 + index * 70, 32, checked((byte)(0x61 + index)));
            Fill(value, 283 + index * 70, 38, checked((byte)(0x71 + index)));
        }
        Fill(value, 461, 38, 0x75);
        U64(value, 499, 12);
        U64(value, 507, 904);
        Fill(value, 516, 32, 0x76);
        Fill(value, 548, 32, 0x77);
        return value;
    }

    private static byte[] Gaj(byte phase)
    {
        var value = Header("GAJ1", GenesisProtectedRecords.GajLength);
        CommonAuthorScope(value);
        Fill(value, 130, 32, 0x21);
        Fill(value, 162, 32, 0x22);
        value[194] = phase;
        Fill(value, 195, 32, 0x23);
        Fill(value, 227, 38, 0x24);
        for (var index = 0; index < 4; index++)
            Fill(value, 265 + index * 38, 38, checked((byte)(0x31 + index)));
        Fill(value, 417, 38, 0x35);
        Fill(value, 455, 38, 0x36);
        Fill(value, 493, 32, 0x37);
        Fill(value, 525, 32, 0x38);
        U64(value, 557, 13);
        if (phase > 0)
        {
            Fill(value, 565, 32, 0x39);
            Fill(value, 597, 38, 0x3a);
            Fill(value, 635, 38, 0x3b);
            Fill(value, 673, 32, 0x3c);
            if (phase == 2)
            {
                value.AsSpan(635, 38).CopyTo(value.AsSpan(705));
                value.AsSpan(673, 32).CopyTo(value.AsSpan(743));
            }
        }
        Fill(value, 775, 32, 0x3d);
        U64(value, 807, 14);
        Fill(value, 816, 32, 0x3e);
        Fill(value, 848, 32, 0x3f);
        return value;
    }

    private static byte[] Header(string magic, int length)
    {
        var value = new byte[length];
        System.Text.Encoding.ASCII.GetBytes(magic).CopyTo(value, 0);
        value[4] = 1;
        return value;
    }

    private static void Scope122(Span<byte> scope)
    {
        scope[..16].Fill(0x11);
        scope.Slice(16, 32).Fill(0x12);
        BinaryPrimitives.WriteUInt16BigEndian(scope.Slice(48, 2),
            (ushort)ComponentKind.Shared);
        scope.Slice(50, 32).Fill(0x13);
        BinaryPrimitives.WriteUInt64BigEndian(scope.Slice(82, 8), 9);
        scope.Slice(90, 32).Fill(0x14);
    }

    private static void CommonAuthorScope(byte[] value)
    {
        Fill(value, 8, 16, 0x11);
        Fill(value, 24, 32, 0x12);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(56, 2),
            (ushort)ComponentKind.Shared);
        Fill(value, 58, 32, 0x13);
        U64(value, 90, 9);
        Fill(value, 98, 32, 0x14);
    }

    private static void CommonQuorum(byte[] value)
    {
        Fill(value, 8, 16, 0x11);
        Fill(value, 24, 32, 0x12);
        Fill(value, 56, 32, 0x13);
        U64(value, 88, 9);
        Fill(value, 96, 32, 0x14);
        Fill(value, 128, 38, 0x15);
        Fill(value, 166, 38, 0x16);
        Fill(value, 204, 38, 0x17);
        U64(value, 242, 3);
    }

    private static void Fill(byte[] value, int offset, int length, byte marker) =>
        value.AsSpan(offset, length).Fill(marker);

    private static void U64(byte[] value, int offset, ulong number) =>
        BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(offset, 8), number);

    private sealed class ResetProvider(byte[] gri, byte[] grr)
        : GenesisResetReservationProvider
    {
        public int Calls { get; private set; }

        public override ValueTask<GenesisResetReservationReadResult> RestoreOrReserveAsync(
            GenesisResetReservationRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult(
                new GenesisResetReservationReadResult(gri, grr, healthy: true));
        }
    }

    private sealed class MatchingHmac : IProtectedHmacProvider
    {
        public List<string> Domains { get; } = new();

        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Domains.Add(request.Domain);
            var marker = request.Domain.EndsWith("GRI1", StringComparison.Ordinal)
                ? (byte)0x7f
                : request.Domain.EndsWith("GRR1", StringComparison.Ordinal)
                    ? (byte)0x27
                    : (byte)0x33;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                Enumerable.Repeat(marker, 32).ToArray());
        }
    }

    private sealed class TransactionProvider(byte[] gti)
        : GenesisTransactionReservationProvider
    {
        public int Calls { get; private set; }

        public override ValueTask<GenesisTransactionReservationReadResult> RestoreOrReserveAsync(
            GenesisTransactionReservationRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            return ValueTask.FromResult(
                new GenesisTransactionReservationReadResult(gti, healthy: true));
        }
    }
}
