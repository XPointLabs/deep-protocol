using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class RecoveryProviderRegistryAmendmentTests
{
    [Fact]
    public void UntrustedRegistryReadResult_DefensivelyOwnsItsExactScope()
    {
        var owned = CanonicalGrammar.DecodeOwned(Drc(), RecordDefinitions.Drc1);
        var scope = Scope(owned);
        var expected = scope.ToArray();
        var result = new RecoveryProviderRegistryReadResult(
            scope, 13, protectedStateHmacHealthy: true, recoveryNonceLatchHealthy: true);

        scope.AsSpan().Fill(0xff);
        var retained = result.ExactScope.ToArray();
        retained.AsSpan().Fill(0xff);

        Assert.Equal(expected, result.ExactScope.ToArray());
        Assert.Equal(13UL, result.SourceRevision);
        Assert.True(result.ProtectedStateHmacHealthy);
        Assert.True(result.RecoveryNonceLatchHealthy);
    }

    [Fact]
    public async Task SealedContext_UsesExactOrderedScopeAndHasNoPublicMintingSurface()
    {
        var drc = Drc();
        var owned = CanonicalGrammar.DecodeOwned(drc, RecordDefinitions.Drc1);
        var request = new RecoveryProviderRegistryRequest(owned);
        var scope = Scope(owned);
        var registry = new SequenceRegistry(Snapshot(scope, 17));

        var context = await RecoveryProviderRegistryContext.ReadAsync(registry, request, default);

        Assert.True(typeof(RecoveryProviderRegistryContext).IsSealed);
        Assert.Empty(typeof(RecoveryProviderRegistryContext)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(RecoveryProviderRegistryRequest)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Equal(RecoveryProviderRegistryContext.ExactScopeLength, scope.Length);
        Assert.Equal(158, scope.Length);
        Assert.Equal(2, BinaryPrimitives.ReadUInt16BigEndian(scope.AsSpan(88, 2)));
        Assert.Equal((ushort)RecoveryProtectedKeyKind.ProtectedStateHmac,
            BinaryPrimitives.ReadUInt16BigEndian(scope.AsSpan(90, 2)));
        Assert.Equal((ushort)RecoveryProtectedKeyKind.RecoveryNonceLatch,
            BinaryPrimitives.ReadUInt16BigEndian(scope.AsSpan(124, 2)));
        Assert.False(scope.AsSpan(92, 32).SequenceEqual(scope.AsSpan(126, 32)));
        Assert.DoesNotContain(scope.AsSpan(92, 32).ToArray(), static value => value == 0);
        Assert.DoesNotContain(scope.AsSpan(126, 32).ToArray(), static value => value == 0);
        Assert.Equal(scope, context.ExactScope.ToArray());
        Assert.Equal(request.OperationSelector.ToArray(), context.OperationSelector.ToArray());
        Assert.Equal(17UL, context.SourceRevision);
        Assert.True(context.NoAuthorityClaim);
        Assert.Equal(1, registry.Calls);

        var retainedScope = context.ExactScope.ToArray();
        var retainedSelector = context.OperationSelector.ToArray();
        retainedScope.AsSpan().Fill(0xff);
        retainedSelector.AsSpan().Fill(0xff);
        Assert.Equal(scope, context.ExactScope.ToArray());
        Assert.Equal(request.OperationSelector.ToArray(), context.OperationSelector.ToArray());
    }

    [Fact]
    public async Task ExpectedContextKeyOrder_Exact158RejectsEveryMalformedScopeWithoutMinting()
    {
        var owned = CanonicalGrammar.DecodeOwned(Drc(), RecordDefinitions.Drc1);
        var request = new RecoveryProviderRegistryRequest(owned);
        var exact = Scope(owned);
        var acceptedProvider = new SequenceRegistry(Snapshot(exact, 17));
        var accepted = await RecoveryProviderRegistryContext.ReadAsync(
            acceptedProvider, request, default);

        Assert.Equal(RecoveryProviderRegistryContext.ExactScopeLength, exact.Length);
        Assert.Equal(2, BinaryPrimitives.ReadUInt16BigEndian(exact.AsSpan(88, 2)));
        Assert.Equal((ushort)RecoveryProtectedKeyKind.ProtectedStateHmac,
            BinaryPrimitives.ReadUInt16BigEndian(exact.AsSpan(90, 2)));
        Assert.Equal((ushort)RecoveryProtectedKeyKind.RecoveryNonceLatch,
            BinaryPrimitives.ReadUInt16BigEndian(exact.AsSpan(124, 2)));
        Assert.False(exact.AsSpan(92, 32).SequenceEqual(exact.AsSpan(126, 32)));
        Assert.True(accepted.NoAuthorityClaim);
        Assert.Empty(typeof(RecoveryProviderRegistryContext)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));

        foreach (var mutation in Enum.GetValues<ScopeMutation>())
        {
            var changed = exact.ToArray();
            MutateScope(ref changed, mutation);
            var provider = new SequenceRegistry(Snapshot(changed, 17));
            await Assert.ThrowsAsync<RecordException>(() =>
                RecoveryProviderRegistryContext.ReadAsync(provider, request, default).AsTask());
            Assert.Equal(1, provider.Calls);
        }
    }

    [Fact]
    public void RegistryRequest_FreezesExactDrcOperationSelectorAndRetainUntil()
    {
        var drc = Drc();
        var owned = CanonicalGrammar.DecodeOwned(drc, RecordDefinitions.Drc1);
        var request = new RecoveryProviderRegistryRequest(owned);
        var expected = Combine(
            owned.FieldCopy(1), owned.FieldCopy(2), owned.FieldCopy(4),
            owned.FieldCopy(3), owned.FieldCopy(13));

        Assert.Equal(RecoveryProviderRegistryRequest.OperationSelectorLength, expected.Length);
        Assert.Equal(120, expected.Length);
        Assert.Equal(expected, request.OperationSelector.ToArray());
        Assert.Equal(owned.FieldCopy(1), request.NetworkId.ToArray());
        Assert.Equal(owned.FieldCopy(2), request.ComponentSubject.ToArray());
        Assert.Equal(19UL, request.AccountGeneration);
        Assert.Equal(owned.FieldCopy(3), request.TransactionId.ToArray());
        Assert.Equal(owned.FieldCopy(13), request.ProtectorKeyId.ToArray());
        Assert.Equal(1_000UL, request.RetainUntilUnixSeconds);

        drc.AsSpan().Fill(0xff);
        expected.AsSpan().Fill(0xff);
        var retained = request.OperationSelector.ToArray();
        retained.AsSpan().Fill(0xff);
        Assert.Equal(0x11, request.NetworkId.Span[0]);
        Assert.Equal(0x22, request.ComponentSubject.Span[0]);
        Assert.Equal(0x33, request.TransactionId.Span[0]);
        Assert.Equal(0x44, request.ProtectorKeyId.Span[0]);
    }

    [Theory]
    [InlineData(ScopeMutation.WrongLength)]
    [InlineData(ScopeMutation.WrongNetwork)]
    [InlineData(ScopeMutation.ZeroReset)]
    [InlineData(ScopeMutation.WrongComponent)]
    [InlineData(ScopeMutation.WrongAccountGeneration)]
    [InlineData(ScopeMutation.WrongRowCount)]
    [InlineData(ScopeMutation.ReversedKinds)]
    [InlineData(ScopeMutation.ZeroFirstKey)]
    [InlineData(ScopeMutation.ZeroSecondKey)]
    [InlineData(ScopeMutation.EqualKeys)]
    public async Task ScopeSubstitution_RejectsBeforeAContextExists(ScopeMutation mutation)
    {
        var owned = CanonicalGrammar.DecodeOwned(Drc(), RecordDefinitions.Drc1);
        var request = new RecoveryProviderRegistryRequest(owned);
        var scope = Scope(owned);
        MutateScope(ref scope, mutation);
        var registry = new SequenceRegistry(Snapshot(scope, 1));

        var error = await Assert.ThrowsAsync<RecordException>(() =>
            RecoveryProviderRegistryContext.ReadAsync(registry, request, default).AsTask());

        Assert.Equal(RecordError.InvalidField, error.Error);
        Assert.Equal(1, registry.Calls);
    }

    [Theory]
    [InlineData(0UL, true, true)]
    [InlineData(1UL, false, true)]
    [InlineData(1UL, true, false)]
    public async Task MissingRevisionOrUnhealthyRole_RejectsWithoutAContext(
        ulong revision,
        bool protectedHmacHealthy,
        bool recoveryLatchHealthy)
    {
        var owned = CanonicalGrammar.DecodeOwned(Drc(), RecordDefinitions.Drc1);
        var request = new RecoveryProviderRegistryRequest(owned);
        var registry = new SequenceRegistry(new RecoveryProviderRegistryReadResult(
            Scope(owned), revision, protectedHmacHealthy, recoveryLatchHealthy));

        var error = await Assert.ThrowsAsync<RecordException>(() =>
            RecoveryProviderRegistryContext.ReadAsync(registry, request, default).AsTask());

        Assert.Equal(RecordError.InvalidField, error.Error);
        Assert.Equal(1, registry.Calls);
    }

    [Theory]
    [InlineData(RereadMutation.SourceRevision)]
    [InlineData(RereadMutation.KeyId)]
    [InlineData(RereadMutation.UnhealthyProtectedHmac)]
    [InlineData(RereadMutation.UnhealthyRecoveryLatch)]
    public async Task RereadMovement_FailsClosed(RereadMutation mutation)
    {
        var owned = CanonicalGrammar.DecodeOwned(Drc(), RecordDefinitions.Drc1);
        var request = new RecoveryProviderRegistryRequest(owned);
        var initialScope = Scope(owned);
        var movedScope = initialScope.ToArray();
        var revision = 23UL;
        var protectedHealthy = true;
        var latchHealthy = true;
        switch (mutation)
        {
            case RereadMutation.SourceRevision:
                revision++;
                break;
            case RereadMutation.KeyId:
                movedScope[92] ^= 1;
                break;
            case RereadMutation.UnhealthyProtectedHmac:
                protectedHealthy = false;
                break;
            case RereadMutation.UnhealthyRecoveryLatch:
                latchHealthy = false;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        var registry = new SequenceRegistry(
            Snapshot(initialScope, 23),
            new RecoveryProviderRegistryReadResult(
                movedScope, revision, protectedHealthy, latchHealthy));
        var context = await RecoveryProviderRegistryContext.ReadAsync(registry, request, default);

        var error = await Assert.ThrowsAsync<RecordException>(() =>
            context.RevalidateAsync(registry, request, default).AsTask());

        Assert.Equal(RecordError.InvalidField, error.Error);
        Assert.Equal(2, registry.Calls);
    }

    [Fact]
    public async Task StableRereads_PreserveScopeSelectorRevisionAndHealth()
    {
        var owned = CanonicalGrammar.DecodeOwned(Drc(), RecordDefinitions.Drc1);
        var request = new RecoveryProviderRegistryRequest(owned);
        var scope = Scope(owned);
        var registry = new SequenceRegistry(
            Snapshot(scope, 31), Snapshot(scope, 31), Snapshot(scope, 31));
        var context = await RecoveryProviderRegistryContext.ReadAsync(registry, request, default);

        await context.RevalidateAsync(registry, request, default);
        await context.RevalidateAsync(registry, request, default);

        Assert.Equal(3, registry.Calls);
        Assert.Equal(31UL, context.SourceRevision);
        Assert.Equal(scope, context.ExactScope.ToArray());
        Assert.Equal(request.OperationSelector.ToArray(), context.OperationSelector.ToArray());
    }

    [Fact]
    public void TypedLatchRequest_IsExact120DefensivelyOwnedAndNotCallerConstructible()
    {
        var latchKeyId = Bytes(0x61, 32);
        var protectorKeyId = Bytes(0x62, 32);
        var nonce = Bytes(0x63, 24);
        var value = Bytes(0x64, 32);
        var expected = Combine(latchKeyId, protectorKeyId, nonce, value);
        var request = new RecoveryNonceLatchRequest(latchKeyId, protectorKeyId, nonce, value);

        Assert.True(typeof(RecoveryNonceLatchRequest).IsSealed);
        Assert.Empty(typeof(RecoveryNonceLatchRequest)
            .GetConstructors(BindingFlags.Public | BindingFlags.Instance));
        Assert.Equal(RecoveryNonceLatchRequest.ExactLength, expected.Length);
        Assert.Equal(120, expected.Length);
        Assert.Equal(expected, request.ExactRequest.ToArray());
        Assert.Equal(latchKeyId, request.RecoveryNonceLatchKeyId.ToArray());
        Assert.Equal(protectorKeyId, request.ProtectorKeyId.ToArray());
        Assert.Equal(nonce, request.DerivedNonce.ToArray());
        Assert.Equal(value, request.LatchValue.ToArray());

        latchKeyId.AsSpan().Fill(0xff);
        protectorKeyId.AsSpan().Fill(0xff);
        nonce.AsSpan().Fill(0xff);
        value.AsSpan().Fill(0xff);
        expected.AsSpan().Fill(0xff);
        var retained = request.ExactRequest.ToArray();
        retained.AsSpan().Fill(0xff);
        Assert.Equal(0x61, request.RecoveryNonceLatchKeyId.Span[0]);
        Assert.Equal(0x62, request.ProtectorKeyId.Span[0]);
        Assert.Equal(0x63, request.DerivedNonce.Span[0]);
        Assert.Equal(0x64, request.LatchValue.Span[0]);
    }

    [Fact]
    public async Task LatchReread_UsesExactTypedRow2ProtectorNonceValueOrder()
    {
        var owned = CanonicalGrammar.DecodeOwned(Drc(), RecordDefinitions.Drc1);
        var registryRequest = new RecoveryProviderRegistryRequest(owned);
        var scope = Scope(owned);
        var context = await RecoveryProviderRegistryContext.ReadAsync(
            new SequenceRegistry(Snapshot(scope, 41)), registryRequest, default);
        var latchKey = Combine(owned.FieldCopy(13), owned.FieldCopy(12));
        var latchValue = Bytes(0x81, 32);
        var latch = new RecordingLatch(RecoveryNonceLatchDecision.ExactReplay);

        await context.RevalidateLatchAsync(latch, latchKey, latchValue, default);

        Assert.Equal(1, latch.Calls);
        Assert.NotNull(latch.Request);
        var expected = Combine(
            scope.AsSpan(126, 32).ToArray(), owned.FieldCopy(13),
            owned.FieldCopy(12), latchValue);
        Assert.Equal(RecoveryNonceLatchRequest.ExactLength, expected.Length);
        Assert.Equal(expected, latch.Request!.ExactRequest.ToArray());

        expected.AsSpan().Fill(0xff);
        latch.MutateRetainedCopies();
        Assert.Equal(0x72, latch.Request.RecoveryNonceLatchKeyId.Span[0]);
        Assert.Equal(0x44, latch.Request.ProtectorKeyId.Span[0]);
        Assert.Equal(0x39, latch.Request.DerivedNonce.Span[0]);
        Assert.Equal(0x81, latch.Request.LatchValue.Span[0]);
    }

    [Fact]
    public async Task LatchReread_RejectsProtectorCrossFeedBeforeCallback()
    {
        var owned = CanonicalGrammar.DecodeOwned(Drc(), RecordDefinitions.Drc1);
        var request = new RecoveryProviderRegistryRequest(owned);
        var scope = Scope(owned);
        var context = await RecoveryProviderRegistryContext.ReadAsync(
            new SequenceRegistry(Snapshot(scope, 43)), request, default);
        var wrongLatchKey = Combine(owned.FieldCopy(13), owned.FieldCopy(12));
        wrongLatchKey[0] ^= 1;
        var latch = new RecordingLatch(RecoveryNonceLatchDecision.ExactReplay);

        var error = await Assert.ThrowsAsync<RecordException>(() =>
            context.RevalidateLatchAsync(
                latch, wrongLatchKey, Bytes(0x82, 32), default).AsTask());

        Assert.Equal(RecordError.InvalidField, error.Error);
        Assert.Equal(0, latch.Calls);
    }

    [Theory]
    [InlineData(RecoveryNonceLatchDecision.Stored)]
    [InlineData(RecoveryNonceLatchDecision.ForkLatched)]
    public async Task LatchReread_RequiresExactReplay(
        RecoveryNonceLatchDecision decision)
    {
        var owned = CanonicalGrammar.DecodeOwned(Drc(), RecordDefinitions.Drc1);
        var request = new RecoveryProviderRegistryRequest(owned);
        var scope = Scope(owned);
        var context = await RecoveryProviderRegistryContext.ReadAsync(
            new SequenceRegistry(Snapshot(scope, 47)), request, default);
        var latch = new RecordingLatch(decision);

        var error = await Assert.ThrowsAsync<RecordException>(() =>
            context.RevalidateLatchAsync(
                latch, Combine(owned.FieldCopy(13), owned.FieldCopy(12)),
                Bytes(0x83, 32), default).AsTask());

        Assert.Equal(RecordError.InvalidField, error.Error);
        Assert.Equal(1, latch.Calls);
    }

    [Fact]
    public async Task ColdPath_OrdersPreReadAeadHmacAndPostReadWithExactLatchReplay()
    {
        var fixture = RecoveryColdProtectedPayloadTests.CreateTaggedInputFixture();
        var input = ColdRecoveryInput.CreateTerminal(
            fixture.Pin, StructurallyValidDwt(), fixture.Drc, fixture.Rsm);
        var drc = CanonicalGrammar.DecodeOwned(fixture.Drc, RecordDefinitions.Drc1);
        var events = new List<string>();
        var registry = new EventRegistry(
            events, Snapshot(ScopeForColdDrc(drc), 53), Snapshot(ScopeForColdDrc(drc), 53));
        var latch = new EventLatch(events,
            RecoveryNonceLatchDecision.Stored, RecoveryNonceLatchDecision.ExactReplay);
        var protector = new EventProtector(events);
        var hmac = new EventHmacProvider(events, fixture.HmacKey);

        var error = await Assert.ThrowsAsync<RecordException>(async () =>
            await RecoveryVerifier.OpenColdAsync(
                input, protector, registry, latch, hmac, 50, default));

        Assert.Equal(RecordError.InvalidField, error.Error);
        Assert.Equal(new[]
        {
            "registry:1", "derive", "latch:1", "open",
            "hmac:RFC1", "hmac:RAH1", "hmac:DTC2", "hmac:DWH1",
            "registry:2", "latch:2"
        }, events);
        Assert.Equal(2, latch.Requests.Count);
        Assert.Equal(latch.Requests[0].ExactRequest.ToArray(),
            latch.Requests[1].ExactRequest.ToArray());
        Assert.Equal(drc.FieldCopy(13), latch.Requests[0].ProtectorKeyId.ToArray());
        Assert.Equal(drc.FieldCopy(12), latch.Requests[0].DerivedNonce.ToArray());
    }

    [Theory]
    [InlineData(RereadMutation.SourceRevision)]
    [InlineData(RereadMutation.KeyId)]
    [InlineData(RereadMutation.UnhealthyProtectedHmac)]
    [InlineData(RereadMutation.UnhealthyRecoveryLatch)]
    public async Task ColdPath_PostOpenRegistryMovementStopsBeforeLatchRereadOrAuthority(
        RereadMutation mutation)
    {
        var fixture = RecoveryColdProtectedPayloadTests.CreateTaggedInputFixture();
        var input = ColdRecoveryInput.CreateTerminal(
            fixture.Pin, StructurallyValidDwt(), fixture.Drc, fixture.Rsm);
        var drc = CanonicalGrammar.DecodeOwned(fixture.Drc, RecordDefinitions.Drc1);
        var initialScope = ScopeForColdDrc(drc);
        var movedScope = initialScope.ToArray();
        var revision = 59UL;
        var protectedHealthy = true;
        var latchHealthy = true;
        switch (mutation)
        {
            case RereadMutation.SourceRevision:
                revision++;
                break;
            case RereadMutation.KeyId:
                movedScope[92] ^= 1;
                break;
            case RereadMutation.UnhealthyProtectedHmac:
                protectedHealthy = false;
                break;
            case RereadMutation.UnhealthyRecoveryLatch:
                latchHealthy = false;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        var events = new List<string>();
        var registry = new EventRegistry(
            events,
            Snapshot(initialScope, 59),
            new RecoveryProviderRegistryReadResult(
                movedScope, revision, protectedHealthy, latchHealthy));
        var latch = new EventLatch(events, RecoveryNonceLatchDecision.Stored);

        var error = await Assert.ThrowsAsync<RecordException>(async () =>
            await RecoveryVerifier.OpenColdAsync(
                input, new EventProtector(events), registry, latch,
                new EventHmacProvider(events, fixture.HmacKey), 50, default));

        Assert.Equal(RecordError.InvalidField, error.Error);
        Assert.Equal(new[]
        {
            "registry:1", "derive", "latch:1", "open",
            "hmac:RFC1", "hmac:RAH1", "hmac:DTC2", "hmac:DWH1",
            "registry:2"
        }, events);
        Assert.Single(latch.Requests);
    }

    [Fact]
    public async Task ColdPath_Row1CrossFeedRejectsAfterOpenBeforeProtectedHmacCallback()
    {
        var fixture = RecoveryColdProtectedPayloadTests.CreateTaggedInputFixture();
        var input = ColdRecoveryInput.CreateTerminal(
            fixture.Pin, StructurallyValidDwt(), fixture.Drc, fixture.Rsm);
        var drc = CanonicalGrammar.DecodeOwned(fixture.Drc, RecordDefinitions.Drc1);
        var scope = ScopeForColdDrc(drc);
        scope[92] ^= 1;
        var events = new List<string>();

        var error = await Assert.ThrowsAsync<RecordException>(async () =>
            await RecoveryVerifier.OpenColdAsync(
                input, new EventProtector(events),
                new EventRegistry(events, Snapshot(scope, 61)),
                new EventLatch(events, RecoveryNonceLatchDecision.Stored),
                new EventHmacProvider(events, fixture.HmacKey), 50, default));

        Assert.Equal(RecordError.InvalidField, error.Error);
        Assert.Equal(new[] { "registry:1", "derive", "latch:1", "open" }, events);
    }

    private static RecoveryProviderRegistryReadResult Snapshot(byte[] scope, ulong revision) =>
        new(scope, revision, protectedStateHmacHealthy: true, recoveryNonceLatchHealthy: true);

    private static byte[] Scope(OwnedRecord drc)
    {
        var scope = new byte[RecoveryProviderRegistryContext.ExactScopeLength];
        drc.FieldSpan(1).CopyTo(scope.AsSpan(0, 16));
        scope.AsSpan(16, 32).Fill(0x51);
        drc.FieldSpan(2).CopyTo(scope.AsSpan(48, 32));
        drc.FieldSpan(4).CopyTo(scope.AsSpan(80, 8));
        BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(88, 2), 2);
        BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(90, 2),
            (ushort)RecoveryProtectedKeyKind.ProtectedStateHmac);
        scope.AsSpan(92, 32).Fill(0x71);
        BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(124, 2),
            (ushort)RecoveryProtectedKeyKind.RecoveryNonceLatch);
        scope.AsSpan(126, 32).Fill(0x72);
        return scope;
    }

    private static byte[] ScopeForColdDrc(OwnedRecord drc)
    {
        using var manifest = RecoveryManifestParser.DecodeOwned(
            drc.FieldSpan(16), BinaryPrimitives.ReadUInt16BigEndian(drc.FieldSpan(9)));
        var scope = Scope(drc);
        manifest.RfcSourceTuple.Slice(16, 32).CopyTo(scope.AsSpan(16, 32));
        manifest.RfcProtectedKeyId.CopyTo(scope.AsSpan(92, 32));
        return scope;
    }

    private static byte[] StructurallyValidDwt()
    {
        var fields = RecordDefinitions.Dwt1.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength])
            .ToArray();
        fields[0] = Bytes(0x11, 16);
        fields[1] = Reference(ArtifactType.Dwd1, 1_217, 0x21);
        fields[2] = U64(1);
        fields[3] = U64(0);
        fields[4] = Reference(ArtifactType.Rrm1, 332, 0x22);
        fields[5] = Reference(ArtifactType.Krf1, 300, 0x23);
        fields[6] = U64(100);
        fields[7] = new byte[] { 3 };
        var receipts = new byte[435];
        for (var index = 0; index < 3; index++)
        {
            var row = receipts.AsSpan(index * 145, 145);
            row[..32].Fill(checked((byte)(0x31 + index)));
            row[72] = (byte)DurabilityClass.FsyncReplicated;
        }
        fields[8] = receipts;
        fields[9] = Bytes(0x41, 32);
        return CanonicalGrammar.Encode(RecordDefinitions.Dwt1, fields);
    }

    private static byte[] Drc()
    {
        var fields = RecordDefinitions.Drc1.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength])
            .ToArray();
        fields[0] = Bytes(0x11, 16);
        fields[1] = Bytes(0x22, 32);
        fields[2] = Bytes(0x33, 32);
        fields[3] = U64(19);
        fields[4] = Reference(ArtifactType.Dcm1, 812, 0x35);
        fields[5] = Reference(ArtifactType.Drs1, 356, 0x36);
        fields[6] = Bytes(0x37, 32);
        fields[7] = Bytes(0x38, 32);
        fields[8] = U16(1);
        fields[9] = U64(12);
        fields[10] = U64(12);
        fields[11] = Bytes(0x39, 24);
        fields[12] = Bytes(0x44, 32);
        fields[13] = U64(900);
        fields[14] = U64(1_000);
        fields[15] = Bytes(0x45, 12);
        fields[16] = Bytes(0x46, 16);
        return CanonicalGrammar.Encode(RecordDefinitions.Drc1, fields);
    }

    private static void MutateScope(ref byte[] scope, ScopeMutation mutation)
    {
        switch (mutation)
        {
            case ScopeMutation.WrongLength:
                Array.Resize(ref scope, scope.Length - 1);
                break;
            case ScopeMutation.WrongNetwork:
                scope[0] ^= 1;
                break;
            case ScopeMutation.ZeroReset:
                scope.AsSpan(16, 32).Clear();
                break;
            case ScopeMutation.WrongComponent:
                scope[48] ^= 1;
                break;
            case ScopeMutation.WrongAccountGeneration:
                scope[87] ^= 1;
                break;
            case ScopeMutation.WrongRowCount:
                scope[89] = 1;
                break;
            case ScopeMutation.ReversedKinds:
                BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(90, 2),
                    (ushort)RecoveryProtectedKeyKind.RecoveryNonceLatch);
                BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(124, 2),
                    (ushort)RecoveryProtectedKeyKind.ProtectedStateHmac);
                break;
            case ScopeMutation.ZeroFirstKey:
                scope.AsSpan(92, 32).Clear();
                break;
            case ScopeMutation.ZeroSecondKey:
                scope.AsSpan(126, 32).Clear();
                break;
            case ScopeMutation.EqualKeys:
                scope.AsSpan(92, 32).CopyTo(scope.AsSpan(126, 32));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mutation));
        }
    }

    private static byte[] Reference(ArtifactType type, uint length, byte marker)
    {
        var value = new byte[ArtifactReference.Length];
        BinaryPrimitives.WriteUInt16BigEndian(value, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(2), length);
        value.AsSpan(6).Fill(marker);
        return value;
    }

    private static byte[] Combine(params byte[][] values)
    {
        var output = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }
        return output;
    }

    private static byte[] Bytes(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();

    private static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    public enum ScopeMutation
    {
        WrongLength,
        WrongNetwork,
        ZeroReset,
        WrongComponent,
        WrongAccountGeneration,
        WrongRowCount,
        ReversedKinds,
        ZeroFirstKey,
        ZeroSecondKey,
        EqualKeys
    }

    public enum RereadMutation
    {
        SourceRevision,
        KeyId,
        UnhealthyProtectedHmac,
        UnhealthyRecoveryLatch
    }

    private sealed class SequenceRegistry(params RecoveryProviderRegistryReadResult[] results)
        : RecoveryProviderRegistry
    {
        internal int Calls { get; private set; }

        public override ValueTask<RecoveryProviderRegistryReadResult> ReadAsync(
            RecoveryProviderRegistryRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.InRange(Calls, 0, results.Length - 1);
            return ValueTask.FromResult(results[Calls++]);
        }
    }

    private sealed class RecordingLatch(RecoveryNonceLatchDecision decision)
        : RecoveryNonceLatch
    {
        private byte[]? _retainedExact;
        internal int Calls { get; private set; }
        internal RecoveryNonceLatchRequest? Request { get; private set; }

        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Calls++;
            Request = request;
            _retainedExact = request.ExactRequest.ToArray();
            return ValueTask.FromResult(decision);
        }

        internal void MutateRetainedCopies() => _retainedExact!.AsSpan().Fill(0xff);
    }

    private sealed class EventRegistry(
        List<string> events,
        params RecoveryProviderRegistryReadResult[] results) : RecoveryProviderRegistry
    {
        private int _calls;

        public override ValueTask<RecoveryProviderRegistryReadResult> ReadAsync(
            RecoveryProviderRegistryRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            events.Add($"registry:{++_calls}");
            Assert.InRange(_calls, 1, results.Length);
            return ValueTask.FromResult(results[_calls - 1]);
        }
    }

    private sealed class EventLatch(
        List<string> events,
        params RecoveryNonceLatchDecision[] decisions) : RecoveryNonceLatch
    {
        internal List<RecoveryNonceLatchRequest> Requests { get; } = [];

        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Requests.Add(request);
            events.Add($"latch:{Requests.Count}");
            Assert.InRange(Requests.Count, 1, decisions.Length);
            return ValueTask.FromResult(decisions[Requests.Count - 1]);
        }
    }

    private sealed class EventProtector(List<string> events) : RecoveryProtectorProvider
    {
        public override ValueTask DeriveNonceAsync(
            RecoveryProviderRequest request,
            Memory<byte> derivedNonce24,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            events.Add("derive");
            request.StoredNonce.CopyTo(derivedNonce24);
            return ValueTask.CompletedTask;
        }

        public override ValueTask OpenAsync(
            RecoveryProviderRequest request,
            Memory<byte> plaintextDestination,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            events.Add("open");
            request.Ciphertext.CopyTo(plaintextDestination);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class EventHmacProvider(List<string> events, byte[] key)
        : IProtectedHmacProvider
    {
        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            events.Add($"hmac:{request.Domain[^4..]}");
            var domain = Encoding.ASCII.GetBytes(request.Domain);
            var unsigned = request.UnsignedCanonical.Span;
            var input = new byte[2 + domain.Length + 2 + 4 + unsigned.Length];
            BinaryPrimitives.WriteUInt16BigEndian(input, checked((ushort)domain.Length));
            domain.CopyTo(input, 2);
            var offset = 2 + domain.Length;
            BinaryPrimitives.WriteUInt16BigEndian(
                input.AsSpan(offset), ArtifactRegistry.ProtectedHmacSha256);
            BinaryPrimitives.WriteUInt32BigEndian(
                input.AsSpan(offset + 2), checked((uint)unsigned.Length));
            unsigned.CopyTo(input.AsSpan(offset + 6));
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(HMACSHA256.HashData(key, input));
        }
    }
}
