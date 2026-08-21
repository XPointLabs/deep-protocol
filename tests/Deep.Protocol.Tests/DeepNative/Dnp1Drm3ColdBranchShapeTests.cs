using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class Drm3ColdBranchShapeTests
{
    [Fact]
    public void PublicFactories_AreAClosedDisjointTerminalNonterminalUnion()
    {
        var type = typeof(ColdRecoveryInput);
        Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));

        var factories = type.GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Where(method => method.ReturnType == type)
            .OrderBy(method => method.Name, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(new[] { "CreateNonterminal", "CreateTerminal" },
            factories.Select(method => method.Name).ToArray());

        var nonterminal = factories.Single(method => method.Name == "CreateNonterminal")
            .GetParameters();
        Assert.Equal(7, nonterminal.Length);
        Assert.Contains(nonterminal, parameter => parameter.Name == "exactDcl1");
        Assert.DoesNotContain(nonterminal, parameter => parameter.Name == "exactDwt1");

        var terminal = factories.Single(method => method.Name == "CreateTerminal")
            .GetParameters();
        Assert.Equal(4, terminal.Length);
        Assert.Contains(terminal, parameter => parameter.Name == "exactDwt1");
        Assert.DoesNotContain(terminal, parameter => parameter.Name is
            "exactDcp1" or "exactDcs1" or "exactDcq1" or "exactDcl1");
    }

    [Fact]
    public void Factories_RejectMissingOrCrossBranchEvidenceBeforeAnyProviderExists()
    {
        var fixture = RecoveryColdProtectedPayloadTests.CreateTaggedInputFixture();

        Assert.Throws<RecordException>(() => ColdRecoveryInput.CreateNonterminal(
            fixture.Pin, default, fixture.Dcs, fixture.Dcq, fixture.Dcl,
            fixture.Drc, fixture.Rsm));
        Assert.Throws<RecordException>(() => ColdRecoveryInput.CreateNonterminal(
            fixture.Pin, fixture.Dcp, fixture.Dcs, fixture.Dcq, default,
            fixture.Drc, fixture.Rsm));
        Assert.Throws<RecordException>(() => ColdRecoveryInput.CreateTerminal(
            fixture.Pin, default, fixture.Drc, fixture.Rsm));
    }

    [Fact]
    public void NonterminalFactory_FreezesOnlyCandidateAndLeaseRows()
    {
        var fixture = RecoveryColdProtectedPayloadTests.CreateTaggedInputFixture();
        var input = ColdRecoveryInput.CreateNonterminal(
            fixture.Pin, fixture.Dcp, fixture.Dcs, fixture.Dcq, fixture.Dcl,
            fixture.Drc, fixture.Rsm);
        var expectedDcp = fixture.Dcp.ToArray();
        var expectedDrc = fixture.Drc.ToArray();

        fixture.Dcp.AsSpan().Fill(0xff);
        fixture.Dcs.AsSpan().Fill(0xff);
        fixture.Dcq.AsSpan().Fill(0xff);
        fixture.Dcl.AsSpan().Fill(0xff);
        fixture.Drc.AsSpan().Fill(0xff);
        fixture.Rsm.AsSpan().Fill(0xff);

        Assert.False(input.IsTerminal);
        Assert.Empty(input.Dwt.ToArray());
        Assert.Equal(expectedDcp, input.Dcp.ToArray());
        Assert.Equal(expectedDrc, input.Drc.ToArray());
        Assert.True(input.NoAuthorityClaim);
    }

    [Fact]
    public void TerminalFactory_FreezesOnlyDwtAndProtectedCapsuleRows()
    {
        var fixture = RecoveryColdProtectedPayloadTests.CreateTaggedInputFixture();
        var dwt = StructurallyValidDwt();
        var expectedDwt = dwt.ToArray();
        var expectedDrc = fixture.Drc.ToArray();
        var input = ColdRecoveryInput.CreateTerminal(
            fixture.Pin, dwt, fixture.Drc, fixture.Rsm);

        dwt.AsSpan().Fill(0xff);
        fixture.Drc.AsSpan().Fill(0xff);
        fixture.Rsm.AsSpan().Fill(0xff);

        Assert.True(input.IsTerminal);
        Assert.Empty(input.Dcp.ToArray());
        Assert.Empty(input.Dcs.ToArray());
        Assert.Empty(input.Dcq.ToArray());
        Assert.Empty(input.Dcl.ToArray());
        Assert.Equal(expectedDwt, input.Dwt.ToArray());
        Assert.Equal(expectedDrc, input.Drc.ToArray());
        Assert.True(input.NoAuthorityClaim);
    }

    [Fact]
    public async Task TerminalTag_CannotCrossAuthorizeNonterminalDrm3AfterOneOpen()
    {
        var fixture = RecoveryColdProtectedPayloadTests.CreateTaggedInputFixture();
        var input = ColdRecoveryInput.CreateTerminal(
            fixture.Pin, StructurallyValidDwt(), fixture.Drc, fixture.Rsm);
        var drc = CanonicalGrammar.DecodeOwned(fixture.Drc, RecordDefinitions.Drc1);
        var provider = new PlaintextProvider(
            drc.FieldCopy(12), drc.FieldCopy(16));
        var hmac = new HmacProvider(fixture.HmacKey);

        var error = await Assert.ThrowsAsync<RecordException>(async () =>
            await RecoveryVerifier.OpenColdAsync(
                input, provider, new FixedRegistry(fixture.ResetId,fixture.Rsm),
                new StoredLatch(), hmac, 50, default));

        Assert.Equal(RecordError.InvalidField, error.Error);
        Assert.Equal(1, provider.DeriveCalls);
        Assert.Equal(1, provider.OpenCalls);
        Assert.Equal(4, hmac.Calls);
    }

    [Fact]
    public void ResultTypes_ExposeNoCrossBranchCandidateOrCheckpointSurface()
    {
        Assert.True(typeof(ColdRecoveryResult).IsAbstract);
        Assert.True(typeof(ColdRecoveryCandidate).IsSealed);
        Assert.True(typeof(TerminalColdRecoveryState).IsSealed);
        Assert.Empty(typeof(ColdRecoveryCandidate).GetConstructors(
            BindingFlags.Public | BindingFlags.Instance));
        Assert.Empty(typeof(TerminalColdRecoveryState).GetConstructors(
            BindingFlags.Public | BindingFlags.Instance));

        Assert.NotNull(typeof(ColdRecoveryCandidate).GetProperty("Candidate"));
        Assert.NotNull(typeof(ColdRecoveryCandidate).GetProperty("ExternalCheckpoint"));
        Assert.Null(typeof(TerminalColdRecoveryState).GetProperty("Candidate"));
        Assert.Null(typeof(TerminalColdRecoveryState).GetProperty("ExternalCheckpoint"));
        Assert.Null(typeof(TerminalColdRecoveryState).GetProperty("CanonicalDpl"));

        Assert.Empty(typeof(VerifiedRecoveredCutoverCheckpoint).GetConstructors(
            BindingFlags.Public | BindingFlags.Instance));
        Assert.DoesNotContain(typeof(VerifiedRecoveredCutoverCheckpoint)
            .GetMethods(BindingFlags.Public | BindingFlags.Static),
            method => method.ReturnType == typeof(VerifiedRecoveredCutoverCheckpoint));
    }

    private static byte[] StructurallyValidDwt()
    {
        var fields = RecordDefinitions.Dwt1.Fields
            .Select(field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength])
            .ToArray();
        fields[0] = Enumerable.Repeat((byte)0x11, 16).ToArray();
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
        fields[9] = Enumerable.Repeat((byte)0x41, 32).ToArray();
        return CanonicalGrammar.Encode(RecordDefinitions.Dwt1, fields);
    }

    private static byte[] Reference(ArtifactType type, uint length, byte marker)
    {
        var value = new byte[ArtifactReference.Length];
        BinaryPrimitives.WriteUInt16BigEndian(value, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(2), length);
        value.AsSpan(6).Fill(marker);
        return value;
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private sealed class PlaintextProvider(byte[] nonce, byte[] plaintext)
        : RecoveryProtectorProvider
    {
        internal int DeriveCalls { get; private set; }
        internal int OpenCalls { get; private set; }

        public override ValueTask DeriveNonceAsync(
            RecoveryProviderRequest request,
            Memory<byte> derivedNonce24,
            CancellationToken cancellationToken)
        {
            DeriveCalls++;
            nonce.CopyTo(derivedNonce24);
            return ValueTask.CompletedTask;
        }

        public override ValueTask OpenAsync(
            RecoveryProviderRequest request,
            Memory<byte> plaintextDestination,
            CancellationToken cancellationToken)
        {
            OpenCalls++;
            plaintext.CopyTo(plaintextDestination);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class StoredLatch : RecoveryNonceLatch
    {
        private int _calls;
        public override ValueTask<RecoveryNonceLatchDecision> CompareOrLatchAsync(
            RecoveryNonceLatchRequest request,
            CancellationToken cancellationToken) =>
            ValueTask.FromResult(Interlocked.Increment(ref _calls)==1
                ? RecoveryNonceLatchDecision.Stored
                : RecoveryNonceLatchDecision.ExactReplay);
    }

    private sealed class FixedRegistry(byte[] resetId,byte[] rsm)
        : RecoveryProviderRegistry
    {
        public override ValueTask<RecoveryProviderRegistryReadResult> ReadAsync(
            RecoveryProviderRegistryRequest request,CancellationToken cancellationToken)
        {
            var selector=request.OperationSelector.Span;
            var scope=new byte[RecoveryProviderRegistryContext.ExactScopeLength];
            selector[..16].CopyTo(scope);resetId.CopyTo(scope.AsSpan(16));
            selector.Slice(16,32).CopyTo(scope.AsSpan(48));
            selector.Slice(48,8).CopyTo(scope.AsSpan(80));
            BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(88,2),2);
            BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(90,2),
                (ushort)RecoveryProtectedKeyKind.ProtectedStateHmac);
            rsm.AsSpan(499,32).CopyTo(scope.AsSpan(92));
            BinaryPrimitives.WriteUInt16BigEndian(scope.AsSpan(124,2),
                (ushort)RecoveryProtectedKeyKind.RecoveryNonceLatch);
            Enumerable.Repeat((byte)0x6a,32).ToArray().CopyTo(scope.AsSpan(126));
            return ValueTask.FromResult(new RecoveryProviderRegistryReadResult(
                scope,1,true,true));
        }
    }

    private sealed class HmacProvider(byte[] key) : IProtectedHmacProvider
    {
        internal int Calls { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
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
