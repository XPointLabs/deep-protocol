using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Protocol.Tests.ContactV1;

public sealed class Xpk1ClaimJournalTests
{
    [Fact]
    public void ExactRetryIsStableAndSameOperationByteDriftForkLatches()
    {
        var exact = Request(0x11, 0x31);
        var state = Xpk1ClaimJournalState.Stage(exact);

        Assert.True(state.CanDispatchExactRequest);
        Assert.Equal(exact, state.ExactRequest.ToArray());
        Assert.Equal(Xpk1ClaimJournalDisposition.ExactRetry, state.ApplyRequest(exact).Disposition);

        var drifted = Request(0x11, 0x32);
        var fork = state.ApplyRequest(drifted);
        Assert.Equal(Xpk1ClaimJournalDisposition.ForkLatched, fork.Disposition);
        Assert.True(fork.RequiresDurableWrite);
        Assert.True(fork.NextState.IsForkLatched);
        Assert.False(fork.CanDispatchExactRequest);

        var otherOperation = Request(0x12, 0x31);
        var rejected = state.ApplyRequest(otherOperation);
        Assert.Equal(Xpk1ClaimJournalDisposition.ScopeRejected, rejected.Disposition);
        Assert.False(rejected.RequiresDurableWrite);
        Assert.False(rejected.NextState.IsForkLatched);
    }

    [Fact]
    public void TerminalResultIsPersistedAndExactReplayedAcrossRestore()
    {
        var exact = Request(0x21, 0x41);
        var resultWire = Xpc1Codec.Encode(
            exact,
            Xpc1Status.Expired,
            ContactServiceMutationOutcome.None,
            1_050,
            0,
            ContactServicePaddingClass.Bytes256,
            []);
        var result = Xpc1Codec.Decode(resultWire, exact);
        var recorded = Xpk1ClaimJournalState.Stage(exact).RecordFailureResult(result);

        Assert.Equal(Xpk1ClaimJournalDisposition.ResultRecorded, recorded.Disposition);
        Assert.True(recorded.RequiresDurableWrite);
        Assert.True(recorded.NextState.IsTerminal);
        Assert.False(recorded.CanDispatchExactRequest);
        Assert.Equal(resultWire, recorded.NextState.StoredResultWire.ToArray());

        var replay = recorded.NextState.ApplyRequest(exact);
        Assert.Equal(Xpk1ClaimJournalDisposition.TerminalExactReplay, replay.Disposition);
        Assert.True(replay.RequiresStoredResult);
        Assert.False(replay.RequiresDurableWrite);

        var restored = Xpk1ClaimJournalState.RestoreFailure(exact, resultWire);
        Assert.True(restored.IsTerminal);
        Assert.Equal(resultWire, restored.StoredResultWire.ToArray());
        Assert.Equal(
            Xpk1ClaimJournalDisposition.TerminalExactReplay,
            restored.ApplyRequest(exact).Disposition);

        var changedWire = Xpc1Codec.Encode(
            exact,
            Xpc1Status.PreKeysUnavailable,
            ContactServiceMutationOutcome.None,
            1_051,
            0,
            ContactServicePaddingClass.Bytes256,
            []);
        var changed = Xpc1Codec.Decode(changedWire, exact);
        var fork = restored.RecordFailureResult(changed);
        Assert.Equal(Xpk1ClaimJournalDisposition.ForkLatched, fork.Disposition);
        Assert.True(fork.NextState.IsForkLatched);
    }

    [Fact]
    public void RetryableResultCanResolveToOneImmutableTerminalResult()
    {
        var exact = Request(0x22, 0x42);
        var rateLimitedWire = Xpc1Codec.Encode(
            exact,
            Xpc1Status.RateLimited,
            ContactServiceMutationOutcome.None,
            1_050,
            5,
            ContactServicePaddingClass.Bytes256,
            []);
        var staged = Xpk1ClaimJournalState.Stage(exact).RecordFailureResult(
            Xpc1Codec.Decode(rateLimitedWire, exact)).NextState;

        Assert.False(staged.IsTerminal);
        Assert.True(staged.CanDispatchExactRequest);
        Assert.Equal(Xpk1ClaimJournalDisposition.ExactRetry, staged.ApplyRequest(exact).Disposition);

        var terminalWire = Xpc1Codec.Encode(
            exact,
            Xpc1Status.Expired,
            ContactServiceMutationOutcome.None,
            1_055,
            0,
            ContactServicePaddingClass.Bytes256,
            []);
        var terminal = staged.RecordFailureResult(Xpc1Codec.Decode(terminalWire, exact));
        Assert.Equal(Xpk1ClaimJournalDisposition.ResultRecorded, terminal.Disposition);
        Assert.True(terminal.NextState.IsTerminal);
        Assert.Equal(terminalWire, terminal.NextState.StoredResultWire.ToArray());
    }

    [Fact]
    public void SuccessfulResultCannotEnterJournalWithoutVerifiedReceipt()
    {
        Assert.Empty(typeof(Xpk1ClaimJournalState).GetConstructors());
        Assert.DoesNotContain(
            typeof(Xpk1ClaimJournalState).GetMethods(),
            static method => method.Name.Contains("Claim", StringComparison.Ordinal) &&
                method.GetParameters().All(parameter =>
                    parameter.ParameterType != typeof(VerifiedXpc1PreKeyClaimReceipt)) &&
                method.GetParameters().Any(parameter => parameter.ParameterType == typeof(Xpc1Result)));
    }

    [Fact]
    public void ExactXpk1IsAcceptedByTheProductionContactResolveWireBoundary()
    {
        var exact = Request(0x31, 0x51);
        var decoded = Xpk1Codec.Decode(exact);
        var network = CreateNetwork(decoded.NetworkId.Span);

        var verified = OnionTerminalPayloadVerifierV1.VerifyRequest(
            network,
            OnionOperation.ContactResolve,
            exact);

        Assert.Equal(OnionOperation.ContactResolve, verified.Operation);
        Assert.Equal(exact, verified.CanonicalBytes.ToArray());
    }

    private static byte[] Request(byte operationMarker, byte viewMarker)
    {
        var operationId = Bytes(32, operationMarker);
        return Xpk1Codec.Encode(
            Bytes(16, 0x21),
            operationId,
            Bytes(32, viewMarker),
            Bytes(32, 0x41),
            1_000,
            1_100,
            Bytes(32, 0x51),
            Bytes(32, 0x61),
            Bytes(32, 0x71),
            Bytes(32, 0x81),
            Bytes(32, 0x91));
    }

    private static byte[] Bytes(int length, byte seed) =>
        Enumerable.Range(0, length).Select(index => unchecked((byte)(seed + index))).ToArray();

    [UnsafeAccessor(UnsafeAccessorKind.Constructor)]
    private static extern VerifiedOnionNetworkContext CreateNetwork(ReadOnlySpan<byte> networkId);
}
