using System.Buffers.Binary;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.MessagingWire;
using Deep.Protocol.Tests.ContactV2;

namespace Deep.Protocol.Tests.DeepExtension.PrivacyRouting;

public sealed class PrivacyRoutingDid2ClaimTests
{
    [Fact]
    public void ClaimRequestAndResult_AcceptOnlyExactV2OnionPair()
    {
        var fixture = DeepIdV2PreKeyClaimCommitmentTests.Build(Dpk2PrekeyKind.LastResort);
        var request = DeepIdV2PreKeyClaimRequestCodec.Decode(fixture.Request);
        PrivacyRoutingPayloadVerifier.ValidateRequest(request.Field(1).Span,
            PrivacyRoutingOperation.ContactResolve, fixture.Request);
        var wire = DeepIdV2PreKeyClaimResultCodec.Encode(fixture.Request,
            Xpc1V2Status.Claimed, Xpc1V2MutationOutcome.DurablyCommitted,
            1_700_000_123, 0, DeepIdV2PreKeyClaimResultCodecTests.SuccessPayload(fixture));
        Validate(wire);
        var unavailable = DeepIdV2PreKeyClaimResultCodec.Encode(fixture.Request,
            Xpc1V2Status.OutcomeUnknown, Xpc1V2MutationOutcome.OutcomeUnknown, 123, 1, []);
        Validate(unavailable);

        var old = fixture.Request.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(old.AsSpan(4), 1);
        Assert.Throws<PrivacyRoutingProtocolException>(() => PrivacyRoutingPayloadVerifier.ValidateRequest(
            request.Field(1).Span, PrivacyRoutingOperation.ContactResolve, old));
        var oldResult = wire.ToArray();
        BinaryPrimitives.WriteUInt16BigEndian(oldResult.AsSpan(4), 1);
        Assert.Throws<PrivacyRoutingProtocolException>(() => Validate(oldResult));
        var changedNetwork = request.Field(1).ToArray(); changedNetwork[0] ^= 1;
        Assert.Equal(PrivacyRoutingProtocolError.InvalidKeyBinding,
            Assert.Throws<PrivacyRoutingProtocolException>(() => PrivacyRoutingPayloadVerifier.ValidateRequest(
                changedNetwork, PrivacyRoutingOperation.ContactResolve, fixture.Request)).Error);
        var changedRequest = fixture.Request.ToArray(); changedRequest[^40] ^= 1;
        Assert.Throws<PrivacyRoutingProtocolException>(() => PrivacyRoutingPayloadVerifier.ValidateResult(
            PrivacyRoutingOperation.ContactResolve, changedRequest,
            PrivacyRoutingTerminalResult.Success(PrivacyRoutingOperation.ContactResolve, wire)));
        var padding = wire.ToArray(); padding[^1] = 1;
        Assert.Throws<PrivacyRoutingProtocolException>(() => Validate(padding));
        Assert.Throws<PrivacyRoutingProtocolException>(() => Validate([.. wire, 0]));

        void Validate(byte[] result) => PrivacyRoutingPayloadVerifier.ValidateResult(
            PrivacyRoutingOperation.ContactResolve, fixture.Request,
            PrivacyRoutingTerminalResult.Success(PrivacyRoutingOperation.ContactResolve, result));
    }
}
