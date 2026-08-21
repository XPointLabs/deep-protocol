using Google.Protobuf;
using Deep.Protocol.Abstractions.State;

namespace Deep.Protocol.Tests;

public sealed class StateAndGroupTests
{
    [Fact]
    public void OneToOneStateMachineAppliesKnownMessageRequestTransitions()
    {
        var state = new OneToOneSessionState(
            "05d2ad010eeb72d72e561d9de7bd7b6989af77dcabffa03a5111a6c859ae5c3a72",
            OneToOneApprovalState.Unknown,
            null);
        var now = DateTimeOffset.FromUnixTimeMilliseconds(1754971101000);

        state = state.Apply(new OneToOneSessionEvent(OneToOneSessionEventKind.IncomingMessageReceived, now));
        Assert.Equal(OneToOneApprovalState.Pending, state.ApprovalState);

        state = state.Apply(new OneToOneSessionEvent(OneToOneSessionEventKind.MessageRequestApproved, now.AddMilliseconds(1)));
        Assert.Equal(OneToOneApprovalState.Approved, state.ApprovalState);

        state = state.Apply(new OneToOneSessionEvent(OneToOneSessionEventKind.ConversationBlocked, now.AddMilliseconds(2)));
        Assert.Equal(OneToOneApprovalState.Blocked, state.ApprovalState);
    }

    [Fact]
    public void GroupUpdateParserExtractsMemberChangeWithoutInventingWireFields()
    {
        var signature = Enumerable.Repeat((byte)0x55, 64).ToArray();
        var content = new SessionProtos.Content
        {
            DataMessage = new SessionProtos.DataMessage
            {
                GroupUpdateMessage = new SessionProtos.GroupUpdateMessage
                {
                    MemberChangeMessage = new SessionProtos.GroupUpdateMemberChangeMessage
                    {
                        Type = SessionProtos.GroupUpdateMemberChangeMessage.Types.Type.Added,
                        AdminSignature = ByteString.CopyFrom(signature),
                        HistoryShared = true,
                        MemberSessionIds = { "05abc" }
                    }
                }
            }
        };

        var parsed = GroupUpdateParser.TryParseFromContent(content.ToByteArray());

        Assert.NotNull(parsed);
        Assert.Equal(GroupUpdateEventKind.MemberChange, parsed.Kind);
        Assert.Equal(new[] { "05abc" }, parsed.MemberSessionIds);
        Assert.True(parsed.HistoryShared);
        Assert.Equal(signature, parsed.AdminSignature.ToArray());
    }

    [Fact]
    public void GroupUpdateParserRecognizesOtherCommonVariants()
    {
        var inviteSignature = Enumerable.Repeat((byte)0x11, 64).ToArray();
        var invite = GroupUpdateParser.TryParseFromContent(new SessionProtos.Content
        {
            DataMessage = new SessionProtos.DataMessage
            {
                GroupUpdateMessage = new SessionProtos.GroupUpdateMessage
                {
                    InviteMessage = new SessionProtos.GroupUpdateInviteMessage
                    {
                        GroupSessionId = "03invite",
                        Name = "Roadmap",
                        MemberAuthData = ByteString.CopyFrom(new byte[] { 0x01, 0x02 }),
                        AdminSignature = ByteString.CopyFrom(inviteSignature)
                    }
                }
            }
        }.ToByteArray());

        var infoChange = GroupUpdateParser.TryParseFromContent(new SessionProtos.Content
        {
            DataMessage = new SessionProtos.DataMessage
            {
                GroupUpdateMessage = new SessionProtos.GroupUpdateMessage
                {
                    InfoChangeMessage = new SessionProtos.GroupUpdateInfoChangeMessage
                    {
                        Type = SessionProtos.GroupUpdateInfoChangeMessage.Types.Type.Name,
                        UpdatedName = "Roadmap v2",
                        UpdatedExpiration = 3600,
                        AdminSignature = ByteString.CopyFrom(new byte[64])
                    }
                }
            }
        }.ToByteArray());

        var memberLeft = GroupUpdateParser.TryParseFromContent(new SessionProtos.Content
        {
            DataMessage = new SessionProtos.DataMessage
            {
                GroupUpdateMessage = new SessionProtos.GroupUpdateMessage
                {
                    MemberLeftMessage = new SessionProtos.GroupUpdateMemberLeftMessage()
                }
            }
        }.ToByteArray());

        var inviteResponse = GroupUpdateParser.TryParseFromContent(new SessionProtos.Content
        {
            DataMessage = new SessionProtos.DataMessage
            {
                GroupUpdateMessage = new SessionProtos.GroupUpdateMessage
                {
                    InviteResponse = new SessionProtos.GroupUpdateInviteResponseMessage
                    {
                        IsApproved = true
                    }
                }
            }
        }.ToByteArray());

        Assert.NotNull(invite);
        Assert.Equal(GroupUpdateEventKind.Invite, invite.Kind);
        Assert.Equal("Roadmap", invite.UpdatedName);
        Assert.Equal(inviteSignature, invite.AdminSignature.ToArray());

        Assert.NotNull(infoChange);
        Assert.Equal(GroupUpdateEventKind.InfoChange, infoChange.Kind);
        Assert.Equal("Roadmap v2", infoChange.UpdatedName);
        Assert.Equal(3600U, infoChange.UpdatedExpirationSeconds);

        Assert.NotNull(memberLeft);
        Assert.Equal(GroupUpdateEventKind.MemberLeft, memberLeft.Kind);

        Assert.NotNull(inviteResponse);
        Assert.Equal(GroupUpdateEventKind.InviteResponse, inviteResponse.Kind);
        Assert.True(inviteResponse.IsApproved);
    }

    [Fact]
    public void SharedConfigParserExtractsNamespaceEnvelope()
    {
        var serialized = new SessionProtos.Content
        {
            SharedConfigMessage = new SessionProtos.SharedConfigMessage
            {
                Kind = SessionProtos.SharedConfigMessage.Types.Kind.Contacts,
                Seqno = 7,
                Data = ByteString.CopyFrom(new byte[] { 0x10, 0x20, 0x30 })
            }
        }.ToByteArray();

        var envelope = SharedConfigParser.TryParseFromContent(serialized);

        Assert.NotNull(envelope);
        Assert.Equal((int)SessionProtos.SharedConfigMessage.Types.Kind.Contacts, envelope.Kind);
        Assert.Equal(7, envelope.SeqNo);
        Assert.Equal(new byte[] { 0x10, 0x20, 0x30 }, envelope.Data.ToArray());
    }

    [Fact]
    public void SharedConfigNamespaceMergeHonorsSeqNoOrderingAndDuplicateSemantics()
    {
        var state = new SharedConfigNamespaceState();
        var now = DateTimeOffset.UtcNow;

        var apply1 = SharedConfigNamespaceStateMachine.Apply(state, kind: 2, seqNo: 1, new byte[] { 0x01 }, now);
        Assert.Equal(SharedConfigMergeOutcome.Applied, apply1.Outcome);
        Assert.NotNull(apply1.AppliedEntry);

        var duplicate = SharedConfigNamespaceStateMachine.Apply(apply1.State, kind: 2, seqNo: 1, new byte[] { 0x01 }, now.AddSeconds(1));
        Assert.Equal(SharedConfigMergeOutcome.Duplicate, duplicate.Outcome);

        var stale = SharedConfigNamespaceStateMachine.Apply(apply1.State, kind: 2, seqNo: 0, new byte[] { 0x09 }, now.AddSeconds(2));
        Assert.Equal(SharedConfigMergeOutcome.Stale, stale.Outcome);

        var advanced = SharedConfigNamespaceStateMachine.Apply(apply1.State, kind: 2, seqNo: 2, new byte[] { 0x02, 0x03 }, now.AddSeconds(3));
        Assert.Equal(SharedConfigMergeOutcome.Applied, advanced.Outcome);
        Assert.Equal(2, advanced.State.Namespaces[2].SeqNo);
        Assert.Equal(new byte[] { 0x02, 0x03 }, advanced.State.Namespaces[2].Data.ToArray());
    }
}
