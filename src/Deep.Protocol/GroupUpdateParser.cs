using Deep.Protocol.Abstractions.State;

namespace Deep.Protocol;

public static class GroupUpdateParser
{
    public static GroupUpdateEvent? TryParseFromContent(ReadOnlySpan<byte> serializedContent)
    {
        SessionProtos.Content content;
        try
        {
            content = SessionProtos.Content.Parser.ParseFrom(serializedContent);
        }
        catch (Google.Protobuf.InvalidProtocolBufferException)
        {
            return null;
        }

        var update = content.DataMessage?.GroupUpdateMessage;
        if (update is null)
        {
            return null;
        }

        if (update.InviteMessage is { } invite)
        {
            return new GroupUpdateEvent(
                GroupUpdateEventKind.Invite,
                Array.Empty<string>(),
                invite.AdminSignature.ToByteArray(),
                GroupSessionId: invite.GroupSessionId,
                UpdatedName: invite.Name,
                MemberAuthData: invite.MemberAuthData.ToByteArray());
        }

        if (update.InfoChangeMessage is { } infoChange)
        {
            return new GroupUpdateEvent(
                GroupUpdateEventKind.InfoChange,
                Array.Empty<string>(),
                infoChange.AdminSignature.ToByteArray(),
                UpdatedName: infoChange.UpdatedName,
                UpdatedExpirationSeconds: infoChange.HasUpdatedExpiration ? infoChange.UpdatedExpiration : null);
        }

        if (update.MemberChangeMessage is { } memberChange)
        {
            return new GroupUpdateEvent(
                GroupUpdateEventKind.MemberChange,
                memberChange.MemberSessionIds.ToArray(),
                memberChange.AdminSignature.ToByteArray(),
                HistoryShared: memberChange.HasHistoryShared ? memberChange.HistoryShared : null);
        }

        if (update.PromoteMessage is { } promote)
        {
            return new GroupUpdateEvent(
                GroupUpdateEventKind.Promote,
                Array.Empty<string>(),
                ReadOnlyMemory<byte>.Empty,
                UpdatedName: promote.Name,
                GroupIdentitySeed: promote.GroupIdentitySeed.ToByteArray());
        }

        if (update.MemberLeftMessage is not null)
        {
            return new GroupUpdateEvent(
                GroupUpdateEventKind.MemberLeft,
                Array.Empty<string>(),
                ReadOnlyMemory<byte>.Empty);
        }

        if (update.InviteResponse is { } inviteResponse)
        {
            return new GroupUpdateEvent(
                GroupUpdateEventKind.InviteResponse,
                Array.Empty<string>(),
                ReadOnlyMemory<byte>.Empty,
                IsApproved: inviteResponse.IsApproved);
        }

        if (update.DeleteMemberContent is { } deleteContent)
        {
            return new GroupUpdateEvent(
                GroupUpdateEventKind.DeleteMemberContent,
                deleteContent.MemberSessionIds.ToArray(),
                deleteContent.AdminSignature.ToByteArray(),
                MessageHashes: deleteContent.MessageHashes.ToArray());
        }

        if (update.MemberLeftNotificationMessage is not null)
        {
            return new GroupUpdateEvent(
                GroupUpdateEventKind.MemberLeftNotification,
                Array.Empty<string>(),
                ReadOnlyMemory<byte>.Empty);
        }

        return null;
    }
}
