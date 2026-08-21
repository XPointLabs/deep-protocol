using Deep.Protocol.Abstractions.State;

namespace Deep.Protocol;

public static class SharedConfigParser
{
    public static SharedConfigEnvelope? TryParseFromContent(ReadOnlySpan<byte> serializedContent)
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

        var sharedConfig = content.SharedConfigMessage;
        if (sharedConfig is null || !sharedConfig.HasKind || !sharedConfig.HasSeqno || !sharedConfig.HasData)
        {
            return null;
        }

        return new SharedConfigEnvelope((int)sharedConfig.Kind, sharedConfig.Seqno, sharedConfig.Data.ToByteArray());
    }
}
