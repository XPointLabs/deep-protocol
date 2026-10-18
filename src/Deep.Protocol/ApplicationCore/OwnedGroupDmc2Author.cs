using Deep.Protocol.GroupV1;

namespace Deep.Protocol.ApplicationCore;

public static partial class ApplicationCoreCodec
{
    internal static ParsedDmc2 AuthorOwnedGroupDmc2(ReadOnlySpan<byte> network, ReadOnlySpan<byte> logical,
        ReadOnlySpan<byte> conversation, ReadOnlySpan<byte> account, ReadOnlySpan<byte> device, ulong sequence,
        ulong created, ulong expires, GroupDmc2Payload payload) =>
        AuthorDmc2Core(network, logical, conversation, account, device, sequence, created, expires, Dmc2Flags.None, [], payload);
}
