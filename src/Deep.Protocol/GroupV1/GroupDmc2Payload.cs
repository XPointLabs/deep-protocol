using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.GroupV1;

/// <summary>Typed DMC2 carrier for one complete canonical group record. It never creates a shared group key.</summary>
public sealed class GroupDmc2Payload : Dmc2Payload
{
    internal GroupDmc2Payload(Dmc2ContentKind kind, byte[] canonical, GroupRecord record)
        : base(kind, canonical) => Record = record;
    public GroupRecord Record { get; }
}

public static partial class GroupCodec
{
    internal static GroupDmc2Payload DecodeDmc2Payload(Dmc2ContentKind kind, ReadOnlySpan<byte> payload)
    {
        var expected = ExpectedDmcRecord(kind);
        if (payload.Length < 5) throw new GroupFormatException(GroupValidationStage.Bounds, "TruncatedDmcPayload");
        var length = BinaryPrimitives.ReadUInt32BigEndian(payload);
        if (length > int.MaxValue || length != payload.Length - 4) throw new GroupFormatException(GroupValidationStage.Bounds, "InvalidDmcPayloadLength");
        var record = Decode(expected, payload[4..]);
        return new GroupDmc2Payload(kind, payload.ToArray(), record);
    }

    internal static string ExpectedDmcRecord(Dmc2ContentKind kind) => kind switch
    {
        Dmc2ContentKind.GroupProposal => ProtocolMagic.DGP1,
        Dmc2ContentKind.GroupCommit => ProtocolMagic.GCF1,
        Dmc2ContentKind.GroupApplicationMessage => ProtocolMagic.DGM1,
        Dmc2ContentKind.GroupInvite => ProtocolMagic.GIV1,
        Dmc2ContentKind.GroupInvitationAcceptance => ProtocolMagic.GIA1,
        Dmc2ContentKind.GroupCommitChunk => ProtocolMagic.GCF1,
        Dmc2ContentKind.GroupEmergencySequencerTransfer => ProtocolMagic.DGT1,
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };
}
