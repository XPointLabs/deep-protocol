using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.GroupV1;

/// <summary>Typed DMC2 carrier for one complete canonical group record. It never creates a shared group key.</summary>
public sealed class GroupDmc2Payload : Dmc2Payload
{
    internal GroupDmc2Payload(Dmc2ContentKind kind, byte[] canonical, GroupRecord record)
        : base(kind, canonical) => Record = record;
    public GroupRecord Record { get; }
    /// <summary>Inner group selector of kind30, never exposed to the control service.</summary>
    public ReadOnlyMemory<byte> ControlGroup => Kind == Dmc2ContentKind.GroupControlRendezvous ? CanonicalBytes[..32] : throw new InvalidOperationException();
    /// <summary>Intended E2EE recipient of kind30; receipt alone grants no membership.</summary>
    public ReadOnlyMemory<byte> ControlRecipient => Kind == Dmc2ContentKind.GroupControlRendezvous ? CanonicalBytes.Slice(32, 32) : throw new InvalidOperationException();
}

public static partial class GroupCodec
{
    internal static GroupDmc2Payload DecodeDmc2Payload(Dmc2ContentKind kind, ReadOnlySpan<byte> payload)
    {
        if (kind == Dmc2ContentKind.GroupControlRendezvous)
        {
            if (payload.Length != 624 || payload[..32].IndexOfAnyExcept((byte)0) < 0 || payload.Slice(32, 32).IndexOfAnyExcept((byte)0) < 0)
                throw new GroupFormatException(GroupValidationStage.Bounds, "InvalidControlCarrier");
            var descriptor = (GroupControlRendezvousRecord)Decode(ProtocolMagic.GSR1, payload.Slice(64, 528));
            if (!GroupControlCipher.PublicKey(payload[592..]).AsSpan().SequenceEqual(descriptor.Field(9).Span))
                throw new GroupFormatException(GroupValidationStage.Closure, "ControlKeyMismatch");
            return new GroupDmc2Payload(kind, payload.ToArray(), descriptor);
        }
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
