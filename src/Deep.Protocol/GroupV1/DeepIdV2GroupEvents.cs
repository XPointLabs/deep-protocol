using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.Identity;

namespace Deep.Protocol.GroupV1;

/// <summary>Closed endpoint-bound group authors. Generic/raw emission stays disabled.</summary>
public static class DeepIdV2GroupEvents
{
    /// <summary>Authors only a current sequencer's E2EE-bound control descriptor/key carrier.</summary>
    public static async ValueTask<ParsedDmc2> AuthorControlAsync(GroupControlRendezvousRecord descriptor,
        ReadOnlyMemory<byte> sealingScalar, VerifiedGroupTransition head, VerifiedDeepIdV2GroupDirectory sender,
        VerifiedDeepIdV2GroupDirectory recipient, OwnedGenesisDeviceSecrets device, VerifiedOnionNetworkContext network,
        ReadOnlyMemory<byte> logicalId, ReadOnlyMemory<byte> conversation, ulong sequence, OnionTrustedTimeAuthority time, CancellationToken ct = default)
    {
        RequireId(logicalId.Span); RequireId(conversation.Span);
        if (sequence is < 3 or >= long.MaxValue) throw new ArgumentOutOfRangeException(nameof(sequence));
        var first = await time.ReadCurrentAsync(ct).ConfigureAwait(false); RequirePair(sender, recipient, first);
        device.RequireCurrentGroupDevice(sender); GroupCodec.RequireCurrentSequencer(head.Commit, sender, device.DeviceId.Bytes.Span);
        await GroupControlProductionClient.RequireRendezvousAsync(descriptor, head, sender, network, time, ct).ConfigureAwait(false);
        var raw = new byte[624]; head.Commit.Field(2).Span.CopyTo(raw); recipient.AccountId.Span.CopyTo(raw.AsSpan(32));
        descriptor.CanonicalBytes.Span.CopyTo(raw.AsSpan(64)); sealingScalar.Span.CopyTo(raw.AsSpan(592));
        try
        {
            var payload = GroupCodec.DecodeDmc2Payload(Dmc2ContentKind.GroupControlRendezvous, raw);
            var created = checked((Math.Max(Upper(sender, first), Upper(recipient, first)) + 1) * 1000);
            var result = ApplicationCoreCodec.AuthorOwnedGroupDmc2(sender.NetworkId.Span, logicalId.Span, conversation.Span,
                sender.AccountId.Span, device.DeviceId.Bytes.Span, sequence, created, checked(created + 604800000), payload);
            var final = await time.ReadCurrentAsync(ct).ConfigureAwait(false); ContactControlEndpointV2.RequireContinuous(first, final);
            RequirePair(sender, recipient, final); ct.ThrowIfCancellationRequested(); return result;
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }

    public static IReadOnlyList<GroupCommitChunkRecord> Chunk(VerifiedGroupTransition head, ReadOnlyMemory<byte> exactPackage)
    {
        ArgumentNullException.ThrowIfNull(head);
        if (!head.BindsExactGcp1(exactPackage.Span)) throw new CryptographicException("Group package differs from verified custody.");
        var hash = GroupCodec.RecordHash(ProtocolMagic.GCP1, exactPackage.Span);
        var count = checked((uint)((exactPackage.Length + 24575) / 24576));
        var result = new List<GroupCommitChunkRecord>(checked((int)count));
        for (uint index = 0; index < count; index++)
        {
            var offset = checked((int)index * 24576); var bytes = exactPackage.Slice(offset, Math.Min(24576, exactPackage.Length - offset));
            result.Add((GroupCommitChunkRecord)GroupCodec.CreateForAuthoring(ProtocolMagic.GCF1,
                [hash, U32(checked((uint)exactPackage.Length)), U32(24576), U32(index), U32(count), SHA256.HashData(bytes.Span), Lp(bytes.Span)]));
        }
        return result;
    }

    public static async ValueTask<GroupApplicationMessageRecord> TextAsync(VerifiedGroupTransition head,
        VerifiedDeepIdV2GroupDirectory sender, VerifiedDeepIdV2GroupDirectory recipient,
        OwnedGenesisDeviceSecrets device, ReadOnlyMemory<byte> logicalId, ulong groupSequence, string text,
        OnionTrustedTimeAuthority time, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(device); ArgumentNullException.ThrowIfNull(text);
        RequireId(logicalId.Span); if (groupSequence is 0 or >= long.MaxValue) throw new ArgumentOutOfRangeException(nameof(groupSequence));
        var encoded = new UTF8Encoding(false, true).GetBytes(text);
        if (encoded.Length is < 1 or > 24576 || !text.IsNormalized(NormalizationForm.FormC) || text.Contains('\0'))
            throw new ArgumentException("Group text is not canonical/bounded.", nameof(text));
        var first = await time.ReadCurrentAsync(ct).ConfigureAwait(false);
        RequirePair(sender, recipient, first); device.RequireCurrentGroupDevice(sender);
        GroupCodec.RequireGroupApplicationMember(head, sender, device.DeviceId.Bytes.Span);
        GroupCodec.RequireGroupApplicationMember(head, recipient, default);
        var created = checked((Upper(sender, first) + 1) * 1000);
        var expiry = checked(created + BinaryPrimitives.ReadUInt32BigEndian(head.Commit.Field(15).Span) * 1000UL);
        var record = (GroupApplicationMessageRecord)GroupCodec.CreateForAuthoring(ProtocolMagic.DGM1,
            [sender.NetworkId, head.Commit.Field(2), head.Commit.Field(4), head.Commit.ArtifactHash, logicalId,
             sender.AccountId, device.DeviceId.Bytes, U64(groupSequence), U64(created), U64(expiry), U16(1), encoded]);
        var final = await time.ReadCurrentAsync(ct).ConfigureAwait(false); ct.ThrowIfCancellationRequested();
        ContactControlEndpointV2.RequireContinuous(first, final); RequirePair(sender, recipient, final);
        return record;
    }

    public static async ValueTask<ParsedDmc2> AuthorAsync(GroupRecord record, VerifiedGroupTransition head,
        VerifiedDeepIdV2GroupDirectory sender, VerifiedDeepIdV2GroupDirectory recipient, OwnedGenesisDeviceSecrets device,
        ReadOnlyMemory<byte> logicalId, ReadOnlyMemory<byte> conversation, ulong sequence,
        OnionTrustedTimeAuthority time, GroupInvitationRecord? originalInvitation = null,
        ReadOnlyMemory<byte> exactPackage = default, CancellationToken ct = default)
    {
        RequireId(logicalId.Span); RequireId(conversation.Span);
        if (sequence is < 3 or >= long.MaxValue) throw new ArgumentOutOfRangeException(nameof(sequence));
        var first = await time.ReadCurrentAsync(ct).ConfigureAwait(false); RequirePair(sender, recipient, first);
        device.RequireCurrentGroupDevice(sender);
        RequireRecord(record, head, sender, recipient, device.DeviceId.Bytes.Span, first, originalInvitation, exactPackage);
        var kind = Kind(record);
        var payload = new GroupDmc2Payload(kind, Lp(record.CanonicalBytes.Span), record);
        var created = checked((Math.Max(Upper(sender, first), Upper(recipient, first)) + 1) * 1000);
        var expiry = record.Magic switch
        {
            ProtocolMagic.GIV1 => checked(BinaryPrimitives.ReadUInt64BigEndian(record.Field(17).Span) * 1000),
            ProtocolMagic.GIA1 => checked(BinaryPrimitives.ReadUInt64BigEndian(record.Field(14).Span) * 1000),
            ProtocolMagic.DGM1 => BinaryPrimitives.ReadUInt64BigEndian(record.Field(10).Span),
            _ => checked(created + 604800000)
        };
        var result = ApplicationCoreCodec.AuthorOwnedGroupDmc2(sender.NetworkId.Span, logicalId.Span, conversation.Span,
            sender.AccountId.Span, device.DeviceId.Bytes.Span, sequence, created, expiry, payload);
        var final = await time.ReadCurrentAsync(ct).ConfigureAwait(false); ct.ThrowIfCancellationRequested();
        ContactControlEndpointV2.RequireContinuous(first, final); RequirePair(sender, recipient, final);
        return result;
    }

    /// <summary>Endpoint predicates only; native receive and protected state independently own ACK.</summary>
    public static async ValueTask RequireAsync(GroupRecord record, VerifiedGroupTransition head,
        VerifiedDeepIdV2GroupDirectory sender, VerifiedDeepIdV2GroupDirectory recipient, ReadOnlyMemory<byte> senderDevice,
        OnionTrustedTimeAuthority time, GroupInvitationRecord? invitation = null, CancellationToken ct = default)
    {
        var first = await time.ReadCurrentAsync(ct).ConfigureAwait(false); RequirePair(sender, recipient, first);
        RequireRecord(record, head, sender, recipient, senderDevice.Span, first, invitation, default);
        var final = await time.ReadCurrentAsync(ct).ConfigureAwait(false); ct.ThrowIfCancellationRequested();
        ContactControlEndpointV2.RequireContinuous(first, final); RequirePair(sender, recipient, final);
    }

    private static void RequireRecord(GroupRecord record, VerifiedGroupTransition head, VerifiedDeepIdV2GroupDirectory sender,
        VerifiedDeepIdV2GroupDirectory recipient, ReadOnlySpan<byte> device, OnionMonotonicReading reading,
        GroupInvitationRecord? invitation, ReadOnlyMemory<byte> exactPackage)
    {
        switch (record)
        {
            case GroupInvitationRecord offered:
                GroupCodec.RequireCurrentInvitation(head.Commit, offered, sender, recipient, reading); break;
            case GroupInvitationAcceptanceRecord accepted:
                if (invitation is null) throw new CryptographicException("Group consent lost its exact invitation.");
                GroupCodec.RequireCurrentConsent(head.Commit, invitation, accepted, recipient, sender, reading); break;
            case GroupCommitChunkRecord chunk:
                GroupCodec.RequireCurrentSequencer(head.Commit, sender, device);
                if (!exactPackage.IsEmpty)
                {
                    if (!head.BindsExactGcp1(exactPackage.Span) ||
                        BinaryPrimitives.ReadUInt32BigEndian(chunk.Field(2).Span) != checked((uint)exactPackage.Length) ||
                        !chunk.Field(1).Span.SequenceEqual(GroupCodec.RecordHash(ProtocolMagic.GCP1, exactPackage.Span)))
                        throw new CryptographicException("Group chunk differs from verified package.");
                    var index = BinaryPrimitives.ReadUInt32BigEndian(chunk.Field(4).Span);
                    var offset = checked((int)index * 24576); var field = chunk.Field(7).Span;
                    if (offset >= exactPackage.Length || !field[4..].SequenceEqual(exactPackage.Span.Slice(offset, Math.Min(24576, exactPackage.Length - offset))))
                        throw new CryptographicException("Group chunk bytes differ from exact package.");
                }
                break;
            case GroupApplicationMessageRecord message:
                GroupCodec.RequireGroupApplicationMember(head, sender, device); GroupCodec.RequireGroupApplicationMember(head, recipient, default);
                var created = BinaryPrimitives.ReadUInt64BigEndian(message.Field(9).Span);
                var expires = BinaryPrimitives.ReadUInt64BigEndian(message.Field(10).Span);
                if (!message.Field(1).Span.SequenceEqual(sender.NetworkId.Span) || !message.Field(2).Span.SequenceEqual(head.Commit.Field(2).Span) ||
                    !message.Field(3).Span.SequenceEqual(head.Commit.Field(4).Span) || !message.Field(4).Span.SequenceEqual(head.Commit.ArtifactHash.Span) ||
                    !message.Field(6).Span.SequenceEqual(sender.AccountId.Span) || !message.Field(7).Span.SequenceEqual(device) ||
                    BinaryPrimitives.ReadUInt16BigEndian(message.Field(11).Span) != 1 || BinaryPrimitives.ReadUInt64BigEndian(message.Field(8).Span) == 0 ||
                    created > checked((Math.Max(Upper(sender, reading), Upper(recipient, reading)) + 1) * 1000) || expires <= created ||
                    expires - created > checked(BinaryPrimitives.ReadUInt32BigEndian(head.Commit.Field(15).Span) * 1000UL) ||
                    expires <= checked(Upper(recipient, reading) * 1000))
                    throw new CryptographicException("Group application event differs from its current epoch/member/time.");
                var text = new UTF8Encoding(false, true).GetString(message.Field(12).Span);
                if (text.Length == 0 || !text.IsNormalized(NormalizationForm.FormC) || text.Contains('\0'))
                    throw new CryptographicException("Group text is not canonical.");
                break;
            default: throw new NotSupportedException("This group record has no owned connected author/consumer.");
        }
    }

    private static Dmc2ContentKind Kind(GroupRecord record) => record.Magic switch
    { ProtocolMagic.GIV1 => Dmc2ContentKind.GroupInvite, ProtocolMagic.GIA1 => Dmc2ContentKind.GroupInvitationAcceptance,
      ProtocolMagic.GCF1 => Dmc2ContentKind.GroupCommitChunk, ProtocolMagic.DGM1 => Dmc2ContentKind.GroupApplicationMessage,
      _ => throw new NotSupportedException("Unsupported owned group kind.") };
    private static void RequirePair(VerifiedDeepIdV2GroupDirectory sender, VerifiedDeepIdV2GroupDirectory recipient, OnionMonotonicReading reading)
    {
        sender.RequireCurrent(reading); recipient.RequireCurrent(reading);
        if (!sender.NetworkId.Span.SequenceEqual(recipient.NetworkId.Span) || sender.AccountId.Span.SequenceEqual(recipient.AccountId.Span))
            throw new CryptographicException("Group endpoints must be distinct accounts on one network.");
    }
    private static ulong Upper(VerifiedDeepIdV2GroupDirectory account, OnionMonotonicReading reading) =>
        checked(account.Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - account.Proof.MonotonicSample);
    private static void RequireId(ReadOnlySpan<byte> id) { if (id.Length != 32 || id.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("Nonzero group identifier required."); }
    private static byte[] Lp(ReadOnlySpan<byte> bytes) { var result = new byte[checked(bytes.Length + 4)]; BinaryPrimitives.WriteUInt32BigEndian(result, checked((uint)bytes.Length)); bytes.CopyTo(result.AsSpan(4)); return result; }
    private static byte[] U16(ushort value) { var result = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(result, value); return result; }
    private static byte[] U32(uint value) { var result = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(result, value); return result; }
    private static byte[] U64(ulong value) { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
}

public static partial class GroupCodec
{
    internal static void RequireGroupApplicationMember(VerifiedGroupTransition head, VerifiedDeepIdV2GroupDirectory account, ReadOnlySpan<byte> device)
    {
        if (!head.Commit.FieldSpan(1).SequenceEqual(account.NetworkId.Span)) throw new CryptographicException("Group network differs from account.");
        var member = FindMember(ReadMembers(head.Commit.FieldSpan(12)), account.AccountId.Span, true)!;
        RequireCurrentMember(member, account);
        if (!device.IsEmpty && FindDevice(member, device) is null) throw new CryptographicException("Group author device is absent from current membership.");
    }
}
