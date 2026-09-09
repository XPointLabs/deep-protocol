using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;

namespace Deep.Protocol.GroupV1;

public enum GroupControlRequestKind : byte { Write = 1, Fetch = 2 }
public enum GroupControlResultStatus : ushort
{
    Committed = 1,
    ExactReplay = 2,
    Events = 3,
    NoEvents = 4,
    Expired = 5,
    RateLimited = 6,
    StaleView = 7,
    Conflict = 8,
    OutcomeUnknown = 9,
    SizeFailure = 10,
    RecordTooLarge = 11,
}

public sealed class GroupControlClientException : CryptographicException
{
    internal GroupControlClientException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;
    public string Code { get; }
}

public sealed class GroupControlWriteAuthoringRequest
{
    private readonly byte[] operationId, predecessorControlHash, sealedGcf1;
    public GroupControlWriteAuthoringRequest(VerifiedGroupTransition group,
        VerifiedGroupControlPlacement placement, ReadOnlySpan<byte> operationId,
        ulong issuedAtUnixSeconds, ulong expiresAtUnixSeconds, ulong controlSequence,
        ReadOnlySpan<byte> predecessorControlHash, ReadOnlySpan<byte> sealedExactGcf1,
        ulong effectiveExpiresAtUnixSeconds)
    {
        Group = group ?? throw new ArgumentNullException(nameof(group));
        Placement = placement ?? throw new ArgumentNullException(nameof(placement));
        this.operationId = Required(operationId, 32, nameof(operationId), allowZero: false);
        if (issuedAtUnixSeconds == 0 || expiresAtUnixSeconds <= issuedAtUnixSeconds ||
            expiresAtUnixSeconds - issuedAtUnixSeconds > 86_400)
            throw new ArgumentOutOfRangeException(nameof(expiresAtUnixSeconds));
        if (controlSequence == 0) throw new ArgumentOutOfRangeException(nameof(controlSequence));
        this.predecessorControlHash = Required(predecessorControlHash, 32,
            nameof(predecessorControlHash), allowZero: controlSequence == 1);
        var predecessorIsZero = this.predecessorControlHash.AsSpan().IndexOfAnyExcept((byte)0) < 0;
        if ((controlSequence == 1) != predecessorIsZero)
            throw new ArgumentException("The predecessor hash must be zero exactly for control sequence one.", nameof(predecessorControlHash));
        if (sealedExactGcf1.Length is < 1 or > 32_768) throw new ArgumentOutOfRangeException(nameof(sealedExactGcf1));
        sealedGcf1 = sealedExactGcf1.ToArray();
        if (effectiveExpiresAtUnixSeconds <= issuedAtUnixSeconds) throw new ArgumentOutOfRangeException(nameof(effectiveExpiresAtUnixSeconds));
        IssuedAtUnixSeconds = issuedAtUnixSeconds; ExpiresAtUnixSeconds = expiresAtUnixSeconds;
        ControlSequence = controlSequence; EffectiveExpiresAtUnixSeconds = effectiveExpiresAtUnixSeconds;
    }
    public VerifiedGroupTransition Group { get; } public VerifiedGroupControlPlacement Placement { get; }
    public ReadOnlyMemory<byte> OperationId => operationId.ToArray(); public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; } public ulong ControlSequence { get; }
    public ReadOnlyMemory<byte> PredecessorControlHash => predecessorControlHash.ToArray();
    public ReadOnlyMemory<byte> SealedExactGcf1 => sealedGcf1.ToArray(); public ulong EffectiveExpiresAtUnixSeconds { get; }

    internal static byte[] Required(ReadOnlySpan<byte> value, int length, string name, bool allowZero)
    {
        if (value.Length != length || !allowZero && value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} bytes{(allowZero ? string.Empty : " and non-zero")}.", name);
        return value.ToArray();
    }
}

public sealed class GroupControlQueryAuthoringRequest
{
    private readonly byte[] operationId;
    public GroupControlQueryAuthoringRequest(VerifiedGroupTransition group,
        VerifiedGroupControlPlacement placement, ReadOnlySpan<byte> operationId,
        ulong issuedAtUnixSeconds, ulong expiresAtUnixSeconds, ulong afterControlSequence,
        ushort maximumRecords, ushort responsePaddingClass)
    {
        Group = group ?? throw new ArgumentNullException(nameof(group));
        Placement = placement ?? throw new ArgumentNullException(nameof(placement));
        this.operationId = GroupControlWriteAuthoringRequest.Required(operationId, 32, nameof(operationId), allowZero: false);
        if (issuedAtUnixSeconds == 0 || expiresAtUnixSeconds <= issuedAtUnixSeconds ||
            expiresAtUnixSeconds - issuedAtUnixSeconds > 86_400)
            throw new ArgumentOutOfRangeException(nameof(expiresAtUnixSeconds));
        if (maximumRecords is < 1 or > 64) throw new ArgumentOutOfRangeException(nameof(maximumRecords));
        if (responsePaddingClass > 4) throw new ArgumentOutOfRangeException(nameof(responsePaddingClass));
        IssuedAtUnixSeconds = issuedAtUnixSeconds; ExpiresAtUnixSeconds = expiresAtUnixSeconds;
        AfterControlSequence = afterControlSequence; MaximumRecords = maximumRecords;
        ResponsePaddingClass = responsePaddingClass;
    }
    public VerifiedGroupTransition Group { get; } public VerifiedGroupControlPlacement Placement { get; }
    public ReadOnlyMemory<byte> OperationId => operationId.ToArray(); public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; } public ulong AfterControlSequence { get; }
    public ushort MaximumRecords { get; } public ushort ResponsePaddingClass { get; }
}

public abstract class VerifiedGroupControlRequest
{
    private readonly byte[] groupId, groupCommitHash, operationId, gsr1Hash, placementHash;
    private protected VerifiedGroupControlRequest(VerifiedGroupTransition group,
        VerifiedGroupControlPlacement placement, GroupRecord record,
        VerifiedCanonicalOnionRequest terminalRequest, GroupControlRequestKind kind)
    {
        Group = group; Placement = placement; Record = record; TerminalRequest = terminalRequest; Kind = kind;
        groupId = group.Commit.Field(2).ToArray(); groupCommitHash = group.Commit.ArtifactHash.ToArray();
        operationId = record.Field(2).ToArray(); gsr1Hash = placement.Rendezvous.Record.ArtifactHash.ToArray();
        placementHash = placement.PlacementHash.ToArray();
    }
    public GroupControlRequestKind Kind { get; } public VerifiedGroupTransition Group { get; }
    public VerifiedGroupControlPlacement Placement { get; } public GroupRecord Record { get; }
    public ReadOnlyMemory<byte> GroupId => groupId.ToArray(); public ReadOnlyMemory<byte> GroupCommitHash => groupCommitHash.ToArray();
    public ReadOnlyMemory<byte> OperationId => operationId.ToArray(); public ReadOnlyMemory<byte> ExactGsr1Hash => gsr1Hash.ToArray();
    public ReadOnlyMemory<byte> CanonicalBytes => Record.CanonicalBytes;
    internal VerifiedCanonicalOnionRequest TerminalRequest { get; }
    internal ReadOnlySpan<byte> PlacementHashSpan => placementHash;
}

public sealed class VerifiedGroupControlWriteRequest : VerifiedGroupControlRequest
{
    internal VerifiedGroupControlWriteRequest(VerifiedGroupTransition group, VerifiedGroupControlPlacement placement,
        GroupControlWriteRecord record, VerifiedCanonicalOnionRequest terminalRequest)
        : base(group, placement, record, terminalRequest, GroupControlRequestKind.Write) { }
    public new GroupControlWriteRecord Record => (GroupControlWriteRecord)base.Record;
}

public sealed class VerifiedGroupControlQueryRequest : VerifiedGroupControlRequest
{
    internal VerifiedGroupControlQueryRequest(VerifiedGroupTransition group, VerifiedGroupControlPlacement placement,
        GroupControlQueryRecord record, VerifiedCanonicalOnionRequest terminalRequest)
        : base(group, placement, record, terminalRequest, GroupControlRequestKind.Fetch) { }
    public new GroupControlQueryRecord Record => (GroupControlQueryRecord)base.Record;
}

public sealed class VerifiedGroupControlResult
{
    internal VerifiedGroupControlResult(VerifiedGroupControlRequest request, GroupControlResultRecord record)
    { Request = request; Record = record; Status = (GroupControlResultStatus)BinaryPrimitives.ReadUInt16BigEndian(record.Field(4).Span); }
    public VerifiedGroupControlRequest Request { get; } public GroupControlResultRecord Record { get; }
    public GroupControlResultStatus Status { get; } public ReadOnlyMemory<byte> CanonicalBytes => Record.CanonicalBytes;
}

public static class GroupControlProductionClient
{
    private static readonly int[] WriteTags = [1,2,3,4,5,6,16,17,18,19,20,21,22];
    private static readonly int[] QueryTags = [1,2,3,4,5,6,16,17,18,19,20];

    public static VerifiedGroupControlWriteRequest AuthorWrite(GroupControlWriteAuthoringRequest request)
    {
        ArgumentNullException.ThrowIfNull(request); RequireBinding(request.Group, request.Placement,
            request.IssuedAtUnixSeconds, request.ExpiresAtUnixSeconds);
        var rendezvous = request.Placement.Rendezvous.Record; var sealedGcf1 = request.SealedExactGcf1.ToArray();
        var fields = new ReadOnlyMemory<byte>[] { rendezvous.Field(1), request.OperationId,
            request.Placement.ViewHash, request.Placement.PlacementHash, U64(request.IssuedAtUnixSeconds),
            U64(request.ExpiresAtUnixSeconds), rendezvous.Field(2), rendezvous.ArtifactHash,
            U64(request.ControlSequence), request.PredecessorControlHash, SHA256.HashData(sealedGcf1),
            Lp32(sealedGcf1), U64(request.EffectiveExpiresAtUnixSeconds) };
        var record = (GroupControlWriteRecord)GroupCodec.CreateTaggedForAuthoring(ProtocolMagic.GSW1, WriteTags, fields);
        var terminal = OnionTerminalPayloadVerifierV1.VerifyRequest(request.Placement.Network,
            OnionOperation.GroupControl, record.CanonicalBytes);
        return new VerifiedGroupControlWriteRequest(request.Group, request.Placement, record, terminal);
    }

    public static VerifiedGroupControlQueryRequest AuthorQuery(GroupControlQueryAuthoringRequest request)
    {
        ArgumentNullException.ThrowIfNull(request); RequireBinding(request.Group, request.Placement,
            request.IssuedAtUnixSeconds, request.ExpiresAtUnixSeconds);
        var rendezvous = request.Placement.Rendezvous.Record;
        var fields = new ReadOnlyMemory<byte>[] { rendezvous.Field(1), request.OperationId,
            request.Placement.ViewHash, request.Placement.PlacementHash, U64(request.IssuedAtUnixSeconds),
            U64(request.ExpiresAtUnixSeconds), rendezvous.Field(2), rendezvous.ArtifactHash,
            U64(request.AfterControlSequence), U16(request.MaximumRecords), U16(request.ResponsePaddingClass) };
        var record = (GroupControlQueryRecord)GroupCodec.CreateTaggedForAuthoring(ProtocolMagic.GSQ1, QueryTags, fields);
        var terminal = OnionTerminalPayloadVerifierV1.VerifyRequest(request.Placement.Network,
            OnionOperation.GroupControl, record.CanonicalBytes);
        return new VerifiedGroupControlQueryRequest(request.Group, request.Placement, record, terminal);
    }

    public static VerifiedGroupControlResult VerifyResult(VerifiedGroupControlRequest request,
        ReadOnlyMemory<byte> exactCanonicalGss1)
    {
        ArgumentNullException.ThrowIfNull(request);
        try
        {
            _ = OnionTerminalPayloadVerifierV1.VerifySuccess(request.TerminalRequest, exactCanonicalGss1);
            var record = (GroupControlResultRecord)GroupCodec.Decode(ProtocolMagic.GSS1, exactCanonicalGss1.Span);
            if (!Fixed(record.Field(1).Span, request.Placement.Rendezvous.Record.Field(1).Span) ||
                !Fixed(record.Field(2).Span, request.OperationId.Span) ||
                !Fixed(request.Record.Field(4).Span, request.PlacementHashSpan))
                Fail("result-binding-mismatch", "GSS1 is not bound to the exact operation and placement capability.");
            var status = (GroupControlResultStatus)BinaryPrimitives.ReadUInt16BigEndian(record.Field(4).Span);
            if (status is GroupControlResultStatus.Committed or GroupControlResultStatus.ExactReplay)
                VerifyWriteReceipts(request, record);
            return new VerifiedGroupControlResult(request, record);
        }
        catch (GroupControlClientException) { throw; }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new GroupControlClientException("result-invalid", "GSS1 failed exact production verification.", exception);
        }
    }

    private static void RequireBinding(VerifiedGroupTransition group, VerifiedGroupControlPlacement placement,
        ulong issuedAt, ulong expiresAt)
    {
        placement.Network.EnsureCurrent();
        var commit = group.Commit; var rendezvous = placement.Rendezvous; var gsr1 = rendezvous.Record;
        if (!Fixed(commit.Field(1).Span, gsr1.Field(1).Span) ||
            !Fixed(commit.Field(6).Span, rendezvous.Owner.Directory.Record.DeepAccountId.Span))
            Fail("group-placement-mismatch", "The verified GSR1 owner/network does not bind the exact verified group.");
        var owner = GroupCodec.RequireMemberClosureForAuthoring(commit, rendezvous.Owner);
        if (owner.Role != GroupRole.Owner || !owner.Devices.Any(device => Fixed(device.Id, gsr1.Field(10).Span)))
            Fail("group-placement-mismatch", "The verified GSR1 signer is not a current owner device in the exact group commit.");
        var gsrIssued = BinaryPrimitives.ReadUInt64BigEndian(gsr1.Field(12).Span);
        var gsrExpires = BinaryPrimitives.ReadUInt64BigEndian(gsr1.Field(13).Span);
        if (issuedAt < gsrIssued || expiresAt > gsrExpires)
            Fail("request-window-outside-rendezvous", "The GroupControl request window is outside the exact GSR1 lifetime.");
    }

    private static void VerifyWriteReceipts(VerifiedGroupControlRequest request, GroupControlResultRecord result)
    {
        var write = request as VerifiedGroupControlWriteRequest ??
            throw new GroupControlClientException("result-operation-mismatch",
                "A committed GSS1 result is valid only for GSW1.");
        var receipts = result.Field(20).Span;
        if (receipts.Length != 192) Fail("receipt-set-mismatch", "Committed GSS1 must contain exactly two replica receipts.");
        var nodes = request.Placement.ResolveSelectedReplicas().OrderBy(static node => node.NodeId,
            GroupControlByteComparer.Instance).ToArray();
        var tuple = Join(result.Field(3).ToArray(), result.Field(17).ToArray(),
            result.Field(18).ToArray(), result.Field(19).ToArray());
        var signingInput = GroupCodec.SignatureInput("Deep/Group/V1/control-store-commit", tuple);
        try
        {
            for (var index = 0; index < nodes.Length; index++)
            {
                var row = receipts.Slice(index * 96, 96); var node = nodes[index];
                if (!Fixed(row[..32], node.NodeId) || node.IdentityPublicKey is not { Length: 32 } identityKey ||
                    !PublicKeyAuth.VerifyDetached(row[32..].ToArray(), signingInput, identityKey))
                    Fail("receipt-verification-failed", "A GSS1 receipt is absent, substituted, or has an invalid replica signature.");
            }
            if (!Fixed(result.Field(17).Span, write.Record.Field(18).Span) ||
                !Fixed(result.Field(18).Span, write.Record.Field(20).Span))
                Fail("result-write-tuple-mismatch", "GSS1 changed the committed GSW1 sequence or sealed GCF1 hash.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tuple); CryptographicOperations.ZeroMemory(signingInput);
        }
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static byte[] U16(ushort value) { var output = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(output, value); return output; }
    private static byte[] U64(ulong value) { var output = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(output, value); return output; }
    private static byte[] Lp32(ReadOnlySpan<byte> value) { var output = new byte[checked(value.Length + 4)]; BinaryPrimitives.WriteUInt32BigEndian(output, checked((uint)value.Length)); value.CopyTo(output.AsSpan(4)); return output; }
    private static byte[] Join(params byte[][] values) { var output = new byte[checked(values.Sum(static value => value.Length))]; var at = 0; foreach (var value in values) { value.CopyTo(output, at); at += value.Length; } return output; }
    private static void Fail(string code, string message) => throw new GroupControlClientException(code, message);

    private sealed class GroupControlByteComparer : IComparer<byte[]>
    {
        internal static readonly GroupControlByteComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
