using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.ContactV1;

public enum ContactServiceMutationOutcome : byte
{
    None = 0,
    DurablyCommitted = 1,
    OutcomeUnknown = 2,
}

public enum ContactServicePaddingClass : ushort
{
    Bytes256 = 0,
    Bytes1024 = 1,
    Bytes4096 = 2,
    Bytes16384 = 3,
    Bytes65536 = 4,
    Bytes131072 = 5,
}

public enum Xiq1AntiSpamTokenType : ushort { None = 0 }

public enum Xpo1Status : ushort { Committed = 1, ExactReplay = 2, Expired = 3, Unauthorized = 4, StaleView = 5, Conflict = 6, RateLimited = 7, OutcomeUnknown = 8, TemporarilyUnavailable = 9 }
public enum Xis1Status : ushort { Success = 1, Expired = 2, AlreadyClaimed = 3, NotFound = 4, TemporarilyUnavailable = 5, RateLimited = 6, StaleView = 7, Conflict = 8, OutcomeUnknown = 9 }
public enum Xpc1Status : ushort { Claimed = 1, Replay = 2, PreKeysUnavailable = 3, Expired = 4, StaleBundle = 5, RateLimited = 6, Conflict = 7, OutcomeUnknown = 8 }
public enum Xus1OperationKind : byte { Write = 1, Fetch = 2 }
public enum Xus1Status : ushort { WriteCommitted = 1, ExactReplay = 2, Events = 3, NoChange = 4, Expired = 5, RateLimited = 6, StaleGeneration = 7, Conflict = 8, OutcomeUnknown = 9, SizeFailure = 10, RecordTooLarge = 11 }

/// <summary>Owned immutable decoded service record. WireBytes includes authenticated result padding.</summary>
public abstract class ContactServiceWireRecord
{
    private readonly byte[] canonical;
    private readonly byte[] wire;
    private readonly Dictionary<ushort, byte[]> fields;

    internal ContactServiceWireRecord(ServiceRecord record)
    {
        Magic = record.Magic;
        canonical = record.Canonical.ToArray();
        wire = record.Wire.ToArray();
        fields = record.Fields.ToDictionary(pair => pair.Key, pair => pair.Value.ToArray());
    }

    public string Magic { get; }
    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> WireBytes => wire.ToArray();
    public ReadOnlyMemory<byte> CanonicalHash => SHA256.HashData(canonical);
    public ReadOnlyMemory<byte> Field(ushort tag) => fields.TryGetValue(tag, out var value) ? value.ToArray() : ReadOnlyMemory<byte>.Empty;
    internal ReadOnlySpan<byte> FieldSpan(ushort tag) => fields[tag];
}

public abstract class ContactServiceRequestRecord : ContactServiceWireRecord
{
    internal ContactServiceRequestRecord(ServiceRecord record) : base(record)
    {
        IssuedAtUnixSeconds = ServiceWire.U64(FieldSpan(5));
        ExpiresAtUnixSeconds = ServiceWire.U64(FieldSpan(6));
    }

    public ReadOnlyMemory<byte> NetworkId => Field(1);
    public ReadOnlyMemory<byte> OperationId => Field(2);
    public ReadOnlyMemory<byte> ViewHash => Field(3);
    public ReadOnlyMemory<byte> PlacementHash => Field(4);
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> RequestHash => ContactCodec.Sha256Domain("Deep/ContactResolver/V1/request", CanonicalBytes.Span);
}

public abstract class ContactServiceResultRecord : ContactServiceWireRecord
{
    internal ContactServiceResultRecord(ServiceRecord record) : base(record)
    {
        StatusId = ServiceWire.U16(FieldSpan(4));
        MutationOutcome = (ContactServiceMutationOutcome)FieldSpan(5)[0];
        ServerTimeUnixSeconds = ServiceWire.U64(FieldSpan(6));
        RetryAfterSeconds = ServiceWire.U32(FieldSpan(7));
        PaddingClass = (ContactServicePaddingClass)ServiceWire.U16(FieldSpan(8));
    }

    public ReadOnlyMemory<byte> NetworkId => Field(1);
    public ReadOnlyMemory<byte> OperationId => Field(2);
    public ReadOnlyMemory<byte> RequestHash => Field(3);
    public ushort StatusId { get; }
    public ContactServiceMutationOutcome MutationOutcome { get; }
    public ulong ServerTimeUnixSeconds { get; }
    public uint RetryAfterSeconds { get; }
    public ContactServicePaddingClass PaddingClass { get; }
}

public sealed class Xpu1Request : ContactServiceRequestRecord
{
    internal Xpu1Request(ServiceRecord record) : base(record) { Generation = ServiceWire.U64(FieldSpan(18)); UsageLimit = ServiceWire.U32(FieldSpan(22)); EffectiveExpiresAtUnixSeconds = ServiceWire.U64(FieldSpan(23)); }
    public ReadOnlyMemory<byte> LocatorHash => Field(16);
    public ReadOnlyMemory<byte> Xir1Hash => Field(17);
    public ulong Generation { get; }
    public ReadOnlyMemory<byte> PredecessorObjectHash => Field(19);
    public ReadOnlyMemory<byte> ObjectCiphertextHash => Field(20);
    public ReadOnlyMemory<byte> ObjectCiphertext => Field(21);
    public uint UsageLimit { get; }
    public ulong EffectiveExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> RouteClosureHash => Field(24);
    public ReadOnlyMemory<byte> ExactRouteClosure => Field(25);
    public ReadOnlyMemory<byte> ExactXpa1 => Field(26);
    public ReadOnlyMemory<byte> AuthorizedBodyHash => ServiceWire.ProjectedHash(this, "Deep/ContactResolver/V1/XPU-authorized-body", [1,2,3,4,5,6,16,17,18,19,20,21,22,23,24,25]);
}

public sealed class Xiq1Request : ContactServiceRequestRecord
{
    internal Xiq1Request(ServiceRecord record) : base(record) { RequestedGeneration = ServiceWire.U64(FieldSpan(17)); AntiSpamTokenType = (Xiq1AntiSpamTokenType)ServiceWire.U16(FieldSpan(19)); ResponsePaddingClass = (ContactServicePaddingClass)ServiceWire.U16(FieldSpan(21)); }
    public ReadOnlyMemory<byte> LocatorHash => Field(16);
    public ulong RequestedGeneration { get; }
    public ReadOnlyMemory<byte> RedemptionOperationId => Field(18);
    public Xiq1AntiSpamTokenType AntiSpamTokenType { get; }
    public ReadOnlyMemory<byte> AntiSpamToken => Field(20);
    public ContactServicePaddingClass ResponsePaddingClass { get; }
}

public sealed class Xpk1Request : ContactServiceRequestRecord
{
    internal Xpk1Request(ServiceRecord record) : base(record) { RequestedSuite = ServiceWire.U16(FieldSpan(20)); }
    public ReadOnlyMemory<byte> ServiceCapability => Field(16);
    public ReadOnlyMemory<byte> Dcb1Hash => Field(17);
    public ReadOnlyMemory<byte> Xps1Hash => Field(18);
    public ReadOnlyMemory<byte> ResponderDeviceId => Field(19);
    public ushort RequestedSuite { get; }
    public ReadOnlyMemory<byte> SenderEphemeralCommitment => Field(21);
    public ReadOnlyMemory<byte> ClaimOperationId => Field(22);
}

public sealed class Xuw1Request : ContactServiceRequestRecord
{
    internal Xuw1Request(ServiceRecord record) : base(record) { EventGeneration = ServiceWire.U64(FieldSpan(18)); EffectiveExpiresAtUnixSeconds = ServiceWire.U64(FieldSpan(22)); }
    public ReadOnlyMemory<byte> ServiceCapability => Field(16);
    public ReadOnlyMemory<byte> Xur1Hash => Field(17);
    public ulong EventGeneration { get; }
    public ReadOnlyMemory<byte> PredecessorEventHash => Field(19);
    public ReadOnlyMemory<byte> EventCiphertextHash => Field(20);
    public ReadOnlyMemory<byte> SealedUpdate => ServiceWire.DecodeLp32(FieldSpan(21)).ToArray();
    public ulong EffectiveExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> EventHash => ServiceWire.ComputeUpdateEventHash(this);
}

public sealed class Xuq1Request : ContactServiceRequestRecord
{
    internal Xuq1Request(ServiceRecord record) : base(record) { AfterGeneration = ServiceWire.U64(FieldSpan(18)); MaxEvents = ServiceWire.U16(FieldSpan(19)); ResponsePaddingClass = (ContactServicePaddingClass)ServiceWire.U16(FieldSpan(20)); }
    public ReadOnlyMemory<byte> ServiceCapability => Field(16);
    public ReadOnlyMemory<byte> Xur1Hash => Field(17);
    public ulong AfterGeneration { get; }
    public ushort MaxEvents { get; }
    public ContactServicePaddingClass ResponsePaddingClass { get; }
}

public sealed class Xpo1Result : ContactServiceResultRecord { internal Xpo1Result(ServiceRecord record) : base(record) { Status = (Xpo1Status)StatusId; } public Xpo1Status Status { get; } }
public sealed class Xis1Result : ContactServiceResultRecord { internal Xis1Result(ServiceRecord record) : base(record) { Status = (Xis1Status)StatusId; } public Xis1Status Status { get; } }
public sealed class Xpc1Result : ContactServiceResultRecord { internal Xpc1Result(ServiceRecord record) : base(record) { Status = (Xpc1Status)StatusId; } public Xpc1Status Status { get; } }
public sealed class Xus1Result : ContactServiceResultRecord { internal Xus1Result(ServiceRecord record) : base(record) { OperationKind = (Xus1OperationKind)FieldSpan(16)[0]; Status = (Xus1Status)StatusId; } public Xus1OperationKind OperationKind { get; } public Xus1Status Status { get; } }

public static class Xpu1Codec
{
    private static readonly ushort[] Tags = [1,2,3,4,5,6,16,17,18,19,20,21,22,23,24,25,26];
    public static byte[] ComputeAuthorizedBodyHash(
        ReadOnlySpan<byte> networkId16, ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> viewHash32, ReadOnlySpan<byte> placementHash32,
        ulong issuedAt, ulong expiresAt, ReadOnlySpan<byte> locatorHash32,
        ReadOnlySpan<byte> xir1Hash32, ulong generation,
        ReadOnlySpan<byte> predecessorObjectHash32, ReadOnlySpan<byte> objectCiphertext,
        uint usageLimit, ulong effectiveExpiresAt,
        ReadOnlySpan<byte> exactRouteClosure)
    {
        var fields=ServiceWire.RequestFields(networkId16,operationId32,viewHash32,placementHash32,issuedAt,expiresAt,
            [(16,locatorHash32.ToArray()),(17,xir1Hash32.ToArray()),(18,ServiceWire.Be(generation)),(19,predecessorObjectHash32.ToArray()),
             (20,SHA256.HashData(objectCiphertext)),(21,objectCiphertext.ToArray()),(22,ServiceWire.Be(usageLimit)),(23,ServiceWire.Be(effectiveExpiresAt)),
             (24,SHA256.HashData(exactRouteClosure)),(25,exactRouteClosure.ToArray())]);
        return ServiceWire.HashProjection(ProtocolMagic.XPU1,"Deep/ContactResolver/V1/XPU-authorized-body",fields);
    }

    public static byte[] Encode(
        ReadOnlySpan<byte> networkId16, ReadOnlySpan<byte> operationId32,
        ReadOnlySpan<byte> viewHash32, ReadOnlySpan<byte> placementHash32,
        ulong issuedAt, ulong expiresAt, ReadOnlySpan<byte> locatorHash32,
        ReadOnlySpan<byte> xir1Hash32, ulong generation,
        ReadOnlySpan<byte> predecessorObjectHash32, ReadOnlySpan<byte> objectCiphertext,
        uint usageLimit, ulong effectiveExpiresAt, ReadOnlySpan<byte> exactRouteClosure,
        ReadOnlySpan<byte> exactXpa1)
    {
        var bytes=ServiceWire.EncodeRequest(ProtocolMagic.XPU1,networkId16,operationId32,viewHash32,placementHash32,issuedAt,expiresAt,
            [(16,locatorHash32.ToArray()),(17,xir1Hash32.ToArray()),(18,ServiceWire.Be(generation)),(19,predecessorObjectHash32.ToArray()),
             (20,SHA256.HashData(objectCiphertext)),(21,objectCiphertext.ToArray()),(22,ServiceWire.Be(usageLimit)),(23,ServiceWire.Be(effectiveExpiresAt)),
             (24,SHA256.HashData(exactRouteClosure)),(25,exactRouteClosure.ToArray()),(26,exactXpa1.ToArray())]);
        _=Decode(bytes);return bytes;
    }
    public static Xpu1Request Decode(ReadOnlySpan<byte> encoded)
    {
        var record = ServiceWire.ParseRequest(encoded, ProtocolMagic.XPU1, Tags);
        ServiceWire.ValidateRequestCommon(record);
        ServiceWire.ExactLengths(record, (16,32),(17,32),(18,8),(19,32),(20,32),(22,4),(23,8),(24,32));
        ServiceWire.LengthRange(record, 21, 40, 65_575);
        ServiceWire.LengthRange(record, 25, ContactRouteClosureCodec.MinimumEncodedBytes, ContactRouteClosureCodec.MaximumEncodedBytes);
        ServiceWire.LengthRange(record, 26, 12, 65_535);
        ServiceWire.NonZero(record, 16,17,20,24);
        ServiceWire.GenerationPredecessor(record, 18,19);
        if (ServiceWire.U32(record[22]) > 1) ServiceWire.Reject(ContactValidationStage.Scalar, "UsageLimitOutOfRange");
        if (ServiceWire.U64(record[23]) <= ServiceWire.U64(record[5])) ServiceWire.Reject(ContactValidationStage.Scalar, "InvalidEffectiveExpiry");
        var cipherHash = SHA256.HashData(record[21]);
        if (!CryptographicOperations.FixedTimeEquals(cipherHash, record[20])) ServiceWire.Reject(ContactValidationStage.Derived, "ObjectCiphertextHashMismatch");
        var routeHash = SHA256.HashData(record[25]);
        if (!CryptographicOperations.FixedTimeEquals(routeHash, record[24])) ServiceWire.Reject(ContactValidationStage.Derived, "RouteClosureHashMismatch");
        _ = ContactRouteClosureCodec.Decode(record[25]);
        var model = new Xpu1Request(record);
        _ = ServiceWire.ParseValidatedXpa1(model);
        return model;
    }
}

public static class Xiq1Codec
{
    private static readonly ushort[] Tags = [1,2,3,4,5,6,16,17,18,19,20,21];
    public static byte[] Encode(ReadOnlySpan<byte> networkId16,ReadOnlySpan<byte> operationId32,ReadOnlySpan<byte> viewHash32,ReadOnlySpan<byte> placementHash32,ulong issuedAt,ulong expiresAt,ReadOnlySpan<byte> locatorHash32,ulong requestedGeneration,Xiq1AntiSpamTokenType antiSpamTokenType,ReadOnlySpan<byte> antiSpamToken,ContactServicePaddingClass responsePaddingClass)
    {var bytes=ServiceWire.EncodeRequest(ProtocolMagic.XIQ1,networkId16,operationId32,viewHash32,placementHash32,issuedAt,expiresAt,[(16,locatorHash32.ToArray()),(17,ServiceWire.Be(requestedGeneration)),(18,operationId32.ToArray()),(19,ServiceWire.Be((ushort)antiSpamTokenType)),(20,antiSpamToken.ToArray()),(21,ServiceWire.Be((ushort)responsePaddingClass))]);_=Decode(bytes);return bytes;}
    public static Xiq1Request Decode(ReadOnlySpan<byte> encoded)
    {
        var record = ServiceWire.ParseRequest(encoded, ProtocolMagic.XIQ1, Tags);
        ServiceWire.ValidateRequestCommon(record);
        ServiceWire.ExactLengths(record,(16,32),(17,8),(18,32),(19,2),(21,2));
        ServiceWire.LengthRange(record,20,0,4096);
        ServiceWire.NonZero(record,16);
        if (!record[2].SequenceEqual(record[18])) ServiceWire.Reject(ContactValidationStage.Scalar,"RedemptionOperationIdMismatch");
        if(ServiceWire.U16(record[19])!=0||record[20].Length!=0)ServiceWire.Reject(ContactValidationStage.Scalar,"UnknownAntiSpamTokenType");
        ServiceWire.ValidatePadding(ServiceWire.U16(record[21]), false);
        return new Xiq1Request(record);
    }
}

public static class Xpk1Codec
{
    private static readonly ushort[] Tags = [1,2,3,4,5,6,16,17,18,19,20,21,22];
    public static byte[] Encode(ReadOnlySpan<byte> networkId16,ReadOnlySpan<byte> operationId32,ReadOnlySpan<byte> viewHash32,ReadOnlySpan<byte> placementHash32,ulong issuedAt,ulong expiresAt,ReadOnlySpan<byte> serviceCapability32,ReadOnlySpan<byte> dcb1Hash32,ReadOnlySpan<byte> xps1Hash32,ReadOnlySpan<byte> responderDeviceId32,ReadOnlySpan<byte> senderEphemeralCommitment32)
    {var bytes=ServiceWire.EncodeRequest(ProtocolMagic.XPK1,networkId16,operationId32,viewHash32,placementHash32,issuedAt,expiresAt,[(16,serviceCapability32.ToArray()),(17,dcb1Hash32.ToArray()),(18,xps1Hash32.ToArray()),(19,responderDeviceId32.ToArray()),(20,ServiceWire.Be((ushort)0x0201)),(21,senderEphemeralCommitment32.ToArray()),(22,operationId32.ToArray())]);_=Decode(bytes);return bytes;}
    public static Xpk1Request Decode(ReadOnlySpan<byte> encoded)
    {
        var record=ServiceWire.ParseRequest(encoded,ProtocolMagic.XPK1,Tags);
        ServiceWire.ValidateRequestCommon(record);
        ServiceWire.ExactLengths(record,(16,32),(17,32),(18,32),(19,32),(20,2),(21,32),(22,32));
        ServiceWire.NonZero(record,16,17,18,19,21);
        if (ServiceWire.U16(record[20]) != 0x0201) ServiceWire.Reject(ContactValidationStage.Scalar,"UnknownRequestedSuite");
        if (!record[2].SequenceEqual(record[22])) ServiceWire.Reject(ContactValidationStage.Scalar,"ClaimOperationIdMismatch");
        return new Xpk1Request(record);
    }
}

public static class Xuw1Codec
{
    private static readonly ushort[] Tags=[1,2,3,4,5,6,16,17,18,19,20,21,22];
    public static byte[] ComputeEventHash(ulong eventGeneration,ReadOnlySpan<byte> predecessorEventHash32,ReadOnlySpan<byte> eventCiphertextHash32,ulong effectiveExpiresAt,ReadOnlySpan<byte> sealedUpdate)
        =>ServiceWire.ComputeUpdateEventHash(eventGeneration,predecessorEventHash32,eventCiphertextHash32,effectiveExpiresAt,ServiceWire.Lp32(sealedUpdate));
    public static byte[] Encode(ReadOnlySpan<byte> networkId16,ReadOnlySpan<byte> operationId32,ReadOnlySpan<byte> viewHash32,ReadOnlySpan<byte> placementHash32,ulong issuedAt,ulong expiresAt,ReadOnlySpan<byte> serviceCapability32,ReadOnlySpan<byte> xur1Hash32,ulong eventGeneration,ReadOnlySpan<byte> predecessorEventHash32,ReadOnlySpan<byte> sealedUpdate,ulong effectiveExpiresAt)
    {var lp=ServiceWire.Lp32(sealedUpdate);var bytes=ServiceWire.EncodeRequest(ProtocolMagic.XUW1,networkId16,operationId32,viewHash32,placementHash32,issuedAt,expiresAt,[(16,serviceCapability32.ToArray()),(17,xur1Hash32.ToArray()),(18,ServiceWire.Be(eventGeneration)),(19,predecessorEventHash32.ToArray()),(20,SHA256.HashData(sealedUpdate)),(21,lp),(22,ServiceWire.Be(effectiveExpiresAt))]);_=Decode(bytes);return bytes;}
    public static Xuw1Request Decode(ReadOnlySpan<byte> encoded)
    {
        var record=ServiceWire.ParseRequest(encoded,ProtocolMagic.XUW1,Tags);
        ServiceWire.ValidateRequestCommon(record);
        ServiceWire.ExactLengths(record,(16,32),(17,32),(18,8),(19,32),(20,32),(22,8));
        ServiceWire.LengthRange(record,21,5,32772);
        ServiceWire.NonZero(record,16,17,20);
        ServiceWire.GenerationPredecessor(record,18,19);
        var sealedUpdate=ServiceWire.DecodeLp32(record[21]);
        if (sealedUpdate.Length is < 1 or > 32768) ServiceWire.Reject(ContactValidationStage.Bounds,"SealedUpdateLengthOutOfRange");
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(sealedUpdate),record[20])) ServiceWire.Reject(ContactValidationStage.Derived,"EventCiphertextHashMismatch");
        if (ServiceWire.U64(record[22]) <= ServiceWire.U64(record[5])) ServiceWire.Reject(ContactValidationStage.Scalar,"InvalidEffectiveExpiry");
        return new Xuw1Request(record);
    }
}

public static class Xuq1Codec
{
    private static readonly ushort[] Tags=[1,2,3,4,5,6,16,17,18,19,20];
    public static byte[] Encode(ReadOnlySpan<byte> networkId16,ReadOnlySpan<byte> operationId32,ReadOnlySpan<byte> viewHash32,ReadOnlySpan<byte> placementHash32,ulong issuedAt,ulong expiresAt,ReadOnlySpan<byte> serviceCapability32,ReadOnlySpan<byte> xur1Hash32,ulong afterGeneration,ushort maxEvents,ContactServicePaddingClass responsePaddingClass)
    {var bytes=ServiceWire.EncodeRequest(ProtocolMagic.XUQ1,networkId16,operationId32,viewHash32,placementHash32,issuedAt,expiresAt,[(16,serviceCapability32.ToArray()),(17,xur1Hash32.ToArray()),(18,ServiceWire.Be(afterGeneration)),(19,ServiceWire.Be(maxEvents)),(20,ServiceWire.Be((ushort)responsePaddingClass))]);_=Decode(bytes);return bytes;}
    public static Xuq1Request Decode(ReadOnlySpan<byte> encoded)
    {
        var record=ServiceWire.ParseRequest(encoded,ProtocolMagic.XUQ1,Tags);
        ServiceWire.ValidateRequestCommon(record);
        ServiceWire.ExactLengths(record,(16,32),(17,32),(18,8),(19,2),(20,2));
        ServiceWire.NonZero(record,16,17);
        var max=ServiceWire.U16(record[19]); if(max is <1 or >64) ServiceWire.Reject(ContactValidationStage.Scalar,"MaxEventsOutOfRange");
        ServiceWire.ValidatePadding(ServiceWire.U16(record[20]),true);
        return new Xuq1Request(record);
    }
}

public static class Xpo1Codec
{
    public static byte[] Encode(ReadOnlySpan<byte> exactRequest,Xpo1Status status,ContactServiceMutationOutcome outcome,ulong serverTime,uint retryAfter,ContactServicePaddingClass padding,IReadOnlyList<ReadOnlyMemory<byte>> payload){var b=ServiceWire.EncodeResult(ProtocolMagic.XPO1,exactRequest,(ushort)status,outcome,serverTime,retryAfter,padding,payload,false);_=Decode(b,exactRequest);return b;}
    public static Xpo1Result Decode(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> exactRequest) { var r=ServiceWire.ParseResult(encoded,ProtocolMagic.XPO1,false); ServiceWire.ValidateResultCommon(r,exactRequest,ProtocolMagic.XPU1); ServiceWire.ValidateXpo(r); return new Xpo1Result(r); }
}
public static class Xis1Codec
{
    public static byte[] Encode(ReadOnlySpan<byte> exactRequest,Xis1Status status,ContactServiceMutationOutcome outcome,ulong serverTime,uint retryAfter,ContactServicePaddingClass padding,IReadOnlyList<ReadOnlyMemory<byte>> payload){var b=ServiceWire.EncodeResult(ProtocolMagic.XIS1,exactRequest,(ushort)status,outcome,serverTime,retryAfter,padding,payload,false);_=Decode(b,exactRequest);return b;}
    public static Xis1Result Decode(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> exactRequest) { var r=ServiceWire.ParseResult(encoded,ProtocolMagic.XIS1,false); ServiceWire.ValidateResultCommon(r,exactRequest,ProtocolMagic.XIQ1); ServiceWire.ValidateXis(r); return new Xis1Result(r); }
}
public static class Xpc1Codec
{
    public static byte[] ComputeClaimReceiptHash(ReadOnlySpan<byte> requestHash32,ReadOnlySpan<byte> exactDpk2,ReadOnlySpan<byte> exactXpi1,ReadOnlySpan<byte> oneTimePreKeyId32,ulong claimCommitGeneration,ushort lastResortUseCounter)
        =>ServiceWire.ComputeClaimReceiptHash(requestHash32,exactDpk2,exactXpi1,oneTimePreKeyId32,claimCommitGeneration,lastResortUseCounter);
    public static byte[] Encode(ReadOnlySpan<byte> exactRequest,Xpc1Status status,ContactServiceMutationOutcome outcome,ulong serverTime,uint retryAfter,ContactServicePaddingClass padding,IReadOnlyList<ReadOnlyMemory<byte>> payload){var b=ServiceWire.EncodeResult(ProtocolMagic.XPC1,exactRequest,(ushort)status,outcome,serverTime,retryAfter,padding,payload,false);_=Decode(b,exactRequest);return b;}
    public static Xpc1Result Decode(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> exactRequest) { var r=ServiceWire.ParseResult(encoded,ProtocolMagic.XPC1,false); ServiceWire.ValidateResultCommon(r,exactRequest,ProtocolMagic.XPK1); ServiceWire.ValidateXpc(r); return new Xpc1Result(r); }
}
public static class Xus1Codec
{
    public static byte[] Encode(ReadOnlySpan<byte> exactRequest,Xus1OperationKind operationKind,Xus1Status status,ContactServiceMutationOutcome outcome,ulong serverTime,uint retryAfter,ContactServicePaddingClass padding,IReadOnlyList<ReadOnlyMemory<byte>> payload){var all=new List<ReadOnlyMemory<byte>>(payload.Count+1){new byte[]{(byte)operationKind}};all.AddRange(payload);var b=ServiceWire.EncodeResult(ProtocolMagic.XUS1,exactRequest,(ushort)status,outcome,serverTime,retryAfter,padding,all,true);_=Decode(b,exactRequest);return b;}
    public static Xus1Result Decode(ReadOnlySpan<byte> encoded, ReadOnlySpan<byte> exactRequest) { var r=ServiceWire.ParseResult(encoded,ProtocolMagic.XUS1,true); ServiceWire.ValidateResultCommon(r,exactRequest,ServiceWire.ReadMagic(exactRequest)); ServiceWire.ValidateXus(r,exactRequest); return new Xus1Result(r); }
}

internal sealed class ServiceRecord(string magic, byte[] canonical, byte[] wire, Dictionary<ushort,byte[]> fields)
{
    internal string Magic { get; }=magic;
    internal byte[] Canonical { get; }=canonical;
    internal byte[] Wire { get; }=wire;
    internal Dictionary<ushort,byte[]> Fields { get; }=fields;
    internal ReadOnlySpan<byte> this[ushort tag]=>Fields[tag];
}

internal static class ServiceWire
{
    private const int Header=12, FieldHeader=8, MaxCanonical=65_535, MaxXpu1Canonical=92_992, MaxXis1Canonical=89_388;
    private static readonly int[] Buckets=[256,1024,4096,16384,65536,131072];
    internal static ServiceRecord ParseRequest(ReadOnlySpan<byte> bytes,string magic,ushort[] tags)=>Parse(bytes,magic,tags,false,false);
    internal static ServiceRecord ParseResult(ReadOnlySpan<byte> bytes,string magic,bool class4)=>Parse(bytes,magic,null,true,class4);

    internal static byte[] EncodeRequest(string magic,ReadOnlySpan<byte> network,ReadOnlySpan<byte> operation,ReadOnlySpan<byte> view,ReadOnlySpan<byte> placement,ulong issued,ulong expires,IReadOnlyList<(ushort Tag,byte[] Value)> payload)
        =>EncodeRecord(magic,RequestFields(network,operation,view,placement,issued,expires,payload));

    internal static List<(ushort,byte[])> RequestFields(ReadOnlySpan<byte> network,ReadOnlySpan<byte> operation,ReadOnlySpan<byte> view,ReadOnlySpan<byte> placement,ulong issued,ulong expires,IReadOnlyList<(ushort Tag,byte[] Value)> payload)
    {var fields=new List<(ushort,byte[])>{(1,network.ToArray()),(2,operation.ToArray()),(3,view.ToArray()),(4,placement.ToArray()),(5,Be(issued)),(6,Be(expires))};fields.AddRange(payload);return fields;}

    internal static byte[] EncodeResult(string magic,ReadOnlySpan<byte> exactRequest,ushort status,ContactServiceMutationOutcome outcome,ulong serverTime,uint retry,ContactServicePaddingClass padding,IReadOnlyList<ReadOnlyMemory<byte>> payload,bool class4)
    {
        ArgumentNullException.ThrowIfNull(payload);var requestMagic=magic switch{ProtocolMagic.XPO1=>ProtocolMagic.XPU1,ProtocolMagic.XIS1=>ProtocolMagic.XIQ1,ProtocolMagic.XPC1=>ProtocolMagic.XPK1,ProtocolMagic.XUS1=>ReadMagic(exactRequest),_=>throw new ArgumentOutOfRangeException(nameof(magic))};var request=ParseRequestEnvelope(exactRequest,requestMagic);
        var fields=new List<(ushort,byte[])>{(1,request[1]),(2,request[2]),(3,ContactCodec.Sha256Domain("Deep/ContactResolver/V1/request",exactRequest)),(4,Be(status)),(5,new byte[]{(byte)outcome}),(6,Be(serverTime)),(7,Be(retry)),(8,Be((ushort)padding))};
        for(var i=0;i<payload.Count;i++)fields.Add(((ushort)(16+i),payload[i].ToArray()));var canonical=EncodeRecord(magic,fields);ValidatePadding((ushort)padding,class4,magic==ProtocolMagic.XIS1);var size=Buckets[(ushort)padding];if(canonical.Length>size)Reject(ContactValidationStage.Length,"ResultDoesNotFitPaddingClass");var wire=new byte[size];canonical.CopyTo(wire,0);return wire;
    }

    private static byte[] EncodeRecord(string magic,IReadOnlyList<(ushort Tag,byte[] Value)> fields)
    {if(fields.Count==0||fields.Count>ushort.MaxValue)throw new ArgumentOutOfRangeException(nameof(fields));var total=Header;ushort prior=0;foreach(var f in fields){if(f.Tag<=prior)throw new ArgumentException("Fields are not in canonical order.",nameof(fields));total=checked(total+FieldHeader+f.Value.Length);prior=f.Tag;}if(total>CanonicalLimit(magic))Reject(ContactValidationStage.Length,"CanonicalRecordTooLarge");var b=new byte[total];Encoding.ASCII.GetBytes(magic).CopyTo(b,0);BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(4),1);BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(6),0x0201);BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(8),checked((ushort)fields.Count));var o=Header;foreach(var f in fields){BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(o),f.Tag);BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(o+4),checked((uint)f.Value.Length));o+=8;f.Value.CopyTo(b,o);o+=f.Value.Length;}return b;}

    internal static byte[] Be(ushort value){var b=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(b,value);return b;}
    internal static byte[] Be(uint value){var b=new byte[4];BinaryPrimitives.WriteUInt32BigEndian(b,value);return b;}
    internal static byte[] Be(ulong value){var b=new byte[8];BinaryPrimitives.WriteUInt64BigEndian(b,value);return b;}
    internal static byte[] Lp32(ReadOnlySpan<byte> value){var b=new byte[4+value.Length];BinaryPrimitives.WriteUInt32BigEndian(b,checked((uint)value.Length));value.CopyTo(b.AsSpan(4));return b;}

    private static ServiceRecord Parse(ReadOnlySpan<byte> bytes,string magic,ushort[]? exactTags,bool padded,bool class4)
    {
        var maximum=padded?(magic==ProtocolMagic.XIS1?131_072:class4?65_536:MaxCanonical):CanonicalLimit(magic);
        if(bytes.Length<Header||bytes.Length>maximum) Reject(ContactValidationStage.Length,"RecordLengthOutOfRange");
        if(!bytes[..4].SequenceEqual(Encoding.ASCII.GetBytes(magic))) Reject(ContactValidationStage.Header,"WrongRecordType");
        if(U16(bytes[4..6])!=1) Reject(ContactValidationStage.Header,"UnsupportedVersion");
        if(U16(bytes[6..8])!=0x0201) Reject(ContactValidationStage.Header,"UnknownSuite");
        var count=U16(bytes[8..10]); if(count==0) Reject(ContactValidationStage.Header,"WrongFieldCount");
        if(U16(bytes[10..12])!=0) Reject(ContactValidationStage.Header,"NonCanonicalReserved");
        if(exactTags is not null&&count!=exactTags.Length) Reject(ContactValidationStage.Header,"WrongFieldCount");
        var offset=Header; ushort previous=0;var tags=new ushort[count];var offsets=new int[count];var lengths=new int[count];
        for(var i=0;i<count;i++)
        {
            if(bytes.Length-offset<FieldHeader) Reject(ContactValidationStage.FieldScan,"TruncatedFieldHeader");
            var tag=U16(bytes.Slice(offset,2)); if(tag<=previous) Reject(ContactValidationStage.FieldScan,"NonCanonicalTag");
            if(exactTags is not null&&tag!=exactTags[i]) Reject(ContactValidationStage.FieldScan,"UnknownOrMissingTag");
            if(U16(bytes.Slice(offset+2,2))!=0) Reject(ContactValidationStage.FieldScan,"NonCanonicalReserved");
            var length=BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(offset+4,4)); offset+=FieldHeader;
            if(length>int.MaxValue||length>bytes.Length-offset) Reject(ContactValidationStage.Bounds,"TruncatedField");
            tags[i]=tag;offsets[i]=offset;lengths[i]=(int)length;offset+=(int)length;previous=tag;
        }
        var canonicalEnd=offset;
        if(canonicalEnd>CanonicalLimit(magic)) Reject(ContactValidationStage.Length,"CanonicalRecordTooLarge");
        if(!padded&&canonicalEnd!=bytes.Length) Reject(ContactValidationStage.Bounds,"TrailingBytes");
        if(padded)
        {
            var paddingIndex=Array.IndexOf(tags,(ushort)8);if(paddingIndex<0||lengths[paddingIndex]!=2)Reject(ContactValidationStage.Bounds,"MissingPaddingClass");
            var cls=U16(bytes.Slice(offsets[paddingIndex],2)); ValidatePadding(cls,class4,magic==ProtocolMagic.XIS1);
            if(bytes.Length!=Buckets[cls]||canonicalEnd>bytes.Length) Reject(ContactValidationStage.Bounds,"NonCanonicalPaddingLength");
            foreach(var b in bytes[canonicalEnd..]) if(b!=0) Reject(ContactValidationStage.Bounds,"NonZeroPadding");
        }
        var fields=new Dictionary<ushort,byte[]>(count);for(var i=0;i<count;i++)fields.Add(tags[i],bytes.Slice(offsets[i],lengths[i]).ToArray());
        return new ServiceRecord(magic,bytes[..canonicalEnd].ToArray(),bytes.ToArray(),fields);
    }

    internal static string ReadMagic(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length<4) Reject(ContactValidationStage.Header,"TruncatedRequest");
        var magic=Encoding.ASCII.GetString(bytes[..4]);
        if(magic is not (ProtocolMagic.XUW1 or ProtocolMagic.XUQ1)) Reject(ContactValidationStage.Header,"WrongRequestType");
        return magic;
    }

    internal static void ValidateRequestCommon(ServiceRecord r)
    {
        ExactLengths(r,(1,16),(2,32),(3,32),(4,32),(5,8),(6,8)); NonZero(r,1,2,3,4);
        if(U64(r[5])>=U64(r[6])) Reject(ContactValidationStage.Scalar,"InvalidRequestTimeWindow");
    }

    internal static void ValidateResultCommon(ServiceRecord r,ReadOnlySpan<byte> request,string expectedMagic)
    {
        ExactLengths(r,(1,16),(2,32),(3,32),(4,2),(5,1),(6,8),(7,4),(8,2)); NonZero(r,1,2,3);
        var parsed=ParseRequestEnvelope(request,expectedMagic);
        switch(expectedMagic){case ProtocolMagic.XPU1:_=Xpu1Codec.Decode(request);break;case ProtocolMagic.XIQ1:_=Xiq1Codec.Decode(request);break;case ProtocolMagic.XPK1:_=Xpk1Codec.Decode(request);break;}
        if(!r[1].SequenceEqual(parsed[1])||!r[2].SequenceEqual(parsed[2])) Reject(ContactValidationStage.Scalar,"ResultRequestIdentityMismatch");
        var hash=ContactCodec.Sha256Domain("Deep/ContactResolver/V1/request",request);
        if(!CryptographicOperations.FixedTimeEquals(hash,r[3])) Reject(ContactValidationStage.Derived,"RequestHashMismatch");
        if(r[5][0]>2) Reject(ContactValidationStage.Scalar,"UnknownMutationOutcome");
        ValidatePadding(U16(r[8]),r.Magic==ProtocolMagic.XUS1,r.Magic==ProtocolMagic.XIS1);
        if(r.Magic is not (ProtocolMagic.XUS1 or ProtocolMagic.XIS1)&&U16(r[8])!=SmallestPaddingClass(r.Canonical.Length,false)) Reject(ContactValidationStage.Scalar,"NonCanonicalPaddingClass");
    }

    private static Dictionary<ushort,byte[]> ParseRequestEnvelope(ReadOnlySpan<byte> bytes,string magic)
    {
        var record=Parse(bytes,magic,null,false,false);if(!record.Fields.ContainsKey(1)||!record.Fields.ContainsKey(2))Reject(ContactValidationStage.Bounds,"InvalidExactRequest");return record.Fields;
    }

    internal static void ValidateXpo(ServiceRecord r)
    {
        var s=ClosedStatus<Xpo1Status>(r); var o=(ContactServiceMutationOutcome)r[5][0]; var retry=U32(r[7]);
        switch(s){case Xpo1Status.Committed:case Xpo1Status.ExactReplay: Shape(r,19,(16,8),(17,32),(18,8),(19,193)); Require(o==ContactServiceMutationOutcome.DurablyCommitted&&retry==0,"InvalidResultMatrix"); Receipts(r[19]); NonZero(r,17); break; case Xpo1Status.StaleView:case Xpo1Status.Conflict: Shape(r,16,(16,32)); Require(o==0&&retry==0,"InvalidResultMatrix"); NonZero(r,16); break; case Xpo1Status.RateLimited: Shape(r,8); Require(o==0&&retry>0,"InvalidResultMatrix"); break; case Xpo1Status.OutcomeUnknown: Shape(r,8); Require(o==ContactServiceMutationOutcome.OutcomeUnknown&&retry>0,"InvalidResultMatrix"); break; default: Shape(r,8); Require(o==0&&retry==0,"InvalidResultMatrix"); break;}
    }

    internal static void ValidateXis(ServiceRecord r)
    {
        var s=ClosedStatus<Xis1Status>(r);var o=(ContactServiceMutationOutcome)r[5][0];var retry=U32(r[7]);
        switch(s){case Xis1Status.Success: if(r.Fields.Count==15){Shape(r,22,(16,8),(17,8),(18,32),(19,-1),(20,32),(21,-1),(22,193));Require(o==0&&retry==0,"InvalidResultMatrix");Receipts(r[22]);}else{Shape(r,23,(16,8),(17,8),(18,32),(19,-1),(20,32),(21,-1),(22,8),(23,193));Require(o==ContactServiceMutationOutcome.DurablyCommitted&&retry==0,"InvalidResultMatrix");Receipts(r[23]);}LengthRange(r,19,40,65_575);ValidateRouteClosure(r);NonZero(r,18,20);if(!CryptographicOperations.FixedTimeEquals(SHA256.HashData(r[19]),r[18]))Reject(ContactValidationStage.Derived,"ObjectCiphertextHashMismatch");if(!CryptographicOperations.FixedTimeEquals(SHA256.HashData(r[21]),r[20]))Reject(ContactValidationStage.Derived,"RouteClosureHashMismatch");break;case Xis1Status.StaleView:case Xis1Status.Conflict:Shape(r,16,(16,32));Require(o==0&&retry==0,"InvalidResultMatrix");NonZero(r,16);break;case Xis1Status.RateLimited:Shape(r,8);Require(o==0&&retry>0,"InvalidResultMatrix");break;case Xis1Status.OutcomeUnknown:Shape(r,8);Require(o==ContactServiceMutationOutcome.OutcomeUnknown&&retry>0,"InvalidResultMatrix");break;default:Shape(r,8);Require(o==0&&retry==0,"InvalidResultMatrix");break;}
        ValidateXisPadding(r,s==Xis1Status.Success);
    }

    internal static void ValidateXpc(ServiceRecord r)
    {
        var s=ClosedStatus<Xpc1Status>(r);var o=(ContactServiceMutationOutcome)r[5][0];var retry=U32(r[7]);
        switch(s){case Xpc1Status.Claimed:case Xpc1Status.Replay:Shape(r,28,(16,-1),(17,32),(18,32),(19,32),(20,38),(21,8),(22,8),(23,2),(24,8),(25,193),(26,Xpi1Codec.TotalBytes),(27,2),(28,-1));Require(o==ContactServiceMutationOutcome.DurablyCommitted&&retry==0,"InvalidResultMatrix");LengthRange(r,16,1,MaxCanonical);LengthRange(r,28,0,384);NonZero(r,18,19,20,26);Receipts(r[25]);ValidateDpk2Selection(r);ValidateXpcInventoryBinding(r);ValidateClaimReceiptHash(r);break;case Xpc1Status.StaleBundle:Shape(r,18,(16,32),(17,32),(18,32));Require(o==0&&retry==0,"InvalidResultMatrix");NonZero(r,16,17,18);break;case Xpc1Status.Conflict:Shape(r,16,(16,32));Require(o==0&&retry==0,"InvalidResultMatrix");NonZero(r,16);break;case Xpc1Status.RateLimited:Shape(r,8);Require(o==0&&retry>0,"InvalidResultMatrix");break;case Xpc1Status.OutcomeUnknown:Shape(r,8);Require(o==ContactServiceMutationOutcome.OutcomeUnknown&&retry>0,"InvalidResultMatrix");break;default:Shape(r,8);Require(o==0&&retry==0,"InvalidResultMatrix");break;}
    }

    internal static void ValidateXus(ServiceRecord r,ReadOnlySpan<byte> request)
    {
        var s=ClosedStatus<Xus1Status>(r);var k=(Xus1OperationKind)r[16][0];if(k is not (Xus1OperationKind.Write or Xus1OperationKind.Fetch))Reject(ContactValidationStage.Scalar,"UnknownOperationKind");var requestMagic=ReadMagic(request);if((k==Xus1OperationKind.Write)!=(requestMagic==ProtocolMagic.XUW1))Reject(ContactValidationStage.Scalar,"OperationKindRequestMismatch");var o=(ContactServiceMutationOutcome)r[5][0];var retry=U32(r[7]);
        switch(s){case Xus1Status.WriteCommitted:case Xus1Status.ExactReplay:Shape(r,20,(16,1),(17,8),(18,32),(19,8),(20,193));Require(k==Xus1OperationKind.Write&&o==ContactServiceMutationOutcome.DurablyCommitted&&retry==0,"InvalidResultMatrix");NonZero(r,18);Receipts(r[20]);ValidateWriteEventHash(r,request);break;case Xus1Status.Events:Shape(r,20,(16,1),(17,2),(18,-1),(19,8),(20,1));Require(k==Xus1OperationKind.Fetch&&o==0&&retry==0,"InvalidResultMatrix");ValidateEvents(r,request);break;case Xus1Status.NoChange:Shape(r,16,(16,1));Require(k==Xus1OperationKind.Fetch&&o==0&&retry==0,"InvalidResultMatrix");break;case Xus1Status.Expired:Shape(r,16,(16,1));Require(o==0&&retry==0,"InvalidResultMatrix");break;case Xus1Status.RateLimited:Shape(r,16,(16,1));Require(o==0&&retry>0,"InvalidResultMatrix");break;case Xus1Status.StaleGeneration:Shape(r,18,(16,1),(17,8),(18,32));Require(o==0&&retry==0,"InvalidResultMatrix");NonZero(r,18);break;case Xus1Status.Conflict:Shape(r,17,(16,1),(17,32));Require(o==0&&retry==0,"InvalidResultMatrix");NonZero(r,17);break;case Xus1Status.OutcomeUnknown:Shape(r,16,(16,1));Require(k==Xus1OperationKind.Write&&o==ContactServiceMutationOutcome.OutcomeUnknown&&retry>0,"InvalidResultMatrix");break;case Xus1Status.SizeFailure:Shape(r,18,(16,1),(17,4),(18,4));Require(k==Xus1OperationKind.Write&&o==0&&retry==0&&U32(r[17])==32768&&U32(r[18])>32768,"InvalidResultMatrix");break;case Xus1Status.RecordTooLarge:Shape(r,18,(16,1),(17,2),(18,4));Require(k==Xus1OperationKind.Fetch&&o==0&&retry==0,"InvalidResultMatrix");ValidatePadding(U16(r[17]),true);if(U32(r[18])<85||U32(r[18])>32852)Reject(ContactValidationStage.Scalar,"NextRecordBytesOutOfRange");break;default:Reject(ContactValidationStage.Scalar,"UnknownStatus");break;}
        if(k==Xus1OperationKind.Fetch){var req=ParseRequest(request,ProtocolMagic.XUQ1,[1,2,3,4,5,6,16,17,18,19,20]);if(U16(r[8])!=U16(req[20]))Reject(ContactValidationStage.Scalar,"FetchPaddingClassMismatch");if(s==Xus1Status.RecordTooLarge&&U16(r[17])<=U16(req[20]))Reject(ContactValidationStage.Scalar,"RequiredPaddingClassNotLarger");}
        else if(U16(r[8])!=SmallestPaddingClass(r.Canonical.Length,true))Reject(ContactValidationStage.Scalar,"NonCanonicalPaddingClass");
    }

    private static void ValidateXisPadding(ServiceRecord r,bool success)
    {
        var actual=U16(r[8]);
        var expected=success&&r.Canonical.Length>16_384?(ushort)5:SmallestPaddingClass(r.Canonical.Length,false);
        if(actual!=expected)Reject(ContactValidationStage.Scalar,"NonCanonicalPaddingClass");
    }

    private static void ValidateRouteClosure(ServiceRecord r)
    {
        LengthRange(r,21,4_143,23_295);var bytes=r[21];if(bytes[0]!=6)Reject(ContactValidationStage.Scalar,"InvalidRouteClosureCount");
        var magics=new[]{ProtocolMagic.XRR1,ProtocolMagic.XRA1,ProtocolMagic.XRC1,ProtocolMagic.XSS1,ProtocolMagic.PMT2,ProtocolMagic.PMS2};var records=new ContactRecord[6];var offset=1;
        for(var i=0;i<records.Length;i++){if(bytes.Length-offset<4)Reject(ContactValidationStage.Bounds,"TruncatedRouteClosure");var length=BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(offset,4));offset+=4;if(length>int.MaxValue||length>bytes.Length-offset)Reject(ContactValidationStage.Bounds,"TruncatedRouteClosure");records[i]=ContactCodec.Decode(magics[i],bytes.Slice(offset,(int)length));offset+=(int)length;}
        if(offset!=bytes.Length)Reject(ContactValidationStage.Bounds,"TrailingRouteClosureBytes");
        ContactCodec.ValidateRouteUpdateGraph(records[0],records[1],records[2],records[3],records[4],records[5]);
        if(!records[0].FieldSpan(1).SequenceEqual(r[1]))Reject(ContactValidationStage.Closure,"RouteClosureNetworkMismatch");
    }

    internal static byte[] ComputeClaimReceiptHash(ReadOnlySpan<byte> requestHash32,ReadOnlySpan<byte> exactDpk2,ReadOnlySpan<byte> exactXpi1,ReadOnlySpan<byte> oneTimePreKeyId32,ulong claimCommitGeneration,ushort lastResortUseCounter)
    {
        if(requestHash32.Length!=32||oneTimePreKeyId32.Length!=32)throw new ArgumentException("Claim receipt identifiers must be 32 bytes.");
        _=Dpk2Codec.Decode(exactDpk2);var xpi1=Xpi1Codec.Decode(exactXpi1);var dpk2Hash=ContactCodec.Sha256Domain("Deep/Messaging/V2/exact-dpk2",exactDpk2);var xpi1Hash=Xpi1Codec.ComputeHash(xpi1.CanonicalBytes.Span);var tuple=new byte[138];
        requestHash32.CopyTo(tuple);dpk2Hash.CopyTo(tuple,32);xpi1Hash.CopyTo(tuple,64);oneTimePreKeyId32.CopyTo(tuple.AsSpan(96));BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(128),claimCommitGeneration);BinaryPrimitives.WriteUInt16BigEndian(tuple.AsSpan(136),lastResortUseCounter);
        try{return ContactCodec.Sha256Domain("Deep/ContactResolver/V1/prekey-claim-receipt",tuple);}
        finally{CryptographicOperations.ZeroMemory(dpk2Hash);CryptographicOperations.ZeroMemory(xpi1Hash);CryptographicOperations.ZeroMemory(tuple);}
    }

    private static void ValidateClaimReceiptHash(ServiceRecord r)
    {
        var expected=ComputeClaimReceiptHash(r[3],r[16],r[26],r[17],U64(r[24]),U16(r[23]));
        if(!CryptographicOperations.FixedTimeEquals(expected,r[18]))Reject(ContactValidationStage.Derived,"ClaimReceiptHashMismatch");
    }

    private static void ValidateXpcInventoryBinding(ServiceRecord r)
    {
        Xpi1Record manifest;
        Dpk2Record dpk2;
        try
        {
            manifest=Xpi1Codec.Decode(r[26]);
            dpk2=Dpk2Codec.Decode(r[16]);
            PreKeyInventoryPublicationVerifier.VerifyClaimMembership(manifest,r[16],U16(r[27]),r[28]);
        }
        catch(Exception exception) when(exception is FormatException or ArgumentException or OverflowException or CryptographicException)
        {
            Reject(ContactValidationStage.Closure,"InvalidXpi1InventoryMembership");
            throw;
        }
        if(!dpk2.NetworkId.Span.SequenceEqual(manifest.NetworkId.Span)||
           !dpk2.ResponderDeviceId.Span.SequenceEqual(manifest.ResponderDeviceId.Span)||
           !dpk2.ResponderDpd1Ref.Span.SequenceEqual(manifest.ResponderDpd1Reference.Span)||
           dpk2.PrekeyServiceGeneration!=manifest.ServiceGeneration||
           dpk2.InventoryEpoch!=manifest.InventoryEpoch||
           !dpk2.DeviceDirectoryHeadHash.Span.SequenceEqual(manifest.CurrentDmd1Hash.Span)||
           dpk2.NotBefore!=manifest.IssuedAtUnixSeconds||
           dpk2.ExpiresAt!=manifest.ExpiresAtUnixSeconds||
           dpk2.IssuedAt>manifest.IssuedAtUnixSeconds)
            Reject(ContactValidationStage.Closure,"Dpk2Xpi1BindingMismatch");
    }

    internal static byte[] ComputeUpdateEventHash(Xuw1Request request)=>ComputeUpdateEventHash(request.EventGeneration,request.PredecessorEventHash.Span,request.EventCiphertextHash.Span,request.EffectiveExpiresAtUnixSeconds,request.FieldSpan(21));

    internal static byte[] ComputeUpdateEventHash(ulong generation,ReadOnlySpan<byte> predecessor32,ReadOnlySpan<byte> ciphertextHash32,ulong expiresAt,ReadOnlySpan<byte> lp32Ciphertext)
    {
        if(predecessor32.Length!=32||ciphertextHash32.Length!=32)throw new ArgumentException("Update-event hashes must be 32 bytes.");
        _=DecodeLp32(lp32Ciphertext);var tuple=new byte[checked(80+lp32Ciphertext.Length)];BinaryPrimitives.WriteUInt64BigEndian(tuple,generation);predecessor32.CopyTo(tuple.AsSpan(8));ciphertextHash32.CopyTo(tuple.AsSpan(40));BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(72),expiresAt);lp32Ciphertext.CopyTo(tuple.AsSpan(80));return ContactCodec.Sha256Domain("Deep/ContactResolver/V1/update-event",tuple);
    }

    private static void ValidateWriteEventHash(ServiceRecord result,ReadOnlySpan<byte> request)
    {
        var write=Xuw1Codec.Decode(request);if(U64(result[17])!=write.EventGeneration||!CryptographicOperations.FixedTimeEquals(result[18],write.EventHash.Span))Reject(ContactValidationStage.Derived,"UpdateEventHashMismatch");
    }

    private static void ValidateEvents(ServiceRecord r,ReadOnlySpan<byte> request)
    {
        var req=ParseRequest(request,ProtocolMagic.XUQ1,[1,2,3,4,5,6,16,17,18,19,20]);var max=U16(req[19]);var after=U64(req[18]);var count=U16(r[17]);if(count is <1 or >64||count>max)Reject(ContactValidationStage.Scalar,"EventCountOutOfRange");if(r[20][0]>1)Reject(ContactValidationStage.Scalar,"UnknownHasMore");var data=r[18];var offset=0;var prior=after;byte[]? priorHash=null;
        for(var i=0;i<count;i++){if(data.Length-offset<84)Reject(ContactValidationStage.Bounds,"TruncatedEvent");var generation=U64(data.Slice(offset,8));var predecessor=data.Slice(offset+8,32);var hash=data.Slice(offset+40,32);var expires=U64(data.Slice(offset+72,8));var n=BinaryPrimitives.ReadUInt32BigEndian(data.Slice(offset+80,4));if(n is <1 or >32768||n>data.Length-offset-84)Reject(ContactValidationStage.Bounds,"InvalidEventLength");var cipher=data.Slice(offset+84,(int)n);if(!CryptographicOperations.FixedTimeEquals(SHA256.HashData(cipher),hash))Reject(ContactValidationStage.Derived,"EventCiphertextHashMismatch");if(generation<=prior||IsZero(predecessor)||(priorHash is not null&&!CryptographicOperations.FixedTimeEquals(predecessor,priorHash)))Reject(ContactValidationStage.Scalar,"BrokenEventChain");if(expires==0)Reject(ContactValidationStage.Scalar,"InvalidEventExpiry");prior=generation;priorHash=ComputeUpdateEventHash(generation,predecessor,hash,expires,data.Slice(offset+80,4+(int)n));offset+=84+(int)n;}
        if(offset!=data.Length)Reject(ContactValidationStage.Bounds,"TrailingEventBytes");if(U64(r[19])!=prior)Reject(ContactValidationStage.Scalar,"NextGenerationMismatch");
    }

    private static void ValidateDpk2Selection(ServiceRecord r)
    {
        Dpk2Record dpk;try{dpk=Dpk2Codec.Decode(r[16]);}catch(Exception e) when(e is FormatException or ArgumentException){Reject(ContactValidationStage.Bounds,"InvalidExactDpk2");throw;}
        var zero=IsZero(r[17]);if((dpk.MlKemKind==Dpk2PrekeyKind.LastResort)!=zero)Reject(ContactValidationStage.Scalar,"PreKeySelectionMismatch");if(!zero&&!r[17].SequenceEqual(dpk.OneTimeX25519PrekeyId.Span))Reject(ContactValidationStage.Scalar,"PreKeySelectionMismatch");if(dpk.PrekeyServiceGeneration!=U64(r[21])||dpk.ExpiresAt!=U64(r[22]))Reject(ContactValidationStage.Scalar,"Dpk2ServiceBindingMismatch");if((dpk.MlKemKind==Dpk2PrekeyKind.OneTime&&U16(r[23])!=0)||(dpk.MlKemKind==Dpk2PrekeyKind.LastResort&&(U16(r[23])==0||U16(r[23])>dpk.ReuseLimit)))Reject(ContactValidationStage.Scalar,"LastResortCounterMismatch");
    }

    internal static ServiceRecord ParseValidatedXpa1(Xpu1Request request)
    {
        var r=ParseRequest(request.ExactXpa1.Span,ProtocolMagic.XPA1,Enumerable.Range(1,21).Select(i=>(ushort)i).ToArray());
        ExactLengths(r,(1,16),(2,32),(3,32),(4,32),(5,1),(6,32),(7,32),(8,32),(9,8),(10,32),(11,32),(12,4),(13,8),(14,32),(15,8),(16,8),(17,8),(18,32),(19,32),(20,1));
        LengthRange(r,21,192,3_072);NonZero(r,1,2,3,4,6,7,8,11,14,18,19);
        var count=r[20][0];if(count is <2 or >32||r[21].Length!=count*96)Reject(ContactValidationStage.Bounds,"InvalidXpaWitnessList");SortedRows(r[21],96);
        if(r[5][0] is not (1 or 2)||U32(r[12])!=(r[5][0]==1?0u:1u))Reject(ContactValidationStage.Scalar,"InvalidPublicationKindUsage");
        GenerationPredecessor(r,9,10);if(U64(r[15])>U64(r[16])||U64(r[16])>=U64(r[17]))Reject(ContactValidationStage.Scalar,"InvalidXpaTimeWindow");
        if(!r[1].SequenceEqual(request.FieldSpan(1))||!r[3].SequenceEqual(request.FieldSpan(2))||!r[4].SequenceEqual(request.FieldSpan(16))||!r[8].SequenceEqual(request.FieldSpan(17))||!r[9].SequenceEqual(request.FieldSpan(18))||!r[10].SequenceEqual(request.FieldSpan(19))||!r[11].SequenceEqual(request.FieldSpan(20))||!r[12].SequenceEqual(request.FieldSpan(22))||!r[13].SequenceEqual(request.FieldSpan(23))||!CryptographicOperations.FixedTimeEquals(r[19],request.AuthorizedBodyHash.Span))Reject(ContactValidationStage.Derived,"XpaAuthorizationMismatch");
        return r;
    }

    internal static ReadOnlyMemory<byte> ProjectedHash(ContactServiceWireRecord record,string domain,ushort[] tags)=>ContactCodec.Sha256Domain(domain,Project(record.Magic,tags.Select(t=>(t,record.Field(t).ToArray())).ToArray()));
    internal static byte[] HashProjection(string magic,string domain,IReadOnlyList<(ushort Tag,byte[] Value)> fields)=>ContactCodec.Sha256Domain(domain,Project(magic,fields.ToArray()));
    internal static byte[] Project(string magic,(ushort Tag,byte[] Value)[] fields){var size=Header+fields.Sum(f=>FieldHeader+f.Value.Length);var b=new byte[size];Encoding.ASCII.GetBytes(magic).CopyTo(b,0);BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(4),1);BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(6),0x0201);BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(8),checked((ushort)fields.Length));var o=Header;foreach(var f in fields){BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(o),f.Tag);BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(o+4),checked((uint)f.Value.Length));o+=8;f.Value.CopyTo(b,o);o+=f.Value.Length;}return b;}
    private static T ClosedStatus<T>(ServiceRecord r) where T:struct,Enum {var id=U16(r[4]);if(!Enum.IsDefined(typeof(T),id))Reject(ContactValidationStage.Scalar,"UnknownStatus");return (T)Enum.ToObject(typeof(T),id);}
    private static void Shape(ServiceRecord r,ushort last,params(ushort Tag,int Length)[] payload){var expected=8+payload.Length;if(r.Fields.Count!=expected||Enumerable.Range(1,8).Any(tag=>!r.Fields.ContainsKey((ushort)tag))||payload.Where((p,i)=>p.Tag!=16+i).Any()||(payload.Length==0?last!=8:payload[^1].Tag!=last))Reject(ContactValidationStage.FieldScan,"InvalidStatusPayloadShape");foreach(var p in payload)if(!r.Fields.ContainsKey(p.Tag)||(p.Length>=0&&r[p.Tag].Length!=p.Length))Reject(ContactValidationStage.Bounds,"InvalidFieldLength");}
    internal static void ExactLengths(ServiceRecord r,params(ushort Tag,int Length)[] pairs){foreach(var p in pairs)if(!r.Fields.TryGetValue(p.Tag,out var v)||v.Length!=p.Length)Reject(ContactValidationStage.Bounds,"InvalidFieldLength");}
    internal static void LengthRange(ServiceRecord r,ushort tag,int min,int max){if(!r.Fields.TryGetValue(tag,out var v)||v.Length<min||v.Length>max)Reject(ContactValidationStage.Bounds,"InvalidFieldLength");}
    internal static void NonZero(ServiceRecord r,params ushort[] tags){foreach(var t in tags)if(IsZero(r[t]))Reject(ContactValidationStage.Scalar,"ZeroForbidden");}
    internal static void GenerationPredecessor(ServiceRecord r,ushort generation,ushort predecessor){if(IsZero(r[predecessor])!=(U64(r[generation])==0))Reject(ContactValidationStage.Scalar,"InvalidGenesisPredecessor");}
    internal static void ValidatePadding(ushort value,bool class4,bool class5=false){if(value>(class5?5:class4?4:3))Reject(ContactValidationStage.Scalar,"UnknownPaddingClass");}
    private static int CanonicalLimit(string magic)=>magic switch{ProtocolMagic.XPU1=>MaxXpu1Canonical,ProtocolMagic.XIS1=>MaxXis1Canonical,_=>MaxCanonical};
    private static ushort SmallestPaddingClass(int canonicalLength,bool class4){for(ushort i=0;i<=(class4?4:3);i++)if(canonicalLength<=Buckets[i])return i;Reject(ContactValidationStage.Length,"NoPaddingClassFits");return 0;}
    internal static ReadOnlySpan<byte> DecodeLp32(ReadOnlySpan<byte> value){if(value.Length<4)Reject(ContactValidationStage.Bounds,"InvalidLp32");var n=BinaryPrimitives.ReadUInt32BigEndian(value[..4]);if(n>int.MaxValue||n!=value.Length-4)Reject(ContactValidationStage.Bounds,"InvalidLp32");return value[4..];}
    private static void Receipts(ReadOnlySpan<byte> value){if(value.Length!=193||value[0]!=2)Reject(ContactValidationStage.Bounds,"InvalidReplicaReceipts");var a=value.Slice(1,32);var b=value.Slice(97,32);if(IsZero(a)||IsZero(b)||a.SequenceCompareTo(b)>=0||IsZero(value.Slice(33,64))||IsZero(value.Slice(129,64)))Reject(ContactValidationStage.Scalar,"InvalidReplicaReceipts");}
    private static void SortedRows(ReadOnlySpan<byte> value,int width){ReadOnlySpan<byte> prior=default;for(var o=0;o<value.Length;o+=width){var id=value.Slice(o,32);if(IsZero(id)||(!prior.IsEmpty&&prior.SequenceCompareTo(id)>=0)||IsZero(value.Slice(o+32,width-32)))Reject(ContactValidationStage.Scalar,"InvalidSortedRows");prior=id;}}
    private static void Require(bool condition,string code){if(!condition)Reject(ContactValidationStage.Scalar,code);}
    internal static bool IsZero(ReadOnlySpan<byte> v){byte x=0;foreach(var b in v)x|=b;return x==0;}
    internal static ushort U16(ReadOnlySpan<byte> v)=>BinaryPrimitives.ReadUInt16BigEndian(v);
    internal static uint U32(ReadOnlySpan<byte> v)=>BinaryPrimitives.ReadUInt32BigEndian(v);
    internal static ulong U64(ReadOnlySpan<byte> v)=>BinaryPrimitives.ReadUInt64BigEndian(v);
    internal static void Reject(ContactValidationStage stage,string code)=>throw new ContactFormatException(stage,code);
}
