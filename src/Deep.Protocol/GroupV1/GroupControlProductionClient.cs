using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Sodium;
using Deep.Protocol.Identity;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.ApplicationCore;

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

public static class GroupControlProductionClient
{
    private static readonly int[] WriteTags = [1,2,3,4,5,6,16,17,18,19,20,21,22];
    private static readonly int[] QueryTags = [1,2,3,4,5,6,16,17,18,19,20];

    /// <summary>Authors a descriptor only with current group sequencer and independent device custody.</summary>
    public static async ValueTask<GroupControlRendezvousRecord> AuthorRendezvousAsync(VerifiedGroupTransition head,
        VerifiedDeepIdV2GroupDirectory owner, OwnedGenesisDeviceSecrets device, VerifiedOnionNetworkContext network,
        ReadOnlyMemory<byte> sealingPublicKey, OnionTrustedTimeAuthority time, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(head); network.EnsureCurrent();
        if (sealingPublicKey.Length != 32 || sealingPublicKey.Span.IndexOfAnyExcept((byte)0) < 0) throw new ArgumentException("Sealing public key required.");
        var first = await time.ReadCurrentAsync(ct).ConfigureAwait(false); owner.RequireCurrent(first);
        GroupCodec.RequireCurrentSequencer(head.Commit, owner, device.DeviceId.Bytes.Span); device.RequireCurrentGroupDevice(owner);
        if (!network.NetworkId.Span.SequenceEqual(owner.NetworkId.Span)) throw new CryptographicException("Control network mismatch.");
        var certificate = owner.RequireDevice(device.DeviceId.Bytes.Span).Certificate;
        var now = DeepIdV2GroupTransitions.Now(owner, first);
        var expiry = Math.Min(checked(now + 400UL * 86400), certificate.ExpiresAtUnixSeconds);
        ReadOnlyMemory<byte>[] fields = [owner.NetworkId, RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32),
            U64(0), new byte[32], network.Closure!.PmtArtifactReference, RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32),
            sealingPublicKey, device.DeviceId.Bytes, GroupCodec.ReferenceForAuthoring(ProtocolMagic.DPD1, certificate.CanonicalHash.Span), U64(now), U64(expiry), Enumerable.Repeat((byte)1, 64).ToArray()];
        var provisional = GroupCodec.CreateForAuthoring(ProtocolMagic.GSR1, fields);
        fields[13] = device.SignCurrentGroupControlRendezvous(provisional, owner);
        var result = (GroupControlRendezvousRecord)GroupCodec.CreateForAuthoring(ProtocolMagic.GSR1, fields);
        var final = await time.ReadCurrentAsync(ct).ConfigureAwait(false); ContactControlEndpointV2.RequireContinuous(first, final);
        owner.RequireCurrent(final); network.EnsureCurrent(); ct.ThrowIfCancellationRequested(); return result;
    }

    /// <summary>Authenticates a retained descriptor against the current owner device, network history and trusted time.</summary>
    public static async ValueTask RequireRendezvousAsync(GroupControlRendezvousRecord record, VerifiedGroupTransition head,
        VerifiedDeepIdV2GroupDirectory owner, VerifiedOnionNetworkContext network, OnionTrustedTimeAuthority time, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(record); network.EnsureCurrent();
        var reading = await time.ReadCurrentAsync(ct).ConfigureAwait(false); owner.RequireCurrent(reading);
        var device = owner.RequireDevice(record.Field(10).Span).Certificate;
        GroupCodec.RequireCurrentSequencer(head.Commit, owner, record.Field(10).Span);
        var issued = BinaryPrimitives.ReadUInt64BigEndian(record.Field(12).Span);
        var expires = BinaryPrimitives.ReadUInt64BigEndian(record.Field(13).Span);
        var upper = checked(owner.Proof.TrustedUpperUnixSeconds + reading.SampleSeconds - owner.Proof.MonotonicSample);
        if (!record.Field(1).Span.SequenceEqual(owner.NetworkId.Span) || !record.Field(1).Span.SequenceEqual(network.NetworkId.Span) ||
            !record.Field(11).Span.SequenceEqual(GroupCodec.ReferenceForAuthoring(ProtocolMagic.DPD1, device.CanonicalHash.Span)) ||
            issued < device.IssuedAtUnixSeconds || expires > device.ExpiresAtUnixSeconds || issued > upper || expires <= upper ||
            network.Closure is null || !network.Closure.RetainedPmts.Any(pmt =>
                record.Field(6).Span.SequenceEqual(Deep.Protocol.ContactV1.ContactCodec.ArtifactReference(ProtocolMagic.PMT2, pmt).CanonicalBytes.Span)) ||
            !PublicKeyAuth.VerifyDetached(record.Field(14).ToArray(), record.SignatureInput.ToArray(), device.DeviceEd25519PublicKey.ToArray()))
            throw new CryptographicException("Control descriptor has no exact current sequencer signature/history/time binding.");
        network.EnsureCurrent(); ct.ThrowIfCancellationRequested();
    }

    /// <summary>Derives a non-identifying service selector under DR-0145.</summary>
    public static byte[] Selector(GroupControlRendezvousRecord record) => XPointNetworkCrypto.Sha256Domain(
        "Deep/Group/V1/control-selector", Join(record.Field(2).ToArray(), record.Field(3).ToArray(), record.Field(7).ToArray()));

    /// <summary>Creates an original current-view write. Callers must retain exact bytes before dispatch.</summary>
    public static GroupControlWriteRecord AuthorWrite(VerifiedGroupControlPlacement placement, GroupControlRendezvousRecord descriptor,
        ReadOnlyMemory<byte> operation, ulong issued, ulong expires, ulong sequence, ReadOnlyMemory<byte> predecessor,
        ReadOnlyMemory<byte> sealedChunk, ulong effectiveExpires)
    {
        RequirePlacement(placement, descriptor); RequireWindow(placement, issued, expires);
        return (GroupControlWriteRecord)GroupCodec.CreateTaggedForAuthoring(ProtocolMagic.GSW1, WriteTags,
            [descriptor.Field(1), operation, placement.ViewHash, placement.PlacementHash, U64(issued), U64(expires), placement.Selector,
             descriptor.ArtifactHash, U64(sequence), predecessor, SHA256.HashData(sealedChunk.Span), Lp32(sealedChunk.Span), U64(effectiveExpires)]);
    }

    /// <summary>Creates a bounded current-view query; every changed cursor needs a fresh operation ID.</summary>
    public static GroupControlQueryRecord AuthorQuery(VerifiedGroupControlPlacement placement, GroupControlRendezvousRecord descriptor,
        ReadOnlyMemory<byte> operation, ulong issued, ulong expires, ulong afterSequence)
    {
        RequirePlacement(placement, descriptor); RequireWindow(placement, issued, expires);
        return (GroupControlQueryRecord)GroupCodec.CreateTaggedForAuthoring(ProtocolMagic.GSQ1, QueryTags,
            [descriptor.Field(1), operation, placement.ViewHash, placement.PlacementHash, U64(issued), U64(expires), placement.Selector,
             descriptor.ArtifactHash, U64(afterSequence), U16(64), U16(4)]);
    }

    /// <summary>Verifies exact request binding and both selected durable receipt signatures; syntax alone grants no success.</summary>
    public static GroupControlResultRecord VerifyResult(VerifiedGroupControlPlacement placement, GroupRecord request, ReadOnlySpan<byte> exactResult)
    {
        placement.Network.EnsureCurrent();
        if (request is not (GroupControlWriteRecord or GroupControlQueryRecord) ||
            !Fixed(request.Field(1).Span, placement.Network.NetworkId.Span) || !Fixed(request.Field(3).Span, placement.ViewHash.Span) ||
            !Fixed(request.Field(4).Span, placement.PlacementHash.Span) || !Fixed(request.Field(16).Span, placement.Selector.Span))
            throw new CryptographicException("Control request is outside current placement.");
        var result = (GroupControlResultRecord)GroupCodec.Decode(ProtocolMagic.GSS1, exactResult);
        var expectedKind = request is GroupControlWriteRecord ? (byte)1 : (byte)2;
        var requestHash = XPointNetworkCrypto.Sha256Domain("Deep/ContactResolver/V1/request", request.CanonicalBytes.Span);
        if (!Fixed(result.Field(1).Span, request.Field(1).Span) || !Fixed(result.Field(2).Span, request.Field(2).Span) ||
            !Fixed(result.Field(3).Span, requestHash) || result.Field(16).Span[0] != expectedKind)
            throw new CryptographicException("Control reply does not bind its exact original request.");
        var status = (GroupControlResultStatus)BinaryPrimitives.ReadUInt16BigEndian(result.Field(4).Span);
        if (status is GroupControlResultStatus.Committed or GroupControlResultStatus.ExactReplay)
        {
            if (!Fixed(result.Field(17).Span, request.Field(18).Span) || !Fixed(result.Field(18).Span, request.Field(20).Span))
                throw new CryptographicException("Control receipt changed original sequence/ciphertext.");
            var tuple = Join(requestHash, result.Field(17).ToArray(), result.Field(18).ToArray(), result.Field(19).ToArray());
            var signed = GroupCodec.SignatureInput("Deep/Group/V1/control-store-commit", tuple);
            var rows = result.Field(20).ToArray(); var replicas = placement.ReplicaIds;
            if (rows.Length != 192 || replicas.Count != 2) throw new CryptographicException("Exactly two control receipts required.");
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (var at = 0; at < rows.Length; at += 96)
            {
                var id = rows.AsMemory(at, 32);
                if (!seen.Add(Convert.ToHexString(id.Span)) || !replicas.Any(candidate => Fixed(candidate.Span, id.Span)) ||
                    !PublicKeyAuth.VerifyDetached(rows.AsSpan(at + 32, 64).ToArray(), signed,
                        placement.Network.ResolveNodeIdentityPublicKey(id).ToArray()))
                    throw new CryptographicException("Control receipt signer/signature is not an actual selected replica.");
            }
        }
        else if (status == GroupControlResultStatus.Events)
        {
            var first = BinaryPrimitives.ReadUInt64BigEndian(result.Field(18).Span);
            var after = BinaryPrimitives.ReadUInt64BigEndian(request.Field(18).Span);
            if (after == ulong.MaxValue || first != after + 1) throw new CryptographicException("Control stream has an explicit predecessor gap.");
        }
        placement.Network.EnsureCurrent(); return result;
    }

    /// <summary>Authenticates original completed write evidence without granting old-view dispatch authority.</summary>
    public static GroupControlResultRecord VerifyRetainedWriteResult(VerifiedOnionNetworkContext current,
        GroupControlWriteRecord request, ReadOnlySpan<byte> exactResult)
    {
        var result = VerifyResult(GroupControlPlacementVerifier.OriginalFacts(current, request), request, exactResult);
        if ((GroupControlResultStatus)BinaryPrimitives.ReadUInt16BigEndian(result.Field(4).Span) is not
            (GroupControlResultStatus.Committed or GroupControlResultStatus.ExactReplay)) throw new CryptographicException("No retained durable control result.");
        return result;
    }

    private static void RequirePlacement(VerifiedGroupControlPlacement placement, GroupControlRendezvousRecord descriptor)
    {
        placement.Network.EnsureCurrent();
        if (!Fixed(Selector(descriptor), placement.Selector.Span) || !Fixed(descriptor.Field(1).Span, placement.Network.NetworkId.Span) ||
            !Fixed(GroupControlPlacementVerifier.Create(placement.Network, Selector(descriptor), descriptor.Field(6)).PlacementHash.Span, placement.PlacementHash.Span))
            throw new CryptographicException("Control descriptor/placement mismatch.");
    }
    private static void RequireWindow(VerifiedGroupControlPlacement placement, ulong issued, ulong expires)
    {
        if (issued == 0 || expires <= issued || expires - issued > 120 || expires > placement.Network.Closure!.HardUpperUnixSeconds)
            throw new CryptographicException("Control request is outside current network interval.");
    }

    /// <summary>Bounds an original short carriage interval by the actual current verified view.</summary>
    public static ulong RequestExpiry(VerifiedGroupControlPlacement placement, ulong issued) =>
        Math.Min(checked(issued + 120), placement.Network.Closure!.HardUpperUnixSeconds);

    /// <summary>Never backdates an original request before its exact signed PMT2 carriage interval.</summary>
    public static ulong RequestIssued(VerifiedGroupControlPlacement placement, ulong trustedLower) =>
        Math.Max(trustedLower, BinaryPrimitives.ReadUInt64BigEndian(placement.Network.Closure!.Pmt.Field(11).Span));

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
