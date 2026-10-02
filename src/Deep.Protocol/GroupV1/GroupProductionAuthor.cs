using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.GroupV1;

public enum GroupDeviceSignaturePurpose : byte
{
    Invitation = 1,
    InvitationAcceptance = 2,
    Proposal = 3,
    Commit = 4,
}

public sealed class GroupAuthoringException : CryptographicException
{
    internal GroupAuthoringException(string code, string message, Exception? inner = null)
        : base(message, inner) => Code = code;
    public string Code { get; }
}

/// <summary>Custody boundary for one verified active device signing key.</summary>
public interface IGroupDeviceCustodySigner
{
    ReadOnlyMemory<byte> DeviceId { get; }
    ReadOnlyMemory<byte> Ed25519PublicKey { get; }
    ReadOnlyMemory<byte> CustodyDomainHash { get; }
    ValueTask<int> SignAsync(GroupDeviceSigningRequest request, Memory<byte> signature64, CancellationToken cancellationToken);
}

public sealed class GroupDeviceSigningRequest
{
    private readonly byte[] networkId, groupId, accountId, deviceId, custodyDomainHash, signingInput, signingInputHash;
    internal GroupDeviceSigningRequest(GroupDeviceSignaturePurpose purpose, ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> groupId, ReadOnlySpan<byte> accountId, ReadOnlySpan<byte> deviceId,
        ReadOnlySpan<byte> custodyDomainHash, ReadOnlySpan<byte> signingInput)
    {
        Purpose = purpose; this.networkId = networkId.ToArray(); this.groupId = groupId.ToArray();
        this.accountId = accountId.ToArray(); this.deviceId = deviceId.ToArray();
        this.custodyDomainHash = custodyDomainHash.ToArray(); this.signingInput = signingInput.ToArray();
        signingInputHash = SHA256.HashData(signingInput);
    }
    public GroupDeviceSignaturePurpose Purpose { get; }
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> GroupId => groupId.ToArray();
    public ReadOnlyMemory<byte> AccountId => accountId.ToArray();
    public ReadOnlyMemory<byte> DeviceId => deviceId.ToArray();
    public ReadOnlyMemory<byte> CustodyDomainHash => custodyDomainHash.ToArray();
    /// <summary>Exact GROUP-CODEC-01 signing input; valid only during SignAsync.</summary>
    public ReadOnlyMemory<byte> SigningInput => signingInput;
    public ReadOnlyMemory<byte> SigningInputSha256 => signingInputHash;
    internal void Clear() { CryptographicOperations.ZeroMemory(signingInput); CryptographicOperations.ZeroMemory(signingInputHash); }
}

public sealed class VerifiedAuthoredGroupTransition
{
    internal VerifiedAuthoredGroupTransition(GroupCommitPackageRecord package, VerifiedGroupTransition transition)
    { Package = package; Transition = transition; }
    public GroupCommitPackageRecord Package { get; } public VerifiedGroupTransition Transition { get; }
    public ReadOnlyMemory<byte> CanonicalPackageBytes => Package.CanonicalBytes;
}

public static class GroupProductionAuthor
{
    private static byte[] SignaturePlaceholder() { var value = new byte[64]; value[0] = 1; return value; }
    private static byte[] U16(ushort value) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, value); return b; }
    private static byte[] U32(uint value) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, value); return b; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
    private static byte[] Join(params byte[][] values) { var result = new byte[checked(values.Sum(v => v.Length))]; var at = 0; foreach (var value in values) { value.CopyTo(result, at); at += value.Length; } return result; }
    private static void Fail(string code, string message) => throw new GroupAuthoringException(code, message);
}

public static partial class GroupCodec
{
    internal static GroupRecord CreateForAuthoring(string magic, IReadOnlyList<ReadOnlyMemory<byte>> fields)
        => CreateTaggedForAuthoring(magic, Enumerable.Range(1, fields.Count).ToArray(), fields);

    internal static GroupRecord CreateTaggedForAuthoring(string magic, IReadOnlyList<int> tags,
        IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        if (tags.Count != fields.Count) throw new ArgumentException("Tag and field counts must match.", nameof(tags));
        var size = checked(12 + fields.Sum(field => 8 + field.Length)); var bytes = new byte[size]; Encoding.ASCII.GetBytes(magic).CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), checked((ushort)fields.Count)); var at = 12;
        for (var index = 0; index < fields.Count; index++) { BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(at), checked((ushort)tags[index])); BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(at + 4), checked((uint)fields[index].Length)); at += 8; fields[index].Span.CopyTo(bytes.AsSpan(at)); at += fields[index].Length; }
        try { return Decode(magic, bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static byte[] ReferenceForAuthoring(string magic, ReadOnlySpan<byte> hash) => ReferenceBytes(magic, hash);
    internal static byte[] SerializeMembersForAuthoring(IEnumerable<Member> members) => SerializeMembers(members);
    internal static List<Member> ReadMembersForAuthoring(GroupCommitRecord commit) => ReadMembers(commit.FieldSpan(12));
    internal static Member CloneMemberForAuthoring(Member member) => CloneMember(member);
    internal static void EnforceLimitsForAuthoring(List<Member> members) => EnforceGroupLimits(members);
    internal static byte[] MemberEntryHashForAuthoring(Member member) => SHA256.HashData(SerializeMember(member));

    internal sealed record AuthorSupport(ushort Kind, byte[] Reference, byte[] Bytes);

    internal static GroupCommitPackageRecord PackageForAuthoring(GroupCommitRecord commit, IReadOnlyList<GroupProposalRecord> proposals,
        IReadOnlyList<AuthorSupport> supports, IReadOnlyList<(GroupInvitationRecord Invitation, GroupInvitationAcceptanceRecord Acceptance)> pairs)
    {
        var orderedProposals = proposals.OrderBy(value => value.ArtifactHash.ToArray(), AuthorByteComparer.Instance).ToArray();
        var proposalBytes = JoinAuthor(orderedProposals.Select(value => LpAuthor(value.CanonicalBytes.Span)).ToArray());
        var supportParts = supports.OrderBy(value => value.Kind).ThenBy(value => value.Reference, AuthorByteComparer.Instance)
            .Select(value => JoinAuthor(U16Author(value.Kind), value.Reference, LpAuthor(value.Bytes))).ToArray();
        var orderedPairs = pairs.OrderBy(value => value.Invitation.Field(3).ToArray(), AuthorByteComparer.Instance).ToArray();
        var pairParts = orderedPairs.Select(value => JoinAuthor(ArtifactReference(ProtocolMagic.GIV1, value.Invitation).CanonicalBytes.ToArray(), LpAuthor(value.Invitation.CanonicalBytes.Span),
            ArtifactReference(ProtocolMagic.GIA1, value.Acceptance).CanonicalBytes.ToArray(), LpAuthor(value.Acceptance.CanonicalBytes.Span))).ToArray();
        return (GroupCommitPackageRecord)CreateForAuthoring(ProtocolMagic.GCP1, [commit.Field(1), commit.Field(2), commit.Field(4), LpAuthor(commit.CanonicalBytes.Span),
            U16Author(checked((ushort)orderedProposals.Length)), proposalBytes, U32Author(checked((uint)supports.Count)), JoinAuthor(supportParts),
            U16Author(checked((ushort)orderedPairs.Length)), JoinAuthor(pairParts), Array.Empty<byte>()]);
    }
    private sealed class AuthorResolver(Dictionary<string, byte[]> values) : IGroupClosureResolver
    { public ReadOnlyMemory<byte>? Resolve(GroupArtifactReference reference) => values.TryGetValue(Convert.ToHexString(reference.CanonicalBytes.Span), out var value) ? value : null; }
    private sealed class AuthorByteComparer : IComparer<byte[]> { internal static readonly AuthorByteComparer Instance = new(); public int Compare(byte[]? x, byte[]? y) => x.AsSpan().SequenceCompareTo(y); }
    private static byte[] LpAuthor(ReadOnlySpan<byte> value) { var result = new byte[checked(value.Length + 4)]; BinaryPrimitives.WriteUInt32BigEndian(result, checked((uint)value.Length)); value.CopyTo(result.AsSpan(4)); return result; }
    private static byte[] U16Author(ushort value) { var result = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(result, value); return result; }
    private static byte[] U32Author(uint value) { var result = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(result, value); return result; }
    private static byte[] JoinAuthor(params byte[][] values) { var result = new byte[checked(values.Sum(value => value.Length))]; var at = 0; foreach (var value in values) { value.CopyTo(result, at); at += value.Length; } return result; }
}
