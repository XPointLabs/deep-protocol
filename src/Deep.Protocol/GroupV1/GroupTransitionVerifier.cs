using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.DeepNative;
using Sodium;

namespace Deep.Protocol.GroupV1;

public static partial class GroupCodec
{
    /// <summary>
    /// The Contact verifier capability now binds exact ADC1/ADH1/ADP1 evidence,
    /// current DMD1/DRS1 identity state and trusted time without accepting caller keys.
    /// </summary>
    public static bool AccountDirectoryCapabilityAvailable => true;

    private static void Authorize(GroupProposalAction action, ReadOnlySpan<byte> proposer, GroupRole baseRole, GroupRole currentRole, ReadOnlySpan<byte> payload)
    {
        if (baseRole != currentRole) Reject(GroupValidationStage.Transition, "ProposalAuthorizationChanged");
        var ownLeave = action == GroupProposalAction.LeaveAccount && payload[..32].SequenceEqual(proposer);
        var allowed = baseRole switch
        {
            GroupRole.Owner => action != GroupProposalAction.LeaveAccount,
            GroupRole.Admin => action is GroupProposalAction.ActivateAcceptedInvite or GroupProposalAction.RemoveAccount or
                GroupProposalAction.ChangeRole or GroupProposalAction.AddDevice or GroupProposalAction.RemoveDevice or
                GroupProposalAction.ChangeProfile || ownLeave,
            GroupRole.Member => ownLeave,
            _ => false,
        };
        if (!allowed) Reject(GroupValidationStage.Transition, "ProposalUnauthorized");
    }

    private static void VerifySingleDeviceDelta(
        Member before,
        Member after,
        ReadOnlySpan<byte> targetDeviceId,
        ReadOnlySpan<byte> targetDpdReference,
        GroupProposalAction action)
    {
        var beforeById = before.Devices.ToDictionary(
            static device => Convert.ToHexString(device.Id), StringComparer.Ordinal);
        var afterById = after.Devices.ToDictionary(
            static device => Convert.ToHexString(device.Id), StringComparer.Ordinal);
        var target = Convert.ToHexString(targetDeviceId);

        foreach (var pair in beforeById)
        {
            if (pair.Key == target && action == GroupProposalAction.RemoveDevice)
                continue;
            if (!afterById.TryGetValue(pair.Key, out var unchanged) ||
                !unchanged.Reference.AsSpan().SequenceEqual(pair.Value.Reference))
                Reject(GroupValidationStage.Transition, "DeviceDirectoryDeltaMismatch");
        }

        if (action == GroupProposalAction.AddDevice)
        {
            if (beforeById.ContainsKey(target) || afterById.Count != beforeById.Count + 1 ||
                !afterById.TryGetValue(target, out var added) ||
                !added.Reference.AsSpan().SequenceEqual(targetDpdReference))
                Reject(GroupValidationStage.Transition, "DeviceDirectoryDeltaMismatch");
        }
        else if (action == GroupProposalAction.RemoveDevice)
        {
            if (!beforeById.TryGetValue(target, out var removed) ||
                !removed.Reference.AsSpan().SequenceEqual(targetDpdReference) ||
                afterById.ContainsKey(target) || beforeById.Count != afterById.Count + 1)
                Reject(GroupValidationStage.Transition, "DeviceDirectoryDeltaMismatch");
        }
        else
        {
            Reject(GroupValidationStage.Transition, "InvalidDeviceDirectoryDeltaAction");
        }
    }

    private static void RequireMemberHash(Member member, ReadOnlySpan<byte> expected)
    {
        if (!SHA256.HashData(SerializeMember(member)).AsSpan().SequenceEqual(expected))
            Reject(GroupValidationStage.Transition, "MemberEntryHashMismatch");
    }

    private static Member? FindMember(List<Member> members, ReadOnlySpan<byte> account, bool required)
    {
        foreach (var member in members)
            if (member.Account.AsSpan().SequenceEqual(account)) return member;
        if (required) Reject(GroupValidationStage.Transition, "MemberPreconditionFailed");
        return null;
    }

    private static Device? FindDevice(Member member, ReadOnlySpan<byte> deviceId)
    {
        foreach (var device in member.Devices)
            if (device.Id.AsSpan().SequenceEqual(deviceId)) return device;
        return null;
    }

    private static Member CloneMember(Member member) => member with
    {
        Account = member.Account.ToArray(), Adc = member.Adc.ToArray(), Adh = member.Adh.ToArray(),
        Adp = member.Adp.ToArray(), Dmd = member.Dmd.ToArray(), Drs = member.Drs.ToArray(),
        Devices = member.Devices.Select(static device => new Device(device.Id.ToArray(), device.Reference.ToArray())).ToList(),
    };

    private static void EnforceGroupLimits(List<Member> members)
    {
        if (members.Count is < 1 or > 100 || members.Count(member => member.Role == GroupRole.Owner) != 1 ||
            members.Count(member => member.Role is GroupRole.Owner or GroupRole.Admin) > 5 ||
            members.Any(member => member.Devices.Count is < 1 or > 5) || members.Sum(member => member.Devices.Count) > 500)
            Reject(GroupValidationStage.Transition, "GroupLimitExceeded");
    }

    private static byte[] SerializeMembers(IEnumerable<Member> members) => members
        .OrderBy(static member => member.Account, ByteArrayComparer.Instance)
        .SelectMany(SerializeMember).ToArray();

    private static byte[] SerializeMember(Member member)
    {
        var devices = member.Devices.OrderBy(static device => device.Id, ByteArrayComparer.Instance).ToArray();
        var body = new byte[220 + devices.Length * 70];
        member.Account.CopyTo(body, 0); body[32] = (byte)member.Role; member.Adc.CopyTo(body, 33); member.Adh.CopyTo(body, 71);
        member.Adp.CopyTo(body, 109); BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(141), member.DirectoryGeneration);
        member.Dmd.CopyTo(body, 149); member.Drs.CopyTo(body, 181); body[219] = checked((byte)devices.Length);
        for (var i = 0; i < devices.Length; i++) { devices[i].Id.CopyTo(body, 220 + i * 70); devices[i].Reference.CopyTo(body, 252 + i * 70); }
        var result = new byte[body.Length + 2]; BinaryPrimitives.WriteUInt16BigEndian(result, checked((ushort)body.Length)); body.CopyTo(result, 2);
        return result;
    }

    private static ReadOnlySpan<byte> ExactLp(ReadOnlySpan<byte> value)
    {
        var payload = Lp(value, out var used);
        if (used != value.Length) Reject(GroupValidationStage.Bounds, "TrailingLp32Bytes");
        return payload;
    }

    private static byte[] ReferenceBytes(string magic, ReadOnlySpan<byte> hash)
    {
        var value = new byte[38]; Encoding.ASCII.GetBytes(magic).CopyTo(value, 0); value[5] = 1; hash.CopyTo(value.AsSpan(6)); return value;
    }

    private static void RequireReference(ReadOnlySpan<byte> reference, string magic, ReadOnlySpan<byte> hash)
    {
        if (!reference.SequenceEqual(ReferenceBytes(magic, hash))) Reject(GroupValidationStage.Closure, "VerifiedReferenceMismatch");
    }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? x, byte[]? y) => (x ?? []).AsSpan().SequenceCompareTo(y ?? []);
    }

    private sealed class ReadOnlyMemoryComparer : IComparer<ReadOnlyMemory<byte>>
    {
        internal static readonly ReadOnlyMemoryComparer Instance = new();
        public int Compare(ReadOnlyMemory<byte> x, ReadOnlyMemory<byte> y) => x.Span.SequenceCompareTo(y.Span);
    }

    private sealed class VerifiedGroupTransitionImpl(
        GroupCommitRecord commit,
        GroupCommitRecord? predecessor,
        ReadOnlySpan<byte> exactCanonicalGcp1Bytes)
        : VerifiedGroupTransition(commit, predecessor, exactCanonicalGcp1Bytes);
}

/// <summary>
/// Atomic persistence seam for the permanent group fork latch.  Implementations
/// must durably compare exact bytes and fsync/commit <paramref name="replacement"/>
/// before returning true.
/// </summary>
public interface IGroupSuccessorStateStore
{
    bool CompareExchange(ReadOnlyMemory<byte> expected, ReadOnlyMemory<byte> replacement);
}

/// <summary>Restart-safe permanent fork latch for one verified group lineage.</summary>
public sealed class GroupSuccessorLatch
{
    private const int HeaderBytes = 58;
    private byte[] snapshot;
    private ulong revision;
    private ulong? headEpoch;
    private byte[]? headHash;
    private readonly List<ObservedCommit> observed = [];

    private GroupSuccessorLatch() { snapshot = Encode(false, 0, null, null, observed); }

    public bool ForkLatched { get; private set; }
    public ReadOnlyMemory<byte> Snapshot => snapshot.ToArray();
    public static GroupSuccessorLatch CreateEmpty() => new();

    public static GroupSuccessorLatch Restore(ReadOnlySpan<byte> persisted)
    {
        if (persisted.Length < HeaderBytes || !persisted[..4].SequenceEqual(ProtocolMagicBytes.GLS1) ||
            BinaryPrimitives.ReadUInt16BigEndian(persisted[4..]) != 1 ||
            BinaryPrimitives.ReadUInt16BigEndian(persisted[6..]) > 1)
            throw new GroupFormatException(GroupValidationStage.Transition, "InvalidPersistedGroupLineage");
        var count = BinaryPrimitives.ReadUInt16BigEndian(persisted[56..]);
        if (persisted.Length != HeaderBytes + count * 40)
            throw new GroupFormatException(GroupValidationStage.Transition, "InvalidPersistedGroupLineage");
        var latch = new GroupSuccessorLatch
        {
            snapshot = persisted.ToArray(),
            ForkLatched = BinaryPrimitives.ReadUInt16BigEndian(persisted[6..]) == 1,
            revision = BinaryPrimitives.ReadUInt64BigEndian(persisted[8..]),
        };
        // Every durable state change appends exactly one previously unseen commit.
        // Binding the CAS revision to that cardinality prevents rollback/tampering
        // from manufacturing a canonical-looking snapshot after restart.
        if (latch.revision != count)
            throw new GroupFormatException(GroupValidationStage.Transition, "InvalidPersistedGroupLineage");
        var encodedHeadEpoch = BinaryPrimitives.ReadUInt64BigEndian(persisted[16..]);
        var encodedHeadHash = persisted.Slice(24, 32);
        if (count == 0)
        {
            if (encodedHeadEpoch != ulong.MaxValue || encodedHeadHash.IndexOfAnyExcept((byte)0) >= 0 || latch.revision != 0 || latch.ForkLatched)
                throw new GroupFormatException(GroupValidationStage.Transition, "InvalidPersistedGroupLineage");
        }
        else
        {
            latch.headEpoch = encodedHeadEpoch;
            latch.headHash = encodedHeadHash.ToArray();
        }
        var at = HeaderBytes;
        ObservedCommit? priorEntry = null;
        for (var index = 0; index < count; index++, at += 40)
        {
            var epoch = BinaryPrimitives.ReadUInt64BigEndian(persisted[at..]);
            var hash = persisted.Slice(at + 8, 32).ToArray();
            var entry = new ObservedCommit(epoch, hash);
            if (hash.AsSpan().IndexOfAnyExcept((byte)0) < 0 ||
                priorEntry is not null && Compare(priorEntry, entry) >= 0)
                throw new GroupFormatException(GroupValidationStage.Transition, "InvalidPersistedGroupLineage");
            latch.observed.Add(entry); priorEntry = entry;
        }
        if (latch.headEpoch is { } head &&
            !latch.observed.Any(entry => entry.Epoch == head && entry.Hash.AsSpan().SequenceEqual(latch.headHash)))
            throw new GroupFormatException(GroupValidationStage.Transition, "InvalidPersistedGroupLineage");
        if (!Encode(latch.ForkLatched, latch.revision, latch.headEpoch, latch.headHash, latch.observed).AsSpan().SequenceEqual(persisted))
            throw new GroupFormatException(GroupValidationStage.Transition, "NonCanonicalPersistedGroupLineage");
        return latch;
    }

    public GroupLineageDisposition ObserveAndPersist(VerifiedGroupTransition transition, IGroupSuccessorStateStore store)
    {
        ArgumentNullException.ThrowIfNull(transition); ArgumentNullException.ThrowIfNull(store);
        if (ForkLatched) return GroupLineageDisposition.ForkLatched;
        var commit = transition.Commit;
        var epoch = BinaryPrimitives.ReadUInt64BigEndian(commit.Field(4).Span);
        var hash = commit.ArtifactHash.ToArray();
        var nextObserved = observed.Select(static entry => new ObservedCommit(entry.Epoch, entry.Hash.ToArray())).ToList();
        var nextFork = false; ulong? nextHeadEpoch = headEpoch; byte[]? nextHeadHash = headHash?.ToArray();
        GroupLineageDisposition disposition;
        var sameEpoch = nextObserved.Where(entry => entry.Epoch == epoch).ToArray();
        if (sameEpoch.Any(entry => entry.Hash.AsSpan().SequenceEqual(hash)))
            return GroupLineageDisposition.ExactReplay;
        if (sameEpoch.Length != 0)
        {
            nextObserved.Add(new ObservedCommit(epoch, hash));
            nextFork = true; disposition = GroupLineageDisposition.ForkLatched;
        }
        else if (headEpoch is null)
        {
            if (epoch != 0) throw new GroupFormatException(GroupValidationStage.Transition, "LineageMustStartAtGenesis");
            nextObserved.Add(new ObservedCommit(epoch, hash)); nextHeadEpoch = epoch; nextHeadHash = hash;
            disposition = GroupLineageDisposition.AcceptedGenesis;
        }
        else
        {
            if (headEpoch == ulong.MaxValue || epoch != headEpoch + 1 || !commit.Field(5).Span.SequenceEqual(headHash))
                throw new GroupFormatException(GroupValidationStage.Transition, "NonSuccessorCommit");
            nextObserved.Add(new ObservedCommit(epoch, hash)); nextHeadEpoch = epoch; nextHeadHash = hash;
            disposition = GroupLineageDisposition.AcceptedSuccessor;
        }
        if (revision == ulong.MaxValue) throw new GroupFormatException(GroupValidationStage.Transition, "LineageRevisionExhausted");
        var replacement = Encode(nextFork, revision + 1, nextHeadEpoch, nextHeadHash, nextObserved);
        if (!store.CompareExchange(snapshot, replacement))
            throw new GroupFormatException(GroupValidationStage.Transition, "LineagePersistenceConflict");
        snapshot = replacement; revision++;
        ForkLatched = nextFork; headEpoch = nextHeadEpoch; headHash = nextHeadHash;
        observed.Clear(); observed.AddRange(nextObserved.OrderBy(static entry => entry.Epoch).ThenBy(static entry => entry.Hash, HashComparer.Instance));
        return disposition;
    }

    private static byte[] Encode(bool fork, ulong revision, ulong? headEpoch, byte[]? headHash, IEnumerable<ObservedCommit> entries)
    {
        var ordered = entries.OrderBy(static entry => entry.Epoch).ThenBy(static entry => entry.Hash, HashComparer.Instance).ToArray();
        var bytes = new byte[checked(HeaderBytes + ordered.Length * 40)];
        ProtocolMagicBytes.GLS1.CopyTo(bytes); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), fork ? (ushort)1 : (ushort)0);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(8), revision);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(16), headEpoch ?? ulong.MaxValue);
        headHash?.CopyTo(bytes, 24); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(56), checked((ushort)ordered.Length));
        var at = HeaderBytes; foreach (var entry in ordered) { BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(at), entry.Epoch); entry.Hash.CopyTo(bytes, at + 8); at += 40; }
        return bytes;
    }

    private static int Compare(ObservedCommit left, ObservedCommit right)
    {
        var epoch = left.Epoch.CompareTo(right.Epoch);
        return epoch != 0 ? epoch : left.Hash.AsSpan().SequenceCompareTo(right.Hash);
    }

    private sealed record ObservedCommit(ulong Epoch, byte[] Hash);
    private sealed class HashComparer : IComparer<byte[]>
    {
        internal static readonly HashComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => (left ?? []).AsSpan().SequenceCompareTo(right ?? []);
    }
}
