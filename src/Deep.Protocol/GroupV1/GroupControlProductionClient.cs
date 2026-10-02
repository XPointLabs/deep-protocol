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

public static class GroupControlProductionClient
{
    private static readonly int[] WriteTags = [1,2,3,4,5,6,16,17,18,19,20,21,22];
    private static readonly int[] QueryTags = [1,2,3,4,5,6,16,17,18,19,20];

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
