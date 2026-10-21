using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.XPointNetworkV1;

// Pure public signature arithmetic ONLY. No policy, clock, chain, endpoint,
// protected-floor, revocation or authorization result can enter this memo.
internal sealed class ExactEd25519VerificationMemo(int maximumEntries = 4096, int maximumBytes = 8 * 1024 * 1024)
{
    internal static readonly ExactEd25519VerificationMemo Shared = new();
    private sealed record Entry(string Digest, byte[] Key, byte[] Message, byte[] Signature)
    { internal int Bytes => Key.Length + Message.Length + Signature.Length; }
    private readonly object gate = new();
    private readonly Dictionary<string, LinkedListNode<Entry>> entries = new(StringComparer.Ordinal);
    private readonly LinkedList<Entry> fifo = new();
    private int bytes;
    private long nativeVerifications;
    internal (int Entries, int Bytes, long NativeVerifications) Snapshot()
    { lock (gate) return (entries.Count, bytes, Interlocked.Read(ref nativeVerifications)); }

    internal bool Verify(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (key.Length != 32 || signature.Length != 64) return false;
        // Owned copies bind the hit and insertion to the SAME bytes verified
        // by native crypto, even if a caller later mutates its original arrays.
        var ownedKey = key.ToArray(); var ownedMessage = message.ToArray(); var ownedSignature = signature.ToArray();
        var bounded = message.Length <= 65_536 && maximumEntries > 0 && message.Length + 96 <= maximumBytes;
        string? digest = null;
        if (bounded)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            hash.AppendData(ownedKey); hash.AppendData(ownedSignature); hash.AppendData(ownedMessage);
            digest = Convert.ToHexString(hash.GetHashAndReset());
            lock (gate)
                if (entries.TryGetValue(digest, out var hit) &&
                    hit.Value.Key.AsSpan().SequenceEqual(ownedKey) && hit.Value.Message.AsSpan().SequenceEqual(ownedMessage) &&
                    hit.Value.Signature.AsSpan().SequenceEqual(ownedSignature)) return true;
        }
        bool valid;
        Interlocked.Increment(ref nativeVerifications);
        try { valid = PublicKeyAuth.VerifyDetached(ownedSignature, ownedMessage, ownedKey); }
        catch (Exception error) when (error is not OperationCanceledException) { return false; }
        if (!valid || !bounded) return valid;
        var entry = new Entry(digest!, ownedKey, ownedMessage, ownedSignature);
        lock (gate)
        {
            if (entries.Remove(digest!, out var prior)) { bytes -= prior.Value.Bytes; fifo.Remove(prior); }
            while (entries.Count >= maximumEntries || bytes + entry.Bytes > maximumBytes)
            { var first = fifo.First!; entries.Remove(first.Value.Digest); bytes -= first.Value.Bytes; fifo.RemoveFirst(); }
            entries.Add(digest!, fifo.AddLast(entry)); bytes += entry.Bytes;
        }
        return true;
    }
}
