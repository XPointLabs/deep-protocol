using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class MembershipCatalogEnvelopeTests
{
    [Fact]
    public async Task ExactCatalogAndHmac_ReturnOnlyRelativeOwnedEnvelope()
    {
        var key = Bytes(1);
        var keyId = Bytes(2);
        var canonical = Mrlc(key);
        var provider = new HmacProvider(key);

        var verified = await MembershipCatalogEnvelopeVerifier.VerifyAsync(
            canonical,
            keyId,
            provider);
        canonical.AsSpan().Fill(0xff);
        provider.LastTag!.AsSpan().Fill(0xee);

        Assert.True(verified.NoAuthorityClaim);
        Assert.Equal(8U, verified.ArtifactEntryCount);
        Assert.Equal(1U, verified.MemberCount);
        Assert.NotEqual(Bytes(0), verified.VerifiedHmac.ToArray());
        Assert.Equal("MRLC", Encoding.ASCII.GetString(verified.CanonicalBytes.Span[..4]));
    }

    [Fact]
    public async Task ZeroKeyIdOrCatalogHashMix_Rejects()
    {
        var key = Bytes(1);
        var canonical = Mrlc(key);
        var provider = new HmacProvider(key);
        await Assert.ThrowsAsync<RecordException>(() =>
            MembershipCatalogEnvelopeVerifier.VerifyAsync(
                canonical,
                new byte[32],
                provider).AsTask());
        Assert.Equal(0, provider.Calls);

        var mixed = canonical.ToArray();
        mixed[FieldOffset(mixed, 25)] ^= 0x80;
        await Assert.ThrowsAsync<RecordException>(() =>
            MembershipCatalogEnvelopeVerifier.VerifyAsync(
                mixed,
                Bytes(2),
                provider).AsTask());
    }

    private static byte[] Mrlc(byte[] key)
    {
        var catalog = MembershipCatalogTests.Catalog();
        var fields = RecordDefinitions.Mrlc.Fields
            .Select(static field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        fields[0] = Enumerable.Repeat((byte)1, 16).ToArray();
        fields[12] = U32(1);
        fields[22] = U32(8);
        fields[23] = U64(checked((ulong)catalog.Length));
        fields[24] = MembershipCatalogEnvelopeVerifier.ComputeCatalogHash(8, catalog);
        fields[25] = catalog;
        fields[26] = new byte[32];
        var pending = CanonicalGrammar.Encode(RecordDefinitions.Mrlc, fields);
        var record = CanonicalGrammar.DecodeOwned(pending, RecordDefinitions.Mrlc);
        fields[26] = CanonicalGrammar.ComputeProtectedHmac(record, key);
        return CanonicalGrammar.Encode(RecordDefinitions.Mrlc, fields);
    }

    private static int FieldOffset(ReadOnlySpan<byte> encoded, int tag)
    {
        var offset = 12;
        for (var current = 1; current <= tag; current++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(offset + 4, 4)));
            offset += 8;
            if (current == tag) return offset;
            offset += length;
        }
        throw new ArgumentOutOfRangeException(nameof(tag));
    }

    private static byte[] Bytes(byte value) => Enumerable.Repeat(value, 32).ToArray();
    private static byte[] U32(uint value) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, value); return b; }
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }

    private sealed class HmacProvider : IProtectedHmacProvider
    {
        private readonly byte[] _key;
        internal HmacProvider(byte[] key) => _key = key;
        internal int Calls { get; private set; }
        internal byte[]? LastTag { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> ComputeTagAsync(
            ProtectedHmacRequest request,
            CancellationToken cancellationToken)
        {
            Calls++;
            var domain = Encoding.ASCII.GetBytes(request.Domain);
            var input = new byte[2 + domain.Length + 2 + 4 + request.UnsignedCanonical.Length];
            BinaryPrimitives.WriteUInt16BigEndian(input, checked((ushort)domain.Length));
            domain.CopyTo(input, 2);
            var offset = 2 + domain.Length;
            BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(offset), request.Suite);
            BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(offset + 2),
                checked((uint)request.UnsignedCanonical.Length));
            request.UnsignedCanonical.Span.CopyTo(input.AsSpan(offset + 6));
            LastTag = HMACSHA256.HashData(_key, input);
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(LastTag);
        }
    }
}
