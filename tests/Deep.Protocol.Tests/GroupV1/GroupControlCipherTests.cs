using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.GroupV1;
using Deep.Protocol.DeepNative;
using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;

namespace Deep.Protocol.Tests.GroupV1;

// Primitive/canonical grammar coverage, not network or current owner authority.
public sealed class GroupControlCipherTests
{
    private static byte[] B(int size, byte value) => Enumerable.Repeat(value, size).ToArray();
    private static byte[] U64(ulong value) { var b = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(b, value); return b; }
    private static byte[] U32(uint value) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, value); return b; }
    private static byte[] Lp(byte[] bytes) => [.. U32((uint)bytes.Length), .. bytes];
    private static GroupControlRendezvousRecord Descriptor(byte[] key) => (GroupControlRendezvousRecord)GroupCodec.CreateForAuthoring(ProtocolMagic.GSR1,
        [B(16,1), B(32,2), B(32,3), U64(0), new byte[32], GroupCodec.ReferenceForAuthoring(ProtocolMagic.PMT2,B(32,4)),
         B(32,5),B(32,6), GroupControlCipher.PublicKey(key), B(32,7),GroupCodec.ReferenceForAuthoring(ProtocolMagic.DPD1,B(32,8)), U64(100),U64(1000),B(64,9)]);
    private static GroupCommitChunkRecord Chunk()
    {
        var bytes = B(16,12);
        return (GroupCommitChunkRecord)GroupCodec.CreateForAuthoring(ProtocolMagic.GCF1,
            [B(32,10),U32(16),U32(24576),U32(0),U32(1),SHA256.HashData(bytes),Lp(bytes)]);
    }

    [Fact]
    public void ExactRoundTripUsesFreshSealingAndRejectsChangedAssociatedScope()
    {
        var key = GroupControlCipher.GeneratePrivateKey(); var descriptor = Descriptor(key); var chunk = Chunk();
        var sealedBytes = GroupControlCipher.Seal(descriptor,1,new byte[32],900,chunk);
        try
        {
            Assert.Equal(chunk.CanonicalBytes.ToArray(),GroupControlCipher.Open(descriptor,key,1,new byte[32],900,sealedBytes).CanonicalBytes.ToArray());
            Assert.NotEqual(sealedBytes,GroupControlCipher.Seal(descriptor,1,new byte[32],900,chunk));
            Assert.ThrowsAny<Exception>(()=>GroupControlCipher.Open(descriptor,key,2,B(32,11),900,sealedBytes));
            Assert.ThrowsAny<Exception>(()=>GroupControlCipher.Open(descriptor,key,1,new byte[32],899,sealedBytes));
            Assert.Throws<CryptographicException>(()=>GroupControlCipher.Open(descriptor,B(32,13),1,new byte[32],900,sealedBytes));
            var changed = sealedBytes.ToArray(); changed[^1]^=1;
            Assert.ThrowsAny<Exception>(()=>GroupControlCipher.Open(descriptor,key,1,new byte[32],900,changed));
            Assert.Throws<CryptographicException>(()=>GroupControlCipher.Open(descriptor,key,1,new byte[32],900,sealedBytes[..72]));
            Assert.Throws<CryptographicException>(()=>GroupControlCipher.Seal(descriptor,1,B(32,11),900,chunk));
            Assert.Throws<CryptographicException>(()=>GroupControlCipher.Seal(descriptor,1,new byte[32],1001,chunk));
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(sealedBytes); }
    }

    [Fact]
    public void E2eeCarrierRejectsTruncationChangedRecipientAndMismatchedKeyWithoutGenericEmission()
    {
        var key = GroupControlCipher.GeneratePrivateKey(); var descriptor = Descriptor(key);
        var raw = new byte[624]; B(32,14).CopyTo(raw,0); B(32,15).CopyTo(raw,32); descriptor.CanonicalBytes.Span.CopyTo(raw.AsSpan(64)); key.CopyTo(raw,592);
        try
        {
            var payload = GroupCodec.DecodeDmc2Payload(Dmc2ContentKind.GroupControlRendezvous,raw);
            Assert.Equal(B(32,14),payload.ControlGroup.ToArray()); Assert.Equal(B(32,15),payload.ControlRecipient.ToArray());
            Assert.Throws<InvalidOperationException>(()=>ApplicationCoreCodec.AuthorDmc2(B(16,1),B(32,16),B(32,17),B(32,18),B(32,7),3,100000,101000,Dmc2Flags.None,[],payload));
            Assert.Throws<GroupFormatException>(()=>GroupCodec.DecodeDmc2Payload(Dmc2ContentKind.GroupControlRendezvous,raw[..^1]));
            var changed=raw.ToArray(); changed.AsSpan(32,32).Clear();
            Assert.Throws<GroupFormatException>(()=>GroupCodec.DecodeDmc2Payload(Dmc2ContentKind.GroupControlRendezvous,changed));
            raw[^1]^=1;
            Assert.Throws<GroupFormatException>(()=>GroupCodec.DecodeDmc2Payload(Dmc2ContentKind.GroupControlRendezvous,raw));
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(raw); }
    }
}
