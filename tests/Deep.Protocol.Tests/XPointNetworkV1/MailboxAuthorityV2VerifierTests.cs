using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class MailboxAuthorityV2VerifierTests
{
    [Fact]
    public void Verify_BindsRoleSeparatedIssuersToCurrentRootAuthority()
    {
        var fixture = CreateAuthority();
        var exact = AuthorPma2(fixture, tamperSignature: false);

        var verified = MailboxAuthorityV2Verifier.Verify(
            fixture.Authority, exact, 100, 101);

        Assert.Equal(fixture.Network, verified.NetworkId.ToArray());
        Assert.Equal(fixture.DepositKey, verified.ResolveIssuer(
            MailboxCapabilityDomain.Deposit).PublicKey.ToArray());
        Assert.Equal(fixture.RetrieveKey, verified.ResolveIssuer(
            MailboxCapabilityDomain.Retrieve).PublicKey.ToArray());
        Assert.NotEqual(
            verified.ResolveIssuer(MailboxCapabilityDomain.Deposit).PublicKey.ToArray(),
            verified.ResolveIssuer(MailboxCapabilityDomain.Retrieve).PublicKey.ToArray());
    }

    [Fact]
    public void Verify_RejectsInvalidRootReceiptAndExpiredAuthority()
    {
        var fixture = CreateAuthority();
        Assert.Throws<CryptographicException>(() =>
            MailboxAuthorityV2Verifier.Verify(
                fixture.Authority, AuthorPma2(fixture, tamperSignature: true),
                100, 101));
        Assert.Throws<CryptographicException>(() =>
            MailboxAuthorityV2Verifier.Verify(
                fixture.Authority, AuthorPma2(fixture, tamperSignature: false),
                900, 901));
    }

    private static byte[] AuthorPma2(Fixture fixture, bool tamperSignature)
    {
        var fields = new ReadOnlyMemory<byte>[]
        {
            fixture.Network,
            U64(0),
            new byte[32],
            Bytes(32, 0x31),
            fixture.DepositKey,
            fixture.RetrieveKey,
            U64(1),
            U32(3_600),
            U16(1),
            U64(90),
            U64(95),
            U64(800),
            fixture.Authority.AuthorityCoreReference,
            fixture.Authority.DirectoryWitnessPolicyHash,
            new byte[] { 1 },
            Join(fixture.RootId, Bytes(64, 0x44)),
        };
        var unsigned = ContactCodec.AuthorForOperationalAuthority(
            "PMA2", fields);
        var signature = PublicKeyAuth.SignDetached(
            unsigned.SignatureInput.ToArray(), fixture.Root.PrivateKey);
        if (tamperSignature) signature[^1] ^= 1;
        fields[^1] = Join(fixture.RootId, signature);
        return ContactCodec.AuthorForOperationalAuthority(
            "PMA2", fields).CanonicalBytes.ToArray();
    }

    private static Fixture CreateAuthority()
    {
        var network = Bytes(16, 0x11);
        var root = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x20));
        var rootId = Bytes(32, 0x21);
        var sources = new[]
        {
            new AccountDirectoryDts1Source(
                Bytes(32, 0x22), Bytes(32, 0x23), 1,
                "time-a.example", 443, Bytes(32, 0x24), 1),
            new AccountDirectoryDts1Source(
                Bytes(32, 0x25), Bytes(32, 0x26), 1,
                "time-b.example", 443, Bytes(32, 0x27), 1),
        };
        var dts = new AccountDirectoryDts1(
            network, 0, new byte[32], sources, 2, 2, 30, 1,
            1, 1_000, 1, 0,
            [new AccountDirectoryDts1RootReceipt(rootId, Bytes(64, 0x28))]);
        var dtsHash = AccountDirectoryCrypto.ComputeDts1PolicyHash(dts);
        var witnessRows = Join(
            Join(Bytes(32, 0x51), U64(0), Bytes(32, 0x52), Bytes(32, 0x53)),
            Join(Bytes(32, 0x61), U64(0), Bytes(32, 0x62), Bytes(32, 0x63)),
            Join(Bytes(32, 0x71), U64(0), Bytes(32, 0x72), Bytes(32, 0x73)));
        ReadOnlyMemory<byte>[] fields =
        [
            network, U64(0), new byte[32], new byte[] { 1 },
            Join(rootId, U64(0), root.PublicKey), new byte[] { 1 }, U64(0), U16(1),
            new byte[] { 3 }, witnessRows, new byte[] { 2 },
            Reference("DTS1", dtsHash), dtsHash, U32(30), U64(1), U64(1), U64(1), U64(1_000),
            new byte[] { 1 }, Join(rootId, Bytes(64, 0x29)),
        ];
        var unsigned = XPointNetworkCodec.Parse<Xna1Record>(
            XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
        fields[^1] = Join(rootId, PublicKeyAuth.SignDetached(
            XPointNetworkCrypto.ComputeSigningInput(unsigned), root.PrivateKey));
        var xna = XPointNetworkCodec.Parse<Xna1Record>(
            XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
        return new Fixture(
            network,
            root,
            rootId,
            new VerifiedXPointNetworkAuthority(xna, dts, [xna]),
            Bytes(32, 0x81),
            Bytes(32, 0x91));
    }

    private sealed record Fixture(
        byte[] Network,
        KeyPair Root,
        byte[] RootId,
        VerifiedXPointNetworkAuthority Authority,
        byte[] DepositKey,
        byte[] RetrieveKey);

    private static byte[] Reference(string magic, byte[] hash) =>
        [.. System.Text.Encoding.ASCII.GetBytes(magic), 0, 1, .. hash];
    private static byte[] U16(ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        return bytes;
    }
    private static byte[] U32(uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return bytes;
    }
    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }
    private static byte[] Bytes(int length, byte marker) =>
        Enumerable.Repeat(marker, length).ToArray();
    private static byte[] Join(params byte[][] values) =>
        values.SelectMany(static value => value).ToArray();
}
