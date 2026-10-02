using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;
using Sodium;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed partial class AccountDirectoryFreshnessVerificationTests
{

    [Fact]
    public void IssuanceEpoch_IsStableWithinOneUtcDayAndBoundToTheVerifiedAuthority()
    {
        var authority = AuthorityFixture.Create();
        var first = AccountDirectoryDtt1IssuanceEpoch.Derive(
            authority.Verified, 1_700_000_200, 5);
        var sameDay = AccountDirectoryDtt1IssuanceEpoch.Derive(
            authority.Verified, first.ValidFrom + 100, 5);
        var nextDay = AccountDirectoryDtt1IssuanceEpoch.Derive(
            authority.Verified, first.ValidUntil + 6, 5);
        var otherAuthority = AuthorityFixture.Create(seedOffset: 1);
        var other = AccountDirectoryDtt1IssuanceEpoch.Derive(
            otherAuthority.Verified, 1_700_000_200, 5);

        Assert.Equal(first.Id.ToArray(), sameDay.Id.ToArray());
        Assert.NotEqual(first.Id.ToArray(), nextDay.Id.ToArray());
        Assert.NotEqual(first.Id.ToArray(), other.Id.ToArray());
    }

    [Fact]
    public void IssuanceEpoch_RejectsTrustedIntervalsThatCrossUtcDayBoundary()
    {
        var authority = AuthorityFixture.Create();
        var epoch = AccountDirectoryDtt1IssuanceEpoch.Derive(
            authority.Verified, 1_700_000_200, 5);

        Assert.Throws<CryptographicException>(() =>
            AccountDirectoryDtt1IssuanceEpoch.Derive(
                authority.Verified, epoch.ValidUntil, 1));
        Assert.Throws<CryptographicException>(() =>
            AccountDirectoryDtt1IssuanceEpoch.Derive(
                authority.Verified, epoch.ValidUntil + 1, 1));
    }

    [Fact]
    public void Verify_RejectsAValidlySignedDttFromTheWrongIssuanceEpoch()
    {
        var proof = Did2EmptyFixture.Create();
        var authority = proof.Authority;
        var head = AccountDirectoryAdh1Codec.Decode(proof.HeadBytes);
        var nextEpoch = AccountDirectoryDtt1IssuanceEpoch.Derive(
            authority.Verified,
            AccountDirectoryDtt1IssuanceEpoch.Derive(
                authority.Verified, 1_700_000_200, 5).ValidUntil + 6,
            5);
        var wrongEpochDtt = authority.Dtt(
            head, proof.Nonce, epochId: nextEpoch.Id.ToArray());

        Assert.Equal("IssuanceEpochMismatch",
            Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
                proof.Verify(dtt: AccountDirectoryDtt1Codec.Encode(wrongEpochDtt))).Code);
    }

    [Fact]
    public void ProtectedLkgRestore_ReauthenticatesCanonicalOldHeadWithoutCurrentTime()
    {
        var proof = Did2EmptyFixture.Create();
        var authority = proof.Authority;
        var head = AccountDirectoryAdh1Codec.Decode(proof.HeadBytes);
        var expectedHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(head);

        var restored = AccountDirectoryProtectedLkgFactory.Restore(
            authority.Verified, proof.HeadBytes, expectedHash);

        Assert.Equal(proof.HeadBytes, restored.ExactAdh1.ToArray());
        Assert.Equal(expectedHash, restored.CoreHash.ToArray());
        Assert.True(head.ValidUntil < (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    [Fact]
    public void ProtectedLkgRestore_RejectsAlteredBytesAndExpectedHash()
    {
        var proof = Did2EmptyFixture.Create(); var authority = proof.Authority;
        var expectedHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(
            AccountDirectoryAdh1Codec.Decode(proof.HeadBytes));
        var altered = proof.HeadBytes.ToArray(); altered[^1] ^= 1;

        Assert.Equal("InvalidWitnessSignature", Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            AccountDirectoryProtectedLkgFactory.Restore(authority.Verified, altered, expectedHash)).Code);
        Assert.Equal("PersistedLkgHashMismatch", Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            AccountDirectoryProtectedLkgFactory.Restore(authority.Verified, proof.HeadBytes, Bytes(32, 0xee))).Code);
    }

    [Fact]
    public void ProtectedLkgRestore_RejectsWrongNetworkInsufficientThresholdAndBadSignature()
    {
        var proof = Did2EmptyFixture.Create(); var authority = proof.Authority;
        var expectedHash = AccountDirectoryCrypto.ComputeAdh1CoreHash(
            AccountDirectoryAdh1Codec.Decode(proof.HeadBytes));
        var wrongNetworkAuthority = AuthorityFixture.Create(networkMarker: 0x12);
        Assert.Equal("NetworkMismatch", Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            AccountDirectoryProtectedLkgFactory.Restore(wrongNetworkAuthority.Verified, proof.HeadBytes, expectedHash)).Code);
        var wrongAuthority = AuthorityFixture.Create(seedOffset: 1);
        Assert.Equal("AuthorityMismatch", Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            AccountDirectoryProtectedLkgFactory.Restore(wrongAuthority.Verified, proof.HeadBytes, expectedHash)).Code);

        var insufficient = authority.Head(0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray(),
            [WitnessSigner.Valid(authority.Witnesses[0])]);
        Assert.Equal("WrongWitnessThreshold", Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            AccountDirectoryProtectedLkgFactory.Restore(authority.Verified, AccountDirectoryAdh1Codec.Encode(insufficient),
                AccountDirectoryCrypto.ComputeAdh1CoreHash(insufficient))).Code);

        var unrelated = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xee));
        var badSignature = authority.Head(0, new byte[32], 0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(), AccountDirectorySparseMap.EmptyMapRoot.ToArray(),
            [new WitnessSigner(authority.Witnesses[0].Id, unrelated.PrivateKey),
             WitnessSigner.Valid(authority.Witnesses[1])]);
        Assert.Equal("InvalidWitnessSignature", Assert.Throws<AccountDirectoryFreshnessVerificationException>(() =>
            AccountDirectoryProtectedLkgFactory.Restore(authority.Verified, AccountDirectoryAdh1Codec.Encode(badSignature),
                AccountDirectoryCrypto.ComputeAdh1CoreHash(badSignature))).Code);
    }

    private static IReadOnlyList<IAccountDirectoryDtt1WitnessSigner> ValidAuthorSigners(
        AuthorityFixture authority) =>
        authority.Witnesses.Take(2).Select(WitnessSigner.Valid)
            .Cast<IAccountDirectoryDtt1WitnessSigner>().ToArray();

    private static async Task AssertAuthorFailure(string code, Func<Task> action)
    {
        var error = await Assert.ThrowsAsync<AccountDirectoryProofAuthoringException>(action);
        Assert.Equal(code, error.Code);
    }

    private static AccountDirectoryMonotonicRequestWindow Window() =>
        new(Bytes(16, 0x44), 1_000, 1_002, 1_003);

    internal sealed record Witness(byte[] Id, KeyPair Key, byte[] FailureDomain);

    internal sealed record NetworkFixture(byte[] Network,
        VerifiedXPointNetworkAuthority Authority, Witness[] Witnesses);

    internal static NetworkFixture CreateNetworkFixture()
    {
        var authority = AuthorityFixture.Create(timeBase: 1_000_001);
        return new(authority.Network, authority.Verified, authority.Witnesses);
    }
    private sealed record WitnessSigner(byte[] Id, byte[] PrivateKey) : IAccountDirectoryDtt1WitnessSigner
    {
        internal static WitnessSigner Valid(Witness witness) => new(witness.Id, witness.Key.PrivateKey);

        public ReadOnlyMemory<byte> WitnessId => Id.ToArray();

        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                PublicKeyAuth.SignDetached(signingInput.ToArray(), PrivateKey));
        }
    }

    private sealed class FailingWitnessSigner(byte[] id) : IAccountDirectoryDtt1WitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => id.ToArray();

        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken) => throw new IOException("custody unavailable");
    }

    private sealed class ObservingWitnessSigner(Witness witness) : IAccountDirectoryDtt1WitnessSigner
    {
        public ReadOnlyMemory<byte> WitnessId => witness.Id.ToArray();
        internal ReadOnlyMemory<byte>? LastSigningInput { get; private set; }

        public ValueTask<ReadOnlyMemory<byte>> SignDtt1Async(
            ReadOnlyMemory<byte> signingInput,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LastSigningInput = signingInput;
            return ValueTask.FromResult<ReadOnlyMemory<byte>>(
                PublicKeyAuth.SignDetached(signingInput.ToArray(), witness.Key.PrivateKey));
        }
    }

    public enum ForwardFault
    {
        None,
        WrongSourceMembership,
        WrongFinalTargetTuple,
        InvalidRootSignature,
        OmittedGenesisCheckpoint,
        ExtraCheckpointAfterTarget,
    }

    private sealed class AuthorityFixture
    {
        private readonly KeyPair root;
        private readonly ulong timeBase;

        private AuthorityFixture(
            byte[] network,
            KeyPair root,
            Witness[] witnesses,
            byte[] exactXna1,
            VerifiedXPointNetworkAuthority verified,
            ulong timeBase)
        {
            Network = network;
            this.root = root;
            Witnesses = witnesses;
            ExactXna1 = exactXna1;
            Verified = verified;
            this.timeBase = timeBase;
        }

        internal byte[] Network { get; }
        internal Witness[] Witnesses { get; }
        internal byte[] ExactXna1 { get; }
        internal VerifiedXPointNetworkAuthority Verified { get; }

        internal IAccountDirectoryAdf1RootSigner InitialAdf1Signer() =>
            new TestAdf1RootSigner(Verified.RootKeys[0].Id, root.PrivateKey);

        internal static AuthorityFixture Create(byte networkMarker = 0x11,
            byte seedOffset = 0, byte[]? networkOverride = null,
            ulong timeBase = 1_700_000_000)
        {
            var network = networkOverride?.ToArray() ?? Bytes(16, networkMarker);
            var root = PublicKeyAuth.GenerateKeyPair(Bytes(32, checked((byte)(0x20 + seedOffset))));
            var witnesses = Enumerable.Range(0, 3).Select(index => new Witness(
                Bytes(32, checked((byte)(0x40 + seedOffset + index))),
                PublicKeyAuth.GenerateKeyPair(Bytes(32, checked((byte)(0x50 + seedOffset + index)))),
                Bytes(32, checked((byte)(0x60 + seedOffset + index))))).ToArray();
            var dts = Dts(network, root, timeBase);
            var policyHash = AccountDirectoryCrypto.ComputeDts1PolicyHash(AccountDirectoryDts1Codec.Decode(dts));
            var xna = Xna(network, root, witnesses, policyHash, timeBase);
            var xnaRecord = XPointNetworkCodec.Parse<Xna1Record>(xna);
            var pin = new XPointNetworkGenesisPin(network, xnaRecord.CoreHash.Span);
            var verified = XPointNetworkAuthorityVerifier.Verify(pin, [xna], [dts]);
            return new AuthorityFixture(network, root, witnesses, xna,
                verified, timeBase);
        }

        internal AccountDirectoryAdh1 Head(
            ulong generation,
            byte[] predecessor,
            ulong treeSize,
            byte[] appendRoot,
            byte[] mapRoot,
            IReadOnlyList<WitnessSigner>? signers = null,
            byte[]? authorityReference = null,
            byte[]? witnessPolicy = null,
            ushort minimumReader = 1)
        {
            var selected = (signers ?? Witnesses.Take(2).Select(WitnessSigner.Valid).ToArray())
                .OrderBy(static signer => signer.Id, ByteArrayComparer.Instance).ToArray();
            var placeholders = selected.Select((signer, index) => new AccountDirectoryAdh1WitnessEntry(
                signer.Id, Bytes(64, checked((byte)(0x70 + index))))).ToArray();
            var unsigned = new AccountDirectoryAdh1(
                Network, generation, predecessor, treeSize, appendRoot, mapRoot,
                authorityReference ?? Verified.AuthorityCoreReference.ToArray(),
                witnessPolicy ?? Verified.DirectoryWitnessPolicyHash.ToArray(),
                timeBase, checked(timeBase + 10_000), minimumReader, placeholders);
            var signing = AccountDirectoryCrypto.ComputeAdh1SigningInput(unsigned);
            var receipts = selected.Select(signer => new AccountDirectoryAdh1WitnessEntry(
                signer.Id, PublicKeyAuth.SignDetached(signing, signer.PrivateKey))).ToArray();
            return new AccountDirectoryAdh1(
                Network, generation, predecessor, treeSize, appendRoot, mapRoot,
                authorityReference ?? Verified.AuthorityCoreReference.ToArray(),
                witnessPolicy ?? Verified.DirectoryWitnessPolicyHash.ToArray(),
                timeBase, checked(timeBase + 10_000), minimumReader, receipts);
        }

        internal AccountDirectoryDtt1 Dtt(
            AccountDirectoryAdh1 head,
            byte[] nonce,
            IReadOnlyList<WitnessSigner>? signers = null,
            ulong? observed = null,
            byte[]? adhHash = null,
            byte[]? epochId = null)
        {
            var observation = observed ?? checked(timeBase + 200);
            var selected = (signers ?? Witnesses.Take(2).Select(WitnessSigner.Valid).ToArray())
                .OrderBy(static signer => signer.Id, ByteArrayComparer.Instance).ToArray();
            var placeholders = selected.Select((signer, index) => new AccountDirectoryDtt1WitnessReceipt(
                signer.Id, Bytes(64, checked((byte)(0x80 + index))))).ToArray();
            var headHash = adhHash ?? AccountDirectoryCrypto.ComputeAdh1CoreHash(head);
            var epochObserved = observation < Verified.Dts1NotBefore || observation > Verified.Dts1ExpiresAt
                ? Verified.Dts1NotBefore + 100
                : observation;
            var issuanceEpoch = AccountDirectoryDtt1IssuanceEpoch.Derive(Verified, epochObserved, 5);
            var selectedEpochId = epochId ?? issuanceEpoch.Id.ToArray();
            var unsigned = new AccountDirectoryDtt1(
                Network, nonce, observation, 5, headHash, head.LogGeneration, Bytes(32, 0x90), 1,
                Verified.AuthorityCoreReference.Span, Verified.DirectoryWitnessPolicyHash.Span,
                observation, checked(observation + 60), selectedEpochId, placeholders);
            var signing = AccountDirectoryCrypto.ComputeDtt1SigningInput(unsigned);
            var receipts = selected.Select(signer => new AccountDirectoryDtt1WitnessReceipt(
                signer.Id, PublicKeyAuth.SignDetached(signing, signer.PrivateKey))).ToArray();
            return new AccountDirectoryDtt1(
                Network, nonce, observation, 5, headHash, head.LogGeneration, Bytes(32, 0x90), 1,
                Verified.AuthorityCoreReference.Span, Verified.DirectoryWitnessPolicyHash.Span,
                observation, checked(observation + 60), selectedEpochId, receipts);
        }

        internal byte[] CurrentXnv()
        {
            ReadOnlyMemory<byte>[] fields =
            [
                Network,
                U64(0),
                new byte[32],
                Bytes(32, 0x91),
                U64(1),
                Bytes(32, 0x92),
                Verified.AuthorityCoreReference,
                Verified.DirectoryWitnessPolicyHash,
                Reference("XVP1", Bytes(32, 0x93)),
                U16(1),
                U16(3),
                Join(
                    Reference("XND1", Bytes(32, 0x94)),
                    Reference("XND1", Bytes(32, 0x95)),
                    Reference("XND1", Bytes(32, 0x96))),
                U16(0),
                Array.Empty<byte>(),
                U16(0),
                Array.Empty<byte>(),
                U16(1),
                Reference("XCB1", Bytes(32, 0x97)),
                U64(1),
                U64(checked(timeBase - 1_000)),
                U64(checked(timeBase + 10_000)),
                U16(1),
                new byte[] { 2 },
                Join(
                    Witnesses[0].Id, Bytes(64, 0xa1),
                    Witnesses[1].Id, Bytes(64, 0xa2)),
            ];
            var provisional = XPointNetworkCodec.Parse<Xnv1Record>(
                XPointNetworkCodec.Write(XPointNetworkRegistry.Xnv1, fields));
            var input = XPointNetworkCrypto.ComputeSigningInput(provisional);
            try
            {
                fields[23] = Join(
                    Witnesses[0].Id, PublicKeyAuth.SignDetached(input, Witnesses[0].Key.PrivateKey),
                    Witnesses[1].Id, PublicKeyAuth.SignDetached(input, Witnesses[1].Key.PrivateKey));
                return XPointNetworkCodec.Write(XPointNetworkRegistry.Xnv1, fields);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(input);
            }
        }

        internal AccountDirectoryAdf1 SignedAdf(
            ulong generation,
            byte[] predecessor,
            ulong coveredFirst,
            ulong coveredLast,
            ulong coveredCount,
            byte[] coveredRoot,
            byte[] targetHash,
            ulong targetTreeSize,
            byte[] targetAppendRoot,
            byte[] targetMapRoot,
            bool invalidSignature = false,
            ushort minimumReader = 1)
        {
            var rootId = Bytes(32, 0x20);
            var placeholder = new[] { new AccountDirectoryAdf1RootReceipt(rootId, Bytes(64, 0xaa)) };
            var unsigned = new AccountDirectoryAdf1(
                Network, generation, predecessor, coveredFirst, coveredLast, coveredCount, coveredRoot,
                Reference("ADH1", targetHash), targetTreeSize, targetAppendRoot, targetMapRoot,
                Verified.AuthorityCoreReference.Span, checked(timeBase + 150),
                minimumReader,
                placeholder);
            var signer = invalidSignature
                ? PublicKeyAuth.GenerateKeyPair(Bytes(32, 0xab)).PrivateKey
                : root.PrivateKey;
            var signature = PublicKeyAuth.SignDetached(
                AccountDirectoryCrypto.ComputeAdf1SigningInput(unsigned), signer);
            return new AccountDirectoryAdf1(
                Network, generation, predecessor, coveredFirst, coveredLast, coveredCount, coveredRoot,
                Reference("ADH1", targetHash), targetTreeSize, targetAppendRoot, targetMapRoot,
                Verified.AuthorityCoreReference.Span, checked(timeBase + 150),
                minimumReader,
                [new AccountDirectoryAdf1RootReceipt(rootId, signature)]);
        }

        private static byte[] Dts(byte[] network, KeyPair root, ulong timeBase)
        {
            var sources = new[]
            {
                new AccountDirectoryDts1Source(Bytes(32, 0x10), Bytes(32, 0x12), 1,
                    "time-a.example", 443, Bytes(32, 0x14), 5),
                new AccountDirectoryDts1Source(Bytes(32, 0x11), Bytes(32, 0x13), 1,
                    "time-b.example", 443, Bytes(32, 0x15), 5),
            };
            var rootId = Bytes(32, 0x20);
            var placeholder = new[] { new AccountDirectoryDts1RootReceipt(rootId, Bytes(64, 0x21)) };
            var unsigned = new AccountDirectoryDts1(
                network, 0, new byte[32], sources, 2, 2, 30, 5,
                checked(timeBase - 1_000_000), checked(timeBase + 1_000_000), 1, 0, placeholder);
            var signature = PublicKeyAuth.SignDetached(
                AccountDirectoryCrypto.ComputeDts1SigningInput(unsigned), root.PrivateKey);
            return AccountDirectoryDts1Codec.Encode(new AccountDirectoryDts1(
                network, 0, new byte[32], sources, 2, 2, 30, 5,
                checked(timeBase - 1_000_000), checked(timeBase + 1_000_000), 1, 0,
                [new AccountDirectoryDts1RootReceipt(rootId, signature)]));
        }

        private static byte[] Xna(byte[] network, KeyPair root, Witness[] witnesses,
            byte[] policyHash, ulong timeBase)
        {
            ReadOnlyMemory<byte>[] fields = new ReadOnlyMemory<byte>[20];
            fields[0] = network; fields[1] = U64(0); fields[2] = new byte[32]; fields[3] = new byte[] { 1 };
            fields[4] = Join(Bytes(32, 0x20), U64(0), root.PublicKey); fields[5] = new byte[] { 1 };
            fields[6] = U64(0); fields[7] = U16(1); fields[8] = new byte[] { 3 };
            fields[9] = Join(witnesses.Select(witness => Join(
                witness.Id, U64(0), witness.Key.PublicKey, witness.FailureDomain)).ToArray());
            fields[10] = new byte[] { 2 }; fields[11] = Reference("DTS1", policyHash); fields[12] = policyHash;
            fields[13] = U32(30); fields[14] = U64(1); fields[15] = U64(checked(timeBase - 1_000_000));
            fields[16] = U64(checked(timeBase - 1_000_000)); fields[17] = U64(checked(timeBase + 10_000_000)); fields[18] = new byte[] { 1 };
            fields[19] = Join(Bytes(32, 0x20), Bytes(64, 0x22));
            var unsigned = XPointNetworkCodec.Parse<Xna1Record>(XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields));
            var signature = PublicKeyAuth.SignDetached(XPointNetworkCrypto.ComputeSigningInput(unsigned), root.PrivateKey);
            fields[19] = Join(Bytes(32, 0x20), signature);
            return XPointNetworkCodec.Write(XPointNetworkRegistry.Xna1, fields);
        }
    }

    private delegate void SpanMutation(Span<byte> value);

    private static byte[] MutateField(byte[] canonical, int tag, SpanMutation mutation)
    {
        var result = canonical.ToArray();
        var offset = 12;
        for (var current = 1; current <= tag; current++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(result.AsSpan(offset + 4, 4)));
            offset += 8;
            if (current == tag) { mutation(result.AsSpan(offset, length)); return result; }
            offset += length;
        }
        throw new ArgumentOutOfRangeException(nameof(tag));
    }

    private static byte[] Write(string magic, ushort suite, IReadOnlyList<byte[]> fields)
    {
        var output = new byte[checked(12 + fields.Sum(static field => 8 + field.Length))];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), 1);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), suite);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)fields.Count));
        var offset = 12;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4), checked((uint)fields[index].Length));
            offset += 8;
            fields[index].CopyTo(output, offset);
            offset += fields[index].Length;
        }
        return output;
    }

    private static byte[] Reference(string magic, ReadOnlySpan<byte> hash)
    {
        var result = new byte[38];
        Encoding.ASCII.GetBytes(magic).CopyTo(result, 0);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), 1);
        hash.CopyTo(result.AsSpan(6));
        return result;
    }

    private static byte[] CoveredHeadLeaf(ulong generation, ulong treeSize, ReadOnlySpan<byte> headHash)
    {
        var input = new byte[49];
        input[0] = 0;
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(1), generation);
        BinaryPrimitives.WriteUInt64BigEndian(input.AsSpan(9), treeSize);
        headHash.CopyTo(input.AsSpan(17));
        return SHA256.HashData(input);
    }

    private static byte[] Lp32(byte[] value) => Join(U32(checked((uint)value.Length)), value);
    private static byte[] U16(ushort value) { var result = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(result, value); return result; }
    private static byte[] U32(uint value) { var result = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(result, value); return result; }
    private static byte[] U64(ulong value) { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
    private static byte[] Bytes(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
    private static byte[] Join(params byte[][] values) { var result = new byte[values.Sum(static value => value.Length)]; var offset = 0; foreach (var value in values) { value.CopyTo(result, offset); offset += value.Length; } return result; }

    private sealed class ByteArrayComparer : IComparer<byte[]>
    {
        internal static readonly ByteArrayComparer Instance = new();
        public int Compare(byte[]? left, byte[]? right) => left.AsSpan().SequenceCompareTo(right);
    }
}
