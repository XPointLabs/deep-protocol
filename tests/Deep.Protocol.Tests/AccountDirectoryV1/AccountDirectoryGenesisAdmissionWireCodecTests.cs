using System.Buffers.Binary;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ContactV1;
using Deep.Protocol.Tests.ContactV1;
using Sodium;

namespace Deep.Protocol.Tests.AccountDirectoryV1;

public sealed class AccountDirectoryGenesisAdmissionWireCodecTests
{
    [Fact]
    public void RequestRoundTripsExactPublicArtifacts()
    {
        var network = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var account = AccountDirectoryAdc1VerificationTests.Fixture.Create(
            0x21, network.Network);
        var checkpoint = account.CreateCheckpoint([]);
        var operationId = Bytes(32, 0x91);
        var expected = new AccountDirectoryGenesisAdmissionWireRequest(
            operationId,
            account.CreateGenesisAdmission(checkpoint));

        var encoded = AccountDirectoryGenesisAdmissionWireCodec.EncodeRequest(expected);
        var decoded = AccountDirectoryGenesisAdmissionWireCodec.DecodeRequest(encoded);

        Assert.Equal(operationId, decoded.OperationId.ToArray());
        Assert.Equal(expected.Admission.ExactDpa1.ToArray(),
            decoded.Admission.ExactDpa1.ToArray());
        Assert.Equal(expected.Admission.ExactDrs1.ToArray(),
            decoded.Admission.ExactDrs1.ToArray());
        Assert.Equal(expected.Admission.ExactDpd1.Single().ToArray(),
            decoded.Admission.ExactDpd1.Single().ToArray());
        Assert.Equal(expected.Admission.ExactDid1.ToArray(),
            decoded.Admission.ExactDid1.ToArray());
        Assert.Equal(expected.Admission.ExactDab1.ToArray(),
            decoded.Admission.ExactDab1.ToArray());
        Assert.Equal(expected.Admission.ExactDmd1.ToArray(),
            decoded.Admission.ExactDmd1.ToArray());
        Assert.Equal(expected.Admission.ExactAdc1.ToArray(),
            decoded.Admission.ExactAdc1.ToArray());
    }

    [Fact]
    public void RequestRejectsLengthSubstitutionAndTrailingBytes()
    {
        var network = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var account = AccountDirectoryAdc1VerificationTests.Fixture.Create(
            0x21, network.Network);
        var encoded = AccountDirectoryGenesisAdmissionWireCodec.EncodeRequest(
            new AccountDirectoryGenesisAdmissionWireRequest(
                Bytes(32, 0x91),
                account.CreateGenesisAdmission(account.CreateCheckpoint([]))));

        var changedLength = encoded.ToArray();
        BinaryPrimitives.WriteUInt32BigEndian(
            changedLength.AsSpan(8, 4), checked((uint)changedLength.Length + 1));
        Assert.Throws<FormatException>(() =>
            AccountDirectoryGenesisAdmissionWireCodec.DecodeRequest(changedLength));
        Assert.Throws<FormatException>(() =>
            AccountDirectoryGenesisAdmissionWireCodec.DecodeRequest(
                encoded.Concat(new byte[] { 0 }).ToArray()));
    }

    [Fact]
    public void ReceiptRoundTripsSignedHeadWithoutClaimingVerification()
    {
        var network = ContactNetworkAuthorityVerifierTests.Fixture.Create();
        var operationId = Bytes(32, 0x91);
        var leaf = Bytes(32, 0x92);
        var exactHead = SignedGenesisHead(network);

        var encoded = AccountDirectoryGenesisAdmissionWireCodec.EncodeReceipt(
            new AccountDirectoryGenesisAdmissionReceipt(
                operationId, leaf, exactHead));
        var decoded = AccountDirectoryGenesisAdmissionWireCodec.DecodeReceipt(encoded);

        Assert.Equal(operationId, decoded.OperationId.ToArray());
        Assert.Equal(leaf, decoded.DirectoryLeafKey.ToArray());
        Assert.Equal(exactHead, decoded.ExactAdh1.ToArray());
    }

    private static byte[] SignedGenesisHead(
        ContactNetworkAuthorityVerifierTests.Fixture fixture)
    {
        var witnesses = fixture.Witnesses.Take(2).ToArray();
        var provisional = new AccountDirectoryAdh1(
            fixture.Network,
            0,
            new byte[32],
            0,
            AccountDirectoryRfc6962.ComputeEmptyTreeHash(),
            AccountDirectorySparseMap.EmptyMapRoot.Span,
            fixture.Authority.AuthorityCoreReference.Span,
            fixture.Authority.DirectoryWitnessPolicyHash.Span,
            20,
            80,
            1,
            witnesses.Select(static value => new AccountDirectoryAdh1WitnessEntry(
                value.Id, Bytes(64, 1))).ToArray());
        var input = AccountDirectoryCrypto.ComputeAdh1SigningInput(provisional);
        var signed = new AccountDirectoryAdh1(
            provisional.NetworkId.Span,
            provisional.LogGeneration,
            provisional.PredecessorAdh1CoreHash.Span,
            provisional.TreeSize,
            provisional.AppendLogMerkleRoot.Span,
            provisional.CurrentValueMapRoot.Span,
            provisional.ExactXnaAuthorityCoreReference.Span,
            provisional.WitnessPolicyHash.Span,
            provisional.ValidFrom,
            provisional.ValidUntil,
            provisional.MinimumReader,
            witnesses.Select(value => new AccountDirectoryAdh1WitnessEntry(
                value.Id,
                PublicKeyAuth.SignDetached(input, value.Key.PrivateKey))).ToArray());
        return AccountDirectoryAdh1Codec.Encode(signed);
    }

    private static byte[] Bytes(int length, byte value) =>
        Enumerable.Repeat(value, length).ToArray();
}
