using System.Security.Cryptography;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.Tests.MessagingWire;

public sealed class MessagingWireGoldenTests
{
    [Theory]
    [InlineData(Dpk2PrekeyKind.OneTime, Dpk2Codec.OneTimeTotalBytes)]
    [InlineData(Dpk2PrekeyKind.LastResort, Dpk2Codec.LastResortTotalBytes)]
    public void Dpk2_ExactManualWitnessRoundTrips(Dpk2PrekeyKind kind, int expectedLength)
    {
        var record = MessagingWireFixtures.Dpk2(kind);
        var manual = ManualMessagingWire.Record("DPK2", ManualMessagingWire.Dpk2Fields(record));
        var encoded = Dpk2Codec.Encode(record);

        Assert.Equal(expectedLength, encoded.Length);
        Assert.Equal(manual, encoded);
        Assert.Equal(encoded, Dpk2Codec.Encode(Dpk2Codec.Decode(encoded)));
    }

    [Fact]
    public void Dpk2_ProjectionsAndSignatureInputsMatchIndependentWitnesses()
    {
        var record = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var fields = ManualMessagingWire.Dpk2Fields(record);
        var xspkProjection = ManualMessagingWire.Record("DPK2", fields[..17]);
        var mlKemProjection = ManualMessagingWire.Record(
            "DPK2",
            fields[..17].Concat(fields[20..24]).ToArray());
        var unsignedProjection = ManualMessagingWire.Record("DPK2", fields[..25]);

        Assert.Equal(xspkProjection, Dpk2Codec.GetX25519SignedPrekeyProjection(record));
        Assert.Equal(mlKemProjection, Dpk2Codec.GetMlKemPrekeyProjection(record));
        Assert.Equal(unsignedProjection, Dpk2Codec.GetUnsignedBundleProjection(record));
        Assert.Equal(
            ManualMessagingWire.SignatureInput(MessagingWireCryptographicInputs.X25519SignedPrekeyDomain, xspkProjection),
            MessagingWireCryptographicInputs.GetX25519SignedPrekeySignatureInput(record));
        Assert.Equal(
            ManualMessagingWire.SignatureInput(MessagingWireCryptographicInputs.MlKemPrekeyDomain, mlKemProjection),
            MessagingWireCryptographicInputs.GetMlKemPrekeySignatureInput(record));
        Assert.Equal(
            ManualMessagingWire.SignatureInput(MessagingWireCryptographicInputs.PrekeyBundleDomain, unsignedProjection),
            MessagingWireCryptographicInputs.GetPrekeyBundleSignatureInput(record));
    }

    [Theory]
    [InlineData(Dpk2PrekeyKind.OneTime, 4112, Dph2Codec.SmallTotalBytes)]
    [InlineData(Dpk2PrekeyKind.LastResort, 4112, Dph2Codec.SmallTotalBytes)]
    [InlineData(Dpk2PrekeyKind.OneTime, 16400, Dph2Codec.MediumTotalBytes)]
    [InlineData(Dpk2PrekeyKind.LastResort, 16400, Dph2Codec.MediumTotalBytes)]
    [InlineData(Dpk2PrekeyKind.OneTime, 32784, Dph2Codec.LargeTotalBytes)]
    [InlineData(Dpk2PrekeyKind.LastResort, 32784, Dph2Codec.LargeTotalBytes)]
    public void Dph2_AllBucketsAndKindsMatchIndependentWitness(
        Dpk2PrekeyKind kind,
        int ciphertextLength,
        int expectedLength)
    {
        var offering = MessagingWireFixtures.Dpk2(kind);
        var record = MessagingWireFixtures.Dph2(offering, ciphertextLength);
        var manual = ManualMessagingWire.Record("DPH2", ManualMessagingWire.Dph2Fields(record));
        var encoded = Dph2Codec.Encode(record);

        Assert.Equal(expectedLength, encoded.Length);
        Assert.Equal(manual, encoded);
        var decoded = Dph2Codec.Decode(encoded, offering);
        Assert.Equal(encoded, Dph2Codec.Encode(decoded));
    }

    [Fact]
    public void Dph2_SessionTranscriptReplayAndClaimInputsAreDistinctAndExact()
    {
        var offering = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var record = MessagingWireFixtures.Dph2(offering, 4112);
        var dpk2 = ManualMessagingWire.Record("DPK2", ManualMessagingWire.Dpk2Fields(offering));
        var fields = ManualMessagingWire.Dph2Fields(record);
        var header = ManualMessagingWire.Record("DPH2", fields[..19]);
        var exact = ManualMessagingWire.Record("DPH2", fields);
        var sessionValue = ManualMessagingWire.Concat(
            fields[0].Value,
            fields[1].Value,
            fields[2].Value,
            fields[3].Value,
            fields[4].Value,
            fields[5].Value,
            fields[6].Value,
            fields[7].Value,
            fields[8].Value,
            fields[9].Value,
            fields[10].Value,
            fields[11].Value,
            fields[15].Value,
            fields[14].Value,
            fields[16].Value,
            fields[17].Value);
        var expectedSession = ManualMessagingWire.Sha256Domain(
            MessagingWireCryptographicInputs.SessionIdDomain,
            sessionValue);
        var transcriptValue = ManualMessagingWire.Concat(
            ManualMessagingWire.Lp32(dpk2),
            ManualMessagingWire.Lp32(header));
        var expectedTranscriptInput = ManualMessagingWire.DomainInput(
            MessagingWireCryptographicInputs.HandshakeTranscriptDomain,
            transcriptValue);
        var expectedTranscript = SHA512.HashData(expectedTranscriptInput);
        var expectedSenderCommitment = ManualMessagingWire.Sha256Domain(
            MessagingWireCryptographicInputs.SenderEphemeralDomain,
            ManualMessagingWire.Concat(
                fields[0].Value,
                fields[1].Value,
                fields[2].Value,
                fields[4].Value,
                fields[13].Value,
                fields[14].Value,
                fields[17].Value));
        var expectedHeaderHash = ManualMessagingWire.Sha256Domain(
            MessagingWireCryptographicInputs.Dph2HeaderDomain,
            header);
        var expectedInitialAad = ManualMessagingWire.Context(
            MessagingWireCryptographicInputs.Dph2InitialAadDomain,
            header,
            expectedTranscript);
        var expectedReplayInput = ManualMessagingWire.DomainInput(
            MessagingWireCryptographicInputs.ExactDph2ReplayDomain,
            exact);
        var expectedReplay = SHA256.HashData(expectedReplayInput);
        var expectedClaim = ManualMessagingWire.Sha256Domain(
            MessagingWireCryptographicInputs.PrekeyClaimBindingDomain,
            ManualMessagingWire.Concat(
                fields[9].Value,
                fields[12].Value,
                fields[8].Value,
                fields[10].Value,
                expectedReplay));

        Assert.Equal(expectedSession, record.SessionId.ToArray());
        Assert.Equal(expectedSession, MessagingWireCryptographicInputs.ComputeDph2SessionId(record));
        Assert.Equal(
            ManualMessagingWire.Sha256Domain(MessagingWireCryptographicInputs.ExactDpk2Domain, dpk2),
            MessagingWireCryptographicInputs.ComputeExactDpk2Hash(offering));
        Assert.Equal(
            ManualMessagingWire.DomainInput(MessagingWireCryptographicInputs.ExactDpk2Domain, dpk2),
            MessagingWireCryptographicInputs.GetExactDpk2HashInput(offering));
        Assert.Equal(expectedSenderCommitment, MessagingWireCryptographicInputs.ComputeSenderEphemeralCommitment(record));
        Assert.Equal(header, MessagingWireCryptographicInputs.GetDph2HandshakeHeader(record));
        Assert.Equal(expectedHeaderHash, MessagingWireCryptographicInputs.ComputeDph2HeaderHash(record));
        Assert.Equal(
            ManualMessagingWire.DomainInput(MessagingWireCryptographicInputs.Dph2HeaderDomain, header),
            MessagingWireCryptographicInputs.GetDph2HeaderHashInput(record));
        Assert.Equal(expectedTranscriptInput, MessagingWireCryptographicInputs.GetDph2TranscriptHashInput(offering, record));
        Assert.Equal(expectedTranscript, MessagingWireCryptographicInputs.ComputeDph2TranscriptHash(offering, record));
        Assert.Equal(expectedInitialAad, MessagingWireCryptographicInputs.GetDph2InitialAeadAssociatedData(offering, record));
        Assert.Equal(expectedReplayInput, MessagingWireCryptographicInputs.GetDph2FullReplayHashInput(record));
        Assert.Equal(expectedReplay, MessagingWireCryptographicInputs.ComputeDph2FullReplayHash(record));
        Assert.Equal(
            ManualMessagingWire.DomainInput(
                MessagingWireCryptographicInputs.PrekeyClaimBindingDomain,
                ManualMessagingWire.Concat(
                    fields[9].Value,
                    fields[12].Value,
                    fields[8].Value,
                    fields[10].Value,
                    expectedReplay)),
            MessagingWireCryptographicInputs.GetDph2ClaimBindingHashInput(record));
        Assert.Equal(expectedClaim, MessagingWireCryptographicInputs.ComputeDph2ClaimBinding(record));
        Assert.NotEqual(expectedTranscript[..32], expectedReplay);
    }

    public static TheoryData<Dtr2BraidMessageKind, int> Dtr2Kinds => new()
    {
        { Dtr2BraidMessageKind.None, 189 },
        { Dtr2BraidMessageKind.Header, 285 },
        { Dtr2BraidMessageKind.EncapsulationKey, 1341 },
        { Dtr2BraidMessageKind.EncapsulationKeyWithCiphertext1Ack, 1341 },
        { Dtr2BraidMessageKind.Ciphertext1Ack, 189 },
        { Dtr2BraidMessageKind.Ciphertext1, 1149 },
        { Dtr2BraidMessageKind.Ciphertext2, 349 },
    };

    [Theory]
    [MemberData(nameof(Dtr2Kinds))]
    public void Dtr2_EveryClosedKindMatchesIndependentWitness(
        Dtr2BraidMessageKind kind,
        int expectedLength)
    {
        var fixture = MessagingWireFixtures.Dtr2(kind);
        var manual = ManualMessagingWire.Record("DTR2", ManualMessagingWire.Dtr2Fields(fixture));
        var encoded = Dtr2Codec.EncodeEmbedded(fixture.Record);

        Assert.Equal(expectedLength, encoded.Length);
        Assert.Equal(manual, encoded);
        Assert.Equal(encoded, Dtr2Codec.EncodeEmbedded(Dtr2Codec.DecodeEmbedded(encoded)));
    }

    [Fact]
    public void Dpe2_AllTwentyExactBucketsMatchIndependentWitnesses()
    {
        var dtrKinds = new[]
        {
            Dtr2BraidMessageKind.None,
            Dtr2BraidMessageKind.Header,
            Dtr2BraidMessageKind.Ciphertext2,
            Dtr2BraidMessageKind.Ciphertext1,
            Dtr2BraidMessageKind.EncapsulationKey,
        };
        var ciphertextLengths = new[] { 4112, 16400, 32784, 49152 };
        var observed = new List<int>();
        foreach (var ciphertextLength in ciphertextLengths)
        {
            foreach (var kind in dtrKinds)
            {
                var dtr = MessagingWireFixtures.Dtr2(kind);
                var record = MessagingWireFixtures.Dpe2(dtr.Record, ciphertextLength);
                var manualDtr2 = ManualMessagingWire.Record("DTR2", ManualMessagingWire.Dtr2Fields(dtr));
                var manual = ManualMessagingWire.Record(
                    "DPE2",
                    ManualMessagingWire.Dpe2Fields(record, manualDtr2));
                var encoded = Dpe2Codec.Encode(record);

                observed.Add(encoded.Length);
                Assert.Equal(manual, encoded);
                Assert.Equal(encoded, Dpe2Codec.Encode(Dpe2Codec.Decode(encoded)));
            }
        }

        Assert.Equal(Dpe2Codec.AllowedTotalSizes.ToArray(), observed.Order().ToArray());
    }

    [Fact]
    public void Dpe2_HeaderNonceAadAndReplayMatchIndependentWitnesses()
    {
        var dtr = MessagingWireFixtures.Dtr2(Dtr2BraidMessageKind.Header);
        var record = MessagingWireFixtures.Dpe2(dtr.Record, 4112);
        var exactDtr2 = ManualMessagingWire.Record("DTR2", ManualMessagingWire.Dtr2Fields(dtr));
        var fields = ManualMessagingWire.Dpe2Fields(record, exactDtr2);
        var header = ManualMessagingWire.Record("DPE2", fields[..6]);
        var exact = ManualMessagingWire.Record("DPE2", fields);
        var headerHash = ManualMessagingWire.Sha256Domain(
            MessagingWireCryptographicInputs.RatchetHeaderDomain,
            exactDtr2);
        var nonce = ManualMessagingWire.Sha256Domain(
            MessagingWireCryptographicInputs.Dpe2NonceDomain,
            ManualMessagingWire.Concat(fields[1].Value, fields[4].Value, headerHash))[..24];
        var aad = ManualMessagingWire.Context(
            MessagingWireCryptographicInputs.Dpe2AadDomain,
            header,
            headerHash);
        var replayInput = ManualMessagingWire.DomainInput(
            MessagingWireCryptographicInputs.ExactDpe2ReplayDomain,
            exact);

        Assert.Equal(header, MessagingWireCryptographicInputs.GetDpe2Header(record));
        Assert.Equal(
            ManualMessagingWire.DomainInput(MessagingWireCryptographicInputs.RatchetHeaderDomain, exactDtr2),
            MessagingWireCryptographicInputs.GetDtr2HeaderHashInput(dtr.Record));
        Assert.Equal(headerHash, MessagingWireCryptographicInputs.ComputeDtr2HeaderHash(dtr.Record));
        Assert.Equal(headerHash, MessagingWireCryptographicInputs.ComputeDpe2HeaderHash(record));
        Assert.Equal(
            ManualMessagingWire.DomainInput(
                MessagingWireCryptographicInputs.Dpe2NonceDomain,
                ManualMessagingWire.Concat(fields[1].Value, fields[4].Value, headerHash)),
            MessagingWireCryptographicInputs.GetDpe2NonceHashInput(record));
        Assert.Equal(nonce, MessagingWireCryptographicInputs.DeriveDpe2Nonce(record));
        Assert.Equal(aad, MessagingWireCryptographicInputs.GetDpe2AeadAssociatedData(record));
        Assert.Equal(replayInput, MessagingWireCryptographicInputs.GetDpe2FullReplayHashInput(record));
        Assert.Equal(SHA256.HashData(replayInput), MessagingWireCryptographicInputs.ComputeDpe2FullReplayHash(record));
    }

    [Fact]
    public void RepresentativeRecords_HavePinnedGoldenSha256()
    {
        var dpk2 = Dpk2Codec.Encode(MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime));
        var offering = MessagingWireFixtures.Dpk2(Dpk2PrekeyKind.OneTime);
        var dph2 = Dph2Codec.Encode(MessagingWireFixtures.Dph2(offering, 4112));
        var dtrFixture = MessagingWireFixtures.Dtr2(Dtr2BraidMessageKind.Header);
        var dtr2 = Dtr2Codec.EncodeEmbedded(dtrFixture.Record);
        var dpe2 = Dpe2Codec.Encode(MessagingWireFixtures.Dpe2(dtrFixture.Record, 4112));
        var actual = string.Join(
            ":",
            Convert.ToHexString(SHA256.HashData(dpk2)).ToLowerInvariant(),
            Convert.ToHexString(SHA256.HashData(dph2)).ToLowerInvariant(),
            Convert.ToHexString(SHA256.HashData(dtr2)).ToLowerInvariant(),
            Convert.ToHexString(SHA256.HashData(dpe2)).ToLowerInvariant());

        Assert.Equal(
            "822840758e93aa2e9d735eb33ed2958aa23b812c50085a14ce53fbdbe89b189c:" +
            "8e330f48c86d675224f897a2822b7e194d1ea53626820c5a9bfca29f000f65ed:" +
            "9f8db23191cf78c31cfd2dba5747f9b59d9ea60ed9d8442d22140b1a8a9a12b3:" +
            "bf9d9aa5058683b1ae64a352ccefd03d9416e7166d8685e53ccb2f909ce33e24",
            actual);
    }
}
