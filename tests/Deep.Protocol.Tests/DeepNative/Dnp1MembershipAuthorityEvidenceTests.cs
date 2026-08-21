using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.Membership;
using Deep.Protocol.DeepNative;
using Deep.Protocol.Tests.DeepExtension;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class MembershipAuthorityEvidenceTests
{
    [Fact]
    public void MembershipAndMailboxIssuerAuthorityCannotCrossAuthorizeBeforeCrypto()
    {
        var pmaIssuerPublicKey = Fill(0x31, 32);
        var membershipPublicKey = Fill(0x41, 32);
        var network = Fill(0x51, 16);
        var pmaReference = Reference(ArtifactType.Pma1, 256, 0x61);
        var pmrReference = Reference(ArtifactType.Pmr1, 192, 0x62);
        var dnrFields = MinimumFields(RecordDefinitions.Dnr1);
        dnrFields[0] = network;
        dnrFields[3] = pmaReference;
        dnrFields[4] = U64(7);
        dnrFields[5] = pmrReference;
        dnrFields[6] = U64(8);
        dnrFields[7] = SHA256.HashData(pmaIssuerPublicKey);
        dnrFields[13] = U64(1);
        dnrFields[14] = U64(1);
        var dnr = CanonicalGrammar.DecodeOwned(
            CanonicalGrammar.Encode(RecordDefinitions.Dnr1, dnrFields),
            RecordDefinitions.Dnr1);

        MembershipClosureVerifier.VerifyRouterAuthorityBindingBeforeSignatures(
            dnr, network, pmaReference, 7, pmrReference, 8, pmaIssuerPublicKey);
        var dnrError = Assert.Throws<RecordException>(() =>
            MembershipClosureVerifier.VerifyRouterAuthorityBindingBeforeSignatures(
                dnr, network, pmaReference, 7, pmrReference, 8, membershipPublicKey));
        Assert.Equal(RecordError.InvalidField, dnrError.Error);

        var commitment = MembershipFixtures.Commitment(sequence: 7);
        var pmaIssuerId = SHA256.HashData(pmaIssuerPublicKey).AsMemory(0, 16);
        var crossed = new SignedMembershipCommitment
        {
            Statement = commitment,
            Signatures =
            [
                new MembershipSignature
                {
                    SignerId = pmaIssuerId,
                    Domain = MembershipSignatureDomain.Membership,
                    Signature = Fill(0x71, 32)
                }
            ]
        };
        var deterministic = new DeterministicMembershipVerifier();
        var genesis = MembershipFixtures.Genesis();
        var delegation = MembershipFixtures.SignedDelegation(deterministic);
        var verifiedDelegation = MembershipContractVerifier.VerifyDelegation(
            delegation,
            genesis,
            MembershipFixtures.GenesisAuthorityLastKnownGood(),
            1010,
            30,
            2,
            deterministic);
        var context = MembershipFixtures.Context() with
        {
            Genesis = genesis,
            ActiveDelegation = delegation,
            AuthorityLastKnownGood = verifiedDelegation.NextAuthorityLastKnownGood,
            RevokedDelegationHashes = []
        };
        var counter = new CountingVerifier();
        var membershipError = Assert.Throws<MembershipContractException>(() =>
            MembershipContractVerifier.VerifyMembershipFromVerifiedDelegation(
                crossed, context, verifiedDelegation, counter));
        Assert.Equal(MembershipContractError.UnknownSigner, membershipError.Error);
        Assert.Equal(0, counter.Calls);
    }

    [Fact]
    public async Task CurrentDnrcFactSetRejectsBoundsDuplicatesMissingUnusedAndMixedSourcesBeforeCallbacks()
    {
        var exact = await MembershipClosureIntegrationTests.CreateTransportRoutingFactsAsync();
        var other = await MembershipClosureIntegrationTests.CreateTransportRoutingFactsAsync();
        var exactDnr = exact.Dnrc.Certificate.CanonicalBytes.ToArray();
        var crossedDnr = exactDnr.ToArray();
        crossedDnr[^1] ^= 0x01;
        var crossedCertificate = new VerifiedRouterCertificateRelative(
            CanonicalGrammar.DecodeOwned(crossedDnr, RecordDefinitions.Dnr1));
        var sameSourceWrongFact = new CurrentDnrcRelative(
            exact.Dnrc.Mailbox,
            exact.Dnrc.MailboxAuthorityHead,
            exact.Dnrc.PmaCanonical,
            exact.Dnrc.PmrCanonical,
            crossedCertificate,
            exact.Dnrc.Possession,
            pmaEpoch: 9);
        var one = Catalog(exactDnr);
        var two = Catalog(exactDnr, crossedDnr);
        var boundary = typeof(MembershipClosureVerifier).GetMethod(
            "BindCurrentRouterFactSetBeforeCallbacks",
            BindingFlags.NonPublic | BindingFlags.Static)!;
        Assert.DoesNotContain(boundary.GetParameters(), parameter =>
            parameter.ParameterType == typeof(IMembershipSignatureVerifier) ||
            parameter.ParameterType == typeof(IProtectedHmacProvider));

        Assert.Single(MembershipClosureVerifier.BindCurrentRouterFactSetBeforeCallbacks(
            1, one, 0, exact.Cutover, exact.Dnrc.Mailbox, [exact.Dnrc]));

        AssertInvalid(() => MembershipClosureVerifier.BindCurrentRouterFactSetBeforeCallbacks(
            4_097, one, 0, exact.Cutover, exact.Dnrc.Mailbox,
            Enumerable.Repeat(exact.Dnrc, 4_097).ToArray()));
        AssertInvalid(() => MembershipClosureVerifier.BindCurrentRouterFactSetBeforeCallbacks(
            1, one, 0, exact.Cutover, exact.Dnrc.Mailbox, []));
        AssertInvalid(() => MembershipClosureVerifier.BindCurrentRouterFactSetBeforeCallbacks(
            2, two, 0, exact.Cutover, exact.Dnrc.Mailbox, [exact.Dnrc, exact.Dnrc]));
        AssertInvalid(() => MembershipClosureVerifier.BindCurrentRouterFactSetBeforeCallbacks(
            1, one, 0, exact.Cutover, exact.Dnrc.Mailbox, [sameSourceWrongFact]));
        AssertInvalid(() => MembershipClosureVerifier.BindCurrentRouterFactSetBeforeCallbacks(
            1, Catalog(other.Dnrc.Certificate.CanonicalBytes.ToArray()), 0,
            exact.Cutover, exact.Dnrc.Mailbox, [other.Dnrc]));
    }

    private sealed class CountingVerifier : IMembershipSignatureVerifier
    {
        internal int Calls { get; private set; }

        public bool Verify(
            ReadOnlySpan<byte> signerId,
            ReadOnlySpan<byte> publicKey,
            MembershipSignatureDomain domain,
            ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature)
        {
            Calls++;
            return false;
        }
    }

    private static OwnedMembershipCatalog Catalog(params byte[][] dnrs)
    {
        var canonical = dnrs.SelectMany(static value => value).ToArray();
        var rows = new MembershipCatalogRow[checked(dnrs.Length * 3)];
        var offset = 0;
        for (var index = 0; index < dnrs.Length; index++)
        {
            var dnr = dnrs[index];
            rows[index * 3] = new MembershipCatalogRow(
                ArtifactType.Dnr1,
                offset,
                dnr.Length,
                CanonicalGrammar.ComputeReference(
                    ArtifactType.Dnr1, dnr).CanonicalHash);
            offset += dnr.Length;
        }
        return new OwnedMembershipCatalog(canonical, rows);
    }

    private static void AssertInvalid(Action action) =>
        Assert.Equal(RecordError.InvalidField,
            Assert.Throws<RecordException>(action).Error);

    private static ReadOnlyMemory<byte>[] MinimumFields(RecordDefinition definition) =>
        definition.Fields.Select(static field =>
            (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();

    private static byte[] Reference(ArtifactType type, uint length, byte marker)
    {
        var value = new byte[ArtifactReference.Length];
        BinaryPrimitives.WriteUInt16BigEndian(value, (ushort)type);
        BinaryPrimitives.WriteUInt32BigEndian(value.AsSpan(2), length);
        value.AsSpan(6).Fill(marker);
        return value;
    }

    private static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    private static byte[] Fill(byte value, int length) =>
        Enumerable.Repeat(value, length).ToArray();
}
